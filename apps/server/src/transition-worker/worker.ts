import { createHash, randomUUID } from "node:crypto";
import {
  lstat,
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { hashManifestEntries } from "../commitgate/manifest.js";
import { canonicalJson, sha256Canonical } from "../commitgate/protocol.js";
import {
  verifyAuthorityReceiptProof,
  type AuthorityReceiptProofBundle,
  type AuthorityReceiptRecord,
  type AuthorityTerminalEventEnvelope,
} from "../research/receipt-proof.js";
import { computeStateViewId, EMPTY_STATE_HASH, makeStateView } from "../state-view.js";
import { TransitionEventLog, type TransitionEvent } from "../transition-log.js";
import type { StateViewRef } from "../types.js";
import type {
  ApplyPromotionParams,
  ApplyRollbackParams,
  AttemptPermitConsumptionParams,
  AdoptLegacyStateParams,
  ArchiveAgentParams,
  CancelRunParams,
  CancelRunResult,
  DisposeRunParams,
  ExportProposalParams,
  InitializeAgentParams,
  IssuePermitParams,
  PlatformStateParams,
  PrepareParams,
  PrepareRunParams,
  RecordEvidenceParams,
  RecordRuntimeTeardownParams,
  RuntimeTeardownRecord,
  RepairParams,
  SealProposalParams,
  WorkerRpcRequest,
} from "./contracts.js";
import {
  assertSameFilesystem,
  buildWorkerManifest,
  copyClosedTree,
  makeTreeReadonly,
  makeTreeWritable,
  prepareRuntimeIgnoredMountpoints,
} from "./filesystem.js";
import type { WorkerManifest, WorkerManifestOptions } from "./filesystem.js";
import {
  rebuildWorkerProjection,
  WorkerProjectionStore,
  type WorkerProjection,
} from "./projection.js";
import {
  EvidenceBlobStore,
  type EvidenceBlobRef,
} from "./evidence-blob-store.js";
import { WorkerSigningKeyStore } from "./signing-key-store.js";
import {
  validateWorkerEvidenceContract,
} from "../worker-gate-policy.js";
import {
  verifyBrokerAttestation,
  type SignedBrokerAttestation,
} from "../runtime-broker/attestation.js";
import type {
  BrokerRuntimeTeardownPayload,
  BrokerVerifierAttestationPayload,
} from "../runtime-broker/contracts.js";

export interface TransitionWorkerConfig {
  workspaceRoot: string;
  controlRoot: string;
  inboxRoot: string;
  socketPath: string;
  legacyWorkspaceRoot?: string;
  sourceRevision?: string;
  requireVerifiedSourceRevision?: boolean;
  expectedCheckBundleHash?: string;
  expectedVerifierImageDigest?: string;
  expectedVerifierConfigHash?: string;
  expectedResourcePolicyHash?: string;
  /** Production product runs require a durable Broker mount-release fact. */
  requireRuntimeTeardownHandshake?: boolean;
  /** Production accepts Runtime and Verifier facts only from the keyed Broker. */
  requireBrokerAttestations?: boolean;
  brokerAttestationKey?: string;
}

export interface WorkerReceiptSigner {
  readonly keyId: string;
  initialize(): Promise<void>;
  sign(
    receipt: AuthorityReceiptRecord,
    event: AuthorityTerminalEventEnvelope,
    eventChain: readonly AuthorityTerminalEventEnvelope[],
  ): AuthorityReceiptProofBundle;
}

export interface TransitionWorkerDependencies {
  signingKeyStore?: WorkerReceiptSigner;
  /** Production injects the fail-closed Linux filesystem profile. */
  manifestOptions?: WorkerManifestOptions;
}

export interface WorkerHealth {
  status: "ok";
  mode: "authority-v2";
  protocolVersion: 2;
  processUid: number | null;
  manifestSchemaVersion: 2;
  filesystemProfile: "linux-strong" | "portable-development";
  /** Stable public-key fingerprint; safe to pin before retrieving a receipt proof. */
  signingKeyId: string;
}

export interface PreparedRunRef {
  agentId: string;
  runId: string;
  transitionId: string;
  candidateVolumeId: string;
  relativeSubpath: string;
  baseView: StateViewRef;
  baseWorkspaceHash: string;
  candidateHash: string;
}

export interface VerifierWorkspaceRef {
  agentId: string;
  transitionId: string;
  proposalId: string;
  exportVolumeId: string;
  relativeSubpath: string;
  artifactHash: string;
}

type ExchangeRefPurpose = "candidate" | "verifier";

/**
 * Write-once ownership record for a run-scoped exchange-volume subpath.
 *
 * The exchange volume is shared with the Runtime Broker, so path existence is
 * not authority.  This Worker-only record prevents one Agent/transition from
 * adopting, deleting or replacing another run's candidate/verifier bytes.
 */
interface ExchangeRefBinding {
  schemaVersion: 1;
  purpose: ExchangeRefPurpose;
  volumeId: string;
  agentId: string;
  transitionId: string;
  runId: string;
  proposalId: string | null;
}

type RecordedEvaluationContext = NonNullable<RecordEvidenceParams["evaluationContext"]>;
type RecordedCheck = NonNullable<RecordEvidenceParams["checks"]>[number];

/**
 * Complete, bounded and already-redacted evidence retained outside the event
 * chain. Check output is represented only by outputHash; the Worker never
 * accepts arbitrary verifier output in this structure.
 */
interface StoredEvidenceBundleV2 {
  schemaVersion: 2;
  agentId: string;
  transitionId: string;
  proposalId: string;
  artifactHash: string;
  evaluationContextHash: string;
  evidenceDigest: string;
  evaluationContext: RecordedEvaluationContext | null;
  verifierInputHash: string | null;
  checkResultsHash: string | null;
  coverage: "complete" | "partial" | "unavailable";
  requiredChecksPassed: boolean;
  checks: RecordedCheck[];
}

const sha256 = (value: unknown): string =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");

export interface WorkerStateHashes {
  versionedHash: string;
  platformManagedHash: string;
  liveStateHash: string;
}

/**
 * Derive every StateView hash domain from the same canonical Manifest v2.
 * Callers never get to choose these values independently of the bytes owned by
 * the Worker.
 */
export function deriveWorkerStateHashes(manifest: WorkerManifest): WorkerStateHashes {
  return {
    versionedHash: hashManifestEntries(
      manifest.entries.filter((entry) => entry.pathClass === "versioned"),
    ),
    platformManagedHash: hashManifestEntries(
      manifest.entries.filter((entry) => entry.pathClass === "platformManaged"),
    ),
    liveStateHash: manifest.hash,
  };
}

export function inspectProposalDiff(
  base: WorkerManifest,
  candidate: WorkerManifest,
): { changedPaths: string[]; staticFailures: string[] } {
  const before = new Map(base.entries.map((entry) => [entry.path, entry]));
  const after = new Map(candidate.entries.map((entry) => [entry.path, entry]));
  const changedPaths = [...new Set([...before.keys(), ...after.keys()])]
    .filter((entryPath) => JSON.stringify(before.get(entryPath)) !== JSON.stringify(after.get(entryPath)))
    .sort();
  const failures: string[] = [];
  const changedFilePaths = changedPaths.filter(
    (entryPath) => before.get(entryPath)?.type === "file" || after.get(entryPath)?.type === "file",
  );
  if (changedFilePaths.length > 100) failures.push("CHANGED_FILE_BUDGET_EXCEEDED");
  let changedBytes = 0;
  for (const entryPath of changedPaths) {
    const beforeEntry = before.get(entryPath);
    const afterEntry = after.get(entryPath);
    const beforeSize = beforeEntry?.type === "file" ? beforeEntry.size : 0;
    const afterSize = afterEntry?.type === "file" ? afterEntry.size : 0;
    const affectedBytes = Math.max(beforeSize, afterSize);
    if (affectedBytes > 0 || beforeEntry?.type === "file" || afterEntry?.type === "file") {
      // Deletion and shrink are effects too. Charging only the candidate size
      // would let a proposal erase a large authoritative file at zero cost.
      changedBytes += affectedBytes;
      if (affectedBytes > 262_144) {
        failures.push(`SINGLE_FILE_BUDGET_EXCEEDED:${entryPath}`);
      }
    }
    if (entryPath === "protected.txt" || entryPath.startsWith("protected.txt/")) {
      failures.push("PROTECTED_PATH_CHANGED:protected.txt");
    }
    if (entryPath === "AGENTS.md" || entryPath.startsWith("AGENTS.md/")) {
      failures.push("PLATFORM_MANAGED_PATH_CHANGED:AGENTS.md");
    }
  }
  if (changedBytes > 1_048_576) failures.push("CHANGED_BYTE_BUDGET_EXCEEDED");
  return { changedPaths, staticFailures: [...new Set(failures)] };
}

const exists = async (target: string): Promise<boolean> => {
  try {
    await lstat(target);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
};

const errorReason = (error: unknown): string =>
  error instanceof Error ? error.message : String(error);

const isPromotionCasFault = (error: unknown): error is WorkerFault =>
  error instanceof WorkerFault &&
  (error.code === "VIEW_CAS_MISMATCH" || error.code === "WORKSPACE_CAS_MISMATCH");

const CANDIDATE_MANIFEST_POLICY_CODES = new Set([
  "AUTHORITATIVE_ROOT_NOT_DIRECTORY",
  "UNICODE_NORMALIZATION_COLLISION",
  "CASEFOLD_PATH_COLLISION",
  "INVALID_PATH_SEGMENT",
  "FILE_SIZE_UNREPRESENTABLE",
  "OWNERSHIP_MISMATCH",
  "UNSUPPORTED_FILESYSTEM_EXDEV",
  "SPECIAL_MODE_BITS",
  "XATTR_NOT_ALLOWED",
  "ACL_NOT_ALLOWED",
  "CANDIDATE_SCAN_TIME_BUDGET_EXCEEDED",
  "CANDIDATE_ENTRY_BUDGET_EXCEEDED",
  "CANDIDATE_BYTE_BUDGET_EXCEEDED",
  "IGNORED_EPHEMERAL_FILE_BUDGET_EXCEEDED",
  "IGNORED_EPHEMERAL_SINGLE_FILE_BUDGET_EXCEEDED",
  "IGNORED_EPHEMERAL_BYTE_BUDGET_EXCEEDED",
  "SYMLINK_FILE",
  "HARDLINK_FILE",
  "SPECIAL_FILE",
  "SPARSE_FILE",
]);

function candidateManifestPolicyCode(error: unknown): string | null {
  if (!(error instanceof Error)) return null;
  const code = error.message.split(":", 1)[0] ?? "";
  return CANDIDATE_MANIFEST_POLICY_CODES.has(code) ? code : null;
}

function candidateManifestPolicyPath(error: unknown, code: string): string | null {
  if (!(error instanceof Error)) return null;
  const prefix = `${code}:`;
  if (!error.message.startsWith(prefix)) return null;
  const bounded = error.message
    .slice(prefix.length)
    // A receipt may retain path/type metadata, never arbitrary control bytes or
    // candidate contents. Preserve useful POSIX path punctuation and redact the
    // rest into a fixed, bounded diagnostic token.
    .replace(/[^A-Za-z0-9._/:-]/g, "_")
    .slice(0, 80);
  return bounded.length > 0 ? bounded : null;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  Boolean(value) && typeof value === "object" && !Array.isArray(value);

const isRecordedCheck = (value: unknown): value is RecordedCheck => {
  if (!isRecord(value)) return false;
  return (
    typeof value.id === "string" &&
    ["PASS", "FAIL", "ERROR", "SKIPPED"].includes(String(value.status)) &&
    (value.exitCode === null || Number.isInteger(value.exitCode)) &&
    Number.isSafeInteger(value.durationMs) &&
    Number(value.durationMs) >= 0 &&
    typeof value.outputHash === "string" &&
    /^[a-f0-9]{64}$/.test(value.outputHash) &&
    typeof value.timedOut === "boolean"
  );
};

const assertView = (view: StateViewRef): void => {
  const { schemaVersion: _schemaVersion, viewId, ...input } = view;
  if (view.schemaVersion !== 1 || computeStateViewId(input) !== viewId) {
    throw new WorkerFault("VIEW_DIGEST_MISMATCH", "StateView digest is invalid");
  }
};

const intentString = (event: TransitionEvent, key: string): string => {
  const value = (event.payload as Record<string, unknown>)[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new WorkerFault(
      "AUTHORITY_INTENT_INVALID",
      `${event.type} is missing its ${key} binding`,
    );
  }
  return value;
};

const intentView = (event: TransitionEvent): StateViewRef => {
  const value = (event.payload as Record<string, unknown>).view;
  if (!isRecord(value)) {
    throw new WorkerFault("AUTHORITY_INTENT_INVALID", `${event.type} is missing its View`);
  }
  const view = value as unknown as StateViewRef;
  assertView(view);
  return view;
};

const intentStrings = (event: TransitionEvent, key: string): string[] => {
  const value = (event.payload as Record<string, unknown>)[key];
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new WorkerFault(
      "AUTHORITY_INTENT_INVALID",
      `${event.type} has an invalid ${key} binding`,
    );
  }
  return [...value];
};

export class WorkerFault extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "WorkerFault";
  }
}

/**
 * Authority V2 boundary. All paths are derived from fixed worker
 * roots and validated IDs; the JSON-RPC contract never accepts a host path.
 * The default P0 server does not instantiate this class.
 */
export class TransitionWorker {
  readonly log: TransitionEventLog;
  readonly projections: WorkerProjectionStore;
  readonly evidenceBlobs: EvidenceBlobStore;
  private readonly tails = new Map<string, Promise<void>>();
  private readonly exchangeRefTails = new Map<string, Promise<void>>();
  private readonly signingKeys: WorkerReceiptSigner;
  private readonly manifestOptions: WorkerManifestOptions;

  constructor(
    readonly config: TransitionWorkerConfig,
    dependencies: TransitionWorkerDependencies = {},
  ) {
    this.log = new TransitionEventLog(path.join(config.controlRoot, "log"));
    this.projections = new WorkerProjectionStore(config.controlRoot);
    this.evidenceBlobs = new EvidenceBlobStore(config.controlRoot);
    this.manifestOptions = dependencies.manifestOptions ?? {};
    this.signingKeys =
      dependencies.signingKeyStore ?? new WorkerSigningKeyStore(config.controlRoot);
  }

  async initialize(): Promise<void> {
    await Promise.all([
      mkdir(this.config.workspaceRoot, { recursive: true, mode: 0o700 }),
      mkdir(this.config.controlRoot, { recursive: true, mode: 0o700 }),
      mkdir(this.config.inboxRoot, { recursive: true, mode: 0o700 }),
      mkdir(path.dirname(this.config.socketPath), { recursive: true, mode: 0o750 }),
    ]);
    await Promise.all([
      this.signingKeys.initialize(),
      this.evidenceBlobs.initialize(),
    ]);
    // Staging and backup are always siblings of the authoritative workspace.
    // This preflight prevents rename-swap from silently degrading to copy.
    await assertSameFilesystem(this.config.workspaceRoot, this.config.workspaceRoot);
    const logRoot = path.join(this.config.controlRoot, "log");
    let agents: string[] = [];
    try {
      agents = (await readdir(logRoot, { withFileTypes: true }))
        .filter((entry) => entry.isDirectory() && /^[A-Za-z0-9_.-]{1,128}$/.test(entry.name))
        .map((entry) => entry.name);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    for (const agentId of agents) {
      try {
        await this.recoverAgent(agentId);
      } catch (error) {
        // The Worker deliberately has no Docker socket. A product run whose
        // Broker teardown fact is absent must remain byte-for-byte untouched
        // until the API asks the Broker to quiesce/reconcile that bound run
        // and records the resulting attestation through RPC.
        if (!(error instanceof WorkerFault) || error.code !== "RUNTIME_TEARDOWN_REQUIRED") {
          throw error;
        }
      }
    }
    await this.gcStartupOrphans(agents);
  }

  health(): WorkerHealth {
    const signingKeyId = this.signingKeys.keyId;
    if (!/^[a-f0-9]{24}$/.test(signingKeyId)) {
      throw new Error("WORKER_SIGNING_KEY_ID_INVALID");
    }
    return {
      status: "ok",
      mode: "authority-v2",
      protocolVersion: 2,
      processUid: typeof process.getuid === "function" ? process.getuid() : null,
      manifestSchemaVersion: 2,
      filesystemProfile:
        this.manifestOptions.requireExtendedMetadataInspection === true &&
        this.manifestOptions.requireSparseFileDetection === true &&
        this.manifestOptions.requireSingleFilesystem === true
          ? "linux-strong"
          : "portable-development",
      signingKeyId,
    };
  }

  async dispatch(request: WorkerRpcRequest): Promise<unknown> {
    switch (request.method) {
      case "health":
        return this.health();
      case "getProjection":
        return this.projection(request.params.agentId);
      case "getReceiptProof":
        return this.getReceiptProof(request.params.agentId, request.params.receiptId);
      case "rebuildProjection":
        return this.rebuildProjection(request.params.agentId);
      case "recoverAgent":
        return this.recoverAgent(request.params.agentId);
      case "initializeAgent":
        return this.initializeAgent(request.params);
      case "adoptLegacyState":
        return this.adoptLegacyState(request.params);
      case "prepareRun":
        return this.prepareRun(request.params);
      case "recordRuntimeTeardown":
        return this.recordRuntimeTeardown(request.params);
      case "cancelRun":
        return this.cancelRun(request.params);
      case "exportProposal":
        return this.exportProposal(request.params);
      case "disposeRun":
        return this.disposeRun(request.params);
      case "regeneratePlatformState":
        return this.regeneratePlatformState(request.params);
      case "archiveAgent":
        return this.archiveAgent(request.params);
      case "prepare":
        return this.prepare(request.params);
      case "sealProposal":
        return this.sealProposal(request.params);
      case "recordEvidence":
        return this.recordEvidence(request.params);
      case "issuePermit":
        return this.issuePermit(request.params);
      case "attemptPermitConsumption":
        return this.attemptPermitConsumption(request.params);
      case "applyPromotion":
        return this.applyPromotion(request.params);
      case "applyRollback":
        return this.applyRollback(request.params);
      case "repair":
        return this.repair(request.params);
    }
  }

  async projection(agentId: string): Promise<WorkerProjection> {
    const projection = rebuildWorkerProjection(agentId, await this.log.read(agentId));
    await this.hydrateEvidenceProjection(projection);
    return projection;
  }

  async rebuildProjection(agentId: string): Promise<WorkerProjection> {
    const projection = await this.projection(agentId);
    await this.projections.writeHead(projection);
    return projection;
  }

  /**
   * Reconstruct one complete genesis-to-terminal proof prefix on demand.
   * General projection RPCs deliberately retain only the compact v2 envelope
   * so ordinary product reads remain bounded as receipt history grows.
   */
  async getReceiptProof(
    agentId: string,
    receiptId: string,
  ): Promise<AuthorityReceiptProofBundle> {
    this.assertIdentifier(agentId);
    this.assertIdentifier(receiptId);
    const projection = await this.projection(agentId);
    const compact = projection.receiptProofs[receiptId];
    if (!compact) {
      throw new WorkerFault(
        "RECEIPT_PROOF_PENDING",
        "Terminal receipt proof is not available",
      );
    }
    const events = await this.log.read(agentId);
    const terminalEventIndex = events.findIndex(
      (event) => event.eventId === compact.terminalEventId,
    );
    const terminalEvent = events[terminalEventIndex];
    if (
      !terminalEvent ||
      terminalEvent.transitionId !== compact.transitionId ||
      terminalEventIndex < 0
    ) {
      throw new WorkerFault(
        "RECEIPT_PROOF_BINDING_MISSING",
        "Receipt terminal event is missing from the authority log",
      );
    }
    const bundle: AuthorityReceiptProofBundle = {
      schemaVersion: 3,
      receipt: structuredClone(compact.bundle.receipt),
      proof: structuredClone(compact.bundle.proof),
      terminalEvent: structuredClone(terminalEvent),
      predecessorEvent:
        terminalEventIndex > 0 ? structuredClone(events[terminalEventIndex - 1]!) : null,
      eventChain: structuredClone(events.slice(0, terminalEventIndex + 1)),
      publicKeyPem: compact.bundle.publicKeyPem,
    };
    const verification = verifyAuthorityReceiptProof(bundle);
    if (!verification.valid) {
      throw new WorkerFault(
        "RECEIPT_PROOF_BINDING_INVALID",
        verification.reason ?? "Authority receipt proof failed reconstruction",
      );
    }
    return bundle;
  }

  async initializeAgent(input: InitializeAgentParams): Promise<WorkerProjection> {
    return this.serial(input.agentId, async () => {
      await this.recoverPendingWorkerIntents(input.agentId);
      const existing = await this.projection(input.agentId);
      if (existing.head) return existing;
      const workspace = this.workspacePath(input.agentId);
      if (await exists(workspace)) {
        const manifest = await this.buildManifest(workspace);
        if (manifest.entries.length > 0) {
          throw new WorkerFault("AGENT_ALREADY_INITIALIZED", "Workspace already contains state");
        }
      }
      const staging = this.authorityOperationStagingPath(
        input.agentId,
        input.operationId,
        "initialize",
      );
      await rm(staging, { recursive: true, force: true });
      await mkdir(staging, { recursive: false, mode: 0o700 });
      await writeFile(path.join(staging, "AGENTS.md"), input.instructions, {
        encoding: "utf8",
        mode: 0o600,
        flag: "wx",
      });
      await writeFile(
        path.join(staging, ".gitignore"),
        ".codex/\nnode_modules/\ndist/\n.env\n*.log\n",
        { encoding: "utf8", mode: 0o600, flag: "wx" },
      );
      await writeFile(
        path.join(staging, "README.md"),
        `# ${input.name} workspace\n\nFiles created or edited by the Agent live here.\n`,
        { encoding: "utf8", mode: 0o600, flag: "wx" },
      );
      await writeFile(path.join(staging, "protected.txt"), "TRUSTED_BASELINE\n", {
        encoding: "utf8",
        mode: 0o600,
        flag: "wx",
      });
      const manifest = await this.buildManifest(staging);
      const stateHashes = deriveWorkerStateHashes(manifest);
      const view = makeStateView({
        agentId: input.agentId,
        headVersionId: input.headVersionId,
        generation: input.generation,
        ...stateHashes,
        sessionEpoch: input.sessionEpoch,
        agentConfigVersion: input.agentConfigVersion,
        policyVersion: input.policyVersion,
      });
      const intent = await this.log.append({
        agentId: input.agentId,
        transitionId: input.operationId,
        type: "AGENT_INITIALIZATION_PREPARED",
        payload: {
          view,
          workspaceHash: manifest.hash,
          versionId: input.headVersionId,
        },
      });
      await this.finishInitialAuthorityIntent(intent);
      return this.persistProjection(input.agentId);
    });
  }

  async adoptLegacyState(input: AdoptLegacyStateParams): Promise<WorkerProjection> {
    return this.serial(input.agentId, async () => {
      await this.recoverPendingWorkerIntents(input.agentId);
      const existing = await this.projection(input.agentId);
      if (existing.head) {
        if (
          existing.head.view.viewId === input.adoptedView.viewId &&
          existing.head.workspaceHash === input.expectedWorkspaceHash
        ) return existing;
        throw new WorkerFault("LEGACY_STATE_CONFLICT", "Worker projection already differs");
      }
      assertView(input.adoptedView);
      if (
        input.adoptedView.agentId !== input.agentId ||
        input.adoptedView.liveStateHash !== input.expectedWorkspaceHash
      ) {
        throw new WorkerFault("LEGACY_STATE_CONFLICT", "Legacy StateView does not bind the import");
      }
      const source = input.legacyAgentId
        ? this.legacyWorkspacePath(input.legacyAgentId)
        : this.inboxPath(input.sourceVolumeId!);
      if (!(await exists(source))) {
        throw new WorkerFault("LEGACY_STATE_CONFLICT", "Legacy workspace is missing");
      }
      const sourceManifest = await this.buildManifest(source);
      if (sourceManifest.hash !== input.expectedWorkspaceHash) {
        throw new WorkerFault("LEGACY_STATE_CONFLICT", "Legacy workspace hash differs");
      }
      const adoptedStateHashes = deriveWorkerStateHashes(sourceManifest);
      const adoptedView = makeStateView({
        agentId: input.agentId,
        headVersionId: input.versionId,
        generation: input.adoptedView.generation,
        ...adoptedStateHashes,
        sessionEpoch: input.adoptedView.sessionEpoch,
        agentConfigVersion: input.adoptedView.agentConfigVersion,
        policyVersion: input.adoptedView.policyVersion,
      });
      if (canonicalJson(input.adoptedView) !== canonicalJson(adoptedView)) {
        throw new WorkerFault(
          "LEGACY_STATE_CONFLICT",
          "Legacy StateView component hashes or metadata do not match the imported tree",
        );
      }
      const workspace = this.workspacePath(input.agentId);
      if (await exists(workspace)) {
        const current = await this.buildManifest(workspace);
        if (current.entries.length > 0) {
          throw new WorkerFault("LEGACY_STATE_CONFLICT", "Authority workspace is not empty");
        }
      }
      const staging = this.authorityOperationStagingPath(
        input.agentId,
        input.operationId,
        "adopt",
      );
      await rm(staging, { recursive: true, force: true });
      const copied = await this.copyTree(source, staging);
      if (copied.hash !== input.expectedWorkspaceHash) {
        throw new WorkerFault("LEGACY_STATE_CONFLICT", "Legacy import changed during copy");
      }
      const intent = await this.log.append({
        agentId: input.agentId,
        transitionId: input.operationId,
        type: "LEGACY_ADOPTION_PREPARED",
        payload: {
          view: adoptedView,
          workspaceHash: copied.hash,
          versionId: input.versionId,
          sourceVolumeId: input.sourceVolumeId ?? null,
          legacyAgentId: input.legacyAgentId ?? null,
        },
      });
      await this.finishInitialAuthorityIntent(intent);
      return this.persistProjection(input.agentId);
    });
  }

  async attemptPermitConsumption(input: AttemptPermitConsumptionParams): Promise<never> {
    return this.serial(input.agentId, async () => {
      const projection = await this.projection(input.agentId);
      const permit = projection.permits[input.permitId];
      if (
        !permit ||
        permit.transitionId !== input.transitionId ||
        projection.head?.view.viewId !== input.expectedViewId
      ) {
        throw new WorkerFault("HEAD_MISMATCH", "Permit binding or authoritative View differs");
      }
      if (permit.state === "CONSUMED") {
        throw new WorkerFault("PERMIT_REPLAY", "One-shot permit has already been consumed");
      }
      throw new WorkerFault("PERMIT_NOT_CONSUMED", "Diagnostic endpoint never consumes a live permit");
    });
  }

  async prepareRun(input: PrepareRunParams): Promise<PreparedRunRef> {
    return this.serial(input.agentId, async () => {
      if (input.transitionId !== input.runId) {
        throw new WorkerFault(
          "RUN_BINDING_INVALID",
          "The Agent run must own its transition",
        );
      }
      const candidateVolumeId = this.candidateVolumeId(input.runId);
      if (input.candidateVolumeId !== candidateVolumeId) {
        throw new WorkerFault(
          "CANDIDATE_REF_BINDING_MISMATCH",
          "Candidate ref must be the Worker-derived candidate-${runId} identifier",
        );
      }
      const projection = await this.projection(input.agentId);
      await this.assertCurrentCas(
        input.agentId,
        projection,
        input.expectedViewId,
        input.expectedWorkspaceHash,
      );
      if (projection.head?.view.generation !== input.baseGeneration) {
        throw new WorkerFault("VIEW_CAS_MISMATCH", "Generation changed before admission");
      }
      if (
        this.config.requireRuntimeTeardownHandshake === true &&
        input.sessionEpoch !== projection.head?.view.sessionEpoch
      ) {
        throw new WorkerFault(
          "RUNTIME_BINDING_INVALID",
          "Production admission must bind the current session epoch",
        );
      }
      const candidateBinding: ExchangeRefBinding = {
        schemaVersion: 1,
        purpose: "candidate",
        volumeId: candidateVolumeId,
        agentId: input.agentId,
        transitionId: input.transitionId,
        runId: input.runId,
        proposalId: null,
      };
      const bindingState = await this.bindExchangeRef(candidateBinding);
      const existing = projection.transitions[input.transitionId];
      if (existing) {
        const exactReplay =
          existing.state === "PREPARED" &&
          existing.kind === "AGENT_COMMIT" &&
          existing.runId === input.runId &&
          existing.runLeaseId === input.runLeaseId &&
          existing.candidateVolumeId === candidateVolumeId &&
          existing.baseViewId === input.expectedViewId &&
          existing.baseWorkspaceHash === input.expectedWorkspaceHash &&
          existing.baseGeneration === input.baseGeneration &&
          (input.sessionEpoch === undefined ||
            existing.runtimeSessionEpoch === input.sessionEpoch);
        if (!exactReplay) {
          throw new WorkerFault(
            "TRANSITION_REPLAY_CONFLICT",
            "Prepared transition replay differs from its durable admission",
          );
        }
        const candidate = this.inboxPath(candidateVolumeId);
        if (!(await exists(candidate))) {
          throw new WorkerFault(
            "CANDIDATE_STATE_MISMATCH",
            "Prepared transition candidate is missing",
          );
        }
        const candidateManifest = await this.buildManifest(candidate);
        if (candidateManifest.hash !== input.expectedWorkspaceHash) {
          throw new WorkerFault(
            "CANDIDATE_STATE_MISMATCH",
            "Prepared transition candidate no longer matches its admitted base",
          );
        }
        return {
          agentId: input.agentId,
          runId: input.runId,
          transitionId: input.transitionId,
          candidateVolumeId,
          relativeSubpath: candidateVolumeId,
          baseView: projection.head!.view,
          baseWorkspaceHash: input.expectedWorkspaceHash,
          candidateHash: candidateManifest.hash,
        };
      }
      const candidate = this.inboxPath(candidateVolumeId);
      // The directory rename/copy can complete before TRANSITION_PREPARED is
      // appended.  An exact base clone is therefore a recoverable orphan; any
      // other pre-existing bytes remain fail-closed and are never adopted.
      const candidateExisted = await exists(candidate);
      if (candidateExisted && bindingState === "CREATED") {
        await this.blockExchangeRef(candidateVolumeId);
        throw new WorkerFault(
          "EXCHANGE_REF_OCCUPIED",
          "Candidate ref already contains bytes without its exact durable ownership binding",
        );
      }
      const copied = candidateExisted
        ? await this.buildManifest(candidate)
        : await this.copyTree(this.workspacePath(input.agentId), candidate);
      if (copied.hash !== input.expectedWorkspaceHash) {
        throw new WorkerFault(
          candidateExisted ? "CANDIDATE_STATE_MISMATCH" : "WORKSPACE_CAS_MISMATCH",
          "Candidate does not match the authoritative base at admission",
        );
      }
      await prepareRuntimeIgnoredMountpoints(candidate);
      const preparedCandidate = await this.buildManifest(candidate);
      if (preparedCandidate.hash !== copied.hash) {
        throw new WorkerFault(
          "CANDIDATE_STATE_MISMATCH",
          "Runtime ignored mountpoint preparation changed authoritative candidate state",
        );
      }
      await this.log.append({
        agentId: input.agentId,
        transitionId: input.transitionId,
        type: "TRANSITION_PREPARED",
        payload: {
          kind: "AGENT_COMMIT",
          runId: input.runId,
          runLeaseId: input.runLeaseId,
          baseViewId: input.expectedViewId,
          baseWorkspaceHash: input.expectedWorkspaceHash,
          baseGeneration: input.baseGeneration,
          sessionEpoch: input.sessionEpoch ?? projection.head?.view.sessionEpoch ?? 0,
          candidateVolumeId,
        },
      });
      await this.persistProjection(input.agentId);
      return {
        agentId: input.agentId,
        runId: input.runId,
        transitionId: input.transitionId,
        candidateVolumeId,
        relativeSubpath: candidateVolumeId,
        baseView: projection.head?.view ?? null,
        baseWorkspaceHash: input.expectedWorkspaceHash,
        candidateHash: preparedCandidate.hash,
      };
    });
  }

  /**
   * Persists the Broker-owned container/mount release handshake before the
   * Worker may read, seal, promote, or destroy exchange bytes. The schema
   * accepts only a complete attestation; an incomplete observation is not a
   * fact and cannot be converted into an artifact-retention claim.
   */
  async recordRuntimeTeardown(
    input: RecordRuntimeTeardownParams,
  ): Promise<WorkerProjection> {
    return this.serial(input.agentId, async () => {
      let projection = await this.projection(input.agentId);
      const transition = projection.transitions[input.transitionId];
      const signedAttestation = "brokerAttestation" in input.attestation
        ? input.attestation
        : null;
      const signed = signedAttestation !== null;
      const brokerProof = signedAttestation?.brokerAttestation ?? null;
      if (this.config.requireBrokerAttestations === true && !signed) {
        throw new WorkerFault(
          "BROKER_ATTESTATION_REQUIRED",
          "Production Runtime teardown requires a keyed Broker attestation",
        );
      }
      let attestation: RuntimeTeardownRecord | BrokerRuntimeTeardownPayload;
      if (signed) {
        try {
          attestation = verifyBrokerAttestation(
            signedAttestation as SignedBrokerAttestation<BrokerRuntimeTeardownPayload>,
            this.config.brokerAttestationKey ?? "",
          );
        } catch (error) {
          throw new WorkerFault(
            "BROKER_ATTESTATION_INVALID",
            `Runtime teardown attestation is not authentic: ${errorReason(error)}`,
          );
        }
      } else {
        attestation = input.attestation;
      }
      if (
        !transition ||
        !transition.runId ||
        !transition.runLeaseId ||
        transition.runId !== attestation.runId ||
        transition.runLeaseId !== attestation.runLeaseId ||
        attestation.agentId !== input.agentId ||
        (transition.runtimeSessionEpoch !== null &&
          transition.runtimeSessionEpoch !== attestation.sessionEpoch)
      ) {
        throw new WorkerFault(
          "RUNTIME_TEARDOWN_BINDING_INVALID",
          "Runtime teardown does not bind the admitted run lease and session",
        );
      }
      if (attestation.scope === "AGENT" && transition.state !== "PREPARED") {
        throw new WorkerFault(
          "RUNTIME_TEARDOWN_ORDER_INVALID",
          "Agent teardown must be recorded before proposal sealing",
        );
      }
      if (["CONSUMING", "APPLIED", "REPAIRED"].includes(transition.state)) {
        throw new WorkerFault(
          "RUNTIME_TEARDOWN_ORDER_INVALID",
          "Runtime teardown cannot be introduced after the irreversible boundary",
        );
      }
      const digest = sha256Canonical(input.attestation);
      const existing = attestation.scope === "AGENT"
        ? transition.runtimeTeardownAgent
        : transition.runtimeTeardownAll;
      if (existing?.digest === digest) return projection;
      // A later complete Broker reconciliation is allowed to supersede an
      // earlier complete observation (for example after Broker restart). Both
      // remain append-only facts; projection selects the newest one.
      await this.log.append({
        agentId: input.agentId,
        transitionId: input.transitionId,
        type: "RUNTIME_TEARDOWN_RECORDED",
        payload: {
          ...attestation,
          ...(brokerProof ? { brokerAttestation: brokerProof } : {}),
          digest,
        },
      });
      projection = await this.persistProjection(input.agentId);
      return projection;
    });
  }

  /**
   * Makes cancellation an authority decision rather than an API-process hint.
   * The per-Agent serial queue is the irreversible-boundary fence: either this
   * event is appended before PERMIT_CONSUMING, or promotion wins and the
   * caller is told that cancellation was too late/already terminal.
   */
  async cancelRun(input: CancelRunParams): Promise<CancelRunResult> {
    return this.serial(input.agentId, async () => {
      const projection = await this.projection(input.agentId);
      const transition = projection.transitions[input.transitionId];
      if (!transition) return { state: "ALREADY_TERMINAL" };
      if (
        transition.kind !== "AGENT_COMMIT" ||
        transition.runId !== input.runId ||
        transition.runLeaseId !== input.runLeaseId ||
        transition.baseViewId !== input.expectedViewId
      ) {
        throw new WorkerFault(
          "RUN_CANCELLATION_BINDING_MISMATCH",
          "Cancellation does not own the admitted run lease and base View",
        );
      }
      if (transition.state === "CANCELLED") return { state: "CANCELLED" };
      if (["CONSUMING", "APPLIED", "REPAIRED"].includes(transition.state)) {
        return { state: "TOO_LATE" };
      }
      if (["ACKNOWLEDGED", "ROLLED_BACK"].includes(transition.state)) {
        return { state: "ALREADY_TERMINAL" };
      }
      await this.log.append({
        agentId: input.agentId,
        transitionId: input.transitionId,
        type: "RUN_CANCELLED",
        payload: {
          runId: input.runId,
          runLeaseId: input.runLeaseId,
          expectedViewId: input.expectedViewId,
        },
      });
      await this.persistProjection(input.agentId);
      return { state: "CANCELLED" };
    });
  }

  async exportProposal(input: ExportProposalParams): Promise<VerifierWorkspaceRef> {
    return this.serial(input.agentId, async () => {
      await this.recoverPendingWorkerIntents(input.agentId);
      const projection = await this.projection(input.agentId);
      this.assertRunNotCancelled(projection, input.transitionId);
      const transition = projection.transitions[input.transitionId];
      const proposal = projection.proposals[input.proposalId];
      if (
        !proposal ||
        proposal.transitionId !== input.transitionId ||
        !["SEALED", "EVIDENCED", "PERMITTED"].includes(
          transition?.state ?? "",
        )
      ) {
        throw new WorkerFault("PROPOSAL_NOT_SEALED", "Verifier export requires a sealed proposal");
      }
      let bindingState: "CREATED" | "EXISTING" | null = null;
      if (transition?.runId !== null && transition?.runId !== undefined) {
        const exportVolumeId = this.verifierVolumeId(transition.runId);
        if (input.exportVolumeId !== exportVolumeId) {
          throw new WorkerFault(
            "VERIFIER_REF_BINDING_MISMATCH",
            "Verifier ref must be the Worker-derived verify-${runId} identifier",
          );
        }
        bindingState = await this.bindExchangeRef({
          schemaVersion: 1,
          purpose: "verifier",
          volumeId: exportVolumeId,
          agentId: input.agentId,
          transitionId: input.transitionId,
          runId: transition.runId,
          proposalId: input.proposalId,
        });
      }
      const destination = this.inboxPath(input.exportVolumeId);
      if (await exists(destination)) {
        if (proposal.exportVolumeIds.includes(input.exportVolumeId)) {
          const manifest = await this.buildManifest(destination);
          if (manifest.hash !== proposal.artifactHash) {
            throw new WorkerFault("EXPORT_STATE_MISMATCH", "Recorded verifier export changed");
          }
          return {
            agentId: input.agentId,
            transitionId: input.transitionId,
            proposalId: input.proposalId,
            exportVolumeId: input.exportVolumeId,
            relativeSubpath: input.exportVolumeId,
            artifactHash: manifest.hash,
          };
        }
        if (bindingState === "CREATED") {
          await this.blockExchangeRef(input.exportVolumeId);
          throw new WorkerFault(
            "EXCHANGE_REF_OCCUPIED",
            "Verifier ref already contains bytes without its exact durable ownership binding",
          );
        }
        // A destination without a durable export event is not authority. It
        // may be a pre-event crash orphan only when its write-once binding
        // already belongs to this exact Agent/run/proposal. Rebuild it from
        // the immutable proposal rather than accepting its bytes.
        await makeTreeWritable(destination).catch(() => undefined);
        await rm(destination, { recursive: true, force: true });
      }
      const staging = this.proposalExportStagingPath(
        input.agentId,
        input.transitionId,
        input.exportVolumeId,
      );
      await makeTreeWritable(staging).catch(() => undefined);
      await rm(staging, { recursive: true, force: true });
      const copied = await this.copyTree(
        this.proposalPath(input.agentId, input.proposalId),
        staging,
      );
      if (copied.hash !== proposal.artifactHash) {
        throw new WorkerFault("ARTIFACT_HASH_MISMATCH", "Verifier export changed");
      }
      await makeTreeReadonly(staging);
      const intent = await this.log.append({
        agentId: input.agentId,
        transitionId: input.transitionId,
        type: "PROPOSAL_EXPORT_PREPARED",
        payload: {
          proposalId: input.proposalId,
          exportVolumeId: input.exportVolumeId,
          artifactHash: copied.hash,
        },
      });
      await this.finishProposalExportIntent(intent);
      await this.persistProjection(input.agentId);
      return {
        agentId: input.agentId,
        transitionId: input.transitionId,
        proposalId: input.proposalId,
        exportVolumeId: input.exportVolumeId,
        relativeSubpath: input.exportVolumeId,
        artifactHash: copied.hash,
      };
    });
  }

  async disposeRun(input: DisposeRunParams): Promise<WorkerProjection> {
    return this.serial(input.agentId, async () => {
      if (input.finalView) assertView(input.finalView);
      let projection = await this.projection(input.agentId);
      const transition = projection.transitions[input.transitionId];
      if (!transition) throw new WorkerFault("TRANSITION_STATE_INVALID", "Run was not prepared");
      const existingReceipt = projection.terminalReceipts.find(
        (receipt) => receipt.receiptId === input.receiptId,
      );
      if (existingReceipt) {
        if (
          existingReceipt.transitionId !== input.transitionId ||
          existingReceipt.decision !== input.decision
        ) {
          throw new WorkerFault(
            "TERMINAL_RECEIPT_CONFLICT",
            "Receipt ID is already bound to a different terminal disposition",
          );
        }
        if (
          input.finalView &&
          canonicalJson(input.finalView) !== canonicalJson(existingReceipt.view)
        ) {
          throw new WorkerFault(
            "NEXT_VIEW_INVALID",
            "Legacy finalView differs from the durable terminal disposition",
          );
        }
        if (
          input.nextSessionEpoch !== undefined &&
          input.nextSessionEpoch !== existingReceipt.view.sessionEpoch
        ) {
          throw new WorkerFault(
            "NEXT_VIEW_INVALID",
            "Requested session epoch differs from the durable terminal disposition",
          );
        }
        if (input.expectedViewId !== undefined) {
          const terminalEvents = await this.log.transition(input.agentId, input.transitionId);
          const terminalEvent = terminalEvents.find(
            (event) => event.eventId === existingReceipt.eventId,
          );
          const durablePreviousViewId =
            typeof terminalEvent?.payload.previousViewId === "string"
              ? terminalEvent.payload.previousViewId
              : transition.baseViewId;
          if (input.expectedViewId !== durablePreviousViewId) {
            throw new WorkerFault(
              "VIEW_CAS_MISMATCH",
              "Expected View differs from the durable terminal disposition base",
            );
          }
        }
        await this.destroyRunArtifacts(input.agentId, input.transitionId);
        // Compatibility repair for a V1 VIEW_DISPOSITIONED event whose
        // following TRANSITION_ROLLED_BACK append was interrupted.
        projection = await this.projection(input.agentId);
        if (projection.transitions[input.transitionId]?.state !== "ROLLED_BACK") {
          await this.log.append({
            agentId: input.agentId,
            transitionId: input.transitionId,
            type: "TRANSITION_ROLLED_BACK",
            payload: { reason: input.decision, legacyTerminalRepair: true },
          });
          await this.persistProjection(input.agentId);
        }
        return this.recordReceiptProofBestEffort(input.agentId, input.receiptId);
      }
      if (projection.terminalReceipts.some(
        (receipt) => receipt.transitionId === input.transitionId,
      )) {
        throw new WorkerFault(
          "TERMINAL_RECEIPT_CONFLICT",
          "Transition is already bound to a different terminal receipt",
        );
      }
      if (["CONSUMING", "APPLIED", "ACKNOWLEDGED", "REPAIRED"].includes(transition.state)) {
        throw new WorkerFault(
          "TRANSITION_IRREVERSIBLE",
          "Non-commit disposition cannot cross the promotion consuming boundary",
        );
      }
      if (!projection.head) {
        throw new WorkerFault("RECOVERY_REQUIRED", "Non-commit authority HEAD is missing");
      }
      const actualHash = await this.currentWorkspaceHash(input.agentId);
      if (actualHash !== projection.head.workspaceHash) {
        throw new WorkerFault(
          "RECOVERY_REQUIRED",
          "Authoritative workspace differs from the projected HEAD",
        );
      }
      this.deriveNonCommitView({
        agentId: input.agentId,
        authority: projection.head,
        ...(input.expectedViewId !== undefined
          ? { expectedViewId: input.expectedViewId }
          : {}),
        ...(input.nextSessionEpoch !== undefined
          ? { nextSessionEpoch: input.nextSessionEpoch }
          : {}),
        ...(input.finalView !== undefined ? { legacyFinalView: input.finalView } : {}),
      });
      // A negative terminal receipt may claim "artifact destroyed" only
      // after both the candidate/export exchange paths and the Worker-owned
      // sealed bytes are gone. Metadata and digests remain in the event log.
      await this.destroyRunArtifacts(input.agentId, input.transitionId);
      return this.appendNonCommitDisposition({
        agentId: input.agentId,
        transitionId: input.transitionId,
        receiptId: input.receiptId,
        decision: input.decision,
        reasonCodes: input.reasonCodes,
        ...(input.expectedViewId !== undefined
          ? { expectedViewId: input.expectedViewId }
          : {}),
        ...(input.nextSessionEpoch !== undefined
          ? { nextSessionEpoch: input.nextSessionEpoch }
          : {}),
        ...(input.finalView !== undefined ? { legacyFinalView: input.finalView } : {}),
      });
    });
  }

  async regeneratePlatformState(input: PlatformStateParams): Promise<WorkerProjection> {
    return this.serial(input.agentId, async () => {
      await this.recoverPendingWorkerIntents(input.agentId);
      const projection = await this.projection(input.agentId);
      await this.assertCurrentCas(
        input.agentId,
        projection,
        input.expectedViewId,
        input.expectedWorkspaceHash,
      );
      if (!projection.head) throw new WorkerFault("AGENT_NOT_INITIALIZED", "Agent has no authority head");
      if (
        input.sessionEpoch !== projection.head.view.sessionEpoch + 1 ||
        input.agentConfigVersion !== projection.head.view.agentConfigVersion + 1 ||
        input.policyVersion !== projection.head.view.policyVersion
      ) {
        throw new WorkerFault(
          "PLATFORM_STATE_METADATA_INVALID",
          "Platform regeneration must advance one session/config epoch and preserve Worker policy version",
        );
      }
      const staging = this.authorityOperationStagingPath(
        input.agentId,
        input.operationId,
        "platform",
      );
      await rm(staging, { recursive: true, force: true });
      await this.copyTree(this.workspacePath(input.agentId), staging);
      const destination = path.join(staging, "AGENTS.md");
      await writeFile(destination, input.instructions, { encoding: "utf8", mode: 0o600 });
      const manifest = await this.buildManifest(staging);
      const stateHashes = deriveWorkerStateHashes(manifest);
      if (stateHashes.versionedHash !== projection.head.view.versionedHash) {
        throw new WorkerFault(
          "PLATFORM_STATE_SCOPE_VIOLATION",
          "Platform regeneration changed versioned workspace state",
        );
      }
      const nextView = makeStateView({
        agentId: input.agentId,
        headVersionId: projection.head.view.headVersionId,
        generation: projection.head.view.generation + 1,
        ...stateHashes,
        sessionEpoch: input.sessionEpoch,
        agentConfigVersion: input.agentConfigVersion,
        policyVersion: input.policyVersion,
      });
      const intent = await this.log.append({
        agentId: input.agentId,
        transitionId: input.operationId,
        type: "PLATFORM_STATE_REGENERATION_PREPARED",
        payload: {
          baseViewId: projection.head.view.viewId,
          baseWorkspaceHash: projection.head.workspaceHash,
          view: nextView,
          workspaceHash: manifest.hash,
        },
      });
      await this.finishPlatformRegenerationIntent(intent);
      return this.persistProjection(input.agentId);
    });
  }

  async archiveAgent(input: ArchiveAgentParams): Promise<WorkerProjection> {
    return this.serial(input.agentId, async () => {
      await this.recoverPendingWorkerIntents(input.agentId);
      const projection = await this.projection(input.agentId);
      if (projection.archived) {
        if (
          projection.head?.view.viewId === input.expectedViewId &&
          projection.head.workspaceHash === input.expectedWorkspaceHash
        ) return projection;
        throw new WorkerFault("VIEW_CAS_MISMATCH", "Archived authority differs from the request");
      }
      await this.assertCurrentCas(
        input.agentId,
        projection,
        input.expectedViewId,
        input.expectedWorkspaceHash,
      );
      const intent = await this.log.append({
        agentId: input.agentId,
        transitionId: input.operationId,
        type: "AGENT_ARCHIVE_PREPARED",
        payload: { viewId: input.expectedViewId, workspaceHash: input.expectedWorkspaceHash },
      });
      await this.finishArchiveIntent(intent);
      return this.persistProjection(input.agentId);
    });
  }

  /**
   * Deterministically closes process-kill crash points. A CONSUMING transition
   * is forwarded only when the authoritative tree already equals its bound
   * target; it is rolled back when it still equals the prepared base. Any
   * third hash remains RECOVERY_REQUIRED for the CAS-guarded repair method.
   */
  async recoverAgent(agentId: string): Promise<WorkerProjection> {
    return this.serial(agentId, async () => {
      await this.recoverPendingWorkerIntents(agentId);
      let projection = await this.projection(agentId);
      for (const transition of Object.values(projection.transitions)) {
        projection = await this.projection(agentId);
        const current = projection.transitions[transition.transitionId];
        if (!current) continue;
        const terminalReceipt = projection.terminalReceipts.find(
          (receipt) => receipt.transitionId === current.transitionId,
        );
        if (terminalReceipt) {
          // Finish the only legacy two-event gap. New terminals are already
          // ROLLED_BACK by NON_COMMIT_DISPOSITIONED itself.
          if (
            terminalReceipt.decision !== "COMMITTED" &&
            current.state !== "ROLLED_BACK"
          ) {
            await this.log.append({
              agentId,
              transitionId: current.transitionId,
              type: "TRANSITION_ROLLED_BACK",
              payload: { reason: terminalReceipt.decision, legacyTerminalRepair: true },
            });
          }
          await this.deleteBackup(agentId, current.transitionId);
          await rm(this.stagingPath(agentId, current.transitionId), {
            recursive: true,
            force: true,
          });
          await this.destroyRunArtifacts(agentId, current.transitionId);
          projection = await this.persistProjection(agentId);
          continue;
        }
        if (current.state === "ACKNOWLEDGED") {
          // A kill after the terminal event is durable can leave only cleanup
          // work behind. Replaying cleanup is safe and keeps the event log as
          // the sole authority rather than appending a second terminal event.
          await this.deleteBackup(agentId, current.transitionId);
          await rm(this.stagingPath(agentId, current.transitionId), {
            recursive: true,
            force: true,
          });
          await this.destroyRunArtifacts(agentId, current.transitionId);
          projection = await this.projection(agentId);
          continue;
        }
        if (
          ["PREPARED", "SEALED", "EVIDENCED", "PERMITTED", "CANCELLED", "ROLLED_BACK"]
            .includes(current.state)
        ) {
          projection = await this.recoverIncompleteTransition(agentId, current.transitionId);
          continue;
        }
        if (!["CONSUMING", "APPLIED", "REPAIRED"].includes(current.state)) {
          throw new WorkerFault(
            "RECOVERY_REQUIRED",
            `Unsupported non-terminal transition state: ${current.state}`,
          );
        }
        const events = await this.log.transition(agentId, current.transitionId);
        const consuming = this.lastEvent(events, "PERMIT_CONSUMING");
        const intent = consuming?.payload as Record<string, unknown> | undefined;
        if (!intent) throw new WorkerFault("RECOVERY_REQUIRED", "Consuming intent is missing");
        const targetHash = String(intent.targetArtifactHash);
        const workspace = this.workspacePath(agentId);
        const backup = this.backupPath(agentId, current.transitionId);
        if (!(await exists(workspace)) && (await exists(backup))) {
          await this.restoreBackup(agentId, current.transitionId, current.baseWorkspaceHash);
        }
        const actualHash = await this.currentWorkspaceHash(agentId);
        if (actualHash === targetHash) {
          if (!current.appliedView && !intent.nextView) {
            throw new WorkerFault("RECOVERY_REQUIRED", "Applied workspace does not match durable intent");
          }
          if (current.state !== "APPLIED") {
            const nextView = intent.nextView as StateViewRef;
            assertView(nextView);
            await this.log.append({
              agentId,
              transitionId: current.transitionId,
              type: "WORKSPACE_APPLIED",
              payload: { view: nextView, workspaceHash: targetHash, recovered: true },
            });
          }
          const snapshotId = await this.captureSnapshot(agentId, targetHash);
          await this.log.append({
            agentId,
            transitionId: current.transitionId,
            type: "TRANSITION_ACKNOWLEDGED",
            payload: {
              versionId: String(intent.versionId),
              snapshotId,
              receiptId: String(intent.receiptId),
              ...(typeof intent.rollbackTargetVersionId === "string"
                ? { rollbackTargetVersionId: intent.rollbackTargetVersionId }
                : {}),
              recovered: true,
            },
          });
          await this.deleteBackup(agentId, current.transitionId);
          await this.destroyRunArtifacts(agentId, current.transitionId);
          projection = await this.persistProjection(agentId);
        } else if (actualHash === current.baseWorkspaceHash) {
          const baseView = await this.findStateView(agentId, current.baseViewId);
          if (!baseView || baseView.liveStateHash !== current.baseWorkspaceHash) {
            throw new WorkerFault("RECOVERY_REQUIRED", "Prepared base View cannot be reconstructed");
          }
          await this.deleteBackup(agentId, current.transitionId);
          await rm(this.stagingPath(agentId, current.transitionId), {
            recursive: true,
            force: true,
          });
          await this.destroyRunArtifacts(agentId, current.transitionId);
          projection = await this.appendNonCommitDisposition({
            agentId,
            transitionId: current.transitionId,
            receiptId:
              typeof intent.receiptId === "string"
                ? intent.receiptId
                : current.runId ?? current.transitionId,
            decision: "ABORTED",
            reasonCodes: ["RECOVERED_BEFORE_PROMOTION_APPLIED"],
            recovered: true,
            restoredAuthority: {
              view: baseView,
              workspaceHash: current.baseWorkspaceHash,
            },
          });
        } else {
          throw new WorkerFault(
            "RECOVERY_REQUIRED",
            "Workspace matches neither prepared base nor bound target",
          );
        }
      }
      projection = await this.projection(agentId);
      if (projection.head && !projection.archived) {
        const materialized = await this.manifestIfExists(this.workspacePath(agentId));
        if (materialized?.hash !== projection.head.workspaceHash) {
          throw new WorkerFault(
            "RECOVERY_REQUIRED",
            "Stable authoritative workspace differs from the rebuilt event HEAD",
          );
        }
      }
      // Receipt proof is deliberately post-terminal. A signing/key-store
      // failure can never reverse an acknowledged workspace; recovery merely
      // fills the missing proof event once signing becomes available again.
      projection = await this.projection(agentId);
      for (const receipt of projection.terminalReceipts) {
        if (projection.receiptProofs[receipt.receiptId]) continue;
        try {
          projection = await this.recordReceiptProof(agentId, receipt.receiptId);
        } catch {
          // Keep the durable terminal decision authoritative. The proof API
          // reports RECEIPT_PROOF_PENDING until a later recovery succeeds.
        }
      }
      // Projection markers are caches. A kill immediately after a durable
      // ACK can leave the marker stale even though the event chain is valid.
      // Rebuild it on every startup/recovery pass.
      return this.persistProjection(agentId);
    });
  }

  async prepare(input: PrepareParams): Promise<WorkerProjection> {
    return this.serial(input.agentId, async () => {
      if (
        input.kind === "AGENT_COMMIT" &&
        this.config.requireVerifiedSourceRevision === true
      ) {
        throw new WorkerFault(
          "PRODUCT_PREPARE_RUN_REQUIRED",
          "Production Agent commits must use prepareRun with a bound run lease",
        );
      }
      const projection = await this.projection(input.agentId);
      const currentHash = await this.currentWorkspaceHash(input.agentId);
      if (currentHash !== input.expectedWorkspaceHash) {
        throw new WorkerFault("WORKSPACE_CAS_MISMATCH", "Authoritative workspace hash changed");
      }
      if (projection.head) {
        if (
          projection.head.view.viewId !== input.expectedViewId ||
          projection.head.view.generation !== input.baseGeneration ||
          projection.head.workspaceHash !== input.expectedWorkspaceHash
        ) {
          throw new WorkerFault("VIEW_CAS_MISMATCH", "Head view or generation changed");
        }
      } else if (input.baseGeneration !== 0) {
        throw new WorkerFault("VIEW_CAS_MISMATCH", "Uninitialized projection must start at generation zero");
      }
      await this.log.append({
        agentId: input.agentId,
        transitionId: input.transitionId,
        type: "TRANSITION_PREPARED",
        payload: {
          kind: input.kind,
          baseViewId: input.expectedViewId,
          baseWorkspaceHash: input.expectedWorkspaceHash,
          baseGeneration: input.baseGeneration,
        },
      });
      return this.persistProjection(input.agentId);
    });
  }

  async sealProposal(input: SealProposalParams): Promise<WorkerProjection> {
    return this.serial(input.agentId, async () => {
      await this.recoverPendingWorkerIntents(input.agentId);
      const projection = await this.projection(input.agentId);
      this.assertRunNotCancelled(projection, input.transitionId);
      const transition = projection.transitions[input.transitionId];
      if (transition?.runId !== null && transition?.runId !== undefined) {
        const candidateVolumeId = this.candidateVolumeId(transition.runId);
        if (
          transition.candidateVolumeId !== candidateVolumeId ||
          input.sourceVolumeId !== candidateVolumeId
        ) {
          throw new WorkerFault(
            "CANDIDATE_REF_BINDING_MISMATCH",
            "Proposal source must equal the durable Worker-derived candidate ref",
          );
        }
        await this.bindExchangeRef({
          schemaVersion: 1,
          purpose: "candidate",
          volumeId: candidateVolumeId,
          agentId: input.agentId,
          transitionId: input.transitionId,
          runId: transition.runId,
          proposalId: null,
        });
      }
      if (transition?.state === "SEALED" && transition.proposalId === input.proposalId) {
        const existing = projection.proposals[input.proposalId];
        if (
          existing?.baseViewId === input.baseViewId &&
          (!input.expectedArtifactHash || existing.artifactHash === input.expectedArtifactHash) &&
          existing.runtimeTeardownDigest === (input.runtimeTeardownDigest ?? null)
        ) return projection;
        throw new WorkerFault("PROPOSAL_REPLAY_CONFLICT", "Proposal replay differs from sealed fact");
      }
      if (!transition || transition.state !== "PREPARED" || transition.kind !== "AGENT_COMMIT") {
        throw new WorkerFault("TRANSITION_STATE_INVALID", "Commit transition is not prepared");
      }
      if (transition.baseViewId !== input.baseViewId) {
        throw new WorkerFault("VIEW_CAS_MISMATCH", "Proposal base view differs from prepared view");
      }
      if (
        transition.runId !== null &&
        (typeof input.runtimeTeardownDigest !== "string" ||
          !/^[a-f0-9]{64}$/.test(input.runtimeTeardownDigest))
      ) {
        throw new WorkerFault(
          "RUNTIME_TEARDOWN_EVIDENCE_INVALID",
          "Product proposal sealing requires a 64-hex Runtime teardown attestation digest",
        );
      }
      if (this.config.requireRuntimeTeardownHandshake === true && transition.runId) {
        const teardown = transition.runtimeTeardownAgent;
        if (!teardown || teardown.digest !== input.runtimeTeardownDigest) {
          throw new WorkerFault(
            "RUNTIME_TEARDOWN_REQUIRED",
            "Proposal sealing requires the exact durable Agent mount-release attestation",
          );
        }
      }
      const source = this.inboxPath(input.sourceVolumeId);
      let sourceManifest: WorkerManifest;
      try {
        sourceManifest = await this.buildManifest(source);
      } catch (error) {
        const policyCode = candidateManifestPolicyCode(error);
        if (policyCode) {
          const policyPath = candidateManifestPolicyPath(error, policyCode);
          throw new WorkerFault(
            `POLICY_MANIFEST_${policyCode}`,
            `Candidate manifest rejected by ${policyCode}${
              policyPath ? `; path=${policyPath}` : ""
            }`,
          );
        }
        // Missing inspection tooling, inaccessible storage and other I/O
        // failures remain infrastructure errors and therefore ABORTED.
        throw error;
      }
      if (input.expectedArtifactHash && sourceManifest.hash !== input.expectedArtifactHash) {
        throw new WorkerFault("ARTIFACT_HASH_MISMATCH", "Inbox artifact hash differs from request");
      }
      const baseManifest = await this.buildManifest(this.workspacePath(input.agentId));
      const inspection = inspectProposalDiff(baseManifest, sourceManifest);
      const proposalRoot = this.proposalPath(input.agentId, input.proposalId);
      const temporary = this.proposalImportStagingPath(input.agentId, input.proposalId);
      await mkdir(path.dirname(proposalRoot), { recursive: true, mode: 0o700 });
      if (await exists(proposalRoot)) {
        await makeTreeWritable(proposalRoot).catch(() => undefined);
        await rm(proposalRoot, { recursive: true, force: true });
      }
      await makeTreeWritable(temporary).catch(() => undefined);
      await rm(temporary, { recursive: true, force: true });
      const copied = await this.copyTree(source, temporary);
      if (copied.hash !== sourceManifest.hash) {
        throw new WorkerFault("ARTIFACT_HASH_MISMATCH", "Imported artifact digest changed");
      }
      await makeTreeReadonly(temporary);
      await rename(temporary, proposalRoot);
      const intent = await this.log.append({
        agentId: input.agentId,
        transitionId: input.transitionId,
        type: "PROPOSAL_SEAL_PREPARED",
        payload: {
          proposalId: input.proposalId,
          baseViewId: input.baseViewId,
          artifactHash: copied.hash,
          manifestHash: sourceManifest.hash,
          changedPathsDigest: sha256Canonical(inspection.changedPaths),
          runtimeTeardownDigest: input.runtimeTeardownDigest ?? null,
          changedPaths: inspection.changedPaths,
          staticFailures: inspection.staticFailures,
          sourceVolumeId: input.sourceVolumeId,
        },
      });
      await this.finishProposalSealIntent(intent);
      return this.persistProjection(input.agentId);
    });
  }

  async recordEvidence(input: RecordEvidenceParams): Promise<WorkerProjection> {
    return this.serial(input.agentId, async () => {
      const projection = await this.projection(input.agentId);
      this.assertRunNotCancelled(projection, input.transitionId);
      const transition = projection.transitions[input.transitionId];
      this.assertRuntimeTeardown(projection, input.transitionId, "ALL");
      if (!transition || transition.proposalId !== input.proposalId || transition.state !== "SEALED") {
        throw new WorkerFault("EVIDENCE_BINDING_MISMATCH", "Evidence does not bind the sealed proposal");
      }
      const proposal = projection.proposals[input.proposalId];
      if (!proposal) {
        throw new WorkerFault("EVIDENCE_BINDING_MISMATCH", "Sealed proposal projection is missing");
      }
      const completeEvidence =
        input.evaluationContext !== undefined &&
        input.verifierInputHash !== undefined &&
        input.checkResultsHash !== undefined &&
        input.coverage !== undefined &&
        input.requiredChecksPassed !== undefined &&
        input.checks !== undefined;
      if (transition.runId && !completeEvidence) {
        throw new WorkerFault(
          "EVIDENCE_INCOMPLETE",
          "Product Agent runs require a complete typed EvidenceBundle",
        );
      }
      if (completeEvidence) {
        const signedEvidence = input.brokerAttestation;
        if (
          this.config.requireBrokerAttestations === true &&
          transition.runId &&
          !signedEvidence
        ) {
          throw new WorkerFault(
            "BROKER_ATTESTATION_REQUIRED",
            "Production trusted-check evidence requires a keyed Broker attestation",
          );
        }
        if (signedEvidence) {
          let brokerEvidence: BrokerVerifierAttestationPayload;
          try {
            brokerEvidence = verifyBrokerAttestation(
              signedEvidence as SignedBrokerAttestation<BrokerVerifierAttestationPayload>,
              this.config.brokerAttestationKey ?? "",
            );
          } catch (error) {
            throw new WorkerFault(
              "BROKER_ATTESTATION_INVALID",
              `Verifier result attestation is not authentic: ${errorReason(error)}`,
            );
          }
          const signedChecksPassed =
            brokerEvidence.coverage === "complete" &&
            brokerEvidence.checks.length > 0 &&
            brokerEvidence.checks.every(
              (check) =>
                check.status === "PASS" &&
                check.exitCode === 0 &&
                !check.timedOut,
            );
          if (
            brokerEvidence.scope !== "VERIFIER" ||
            brokerEvidence.runId !== transition.runId ||
            brokerEvidence.agentId !== input.agentId ||
            brokerEvidence.runLeaseId !== transition.runLeaseId ||
            brokerEvidence.sessionEpoch !== transition.runtimeSessionEpoch ||
            brokerEvidence.proposalId !== input.proposalId ||
            brokerEvidence.verifierInputHash !== proposal.artifactHash ||
            brokerEvidence.checkSpecHash !== input.evaluationContext!.checkSpecHash ||
            brokerEvidence.checkResultsHash !== sha256Canonical(input.checks) ||
            brokerEvidence.coverage !== input.coverage ||
            canonicalJson(brokerEvidence.checks) !== canonicalJson(input.checks) ||
            brokerEvidence.environment.checkBundleHash !==
              input.evaluationContext!.checkBundleHash ||
            brokerEvidence.environment.verifierImageDigest !==
              input.evaluationContext!.verifierImageDigest ||
            brokerEvidence.environment.verifierConfigHash !==
              input.evaluationContext!.verifierConfigHash ||
            brokerEvidence.environment.resourcePolicyHash !==
              input.evaluationContext!.resourcePolicyHash ||
            brokerEvidence.environment.sourceRevision !==
              input.evaluationContext!.sourceRevision ||
            signedChecksPassed !== input.requiredChecksPassed
          ) {
            throw new WorkerFault(
              "BROKER_ATTESTATION_BINDING_MISMATCH",
              "Verifier attestation does not bind the admitted run, Proposal, checks, and environment pins",
            );
          }
        }
        if (
          this.config.requireVerifiedSourceRevision === true &&
          (!/^[a-f0-9]{40}$/.test(this.config.sourceRevision ?? "") ||
            input.evaluationContext!.sourceRevision !== this.config.sourceRevision)
        ) {
          throw new WorkerFault(
            "SOURCE_REVISION_MISMATCH",
            "Production evidence must bind the exact Transition Worker source revision",
          );
        }
        if (!input.checks!.every(isRecordedCheck)) {
          throw new WorkerFault(
            "EVIDENCE_INVALID",
            "Trusted-check evidence contains malformed redacted results",
          );
        }
        if (
          input.evaluationContext!.runId !== transition.runId ||
          input.evaluationContext!.agentId !== input.agentId ||
          input.evaluationContext!.proposalId !== input.proposalId ||
          input.evaluationContext!.baseView.viewId !== transition.baseViewId ||
          sha256Canonical(input.evaluationContext) !== input.evaluationContextHash ||
          input.verifierInputHash !== proposal.artifactHash
        ) {
          throw new WorkerFault(
            "EVIDENCE_BINDING_MISMATCH",
            "Evaluation context or verifier input does not bind the sealed proposal",
          );
        }
        const computedCheckResultsHash = sha256Canonical(input.checks);
        const checksPassed =
          input.coverage === "complete" &&
          input.checks!.length > 0 &&
          input.checks!.every(
            (check) =>
              check.status === "PASS" && check.exitCode === 0 && !check.timedOut,
          );
        const computedEvidenceDigest = sha256Canonical({
          schemaVersion: 1,
          proposalId: input.proposalId,
          artifactHash: proposal.artifactHash,
          evaluationContextHash: input.evaluationContextHash,
          checkResultsHash: computedCheckResultsHash,
        });
        if (
          computedCheckResultsHash !== input.checkResultsHash ||
          checksPassed !== input.requiredChecksPassed ||
          computedEvidenceDigest !== input.evidenceDigest
        ) {
          throw new WorkerFault(
            "EVIDENCE_DIGEST_MISMATCH",
            "Typed evidence fields do not match their canonical digests",
          );
        }
      }
      const storedEvidence: StoredEvidenceBundleV2 = {
        schemaVersion: 2,
        agentId: input.agentId,
        transitionId: input.transitionId,
        proposalId: input.proposalId,
        artifactHash: proposal.artifactHash,
        evaluationContextHash: input.evaluationContextHash,
        evidenceDigest: input.evidenceDigest,
        evaluationContext: input.evaluationContext ?? null,
        verifierInputHash: input.verifierInputHash ?? null,
        checkResultsHash: input.checkResultsHash ?? null,
        coverage: input.coverage ?? "unavailable",
        requiredChecksPassed: input.requiredChecksPassed ?? false,
        checks: input.checks ?? [],
      };
      let evidenceBlob: EvidenceBlobRef;
      try {
        evidenceBlob = await this.evidenceBlobs.put(storedEvidence);
      } catch (error) {
        const code =
          error && typeof error === "object" && "code" in error
            ? String(error.code)
            : "EVIDENCE_BLOB_WRITE_FAILED";
        throw new WorkerFault(code, `Evidence blob could not be recorded: ${errorReason(error)}`);
      }
      await this.log.append({
        agentId: input.agentId,
        transitionId: input.transitionId,
        type: "EVIDENCE_RECORDED",
        payload: {
          schemaVersion: 2,
          proposalId: input.proposalId,
          evaluationContextHash: input.evaluationContextHash,
          evidenceDigest: input.evidenceDigest,
          verifierInputHash: input.verifierInputHash ?? null,
          checkResultsHash: input.checkResultsHash ?? null,
          coverage: input.coverage ?? "unavailable",
          requiredChecksPassed: input.requiredChecksPassed ?? false,
          checkCount: input.checks?.length ?? 0,
          sourceRevision: input.evaluationContext?.sourceRevision ?? null,
          policyHash: input.evaluationContext?.policyHash ?? null,
          brokerAttestationDigest: input.brokerAttestation
            ? sha256Canonical(input.brokerAttestation)
            : null,
          evidenceBlobHash: evidenceBlob.blobId,
          evidenceBlobSize: evidenceBlob.sizeBytes,
        },
      });
      return this.persistProjection(input.agentId);
    });
  }

  async issuePermit(input: IssuePermitParams): Promise<WorkerProjection> {
    return this.serial(input.agentId, async () => {
      const projection = await this.projection(input.agentId);
      this.assertRunNotCancelled(projection, input.transitionId);
      this.assertRuntimeTeardown(projection, input.transitionId, "ALL");
      const transition = projection.transitions[input.transitionId];
      const proposal = projection.proposals[input.proposalId];
      const projectedEvidence = projection.evidence[input.proposalId];
      if (
        !transition ||
        transition.state !== "EVIDENCED" ||
        !proposal ||
        proposal.baseViewId !== input.baseViewId ||
        proposal.artifactHash !== input.targetArtifactHash ||
        !projectedEvidence ||
        projectedEvidence.evaluationContextHash !== input.evaluationContextHash ||
        projectedEvidence.evidenceDigest !== input.evidenceDigest ||
        Date.parse(input.expiresAt) <= Date.now()
      ) {
        throw new WorkerFault("PERMIT_BINDING_MISMATCH", "Permit inputs do not bind current evidence");
      }
      if (proposal.staticFailures.length > 0) {
        throw new WorkerFault(
          "PROPOSAL_POLICY_VIOLATION",
          "A proposal with Worker-recorded static policy failures cannot receive a permit",
        );
      }
      if (projectedEvidence.evidenceBlob) {
        await this.assertEvidenceBlobBindings(input, projection);
      } else if (
        transition.runId !== null ||
        (transition.kind === "AGENT_COMMIT" &&
          this.config.requireVerifiedSourceRevision === true)
      ) {
        // V1 inline evidence remains readable for historical projection and
        // receipt verification, but it cannot authorize a new product effect.
        throw new WorkerFault(
          "EVIDENCE_BLOB_REQUIRED",
          "Product Agent runs require blob-backed evidence before permit issuance",
        );
      }
      await this.log.append({
        agentId: input.agentId,
        transitionId: input.transitionId,
        type: "PERMIT_ISSUED",
        payload: { ...input },
      });
      return this.persistProjection(input.agentId);
    });
  }

  async applyPromotion(input: ApplyPromotionParams): Promise<WorkerProjection> {
    return this.serial(input.agentId, async () => {
      if (input.nextView) assertView(input.nextView);
      const projection = await this.projection(input.agentId);
      this.assertRunNotCancelled(projection, input.transitionId);
      this.assertRuntimeTeardown(projection, input.transitionId, "ALL");
      const transition = projection.transitions[input.transitionId];
      const permit = projection.permits[input.permitId];
      const proposal = projection.proposals[input.proposalId];
      if (
        !transition ||
        transition.state !== "PERMITTED" ||
        transition.permitId !== input.permitId ||
        !permit ||
        permit.state !== "ISSUED" ||
        !proposal ||
        permit.proposalId !== input.proposalId ||
        permit.targetArtifactHash !== proposal.artifactHash ||
        permit.baseViewId !== input.expectedViewId ||
        Date.parse(permit.expiresAt) <= Date.now()
      ) {
        throw new WorkerFault("PERMIT_REPLAY", "Promotion permit is invalid, expired, or consumed");
      }
      let currentHead: WorkerProjection["head"];
      try {
        await this.assertCurrentCas(
          input.agentId,
          projection,
          input.expectedViewId,
          input.expectedWorkspaceHash,
        );
        currentHead = projection.head;
        if (!currentHead || currentHead.view.generation !== transition.baseGeneration) {
          throw new WorkerFault(
            "VIEW_CAS_MISMATCH",
            "Prepared generation no longer matches the authoritative HEAD",
          );
        }
      } catch (error) {
        if (!isPromotionCasFault(error)) throw error;
        // A CAS rejection is itself an authoritative terminal outcome.  Make
        // it durable while this Agent's transition lock is still held, before
        // returning the typed fault to the Runner.  Otherwise an API/Runner
        // crash in that gap would leave a PERMITTED transition for startup
        // recovery to misclassify as ABORTED.
        await this.appendPromotionCasConflict(input, error);
        throw error;
      }
      const sealedSource = this.proposalPath(input.agentId, input.proposalId);
      const sealedManifest = await this.buildManifest(sealedSource);
      if (
        sealedManifest.hash !== proposal.artifactHash ||
        sealedManifest.hash !== proposal.manifestHash
      ) {
        throw new WorkerFault(
          "PROMOTION_SOURCE_CHANGED",
          "Sealed proposal manifest no longer matches its recorded artifact",
        );
      }
      const nextView = makeStateView({
        agentId: input.agentId,
        headVersionId: input.versionId,
        generation: currentHead.view.generation + 1,
        ...deriveWorkerStateHashes(sealedManifest),
        sessionEpoch: currentHead.view.sessionEpoch,
        agentConfigVersion: currentHead.view.agentConfigVersion,
        policyVersion: currentHead.view.policyVersion,
      });
      this.assertLegacyNextView(input.nextView, nextView);
      await this.log.append({
        agentId: input.agentId,
        transitionId: input.transitionId,
        type: "PERMIT_CONSUMING",
        payload: {
          permitId: input.permitId,
          proposalId: input.proposalId,
          nextView,
          versionId: input.versionId,
          receiptId: input.receiptId,
          targetArtifactHash: proposal.artifactHash,
        },
      });
      return this.applyTreeAndAcknowledge({
        agentId: input.agentId,
        transitionId: input.transitionId,
        source: this.proposalPath(input.agentId, input.proposalId),
        targetHash: proposal.artifactHash,
        expectedBaseHash: input.expectedWorkspaceHash,
        nextView,
        baseView: currentHead.view,
        versionId: input.versionId,
        receiptId: input.receiptId,
      });
    });
  }

  async applyRollback(input: ApplyRollbackParams): Promise<WorkerProjection> {
    return this.serial(input.agentId, async () => {
      if (input.nextView) assertView(input.nextView);
      let projection = await this.projection(input.agentId);
      const transition = projection.transitions[input.transitionId];
      if (!transition || transition.kind !== "ROLLBACK" || transition.state !== "PREPARED") {
        throw new WorkerFault("TRANSITION_STATE_INVALID", "Rollback transition is not prepared");
      }
      await this.assertCurrentCas(input.agentId, projection, input.expectedViewId, input.expectedWorkspaceHash);
      const currentHead = projection.head;
      if (!currentHead || currentHead.view.generation !== transition.baseGeneration) {
        throw new WorkerFault(
          "VIEW_CAS_MISMATCH",
          "Prepared generation no longer matches the authoritative HEAD",
        );
      }
      const matchingVersions = projection.versions.filter(
        (version) => version.versionId === input.targetVersionId,
      );
      if (matchingVersions.length === 0) {
        throw new WorkerFault(
          "ROLLBACK_TARGET_VERSION_NOT_FOUND",
          "Rollback target version does not exist in the Worker projection",
        );
      }
      if (matchingVersions.length !== 1) {
        throw new WorkerFault(
          "ROLLBACK_TARGET_VERSION_AMBIGUOUS",
          "Rollback target version is not unique in the Worker projection",
        );
      }
      const targetVersion = matchingVersions[0]!;
      if (
        targetVersion.snapshotId !== input.targetSnapshotId ||
        targetVersion.workspaceHash !== targetVersion.snapshotId
      ) {
        throw new WorkerFault(
          "ROLLBACK_TARGET_BINDING_MISMATCH",
          "Rollback target version does not bind the requested Worker snapshot",
        );
      }
      // From this point onward, audit facts are derived from the Worker version
      // projection rather than copied from the RPC caller.
      const targetVersionId = targetVersion.versionId;
      const targetSnapshotId = targetVersion.snapshotId;
      const source = this.snapshotPath(input.agentId, targetSnapshotId);
      if (!(await exists(source))) {
        throw new WorkerFault(
          "SNAPSHOT_PRUNED",
          "Rollback target snapshot is not available in Worker storage",
        );
      }
      const manifest = await this.buildManifest(source);
      if (
        manifest.hash !== targetSnapshotId ||
        manifest.hash !== targetVersion.workspaceHash
      ) {
        throw new WorkerFault("SNAPSHOT_DIGEST_MISMATCH", "Rollback snapshot digest changed");
      }
      const nextView = makeStateView({
        agentId: input.agentId,
        headVersionId: input.versionId,
        generation: currentHead.view.generation + 1,
        ...deriveWorkerStateHashes(manifest),
        sessionEpoch: currentHead.view.sessionEpoch + 1,
        agentConfigVersion: currentHead.view.agentConfigVersion,
        policyVersion: currentHead.view.policyVersion,
      });
      this.assertLegacyNextView(input.nextView, nextView);
      const proposalId = `snapshot-${targetSnapshotId}`;
      const contextHash = sha256({
        rollbackPermitId: input.rollbackPermitId,
        targetSnapshotId,
        targetVersionId,
        expectedViewId: input.expectedViewId,
      });
      const evidenceDigest = sha256({ contextHash, targetHash: manifest.hash });
      await this.log.append({
        agentId: input.agentId,
        transitionId: input.transitionId,
        type: "PROPOSAL_SEALED",
        payload: {
          proposalId,
          baseViewId: input.expectedViewId,
          artifactHash: manifest.hash,
          source: "version_snapshot",
        },
      });
      await this.log.append({
        agentId: input.agentId,
        transitionId: input.transitionId,
        type: "EVIDENCE_RECORDED",
        payload: {
          proposalId,
          evaluationContextHash: contextHash,
          evidenceDigest,
          // A rollback verifies the immutable Worker-owned snapshot directly.
          verifierInputHash: manifest.hash,
        },
      });
      await this.log.append({
        agentId: input.agentId,
        transitionId: input.transitionId,
        type: "PERMIT_ISSUED",
        payload: {
          permitId: input.rollbackPermitId,
          proposalId,
          baseViewId: input.expectedViewId,
          targetArtifactHash: manifest.hash,
          evaluationContextHash: contextHash,
          evidenceDigest,
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
        },
      });
      await this.log.append({
        agentId: input.agentId,
        transitionId: input.transitionId,
        type: "PERMIT_CONSUMING",
        payload: {
          permitId: input.rollbackPermitId,
          proposalId,
          nextView,
          versionId: input.versionId,
          receiptId: input.receiptId,
          targetArtifactHash: manifest.hash,
          rollbackTargetVersionId: targetVersionId,
        },
      });
      projection = await this.applyTreeAndAcknowledge({
        agentId: input.agentId,
        transitionId: input.transitionId,
        source,
        targetHash: manifest.hash,
        expectedBaseHash: input.expectedWorkspaceHash,
        nextView,
        baseView: currentHead.view,
        versionId: input.versionId,
        receiptId: input.receiptId,
        rollbackTargetVersionId: targetVersionId,
      });
      return projection;
    });
  }

  async repair(input: RepairParams): Promise<WorkerProjection> {
    return this.serial(input.agentId, async () => {
      const projection = await this.projection(input.agentId);
      const transition = projection.transitions[input.transitionId];
      if (!transition || !["CONSUMING", "APPLIED"].includes(transition.state)) {
        throw new WorkerFault("REPAIR_NOT_REQUIRED", "Transition is not at a recoverable crash point");
      }
      await this.assertCurrentCas(input.agentId, projection, input.expectedViewId, input.expectedWorkspaceHash);
      const events = await this.log.transition(input.agentId, input.transitionId);
      const consuming = this.lastEvent(events, "PERMIT_CONSUMING");
      const intent = consuming?.payload as Record<string, unknown> | undefined;
      if (!intent) throw new WorkerFault("RECOVERY_METADATA_MISSING", "Transition intent is incomplete");

      if (input.action === "rollback") {
        const baseView = await this.findStateView(input.agentId, transition.baseViewId);
        if (!baseView || baseView.liveStateHash !== transition.baseWorkspaceHash) {
          throw new WorkerFault("RECOVERY_REQUIRED", "Prepared base View cannot be reconstructed");
        }
        await this.restoreBackup(input.agentId, input.transitionId, transition.baseWorkspaceHash);
        await this.log.appendRepair({
          ...input,
          actualViewId: input.expectedViewId,
          actualWorkspaceHash: input.expectedWorkspaceHash,
        });
        await this.destroyRunArtifacts(input.agentId, input.transitionId);
        return this.appendNonCommitDisposition({
          agentId: input.agentId,
          transitionId: input.transitionId,
          receiptId: transition.runId ?? input.transitionId,
          decision: "ABORTED",
          reasonCodes: ["REPAIR_ROLLBACK_APPLIED"],
          recovered: true,
          restoredAuthority: {
            view: baseView,
            workspaceHash: transition.baseWorkspaceHash,
          },
        });
      }

      const nextView = intent.nextView as StateViewRef;
      assertView(nextView);
      const targetHash = String(intent.targetArtifactHash);
      const source = transition.kind === "ROLLBACK"
        ? this.snapshotPath(input.agentId, targetHash)
        : this.proposalPath(input.agentId, String(intent.proposalId));
      if ((await this.currentWorkspaceHash(input.agentId)) !== targetHash) {
        await this.replaceWorkspace(
          input.agentId,
          input.transitionId,
          source,
          targetHash,
          input.expectedWorkspaceHash,
        );
      }
      await this.log.appendRepair({
        ...input,
        actualViewId: input.expectedViewId,
        actualWorkspaceHash: input.expectedWorkspaceHash,
      });
      await this.finishAppliedTransition({
        agentId: input.agentId,
        transitionId: input.transitionId,
        targetHash,
        nextView,
        versionId: String(intent.versionId),
        receiptId: String(intent.receiptId),
        ...(typeof intent.rollbackTargetVersionId === "string"
          ? { rollbackTargetVersionId: intent.rollbackTargetVersionId }
          : {}),
      });
      await this.deleteBackup(input.agentId, input.transitionId).catch(() => undefined);
      await this.persistProjection(input.agentId);
      return this.recordReceiptProofBestEffort(input.agentId, String(intent.receiptId));
    });
  }

  private async applyTreeAndAcknowledge(input: {
    agentId: string;
    transitionId: string;
    source: string;
    targetHash: string;
    expectedBaseHash: string;
    nextView: StateViewRef;
    baseView: StateViewRef | null;
    versionId: string;
    receiptId: string;
    rollbackTargetVersionId?: string;
  }): Promise<WorkerProjection> {
    try {
      await this.replaceWorkspace(
        input.agentId,
        input.transitionId,
        input.source,
        input.targetHash,
        input.expectedBaseHash,
      );
      await this.finishAppliedTransition(input);
    } catch (error) {
      // append() can report a test-injected failure after the terminal ACK is
      // already durable. Never turn that committed fact into a rollback.
      const durable = await this.projection(input.agentId).catch(() => null);
      if (durable?.transitions[input.transitionId]?.state === "ACKNOWLEDGED") {
        await this.deleteBackup(input.agentId, input.transitionId).catch(() => undefined);
        await this.destroyRunArtifacts(input.agentId, input.transitionId).catch(() => undefined);
        await this.persistProjection(input.agentId);
        return this.recordReceiptProofBestEffort(input.agentId, input.receiptId);
      }
      try {
        await this.restoreBackup(input.agentId, input.transitionId, input.expectedBaseHash);
      } catch (restoreError) {
        throw new WorkerFault(
          "RECOVERY_REQUIRED",
          `Promotion failed and the exact base could not be restored: ${errorReason(restoreError)}`,
        );
      }
      if (!input.baseView) {
        throw new WorkerFault(
          "RECOVERY_REQUIRED",
          "Promotion base was restored but its StateView cannot be reconstructed",
        );
      }
      try {
        await this.destroyRunArtifacts(input.agentId, input.transitionId);
        await this.appendNonCommitDisposition({
          agentId: input.agentId,
          transitionId: input.transitionId,
          receiptId: input.receiptId,
          decision: "ABORTED",
          reasonCodes: ["PROMOTION_APPLY_FAILED", errorReason(error).slice(0, 128)],
          recovered: true,
          restoredAuthority: {
            view: input.baseView,
            workspaceHash: input.expectedBaseHash,
          },
        });
      } catch (dispositionError) {
        throw new WorkerFault(
          "RECOVERY_REQUIRED",
          `Promotion base was restored but its terminal disposition is incomplete: ${errorReason(dispositionError)}`,
        );
      }
      throw error;
    }
    // Cleanup/projection/proof all happen after the immutable ACK. Failures in
    // this section are recoverable metadata work and must not roll back HEAD.
    await this.deleteBackup(input.agentId, input.transitionId).catch(() => undefined);
    await this.destroyRunArtifacts(input.agentId, input.transitionId).catch(() => undefined);
    await this.persistProjection(input.agentId);
    return this.recordReceiptProofBestEffort(input.agentId, input.receiptId);
  }

  private async recordReceiptProofBestEffort(
    agentId: string,
    receiptId: string,
  ): Promise<WorkerProjection> {
    try {
      return await this.recordReceiptProof(agentId, receiptId);
    } catch {
      return this.persistProjection(agentId);
    }
  }

  /**
   * Appends the one and only non-commit terminal fact.  The event both records
   * the receipt and closes the transition (including permit revocation), so a
   * process kill cannot strand VIEW_DISPOSITIONED ahead of ROLLED_BACK.
   */
  private async appendNonCommitDisposition(input: {
    agentId: string;
    transitionId: string;
    receiptId: string;
    decision: "QUARANTINED" | "CONFLICTED" | "ABORTED";
    reasonCodes: string[];
    expectedViewId?: string;
    nextSessionEpoch?: number;
    legacyFinalView?: StateViewRef;
    recovered?: boolean;
    restoredAuthority?: {
      view: StateViewRef;
      workspaceHash: string;
    };
  }): Promise<WorkerProjection> {
    const projection = await this.projection(input.agentId);
    const transition = projection.transitions[input.transitionId];
    if (!transition) {
      throw new WorkerFault("TRANSITION_STATE_INVALID", "Run was not prepared");
    }
    if (projection.terminalReceipts.some((receipt) => receipt.receiptId === input.receiptId)) {
      throw new WorkerFault(
        "TERMINAL_RECEIPT_CONFLICT",
        "Terminal disposition has already been recorded",
      );
    }
    const authority = input.restoredAuthority ?? projection.head;
    if (!authority || authority.view.agentId !== input.agentId) {
      throw new WorkerFault("RECOVERY_REQUIRED", "Non-commit authority HEAD is missing");
    }
    assertView(authority.view);
    const actualHash = await this.currentWorkspaceHash(input.agentId);
    if (
      actualHash !== authority.workspaceHash ||
      authority.view.liveStateHash !== authority.workspaceHash
    ) {
      throw new WorkerFault(
        "RECOVERY_REQUIRED",
        "Authoritative workspace does not match the non-commit disposition base",
      );
    }
    const finalView = this.deriveNonCommitView({
      agentId: input.agentId,
      authority,
      ...(input.expectedViewId !== undefined
        ? { expectedViewId: input.expectedViewId }
        : {}),
      ...(input.nextSessionEpoch !== undefined
        ? { nextSessionEpoch: input.nextSessionEpoch }
        : {}),
      ...(input.legacyFinalView !== undefined
        ? { legacyFinalView: input.legacyFinalView }
        : {}),
    });
    await this.log.append({
      agentId: input.agentId,
      transitionId: input.transitionId,
      type: "NON_COMMIT_DISPOSITIONED",
      payload: {
        schemaVersion: 2,
        receiptId: input.receiptId,
        decision: input.decision,
        previousViewId: authority.view.viewId,
        viewId: finalView.viewId,
        view: finalView,
        workspaceHash: authority.workspaceHash,
        reasonCodes: [...new Set(input.reasonCodes)].sort(),
        recovered: input.recovered === true,
        restoredWorkspace: input.restoredAuthority !== undefined,
      },
    });
    await this.persistProjection(input.agentId);
    return this.recordReceiptProofBestEffort(input.agentId, input.receiptId);
  }

  /**
   * Durably closes a rejected promotion before its typed CAS fault crosses the
   * Worker RPC boundary.  The terminal event is appended before best-effort
   * artifact cleanup so a kill at any later instruction can only recover the
   * same CONFLICTED receipt.  The current authority HEAD (not the stale
   * proposal base) is used as the disposition base, preserving its generation
   * and filesystem bytes while advancing exactly one session epoch.
   */
  private async appendPromotionCasConflict(
    input: ApplyPromotionParams,
    fault: WorkerFault,
  ): Promise<void> {
    let projection = await this.projection(input.agentId);
    const existing = projection.terminalReceipts.find(
      (receipt) =>
        receipt.receiptId === input.receiptId &&
        receipt.transitionId === input.transitionId,
    );
    if (existing) {
      if (existing.decision !== "CONFLICTED") {
        throw new WorkerFault(
          "TERMINAL_RECEIPT_CONFLICT",
          "Promotion CAS receipt is already bound to another terminal decision",
        );
      }
      return;
    }
    if (projection.terminalReceipts.some(
      (receipt) => receipt.transitionId === input.transitionId,
    )) {
      throw new WorkerFault(
        "TERMINAL_RECEIPT_CONFLICT",
        "Promotion transition is already bound to another terminal receipt",
      );
    }
    if (!projection.head) {
      throw new WorkerFault(
        "RECOVERY_REQUIRED",
        "Promotion CAS rejection has no authoritative disposition HEAD",
      );
    }
    // A WORKSPACE_CAS_MISMATCH caused by a stale expected hash is safe to
    // terminalize when the materialized authority still matches the Worker
    // HEAD.  An out-of-band mutation of the Worker-owned tree is corruption,
    // not a state winner, and remains explicit RECOVERY_REQUIRED rather than
    // fabricating a no-effect proof.
    const actualHash = await this.currentWorkspaceHash(input.agentId);
    if (actualHash !== projection.head.workspaceHash) {
      throw new WorkerFault(
        "RECOVERY_REQUIRED",
        "Promotion CAS rejection cannot bind a drifted authoritative workspace",
      );
    }
    await this.appendNonCommitDisposition({
      agentId: input.agentId,
      transitionId: input.transitionId,
      receiptId: input.receiptId,
      decision: "CONFLICTED",
      reasonCodes: [fault.code],
    });

    // Cleanup is deliberately after the atomic terminal event.  Recovery sees
    // the receipt first and can replay this deletion without changing its
    // decision, session View, or effect proof.
    await this.destroyRunArtifacts(input.agentId, input.transitionId).catch(() => undefined);
    projection = await this.persistProjection(input.agentId);
    if (!projection.terminalReceipts.some(
      (receipt) =>
        receipt.receiptId === input.receiptId &&
        receipt.transitionId === input.transitionId &&
        receipt.decision === "CONFLICTED",
    )) {
      throw new WorkerFault(
        "RECOVERY_REQUIRED",
        "Promotion CAS terminal event is not present in the rebuilt projection",
      );
    }
  }

  private deriveNonCommitView(input: {
    agentId: string;
    authority: { view: StateViewRef; workspaceHash: string };
    expectedViewId?: string;
    nextSessionEpoch?: number;
    legacyFinalView?: StateViewRef;
  }): StateViewRef {
    if (
      input.expectedViewId !== undefined &&
      input.expectedViewId !== input.authority.view.viewId
    ) {
      throw new WorkerFault(
        "VIEW_CAS_MISMATCH",
        "Authoritative View changed before non-commit disposition",
      );
    }
    const requestedEpoch =
      input.nextSessionEpoch ??
      input.legacyFinalView?.sessionEpoch ??
      input.authority.view.sessionEpoch + 1;
    if (requestedEpoch !== input.authority.view.sessionEpoch + 1) {
      throw new WorkerFault(
        "NEXT_VIEW_INVALID",
        "Non-commit disposition must advance exactly one session epoch",
      );
    }
    const finalView = makeStateView({
      agentId: input.agentId,
      headVersionId: input.authority.view.headVersionId,
      generation: input.authority.view.generation,
      versionedHash: input.authority.view.versionedHash,
      platformManagedHash: input.authority.view.platformManagedHash,
      liveStateHash: input.authority.workspaceHash,
      sessionEpoch: requestedEpoch,
      agentConfigVersion: input.authority.view.agentConfigVersion,
      policyVersion: input.authority.view.policyVersion,
    });
    if (
      input.legacyFinalView &&
      canonicalJson(input.legacyFinalView) !== canonicalJson(finalView)
    ) {
      throw new WorkerFault(
        "NEXT_VIEW_INVALID",
        "Client-authored finalView differs from the Worker-derived View",
      );
    }
    return finalView;
  }

  /**
   * Completes every durable, projection-neutral filesystem intent before the
   * ordinary run-state recovery loop observes the workspace. An intent is
   * always appended after a closed staging tree exists and before the
   * authoritative rename, so restart can either forward one exact tree or
   * fail closed. It never guesses from client input.
   */
  private async recoverPendingWorkerIntents(agentId: string): Promise<void> {
    for (;;) {
      const events = await this.log.read(agentId);
      const pending = events.find(
        (event) => this.isWorkerIntent(event) && !this.intentHasCompletion(event, events),
      );
      if (!pending) {
        for (const event of events.filter((candidate) => this.isWorkerIntent(candidate))) {
          if (this.intentHasCompletion(event, events)) {
            await this.cleanupCompletedIntent(event);
          }
        }
        return;
      }
      switch (pending.type) {
        case "AGENT_INITIALIZATION_PREPARED":
        case "LEGACY_ADOPTION_PREPARED":
          await this.finishInitialAuthorityIntent(pending);
          break;
        case "PLATFORM_STATE_REGENERATION_PREPARED":
          await this.finishPlatformRegenerationIntent(pending);
          break;
        case "AGENT_ARCHIVE_PREPARED":
          await this.finishArchiveIntent(pending);
          break;
        case "PROPOSAL_SEAL_PREPARED":
          await this.finishProposalSealIntent(pending);
          break;
        case "PROPOSAL_EXPORT_PREPARED":
          await this.finishProposalExportIntent(pending);
          break;
      }
    }
  }

  private isWorkerIntent(event: TransitionEvent): boolean {
    return [
      "AGENT_INITIALIZATION_PREPARED",
      "LEGACY_ADOPTION_PREPARED",
      "PLATFORM_STATE_REGENERATION_PREPARED",
      "AGENT_ARCHIVE_PREPARED",
      "PROPOSAL_SEAL_PREPARED",
      "PROPOSAL_EXPORT_PREPARED",
    ].includes(event.type);
  }

  private intentHasCompletion(intent: TransitionEvent, events: readonly TransitionEvent[]): boolean {
    const expected = (() => {
      switch (intent.type) {
        case "AGENT_INITIALIZATION_PREPARED": return "AGENT_INITIALIZED";
        case "LEGACY_ADOPTION_PREPARED": return "LEGACY_STATE_ADOPTED";
        case "PLATFORM_STATE_REGENERATION_PREPARED": return "PLATFORM_STATE_REGENERATED";
        case "AGENT_ARCHIVE_PREPARED": return "AGENT_ARCHIVED";
        case "PROPOSAL_SEAL_PREPARED": return "PROPOSAL_SEALED";
        case "PROPOSAL_EXPORT_PREPARED": return "PROPOSAL_EXPORTED";
        default: return null;
      }
    })();
    if (!expected) return false;
    const intentPayload = intent.payload as Record<string, unknown>;
    return events.some((event) => {
      if (
        event.sequence <= intent.sequence ||
        event.transitionId !== intent.transitionId ||
        event.type !== expected
      ) return false;
      if (intent.type === "PROPOSAL_EXPORT_PREPARED") {
        const payload = event.payload as Record<string, unknown>;
        return payload.proposalId === intentPayload.proposalId &&
          payload.exportVolumeId === intentPayload.exportVolumeId;
      }
      if (intent.type === "PROPOSAL_SEAL_PREPARED") {
        return (event.payload as Record<string, unknown>).proposalId === intentPayload.proposalId;
      }
      return true;
    });
  }

  private async finishInitialAuthorityIntent(intent: TransitionEvent): Promise<void> {
    if (
      intent.type !== "AGENT_INITIALIZATION_PREPARED" &&
      intent.type !== "LEGACY_ADOPTION_PREPARED"
    ) throw new WorkerFault("AUTHORITY_INTENT_INVALID", "Initial authority intent type is invalid");
    const events = await this.log.transition(intent.agentId, intent.transitionId);
    if (this.intentHasCompletion(intent, events)) {
      await this.cleanupCompletedIntent(intent);
      return;
    }
    const targetHash = intentString(intent, "workspaceHash");
    const versionId = intentString(intent, "versionId");
    const view = intentView(intent);
    if (view.agentId !== intent.agentId || view.liveStateHash !== targetHash) {
      throw new WorkerFault("AUTHORITY_INTENT_INVALID", "Initial View does not bind the staged tree");
    }
    const kind = intent.type === "AGENT_INITIALIZATION_PREPARED" ? "initialize" : "adopt";
    const staging = this.authorityOperationStagingPath(
      intent.agentId,
      intent.transitionId,
      kind,
    );
    const workspace = this.workspacePath(intent.agentId);
    const workspaceManifest = await this.manifestIfExists(workspace);
    if (workspaceManifest?.hash !== targetHash) {
      const staged = await this.manifestIfExists(staging);
      if (staged?.hash !== targetHash) {
        throw new WorkerFault(
          "RECOVERY_REQUIRED",
          "Initial authority intent has neither its exact staging tree nor applied workspace",
        );
      }
      if (workspaceManifest && workspaceManifest.entries.length > 0) {
        throw new WorkerFault(
          "RECOVERY_REQUIRED",
          "Initial authority intent would overwrite an unrelated authoritative tree",
        );
      }
      if (workspaceManifest) await rm(workspace, { recursive: true, force: true });
      await assertSameFilesystem(this.config.workspaceRoot, staging);
      await rename(staging, workspace);
    }
    if ((await this.manifestIfExists(workspace))?.hash !== targetHash) {
      throw new WorkerFault("RECOVERY_REQUIRED", "Initial authority rename did not apply its bound tree");
    }
    const snapshotId = await this.captureSnapshot(intent.agentId, targetHash);
    const payload = intent.payload as Record<string, unknown>;
    await this.log.append({
      agentId: intent.agentId,
      transitionId: intent.transitionId,
      type:
        intent.type === "AGENT_INITIALIZATION_PREPARED"
          ? "AGENT_INITIALIZED"
          : "LEGACY_STATE_ADOPTED",
      payload: {
        view,
        workspaceHash: targetHash,
        versionId,
        snapshotId,
        ...(intent.type === "LEGACY_ADOPTION_PREPARED"
          ? {
              sourceVolumeId:
                typeof payload.sourceVolumeId === "string" ? payload.sourceVolumeId : null,
              legacyAgentId:
                typeof payload.legacyAgentId === "string" ? payload.legacyAgentId : null,
            }
          : {}),
        recovered: true,
      },
    });
    await this.cleanupCompletedIntent(intent);
  }

  private async finishPlatformRegenerationIntent(intent: TransitionEvent): Promise<void> {
    if (intent.type !== "PLATFORM_STATE_REGENERATION_PREPARED") {
      throw new WorkerFault("AUTHORITY_INTENT_INVALID", "Platform intent type is invalid");
    }
    const events = await this.log.transition(intent.agentId, intent.transitionId);
    if (this.intentHasCompletion(intent, events)) {
      await this.cleanupCompletedIntent(intent);
      return;
    }
    const baseViewId = intentString(intent, "baseViewId");
    const baseHash = intentString(intent, "baseWorkspaceHash");
    const targetHash = intentString(intent, "workspaceHash");
    const view = intentView(intent);
    if (view.agentId !== intent.agentId || view.liveStateHash !== targetHash) {
      throw new WorkerFault("AUTHORITY_INTENT_INVALID", "Platform View does not bind the staged tree");
    }
    const projection = await this.projection(intent.agentId);
    if (
      projection.head?.view.viewId !== baseViewId ||
      projection.head.workspaceHash !== baseHash
    ) {
      throw new WorkerFault("RECOVERY_REQUIRED", "Platform intent base no longer matches event HEAD");
    }
    const workspace = this.workspacePath(intent.agentId);
    const staging = this.authorityOperationStagingPath(
      intent.agentId,
      intent.transitionId,
      "platform",
    );
    const backup = this.authorityOperationBackupPath(intent.agentId, intent.transitionId);
    const current = await this.manifestIfExists(workspace);
    const staged = await this.manifestIfExists(staging);
    const backedUp = await this.manifestIfExists(backup);
    if (current?.hash !== targetHash) {
      if (staged?.hash !== targetHash) {
        throw new WorkerFault("RECOVERY_REQUIRED", "Platform intent target staging tree is missing");
      }
      if (current?.hash === baseHash && !backedUp) {
        await rename(workspace, backup);
        await rename(staging, workspace);
      } else if (!current && backedUp?.hash === baseHash) {
        await rename(staging, workspace);
      } else {
        throw new WorkerFault(
          "RECOVERY_REQUIRED",
          "Platform workspace matches neither a forwardable base nor its bound target",
        );
      }
    }
    if ((await this.manifestIfExists(workspace))?.hash !== targetHash) {
      throw new WorkerFault("RECOVERY_REQUIRED", "Platform rename did not apply its bound target");
    }
    await this.log.append({
      agentId: intent.agentId,
      transitionId: intent.transitionId,
      type: "PLATFORM_STATE_REGENERATED",
      payload: { view, workspaceHash: targetHash, recovered: true },
    });
    await this.cleanupCompletedIntent(intent);
  }

  private async finishArchiveIntent(intent: TransitionEvent): Promise<void> {
    if (intent.type !== "AGENT_ARCHIVE_PREPARED") {
      throw new WorkerFault("AUTHORITY_INTENT_INVALID", "Archive intent type is invalid");
    }
    const events = await this.log.transition(intent.agentId, intent.transitionId);
    if (this.intentHasCompletion(intent, events)) return;
    const viewId = intentString(intent, "viewId");
    const targetHash = intentString(intent, "workspaceHash");
    const projection = await this.projection(intent.agentId);
    if (
      projection.head?.view.viewId !== viewId ||
      projection.head.workspaceHash !== targetHash
    ) {
      throw new WorkerFault("RECOVERY_REQUIRED", "Archive intent no longer matches event HEAD");
    }
    const workspace = this.workspacePath(intent.agentId);
    const archive = this.archivePath(intent.agentId, intent.transitionId);
    const current = await this.manifestIfExists(workspace);
    const archived = await this.manifestIfExists(archive);
    if (current && archived) {
      throw new WorkerFault("RECOVERY_REQUIRED", "Archive intent has two authority copies");
    }
    if (current) {
      if (current.hash !== targetHash) {
        throw new WorkerFault("RECOVERY_REQUIRED", "Archive source no longer matches intent");
      }
      await mkdir(path.dirname(archive), { recursive: true, mode: 0o700 });
      await rename(workspace, archive);
    } else if (archived?.hash !== targetHash) {
      throw new WorkerFault("RECOVERY_REQUIRED", "Archive destination is missing or corrupt");
    }
    await this.log.append({
      agentId: intent.agentId,
      transitionId: intent.transitionId,
      type: "AGENT_ARCHIVED",
      payload: { viewId, workspaceHash: targetHash, recovered: true },
    });
  }

  private async finishProposalSealIntent(intent: TransitionEvent): Promise<void> {
    if (intent.type !== "PROPOSAL_SEAL_PREPARED") {
      throw new WorkerFault("AUTHORITY_INTENT_INVALID", "Proposal seal intent type is invalid");
    }
    const events = await this.log.transition(intent.agentId, intent.transitionId);
    if (this.intentHasCompletion(intent, events)) {
      await this.cleanupCompletedIntent(intent);
      return;
    }
    const proposalId = intentString(intent, "proposalId");
    const artifactHash = intentString(intent, "artifactHash");
    const manifestHash = intentString(intent, "manifestHash");
    const baseViewId = intentString(intent, "baseViewId");
    const sourceVolumeId = intentString(intent, "sourceVolumeId");
    if (artifactHash !== manifestHash) {
      throw new WorkerFault("AUTHORITY_INTENT_INVALID", "Proposal intent hash domains differ");
    }
    const projection = await this.projection(intent.agentId);
    const transition = projection.transitions[intent.transitionId];
    if (
      !transition ||
      transition.kind !== "AGENT_COMMIT" ||
      transition.state !== "PREPARED" ||
      transition.baseViewId !== baseViewId
    ) {
      throw new WorkerFault("RECOVERY_REQUIRED", "Proposal intent no longer binds a prepared commit");
    }
    if (transition.runId !== null) {
      const candidateVolumeId = this.candidateVolumeId(transition.runId);
      if (
        transition.candidateVolumeId !== candidateVolumeId ||
        sourceVolumeId !== candidateVolumeId
      ) {
        throw new WorkerFault(
          "RECOVERY_REQUIRED",
          "Proposal intent source differs from its durable candidate ref",
        );
      }
      await this.bindExchangeRef({
        schemaVersion: 1,
        purpose: "candidate",
        volumeId: candidateVolumeId,
        agentId: intent.agentId,
        transitionId: intent.transitionId,
        runId: transition.runId,
        proposalId: null,
      });
    }
    if (this.config.requireRuntimeTeardownHandshake === true && transition.runId) {
      const teardown = transition.runtimeTeardownAgent;
      const recordedDigest = typeof (intent.payload as Record<string, unknown>)
        .runtimeTeardownDigest === "string"
        ? String((intent.payload as Record<string, unknown>).runtimeTeardownDigest)
        : null;
      if (!teardown || teardown.digest !== recordedDigest) {
        throw new WorkerFault(
          "RUNTIME_TEARDOWN_REQUIRED",
          "Seal recovery is fenced until Broker confirms Agent mount release",
        );
      }
    }
    const proposal = this.proposalPath(intent.agentId, proposalId);
    if ((await this.manifestIfExists(proposal))?.hash !== artifactHash) {
      throw new WorkerFault("RECOVERY_REQUIRED", "Immutable proposal import is missing or corrupt");
    }
    await makeTreeReadonly(proposal);
    const source = this.inboxPath(sourceVolumeId);
    await makeTreeWritable(source).catch(() => undefined);
    await rm(source, { recursive: true, force: true });
    if (await exists(source)) {
      throw new WorkerFault("RECOVERY_REQUIRED", "Candidate source survived proposal sealing");
    }
    const payload = intent.payload as Record<string, unknown>;
    await this.log.append({
      agentId: intent.agentId,
      transitionId: intent.transitionId,
      type: "PROPOSAL_SEALED",
      payload: {
        proposalId,
        baseViewId,
        artifactHash,
        manifestHash,
        changedPathsDigest: intentString(intent, "changedPathsDigest"),
        runtimeTeardownDigest:
          typeof payload.runtimeTeardownDigest === "string"
            ? payload.runtimeTeardownDigest
            : null,
        changedPaths: intentStrings(intent, "changedPaths"),
        staticFailures: intentStrings(intent, "staticFailures"),
        sourceVolumeId,
        sourceDestroyed: true,
        recovered: true,
      },
    });
    await this.cleanupCompletedIntent(intent);
  }

  private async finishProposalExportIntent(intent: TransitionEvent): Promise<void> {
    if (intent.type !== "PROPOSAL_EXPORT_PREPARED") {
      throw new WorkerFault("AUTHORITY_INTENT_INVALID", "Proposal export intent type is invalid");
    }
    const events = await this.log.transition(intent.agentId, intent.transitionId);
    if (this.intentHasCompletion(intent, events)) {
      await this.cleanupCompletedIntent(intent);
      return;
    }
    const proposalId = intentString(intent, "proposalId");
    const exportVolumeId = intentString(intent, "exportVolumeId");
    const artifactHash = intentString(intent, "artifactHash");
    const projection = await this.projection(intent.agentId);
    const proposal = projection.proposals[proposalId];
    const transition = projection.transitions[intent.transitionId];
    if (
      !proposal ||
      proposal.transitionId !== intent.transitionId ||
      proposal.artifactHash !== artifactHash ||
      proposal.state !== "SEALED"
    ) {
      throw new WorkerFault("RECOVERY_REQUIRED", "Export intent no longer binds a sealed proposal");
    }
    if (transition?.runId !== null && transition?.runId !== undefined) {
      const expectedExportVolumeId = this.verifierVolumeId(transition.runId);
      if (exportVolumeId !== expectedExportVolumeId) {
        throw new WorkerFault(
          "RECOVERY_REQUIRED",
          "Verifier export intent differs from its durable run-scoped ref",
        );
      }
      await this.bindExchangeRef({
        schemaVersion: 1,
        purpose: "verifier",
        volumeId: expectedExportVolumeId,
        agentId: intent.agentId,
        transitionId: intent.transitionId,
        runId: transition.runId,
        proposalId,
      });
    }
    const destination = this.inboxPath(exportVolumeId);
    const staging = this.proposalExportStagingPath(
      intent.agentId,
      intent.transitionId,
      exportVolumeId,
    );
    const exported = await this.manifestIfExists(destination);
    if (exported?.hash !== artifactHash) {
      const staged = await this.manifestIfExists(staging);
      if (exported || staged?.hash !== artifactHash) {
        throw new WorkerFault("RECOVERY_REQUIRED", "Verifier export intent has no exact source tree");
      }
      await rename(staging, destination);
    }
    await makeTreeReadonly(destination);
    await this.log.append({
      agentId: intent.agentId,
      transitionId: intent.transitionId,
      type: "PROPOSAL_EXPORTED",
      payload: { proposalId, exportVolumeId, artifactHash, recovered: true },
    });
    await this.cleanupCompletedIntent(intent);
  }

  private async cleanupCompletedIntent(intent: TransitionEvent): Promise<void> {
    let targets: string[] = [];
    switch (intent.type) {
      case "AGENT_INITIALIZATION_PREPARED": {
        targets = [this.authorityOperationStagingPath(intent.agentId, intent.transitionId, "initialize")];
        break;
      }
      case "LEGACY_ADOPTION_PREPARED": {
        targets = [this.authorityOperationStagingPath(intent.agentId, intent.transitionId, "adopt")];
        break;
      }
      case "PLATFORM_STATE_REGENERATION_PREPARED": {
        const backup = this.authorityOperationBackupPath(intent.agentId, intent.transitionId);
        const backupManifest = await this.manifestIfExists(backup);
        if (backupManifest && backupManifest.hash !== intentString(intent, "baseWorkspaceHash")) {
          throw new WorkerFault("RECOVERY_REQUIRED", "Platform backup differs from the durable base");
        }
        targets = [
          this.authorityOperationStagingPath(intent.agentId, intent.transitionId, "platform"),
          backup,
        ];
        break;
      }
      case "PROPOSAL_SEAL_PREPARED":
        targets = [this.proposalImportStagingPath(intent.agentId, intentString(intent, "proposalId"))];
        break;
      case "PROPOSAL_EXPORT_PREPARED":
        targets = [this.proposalExportStagingPath(
          intent.agentId,
          intent.transitionId,
          intentString(intent, "exportVolumeId"),
        )];
        break;
      case "AGENT_ARCHIVE_PREPARED": {
        const workspace = await this.manifestIfExists(this.workspacePath(intent.agentId));
        const archived = await this.manifestIfExists(
          this.archivePath(intent.agentId, intent.transitionId),
        );
        if (workspace || archived?.hash !== intentString(intent, "workspaceHash")) {
          throw new WorkerFault("RECOVERY_REQUIRED", "Archived authority differs from its event fact");
        }
        return;
      }
    }
    for (const target of targets) {
      await makeTreeWritable(target).catch(() => undefined);
      await rm(target, { recursive: true, force: true });
    }
  }

  private async manifestIfExists(target: string): Promise<WorkerManifest | null> {
    if (!(await exists(target))) return null;
    return this.buildManifest(target);
  }

  /** Startup-only GC. Every retained path must be reachable from the event log. */
  private async gcStartupOrphans(agentIds: readonly string[]): Promise<void> {
    const referencedBlobs = new Set<string>();
    const referencedProposals = new Set<string>();
    const referencedOperationArtifacts = new Set<string>();
    const referencedExportStaging = new Set<string>();
    for (const agentId of agentIds) {
      const events = await this.log.read(agentId);
      const rawProjection = rebuildWorkerProjection(agentId, events);
      for (const proposal of Object.values(rawProjection.proposals)) {
        if (proposal.state === "SEALED") {
          referencedProposals.add(this.proposalPath(agentId, proposal.proposalId));
        }
      }
      for (const event of events) {
        const payload = event.payload as Record<string, unknown>;
        if (
          event.type === "EVIDENCE_RECORDED" &&
          typeof payload.evidenceBlobHash === "string"
        ) referencedBlobs.add(payload.evidenceBlobHash);
        if (!this.isWorkerIntent(event) || this.intentHasCompletion(event, events)) continue;
        switch (event.type) {
          case "AGENT_INITIALIZATION_PREPARED":
            referencedOperationArtifacts.add(
              this.authorityOperationStagingPath(agentId, event.transitionId, "initialize"),
            );
            break;
          case "LEGACY_ADOPTION_PREPARED":
            referencedOperationArtifacts.add(
              this.authorityOperationStagingPath(agentId, event.transitionId, "adopt"),
            );
            break;
          case "PLATFORM_STATE_REGENERATION_PREPARED":
            referencedOperationArtifacts.add(
              this.authorityOperationStagingPath(agentId, event.transitionId, "platform"),
            );
            referencedOperationArtifacts.add(
              this.authorityOperationBackupPath(agentId, event.transitionId),
            );
            break;
          case "PROPOSAL_SEAL_PREPARED":
            referencedProposals.add(this.proposalPath(agentId, intentString(event, "proposalId")));
            break;
          case "PROPOSAL_EXPORT_PREPARED":
            referencedExportStaging.add(this.proposalExportStagingPath(
              agentId,
              event.transitionId,
              intentString(event, "exportVolumeId"),
            ));
            break;
          case "AGENT_ARCHIVE_PREPARED":
            break;
        }
      }
    }

    for (const entry of await this.readDirectory(this.config.workspaceRoot)) {
      if (!entry.isDirectory() || !entry.name.startsWith(".cg-authority-")) continue;
      const target = path.join(this.config.workspaceRoot, entry.name);
      if (referencedOperationArtifacts.has(target)) continue;
      await makeTreeWritable(target).catch(() => undefined);
      await rm(target, { recursive: true, force: true });
    }

    const proposalRoot = path.join(this.config.controlRoot, "proposals");
    for (const agentEntry of await this.readDirectory(proposalRoot)) {
      if (!agentEntry.isDirectory()) continue;
      const agentRoot = path.join(proposalRoot, agentEntry.name);
      for (const proposalEntry of await this.readDirectory(agentRoot)) {
        const target = path.join(agentRoot, proposalEntry.name);
        if (proposalEntry.isDirectory() && referencedProposals.has(target)) continue;
        await makeTreeWritable(target).catch(() => undefined);
        await rm(target, { recursive: true, force: true });
      }
    }

    for (const entry of await this.readDirectory(this.config.inboxRoot)) {
      if (!entry.name.startsWith(".cg-export-")) continue;
      const target = path.join(this.config.inboxRoot, entry.name);
      if (referencedExportStaging.has(target)) continue;
      await makeTreeWritable(target).catch(() => undefined);
      await rm(target, { recursive: true, force: true });
    }
    await this.evidenceBlobs.pruneUnreferenced(referencedBlobs);
  }

  private async readDirectory(root: string) {
    try {
      return await readdir(root, { withFileTypes: true });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
  }

  /**
   * Deletes all run-owned bytes while retaining only bounded proposal/evidence
   * metadata in the append-only fact source. The event is appended only after
   * every known path is absent, so receipt retention claims remain auditable.
   */
  private async destroyRunArtifacts(
    agentId: string,
    transitionId: string,
  ): Promise<WorkerProjection> {
    let projection = await this.projection(agentId);
    const transition = projection.transitions[transitionId];
    if (!transition) {
      throw new WorkerFault("TRANSITION_STATE_INVALID", "Run was not prepared");
    }
    if (transition.artifactsDestroyed) return projection;
    this.assertRuntimeTeardown(projection, transitionId, "ALL");
    const proposal = transition.proposalId
      ? projection.proposals[transition.proposalId]
      : undefined;
    const exchangeIds = [
      transition.candidateVolumeId,
      ...(proposal?.exportVolumeIds ?? []),
      // Legacy v1 exports were not evented; the product naming contract is
      // deterministic, so recovery can still remove that one known path.
      transition.runId ? `verify-${transition.runId}` : null,
    ].filter((value): value is string => typeof value === "string");
    for (const volumeId of [...new Set(exchangeIds)].sort()) {
      const target = this.inboxPath(volumeId);
      await makeTreeWritable(target).catch(() => undefined);
      await rm(target, { recursive: true, force: true });
      if (await exists(target)) {
        throw new WorkerFault("RUN_ARTIFACT_CLEANUP_FAILED", "Exchange artifact still exists");
      }
    }
    if (proposal && proposal.state !== "DESTROYED") {
      const target = this.proposalPath(agentId, proposal.proposalId);
      await makeTreeWritable(target).catch(() => undefined);
      await rm(target, { recursive: true, force: true });
      if (await exists(target)) {
        throw new WorkerFault("RUN_ARTIFACT_CLEANUP_FAILED", "Sealed proposal still exists");
      }
    }
    await this.log.append({
      agentId,
      transitionId,
      type: "RUN_ARTIFACTS_DESTROYED",
      payload: {
        proposalId: proposal?.proposalId ?? null,
        exchangeArtifactCount: new Set(exchangeIds).size,
        sealedArtifactDestroyed: Boolean(proposal),
      },
    });
    projection = await this.persistProjection(agentId);
    return projection;
  }

  private async recoverIncompleteTransition(
    agentId: string,
    transitionId: string,
  ): Promise<WorkerProjection> {
    const projection = await this.projection(agentId);
    const transition = projection.transitions[transitionId];
    if (!transition) return projection;
    const existing = projection.terminalReceipts.find(
      (receipt) => receipt.transitionId === transitionId,
    );
    if (existing) return projection;
    if (
      !["PREPARED", "SEALED", "EVIDENCED", "PERMITTED", "CANCELLED", "ROLLED_BACK"]
        .includes(transition.state)
    ) {
      throw new WorkerFault(
        "RECOVERY_REQUIRED",
        `Transition ${transitionId} is beyond deterministic abort recovery`,
      );
    }
    if (!projection.head) {
      throw new WorkerFault("RECOVERY_REQUIRED", "Incomplete run has no authoritative HEAD");
    }
    const actualHash = await this.currentWorkspaceHash(agentId);
    if (actualHash !== projection.head.workspaceHash) {
      if (transition.state === "ROLLED_BACK" && actualHash === transition.baseWorkspaceHash) {
        const baseView = await this.findStateView(agentId, transition.baseViewId);
        if (!baseView || baseView.liveStateHash !== transition.baseWorkspaceHash) {
          throw new WorkerFault(
            "RECOVERY_REQUIRED",
            "Legacy rollback base View cannot be reconstructed",
          );
        }
        await this.deleteBackup(agentId, transitionId);
        await rm(this.stagingPath(agentId, transitionId), { recursive: true, force: true });
        await this.destroyRunArtifacts(agentId, transitionId);
        return this.appendNonCommitDisposition({
          agentId,
          transitionId,
          receiptId: transition.runId ?? transitionId,
          decision: "ABORTED",
          reasonCodes: ["LEGACY_ROLLBACK_TERMINAL_RECOVERED"],
          recovered: true,
          restoredAuthority: {
            view: baseView,
            workspaceHash: transition.baseWorkspaceHash,
          },
        });
      }
      throw new WorkerFault(
        "RECOVERY_REQUIRED",
        "Incomplete run workspace does not match the current authoritative HEAD",
      );
    }
    await this.deleteBackup(agentId, transitionId);
    await rm(this.stagingPath(agentId, transitionId), { recursive: true, force: true });
    await this.destroyRunArtifacts(agentId, transitionId);
    const receiptId = transition.runId ?? transitionId;
    return this.appendNonCommitDisposition({
      agentId,
      transitionId,
      receiptId,
      decision: "ABORTED",
      reasonCodes: [
        transition.state === "CANCELLED"
          ? "RUN_CANCELLED_RECOVERED"
          : `INCOMPLETE_${transition.state}_RECOVERED`,
      ],
      recovered: true,
    });
  }

  private async findStateView(
    agentId: string,
    viewId: string | null,
  ): Promise<StateViewRef | null> {
    if (!viewId) return null;
    const projection = await this.projection(agentId);
    if (projection.head?.view.viewId === viewId) return projection.head.view;
    const events = await this.log.read(agentId);
    for (const event of [...events].reverse()) {
      const payload = event.payload as Record<string, unknown>;
      for (const candidate of [payload.view, payload.nextView, payload.restoredView]) {
        if (!candidate || typeof candidate !== "object") continue;
        const view = candidate as StateViewRef;
        if (view.viewId !== viewId) continue;
        try {
          assertView(view);
          return view;
        } catch {
          throw new WorkerFault("RECOVERY_REQUIRED", "Historical StateView is malformed");
        }
      }
    }
    return null;
  }

  private async recordReceiptProof(
    agentId: string,
    receiptId: string,
  ): Promise<WorkerProjection> {
    const projection = await this.projection(agentId);
    if (projection.receiptProofs[receiptId]) return projection;
    const terminalReceipt = projection.terminalReceipts.find(
      (receipt) => receipt.receiptId === receiptId,
    );
    if (!terminalReceipt || !terminalReceipt.viewId) {
      throw new WorkerFault("RECEIPT_PROOF_PENDING", "Terminal receipt is not available");
    }
    const transition = projection.transitions[terminalReceipt.transitionId];
    if (!transition || !transition.baseViewId) {
      throw new WorkerFault("RECEIPT_PROOF_BINDING_MISSING", "Transition base View is missing");
    }
    const proposal = transition.proposalId
      ? projection.proposals[transition.proposalId]
      : undefined;
    const evidence = transition.proposalId
      ? projection.evidence[transition.proposalId]
      : undefined;
    const permit = transition.permitId
      ? projection.permits[transition.permitId]
      : undefined;
    const agentEvents = await this.log.read(agentId);
    const terminalEventIndex = agentEvents.findIndex(
      (event) => event.eventId === terminalReceipt.eventId,
    );
    const terminalEvent = agentEvents[terminalEventIndex];
    if (!terminalEvent) {
      throw new WorkerFault("RECEIPT_PROOF_BINDING_MISSING", "Terminal event is missing");
    }
    const permitState =
      permit?.state === "CONSUMED" || permit?.state === "REVOKED"
        ? permit.state
        : null;
    const receiptCommon = {
      receiptId,
      runId: transition.runId ?? receiptId,
      agentId,
      transitionId: terminalReceipt.transitionId,
      decision: terminalReceipt.decision,
      baseViewId: transition.baseViewId,
      finalViewId: terminalReceipt.viewId,
      baseGeneration: transition.baseGeneration,
      nextGeneration: terminalReceipt.view.generation,
      baseWorkspaceHash: transition.baseWorkspaceHash,
      finalWorkspaceHash: terminalReceipt.workspaceHash,
      proposalId: proposal?.proposalId ?? null,
      proposalArtifactHash: proposal?.artifactHash ?? null,
      verifierInputHash: evidence?.verifierInputHash ?? null,
      promotionSourceHash: permit?.targetArtifactHash ?? null,
      evaluationContextHash: evidence?.evaluationContextHash ?? null,
      evidenceDigest: evidence?.evidenceDigest ?? null,
      permitId: permit?.permitId ?? null,
      permitState,
      sourceRevision: evidence?.sourceRevision ?? this.config.sourceRevision ?? "unverified",
    };
    const receipt: AuthorityReceiptRecord =
      terminalReceipt.dispositionBaseViewId != null &&
      terminalReceipt.dispositionBaseGeneration != null &&
      terminalReceipt.dispositionBaseWorkspaceHash != null
        ? {
            schemaVersion: 2,
            ...receiptCommon,
            dispositionBaseViewId: terminalReceipt.dispositionBaseViewId,
            dispositionBaseGeneration: terminalReceipt.dispositionBaseGeneration,
            dispositionBaseWorkspaceHash: terminalReceipt.dispositionBaseWorkspaceHash,
          }
        : { schemaVersion: 1, ...receiptCommon };
    const bundle = this.signingKeys.sign(
      receipt,
      terminalEvent,
      agentEvents.slice(0, terminalEventIndex + 1),
    );
    const verification = verifyAuthorityReceiptProof(bundle);
    if (!verification.valid) {
      throw new WorkerFault(
        "RECEIPT_PROOF_BINDING_INVALID",
        verification.reason ?? "Authority receipt proof failed local verification",
      );
    }
    await this.log.append({
      agentId,
      transitionId: terminalReceipt.transitionId,
      type: "RECEIPT_PROOF_RECORDED",
      payload: {
        schemaVersion: 2,
        receiptId,
        terminalEventId: terminalEvent.eventId,
        // Keep the append-only log compact. Embedding a genesis-to-terminal
        // chain here would recursively embed every earlier proof event and
        // grow exponentially. Projection rebuild deterministically rejoins
        // this signed envelope with the already-verified event prefix.
        receipt: bundle.receipt,
        proof: bundle.proof,
        publicKeyPem: bundle.publicKeyPem,
      },
    });
    return this.persistProjection(agentId);
  }

  private async replaceWorkspace(
    agentId: string,
    transitionId: string,
    source: string,
    targetHash: string,
    expectedBaseHash: string,
  ): Promise<void> {
    const workspace = this.workspacePath(agentId);
    const staging = this.stagingPath(agentId, transitionId);
    const backup = this.backupPath(agentId, transitionId);
    await rm(staging, { recursive: true, force: true });
    const copied = await this.copyTree(source, staging);
    if (copied.hash !== targetHash) throw new WorkerFault("PROMOTION_SOURCE_CHANGED", "Source digest changed");
    await assertSameFilesystem(this.config.workspaceRoot, staging);
    const currentHash = await this.currentWorkspaceHash(agentId);
    if (currentHash !== expectedBaseHash) {
      throw new WorkerFault("WORKSPACE_CAS_MISMATCH", "Workspace changed before rename-swap");
    }
    if (await exists(backup)) throw new WorkerFault("BACKUP_ALREADY_EXISTS", "Transition backup exists");
    if (await exists(workspace)) {
      await rename(workspace, backup);
      // This event is appended only after the old authoritative tree is
      // durably addressable at the transition-scoped backup path. Recovery
      // can therefore restore the exact base tree after a process SIGKILL.
      await this.log.append({
        agentId,
        transitionId,
        type: "BACKUP_CREATED",
        payload: { baseWorkspaceHash: expectedBaseHash },
      });
    }
    try {
      await rename(staging, workspace);
    } catch (error) {
      if (await exists(backup)) await rename(backup, workspace);
      throw error;
    }
    const applied = await this.buildManifest(workspace);
    if (applied.hash !== targetHash) throw new WorkerFault("PROMOTION_DIGEST_MISMATCH", "Applied tree changed");
  }

  private async finishAppliedTransition(input: {
    agentId: string;
    transitionId: string;
    targetHash: string;
    nextView: StateViewRef;
    versionId: string;
    receiptId: string;
    rollbackTargetVersionId?: string;
  }): Promise<void> {
    if (input.nextView.liveStateHash !== input.targetHash) {
      throw new WorkerFault("VIEW_WORKSPACE_HASH_MISMATCH", "Next view does not bind applied state");
    }
    const snapshotId = await this.captureSnapshot(input.agentId, input.targetHash);
    await this.log.append({
      agentId: input.agentId,
      transitionId: input.transitionId,
      type: "WORKSPACE_APPLIED",
      payload: { view: input.nextView, workspaceHash: input.targetHash },
    });
    if (input.rollbackTargetVersionId) {
      // A rollback is a new forward event, not history mutation. Keep a
      // distinct durable crash boundary while WORKSPACE_APPLIED remains the
      // canonical HEAD transition used by projection rebuild.
      await this.log.append({
        agentId: input.agentId,
        transitionId: input.transitionId,
        type: "ROLLBACK_APPLIED",
        payload: {
          workspaceHash: input.targetHash,
          rollbackTargetVersionId: input.rollbackTargetVersionId,
        },
      });
    }
    await this.log.append({
      agentId: input.agentId,
      transitionId: input.transitionId,
      type: "TRANSITION_ACKNOWLEDGED",
      payload: {
        versionId: input.versionId,
        snapshotId,
        receiptId: input.receiptId,
        ...(input.rollbackTargetVersionId
          ? { rollbackTargetVersionId: input.rollbackTargetVersionId }
          : {}),
      },
    });
  }

  private async captureSnapshot(agentId: string, expectedHash: string): Promise<string> {
    const destination = this.snapshotPath(agentId, expectedHash);
    if (await exists(destination)) {
      if ((await this.buildManifest(destination)).hash !== expectedHash) {
        throw new WorkerFault("SNAPSHOT_DIGEST_MISMATCH", "Existing snapshot is corrupt");
      }
      return expectedHash;
    }
    await mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
    const temporary = `${destination}.tmp-${randomUUID()}`;
    const copied = await this.copyTree(this.workspacePath(agentId), temporary);
    if (copied.hash !== expectedHash) throw new WorkerFault("SNAPSHOT_DIGEST_MISMATCH", "Snapshot changed");
    await makeTreeReadonly(temporary);
    await rename(temporary, destination);
    return expectedHash;
  }

  private async restoreBackup(agentId: string, transitionId: string, expectedHash: string): Promise<void> {
    const workspace = this.workspacePath(agentId);
    const backup = this.backupPath(agentId, transitionId);
    if (await exists(backup)) {
      // Validate the recovery source before moving the current authoritative
      // name.  A corrupt/missing backup must never displace the only remaining
      // workspace and then be mislabeled as a completed rollback.
      if ((await this.buildManifest(backup)).hash !== expectedHash) {
        throw new WorkerFault("RECOVERY_REQUIRED", "Backup does not match the admitted base hash");
      }
      const failed = `${workspace}.failed-${randomUUID()}`;
      const movedWorkspace = await exists(workspace);
      if (movedWorkspace) await rename(workspace, failed);
      try {
        await rename(backup, workspace);
      } catch (error) {
        if (movedWorkspace && !(await exists(workspace)) && (await exists(failed))) {
          await rename(failed, workspace).catch(() => undefined);
        }
        throw new WorkerFault(
          "RECOVERY_REQUIRED",
          `Backup rename failed: ${errorReason(error)}`,
        );
      }
      await makeTreeWritable(failed).catch(() => undefined);
      await rm(failed, { recursive: true, force: true }).catch(() => undefined);
    }
    if ((await this.currentWorkspaceHash(agentId)) !== expectedHash) {
      throw new WorkerFault("RECOVERY_REQUIRED", "Backup cannot restore expected workspace hash");
    }
    await rm(this.stagingPath(agentId, transitionId), { recursive: true, force: true });
  }

  private async deleteBackup(agentId: string, transitionId: string): Promise<void> {
    const backup = this.backupPath(agentId, transitionId);
    await makeTreeWritable(backup).catch(() => undefined);
    await rm(backup, { recursive: true, force: true });
  }

  private async hydrateEvidenceProjection(projection: WorkerProjection): Promise<void> {
    for (const [proposalId, projected] of Object.entries(projection.evidence)) {
      if (!projected.evidenceBlob) continue;
      const bundle = await this.loadEvidenceBlob(projection, proposalId);
      projected.checks = bundle.checks.map((check) => ({ ...check }));
      if (isRecord(bundle.evaluationContext)) {
        projected.sourceRevision =
          typeof bundle.evaluationContext.sourceRevision === "string"
            ? bundle.evaluationContext.sourceRevision
            : null;
        projected.policyHash =
          typeof bundle.evaluationContext.policyHash === "string"
            ? bundle.evaluationContext.policyHash
            : null;
      }
    }
  }

  private async loadEvidenceBlob(
    projection: WorkerProjection,
    proposalId: string,
  ): Promise<StoredEvidenceBundleV2> {
    const projected = projection.evidence[proposalId];
    const proposal = projection.proposals[proposalId];
    const transition = projected
      ? projection.transitions[projected.transitionId]
      : undefined;
    if (!transition || !proposal || !projected?.evidenceBlob) {
      throw new WorkerFault(
        "EVIDENCE_BLOB_REQUIRED",
        "Projected evidence requires a content-addressed blob",
      );
    }

    let raw: unknown;
    try {
      raw = await this.evidenceBlobs.get(projected.evidenceBlob.blobId);
    } catch (error) {
      throw new WorkerFault(
        "EVIDENCE_BLOB_INVALID",
        `Evidence blob is missing or corrupt: ${errorReason(error)}`,
      );
    }
    if (!isRecord(raw) || raw.schemaVersion !== 2) {
      throw new WorkerFault("EVIDENCE_BLOB_INVALID", "Evidence blob schema is invalid");
    }
    const canonicalSize = Buffer.byteLength(canonicalJson(raw), "utf8");
    if (canonicalSize !== projected.evidenceBlob.sizeBytes) {
      throw new WorkerFault("EVIDENCE_BLOB_INVALID", "Evidence blob size does not match its event reference");
    }
    const bundle = raw as unknown as StoredEvidenceBundleV2;
    if (
      bundle.agentId !== projection.agentId ||
      bundle.transitionId !== transition.transitionId ||
      bundle.proposalId !== proposalId ||
      bundle.artifactHash !== proposal.artifactHash ||
      bundle.evaluationContextHash !== projected.evaluationContextHash ||
      bundle.evidenceDigest !== projected.evidenceDigest ||
      bundle.verifierInputHash !== projected.verifierInputHash ||
      bundle.checkResultsHash !== projected.checkResultsHash ||
      bundle.coverage !== projected.coverage ||
      bundle.requiredChecksPassed !== projected.requiredChecksPassed ||
      !Array.isArray(bundle.checks) ||
      bundle.checks.length !== projected.checkCount ||
      !bundle.checks.every(isRecordedCheck)
    ) {
      throw new WorkerFault(
        "EVIDENCE_BLOB_BINDING_MISMATCH",
        "Evidence blob fields do not bind the immutable event summary",
      );
    }
    if (bundle.evaluationContext === null) {
      if (
        bundle.verifierInputHash !== null ||
        bundle.checkResultsHash !== null ||
        bundle.coverage !== "unavailable" ||
        bundle.requiredChecksPassed ||
        bundle.checks.length !== 0 ||
        transition.runId !== null
      ) {
        throw new WorkerFault(
          "EVIDENCE_INCOMPLETE",
          "Product Agent run is missing its typed evidence fields",
        );
      }
      return bundle;
    }
    if (
      !isRecord(bundle.evaluationContext) ||
      !isRecord(bundle.evaluationContext.baseView) ||
      typeof bundle.verifierInputHash !== "string" ||
      typeof bundle.checkResultsHash !== "string"
    ) {
      throw new WorkerFault(
        "EVIDENCE_INCOMPLETE",
        "Typed evidence blob is incomplete",
      );
    }
    const context = bundle.evaluationContext as unknown as RecordedEvaluationContext;
    const computedCheckResultsHash = sha256Canonical(bundle.checks);
    const computedEvidenceDigest = sha256Canonical({
      schemaVersion: 1,
      proposalId: bundle.proposalId,
      artifactHash: bundle.artifactHash,
      evaluationContextHash: bundle.evaluationContextHash,
      checkResultsHash: computedCheckResultsHash,
    });
    const checksPassed = bundle.checks.every(
      (check) => check.status === "PASS" && check.exitCode === 0 && !check.timedOut,
    );
    if (
      (transition.runId !== null && context.runId !== transition.runId) ||
      context.agentId !== projection.agentId ||
      context.proposalId !== proposalId ||
      context.baseView?.viewId !== transition.baseViewId ||
      sha256Canonical(context) !== bundle.evaluationContextHash ||
      bundle.verifierInputHash !== proposal.artifactHash ||
      computedCheckResultsHash !== bundle.checkResultsHash ||
      computedEvidenceDigest !== bundle.evidenceDigest ||
      (bundle.coverage === "complete" && bundle.checks.length > 0 && checksPassed) !==
        bundle.requiredChecksPassed ||
      projected.sourceRevision !== context.sourceRevision ||
      projected.policyHash !== context.policyHash
    ) {
      throw new WorkerFault(
        "EVIDENCE_BLOB_BINDING_MISMATCH",
        "Stored trusted-check evidence failed its proposal or context binding",
      );
    }
    return bundle;
  }

  private async assertEvidenceBlobBindings(
    input: IssuePermitParams,
    projection: WorkerProjection,
  ): Promise<void> {
    const transition = projection.transitions[input.transitionId];
    const bundle = await this.loadEvidenceBlob(projection, input.proposalId);
    if (
      !transition ||
      bundle.agentId !== input.agentId ||
      bundle.transitionId !== input.transitionId ||
      bundle.evaluationContextHash !== input.evaluationContextHash ||
      bundle.evidenceDigest !== input.evidenceDigest
    ) {
      throw new WorkerFault(
        "EVIDENCE_BLOB_BINDING_MISMATCH",
        "Permit inputs do not bind the stored evidence bundle",
      );
    }
    const requiresProductEvidence =
      transition.runId !== null ||
      (transition.kind === "AGENT_COMMIT" &&
        this.config.requireVerifiedSourceRevision === true);
    if (
      requiresProductEvidence &&
      (bundle.coverage !== "complete" ||
        bundle.requiredChecksPassed !== true ||
        bundle.checks.length === 0 ||
        !bundle.checks.every(
          (check) => check.status === "PASS" && check.exitCode === 0 && !check.timedOut,
        ))
    ) {
      throw new WorkerFault(
        "EVIDENCE_INCOMPLETE",
        "Product Agent permit requires complete passing trusted-check evidence",
      );
    }
    if (requiresProductEvidence) {
      if (!bundle.evaluationContext) {
        throw new WorkerFault(
          "EVIDENCE_INCOMPLETE",
          "Product Agent permit requires an EvaluationContext",
        );
      }
      const contractFailure = validateWorkerEvidenceContract({
        context: bundle.evaluationContext,
        checks: bundle.checks,
        coverage: bundle.coverage,
        requiredChecksPassed: bundle.requiredChecksPassed,
        sourceRevision: this.config.sourceRevision ?? "unverified",
        requireEnvironmentPins: this.config.requireVerifiedSourceRevision === true,
        ...(this.config.expectedCheckBundleHash
          ? { expectedCheckBundleHash: this.config.expectedCheckBundleHash }
          : {}),
        ...(this.config.expectedVerifierImageDigest
          ? { expectedVerifierImageDigest: this.config.expectedVerifierImageDigest }
          : {}),
        ...(this.config.expectedVerifierConfigHash
          ? { expectedVerifierConfigHash: this.config.expectedVerifierConfigHash }
          : {}),
        ...(this.config.expectedResourcePolicyHash
          ? { expectedResourcePolicyHash: this.config.expectedResourcePolicyHash }
          : {}),
      });
      if (contractFailure) {
        throw new WorkerFault(contractFailure.code, contractFailure.message);
      }
    }
  }

  private assertLegacyNextView(
    legacyNextView: StateViewRef | undefined,
    workerDerivedView: StateViewRef,
  ): void {
    if (!legacyNextView) return;
    if (canonicalJson(legacyNextView) !== canonicalJson(workerDerivedView)) {
      throw new WorkerFault(
        "NEXT_VIEW_INVALID",
        "Client-authored nextView differs from the Worker-derived authoritative View",
      );
    }
  }

  private assertRunNotCancelled(
    projection: WorkerProjection,
    transitionId: string,
  ): void {
    if (projection.transitions[transitionId]?.state === "CANCELLED") {
      throw new WorkerFault("RUN_CANCELLED", "The authoritative run lease was cancelled");
    }
  }

  private assertRuntimeTeardown(
    projection: WorkerProjection,
    transitionId: string,
    scope: "AGENT" | "ALL",
  ): void {
    if (this.config.requireRuntimeTeardownHandshake !== true) return;
    const transition = projection.transitions[transitionId];
    if (!transition?.runId) return;
    const attestation = scope === "AGENT"
      ? transition.runtimeTeardownAgent
      : transition.runtimeTeardownAll;
    if (!attestation) {
      throw new WorkerFault(
        "RUNTIME_TEARDOWN_REQUIRED",
        `${scope} Broker container/mount teardown has not been durably recorded`,
      );
    }
  }

  private async assertCurrentCas(
    agentId: string,
    projection: WorkerProjection,
    expectedViewId: string,
    expectedWorkspaceHash: string,
  ): Promise<void> {
    if (projection.head && projection.head.view.viewId !== expectedViewId) {
      throw new WorkerFault("VIEW_CAS_MISMATCH", "Current head ViewId differs from permit");
    }
    const actualHash = await this.currentWorkspaceHash(agentId);
    if (actualHash !== expectedWorkspaceHash) {
      throw new WorkerFault("WORKSPACE_CAS_MISMATCH", "Current workspace hash differs from permit");
    }
  }

  private buildManifest(root: string): Promise<WorkerManifest> {
    return buildWorkerManifest(root, this.manifestOptions);
  }

  private copyTree(source: string, destination: string): Promise<WorkerManifest> {
    return copyClosedTree(source, destination, this.manifestOptions);
  }

  private async currentWorkspaceHash(agentId: string): Promise<string> {
    const workspace = this.workspacePath(agentId);
    if (!(await exists(workspace))) {
      await mkdir(workspace, { recursive: false, mode: 0o700 });
    }
    return (await this.buildManifest(workspace)).hash;
  }

  private async persistProjection(agentId: string): Promise<WorkerProjection> {
    const projection = await this.projection(agentId);
    await this.projections.writeHead(projection);
    return projection;
  }

  private lastEvent(events: TransitionEvent[], type: TransitionEvent["type"]): TransitionEvent | null {
    return [...events].reverse().find((event) => event.type === type) ?? null;
  }

  private workspacePath(agentId: string): string {
    this.assertIdentifier(agentId);
    return path.join(this.config.workspaceRoot, agentId);
  }

  private stagingPath(agentId: string, transitionId: string): string {
    this.assertIdentifier(agentId);
    this.assertIdentifier(transitionId);
    return path.join(this.config.workspaceRoot, `.cg-stage-${agentId}-${transitionId}`);
  }

  private backupPath(agentId: string, transitionId: string): string {
    this.assertIdentifier(agentId);
    this.assertIdentifier(transitionId);
    return path.join(this.config.workspaceRoot, `.cg-backup-${agentId}-${transitionId}`);
  }

  private operationPathToken(...parts: string[]): string {
    for (const part of parts) this.assertIdentifier(part);
    return createHash("sha256").update(canonicalJson(parts)).digest("hex");
  }

  private authorityOperationStagingPath(
    agentId: string,
    operationId: string,
    kind: "initialize" | "adopt" | "platform",
  ): string {
    const token = this.operationPathToken(agentId, operationId, kind);
    return path.join(this.config.workspaceRoot, `.cg-authority-${kind}-stage-${token}`);
  }

  private authorityOperationBackupPath(agentId: string, operationId: string): string {
    const token = this.operationPathToken(agentId, operationId, "platform-backup");
    return path.join(this.config.workspaceRoot, `.cg-authority-platform-backup-${token}`);
  }

  private archivePath(agentId: string, operationId: string): string {
    const token = this.operationPathToken(agentId, operationId, "archive").slice(0, 32);
    return path.join(this.config.workspaceRoot, ".deleted", `${agentId}-${token}`);
  }

  private candidateVolumeId(runId: string): string {
    this.assertIdentifier(runId);
    const volumeId = `candidate-${runId}`;
    this.assertIdentifier(volumeId);
    return volumeId;
  }

  private verifierVolumeId(runId: string): string {
    this.assertIdentifier(runId);
    const volumeId = `verify-${runId}`;
    this.assertIdentifier(volumeId);
    return volumeId;
  }

  private exchangeRefBindingPath(volumeId: string): string {
    this.assertIdentifier(volumeId);
    return path.join(this.config.controlRoot, "exchange-ref-bindings", `${volumeId}.json`);
  }

  private exchangeRefBlockedPath(volumeId: string): string {
    this.assertIdentifier(volumeId);
    return path.join(this.config.controlRoot, "exchange-ref-bindings", `${volumeId}.blocked`);
  }

  /**
   * Claims or verifies an immutable exchange-ref binding. The file lives in
   * the Worker-only control volume and is intentionally retained after run
   * cleanup, making a run ID a one-shot namespace across Agents and restarts.
   */
  private async bindExchangeRef(
    binding: ExchangeRefBinding,
  ): Promise<"CREATED" | "EXISTING"> {
    this.assertIdentifier(binding.volumeId);
    this.assertIdentifier(binding.agentId);
    this.assertIdentifier(binding.transitionId);
    this.assertIdentifier(binding.runId);
    if (binding.proposalId !== null) this.assertIdentifier(binding.proposalId);
    return this.serialExchangeRef(binding.volumeId, async () => {
      const destination = this.exchangeRefBindingPath(binding.volumeId);
      await mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
      try {
        await writeFile(destination, canonicalJson(binding) + "\n", {
          encoding: "utf8",
          mode: 0o400,
          flag: "wx",
        });
        return "CREATED";
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      }
      let stored: unknown;
      try {
        stored = JSON.parse(await readFile(destination, "utf8"));
      } catch {
        throw new WorkerFault(
          "EXCHANGE_REF_BINDING_CORRUPT",
          "Exchange ref ownership record is unreadable",
        );
      }
      if (canonicalJson(stored) !== canonicalJson(binding)) {
        throw new WorkerFault(
          "EXCHANGE_REF_OCCUPIED",
          "Exchange ref is already bound to a different Agent, run or proposal",
        );
      }
      if (await exists(this.exchangeRefBlockedPath(binding.volumeId))) {
        throw new WorkerFault(
          "EXCHANGE_REF_OCCUPIED",
          "Exchange ref was permanently blocked after unowned bytes were observed",
        );
      }
      return "EXISTING";
    });
  }

  private async blockExchangeRef(volumeId: string): Promise<void> {
    const destination = this.exchangeRefBlockedPath(volumeId);
    try {
      await writeFile(destination, "blocked\n", {
        encoding: "utf8",
        mode: 0o400,
        flag: "wx",
      });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
  }

  private inboxPath(sourceVolumeId: string): string {
    this.assertIdentifier(sourceVolumeId);
    return path.join(this.config.inboxRoot, sourceVolumeId);
  }

  private legacyWorkspacePath(agentId: string): string {
    this.assertIdentifier(agentId);
    if (!this.config.legacyWorkspaceRoot) {
      throw new WorkerFault("LEGACY_STATE_UNAVAILABLE", "No read-only legacy workspace root is configured");
    }
    return path.join(this.config.legacyWorkspaceRoot, agentId);
  }

  private proposalPath(agentId: string, proposalId: string): string {
    this.assertIdentifier(agentId);
    this.assertIdentifier(proposalId);
    return path.join(this.config.controlRoot, "proposals", agentId, proposalId);
  }

  private proposalImportStagingPath(agentId: string, proposalId: string): string {
    return `${this.proposalPath(agentId, proposalId)}.importing`;
  }

  private proposalExportStagingPath(
    agentId: string,
    transitionId: string,
    exportVolumeId: string,
  ): string {
    const token = this.operationPathToken(agentId, transitionId, exportVolumeId, "export");
    return path.join(this.config.inboxRoot, `.cg-export-${token}`);
  }

  private snapshotPath(agentId: string, snapshotId: string): string {
    this.assertIdentifier(agentId);
    this.assertIdentifier(snapshotId);
    return path.join(this.config.controlRoot, "snapshots", agentId, snapshotId);
  }

  private assertIdentifier(value: string): void {
    if (!/^[A-Za-z0-9_.-]{1,128}$/.test(value)) {
      throw new WorkerFault("IDENTIFIER_INVALID", "Worker IDs cannot encode host paths");
    }
  }

  private async serial<T>(agentId: string, operation: () => Promise<T>): Promise<T> {
    const prior = this.tails.get(agentId) ?? Promise.resolve();
    let result!: T;
    const current = prior.then(async () => {
      result = await operation();
    });
    this.tails.set(agentId, current.catch(() => undefined));
    await current;
    return result;
  }

  private async serialExchangeRef<T>(
    volumeId: string,
    operation: () => Promise<T>,
  ): Promise<T> {
    const prior = this.exchangeRefTails.get(volumeId) ?? Promise.resolve();
    let result!: T;
    const current = prior.then(async () => {
      result = await operation();
    });
    const tail = current.catch(() => undefined);
    this.exchangeRefTails.set(volumeId, tail);
    try {
      await current;
      return result;
    } finally {
      if (this.exchangeRefTails.get(volumeId) === tail) {
        this.exchangeRefTails.delete(volumeId);
      }
    }
  }
}

export function loadTransitionWorkerConfig(
  environment: NodeJS.ProcessEnv = process.env,
): TransitionWorkerConfig {
  const workspaceRoot = path.resolve(
    environment.TRANSITION_WORKER_WORKSPACE_ROOT ?? "/var/lib/commitgate/workspaces",
  );
  const controlRoot = path.resolve(
    environment.TRANSITION_WORKER_CONTROL_ROOT ?? "/var/lib/commitgate/control",
  );
  const inboxRoot = path.resolve(
    environment.TRANSITION_WORKER_INBOX_ROOT ?? "/var/lib/commitgate/inbox",
  );
  const socketPath = path.resolve(
    environment.TRANSITION_WORKER_SOCKET ?? "/run/commitgate/transition-worker.sock",
  );
  const legacyWorkspaceRoot = environment.TRANSITION_WORKER_LEGACY_WORKSPACE_ROOT
    ? path.resolve(environment.TRANSITION_WORKER_LEGACY_WORKSPACE_ROOT)
    : undefined;
  const sourceRevision =
    environment.COMMITGATE_SOURCE_REVISION ?? environment.GIT_REVISION ?? "unverified";
  const requireVerifiedSourceRevision = environment.NODE_ENV === "production";
  const requireRuntimeTeardownHandshake = environment.NODE_ENV === "production";
  const requireBrokerAttestations = environment.NODE_ENV === "production";
  const brokerAttestationKey = environment.BROKER_ATTESTATION_KEY?.trim() || undefined;
  if (requireVerifiedSourceRevision && !/^[a-f0-9]{40}$/.test(sourceRevision)) {
    throw new Error(
      "Production Transition Worker requires a full 40-hex COMMITGATE_SOURCE_REVISION",
    );
  }
  if (
    requireBrokerAttestations &&
    Buffer.byteLength(brokerAttestationKey ?? "", "utf8") < 32
  ) {
    throw new Error(
      "Production Transition Worker requires a 32-byte Broker attestation key",
    );
  }
  const expectedCheckBundleHash =
    environment.COMMITGATE_EXPECTED_CHECK_BUNDLE_HASH?.trim() || undefined;
  const expectedVerifierImageDigest =
    environment.COMMITGATE_EXPECTED_VERIFIER_IMAGE_DIGEST?.trim() || undefined;
  const expectedVerifierConfigHash =
    environment.COMMITGATE_EXPECTED_VERIFIER_CONFIG_HASH?.trim() || undefined;
  const expectedResourcePolicyHash =
    environment.COMMITGATE_EXPECTED_RESOURCE_POLICY_HASH?.trim() || undefined;
  const pinnedDigests = [
    ["COMMITGATE_EXPECTED_CHECK_BUNDLE_HASH", expectedCheckBundleHash],
    ["COMMITGATE_EXPECTED_VERIFIER_CONFIG_HASH", expectedVerifierConfigHash],
    ["COMMITGATE_EXPECTED_RESOURCE_POLICY_HASH", expectedResourcePolicyHash],
  ] as const;
  for (const [name, value] of pinnedDigests) {
    if (value !== undefined && !/^[a-f0-9]{64}$/.test(value)) {
      throw new Error(`${name} must be a lowercase 64-hex SHA-256 digest`);
    }
  }
  if (
    expectedVerifierImageDigest !== undefined &&
    !/^sha256:[a-f0-9]{64}$/.test(expectedVerifierImageDigest)
  ) {
    throw new Error(
      "COMMITGATE_EXPECTED_VERIFIER_IMAGE_DIGEST must be an immutable sha256:<64-hex> digest",
    );
  }
  if (
    requireVerifiedSourceRevision &&
    (!expectedCheckBundleHash ||
      !expectedVerifierImageDigest ||
      !expectedVerifierConfigHash ||
      !expectedResourcePolicyHash)
  ) {
    throw new Error(
      "Production Transition Worker requires pinned trusted bundle, Verifier image/config, and resource policy hashes",
    );
  }
  const unique = new Set([workspaceRoot, controlRoot, inboxRoot]);
  if (unique.size !== 3) throw new Error("Transition worker roots must be distinct");
  const roots = [workspaceRoot, controlRoot, inboxRoot];
  for (const outer of roots) {
    for (const inner of roots) {
      if (outer === inner) continue;
      const relative = path.relative(outer, inner);
      if (relative && !relative.startsWith("..") && !path.isAbsolute(relative)) {
        throw new Error("Transition worker roots must not contain one another");
      }
    }
  }
  return {
    workspaceRoot,
    controlRoot,
    inboxRoot,
    socketPath,
    ...(legacyWorkspaceRoot ? { legacyWorkspaceRoot } : {}),
    sourceRevision,
    requireVerifiedSourceRevision,
    requireRuntimeTeardownHandshake,
    requireBrokerAttestations,
    ...(brokerAttestationKey ? { brokerAttestationKey } : {}),
    ...(expectedCheckBundleHash ? { expectedCheckBundleHash } : {}),
    ...(expectedVerifierImageDigest ? { expectedVerifierImageDigest } : {}),
    ...(expectedVerifierConfigHash ? { expectedVerifierConfigHash } : {}),
    ...(expectedResourcePolicyHash ? { expectedResourcePolicyHash } : {}),
  };
}
