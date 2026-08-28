import { createHash, randomUUID } from "node:crypto";
import {
  lstat,
  mkdir,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { computeStateViewId, EMPTY_STATE_HASH, makeStateView } from "../state-view.js";
import { TransitionEventLog, type TransitionEvent } from "../transition-log.js";
import type { StateViewRef } from "../types.js";
import type {
  ApplyPromotionParams,
  ApplyRollbackParams,
  AttemptPermitConsumptionParams,
  AdoptLegacyStateParams,
  ArchiveAgentParams,
  DisposeRunParams,
  ExportProposalParams,
  InitializeAgentParams,
  IssuePermitParams,
  PlatformStateParams,
  PrepareParams,
  PrepareRunParams,
  RecordEvidenceParams,
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
} from "./filesystem.js";
import {
  rebuildWorkerProjection,
  WorkerProjectionStore,
  type WorkerProjection,
} from "./projection.js";
import type { WorkerManifest } from "./filesystem.js";

export interface TransitionWorkerConfig {
  workspaceRoot: string;
  controlRoot: string;
  inboxRoot: string;
  socketPath: string;
  legacyWorkspaceRoot?: string;
}

export interface WorkerHealth {
  status: "ok";
  mode: "authority-v2";
  protocolVersion: 2;
  processUid: number | null;
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

const sha256 = (value: unknown): string =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");

const IGNORED_EPHEMERAL = [".git", ".codex", "node_modules", "dist", "coverage"] as const;

function inspectProposalDiff(
  base: WorkerManifest,
  candidate: WorkerManifest,
): { changedPaths: string[]; staticFailures: string[] } {
  const before = new Map(base.entries.map((entry) => [entry.path, entry]));
  const after = new Map(candidate.entries.map((entry) => [entry.path, entry]));
  const changedPaths = [...new Set([...before.keys(), ...after.keys()])]
    .filter((entryPath) => JSON.stringify(before.get(entryPath)) !== JSON.stringify(after.get(entryPath)))
    .sort();
  const failures: string[] = [];
  if (changedPaths.length > 100) failures.push("CHANGED_FILE_BUDGET_EXCEEDED");
  let changedBytes = 0;
  for (const entryPath of changedPaths) {
    const entry = after.get(entryPath);
    if (entry?.type === "file") {
      changedBytes += entry.size;
      if (entry.size > 262_144) failures.push(`SINGLE_FILE_BUDGET_EXCEEDED:${entryPath}`);
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

const assertView = (view: StateViewRef): void => {
  const { schemaVersion: _schemaVersion, viewId, ...input } = view;
  if (view.schemaVersion !== 1 || computeStateViewId(input) !== viewId) {
    throw new WorkerFault("VIEW_DIGEST_MISMATCH", "StateView digest is invalid");
  }
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
  private readonly tails = new Map<string, Promise<void>>();

  constructor(readonly config: TransitionWorkerConfig) {
    this.log = new TransitionEventLog(path.join(config.controlRoot, "log"));
    this.projections = new WorkerProjectionStore(config.controlRoot);
  }

  async initialize(): Promise<void> {
    await Promise.all([
      mkdir(this.config.workspaceRoot, { recursive: true, mode: 0o700 }),
      mkdir(this.config.controlRoot, { recursive: true, mode: 0o700 }),
      mkdir(this.config.inboxRoot, { recursive: true, mode: 0o700 }),
      mkdir(path.dirname(this.config.socketPath), { recursive: true, mode: 0o750 }),
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
    for (const agentId of agents) await this.recoverAgent(agentId);
  }

  health(): WorkerHealth {
    return {
      status: "ok",
      mode: "authority-v2",
      protocolVersion: 2,
      processUid: typeof process.getuid === "function" ? process.getuid() : null,
    };
  }

  async dispatch(request: WorkerRpcRequest): Promise<unknown> {
    switch (request.method) {
      case "health":
        return this.health();
      case "getProjection":
        return this.projection(request.params.agentId);
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
    return rebuildWorkerProjection(agentId, await this.log.read(agentId));
  }

  async rebuildProjection(agentId: string): Promise<WorkerProjection> {
    const projection = await this.projection(agentId);
    await this.projections.writeHead(projection);
    return projection;
  }

  async initializeAgent(input: InitializeAgentParams): Promise<WorkerProjection> {
    return this.serial(input.agentId, async () => {
      const existing = await this.projection(input.agentId);
      if (existing.head) return existing;
      const workspace = this.workspacePath(input.agentId);
      if (await exists(workspace)) {
        const manifest = await buildWorkerManifest(workspace);
        if (manifest.entries.length > 0) {
          throw new WorkerFault("AGENT_ALREADY_INITIALIZED", "Workspace already contains state");
        }
      } else {
        await mkdir(workspace, { recursive: false, mode: 0o700 });
      }
      await writeFile(path.join(workspace, "AGENTS.md"), input.instructions, {
        encoding: "utf8",
        mode: 0o600,
        flag: "wx",
      });
      await writeFile(
        path.join(workspace, ".gitignore"),
        ".codex/\nnode_modules/\ndist/\n.env\n*.log\n",
        { encoding: "utf8", mode: 0o600, flag: "wx" },
      );
      await writeFile(
        path.join(workspace, "README.md"),
        `# ${input.name} workspace\n\nFiles created or edited by the Agent live here.\n`,
        { encoding: "utf8", mode: 0o600, flag: "wx" },
      );
      await writeFile(path.join(workspace, "protected.txt"), "TRUSTED_BASELINE\n", {
        encoding: "utf8",
        mode: 0o600,
        flag: "wx",
      });
      const manifest = await buildWorkerManifest(workspace);
      const view = makeStateView({
        agentId: input.agentId,
        headVersionId: input.headVersionId,
        generation: input.generation,
        versionedHash: manifest.hash,
        platformManagedHash: manifest.hash,
        liveStateHash: manifest.hash,
        sessionEpoch: input.sessionEpoch,
        agentConfigVersion: input.agentConfigVersion,
        policyVersion: input.policyVersion,
      });
      const snapshotId = await this.captureSnapshot(input.agentId, manifest.hash);
      await this.log.append({
        agentId: input.agentId,
        transitionId: input.operationId,
        type: "AGENT_INITIALIZED",
        payload: {
          view,
          workspaceHash: manifest.hash,
          versionId: input.headVersionId,
          snapshotId,
        },
      });
      return this.persistProjection(input.agentId);
    });
  }

  async adoptLegacyState(input: AdoptLegacyStateParams): Promise<WorkerProjection> {
    return this.serial(input.agentId, async () => {
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
      const sourceManifest = await buildWorkerManifest(source);
      if (sourceManifest.hash !== input.expectedWorkspaceHash) {
        throw new WorkerFault("LEGACY_STATE_CONFLICT", "Legacy workspace hash differs");
      }
      const workspace = this.workspacePath(input.agentId);
      if (await exists(workspace)) {
        const current = await buildWorkerManifest(workspace);
        if (current.entries.length > 0) {
          throw new WorkerFault("LEGACY_STATE_CONFLICT", "Authority workspace is not empty");
        }
        await rm(workspace, { recursive: true, force: true });
      }
      const copied = await copyClosedTree(source, workspace);
      if (copied.hash !== input.expectedWorkspaceHash) {
        throw new WorkerFault("LEGACY_STATE_CONFLICT", "Legacy import changed during copy");
      }
      const snapshotId = await this.captureSnapshot(input.agentId, copied.hash);
      await this.log.append({
        agentId: input.agentId,
        transitionId: input.operationId,
        type: "LEGACY_STATE_ADOPTED",
        payload: {
          view: input.adoptedView,
          workspaceHash: copied.hash,
          versionId: input.versionId,
          snapshotId,
          sourceVolumeId: input.sourceVolumeId ?? null,
          legacyAgentId: input.legacyAgentId ?? null,
        },
      });
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
      if (projection.transitions[input.transitionId]) {
        throw new WorkerFault("TRANSITION_ALREADY_PREPARED", "Transition already exists");
      }
      const candidate = this.inboxPath(input.candidateVolumeId);
      if (await exists(candidate)) {
        throw new WorkerFault("CANDIDATE_ALREADY_EXISTS", "Candidate volume already exists");
      }
      const copied = await copyClosedTree(this.workspacePath(input.agentId), candidate);
      if (copied.hash !== input.expectedWorkspaceHash) {
        throw new WorkerFault("WORKSPACE_CAS_MISMATCH", "Workspace changed during materialization");
      }
      await this.log.append({
        agentId: input.agentId,
        transitionId: input.transitionId,
        type: "TRANSITION_PREPARED",
        payload: {
          kind: "AGENT_COMMIT",
          baseViewId: input.expectedViewId,
          baseWorkspaceHash: input.expectedWorkspaceHash,
          baseGeneration: input.baseGeneration,
          candidateVolumeId: input.candidateVolumeId,
        },
      });
      await this.persistProjection(input.agentId);
      return {
        agentId: input.agentId,
        runId: input.transitionId,
        transitionId: input.transitionId,
        candidateVolumeId: input.candidateVolumeId,
        relativeSubpath: input.candidateVolumeId,
        baseView: projection.head!.view,
        baseWorkspaceHash: input.expectedWorkspaceHash,
        candidateHash: copied.hash,
      };
    });
  }

  async exportProposal(input: ExportProposalParams): Promise<VerifierWorkspaceRef> {
    return this.serial(input.agentId, async () => {
      const projection = await this.projection(input.agentId);
      const proposal = projection.proposals[input.proposalId];
      if (
        !proposal ||
        proposal.transitionId !== input.transitionId ||
        !["SEALED", "EVIDENCED", "PERMITTED"].includes(
          projection.transitions[input.transitionId]?.state ?? "",
        )
      ) {
        throw new WorkerFault("PROPOSAL_NOT_SEALED", "Verifier export requires a sealed proposal");
      }
      const destination = this.inboxPath(input.exportVolumeId);
      if (await exists(destination)) {
        throw new WorkerFault("EXPORT_ALREADY_EXISTS", "Verifier export already exists");
      }
      const copied = await copyClosedTree(
        this.proposalPath(input.agentId, input.proposalId),
        destination,
      );
      if (copied.hash !== proposal.artifactHash) {
        throw new WorkerFault("ARTIFACT_HASH_MISMATCH", "Verifier export changed");
      }
      await makeTreeReadonly(destination);
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
      assertView(input.finalView);
      const projection = await this.projection(input.agentId);
      const transition = projection.transitions[input.transitionId];
      if (!transition) throw new WorkerFault("TRANSITION_STATE_INVALID", "Run was not prepared");
      if (!projection.head || input.finalView.agentId !== input.agentId) {
        throw new WorkerFault("VIEW_DIGEST_MISMATCH", "Disposition view is invalid");
      }
      if (
        input.finalView.generation !== projection.head.view.generation ||
        input.finalView.liveStateHash !== projection.head.workspaceHash
      ) {
        throw new WorkerFault("NEXT_VIEW_INVALID", "Non-commit disposition changed workspace generation");
      }
      await this.log.append({
        agentId: input.agentId,
        transitionId: input.transitionId,
        type: "VIEW_DISPOSITIONED",
        payload: {
          receiptId: input.receiptId,
          decision: input.decision,
          viewId: input.finalView.viewId,
          view: input.finalView,
          workspaceHash: projection.head.workspaceHash,
          reasonCodes: input.reasonCodes,
        },
      });
      const transitionEvent = await this.lastEvent(
        await this.log.transition(input.agentId, input.transitionId),
        "TRANSITION_ROLLED_BACK",
      );
      if (!transitionEvent) {
        await this.log.append({
          agentId: input.agentId,
          transitionId: input.transitionId,
          type: "TRANSITION_ROLLED_BACK",
          payload: { reason: input.decision },
        });
      }
      return this.persistProjection(input.agentId);
    });
  }

  async regeneratePlatformState(input: PlatformStateParams): Promise<WorkerProjection> {
    return this.serial(input.agentId, async () => {
      const projection = await this.projection(input.agentId);
      await this.assertCurrentCas(
        input.agentId,
        projection,
        input.expectedViewId,
        input.expectedWorkspaceHash,
      );
      if (!projection.head) throw new WorkerFault("AGENT_NOT_INITIALIZED", "Agent has no authority head");
      const destination = path.join(this.workspacePath(input.agentId), "AGENTS.md");
      const temporary = `${destination}.tmp-${randomUUID()}`;
      await writeFile(temporary, input.instructions, { encoding: "utf8", mode: 0o600, flag: "wx" });
      await rename(temporary, destination);
      const manifest = await buildWorkerManifest(this.workspacePath(input.agentId));
      const nextView = makeStateView({
        agentId: input.agentId,
        headVersionId: projection.head.view.headVersionId,
        generation: projection.head.view.generation + 1,
        versionedHash: projection.head.view.versionedHash,
        platformManagedHash: manifest.hash,
        liveStateHash: manifest.hash,
        sessionEpoch: input.sessionEpoch,
        agentConfigVersion: input.agentConfigVersion,
        policyVersion: input.policyVersion,
      });
      await this.log.append({
        agentId: input.agentId,
        transitionId: input.operationId,
        type: "PLATFORM_STATE_REGENERATED",
        payload: { view: nextView, workspaceHash: manifest.hash },
      });
      return this.persistProjection(input.agentId);
    });
  }

  async archiveAgent(input: ArchiveAgentParams): Promise<WorkerProjection> {
    return this.serial(input.agentId, async () => {
      const projection = await this.projection(input.agentId);
      await this.assertCurrentCas(
        input.agentId,
        projection,
        input.expectedViewId,
        input.expectedWorkspaceHash,
      );
      const archiveRoot = path.join(this.config.workspaceRoot, ".deleted");
      await mkdir(archiveRoot, { recursive: true, mode: 0o700 });
      await rename(
        this.workspacePath(input.agentId),
        path.join(archiveRoot, `${input.agentId}-${input.operationId}`),
      );
      await this.log.append({
        agentId: input.agentId,
        transitionId: input.operationId,
        type: "AGENT_ARCHIVED",
        payload: { viewId: input.expectedViewId, workspaceHash: input.expectedWorkspaceHash },
      });
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
      let projection = await this.projection(agentId);
      for (const transition of Object.values(projection.transitions)) {
        if (transition.state !== "CONSUMING" && transition.state !== "APPLIED") continue;
        const events = await this.log.transition(agentId, transition.transitionId);
        const consuming = this.lastEvent(events, "PERMIT_CONSUMING");
        const intent = consuming?.payload as Record<string, unknown> | undefined;
        if (!intent) throw new WorkerFault("RECOVERY_REQUIRED", "Consuming intent is missing");
        const targetHash = String(intent.targetArtifactHash);
        const workspace = this.workspacePath(agentId);
        const backup = this.backupPath(agentId, transition.transitionId);
        if (!(await exists(workspace)) && (await exists(backup))) {
          await rename(backup, workspace);
        }
        const actualHash = await this.currentWorkspaceHash(agentId);
        if (transition.state === "APPLIED" || actualHash === targetHash) {
          if (actualHash !== targetHash || !transition.appliedView && !intent.nextView) {
            throw new WorkerFault("RECOVERY_REQUIRED", "Applied workspace does not match durable intent");
          }
          if (transition.state !== "APPLIED") {
            const nextView = intent.nextView as StateViewRef;
            assertView(nextView);
            await this.log.append({
              agentId,
              transitionId: transition.transitionId,
              type: "WORKSPACE_APPLIED",
              payload: { view: nextView, workspaceHash: targetHash, recovered: true },
            });
          }
          const snapshotId = await this.captureSnapshot(agentId, targetHash);
          await this.log.append({
            agentId,
            transitionId: transition.transitionId,
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
          await this.deleteBackup(agentId, transition.transitionId);
        } else if (actualHash === transition.baseWorkspaceHash) {
          await this.deleteBackup(agentId, transition.transitionId);
          await rm(this.stagingPath(agentId, transition.transitionId), {
            recursive: true,
            force: true,
          });
          await this.log.append({
            agentId,
            transitionId: transition.transitionId,
            type: "TRANSITION_ROLLED_BACK",
            payload: { recovered: true, reason: "workspace_remained_at_base" },
          });
        } else {
          throw new WorkerFault(
            "RECOVERY_REQUIRED",
            "Workspace matches neither prepared base nor bound target",
          );
        }
        projection = await this.persistProjection(agentId);
      }
      return projection;
    });
  }

  async prepare(input: PrepareParams): Promise<WorkerProjection> {
    return this.serial(input.agentId, async () => {
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
      const projection = await this.projection(input.agentId);
      const transition = projection.transitions[input.transitionId];
      if (!transition || transition.state !== "PREPARED" || transition.kind !== "AGENT_COMMIT") {
        throw new WorkerFault("TRANSITION_STATE_INVALID", "Commit transition is not prepared");
      }
      if (transition.baseViewId !== input.baseViewId) {
        throw new WorkerFault("VIEW_CAS_MISMATCH", "Proposal base view differs from prepared view");
      }
      const source = this.inboxPath(input.sourceVolumeId);
      for (const ignored of IGNORED_EPHEMERAL) {
        await rm(path.join(source, ignored), { recursive: true, force: true });
      }
      const sourceManifest = await buildWorkerManifest(source);
      if (input.expectedArtifactHash && sourceManifest.hash !== input.expectedArtifactHash) {
        throw new WorkerFault("ARTIFACT_HASH_MISMATCH", "Inbox artifact hash differs from request");
      }
      const baseManifest = await buildWorkerManifest(this.workspacePath(input.agentId));
      const inspection = inspectProposalDiff(baseManifest, sourceManifest);
      const proposalRoot = this.proposalPath(input.agentId, input.proposalId);
      const temporary = `${proposalRoot}.tmp-${randomUUID()}`;
      await mkdir(path.dirname(proposalRoot), { recursive: true, mode: 0o700 });
      const copied = await copyClosedTree(source, temporary);
      if (copied.hash !== sourceManifest.hash) {
        throw new WorkerFault("ARTIFACT_HASH_MISMATCH", "Imported artifact digest changed");
      }
      await makeTreeReadonly(temporary);
      await rename(temporary, proposalRoot);
      await makeTreeWritable(source);
      await rm(source, { recursive: true, force: true });
      await this.log.append({
        agentId: input.agentId,
        transitionId: input.transitionId,
        type: "PROPOSAL_SEALED",
        payload: {
          proposalId: input.proposalId,
          baseViewId: input.baseViewId,
          artifactHash: copied.hash,
          changedPaths: inspection.changedPaths,
          staticFailures: inspection.staticFailures,
          sourceVolumeId: input.sourceVolumeId,
          sourceDestroyed: true,
        },
      });
      return this.persistProjection(input.agentId);
    });
  }

  async recordEvidence(input: RecordEvidenceParams): Promise<WorkerProjection> {
    return this.serial(input.agentId, async () => {
      const projection = await this.projection(input.agentId);
      const transition = projection.transitions[input.transitionId];
      if (!transition || transition.proposalId !== input.proposalId || transition.state !== "SEALED") {
        throw new WorkerFault("EVIDENCE_BINDING_MISMATCH", "Evidence does not bind the sealed proposal");
      }
      await this.log.append({
        agentId: input.agentId,
        transitionId: input.transitionId,
        type: "EVIDENCE_RECORDED",
        payload: {
          proposalId: input.proposalId,
          evaluationContextHash: input.evaluationContextHash,
          evidenceDigest: input.evidenceDigest,
        },
      });
      return this.persistProjection(input.agentId);
    });
  }

  async issuePermit(input: IssuePermitParams): Promise<WorkerProjection> {
    return this.serial(input.agentId, async () => {
      const projection = await this.projection(input.agentId);
      const transition = projection.transitions[input.transitionId];
      const proposal = projection.proposals[input.proposalId];
      const evidenceEvent = this.lastEvent(
        await this.log.transition(input.agentId, input.transitionId),
        "EVIDENCE_RECORDED",
      );
      const evidence = evidenceEvent?.payload as Record<string, unknown> | undefined;
      if (
        !transition ||
        transition.state !== "EVIDENCED" ||
        !proposal ||
        proposal.baseViewId !== input.baseViewId ||
        proposal.artifactHash !== input.targetArtifactHash ||
        evidence?.evaluationContextHash !== input.evaluationContextHash ||
        evidence?.evidenceDigest !== input.evidenceDigest ||
        Date.parse(input.expiresAt) <= Date.now()
      ) {
        throw new WorkerFault("PERMIT_BINDING_MISMATCH", "Permit inputs do not bind current evidence");
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
      assertView(input.nextView);
      const projection = await this.projection(input.agentId);
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
      this.assertNextView(input.nextView, input.agentId, input.versionId, transition.baseGeneration);
      await this.assertCurrentCas(input.agentId, projection, input.expectedViewId, input.expectedWorkspaceHash);
      await this.log.append({
        agentId: input.agentId,
        transitionId: input.transitionId,
        type: "PERMIT_CONSUMING",
        payload: {
          permitId: input.permitId,
          proposalId: input.proposalId,
          nextView: input.nextView,
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
        nextView: input.nextView,
        versionId: input.versionId,
        receiptId: input.receiptId,
      });
    });
  }

  async applyRollback(input: ApplyRollbackParams): Promise<WorkerProjection> {
    return this.serial(input.agentId, async () => {
      assertView(input.nextView);
      let projection = await this.projection(input.agentId);
      const transition = projection.transitions[input.transitionId];
      if (!transition || transition.kind !== "ROLLBACK" || transition.state !== "PREPARED") {
        throw new WorkerFault("TRANSITION_STATE_INVALID", "Rollback transition is not prepared");
      }
      this.assertNextView(input.nextView, input.agentId, input.versionId, transition.baseGeneration);
      await this.assertCurrentCas(input.agentId, projection, input.expectedViewId, input.expectedWorkspaceHash);
      const source = this.snapshotPath(input.agentId, input.targetSnapshotId);
      const manifest = await buildWorkerManifest(source);
      if (manifest.hash !== input.targetSnapshotId) {
        throw new WorkerFault("SNAPSHOT_DIGEST_MISMATCH", "Rollback snapshot digest changed");
      }
      const proposalId = `snapshot-${input.targetSnapshotId}`;
      const contextHash = sha256({
        rollbackPermitId: input.rollbackPermitId,
        targetSnapshotId: input.targetSnapshotId,
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
        payload: { proposalId, evaluationContextHash: contextHash, evidenceDigest },
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
          nextView: input.nextView,
          versionId: input.versionId,
          receiptId: input.receiptId,
          targetArtifactHash: manifest.hash,
          rollbackTargetVersionId: input.targetVersionId,
        },
      });
      projection = await this.applyTreeAndAcknowledge({
        agentId: input.agentId,
        transitionId: input.transitionId,
        source,
        targetHash: manifest.hash,
        expectedBaseHash: input.expectedWorkspaceHash,
        nextView: input.nextView,
        versionId: input.versionId,
        receiptId: input.receiptId,
        rollbackTargetVersionId: input.targetVersionId,
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
        await this.restoreBackup(input.agentId, input.transitionId, transition.baseWorkspaceHash);
        await this.log.appendRepair({
          ...input,
          actualViewId: input.expectedViewId,
          actualWorkspaceHash: input.expectedWorkspaceHash,
        });
        await this.log.append({
          agentId: input.agentId,
          transitionId: input.transitionId,
          type: "TRANSITION_ROLLED_BACK",
          payload: { action: "rollback", repaired: true },
        });
        return this.persistProjection(input.agentId);
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
      return this.persistProjection(input.agentId);
    });
  }

  private async applyTreeAndAcknowledge(input: {
    agentId: string;
    transitionId: string;
    source: string;
    targetHash: string;
    expectedBaseHash: string;
    nextView: StateViewRef;
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
      await this.deleteBackup(input.agentId, input.transitionId);
      return this.persistProjection(input.agentId);
    } catch (error) {
      await this.restoreBackup(input.agentId, input.transitionId, input.expectedBaseHash).catch(
        () => undefined,
      );
      await this.log.append({
        agentId: input.agentId,
        transitionId: input.transitionId,
        type: "TRANSITION_ROLLED_BACK",
        payload: {
          reason: error instanceof Error ? error.message : String(error),
        },
      }).catch(() => undefined);
      throw error;
    }
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
    const copied = await copyClosedTree(source, staging);
    if (copied.hash !== targetHash) throw new WorkerFault("PROMOTION_SOURCE_CHANGED", "Source digest changed");
    await assertSameFilesystem(this.config.workspaceRoot, staging);
    const currentHash = await this.currentWorkspaceHash(agentId);
    if (currentHash !== expectedBaseHash) {
      throw new WorkerFault("WORKSPACE_CAS_MISMATCH", "Workspace changed before rename-swap");
    }
    if (await exists(backup)) throw new WorkerFault("BACKUP_ALREADY_EXISTS", "Transition backup exists");
    if (await exists(workspace)) await rename(workspace, backup);
    try {
      await rename(staging, workspace);
    } catch (error) {
      if (await exists(backup)) await rename(backup, workspace);
      throw error;
    }
    const applied = await buildWorkerManifest(workspace);
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
      if ((await buildWorkerManifest(destination)).hash !== expectedHash) {
        throw new WorkerFault("SNAPSHOT_DIGEST_MISMATCH", "Existing snapshot is corrupt");
      }
      return expectedHash;
    }
    await mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
    const temporary = `${destination}.tmp-${randomUUID()}`;
    const copied = await copyClosedTree(this.workspacePath(agentId), temporary);
    if (copied.hash !== expectedHash) throw new WorkerFault("SNAPSHOT_DIGEST_MISMATCH", "Snapshot changed");
    await makeTreeReadonly(temporary);
    await rename(temporary, destination);
    return expectedHash;
  }

  private async restoreBackup(agentId: string, transitionId: string, expectedHash: string): Promise<void> {
    const workspace = this.workspacePath(agentId);
    const backup = this.backupPath(agentId, transitionId);
    if (await exists(backup)) {
      const failed = `${workspace}.failed-${randomUUID()}`;
      if (await exists(workspace)) await rename(workspace, failed);
      await rename(backup, workspace);
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

  private assertNextView(
    nextView: StateViewRef,
    agentId: string,
    versionId: string,
    baseGeneration: number,
  ): void {
    if (
      nextView.agentId !== agentId ||
      nextView.headVersionId !== versionId ||
      nextView.generation !== baseGeneration + 1
    ) {
      throw new WorkerFault("NEXT_VIEW_INVALID", "Next view does not advance the prepared transition");
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

  private async currentWorkspaceHash(agentId: string): Promise<string> {
    const workspace = this.workspacePath(agentId);
    if (!(await exists(workspace))) {
      await mkdir(workspace, { recursive: false, mode: 0o700 });
    }
    return (await buildWorkerManifest(workspace)).hash;
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
  };
}
