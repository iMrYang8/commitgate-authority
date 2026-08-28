import { mkdir, rm } from "node:fs/promises";
import path from "node:path";
import { CommitGateRecoveryRequiredError } from "../errors.js";
import type { GateLifecycleEventName, ModelProviderIdentity } from "../types.js";
import type { TransitionAuthority } from "../transition-authority.js";
import { createInProcessTransitionAuthority } from "../transition-authority-factory.js";
import { WorkspaceManager } from "../workspace.js";
import { writeJsonAtomic } from "./atomic-json.js";
import { assertContained, assertSafeIdentifier, copyWorkspace, pathExists } from "./file-ops.js";
import { buildManifest, diffManifests, patchHash } from "./manifest.js";
import { defaultCommitGatePolicy, loadPolicy, policyHash, validatePolicy } from "./policy.js";
import {
  PermitStateError,
  PromotionPermitStore,
  type PromotionCapability,
} from "./promotion-permit-store.js";
import {
  assertStateViewRef,
  computeCheckResultsHash,
  computeEvaluationContextHash,
  createEvidenceBundle,
  createStateViewRef,
  sha256Canonical,
} from "./protocol.js";
import { ReceiptStore, sanitizeReceipt } from "./receipt-store.js";
import {
  auditCandidateResourceUsage,
  normalizeCandidateResourceLimits,
  type CandidateResourceLimits,
} from "./resource-budget.js";
import {
  ProposalSealError,
  SealedProposalStore,
  assertReadonlySealedPayload,
  runtimeTeardownDigest,
  type ResolvedSealedProposal,
} from "./sealed-proposal-store.js";
import { computeCheckSpecHash } from "./trusted-check-bundle.js";
import type {
  CheckResult,
  CommitGatePolicy,
  CommitGateSummaryData,
  EvaluationContext,
  FailureClass,
  GateDecision,
  GateFinalization,
  GateReceipt,
  ManifestChange,
  PreparedCandidate,
  PromotionHandle,
  PromotionPermit,
  StateViewCaptureInput,
  StateViewProvider,
  StateViewRef,
  VerifierExecutionEnvironment,
  VerifierRunner,
} from "./types.js";
import { validateCandidate } from "./validators.js";
import { VersionStore } from "./version-store.js";
import { StateConflictError, WorkspaceTransaction } from "./workspace-transaction.js";

export interface CommitGateCoordinatorOptions {
  workspaceRoot: string;
  controlRoot?: string;
  trustedChecksRoot?: string;
  verifier: VerifierRunner;
  receiptStore?: ReceiptStore;
  versionStore?: VersionStore;
  transaction?: WorkspaceTransaction;
  transitionWriter?: TransitionAuthority;
  proposalStore?: SealedProposalStore;
  permitStore?: PromotionPermitStore;
  stateViewProvider?: StateViewProvider;
  defaultPolicy?: CommitGatePolicy;
  sensitiveValues?: readonly string[];
  requireTrustedChecks?: boolean;
  requireRuntimeTeardownEvidence?: boolean;
  sourceRevision?: string;
  candidateResourceLimits?: Partial<CandidateResourceLimits>;
  now?: () => Date;
}

export interface PrepareInput {
  runId: string;
  agentId: string;
  persistentPath: string;
  sessionEpoch?: number;
  policy?: CommitGatePolicy;
  runLeaseId?: string;
  expectedBaseViewId?: string;
  stateGeneration?: number;
  expectedHeadVersionId?: string | null;
  agentConfigVersion?: number;
  policyVersion?: number;
  provider?: ModelProviderIdentity | null;
}

export interface AdmissionFailureInput {
  runId: string;
  agentId: string;
  sessionEpoch: number;
  baseViewId?: string;
  stateGeneration?: number;
  baseLiveStateHash?: string;
  startedAt?: string;
  provider?: ModelProviderIdentity | null;
}

interface ExpectedViewMetadata {
  generation?: number | undefined;
  headVersionId?: string | null | undefined;
  agentConfigVersion?: number | undefined;
  policyVersion?: number | undefined;
}

interface PendingPromotion {
  prepared: PreparedCandidate;
  handle: PromotionHandle;
  receipt: GateReceipt;
  sealed: ResolvedSealedProposal;
  permit: PromotionPermit;
  capability: PromotionCapability;
}

interface CheckAssessment {
  evidenceComplete: boolean;
  resultFailures: string[];
  evidenceFailures: string[];
}

interface ProtocolReceiptDetails {
  sealed?: ResolvedSealedProposal;
  changes?: ManifestChange[];
  candidateHash?: string | null;
  evaluationContextHash?: string | null;
  evidenceDigest?: string | null;
  permit?: PromotionPermit | null;
}

function normalizeCheckResult(value: CheckResult, index: number): CheckResult {
  const candidate = value as Partial<CheckResult>;
  const statusValid = ["PASS", "FAIL", "ERROR", "SKIPPED"].includes(String(candidate.status));
  const structurallyValid =
    typeof candidate.id === "string" &&
    typeof candidate.output === "string" &&
    typeof candidate.timedOut === "boolean" &&
    typeof candidate.durationMs === "number" &&
    Number.isFinite(candidate.durationMs) &&
    candidate.durationMs >= 0 &&
    (candidate.exitCode === null || Number.isInteger(candidate.exitCode)) &&
    statusValid;
  return {
    id: typeof candidate.id === "string" ? candidate.id : `__invalid_${index}`,
    status: structurallyValid ? candidate.status! : "ERROR",
    exitCode:
      candidate.exitCode === null || Number.isInteger(candidate.exitCode)
        ? (candidate.exitCode ?? null)
        : null,
    durationMs:
      typeof candidate.durationMs === "number" && Number.isFinite(candidate.durationMs) && candidate.durationMs >= 0
        ? candidate.durationMs
        : 0,
    output: structurallyValid ? candidate.output! : "Malformed verifier result was normalized fail-closed",
    timedOut: candidate.timedOut === true,
  };
}

function assessTrustedChecks(checks: readonly CheckResult[], policy: CommitGatePolicy): CheckAssessment {
  const requiredIds = new Set(policy.requiredChecks.map((check) => check.id));
  const seen = new Map<string, number>();
  const evidenceFailures: string[] = [];
  const resultFailures: string[] = [];
  for (const check of checks) {
    seen.set(check.id, (seen.get(check.id) ?? 0) + 1);
    if (!requiredIds.has(check.id)) {
      evidenceFailures.push("TRUSTED_CHECK_UNEXPECTED:" + check.id);
      continue;
    }
    if ((seen.get(check.id) ?? 0) > 1) {
      evidenceFailures.push("TRUSTED_CHECK_DUPLICATE:" + check.id);
      continue;
    }
    if (check.status === "PASS") {
      if (check.exitCode !== 0 || check.timedOut) evidenceFailures.push("TRUSTED_CHECK_EVIDENCE_INVALID:" + check.id);
    } else if (check.status === "FAIL") {
      if (typeof check.exitCode !== "number" || check.exitCode === 0 || check.timedOut) {
        evidenceFailures.push("TRUSTED_CHECK_EVIDENCE_INVALID:" + check.id);
      } else {
        resultFailures.push("TRUSTED_CHECK_FAILED:" + check.id);
      }
    } else {
      evidenceFailures.push("TRUSTED_CHECK_INCOMPLETE:" + check.id);
    }
  }
  for (const requiredId of requiredIds) {
    if (!seen.has(requiredId)) evidenceFailures.push("TRUSTED_CHECK_RESULT_MISSING:" + requiredId);
  }
  return { evidenceComplete: evidenceFailures.length === 0, resultFailures, evidenceFailures };
}

export class CommitGateCoordinator {
  readonly controlRoot: string;
  readonly receiptStore: ReceiptStore;
  readonly versionStore: VersionStore;
  readonly proposalStore: SealedProposalStore;
  readonly permitStore: PromotionPermitStore;
  private readonly transaction: WorkspaceTransaction | null;
  private readonly transitionWriter: TransitionAuthority | null;
  private readonly trustedChecksRoot: string;
  private readonly pending = new Map<string, PendingPromotion>();
  private readonly now: () => Date;
  private readonly candidateResourceLimits: CandidateResourceLimits;
  private stateViewProvider: StateViewProvider | undefined;

  constructor(private readonly options: CommitGateCoordinatorOptions) {
    this.controlRoot = path.resolve(options.controlRoot ?? path.join(path.resolve(options.workspaceRoot), ".commitgate"));
    this.trustedChecksRoot = path.resolve(options.trustedChecksRoot ?? path.join(this.controlRoot, "trusted-checks"));
    this.receiptStore = options.receiptStore ?? new ReceiptStore(this.controlRoot);
    this.transitionWriter =
      options.transitionWriter ??
      (options.transaction
        ? null
        : createInProcessTransitionAuthority(
            new WorkspaceManager(options.workspaceRoot),
            this.controlRoot,
          ));
    this.transaction = options.transaction ?? null;
    const mutationAuthority = this.transitionWriter ?? this.transaction;
    if (!mutationAuthority) throw new Error("CommitGate transition authority is required");
    this.versionStore =
      options.versionStore ?? new VersionStore(this.controlRoot, {}, mutationAuthority);
    this.proposalStore = options.proposalStore ?? new SealedProposalStore();
    this.permitStore = options.permitStore ?? new PromotionPermitStore();
    this.stateViewProvider = options.stateViewProvider;
    this.now = options.now ?? (() => new Date());
    this.candidateResourceLimits = normalizeCandidateResourceLimits(
      options.candidateResourceLimits,
    );
  }

  async initialize(): Promise<void> {
    await mkdir(this.controlRoot, { recursive: true, mode: 0o700 });
    await mkdir(this.trustedChecksRoot, { recursive: true, mode: 0o700 });
  }

  /**
   * Public diagnostic surface for proving that a terminal permit cannot be
   * claimed twice. It exercises PromotionPermitStore.claim with only
   * server-owned bindings and never invokes the workspace transaction.
   */
  async attemptConsumedPermitReplay(input: {
    agentId: string;
    runId: string;
    permitId: string;
    expectedCurrentViewId: string;
  }): Promise<{ code: "PERMIT_REPLAY"; permitState: "CONSUMED" }> {
    assertSafeIdentifier(input.agentId, "agentId");
    assertSafeIdentifier(input.runId, "runId");
    assertSafeIdentifier(input.permitId, "permitId");
    const receipt = await this.receiptStore.get(input.agentId, input.runId);
    if (
      !receipt ||
      receipt.phase !== "TERMINAL" ||
      receipt.decision !== "COMMITTED" ||
      receipt.permitId !== input.permitId ||
      receipt.permitState !== "CONSUMED" ||
      !receipt.proposalId ||
      !receipt.baseView ||
      !receipt.evaluationContextHash ||
      !receipt.evidenceDigest
    ) {
      throw new Error("PERMIT_REPLAY_BINDINGS_UNAVAILABLE");
    }
    const controlPath = path.join(this.controlRoot, input.agentId);
    assertContained(this.controlRoot, controlPath, "agent control path");
    const persistedPermit = await this.permitStore.get(
      controlPath,
      input.permitId,
    );
    if (persistedPermit.state !== "CONSUMED") {
      throw new Error("PERMIT_NOT_TERMINALLY_CONSUMED");
    }
    const descriptor = await this.proposalStore.describe(
      controlPath,
      receipt.proposalId,
    );
    try {
      await this.permitStore.claim({
        agentId: input.agentId,
        controlPath,
        permitId: input.permitId,
        proposal: { ...descriptor.proposal, state: "SEALED" },
        proposalPath: descriptor.payloadPath,
        proposalManifest: descriptor.manifest,
        baseView: receipt.baseView,
        evaluationContextHash: receipt.evaluationContextHash,
        evidenceDigest: receipt.evidenceDigest,
      });
    } catch (error) {
      if (error instanceof PermitStateError && error.code === "PERMIT_REPLAY") {
        await this.receiptStore.appendPermitReplayEvent({
          agentId: input.agentId,
          runId: input.runId,
          permitId: input.permitId,
          expectedViewId: input.expectedCurrentViewId,
          createdAt: this.now().toISOString(),
        });
        return { code: "PERMIT_REPLAY", permitState: "CONSUMED" };
      }
      throw error;
    }
    throw new Error("CONSUMED_PERMIT_UNEXPECTEDLY_RECLAIMED");
  }

  hasPendingPromotion(runId: string): boolean {
    return this.pending.has(runId);
  }

  setStateViewProvider(provider: StateViewProvider | undefined): void {
    this.stateViewProvider = provider;
  }

  recordRuntimeTeardown(
    prepared: PreparedCandidate,
    evidence: {
      containerExited: boolean;
      containerRemoved: boolean;
      mountsReleased: boolean;
      [key: string]: unknown;
    },
  ): void {
    prepared.runtimeTeardownVerified =
      evidence.containerExited &&
      evidence.containerRemoved &&
      evidence.mountsReleased &&
      (evidence.relayCapabilityRequired !== true ||
        evidence.relayCapabilityRevoked === true);
    prepared.runtimeTeardownDigest = runtimeTeardownDigest(evidence);
    if (
      prepared.provider &&
      typeof evidence.resolvedModel === "string" &&
      evidence.resolvedModel.trim()
    ) {
      prepared.provider = {
        ...prepared.provider,
        resolvedModel: evidence.resolvedModel.trim(),
      };
    }
  }

  async policyForAgent(agentId: string): Promise<CommitGatePolicy> {
    await this.initialize();
    assertSafeIdentifier(agentId, "agentId");
    const controlPath = path.join(this.controlRoot, agentId);
    await mkdir(controlPath, { recursive: true, mode: 0o700 });
    const policyPath = path.join(controlPath, "policy.json");
    if (await pathExists(policyPath)) return loadPolicy(policyPath);
    const policy = validatePolicy(this.options.defaultPolicy ?? defaultCommitGatePolicy);
    await writeJsonAtomic(policyPath, policy);
    return policy;
  }

  async initializeAgent(agentId: string, persistentPath: string): Promise<Awaited<ReturnType<VersionStore["initializeAgent"]>>> {
    const policy = await this.policyForAgent(agentId);
    return this.versionStore.initializeAgent(agentId, persistentPath, policy);
  }

  async prepare(input: PrepareInput): Promise<PreparedCandidate> {
    await this.initialize();
    assertSafeIdentifier(input.runId, "runId");
    assertSafeIdentifier(input.agentId, "agentId");
    const persistentPath = path.resolve(input.persistentPath);
    assertContained(this.options.workspaceRoot, persistentPath, "persistent workspace");
    if (persistentPath === this.controlRoot || persistentPath.startsWith(this.controlRoot + path.sep)) {
      throw new Error("Persistent workspace cannot be inside the CommitGate control plane");
    }
    const controlPath = path.join(this.controlRoot, input.agentId);
    const candidatePath = path.join(controlPath, "candidates", input.runId);
    const verifyPath = path.join(controlPath, "verify", input.runId);
    for (const value of [controlPath, candidatePath, verifyPath]) assertContained(this.controlRoot, value, "control path");
    await mkdir(controlPath, { recursive: true, mode: 0o700 });
    const storedPolicyPath = path.join(controlPath, "policy.json");
    const policy = input.policy ? validatePolicy(input.policy) : await this.policyForAgent(input.agentId);
    await this.versionStore.initializeAgent(input.agentId, persistentPath, policy);

    const materialize = async () => {
      const baseBefore = await buildManifest(persistentPath, policy);
      await copyWorkspace(persistentPath, candidatePath, policy, {
        include: new Set(["versioned", "platformManaged"]),
      });
      const candidateBase = await buildManifest(candidatePath, policy);
      const baseAfter = await buildManifest(persistentPath, policy);
      return { baseBefore, candidateBase, baseAfter };
    };
    const { baseBefore, candidateBase, baseAfter } = this.transitionWriter
      ? await this.transitionWriter.materializeCandidate({
          agentId: input.agentId,
          persistentPath,
          candidatePath,
          policy,
        })
      : await materialize();
    if (baseBefore.hash !== candidateBase.hash || baseBefore.hash !== baseAfter.hash) {
      await rm(candidatePath, { recursive: true, force: true });
      throw new StateConflictError("Workspace changed while preparing candidate");
    }
    const baseView = await this.captureStateView(
      input.agentId,
      persistentPath,
      policy,
      input.sessionEpoch ?? 0,
      {
        generation: input.stateGeneration,
        headVersionId: input.expectedHeadVersionId,
        agentConfigVersion: input.agentConfigVersion,
        policyVersion: input.policyVersion,
      },
    );
    if (baseView.liveStateHash !== baseBefore.hash) {
      await rm(candidatePath, { recursive: true, force: true });
      throw new StateConflictError("Workspace changed while capturing the admitted StateView");
    }
    if (input.expectedBaseViewId && baseView.viewId !== input.expectedBaseViewId) {
      await rm(candidatePath, { recursive: true, force: true });
      throw new StateConflictError("Admitted StateView does not match RunnerRequest.baseViewId");
    }
    return {
      runId: input.runId,
      agentId: input.agentId,
      persistentPath,
      controlPath,
      candidatePath,
      verifyPath,
      baseManifest: baseBefore,
      baseSnapshotHash: baseBefore.hash,
      baseView,
      policy,
      policyHash: policyHash(policy),
      policyPath: input.policy ? null : storedPolicyPath,
      runLeaseId: input.runLeaseId ?? input.runId,
      runtimeTeardownDigest: runtimeTeardownDigest({
        runId: input.runId,
        verified: false,
        reason: "runtime attestation not recorded",
      }),
      runtimeTeardownVerified: false,
      sessionEpoch: baseView.sessionEpoch,
      provider: input.provider ? structuredClone(input.provider) : null,
      startedAt: this.now().toISOString(),
    };
  }

  async verifyAndFinalize(prepared: PreparedCandidate, signal?: AbortSignal): Promise<GateFinalization> {
    const existing = await this.receiptStore.get(prepared.agentId, prepared.runId);
    if (existing) return { receipt: existing, summary: this.toSummary(existing) };
    if (signal?.aborted) return this.abort(prepared, signal.reason ?? new Error("Run cancelled"));

    let candidateBefore;
    try {
      await auditCandidateResourceUsage(
        prepared.candidatePath,
        prepared.policy,
        this.candidateResourceLimits,
      );
      candidateBefore = await buildManifest(prepared.candidatePath, prepared.policy);
    } catch (error) {
      return this.reject(prepared, "QUARANTINED", "agent_wrong", [this.reason(error)], [], { candidateHash: null });
    }
    const candidateStatic = await validateCandidate(
      prepared.policy,
      prepared.baseManifest,
      candidateBefore,
      prepared.candidatePath,
      this.options.sensitiveValues,
    );
    const changedPathsDigest = patchHash(candidateStatic.changes);
    let sealed: ResolvedSealedProposal;
    try {
      const sealInput = {
          runId: prepared.runId,
          agentId: prepared.agentId,
          controlPath: prepared.controlPath,
          candidatePath: prepared.candidatePath,
          baseViewId: prepared.baseView.viewId,
          policy: prepared.policy,
          changedPathsDigest,
          runtimeTeardownDigest: prepared.runtimeTeardownDigest,
          expectedCandidateHash: candidateBefore.hash,
          sealedAt: this.now().toISOString(),
        };
      sealed = this.transitionWriter
        ? await this.transitionWriter.sealProposal(sealInput)
        : await this.proposalStore.seal(sealInput);
    } catch (error) {
      const invalid = error instanceof ProposalSealError && error.code === "CANDIDATE_INVALID";
      return this.reject(
        prepared,
        invalid ? "QUARANTINED" : "ABORTED",
        invalid ? "agent_wrong" : "evidence_broken",
        [this.reason(error)],
        [],
        { changes: candidateStatic.changes, candidateHash: candidateBefore.hash },
      );
    }

    await rm(prepared.candidatePath, { recursive: true, force: true });
    const sealedStatic = await validateCandidate(
      prepared.policy,
      prepared.baseManifest,
      sealed.manifest,
      sealed.payloadPath,
      this.options.sensitiveValues,
    );
    if (patchHash(sealedStatic.changes) !== changedPathsDigest || sealed.manifest.hash !== candidateBefore.hash) {
      return this.reject(prepared, "ABORTED", "evidence_broken", ["SEALED_PROPOSAL_DIFF_MISMATCH"], [], {
        sealed,
        changes: sealedStatic.changes,
      });
    }
    if (sealedStatic.failures.length > 0) {
      return this.reject(prepared, "QUARANTINED", "agent_wrong", sealedStatic.failures, [], {
        sealed,
        changes: sealedStatic.changes,
      });
    }
    if (
      this.options.requireRuntimeTeardownEvidence === true &&
      !prepared.runtimeTeardownVerified
    ) {
      return this.reject(
        prepared,
        "ABORTED",
        "evidence_broken",
        ["RUNTIME_TEARDOWN_EVIDENCE_MISSING"],
        [],
        { sealed, changes: sealedStatic.changes },
      );
    }
    if (
      this.options.requireTrustedChecks === true &&
      prepared.policy.protectedPaths.length > 0 &&
      prepared.policy.requiredChecks.length === 0
    ) {
      return this.reject(prepared, "ABORTED", "evidence_broken", ["TRUSTED_CHECK_SET_REQUIRED"], [], {
        sealed,
        changes: sealedStatic.changes,
      });
    }
    if (signal?.aborted) {
      return this.reject(prepared, "ABORTED", "infra_errored", [this.reason(signal.reason ?? new Error("Run cancelled"))], [], {
        sealed,
        changes: sealedStatic.changes,
      });
    }

    let context: EvaluationContext;
    let evaluationContextHash: string;
    try {
      context = await this.buildEvaluationContext(prepared, sealed);
      evaluationContextHash = computeEvaluationContextHash(context);
    } catch (error) {
      return this.reject(prepared, "ABORTED", "infra_errored", ["EVALUATION_CONTEXT_ERROR:" + this.reason(error)], [], {
        sealed,
        changes: sealedStatic.changes,
      });
    }
    if (context.policyHash !== prepared.policyHash) {
      return this.reject(prepared, "ABORTED", "evidence_broken", ["POLICY_CHANGED_BEFORE_VERIFICATION"], [], {
        sealed,
        changes: sealedStatic.changes,
        evaluationContextHash,
      });
    }

    const checks: CheckResult[] = [];
    try {
      // Verifier mounts the gate-owned sealed payload itself read-only. A
      // mutable verify clone would re-introduce a switch-then-restore window.
      await assertReadonlySealedPayload(
        sealed.payloadPath,
        prepared.policy,
        sealed.manifest,
      );
      const rawChecks = await this.options.verifier.run({
        runId: prepared.runId,
        agentId: prepared.agentId,
        verifyPath: sealed.payloadPath,
        trustedChecksPath: this.trustedChecksRoot,
        checks: prepared.policy.requiredChecks,
        timeoutMs: prepared.policy.verifierTimeoutMs,
        maxOutputBytes: prepared.policy.verifierMaxOutputBytes,
        proposalId: sealed.proposal.proposalId,
        evaluationContextHash,
        checkBundleHash: context.checkBundleHash,
        ...(signal ? { signal } : {}),
      });
      checks.push(...rawChecks.map(normalizeCheckResult));
    } catch (error) {
      const reason = signal?.aborted ? this.reason(signal.reason ?? error) : "VERIFIER_INFRA_ERROR:" + this.reason(error);
      return this.reject(prepared, "ABORTED", "infra_errored", [reason], checks, {
        sealed,
        changes: sealedStatic.changes,
        evaluationContextHash,
      });
    }

    try {
      const [, sealedAfter, contextAfter] = await Promise.all([
        assertReadonlySealedPayload(
          sealed.payloadPath,
          prepared.policy,
          sealed.manifest,
        ),
        this.proposalStore.resolve(prepared.controlPath, sealed.proposal.proposalId, prepared.policy),
        this.buildEvaluationContext(prepared, sealed),
      ]);
      if (sealedAfter.proposal.artifactHash !== sealed.proposal.artifactHash) throw new Error("SEALED_PROPOSAL_MUTATED");
      if (computeEvaluationContextHash(contextAfter) !== evaluationContextHash) throw new Error("EVALUATION_CONTEXT_CHANGED");
    } catch (error) {
      return this.reject(prepared, "ABORTED", "evidence_broken", [this.reason(error)], checks, {
        sealed,
        changes: sealedStatic.changes,
        evaluationContextHash,
      });
    }

    const assessment = assessTrustedChecks(checks, prepared.policy);
    if (assessment.evidenceFailures.length > 0) {
      return this.reject(prepared, "ABORTED", "evidence_broken", assessment.evidenceFailures, checks, {
        sealed,
        changes: sealedStatic.changes,
        evaluationContextHash,
      });
    }
    if (assessment.resultFailures.length > 0) {
      return this.reject(prepared, "QUARANTINED", "agent_wrong", assessment.resultFailures, checks, {
        sealed,
        changes: sealedStatic.changes,
        evaluationContextHash,
      });
    }

    let currentView: StateViewRef;
    try {
      currentView = await this.captureStateView(
        prepared.agentId,
        prepared.persistentPath,
        prepared.policy,
        prepared.baseView.sessionEpoch,
        {
          generation: prepared.baseView.generation,
          headVersionId: prepared.baseView.headVersionId,
          agentConfigVersion: prepared.baseView.agentConfigVersion,
          policyVersion: prepared.baseView.policyVersion,
        },
      );
    } catch (error) {
      return this.reject(prepared, "ABORTED", "infra_errored", ["STATE_VIEW_CAPTURE_ERROR:" + this.reason(error)], checks, {
        sealed,
        changes: sealedStatic.changes,
        evaluationContextHash,
      });
    }
    if (currentView.viewId !== prepared.baseView.viewId) {
      return this.reject(prepared, "CONFLICTED", "state_conflict", ["STATE_VIEW_CONFLICT"], checks, {
        sealed,
        changes: sealedStatic.changes,
        evaluationContextHash,
      });
    }

    const evidence = createEvidenceBundle({
      proposalId: sealed.proposal.proposalId,
      evaluationContextHash,
      verifierInputHash: sealed.proposal.manifestHash,
      checkResultsHash: computeCheckResultsHash(checks),
      coverage: assessment.evidenceComplete ? "complete" : "partial",
      requiredChecksPassed:
        assessment.evidenceComplete &&
        assessment.evidenceFailures.length === 0 &&
        assessment.resultFailures.length === 0 &&
        checks.every((check) => check.status === "PASS"),
      issuedAt: this.now().toISOString(),
    });
    let permit: PromotionPermit | null = null;
    let capability: PromotionCapability | null = null;
    let handle: PromotionHandle | null = null;
    try {
      permit = await this.permitStore.issue({
        runId: prepared.runId,
        agentId: prepared.agentId,
        controlPath: prepared.controlPath,
        proposal: sealed.proposal,
        baseView: prepared.baseView,
        evaluationContextHash,
        evidence,
      });
      const promotionSource = await this.proposalStore.resolve(
        prepared.controlPath,
        sealed.proposal.proposalId,
        prepared.policy,
      );
      capability = await this.permitStore.claim({
        agentId: prepared.agentId,
        controlPath: prepared.controlPath,
        permitId: permit.permitId,
        proposal: promotionSource.proposal,
        proposalPath: promotionSource.payloadPath,
        proposalManifest: promotionSource.manifest,
        baseView: prepared.baseView,
        evaluationContextHash,
        evidenceDigest: evidence.digest,
      });
      permit = capability.permit;
      // Persist the complete protocol binding before entering rename-swap.
      // If the process dies after the swap but before the normal promoted
      // receipt write, startup recovery can still disposition this nonterminal
      // transaction record instead of recovering an unaudited workspace.
      let receipt = this.makeReceipt({
        prepared,
        decision: "COMMITTED",
        failureClass: null,
        reasonCodes: [],
        checks,
        candidateHash: sealed.proposal.manifestHash,
        finalHash: sealed.proposal.manifestHash,
        changedPaths: sealedStatic.changes.map((change) => change.path),
        patch: changedPathsDigest,
        versionId: null,
        pendingAck: true,
        staticEvidence: "complete",
        candidateCleanup: "deleted",
        proposalId: sealed.proposal.proposalId,
        evaluationContextHash,
        evidenceDigest: evidence.digest,
        permit,
      });
      await this.receiptStore.put(receipt);
      const promoteInput = {
        runId: prepared.runId,
        agentId: prepared.agentId,
        persistentPath: prepared.persistentPath,
        controlPath: prepared.controlPath,
        policy: prepared.policy,
        capability,
        assertCurrentView: async () => {
          const latestContext = await this.buildEvaluationContext(
            prepared,
            sealed,
          );
          if (
            computeEvaluationContextHash(latestContext) !==
            evaluationContextHash
          ) {
            throw new Error("EVALUATION_CONTEXT_CHANGED_BEFORE_SWAP");
          }
          const latest = await this.captureStateView(
            prepared.agentId,
            prepared.persistentPath,
            prepared.policy,
            prepared.baseView.sessionEpoch,
            {
              generation: prepared.baseView.generation,
              headVersionId: prepared.baseView.headVersionId,
              agentConfigVersion: prepared.baseView.agentConfigVersion,
              policyVersion: prepared.baseView.policyVersion,
            },
          );
          return latest.viewId === prepared.baseView.viewId;
        },
      };
      handle = this.transitionWriter
        ? await this.transitionWriter.applyPromotion(promoteInput)
        : await this.transaction!.promoteAuthorized(promoteInput);
      permit = await this.permitStore.markConsumed(prepared.controlPath, capability);
      const finalManifest = await buildManifest(prepared.persistentPath, prepared.policy);
      receipt = {
        ...receipt,
        finalSnapshotHash: finalManifest.hash,
        permitState: permit.state,
        completedAt: this.now().toISOString(),
      };
      await this.receiptStore.put(receipt);
      this.pending.set(prepared.runId, { prepared, handle, receipt, sealed, permit, capability });
      try {
        await this.cleanupTransient(prepared);
      } catch {
        receipt = { ...receipt, candidateCleanup: "deferred" };
        await this.receiptStore.put(receipt);
        this.pending.get(prepared.runId)!.receipt = receipt;
      }
      return { receipt, summary: this.toSummary(receipt) };
    } catch (error) {
      if (error instanceof CommitGateRecoveryRequiredError) throw error;
      if (handle) {
        this.pending.delete(prepared.runId);
        try {
          await handle.rollback();
        } catch (rollbackError) {
          throw new CommitGateRecoveryRequiredError(
            "CommitGate promotion finalization and fail-closed rollback both failed",
            new AggregateError([error, rollbackError]),
          );
        }
      }
      if (permit) await this.permitStore.revoke(prepared.controlPath, permit.permitId).catch(() => undefined);
      const details = {
        sealed,
        changes: sealedStatic.changes,
        evaluationContextHash,
        evidenceDigest: evidence.digest,
        permit,
      };
      if (error instanceof StateConflictError) {
        return this.reject(prepared, "CONFLICTED", "state_conflict", [error.message], checks, details);
      }
      const contextDrift = this.reason(error).startsWith(
        "EVALUATION_CONTEXT_CHANGED",
      );
      return this.reject(
        prepared,
        "ABORTED",
        contextDrift ? "evidence_broken" : "infra_errored",
        [this.reason(error)],
        checks,
        details,
      );
    }
  }

  async acknowledge(runId: string): Promise<GateFinalization> {
    const pending = this.pending.get(runId);
    if (!pending) throw new Error("No pending CommitGate promotion for run " + runId);
    const staged = await this.stageAcknowledge(runId);
    await pending.handle.acknowledge();
    const receipt: GateReceipt = {
      ...staged.receipt,
      phase: "TERMINAL",
      transactionStatus: "TERMINAL",
      artifactRetention: "version_snapshot",
      promotionPendingDatabaseAck: false,
      permitState: "CONSUMED",
    };
    await this.versionStore.releaseRetention(pending.prepared.agentId);
    await this.proposalStore.destroy(pending.prepared.controlPath, pending.sealed.proposal.proposalId).catch(() => undefined);
    await this.receiptStore.put(receipt);
    this.pending.delete(runId);
    return { receipt, summary: this.toSummary(receipt) };
  }

  async stageAcknowledge(runId: string): Promise<GateFinalization> {
    const pending = this.pending.get(runId);
    if (!pending) throw new Error("No pending CommitGate promotion for run " + runId);
    if (pending.receipt.versionId) return { receipt: pending.receipt, summary: this.toSummary(pending.receipt) };
    const sealed = await this.proposalStore.resolve(
      pending.prepared.controlPath,
      pending.sealed.proposal.proposalId,
      pending.prepared.policy,
    );
    const version = await this.versionStore.recordCommit(
      pending.prepared.agentId,
      pending.prepared.persistentPath,
      pending.prepared.policy,
      runId,
      {
        deferPrune: true,
        sourcePath: sealed.payloadPath,
        sourceManifest: sealed.manifest,
      },
    );
    const platformManagedHash = (
      await buildManifest(pending.prepared.persistentPath, pending.prepared.policy, {
        include: new Set(["platformManaged"]),
      })
    ).hash;
    const nextView = createStateViewRef({
      schemaVersion: 1,
      agentId: pending.prepared.agentId,
      headVersionId: version.id,
      generation: pending.prepared.baseView.generation + 1,
      versionedHash: version.snapshotHash,
      platformManagedHash,
      liveStateHash: pending.receipt.finalSnapshotHash,
      sessionEpoch: pending.prepared.baseView.sessionEpoch,
      agentConfigVersion: pending.prepared.baseView.agentConfigVersion,
      policyVersion: pending.prepared.baseView.policyVersion,
    });
    pending.receipt = {
      ...pending.receipt,
      versionId: version.id,
      promotionPendingDatabaseAck: true,
      artifactRetention: "version_snapshot",
      nextView,
      finalViewId: nextView.viewId,
      baseGeneration: pending.prepared.baseView.generation,
      nextGeneration: pending.prepared.baseView.generation + 1,
      generation: pending.prepared.baseView.generation + 1,
    };
    await this.receiptStore.put(pending.receipt);
    return { receipt: pending.receipt, summary: this.toSummary(pending.receipt) };
  }

  async rollbackPending(runId: string): Promise<void> {
    const pending = this.pending.get(runId);
    if (!pending) return;
    await pending.handle.rollback();
    await this.versionStore.revertRunVersion(pending.prepared.agentId, runId);
    const receipt: GateReceipt = {
      ...pending.receipt,
      decision: "ABORTED",
      phase: "TERMINAL",
      transactionStatus: "TERMINAL",
      artifactRetention: "destroyed",
      failureClass: "infra_errored",
      reasonCodes: [...pending.receipt.reasonCodes, "DATABASE_COMMIT_ROLLED_BACK"],
      finalSnapshotHash: pending.prepared.baseSnapshotHash,
      nextView: null,
      finalViewId: null,
      baseGeneration: pending.prepared.baseView.generation,
      nextGeneration: pending.prepared.baseView.generation,
      generation: pending.prepared.baseView.generation,
      threadDisposition: "reset",
      sessionEpoch: pending.prepared.sessionEpoch + 1,
      versionId: null,
      promotionPendingDatabaseAck: false,
      completedAt: this.now().toISOString(),
    };
    await this.receiptStore.put(receipt);
    this.pending.delete(runId);
    await this.proposalStore.destroy(pending.prepared.controlPath, pending.sealed.proposal.proposalId).catch(() => undefined);
  }

  async finalizeDisposition(
    agentId: string,
    runId: string,
    finalView: StateViewRef,
  ): Promise<GateFinalization> {
    assertStateViewRef(finalView);
    const receipt = await this.receiptStore.get(agentId, runId);
    if (!receipt) throw new Error("Non-promotion receipt not found");
    if (receipt.phase === "TERMINAL") {
      return { receipt, summary: this.toSummary(receipt) };
    }
    if (
      receipt.phase !== "PENDING_DISPOSITION" ||
      receipt.decision === "COMMITTED" ||
      finalView.agentId !== agentId ||
      finalView.liveStateHash !== receipt.finalSnapshotHash ||
      finalView.generation !== receipt.generation
    ) {
      throw new Error("NON_PROMOTION_DISPOSITION_BINDING_MISMATCH");
    }
    const terminal: GateReceipt = {
      ...receipt,
      phase: "TERMINAL",
      transactionStatus: "TERMINAL",
      finalViewId: finalView.viewId,
      nextView: structuredClone(finalView),
      sessionEpoch: finalView.sessionEpoch,
      artifactRetention: "destroyed",
      completedAt: this.now().toISOString(),
    };
    await this.receiptStore.put(terminal);
    return { receipt: terminal, summary: this.toSummary(terminal) };
  }

  async abort(prepared: PreparedCandidate, error: unknown): Promise<GateFinalization> {
    return this.reject(prepared, "ABORTED", "infra_errored", [this.reason(error)], []);
  }

  /**
   * Every admitted run gets a receipt even when candidate materialization never
   * produced a PreparedCandidate. Unknown evidence is represented explicitly;
   * no synthetic hash is presented as observed workspace evidence.
   */
  async recordAdmissionFailure(
    input: AdmissionFailureInput,
    error: unknown,
    decision: "ABORTED" | "CONFLICTED" = "ABORTED",
  ): Promise<GateFinalization> {
    assertSafeIdentifier(input.runId, "runId");
    assertSafeIdentifier(input.agentId, "agentId");
    const existing = await this.receiptStore.get(input.agentId, input.runId);
    if (existing) return { receipt: existing, summary: this.toSummary(existing) };
    let currentPolicy = validatePolicy(this.options.defaultPolicy ?? defaultCommitGatePolicy);
    try {
      currentPolicy = await this.policyForAgent(input.agentId);
    } catch {
      // The admission error itself may be an invalid policy. The fallback hash
      // is identified as unavailable in evidence rather than treated as proof.
    }
    const unavailableHash =
      input.baseLiveStateHash ??
      sha256Canonical({ unavailable: "admission-live-state", runId: input.runId });
    const receipt = sanitizeReceipt(
      {
        schemaVersion: 2,
        runId: input.runId,
        agentId: input.agentId,
        phase: "PENDING_DISPOSITION",
        decision,
        failureClass: decision === "CONFLICTED" ? "state_conflict" : "infra_errored",
        reasonCodes: [
          (decision === "CONFLICTED" ? "ADMISSION_VIEW_CONFLICT:" : "ADMISSION_FAILED:") +
            this.reason(error),
        ],
        baseSnapshotHash: unavailableHash,
        candidateSnapshotHash: null,
        patchHash: null,
        finalSnapshotHash: unavailableHash,
        policyHash: policyHash(currentPolicy),
        evidence: { admission: "unavailable", static: "unavailable", trustedChecks: "unavailable" },
        checks: [],
        changedPaths: [],
        threadDisposition: "reset",
        candidateCleanup: "deleted",
        sessionEpoch: input.sessionEpoch + 1,
        versionId: null,
        promotionPendingDatabaseAck: false,
        ...(input.baseViewId ? { baseViewId: input.baseViewId } : {}),
        baseView: null,
        nextView: null,
        finalViewId: null,
        baseGeneration: input.stateGeneration ?? 0,
        nextGeneration: input.stateGeneration ?? 0,
        generation: input.stateGeneration ?? 0,
        proposalId: null,
        evaluationContextHash: null,
        evidenceDigest: null,
        permitId: null,
        permitState: null,
        transactionStatus: "PENDING_DISPOSITION",
        artifactRetention: "destroyed",
        provider: input.provider ? structuredClone(input.provider) : null,
        startedAt: input.startedAt ?? this.now().toISOString(),
        completedAt: this.now().toISOString(),
      },
      this.options.sensitiveValues,
    );
    await this.receiptStore.put(receipt);
    return { receipt, summary: this.toSummary(receipt) };
  }

  private async reject(
    prepared: PreparedCandidate,
    decision: Exclude<GateDecision, "COMMITTED">,
    failureClass: FailureClass,
    reasonCodes: string[],
    checks: CheckResult[],
    details: ProtocolReceiptDetails = {},
  ): Promise<GateFinalization> {
    const finalManifest = await buildManifest(prepared.persistentPath, prepared.policy);
    let changes = details.changes ?? [];
    let staticEvidence: GateReceipt["evidence"][string] = details.changes ? "complete" : "unavailable";
    if (!details.changes) {
      try {
        if (await pathExists(prepared.candidatePath)) {
          const candidate = await buildManifest(prepared.candidatePath, prepared.policy);
          changes = diffManifests(prepared.baseManifest, candidate);
          staticEvidence = "complete";
        }
      } catch {
        // Invalid candidates still receive a metadata-only fail-closed receipt.
      }
    }
    let candidateCleanup: GateReceipt["candidateCleanup"] = "deleted";
    try {
      await this.cleanupTransient(prepared);
      if (details.sealed) await this.proposalStore.destroy(prepared.controlPath, details.sealed.proposal.proposalId);
    } catch {
      candidateCleanup = "deferred";
    }
    const receipt = this.makeReceipt({
      prepared,
      decision,
      failureClass,
      reasonCodes,
      checks,
      candidateHash:
        details.candidateHash === undefined ? (details.sealed?.proposal.manifestHash ?? null) : details.candidateHash,
      finalHash: finalManifest.hash,
      changedPaths: changes.map((change) => change.path),
      patch: changes.length > 0 ? patchHash(changes) : null,
      versionId: null,
      pendingAck: false,
      staticEvidence,
      candidateCleanup,
      proposalId: details.sealed?.proposal.proposalId ?? null,
      evaluationContextHash: details.evaluationContextHash ?? null,
      evidenceDigest: details.evidenceDigest ?? null,
      permit: details.permit ?? null,
    });
    await this.receiptStore.put(receipt);
    return { receipt, summary: this.toSummary(receipt) };
  }

  private makeReceipt(input: {
    prepared: PreparedCandidate;
    decision: GateDecision;
    failureClass: FailureClass | null;
    reasonCodes: string[];
    checks: CheckResult[];
    candidateHash: string | null;
    finalHash: string;
    changedPaths: string[];
    patch: string | null;
    versionId: string | null;
    pendingAck: boolean;
    staticEvidence: GateReceipt["evidence"][string];
    candidateCleanup: GateReceipt["candidateCleanup"];
    proposalId: string | null;
    evaluationContextHash: string | null;
    evidenceDigest: string | null;
    permit: PromotionPermit | null;
  }): GateReceipt {
    const requiredComplete = assessTrustedChecks(input.checks, input.prepared.policy).evidenceComplete;
    return sanitizeReceipt(
      {
        schemaVersion: 2,
        runId: input.prepared.runId,
        agentId: input.prepared.agentId,
        phase: input.pendingAck
          ? "PENDING_PROMOTION"
          : input.decision === "COMMITTED"
            ? "TERMINAL"
            : "PENDING_DISPOSITION",
        decision: input.decision,
        failureClass: input.failureClass,
        reasonCodes: input.reasonCodes,
        baseSnapshotHash: input.prepared.baseSnapshotHash,
        candidateSnapshotHash: input.candidateHash,
        patchHash: input.patch,
        finalSnapshotHash: input.finalHash,
        policyHash: input.prepared.policyHash,
        evidence: {
          static: input.staticEvidence,
          trustedChecks:
            input.prepared.policy.requiredChecks.length === 0
              ? "complete"
              : requiredComplete
                ? "complete"
                : input.checks.length > 0
                  ? "partial"
                  : "unavailable",
        },
        checks: input.checks,
        changedPaths: input.changedPaths,
        threadDisposition: input.decision === "COMMITTED" ? "resumed" : "reset",
        candidateCleanup: input.candidateCleanup,
        sessionEpoch: input.decision === "COMMITTED" ? input.prepared.sessionEpoch : input.prepared.sessionEpoch + 1,
        versionId: input.versionId,
        promotionPendingDatabaseAck: input.pendingAck,
        baseViewId: input.prepared.baseView.viewId,
        baseView: structuredClone(input.prepared.baseView),
        nextView: null,
        finalViewId: null,
        baseGeneration: input.prepared.baseView.generation,
        nextGeneration:
          input.decision === "COMMITTED"
            ? input.prepared.baseView.generation + 1
            : input.prepared.baseView.generation,
        generation:
          input.decision === "COMMITTED"
            ? input.prepared.baseView.generation + 1
            : input.prepared.baseView.generation,
        proposalId: input.proposalId,
        evaluationContextHash: input.evaluationContextHash,
        evidenceDigest: input.evidenceDigest,
        permitId: input.permit?.permitId ?? null,
        permitState: input.permit?.state ?? null,
        transactionStatus: input.pendingAck
          ? "PENDING_PROMOTION"
          : input.decision === "COMMITTED"
            ? "TERMINAL"
            : "PENDING_DISPOSITION",
        artifactRetention: input.pendingAck
          ? "sealed"
          : input.candidateCleanup === "deleted"
            ? "destroyed"
            : "deferred",
        provider: input.prepared.provider
          ? structuredClone(input.prepared.provider)
          : null,
        startedAt: input.prepared.startedAt,
        completedAt: this.now().toISOString(),
      },
      this.options.sensitiveValues,
    );
  }

  private async buildEvaluationContext(
    prepared: PreparedCandidate,
    sealed: ResolvedSealedProposal,
  ): Promise<EvaluationContext> {
    const currentPolicyHash = prepared.policyPath
      ? policyHash(await loadPolicy(prepared.policyPath))
      : policyHash(prepared.policy);
    const environment = await this.describeVerifierEnvironment(prepared.runId);
    return {
      schemaVersion: 1,
      runId: prepared.runId,
      agentId: prepared.agentId,
      proposalId: sealed.proposal.proposalId,
      baseView: prepared.baseView,
      manifestSchemaVersion: sealed.manifest.schemaVersion,
      policyHash: currentPolicyHash,
      // The verifier reports the hash of the gate-owned content-addressed
      // payload it will mount. Binding the mutable administrator source here
      // would make the context describe different bytes from execution.
      checkBundleHash: environment.checkBundleHash,
      checkSpecHash: computeCheckSpecHash(prepared.policy.requiredChecks),
      verifierImageDigest: environment.imageDigest,
      verifierConfigHash: sha256Canonical({
        reportedConfigHash: environment.configHash,
        imageReference: environment.imageReference,
        imageId: environment.imageId,
      }),
      resourcePolicyHash:
        environment.resourcePolicyHash ??
        sha256Canonical({
          timeoutMs: prepared.policy.verifierTimeoutMs,
          maxOutputBytes: prepared.policy.verifierMaxOutputBytes,
        }),
      sourceRevision:
        environment.sourceRevision ??
        this.options.sourceRevision ??
        process.env.COMMITGATE_SOURCE_REVISION ??
        "unverified",
    };
  }

  private async describeVerifierEnvironment(runId: string): Promise<VerifierExecutionEnvironment> {
    const described = await this.options.verifier.describeExecutionEnvironment?.(runId);
    if (described) return described;
    const identity = this.options.verifier.constructor.name || "VerifierRunner";
    return {
      imageReference: "unreported:" + identity,
      imageId: "unreported",
      imageDigest: sha256Canonical({ unreportedVerifier: identity }),
      configHash: sha256Canonical({ unreportedConfig: identity }),
      checkBundleHash: "unreported",
    };
  }

  private async captureStateView(
    agentId: string,
    persistentPath: string,
    policy: CommitGatePolicy,
    sessionEpoch: number,
    expected: ExpectedViewMetadata = {},
  ): Promise<StateViewRef> {
    const [live, versioned, platformManaged, head] = await Promise.all([
      buildManifest(persistentPath, policy),
      buildManifest(persistentPath, policy, { include: new Set(["versioned"]) }),
      buildManifest(persistentPath, policy, { include: new Set(["platformManaged"]) }),
      this.versionStore.head(agentId),
    ]);
    if (!head) throw new Error("StateView requires an initialized version head");
    const capture: StateViewCaptureInput = {
      agentId,
      persistentPath,
      headVersionId: expected.headVersionId ?? head.id,
      generation: expected.generation ?? head.sequence,
      versionedHash: versioned.hash,
      platformManagedHash: platformManaged.hash,
      liveStateHash: live.hash,
      sessionEpoch,
      agentConfigVersion: expected.agentConfigVersion ?? 1,
      policyVersion: expected.policyVersion ?? policy.schemaVersion,
    };
    const view = this.stateViewProvider
      ? await this.stateViewProvider.capture(capture)
      : createStateViewRef({
          schemaVersion: 1,
          agentId: capture.agentId,
          headVersionId: capture.headVersionId,
          generation: capture.generation,
          versionedHash: capture.versionedHash,
          platformManagedHash: capture.platformManagedHash,
          liveStateHash: capture.liveStateHash,
          sessionEpoch: capture.sessionEpoch,
          agentConfigVersion: capture.agentConfigVersion,
          policyVersion: capture.policyVersion,
        });
    assertStateViewRef(view);
    if (
      view.agentId !== agentId ||
      view.versionedHash !== versioned.hash ||
      view.platformManagedHash !== platformManaged.hash ||
      view.liveStateHash !== live.hash
    ) {
      throw new Error("StateView provider returned a view for different bytes");
    }
    return view;
  }

  private toSummary(receipt: GateReceipt): CommitGateSummaryData {
    const lifecycle: GateLifecycleEventName[] = ["RUN_STARTED"];
    if (receipt.proposalId) lifecycle.push("PROPOSAL_SEALED");
    if (receipt.checks.length > 0) lifecycle.push("VERIFICATION_COMPLETED");
    if (receipt.permitId) lifecycle.push("PERMIT_ISSUED");
    if (receipt.decision === "COMMITTED") lifecycle.push("VIEW_COMMITTED");
    if (receipt.threadDisposition === "reset") lifecycle.push("SESSION_RESET");
    if (receipt.decision === "ABORTED") lifecycle.push("RUN_ABORTED");
    return {
      decision: receipt.decision,
      failureClass: receipt.failureClass,
      receiptId: receipt.runId,
      baseHash: receipt.baseSnapshotHash,
      candidateHash: receipt.candidateSnapshotHash,
      finalHash: receipt.finalSnapshotHash,
      policyHash: receipt.policyHash,
      checks: receipt.checks.map((check) => ({
        id: check.id,
        status: check.status,
        reasonCode:
          check.status === "PASS"
            ? null
            : check.timedOut
              ? "CHECK_TIMEOUT"
              : check.status === "FAIL"
                ? "CHECK_NONZERO_EXIT"
                : check.status === "SKIPPED"
                  ? "CHECK_SKIPPED"
                  : "CHECK_ERROR",
      })),
      changedPaths: receipt.changedPaths,
      threadDisposition: receipt.threadDisposition,
      candidateCleanup: receipt.candidateCleanup ?? "deferred",
      transactionStatus:
        receipt.transactionStatus ??
        (receipt.promotionPendingDatabaseAck ? "PENDING_PROMOTION" : "TERMINAL"),
      baseViewId: receipt.baseViewId ?? null,
      nextViewId: receipt.finalViewId ?? null,
      baseGeneration:
        receipt.baseGeneration ??
        (receipt.generation === undefined
          ? null
          : receipt.decision === "COMMITTED" && receipt.finalViewId
            ? Math.max(0, receipt.generation - 1)
            : receipt.generation),
      nextGeneration:
        receipt.nextGeneration ?? receipt.generation ?? null,
      proposalId: receipt.proposalId ?? null,
      proposalHash: receipt.candidateSnapshotHash,
      evaluationContextHash: receipt.evaluationContextHash ?? null,
      evidenceDigest: receipt.evidenceDigest ?? null,
      permitId: receipt.permitId ?? null,
      permitState: receipt.permitState ?? null,
      artifactRetention:
        receipt.artifactRetention === "sealed"
          ? "deferred"
          : receipt.artifactRetention ??
            (receipt.decision === "COMMITTED" ? "version_snapshot" : "destroyed"),
      provider: receipt.provider ?? null,
      lifecycle: lifecycle.map((name, index) => ({ sequence: index + 1, name })),
    };
  }

  private async cleanupTransient(prepared: PreparedCandidate): Promise<void> {
    await Promise.all([
      rm(prepared.candidatePath, { recursive: true, force: true }),
      rm(prepared.verifyPath, { recursive: true, force: true }),
    ]);
  }

  private reason(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
  }
}
