import { createHash, randomUUID } from "node:crypto";
import type { RuntimeTeardownAttestation } from "./container-codex-runner.js";
import {
  CommitGateRecoveryRequiredError,
  HttpError,
  RunCancelledError,
} from "./errors.js";
import {
  computeCheckResultsHash,
  computeEvaluationContextHash,
  sha256Canonical,
} from "./commitgate/protocol.js";
import {
  WORKER_CHECK_SPEC_HASH,
  WORKER_GATE_POLICY_HASH,
  WORKER_MANIFEST_SCHEMA_VERSION,
  workerGatePolicy,
} from "./worker-gate-policy.js";
import { deriveEffectDispositionProof } from "./commitgate/effect-proof.js";
import type {
  CheckResult,
  EvaluationContext,
  GateFinalization,
  GateReceipt,
  PromotionPermit,
  StateViewRef,
} from "./commitgate/types.js";
import type { TransitionAuthorityClient } from "./transition-authority-client.js";
import type {
  AgentRunner,
  CommitGateSummary,
  RunnerCancellation,
  RunnerRequest,
  RunnerResult,
} from "./types.js";
import type {
  BrokerReconcileRequest,
  BrokerTeardownRequest,
  BrokerVerifierRequest,
  BrokerVerifierResult,
  RuntimeReconciliationAttestation,
  SignedBrokerRuntimeTeardownAttestation,
} from "./runtime-broker/contracts.js";
import type { PreparedRunRef } from "./transition-worker/worker.js";
import type { WorkerProjection } from "./transition-worker/projection.js";

interface BrokerBackedRunner extends AgentRunner {
  attestCommitGateTeardown(
    request: BrokerTeardownRequest,
  ): Promise<SignedBrokerRuntimeTeardownAttestation | RuntimeTeardownAttestation>;
  reconcileCommitGateRuntime(
    request: BrokerReconcileRequest,
  ): Promise<RuntimeReconciliationAttestation>;
  runVerifier(request: BrokerVerifierRequest): Promise<BrokerVerifierResult>;
}

interface StoredRun {
  request: RunnerRequest;
  baseView: StateViewRef;
  proposalId: string | null;
  permit: PromotionPermit | null;
  promotionInput: Parameters<TransitionAuthorityClient["applyPromotion"]>[0] | null;
  receipt: GateReceipt;
  summary: CommitGateSummary;
}

interface ActiveWorkerRun {
  request: RunnerRequest;
  controller: AbortController;
  admitted: Promise<void>;
  resolveAdmission: () => void;
  admissionResolved: boolean;
  prepared: PreparedRunRef | null;
  cancellationAccepted: boolean;
}

const STATE_CONFLICT_CODES = new Set([
  "VIEW_CAS_MISMATCH",
  "WORKSPACE_CAS_MISMATCH",
]);

const isManifestPolicyFault = (code: string): boolean =>
  code.startsWith("POLICY_MANIFEST_");

const manifestPolicyPathReason = (error: unknown): string | null => {
  if (!(error instanceof Error)) return null;
  const marker = "; path=";
  const offset = error.message.indexOf(marker);
  if (offset < 0) return null;
  const path = error.message.slice(offset + marker.length);
  if (!/^[A-Za-z0-9._/:-]{1,80}$/.test(path)) return null;
  return `POLICY_MANIFEST_PATH:${path}`;
};

/**
 * Only transport failures can make the result of an authority mutation
 * ambiguous.  A typed Worker fault is already a definitive negative outcome
 * and must never be "recovered" into a different terminal decision.  In
 * particular, running recovery for VIEW_CAS_MISMATCH would dispose the stale
 * PERMITTED transition as ABORTED before AgentService can terminalize it as
 * CONFLICTED.
 */
const AMBIGUOUS_AUTHORITY_RESPONSE_CODES = new Set([
  "WORKER_RPC_TIMEOUT",
  "WORKER_RPC_TRUNCATED",
  "RPC_RESPONSE_TOO_LARGE",
  "RPC_RESPONSE_ID_MISMATCH",
  "ECONNRESET",
  "EPIPE",
  "ERR_STREAM_PREMATURE_CLOSE",
]);

const now = (): string => new Date().toISOString();
const WORKER_POLICY = workerGatePolicy();

function summaryLifecycle(
  summary: CommitGateSummary,
): NonNullable<CommitGateSummary["lifecycle"]> {
  const names: NonNullable<CommitGateSummary["lifecycle"]>[number]["name"][] = ["RUN_STARTED"];
  if (summary.proposalId) names.push("PROPOSAL_SEALED");
  if (summary.checks.length > 0) names.push("VERIFICATION_COMPLETED");
  if (summary.permitId) names.push("PERMIT_ISSUED");
  if (summary.decision === "COMMITTED") names.push("VIEW_COMMITTED");
  if (summary.threadDisposition === "reset") names.push("SESSION_RESET");
  if (summary.decision === "ABORTED") names.push("RUN_ABORTED");
  return names.map((name, index) => ({ sequence: index + 1, name }));
}

/** Production CommitGate path backed by the out-of-process transition authority. */
export class WorkerCommitGateRunner implements AgentRunner {
  readonly mode = "worker" as const;
  private readonly runs = new Map<string, StoredRun>();
  private readonly active = new Map<string, ActiveWorkerRun>();

  constructor(
    private readonly inner: BrokerBackedRunner,
    readonly authority: TransitionAuthorityClient,
    private readonly exchangeRoot: string,
    private readonly sourceRevision: string,
    private readonly requireVerifiedSourceRevision = false,
  ) {}

  async isAvailable(): Promise<boolean> {
    try {
      await this.authority.initialize();
      return await this.inner.isAvailable();
    } catch {
      return false;
    }
  }

  async run(request: RunnerRequest): Promise<RunnerResult> {
    if (this.active.has(request.agentId)) throw new Error("Agent already has an active Worker run");
    if (
      !request.baseViewId ||
      request.stateGeneration === undefined ||
      !request.baseLiveStateHash
    ) {
      throw new Error("WORKER_AUTHORITY_BASE_VIEW_REQUIRED");
    }
    let resolveAdmission!: () => void;
    const active: ActiveWorkerRun = {
      request,
      controller: new AbortController(),
      admitted: new Promise<void>((resolve) => {
        resolveAdmission = resolve;
      }),
      resolveAdmission: () => {
        if (active.admissionResolved) return;
        active.admissionResolved = true;
        resolveAdmission();
      },
      admissionResolved: false,
      prepared: null,
      cancellationAccepted: false,
    };
    this.active.set(request.agentId, active);
    const candidateVolumeId = `candidate-${request.runId}`;
    const prepareInput: Parameters<TransitionAuthorityClient["prepareRun"]>[0] = {
      agentId: request.agentId,
      transitionId: request.runId,
      runId: request.runId,
      runLeaseId: request.runLeaseId ?? request.runId,
      candidateVolumeId,
      expectedViewId: request.baseViewId,
      expectedWorkspaceHash: request.baseLiveStateHash,
      baseGeneration: request.stateGeneration,
      sessionEpoch: request.sessionEpoch ?? 0,
    };
    let output = "";
    let threadId: string | null = null;
    let usage: RunnerResult["usage"] = null;
    let prepared: PreparedRunRef | null = null;
    let evidenceRequest = request;
    let proposalId: string | null = null;
    let proposalHash: string | null = null;
    let changedPaths: string[] = [];
    let observedChecks: CheckResult[] = [];
    let evaluationContextHash: string | null = null;
    let evidenceDigest: string | null = null;
    let runtimeTeardownDigest: string | null = null;
    try {
      prepared = await this.authority.prepareRun(prepareInput);
      active.prepared = prepared;
      active.resolveAdmission();
      this.throwIfCancelled(active);
      const result = await this.inner.run({
        ...request,
        workspacePath: `${this.exchangeRoot}/${candidateVolumeId}`,
        workspaceRef: {
          volumeId: candidateVolumeId,
          relativeSubpath: candidateVolumeId,
          runId: request.runId,
          agentId: request.agentId,
        },
      });
      output = result.output;
      threadId = result.threadId;
      usage = result.usage;
      this.throwIfCancelled(active);
      const teardown = await this.inner.attestCommitGateTeardown(
        this.teardownRequest(request, "AGENT"),
      );
      if (teardown.resolvedModel && request.provider) {
        evidenceRequest = {
          ...request,
          provider: { ...request.provider, resolvedModel: teardown.resolvedModel },
        };
      }
      this.throwIfCancelled(active);
      if (!teardown.containerExited || !teardown.containerRemoved || !teardown.mountsReleased) {
        return this.nonCommitResult(
          evidenceRequest,
          prepared.baseView,
          output,
          usage,
          "ABORTED",
          "infra_errored",
          ["RUNTIME_TEARDOWN_EVIDENCE_MISSING"],
          [],
          null,
        );
      }
      runtimeTeardownDigest = await this.recordRuntimeTeardown(
        request,
        "AGENT",
        teardown,
      );

      proposalId = `proposal-${request.runId}`;
      const sealedProjection = await this.authority.sealProposal({
        agentId: request.agentId,
        transitionId: request.runId,
        proposalId,
        sourceVolumeId: candidateVolumeId,
        baseViewId: prepared.baseView.viewId,
        runtimeTeardownDigest,
      });
      const proposal = sealedProjection.proposals[proposalId];
      if (!proposal) throw new Error("WORKER_PROPOSAL_PROJECTION_MISSING");
      proposalHash = proposal.artifactHash;
      changedPaths = proposal.changedPaths;
      this.throwIfCancelled(active);
      if (proposal.staticFailures.length > 0) {
        const policyTeardown = await this.inner.attestCommitGateTeardown(
          this.teardownRequest(request, "ALL"),
        );
        await this.recordRuntimeTeardown(request, "ALL", policyTeardown);
        return this.nonCommitResult(
          evidenceRequest,
          prepared.baseView,
          output,
          usage,
          "QUARANTINED",
          "agent_wrong",
          proposal.staticFailures,
          [],
          proposalId,
          proposal.artifactHash,
          proposal.changedPaths,
        );
      }

      const exportVolumeId = `verify-${request.runId}`;
      const exported = await this.authority.exportProposal({
        agentId: request.agentId,
        transitionId: request.runId,
        proposalId,
        exportVolumeId,
      });
      this.throwIfCancelled(active);
      const checks = WORKER_POLICY.requiredChecks;
      const verification = await this.inner.runVerifier({
        runId: request.runId,
        agentId: request.agentId,
        runLeaseId: request.runLeaseId ?? request.runId,
        sessionEpoch: request.sessionEpoch ?? 0,
        proposalId,
        verifierInputHash: exported.artifactHash,
        checkSpecHash: WORKER_CHECK_SPEC_HASH,
        workspaceRef: {
          volumeId: exportVolumeId,
          relativeSubpath: exported.relativeSubpath,
          runId: request.runId,
          agentId: request.agentId,
        },
        checks,
        timeoutMs: WORKER_POLICY.verifierTimeoutMs,
        maxOutputBytes: WORKER_POLICY.verifierMaxOutputBytes,
      });
      observedChecks = verification.checks;
      this.throwIfCancelled(active);
      const completeTeardown = await this.inner.attestCommitGateTeardown(
        this.teardownRequest(request, "ALL"),
      );
      if (
        !completeTeardown.containerExited ||
        !completeTeardown.containerRemoved ||
        !completeTeardown.mountsReleased
      ) {
        throw Object.assign(
          new Error("Verifier Runtime teardown attestation is incomplete"),
          { code: "RUNTIME_TEARDOWN_EVIDENCE_MISSING" },
        );
      }
      await this.recordRuntimeTeardown(request, "ALL", completeTeardown);
      const verifierSourceRevision = verification.environment.sourceRevision;
      if (
        this.requireVerifiedSourceRevision &&
        (!/^[a-f0-9]{40}$/.test(this.sourceRevision) ||
          verifierSourceRevision !== this.sourceRevision)
      ) {
        throw Object.assign(
          new Error("Verifier image/source revision does not match the frozen product source"),
          { code: "SOURCE_REVISION_MISMATCH" },
        );
      }
      const context: EvaluationContext = {
        schemaVersion: 1,
        runId: request.runId,
        agentId: request.agentId,
        proposalId,
        baseView: prepared.baseView,
        manifestSchemaVersion: WORKER_MANIFEST_SCHEMA_VERSION,
        policyHash: WORKER_GATE_POLICY_HASH,
        checkBundleHash: verification.environment.checkBundleHash,
        checkSpecHash: WORKER_CHECK_SPEC_HASH,
        verifierImageDigest: verification.environment.imageDigest,
        verifierConfigHash: verification.environment.configHash,
        resourcePolicyHash: verification.environment.resourcePolicyHash ?? "unverified",
        sourceRevision: verifierSourceRevision ?? this.sourceRevision,
      };
      evaluationContextHash = computeEvaluationContextHash(context);
      const checkResultsHash = computeCheckResultsHash(verification.checks);
      const expectedCheckIds = new Set(checks.map((check) => check.id));
      const observedCheckIds = new Set(verification.checks.map((check) => check.id));
      const coverage =
        verification.checks.length === checks.length &&
        observedCheckIds.size === expectedCheckIds.size &&
        [...expectedCheckIds].every((id) => observedCheckIds.has(id))
          ? "complete" as const
          : verification.checks.length > 0
            ? "partial" as const
            : "unavailable" as const;
      const requiredChecksPassed =
        coverage === "complete" &&
        verification.checks.every(
          (check) => check.status === "PASS" && check.exitCode === 0 && !check.timedOut,
        );
      evidenceDigest = sha256Canonical({
        schemaVersion: 1,
        proposalId,
        artifactHash: proposal.artifactHash,
        evaluationContextHash,
        checkResultsHash,
      });
      await this.authority.recordEvidence({
        agentId: request.agentId,
        transitionId: request.runId,
        proposalId,
        evaluationContextHash,
        evidenceDigest,
        evaluationContext: context,
        verifierInputHash: exported.artifactHash,
        checkResultsHash,
        coverage,
        requiredChecksPassed,
        checks: verification.checks.map((check) => ({
          id: check.id,
          status: check.status,
          exitCode: check.exitCode,
          durationMs: check.durationMs,
          outputHash: createHash("sha256").update(check.output).digest("hex"),
          timedOut: check.timedOut,
        })),
        brokerAttestation: verification.attestation,
      });
      this.throwIfCancelled(active);
      const infraFailure = verification.checks.some(
        (check) => check.status === "ERROR" || check.status === "SKIPPED" || check.timedOut,
      );
      const checkFailure = verification.checks.some((check) => check.status === "FAIL");
      if (infraFailure || checkFailure) {
        return this.nonCommitResult(
          evidenceRequest,
          prepared.baseView,
          output,
          usage,
          infraFailure ? "ABORTED" : "QUARANTINED",
          infraFailure ? "infra_errored" : "agent_wrong",
          verification.checks
            .filter((check) => check.status !== "PASS")
            .map((check) => `TRUSTED_CHECK_${check.status}:${check.id}`),
          verification.checks,
          proposalId,
          proposal.artifactHash,
          proposal.changedPaths,
          evaluationContextHash,
          evidenceDigest,
        );
      }

      const permitId = `permit-${request.runId}`;
      const expiresAt = new Date(Date.now() + 60_000).toISOString();
      await this.authority.issuePermit({
        agentId: request.agentId,
        transitionId: request.runId,
        permitId,
        proposalId,
        baseViewId: prepared.baseView.viewId,
        targetArtifactHash: proposal.artifactHash,
        evaluationContextHash,
        evidenceDigest,
        expiresAt,
      });
      this.throwIfCancelled(active);
      const versionId = randomUUID();
      const promotionInput = {
        agentId: request.agentId,
        transitionId: request.runId,
        permitId,
        proposalId,
        expectedViewId: prepared.baseView.viewId,
        expectedWorkspaceHash: prepared.baseWorkspaceHash,
        versionId,
        receiptId: request.runId,
      };
      const promotedProjection = await this.authority.applyPromotion(promotionInput);
      const terminal = promotedProjection.terminalReceipts.find(
        (candidate) =>
          candidate.receiptId === request.runId &&
          candidate.transitionId === request.runId &&
          candidate.decision === "COMMITTED",
      );
      if (!terminal) throw new Error("WORKER_TERMINAL_RECEIPT_MISSING");
      const finalView = terminal.view;
      if (
        terminal.workspaceHash !== proposal.artifactHash ||
        finalView.agentId !== request.agentId ||
        finalView.headVersionId !== versionId ||
        finalView.generation !== prepared.baseView.generation + 1 ||
        finalView.sessionEpoch !== prepared.baseView.sessionEpoch ||
        finalView.agentConfigVersion !== prepared.baseView.agentConfigVersion ||
        finalView.policyVersion !== prepared.baseView.policyVersion
      ) {
        throw new Error("WORKER_COMMITTED_VIEW_BINDING_MISMATCH");
      }
      const permit: PromotionPermit = {
        schemaVersion: 1,
        permitId,
        runId: request.runId,
        agentId: request.agentId,
        proposalId,
        baseViewId: prepared.baseView.viewId,
        targetArtifactHash: proposal.artifactHash,
        evaluationContextHash,
        evidenceDigest,
        nonce: randomUUID(),
        expiresAt,
        state: "CONSUMED",
        issuedAt: now(),
        updatedAt: now(),
      };
      const summary = this.summary({
        request: evidenceRequest,
        baseView: prepared.baseView,
        finalView,
        decision: "COMMITTED",
        failureClass: null,
        reasonCodes: [],
        checks: verification.checks,
        proposalId,
        proposalHash: proposal.artifactHash,
        changedPaths: proposal.changedPaths,
        evaluationContextHash,
        evidenceDigest,
        permit,
        verifierInputHash: exported.artifactHash,
        artifactsDestroyed:
          promotedProjection.transitions[request.runId]?.artifactsDestroyed === true,
      });
      const receipt = this.receipt(evidenceRequest, summary, prepared.baseView, finalView);
      this.runs.set(request.runId, {
        request: evidenceRequest,
        baseView: prepared.baseView,
        proposalId,
        permit,
        promotionInput,
        receipt,
        summary,
      });
      return { output, threadId, usage, commitGate: summary };
    } catch (error) {
      const initialCode =
        error && typeof error === "object" && "code" in error && typeof error.code === "string"
          ? error.code
          : error instanceof Error && AMBIGUOUS_AUTHORITY_RESPONSE_CODES.has(error.message)
            ? error.message
            : "WORKER_RUNTIME_ERROR";
      if (!prepared && AMBIGUOUS_AUTHORITY_RESPONSE_CODES.has(initialCode)) {
        // Admission may be durable even though its response was lost. The
        // Worker implements exact-parameter idempotence, so retry recovers the
        // opaque candidate/base references without starting Agent execution.
        // The original transport fault remains an ABORTED run and is disposed
        // through the normal authority-first terminal path.
        try {
          prepared = await this.authority.prepareRun(prepareInput);
          active.prepared = prepared;
          active.resolveAdmission();
        } catch {
          // The authority is still unavailable. Startup recovery owns any
          // durable admission; never guess from API-local state.
        }
      }
      if (prepared) {
        const code =
          error && typeof error === "object" && "code" in error && typeof error.code === "string"
            ? error.code
            : error instanceof Error && AMBIGUOUS_AUTHORITY_RESPONSE_CODES.has(error.message)
              ? error.message
              : "WORKER_RUNTIME_ERROR";
        // A Unix-RPC timeout/truncation is an unknown outcome, not evidence
        // that the Worker rejected the transition. In particular, the Worker
        // may have durably ACKNOWLEDGED promotion before the response was lost.
        // Reconcile from the authority fact source only for those ambiguous
        // transport outcomes. Typed CAS/policy/evidence faults are definitive.
        if (AMBIGUOUS_AUTHORITY_RESPONSE_CODES.has(code)) {
          const recoveredCommit = await this.recoverAcknowledgedCommit({
            request: evidenceRequest,
            baseView: prepared.baseView,
            output,
            threadId,
            usage,
            checks: observedChecks,
          });
          if (recoveredCommit) return recoveredCommit;
        }
        const cancelled =
          active.cancellationAccepted ||
          error instanceof RunCancelledError ||
          code === "RUN_CANCELLED";
        const conflict = STATE_CONFLICT_CODES.has(code);
        const manifestPolicyViolation = isManifestPolicyFault(code);
        const manifestPathReason = manifestPolicyViolation
          ? manifestPolicyPathReason(error)
          : null;
        let runtimeRecoveryCode: string | null = null;
        try {
          await this.reconcileAndRecordRuntimeTeardown(evidenceRequest, "ALL");
        } catch (runtimeError) {
          runtimeRecoveryCode =
            runtimeError && typeof runtimeError === "object" && "code" in runtimeError &&
              typeof runtimeError.code === "string"
              ? runtimeError.code
              : "RUNTIME_TEARDOWN_RECOVERY_PENDING";
        }
        const nonCommit = this.nonCommitResult(
          evidenceRequest,
          prepared.baseView,
          output,
          usage,
          conflict
            ? "CONFLICTED"
            : !cancelled && manifestPolicyViolation
              ? "QUARANTINED"
              : "ABORTED",
          conflict
            ? "state_conflict"
            : !cancelled && manifestPolicyViolation
              ? "agent_wrong"
              : "infra_errored",
          [
            cancelled ? "RUN_CANCELLED" : code,
            ...(manifestPathReason ? [manifestPathReason] : []),
            ...(runtimeRecoveryCode ? [runtimeRecoveryCode] : []),
          ],
          observedChecks,
          proposalId,
          proposalHash,
          changedPaths,
          evaluationContextHash,
          evidenceDigest,
        );
        if (cancelled) throw new RunCancelledError();
        return nonCommit;
      }
      if (active.cancellationAccepted) throw new RunCancelledError();
      throw error;
    } finally {
      active.resolveAdmission();
      this.active.delete(request.agentId);
    }
  }

  async cancel(agentId: string, cancellation?: RunnerCancellation): Promise<boolean> {
    const active = this.active.get(agentId);
    if (!active) return false;
    if (
      !cancellation ||
      active.request.runId !== cancellation.runId ||
      (active.request.runLeaseId ?? active.request.runId) !== cancellation.runLeaseId ||
      (active.request.sessionEpoch ?? 0) !== cancellation.sessionEpoch
    ) {
      return false;
    }
    await active.admitted;
    if (!active.prepared) return false;
    const disposition = await this.authority.cancelRun({
      agentId,
      transitionId: cancellation.runId,
      runId: cancellation.runId,
      runLeaseId: cancellation.runLeaseId,
      expectedViewId: active.prepared.baseView.viewId,
    });
    if (disposition.state === "TOO_LATE") {
      throw new HttpError(
        409,
        "The workspace transition has crossed the irreversible promotion boundary",
        "TRANSITION_IRREVERSIBLE",
      );
    }
    if (disposition.state === "ALREADY_TERMINAL") return false;
    active.cancellationAccepted = true;
    active.controller.abort(new RunCancelledError());
    await this.inner.cancel(agentId, cancellation);
    return true;
  }

  async finalizeDisposition(
    agentId: string,
    runId: string,
    _legacyRequestedFinalView: StateViewRef,
  ): Promise<GateFinalization> {
    const stored = this.runs.get(runId);
    if (!stored || stored.request.agentId !== agentId) throw new Error("WORKER_RUN_NOT_FOUND");
    if (stored.summary.decision === "COMMITTED") return { receipt: stored.receipt, summary: stored.summary };
    // Recovery may already have durably terminalized this run while the API
    // process was unavailable.  Always consult the Worker fact source before
    // deriving a new session epoch; otherwise an idempotent finalize retry
    // would incorrectly request epoch N+2 for a receipt already fixed at N+1.
    let projection = await this.authority.getProjection(agentId);
    let projected = projection.terminalReceipts.find(
      (receipt) => receipt.receiptId === runId && receipt.transitionId === runId,
    );
    if (!projected) {
      if (!projection.head) throw new Error("WORKER_HEAD_MISSING");
      await this.reconcileAndRecordRuntimeTeardown(stored.request, "ALL");
      projection = await this.authority.disposeRun({
        agentId,
        transitionId: runId,
        receiptId: runId,
        decision: stored.summary.decision,
        expectedViewId: projection.head.view.viewId,
        nextSessionEpoch: projection.head.view.sessionEpoch + 1,
        reasonCodes: stored.receipt.reasonCodes,
      });
      projected = projection.terminalReceipts.find(
        (receipt) => receipt.receiptId === runId && receipt.transitionId === runId,
      );
    }
    if (!projected) throw new Error("WORKER_TERMINAL_RECEIPT_MISSING");
    const authoritativeFinalView = projected.view;
    const artifactsDestroyed =
      projection.transitions[runId]?.artifactsDestroyed === true;
    const permitId = projection.transitions[runId]?.permitId;
    const projectedPermitState = permitId ? projection.permits[permitId]?.state ?? null : null;
    const failureClass =
      projected.decision === "CONFLICTED"
        ? "state_conflict"
        : projected.decision === "QUARANTINED"
          ? "agent_wrong"
          : projected.decision === "ABORTED"
            ? (stored.summary.failureClass ?? "infra_errored")
            : null;
    const effectProof = deriveEffectDispositionProof({
      decision: projected.decision,
      baseHash: stored.baseView.liveStateHash,
      candidateHash: stored.summary.candidateHash,
      finalHash: projected.workspaceHash,
      sealedProposalHash: stored.summary.proposalHash ?? null,
      verifierInputHash: null,
      promotionSourceHash: null,
      finalAuthoritativeHash: projected.workspaceHash,
      // The Worker terminal fact is authoritative for disposition-time HEAD.
      // In a CONFLICTED run this may differ from the stale admission base, but
      // the non-effect invariant compares before/after the rejected proposal.
      authoritativeBeforeHash:
        projected.dispositionBaseWorkspaceHash ?? projected.workspaceHash,
    });
    stored.summary = {
      ...stored.summary,
      transactionStatus: "TERMINAL",
      decision: projected.decision,
      failureClass,
      nextViewId: authoritativeFinalView.viewId,
      finalView: authoritativeFinalView,
      finalHash: projected.workspaceHash,
      nextGeneration: authoritativeFinalView.generation,
      permitState: projectedPermitState,
      threadDisposition: projected.decision === "COMMITTED" ? "resumed" : "reset",
      candidateCleanup: artifactsDestroyed ? "deleted" : "deferred",
      artifactRetention: artifactsDestroyed
        ? projected.decision === "COMMITTED"
          ? "version_snapshot"
          : "destroyed"
        : "deferred",
      effectProof,
    };
    stored.summary.lifecycle = summaryLifecycle(stored.summary);
    stored.receipt = {
      ...stored.receipt,
      phase: "TERMINAL",
      transactionStatus: "TERMINAL",
      decision: projected.decision,
      failureClass,
      reasonCodes: projected.reasonCodes,
      nextView: authoritativeFinalView,
      finalViewId: authoritativeFinalView.viewId,
      finalSnapshotHash: projected.workspaceHash,
      sessionEpoch: authoritativeFinalView.sessionEpoch,
      versionId: authoritativeFinalView.headVersionId,
      nextGeneration: authoritativeFinalView.generation,
      generation: authoritativeFinalView.generation,
      permitState: projectedPermitState,
      threadDisposition: projected.decision === "COMMITTED" ? "resumed" : "reset",
      candidateCleanup: artifactsDestroyed ? "deleted" : "deferred",
      artifactRetention: artifactsDestroyed
        ? projected.decision === "COMMITTED"
          ? "version_snapshot"
          : "destroyed"
        : "deferred",
      effectProof,
      completedAt: now(),
    };
    return { receipt: stored.receipt, summary: stored.summary };
  }

  async attemptConsumedPermitReplay(runId: string): Promise<never> {
    const stored = this.runs.get(runId);
    if (!stored?.permit) throw new Error("WORKER_PROMOTION_NOT_FOUND");
    await this.authority.attemptPermitConsumption({
      agentId: stored.request.agentId,
      transitionId: runId,
      permitId: stored.permit.permitId,
      expectedViewId: stored.summary.nextViewId!,
    });
    throw new Error("PERMIT_REPLAY_EXPECTED");
  }

  getReceipt(runId: string): GateReceipt | null {
    return this.runs.get(runId)?.receipt ?? null;
  }

  /**
   * Startup handshake for Worker/Broker/API process-kill recovery. The Broker
   * rediscovers and removes any run-bound Agent/Verifier containers by label;
   * only then may the Worker deterministically terminalize and clean paths.
   */
  async recoverAuthority(
    agentId: string,
    existingProjection?: WorkerProjection,
  ): Promise<WorkerProjection> {
    let projection = existingProjection ?? await this.authority.getProjection(agentId);
    for (const transition of Object.values(projection.transitions)) {
      if (
        !transition.runId ||
        !transition.runLeaseId ||
        transition.artifactsDestroyed ||
        transition.runtimeTeardownAll
      ) continue;
      if (transition.runtimeSessionEpoch === null) {
        throw new CommitGateRecoveryRequiredError(
          `RUNTIME_BINDING_MISSING:${transition.transitionId}`,
        );
      }
      try {
        const attestation = await this.inner.reconcileCommitGateRuntime({
          agentId,
          runId: transition.runId,
          runLeaseId: transition.runLeaseId,
          sessionEpoch: transition.runtimeSessionEpoch,
          scope: "ALL",
        });
        projection = await this.authority.recordRuntimeTeardown({
          agentId,
          transitionId: transition.transitionId,
          attestation,
        });
      } catch (error) {
        throw new CommitGateRecoveryRequiredError(
          `Runtime mount-release reconciliation is required for ${transition.transitionId}`,
          error,
        );
      }
    }
    return this.authority.recover(agentId);
  }

  private async recordRuntimeTeardown(
    request: RunnerRequest,
    scope: "AGENT" | "ALL",
    teardown: SignedBrokerRuntimeTeardownAttestation | RuntimeTeardownAttestation,
  ): Promise<string> {
    if (!teardown.containerExited || !teardown.containerRemoved || !teardown.mountsReleased) {
      throw Object.assign(new Error("Runtime teardown attestation is incomplete"), {
        code: "RUNTIME_TEARDOWN_EVIDENCE_MISSING",
      });
    }
    if ("brokerAttestation" in teardown && teardown.scope !== scope) {
      throw Object.assign(
        new Error("Broker teardown attestation scope differs from the requested Worker fact"),
        { code: "BROKER_ATTESTATION_BINDING_MISMATCH" },
      );
    }
    const projection = await this.authority.recordRuntimeTeardown({
      agentId: request.agentId,
      transitionId: request.runId,
      attestation: "brokerAttestation" in teardown
        ? teardown
        : {
            schemaVersion: 1,
            runId: request.runId,
            agentId: request.agentId,
            runLeaseId: request.runLeaseId ?? request.runId,
            sessionEpoch: request.sessionEpoch ?? 0,
            scope,
            containerExited: true,
            containerRemoved: true,
            mountsReleased: true,
            source: "runtime-attestation",
          },
    });
    const transition = projection.transitions[request.runId];
    const recorded = scope === "AGENT"
      ? transition?.runtimeTeardownAgent
      : transition?.runtimeTeardownAll;
    if (!recorded) throw new Error("WORKER_RUNTIME_TEARDOWN_PROJECTION_MISSING");
    return recorded.digest;
  }

  private async reconcileAndRecordRuntimeTeardown(
    request: RunnerRequest,
    scope: "AGENT" | "ALL",
  ): Promise<string> {
    const attestation = await this.inner.reconcileCommitGateRuntime({
      agentId: request.agentId,
      runId: request.runId,
      runLeaseId: request.runLeaseId ?? request.runId,
      sessionEpoch: request.sessionEpoch ?? 0,
      scope,
    });
    const projection = await this.authority.recordRuntimeTeardown({
      agentId: request.agentId,
      transitionId: request.runId,
      attestation,
    });
    const transition = projection.transitions[request.runId];
    const recorded = scope === "AGENT"
      ? transition?.runtimeTeardownAgent
      : transition?.runtimeTeardownAll;
    if (!recorded) throw new Error("WORKER_RUNTIME_TEARDOWN_PROJECTION_MISSING");
    return recorded.digest;
  }

  private teardownRequest(
    request: RunnerRequest,
    scope: "AGENT" | "ALL",
  ): BrokerTeardownRequest {
    return {
      runId: request.runId,
      agentId: request.agentId,
      runLeaseId: request.runLeaseId ?? request.runId,
      sessionEpoch: request.sessionEpoch ?? 0,
      scope,
    };
  }

  private throwIfCancelled(active: ActiveWorkerRun): void {
    if (active.cancellationAccepted || active.controller.signal.aborted) {
      throw new RunCancelledError();
    }
  }

  private async recoverAcknowledgedCommit(input: {
    request: RunnerRequest;
    baseView: StateViewRef;
    output: string;
    threadId: string | null;
    usage: RunnerResult["usage"];
    checks: CheckResult[];
  }): Promise<RunnerResult | null> {
    let projection;
    try {
      // recover() is idempotent and completes a durable CONSUMING/APPLIED
      // transition before returning its rebuilt projection.
      projection = await this.authority.recover(input.request.agentId);
    } catch {
      try {
        projection = await this.authority.getProjection(input.request.agentId);
      } catch {
        return null;
      }
    }
    const terminal = projection.terminalReceipts.find(
      (receipt) =>
        receipt.receiptId === input.request.runId &&
        receipt.transitionId === input.request.runId &&
        receipt.decision === "COMMITTED",
    );
    if (!terminal) return null;
    const transition = projection.transitions[input.request.runId];
    const proposal = transition?.proposalId
      ? projection.proposals[transition.proposalId]
      : undefined;
    const evidence = transition?.proposalId
      ? projection.evidence[transition.proposalId]
      : undefined;
    const projectedPermit = transition?.permitId
      ? projection.permits[transition.permitId]
      : undefined;
    if (
      !transition ||
      !proposal ||
      !evidence ||
      !projectedPermit ||
      projectedPermit.state !== "CONSUMED" ||
      terminal.view.generation !== input.baseView.generation + 1 ||
      terminal.workspaceHash !== proposal.artifactHash
    ) {
      throw new Error("WORKER_ACKNOWLEDGED_COMMIT_BINDING_INVALID");
    }
    const timestamp = now();
    const permit: PromotionPermit = {
      schemaVersion: 1,
      permitId: projectedPermit.permitId,
      runId: input.request.runId,
      agentId: input.request.agentId,
      proposalId: projectedPermit.proposalId,
      baseViewId: projectedPermit.baseViewId,
      targetArtifactHash: projectedPermit.targetArtifactHash,
      evaluationContextHash: projectedPermit.evaluationContextHash,
      evidenceDigest: projectedPermit.evidenceDigest,
      // The nonce is intentionally never projected out of the Worker. This
      // local placeholder is not accepted by any authority operation.
      nonce: "authority-projected-redacted",
      expiresAt: projectedPermit.expiresAt,
      state: "CONSUMED",
      issuedAt: timestamp,
      updatedAt: timestamp,
    };
    const summary = this.summary({
      request: input.request,
      baseView: input.baseView,
      finalView: terminal.view,
      decision: "COMMITTED",
      failureClass: null,
      reasonCodes: [],
      checks: input.checks.length > 0
        ? input.checks
        : evidence.checks.map((check) => ({
            id: check.id,
            status: check.status,
            exitCode: check.exitCode,
            durationMs: check.durationMs,
            output: "[redacted authority evidence]",
            timedOut: check.timedOut,
          })),
      proposalId: proposal.proposalId,
      proposalHash: proposal.artifactHash,
      changedPaths: proposal.changedPaths,
      evaluationContextHash: evidence.evaluationContextHash,
      evidenceDigest: evidence.evidenceDigest,
      permit,
      verifierInputHash: evidence.verifierInputHash,
      artifactsDestroyed: transition.artifactsDestroyed,
    });
    const receipt = this.receipt(input.request, summary, input.baseView, terminal.view);
    this.runs.set(input.request.runId, {
      request: input.request,
      baseView: input.baseView,
      proposalId: proposal.proposalId,
      permit,
      promotionInput: null,
      receipt,
      summary,
    });
    return {
      output: input.output,
      threadId: input.threadId,
      usage: input.usage,
      commitGate: summary,
    };
  }

  private nonCommitResult(
    request: RunnerRequest,
    baseView: StateViewRef,
    output: string,
    usage: RunnerResult["usage"],
    decision: "QUARANTINED" | "CONFLICTED" | "ABORTED",
    failureClass: NonNullable<CommitGateSummary["failureClass"]>,
    reasonCodes: string[],
    checks: CheckResult[],
    proposalId: string | null,
    proposalHash: string | null = null,
    changedPaths: string[] = [],
    evaluationContextHash: string | null = null,
    evidenceDigest: string | null = null,
  ): RunnerResult {
    const summary = this.summary({
      request,
      baseView,
      finalView: baseView,
      decision,
      failureClass,
      reasonCodes,
      checks,
      proposalId,
      proposalHash,
      changedPaths,
      evaluationContextHash,
      evidenceDigest,
      permit: null,
    });
    const receipt = this.receipt(request, summary, baseView, null, reasonCodes);
    this.runs.set(request.runId, {
      request,
      baseView,
      proposalId,
      permit: null,
      promotionInput: null,
      receipt,
      summary,
    });
    return { output, threadId: null, usage, commitGate: summary };
  }

  private summary(input: {
    request: RunnerRequest;
    baseView: StateViewRef;
    finalView: StateViewRef;
    decision: CommitGateSummary["decision"];
    failureClass: CommitGateSummary["failureClass"];
    reasonCodes: string[];
    checks: CheckResult[];
    proposalId: string | null;
    proposalHash: string | null;
    changedPaths: string[];
    evaluationContextHash: string | null;
    evidenceDigest: string | null;
    permit: PromotionPermit | null;
    verifierInputHash?: string | null;
    artifactsDestroyed?: boolean;
  }): CommitGateSummary {
    const artifactsDestroyed = input.artifactsDestroyed === true;
    const summary: CommitGateSummary = {
      transactionStatus: input.decision === "COMMITTED" ? "TERMINAL" : "PENDING_DISPOSITION",
      decision: input.decision,
      failureClass: input.failureClass,
      receiptId: input.request.runId,
      baseHash: input.baseView.liveStateHash,
      candidateHash: input.proposalHash,
      finalHash: input.finalView.liveStateHash,
      policyHash: WORKER_GATE_POLICY_HASH,
      checks: input.checks.map((check) => ({
        id: check.id,
        status: check.status,
        reasonCode: check.status === "PASS" ? null : `TRUSTED_CHECK_${check.status}`,
      })),
      changedPaths: input.changedPaths,
      threadDisposition: input.decision === "COMMITTED" ? "resumed" : "reset",
      candidateCleanup: artifactsDestroyed ? "deleted" : "deferred",
      baseViewId: input.baseView.viewId,
      nextViewId: input.finalView.viewId,
      baseGeneration: input.baseView.generation,
      nextGeneration: input.finalView.generation,
      proposalId: input.proposalId,
      proposalHash: input.proposalHash,
      evaluationContextHash: input.evaluationContextHash,
      evidenceDigest: input.evidenceDigest,
      permitId: input.permit?.permitId ?? null,
      permitState: input.permit?.state ?? null,
      artifactRetention: artifactsDestroyed
        ? input.decision === "COMMITTED"
          ? "version_snapshot"
          : "destroyed"
        : "deferred",
      provider: input.request.provider ?? null,
      finalView: input.finalView,
      effectProof: deriveEffectDispositionProof({
        decision: input.decision,
        baseHash: input.baseView.liveStateHash,
        candidateHash: input.proposalHash,
        finalHash: input.finalView.liveStateHash,
        sealedProposalHash: input.proposalHash,
        verifierInputHash: input.verifierInputHash ?? null,
        promotionSourceHash: input.permit?.targetArtifactHash ?? null,
        finalAuthoritativeHash: input.finalView.liveStateHash,
      }),
    };
    summary.lifecycle = summaryLifecycle(summary);
    return summary;
  }

  private receipt(
    request: RunnerRequest,
    summary: CommitGateSummary,
    baseView: StateViewRef,
    finalView: StateViewRef | null,
    reasonCodes: string[] = [],
  ): GateReceipt {
    return {
      schemaVersion: 2,
      runId: request.runId,
      agentId: request.agentId,
      phase: summary.decision === "COMMITTED" ? "TERMINAL" : "PENDING_DISPOSITION",
      decision: summary.decision,
      failureClass: summary.failureClass,
      reasonCodes,
      baseSnapshotHash: summary.baseHash,
      candidateSnapshotHash: summary.candidateHash,
      patchHash: null,
      finalSnapshotHash: summary.finalHash,
      policyHash: summary.policyHash,
      evidence: { static: summary.proposalId ? "complete" : "unavailable" },
      checks: summary.checks.map((check) => ({
        id: check.id,
        status: check.status,
        exitCode: check.status === "PASS" ? 0 : null,
        durationMs: 0,
        output: "",
        timedOut: false,
      })),
      changedPaths: summary.changedPaths,
      threadDisposition: summary.threadDisposition,
      candidateCleanup: summary.candidateCleanup,
      sessionEpoch: baseView.sessionEpoch,
      versionId: finalView?.headVersionId ?? null,
      promotionPendingDatabaseAck: false,
      baseView,
      nextView: finalView,
      baseViewId: baseView.viewId,
      finalViewId: finalView?.viewId ?? null,
      baseGeneration: baseView.generation,
      nextGeneration: finalView?.generation ?? baseView.generation,
      generation: finalView?.generation ?? baseView.generation,
      proposalId: summary.proposalId ?? null,
      evaluationContextHash: summary.evaluationContextHash ?? null,
      evidenceDigest: summary.evidenceDigest ?? null,
      permitId: summary.permitId ?? null,
      permitState: summary.permitState ?? null,
      transactionStatus: summary.transactionStatus === "TERMINAL" ? "TERMINAL" : "PENDING_DISPOSITION",
      artifactRetention: summary.artifactRetention ?? "deferred",
      provider: summary.provider ?? null,
      ...(summary.effectProof ? { effectProof: summary.effectProof } : {}),
      startedAt: now(),
      completedAt: now(),
    };
  }
}
