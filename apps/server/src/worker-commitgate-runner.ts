import { randomUUID } from "node:crypto";
import type { RuntimeTeardownAttestation } from "./container-codex-runner.js";
import {
  computeCheckResultsHash,
  computeEvaluationContextHash,
  sha256Canonical,
} from "./commitgate/protocol.js";
import { defaultCommitGatePolicy, policyHash } from "./commitgate/policy.js";
import { computeCheckSpecHash } from "./commitgate/trusted-check-bundle.js";
import type {
  CheckResult,
  EvaluationContext,
  GateFinalization,
  GateReceipt,
  PromotionPermit,
  StateViewRef,
} from "./commitgate/types.js";
import { makeStateView } from "./state-view.js";
import type { TransitionAuthorityClient } from "./transition-authority-client.js";
import type {
  AgentRunner,
  CommitGateSummary,
  RunnerCancellation,
  RunnerRequest,
  RunnerResult,
} from "./types.js";
import type {
  BrokerVerifierRequest,
  BrokerVerifierResult,
} from "./runtime-broker/contracts.js";
import type { PreparedRunRef } from "./transition-worker/worker.js";

interface BrokerBackedRunner extends AgentRunner {
  attestCommitGateTeardown(runId: string): Promise<RuntimeTeardownAttestation>;
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

const now = (): string => new Date().toISOString();
const WORKER_POLICY = {
  ...defaultCommitGatePolicy,
  requiredChecks: [
    {
      id: "workspace-sanity",
      runner: "node" as const,
      entrypoint: "workspace-sanity.mjs",
      args: [],
      timeoutMs: 15_000,
      scratchBytes: 64 * 1024 * 1024,
    },
  ],
};

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
  private readonly active = new Map<string, AbortController>();

  constructor(
    private readonly inner: BrokerBackedRunner,
    readonly authority: TransitionAuthorityClient,
    private readonly exchangeRoot: string,
    private readonly sourceRevision: string,
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
    const controller = new AbortController();
    this.active.set(request.agentId, controller);
    const candidateVolumeId = `candidate-${request.runId}`;
    let output = "";
    let threadId: string | null = null;
    let usage: RunnerResult["usage"] = null;
    let prepared: PreparedRunRef | null = null;
    let evidenceRequest = request;
    try {
      prepared = await this.authority.prepareRun({
        agentId: request.agentId,
        transitionId: request.runId,
        candidateVolumeId,
        expectedViewId: request.baseViewId,
        expectedWorkspaceHash: request.baseLiveStateHash,
        baseGeneration: request.stateGeneration,
      });
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
      const teardown = await this.inner.attestCommitGateTeardown(request.runId);
      if (teardown.resolvedModel && request.provider) {
        evidenceRequest = {
          ...request,
          provider: { ...request.provider, resolvedModel: teardown.resolvedModel },
        };
      }
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

      const proposalId = `proposal-${request.runId}`;
      const sealedProjection = await this.authority.sealProposal({
        agentId: request.agentId,
        transitionId: request.runId,
        proposalId,
        sourceVolumeId: candidateVolumeId,
        baseViewId: prepared.baseView.viewId,
      });
      const proposal = sealedProjection.proposals[proposalId];
      if (!proposal) throw new Error("WORKER_PROPOSAL_PROJECTION_MISSING");
      if (proposal.staticFailures.length > 0) {
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
      const checks = WORKER_POLICY.requiredChecks;
      const verification = await this.inner.runVerifier({
        runId: request.runId,
        agentId: request.agentId,
        proposalId,
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
      const context: EvaluationContext = {
        schemaVersion: 1,
        runId: request.runId,
        agentId: request.agentId,
        proposalId,
        baseView: prepared.baseView,
        manifestSchemaVersion: 1,
        policyHash: policyHash(WORKER_POLICY),
        checkBundleHash: verification.environment.checkBundleHash,
        checkSpecHash: computeCheckSpecHash(checks),
        verifierImageDigest: verification.environment.imageDigest,
        verifierConfigHash: verification.environment.configHash,
        resourcePolicyHash: verification.environment.resourcePolicyHash ?? "unverified",
        sourceRevision: verification.environment.sourceRevision ?? this.sourceRevision,
      };
      const evaluationContextHash = computeEvaluationContextHash(context);
      const evidenceDigest = sha256Canonical({
        schemaVersion: 1,
        proposalId,
        artifactHash: proposal.artifactHash,
        evaluationContextHash,
        checkResultsHash: computeCheckResultsHash(verification.checks),
      });
      await this.authority.recordEvidence({
        agentId: request.agentId,
        transitionId: request.runId,
        proposalId,
        evaluationContextHash,
        evidenceDigest,
      });
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
      const versionId = randomUUID();
      const finalView = makeStateView({
        agentId: request.agentId,
        headVersionId: versionId,
        generation: prepared.baseView.generation + 1,
        versionedHash: proposal.artifactHash,
        platformManagedHash: proposal.artifactHash,
        liveStateHash: proposal.artifactHash,
        sessionEpoch: prepared.baseView.sessionEpoch,
        agentConfigVersion: prepared.baseView.agentConfigVersion,
        policyVersion: prepared.baseView.policyVersion,
      });
      const promotionInput = {
        agentId: request.agentId,
        transitionId: request.runId,
        permitId,
        proposalId,
        expectedViewId: prepared.baseView.viewId,
        expectedWorkspaceHash: prepared.baseWorkspaceHash,
        nextView: finalView,
        versionId,
        receiptId: request.runId,
      };
      await this.authority.applyPromotion(promotionInput);
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
      if (prepared) {
        const code =
          error && typeof error === "object" && "code" in error && typeof error.code === "string"
            ? error.code
            : "WORKER_RUNTIME_ERROR";
        const aborted = this.nonCommitResult(
          evidenceRequest,
          prepared.baseView,
          output,
          usage,
          "ABORTED",
          "infra_errored",
          [code],
          [],
          null,
        );
        if (controller.signal.aborted) throw controller.signal.reason ?? error;
        return aborted;
      }
      if (controller.signal.aborted) throw controller.signal.reason ?? error;
      throw error;
    } finally {
      this.active.delete(request.agentId);
    }
  }

  async cancel(agentId: string, cancellation?: RunnerCancellation): Promise<boolean> {
    this.active.get(agentId)?.abort(new Error("RUN_CANCELLED"));
    return this.inner.cancel(agentId, cancellation);
  }

  async finalizeDisposition(
    agentId: string,
    runId: string,
    finalView: StateViewRef,
  ): Promise<GateFinalization> {
    const stored = this.runs.get(runId);
    if (!stored || stored.request.agentId !== agentId) throw new Error("WORKER_RUN_NOT_FOUND");
    if (stored.summary.decision === "COMMITTED") return { receipt: stored.receipt, summary: stored.summary };
    const projection = await this.authority.disposeRun({
      agentId,
      transitionId: runId,
      receiptId: runId,
      decision: stored.summary.decision,
      finalView,
      reasonCodes: stored.receipt.reasonCodes,
    });
    const projected = projection.terminalReceipts.find((receipt) => receipt.receiptId === runId);
    if (!projected) throw new Error("WORKER_TERMINAL_RECEIPT_MISSING");
    stored.summary = { ...stored.summary, nextViewId: finalView.viewId, finalView };
    stored.receipt = {
      ...stored.receipt,
      phase: "TERMINAL",
      transactionStatus: "TERMINAL",
      nextView: finalView,
      finalViewId: finalView.viewId,
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
  }): CommitGateSummary {
    const summary: CommitGateSummary = {
      transactionStatus: input.decision === "COMMITTED" ? "TERMINAL" : "PENDING_DISPOSITION",
      decision: input.decision,
      failureClass: input.failureClass,
      receiptId: input.request.runId,
      baseHash: input.baseView.liveStateHash,
      candidateHash: input.proposalHash,
      finalHash: input.finalView.liveStateHash,
      policyHash: policyHash(WORKER_POLICY),
      checks: input.checks.map((check) => ({
        id: check.id,
        status: check.status,
        reasonCode: check.status === "PASS" ? null : `TRUSTED_CHECK_${check.status}`,
      })),
      changedPaths: input.changedPaths,
      threadDisposition: input.decision === "COMMITTED" ? "resumed" : "reset",
      candidateCleanup: "deleted",
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
      artifactRetention: input.decision === "COMMITTED" ? "version_snapshot" : "destroyed",
      provider: input.request.provider ?? null,
      finalView: input.finalView,
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
      startedAt: now(),
      completedAt: now(),
    };
  }
}
