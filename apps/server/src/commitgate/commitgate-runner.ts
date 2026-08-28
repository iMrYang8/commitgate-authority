import type { AgentRunner, RunnerCancellation, RunnerRequest } from "../types.js";
import {
  CommitGateRecoveryRequiredError,
  RunCancelledError,
} from "../errors.js";
import { CommitGateCoordinator } from "./coordinator.js";
import type {
  CommitGateRunnerResult,
  GateFinalization,
  PreparedCandidate,
  StateViewRef,
} from "./types.js";
import { StateConflictError } from "./workspace-transaction.js";

export interface CommitGateRunnerOptions {
  autoAcknowledge?: boolean;
  sessionEpoch?: (agentId: string) => number | Promise<number>;
  onLifecycleEvent?: (
    event: CommitGateLifecycleEvent,
  ) => void | Promise<void>;
}

export interface CommitGateLifecycleEvent {
  runId: string;
  runLeaseId: string;
  baseViewId: string;
  sessionEpoch: number;
  status: "PROVISIONAL" | "DECIDED";
  proposalId?: string;
  output?: string;
}

export class CommitGateRunner implements AgentRunner {
  private readonly active = new Map<
    string,
    { controller: AbortController; prepared: PreparedCandidate | null }
  >();
  private readonly autoAcknowledge: boolean;
  private lifecycleHandler: CommitGateRunnerOptions["onLifecycleEvent"];

  constructor(
    private readonly inner: AgentRunner,
    readonly coordinator: CommitGateCoordinator,
    private readonly options: CommitGateRunnerOptions = {},
  ) {
    this.autoAcknowledge = options.autoAcknowledge ?? false;
    this.lifecycleHandler = options.onLifecycleEvent;
  }

  setLifecycleEventHandler(
    handler: CommitGateRunnerOptions["onLifecycleEvent"],
  ): void {
    this.lifecycleHandler = handler;
  }

  async isAvailable(): Promise<boolean> {
    await this.coordinator.initialize();
    return this.inner.isAvailable();
  }

  async run(request: RunnerRequest): Promise<CommitGateRunnerResult> {
    if (!request.runId) throw new Error("CommitGate requires RunnerRequest.runId");
    if (this.active.has(request.agentId)) throw new Error("Agent already has an active CommitGate run");
    const controller = new AbortController();
    const active = { controller, prepared: null as PreparedCandidate | null };
    this.active.set(request.agentId, active);
    try {
      const sessionEpoch =
        request.sessionEpoch ??
        (await this.options.sessionEpoch?.(request.agentId)) ??
        0;
      const prepared = await this.coordinator.prepare({
        runId: request.runId,
        agentId: request.agentId,
        persistentPath: request.workspacePath,
        sessionEpoch,
        ...(request.runLeaseId ? { runLeaseId: request.runLeaseId } : {}),
        ...(request.baseViewId ? { expectedBaseViewId: request.baseViewId } : {}),
        ...(request.stateGeneration === undefined
          ? {}
          : { stateGeneration: request.stateGeneration }),
        ...(request.expectedHeadVersionId === undefined
          ? {}
          : { expectedHeadVersionId: request.expectedHeadVersionId }),
        ...(request.agentConfigVersion === undefined
          ? {}
          : { agentConfigVersion: request.agentConfigVersion }),
        ...(request.policyVersion === undefined
          ? {}
          : { policyVersion: request.policyVersion }),
        provider: request.provider ?? null,
      });
      active.prepared = prepared;
      if (controller.signal.aborted) throw new RunCancelledError();
      const result = await this.inner.run({ ...request, workspacePath: prepared.candidatePath });
      const attestor = this.inner as AgentRunner & {
        attestCommitGateTeardown?: (runId: string) => Promise<{
          containerExited: boolean;
          containerRemoved: boolean;
          mountsReleased: boolean;
          [key: string]: unknown;
        }>;
      };
      if (attestor.attestCommitGateTeardown) {
        this.coordinator.recordRuntimeTeardown(
          prepared,
          await attestor.attestCommitGateTeardown(request.runId),
        );
      }
      await this.lifecycleHandler?.({
        runId: request.runId,
        runLeaseId: prepared.runLeaseId,
        baseViewId: prepared.baseView.viewId,
        sessionEpoch: prepared.baseView.sessionEpoch,
        status: "PROVISIONAL",
        output: result.output,
      });
      let finalization = await this.coordinator.verifyAndFinalize(prepared, controller.signal);
      if (controller.signal.aborted) {
        if (
          finalization.receipt.decision === "COMMITTED" &&
          finalization.receipt.promotionPendingDatabaseAck
        ) {
          try {
            await this.coordinator.rollbackPending(request.runId);
          } catch (error) {
            // Preserve the COMMITTED+pending receipt. Overwriting it with a
            // normal ABORTED receipt would hide the unresolved journal and let
            // the product admit a new run before startup recovery.
            throw new CommitGateRecoveryRequiredError(
              "CommitGate cancellation could not roll back the pending promotion",
              error,
            );
          }
        }
        throw new RunCancelledError();
      }
      if (finalization.receipt.decision === "COMMITTED" && this.autoAcknowledge) {
        finalization = await this.coordinator.acknowledge(request.runId);
      }
      await this.lifecycleHandler?.({
        runId: request.runId,
        runLeaseId: prepared.runLeaseId,
        baseViewId: prepared.baseView.viewId,
        sessionEpoch: prepared.baseView.sessionEpoch,
        status: "DECIDED",
        ...(finalization.receipt.proposalId
          ? { proposalId: finalization.receipt.proposalId }
          : {}),
      });
      return {
        ...result,
        threadId: finalization.receipt.decision === "COMMITTED" ? result.threadId : null,
        commitGate: finalization.summary,
      };
    } catch (error) {
      if (error instanceof CommitGateRecoveryRequiredError) throw error;
      if (!active.prepared) {
        let admission: GateFinalization;
        try {
          admission = await this.coordinator.recordAdmissionFailure(
            {
              runId: request.runId,
              agentId: request.agentId,
              sessionEpoch: request.sessionEpoch ?? 0,
              ...(request.baseViewId ? { baseViewId: request.baseViewId } : {}),
              ...(request.stateGeneration === undefined
                ? {}
                : { stateGeneration: request.stateGeneration }),
              ...(request.baseLiveStateHash
                ? { baseLiveStateHash: request.baseLiveStateHash }
                : {}),
              provider: request.provider ?? null,
            },
            error,
            error instanceof StateConflictError ? "CONFLICTED" : "ABORTED",
          );
        } catch (receiptError) {
          throw new AggregateError(
            [error, receiptError],
            "CommitGate admission and minimum receipt persistence both failed",
          );
        }
        await this.lifecycleHandler?.({
          runId: request.runId,
          runLeaseId: request.runLeaseId ?? request.runId,
          baseViewId: request.baseViewId ?? "unavailable",
          sessionEpoch: request.sessionEpoch ?? 0,
          status: "DECIDED",
        });
        if (admission.receipt.decision === "CONFLICTED") {
          return {
            output: "CommitGate admission conflicted; the Agent runtime was not executed.",
            threadId: null,
            usage: null,
            commitGate: admission.summary,
          };
        }
      }
      if (
        active.prepared &&
        this.coordinator.hasPendingPromotion(request.runId)
      ) {
        throw new CommitGateRecoveryRequiredError(
          "CommitGate failed while a promotion journal was pending",
          error,
        );
      }
      let abortError: unknown = null;
      if (active.prepared) {
        try {
          await this.coordinator.abort(active.prepared, error);
        } catch (candidateAbortError) {
          abortError = candidateAbortError;
        }
      }
      if (controller.signal.aborted) throw new RunCancelledError();
      if (abortError) {
        throw new AggregateError(
          [error, abortError],
          "CommitGate execution and abort receipt persistence both failed",
        );
      }
      throw error;
    } finally {
      this.active.delete(request.agentId);
    }
  }

  async cancel(agentId: string, cancellation?: RunnerCancellation): Promise<boolean> {
    const active = this.active.get(agentId);
    if (active) active.controller.abort(new RunCancelledError());
    const innerCancelled = await this.inner.cancel(agentId, cancellation);
    if (!active) return innerCancelled;
    return true;
  }

  async stageAcknowledge(runId: string): Promise<GateFinalization> {
    return this.coordinator.stageAcknowledge(runId);
  }

  async acknowledge(runId: string): Promise<GateFinalization> {
    return this.coordinator.acknowledge(runId);
  }

  async rollbackPending(runId: string): Promise<void> {
    await this.coordinator.rollbackPending(runId);
  }

  async finalizeDisposition(
    agentId: string,
    runId: string,
    finalView: StateViewRef,
  ): Promise<GateFinalization> {
    return this.coordinator.finalizeDisposition(agentId, runId, finalView);
  }
}
