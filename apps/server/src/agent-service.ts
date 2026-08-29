import { randomUUID } from "node:crypto";
import { access } from "node:fs/promises";
import path from "node:path";
import type { AppConfig } from "./config.js";
import { isModelConfigured, modelProviderIdentity } from "./config.js";
import {
  buildManifest,
  redactReceiptText,
  type CommitGateComponents,
  type GateReceipt,
  type CommitGateLifecycleEvent,
  deriveEffectDispositionProof,
  policyHash,
  VersionStoreError,
} from "./commitgate/index.js";
import type { CommitGateRuntimeComponents } from "./commitgate-runtime.js";
import {
  CommitGateRecoveryRequiredError,
  HttpError,
  RunCancelledError,
} from "./errors.js";
import { JsonStore } from "./store.js";
import type {
  Agent,
  AgentRun,
  AgentRunner,
  CommitGateSummary,
  CreateAgentInput,
  Database,
  Message,
  SnapshotMetadata,
  StateViewRef,
  UpdateAgentInput,
  WorkspaceVersion,
} from "./types.js";
import { EMPTY_STATE_HASH, refreshAgentViewId, stateViewForAgent } from "./state-view.js";
import { retireCodexSessionHome } from "./model-provider.js";
import { WorkspaceManager } from "./workspace.js";
import type { TransitionAuthority } from "./transition-authority.js";
import type { AuthorityHealth } from "./transition-authority-client.js";
import { createInProcessTransitionAuthority } from "./transition-authority-factory.js";
import { TransitionEventLog } from "./transition-log.js";
import type {
  ProjectedTerminalReceipt,
  WorkerProjection,
} from "./transition-worker/projection.js";
import {
  verifyAuthorityReceiptProof,
  type AuthorityReceiptProofBundle,
} from "./research/receipt-proof.js";
import {
  API_PROJECTION_FAULT_POINT,
  maybeInjectApiProjectionFault,
} from "./api-projection-fault-injection.js";

const now = () => new Date().toISOString();
const RECOVERY_REQUIRED_MESSAGE =
  "CommitGate recovery required: restart the server after repairing the journal or policy";

function reconciliationPrefix(agent: Agent): string {
  return `<commitgate_context>
The prior continuation was fenced after a CommitGate decision, rollback,
recovery, or Agent configuration change. Only the current workspace view is
authoritative. Inspect it before acting and do not assume rejected files exist.
view_id=${agent.currentViewId}
generation=${agent.stateGeneration}
live_state_hash=${agent.currentLiveStateHash}
session_epoch=${agent.sessionEpoch}
</commitgate_context>`;
}

interface VersionProjection {
  versions: WorkspaceVersion[];
  snapshots: SnapshotMetadata[];
  headVersionId: string | null;
}

export class AgentService {
  private readonly activeExecutions = new Map<string, Promise<void>>();
  private readonly activeRollbacks = new Map<string, Promise<unknown>>();
  private readonly activeLifecycleMutations = new Set<string>();
  private readonly activeConfigurationMutations = new Set<string>();
  private readonly recoveryReservations = new Set<string>();
  private readonly cancellationRequests = new Set<string>();
  private readonly transitionWriter: TransitionAuthority | null;
  private readonly transitionEvents: TransitionEventLog;
  private workerAuthorityHealth: AuthorityHealth | null = null;

  constructor(
    private readonly config: AppConfig,
    private readonly store: JsonStore,
    private readonly workspaces: WorkspaceManager,
    private readonly runner: AgentRunner,
    private readonly commitGate: CommitGateRuntimeComponents | null = null,
  ) {
    this.transitionWriter = commitGate?.mode === "worker"
      ? null
      : commitGate?.transitionWriter ??
        createInProcessTransitionAuthority(
          workspaces,
          commitGate?.coordinator.controlRoot,
        );
    this.transitionEvents = new TransitionEventLog(
      path.join(
        commitGate?.mode === "worker" ? config.dataDirectory : config.commitGateControlRoot,
        "transition-events",
      ),
    );
    if (commitGate && commitGate.mode !== "worker") {
      commitGate.coordinator.setStateViewProvider({
        capture: (input) => {
          const agent = this.store.snapshot().agents.find((item) => item.id === input.agentId);
          if (!agent || path.resolve(agent.workspacePath) !== path.resolve(input.persistentPath)) {
            throw new Error("STATE_VIEW_AGENT_BINDING_MISMATCH");
          }
          return stateViewForAgent(agent);
        },
      });
      commitGate.runner.setLifecycleEventHandler((event) =>
        this.handleCommitGateLifecycleEvent(event),
      );
    }
  }

  async initialize(): Promise<void> {
    await this.store.initialize();
    if (this.commitGate?.mode === "worker") {
      this.workerAuthorityHealth = await this.commitGate.authority.initialize();
      if (
        this.config.nodeEnv === "production" &&
        this.workerAuthorityHealth.filesystemProfile !== "linux-strong"
      ) {
        throw new Error("AUTHORITY_FILESYSTEM_PROFILE_INVALID");
      }
      await this.initializeWorkerAuthorityProjection();
      return;
    }
    await this.transitionWriter!.initialize();

    let recoveryManualAgents = new Set<string>();
    let recoveryResolvedAgents = new Set<string>();
    const recoveryRolledBackRuns = new Set<string>();
    const recoveryAcknowledgedRuns = new Set<string>();
    const recoveryHealthyAgents = new Set<string>();
    if (this.commitGate) {
      await this.commitGate.coordinator.initialize();
      const recovery = await this.transitionWriter!.recoverTransition({
        workspaceRoot: this.config.workspaceRoot,
        controlRoot: this.config.commitGateControlRoot,
        getDatabaseHead: (agentId) => {
          const database = this.store.snapshot();
          const headId = database.agents.find((agent) => agent.id === agentId)?.headVersionId;
          const version = database.versions.find(
            (item) => item.agentId === agentId && item.id === headId,
          );
          return version
            ? {
                versionId: version.id,
                liveStateHash: version.liveStateHash,
                runId: version.sourceRunId,
                kind: version.kind,
              }
            : null;
        },
      });
      recoveryManualAgents = new Set(
        recovery.actions
          .filter((action) => action.action === "manual_intervention")
          .map((action) => action.agentId),
      );
      recoveryResolvedAgents = new Set(
        recovery.actions
          .filter(
            (action) =>
              action.action === "acknowledged" || action.action === "rolled_back",
          )
          .map((action) => action.agentId),
      );
      for (const action of recovery.actions) {
        if (action.action === "rolled_back") {
          recoveryRolledBackRuns.add(action.runId);
        } else if (action.action === "acknowledged") {
          recoveryAcknowledgedRuns.add(action.runId);
        }
      }

      for (const agent of this.store.snapshot().agents) {
        if (recoveryManualAgents.has(agent.id)) continue;
        try {
          await this.commitGate.coordinator.initializeAgent(agent.id, agent.workspacePath);
          const policy = await this.commitGate.coordinator.policyForAgent(agent.id);
          const hashes = await this.captureWorkspaceHashes(agent.workspacePath, policy);
          const projection = await this.projectVersions(agent.id, hashes.liveStateHash);
          await this.store.mutate((database) => {
            this.applyVersionProjection(database, agent.id, projection);
            const stored = database.agents.find((item) => item.id === agent.id);
            if (!stored) return;
            const head = projection.versions.find(
              (version) => version.id === projection.headVersionId,
            );
            stored.currentVersionedHash = hashes.versionedHash;
            stored.currentPlatformManagedHash = hashes.platformManagedHash;
            stored.currentLiveStateHash = hashes.liveStateHash;
            stored.stateGeneration = Math.max(stored.stateGeneration, head?.generation ?? 1);
            refreshAgentViewId(stored);
          });
          recoveryHealthyAgents.add(agent.id);
        } catch {
          recoveryManualAgents.add(agent.id);
        }
      }
      // The recovery decision is known before the final DB mutation. Reserve
      // affected Agents in memory as well, so a transient DB failure cannot
      // leave an unresolved journal writable in this still-running process.
      for (const agentId of recoveryManualAgents) {
        this.recoveryReservations.add(agentId);
      }
    }

    const persistedReceipts = new Map<string, GateReceipt>();
    if (this.commitGate) {
      for (const run of this.store.snapshot().runs) {
        const receipt = await this.commitGate.receiptStore.get(run.agentId, run.id);
        if (receipt) persistedReceipts.set(run.id, receipt);
      }
    }

    const recoveredAbortAgents = new Set<string>();
    const resetSessionAgents = new Set<string>();
    await this.store.mutate((database) => {
      const authoritativeRolledBackRuns = new Set(
        database.messages
          .filter(
            (message) =>
              message.role === "assistant" &&
              message.authority === "AUTHORITATIVE" &&
              recoveryRolledBackRuns.has(message.runId ?? ""),
          )
          .map((message) => message.runId!),
      );
      for (const run of database.runs) {
        const receipt = persistedReceipts.get(run.id);
        if (receipt) run.commitGate = this.summaryFromReceipt(receipt);
        const wasCompleted = run.status === "completed";
        if (recoveryRolledBackRuns.has(run.id)) {
          run.status = "failed";
          run.error = "CommitGate startup recovery rolled back this run";
          run.completedAt = run.completedAt ?? now();
          if (run.commitGate) {
            run.commitGate = {
              ...run.commitGate,
              decision: "ABORTED",
              failureClass: "infra_errored",
              finalHash: run.commitGate.baseHash,
              threadDisposition: "reset",
              transactionStatus: "TERMINAL",
              nextViewId: null,
              artifactRetention: "destroyed",
            };
          }
          if (wasCompleted || authoritativeRolledBackRuns.has(run.id)) {
            recoveredAbortAgents.add(run.agentId);
          }
        } else if (recoveryAcknowledgedRuns.has(run.id)) {
          if (run.commitGate) {
            run.commitGate = {
              ...run.commitGate,
              transactionStatus: "TERMINAL",
              artifactRetention: "version_snapshot",
            };
          }
          run.transactionStatus = "TERMINAL";
        } else if (run.status === "queued" || run.status === "running") {
          run.status = "cancelled";
          run.error = "Server restarted while this run was active";
          run.completedAt = now();
        } else if (receipt?.decision === "ABORTED" && run.status === "completed") {
          run.status = "failed";
          run.error = "CommitGate startup recovery rolled back this run";
          recoveredAbortAgents.add(run.agentId);
        }
      }
      for (const agent of database.agents) {
        if (recoveryManualAgents.has(agent.id)) {
          agent.status = "error";
          agent.lastError = RECOVERY_REQUIRED_MESSAGE;
          agent.recoveryRequired = true;
          agent.codexThreadId = null;
          agent.sessionEpoch += 1;
          agent.needsReconciliation = true;
          resetSessionAgents.add(agent.id);
        } else if (recoveredAbortAgents.has(agent.id)) {
          const sessionAlreadyReset =
            agent.needsReconciliation && agent.codexThreadId === null;
          agent.status = agent.recoveryRequired ? "ready" : "error";
          agent.recoveryRequired = false;
          agent.lastError = agent.status === "error"
            ? "CommitGate startup recovery rolled back a completed run"
            : null;
          agent.codexThreadId = null;
          if (!sessionAlreadyReset) agent.sessionEpoch += 1;
          agent.needsReconciliation = true;
          resetSessionAgents.add(agent.id);
          agent.updatedAt = now();
        } else if (
          agent.recoveryRequired &&
          (recoveryResolvedAgents.has(agent.id) || recoveryHealthyAgents.has(agent.id))
        ) {
          agent.status = "ready";
          agent.lastError = null;
          agent.recoveryRequired = false;
          agent.updatedAt = now();
        } else if (agent.status === "busy") {
          agent.status = "ready";
          agent.codexThreadId = null;
          agent.sessionEpoch += 1;
          agent.needsReconciliation = true;
          resetSessionAgents.add(agent.id);
          agent.updatedAt = now();
        }
        agent.activeRunLeaseId = null;
        refreshAgentViewId(agent);
      }
      for (const message of database.messages) {
        if (
          message.role !== "assistant" ||
          !message.runId ||
          !recoveryRolledBackRuns.has(message.runId)
        ) {
          continue;
        }
        const agent = database.agents.find((item) => item.id === message.agentId);
        message.authority = "REJECTED";
        message.viewId = agent?.currentViewId ?? null;
      }
      for (const run of database.runs) {
        if (!recoveryRolledBackRuns.has(run.id) || !run.commitGate) continue;
        const agent = database.agents.find((item) => item.id === run.agentId);
        if (!agent) continue;
        run.commitGate.nextViewId = agent.currentViewId;
        run.commitGate.nextGeneration = agent.stateGeneration;
        run.transactionStatus = "TERMINAL";
      }
    });
    for (const agentId of resetSessionAgents) await this.retireSessionFence(agentId);
    if (this.commitGate) {
      for (const [runId, receipt] of persistedReceipts) {
        if (receipt.phase !== "PENDING_DISPOSITION") continue;
        const agent = this.store.snapshot().agents.find((item) => item.id === receipt.agentId);
        if (!agent) continue;
        try {
          const finalization = await this.commitGate.runner.finalizeDisposition(
            agent.id,
            runId,
            stateViewForAgent(agent),
          );
          await this.store.mutate((database) => {
            const storedRun = database.runs.find((item) => item.id === runId);
            if (!storedRun) return;
            storedRun.transactionStatus = "TERMINAL";
            storedRun.commitGate = {
              ...finalization.summary,
              provider: storedRun.provider,
            };
          });
        } catch (error) {
          this.recoveryReservations.add(agent.id);
          await this.markRecoveryRequired(agent.id, error);
        }
      }
    }
    for (const agentId of new Set([
      ...recoveryResolvedAgents,
      ...recoveryHealthyAgents,
    ])) {
      if (!recoveryManualAgents.has(agentId)) {
        this.recoveryReservations.delete(agentId);
      }
    }
  }

  private async initializeWorkerAuthorityProjection(): Promise<void> {
    if (this.commitGate?.mode !== "worker") return;
    const agents = this.store.snapshot().agents;
    for (const current of agents) {
      let projection = await this.commitGate.runner.recoverAuthority(
        current.id,
        await this.commitGate.authority.getProjection(current.id),
      );
      if (!projection.head) {
        if (!current.headVersionId) {
          throw new Error(`LEGACY_STATE_CONFLICT:${current.id}:missing head version`);
        }
        projection = await this.commitGate.authority.adoptLegacyState({
          agentId: current.id,
          operationId: `legacy-adopt-${current.id}`,
          legacyAgentId: current.id,
          expectedWorkspaceHash: current.currentLiveStateHash,
          adoptedView: stateViewForAgent(current),
          versionId: current.headVersionId,
        });
      }
      projection = await this.recoverWorkerAdmissionGap(current, projection);
      const pendingProjection = this.latestWorkerTerminalProjectionGap(
        this.store.snapshot(),
        current.id,
        projection,
      );
      if (pendingProjection) {
        maybeInjectApiProjectionFault({
          point: API_PROJECTION_FAULT_POINT,
          source: "startup-recovery",
          agentId: current.id,
          runId: pendingProjection.runId,
          decision: pendingProjection.receipt.decision,
          viewId: pendingProjection.receipt.view.viewId,
          generation: pendingProjection.receipt.view.generation,
          projectionDigest: projection.digest,
        });
      }
      const retireRecoveredSession = await this.store.mutate((database) => {
        const agent = database.agents.find((item) => item.id === current.id);
        if (!agent) return false;
        return this.applyWorkerAuthorityProjection(database, agent, projection);
      });
      if (retireRecoveredSession) await this.retireSessionFence(current.id);
    }
  }

  /**
   * Closes the product/authority run-admission gap: the product DB can
   * durably record a queued Run and its lease immediately before the API is
   * killed, while the Worker has not yet appended TRANSITION_PREPARED.  On
   * restart we replay that exact, CAS-bound admission into the Worker, accept
   * cancellation there, and let ordinary Worker recovery create the terminal
   * ABORTED receipt.  This keeps the Worker as the fact source instead of
   * locally inventing a terminal Run or silently clearing its lease.
   */
  private async recoverWorkerAdmissionGap(
    agent: Agent,
    projection: WorkerProjection,
  ): Promise<WorkerProjection> {
    if (this.commitGate?.mode !== "worker") return projection;
    const activeRuns = this.store.snapshot().runs.filter(
      (run) =>
        run.agentId === agent.id &&
        (run.status === "queued" || run.status === "running"),
    );
    if (activeRuns.length === 0) return projection;
    if (activeRuns.length !== 1) {
      throw new Error(`WORKER_ADMISSION_DB_INVARIANT_VIOLATION:${agent.id}`);
    }
    const run = activeRuns[0]!;
    const transition = projection.transitions[run.id];
    if (transition) {
      if (
        transition.runId !== run.id ||
        transition.runLeaseId !== run.runLeaseId
      ) {
        throw new Error(`WORKER_ADMISSION_TRANSITION_BINDING_MISMATCH:${run.id}`);
      }
      const terminal = projection.terminalReceipts.some(
        (receipt) => receipt.transitionId === run.id,
      );
      if (!terminal) {
        throw new Error(`WORKER_ACTIVE_TRANSITION_NOT_TERMINAL:${run.id}`);
      }
      return projection;
    }
    const head = projection.head;
    if (!head) throw new Error(`WORKER_HEAD_MISSING:${agent.id}`);
    // JsonStore intentionally clears an active lease while loading a v3 file
    // after process restart. The immutable Run row still carries the exact
    // admission lease; accept the cleared marker, but never a competing one.
    if (
      agent.activeRunLeaseId !== null &&
      agent.activeRunLeaseId !== run.runLeaseId
    ) {
      throw new Error(`WORKER_ADMISSION_LEASE_MISMATCH:${run.id}`);
    }
    if (run.baseViewId !== head.view.viewId) {
      throw new Error(`WORKER_ADMISSION_RUN_VIEW_MISMATCH:${run.id}`);
    }
    if (agent.currentViewId !== head.view.viewId) {
      throw new Error(`WORKER_ADMISSION_AGENT_VIEW_MISMATCH:${run.id}`);
    }
    if (agent.currentLiveStateHash !== head.workspaceHash) {
      throw new Error(`WORKER_ADMISSION_WORKSPACE_HASH_MISMATCH:${run.id}`);
    }

    await this.commitGate.authority.prepareRun({
      agentId: agent.id,
      transitionId: run.id,
      runId: run.id,
      runLeaseId: run.runLeaseId,
      candidateVolumeId: `candidate-${run.id}`,
      expectedViewId: head.view.viewId,
      expectedWorkspaceHash: head.workspaceHash,
      baseGeneration: head.view.generation,
      sessionEpoch: head.view.sessionEpoch,
    });
    const cancellation = await this.commitGate.authority.cancelRun({
      agentId: agent.id,
      transitionId: run.id,
      runId: run.id,
      runLeaseId: run.runLeaseId,
      expectedViewId: head.view.viewId,
    });
    if (cancellation.state !== "CANCELLED") {
      throw new Error(`WORKER_ADMISSION_RECOVERY_CANCEL_FAILED:${run.id}:${cancellation.state}`);
    }
    return this.commitGate.runner.recoverAuthority(
      agent.id,
      await this.commitGate.authority.getProjection(agent.id),
    );
  }

  /**
   * Reconciles the product database from the append-only Worker facts. This is
   * deliberately a projection, not a second transition: it never asks the
   * Worker to change HEAD and is safe to repeat after any API process crash.
   */
  private applyWorkerAuthorityProjection(
    database: Database,
    agent: Agent,
    projection: WorkerProjection,
  ): boolean {
    const head = projection.head;
    if (!head) throw new Error(`WORKER_HEAD_MISSING:${agent.id}`);
    const previousViewId = agent.currentViewId;
    agent.workspaceRef = { authority: "transition-worker", agentId: agent.id };
    this.applyWorkerHead(agent, projection);
    this.applyWorkerVersions(database, agent.id, projection);

    const latestReceiptByRun = new Map<string, ProjectedTerminalReceipt>();
    for (const receipt of projection.terminalReceipts) {
      const transition = projection.transitions[receipt.transitionId];
      if (!transition?.runId) continue;
      const existing = latestReceiptByRun.get(transition.runId);
      if (!existing || existing.sequence < receipt.sequence) {
        latestReceiptByRun.set(transition.runId, receipt);
      }
    }

    let latestRecovered:
      | {
          receipt: ProjectedTerminalReceipt;
          runLeaseId: string | null;
          cancelled: boolean;
        }
      | null = null;
    for (const [runId, receipt] of latestReceiptByRun) {
      const run = database.runs.find(
        (candidate) => candidate.id === runId && candidate.agentId === agent.id,
      );
      if (!run) continue;
      const transition = projection.transitions[receipt.transitionId];
      if (!transition) throw new Error(`WORKER_TERMINAL_TRANSITION_MISSING:${runId}`);
      if (transition.runLeaseId && transition.runLeaseId !== run.runLeaseId) {
        // A terminal fact for another admission attempt must never overwrite
        // the current Run row. Leave it visible only in the Worker audit log.
        continue;
      }
      const cancelled = receipt.reasonCodes.some((code) => code.startsWith("RUN_CANCELLED"));
      const expectedStatus = this.workerRunStatus(receipt.decision, cancelled);
      const expectedAuthority: Message["authority"] =
        receipt.decision === "COMMITTED" ? "AUTHORITATIVE" : "REJECTED";
      const assistant = database.messages.find(
        (message) => message.runId === run.id && message.role === "assistant",
      );
      const hadProjectionGap =
        run.transactionStatus !== "TERMINAL" ||
        run.status !== expectedStatus ||
        run.commitGate?.decision !== receipt.decision ||
        run.commitGate?.nextViewId !== receipt.view.viewId ||
        run.commitGate?.nextGeneration !== receipt.view.generation;
      const summary = this.summaryFromWorkerProjection(
        run,
        projection,
        receipt,
        hadProjectionGap,
      );

      run.status = expectedStatus;
      run.error = receipt.decision === "ABORTED" && !cancelled
        ? summary.failureClass ?? "infra_errored"
        : null;
      run.commitGate = summary;
      run.transactionStatus = "TERMINAL";
      run.baseViewId = summary.baseViewId ?? run.baseViewId;
      run.proposalId = summary.proposalId ?? null;
      run.evaluationContextHash = summary.evaluationContextHash ?? null;
      run.permitId = summary.permitId ?? null;
      run.completedAt = run.completedAt ?? now();
      if (!run.output && assistant) run.output = assistant.content;

      if (assistant) {
        assistant.authority = expectedAuthority;
        assistant.viewId = receipt.view.viewId;
        assistant.proposalId = summary.proposalId ?? null;
      } else if (run.output) {
        this.upsertAssistantMessage(database, {
          agentId: agent.id,
          runId: run.id,
          content: run.output,
          authority: expectedAuthority,
          viewId: receipt.view.viewId,
          proposalId: summary.proposalId ?? null,
          createdAt: run.completedAt,
        });
      }

      if (
        hadProjectionGap &&
        (!latestRecovered || latestRecovered.receipt.sequence < receipt.sequence)
      ) {
        latestRecovered = {
          receipt,
          runLeaseId: transition.runLeaseId,
          cancelled,
        };
      }
    }

    if (!latestRecovered) {
      const hasActiveProductRun = database.runs.some(
        (run) =>
          run.agentId === agent.id &&
          (run.status === "queued" || run.status === "running"),
      );
      if (agent.status === "busy" && !hasActiveProductRun) {
        // Rollback has no AgentRun row. A kill after its DB admission but
        // before Worker prepare therefore leaves only a stale busy marker; a
        // kill after Worker prepare/apply is reflected by the recovered HEAD.
        // In either case no execution survives process restart, so release the
        // product lock. Retire continuation state only when Worker recovery
        // actually changed the authoritative View.
        agent.status = "ready";
        agent.activeRunLeaseId = null;
        agent.lastError = null;
        agent.updatedAt = now();
        if (previousViewId !== head.view.viewId) {
          agent.codexThreadId = null;
          agent.needsReconciliation = true;
          return true;
        }
      }
      return false;
    }
    const ownsProjectedLease =
      agent.activeRunLeaseId === null ||
      agent.activeRunLeaseId === latestRecovered.runLeaseId;
    if (!ownsProjectedLease) return false;
    if (agent.status !== "stopped") {
      agent.status =
        latestRecovered.receipt.decision === "ABORTED" && !latestRecovered.cancelled
          ? "error"
          : "ready";
    }
    agent.activeRunLeaseId = null;
    agent.codexThreadId = null;
    agent.needsReconciliation = true;
    agent.lastError =
      latestRecovered.receipt.decision === "ABORTED" && !latestRecovered.cancelled
        ? "infra_errored"
        : null;
    agent.updatedAt = now();
    return true;
  }

  private workerRunStatus(
    decision: ProjectedTerminalReceipt["decision"],
    cancelled: boolean,
  ): AgentRun["status"] {
    if (decision === "ABORTED") return cancelled ? "cancelled" : "failed";
    return "completed";
  }

  private latestWorkerTerminalProjectionGap(
    database: Database,
    agentId: string,
    projection: WorkerProjection,
  ): { runId: string; receipt: ProjectedTerminalReceipt } | null {
    let latest: { runId: string; receipt: ProjectedTerminalReceipt } | null = null;
    for (const receipt of projection.terminalReceipts) {
      const transition = projection.transitions[receipt.transitionId];
      if (!transition?.runId) continue;
      const run = database.runs.find(
        (candidate) => candidate.id === transition.runId && candidate.agentId === agentId,
      );
      if (
        !run ||
        (transition.runLeaseId !== null && transition.runLeaseId !== run.runLeaseId)
      ) {
        continue;
      }
      const cancelled = receipt.reasonCodes.some((code) => code.startsWith("RUN_CANCELLED"));
      const gap =
        run.transactionStatus !== "TERMINAL" ||
        run.status !== this.workerRunStatus(receipt.decision, cancelled) ||
        run.commitGate?.decision !== receipt.decision ||
        run.commitGate?.nextViewId !== receipt.view.viewId ||
        run.commitGate?.nextGeneration !== receipt.view.generation;
      if (gap && (!latest || latest.receipt.sequence < receipt.sequence)) {
        latest = { runId: transition.runId, receipt };
      }
    }
    return latest;
  }

  private summaryFromWorkerProjection(
    run: AgentRun,
    projection: WorkerProjection,
    receipt: ProjectedTerminalReceipt,
    recoveredProjection: boolean,
  ): CommitGateSummary {
    const transition = projection.transitions[receipt.transitionId];
    if (!transition?.baseViewId) {
      throw new Error(`WORKER_TERMINAL_BINDING_MISSING:${run.id}:transition`);
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
    if (
      receipt.decision === "COMMITTED" &&
      transition.kind === "AGENT_COMMIT" &&
      (!proposal || !evidence || !permit || permit.state !== "CONSUMED")
    ) {
      throw new Error(`WORKER_TERMINAL_BINDING_MISSING:${run.id}:commit-proof`);
    }
    const failureClass: CommitGateSummary["failureClass"] =
      receipt.decision === "COMMITTED"
        ? null
        : receipt.decision === "QUARANTINED"
          ? "agent_wrong"
          : receipt.decision === "CONFLICTED"
            ? "state_conflict"
            : "infra_errored";
    const checks = evidence?.checks.map((check) => ({
      id: check.id,
      status: check.status,
      reasonCode: check.status === "PASS" ? null : `TRUSTED_CHECK_${check.status}`,
    })) ?? run.commitGate?.checks ?? [];
    const candidateHash = proposal?.artifactHash ?? run.commitGate?.candidateHash ?? null;
    // ACK proves the authoritative HEAD transition, not cleanup.  Only the
    // later RUN_ARTIFACTS_DESTROYED fact may claim that run-owned bytes are
    // gone; a post-ACK cleanup failure therefore remains explicitly deferred.
    const candidateCleanup: CommitGateSummary["candidateCleanup"] =
      transition.artifactsDestroyed ? "deleted" : "deferred";
    const artifactRetention: NonNullable<CommitGateSummary["artifactRetention"]> =
      transition.artifactsDestroyed
        ? receipt.decision === "COMMITTED"
          ? "version_snapshot"
          : "destroyed"
        : "deferred";
    const summary: CommitGateSummary = {
      transactionStatus: "TERMINAL",
      decision: receipt.decision,
      failureClass,
      receiptId: receipt.receiptId,
      baseHash: transition.baseWorkspaceHash,
      candidateHash,
      finalHash: receipt.workspaceHash,
      policyHash: evidence?.policyHash ?? run.commitGate?.policyHash ?? "worker-authority",
      checks,
      changedPaths: proposal?.changedPaths ?? run.commitGate?.changedPaths ?? [],
      threadDisposition:
        receipt.decision === "COMMITTED" && !recoveredProjection
          ? run.commitGate?.threadDisposition ?? "resumed"
          : "reset",
      candidateCleanup,
      baseViewId: transition.baseViewId,
      nextViewId: receipt.view.viewId,
      baseGeneration: transition.baseGeneration,
      nextGeneration: receipt.view.generation,
      proposalId: proposal?.proposalId ?? null,
      proposalHash: candidateHash,
      evaluationContextHash: evidence?.evaluationContextHash ?? null,
      evidenceDigest: evidence?.evidenceDigest ?? null,
      permitId: permit?.permitId ?? null,
      permitState: permit?.state ?? null,
      artifactRetention,
      provider: run.provider,
      ...(run.commitGate?.lifecycle ? { lifecycle: run.commitGate.lifecycle } : {}),
      finalView: receipt.view,
      effectProof: deriveEffectDispositionProof({
        decision: receipt.decision,
        baseHash: transition.baseWorkspaceHash,
        candidateHash,
        finalHash: receipt.workspaceHash,
        authoritativeBeforeHash:
          receipt.decision === "COMMITTED"
            ? transition.baseWorkspaceHash
            : receipt.workspaceHash,
        sealedProposalHash: proposal?.artifactHash ?? null,
        verifierInputHash: evidence?.verifierInputHash ?? null,
        promotionSourceHash: permit?.targetArtifactHash ?? null,
        finalAuthoritativeHash: receipt.workspaceHash,
      }),
    };
    return summary;
  }

  private applyWorkerHead(agent: Agent, projection: WorkerProjection): void {
    const head = projection.head;
    if (!head) throw new Error(`WORKER_HEAD_MISSING:${agent.id}`);
    agent.headVersionId = head.view.headVersionId;
    agent.stateGeneration = head.view.generation;
    agent.currentVersionedHash = head.view.versionedHash;
    agent.currentPlatformManagedHash = head.view.platformManagedHash;
    agent.currentLiveStateHash = head.view.liveStateHash;
    agent.sessionEpoch = head.view.sessionEpoch;
    agent.agentConfigVersion = head.view.agentConfigVersion;
    agent.policyVersion = head.view.policyVersion;
    agent.currentViewId = head.view.viewId;
    agent.recoveryRequired = false;
  }

  private applyWorkerVersions(
    database: Database,
    agentId: string,
    projection: WorkerProjection,
  ): void {
    const existingVersions = new Map(
      database.versions
        .filter((version) => version.agentId === agentId)
        .map((version) => [version.id, version]),
    );
    const existingSnapshots = new Map(
      database.snapshots
        .filter((snapshot) => snapshot.agentId === agentId)
        .map((snapshot) => [snapshot.hash, snapshot]),
    );
    database.versions = database.versions.filter((version) => version.agentId !== agentId);
    let parentVersionId: string | null = null;
    for (let index = 0; index < projection.versions.length; index += 1) {
      const version = projection.versions[index]!;
      const existing = existingVersions.get(version.versionId);
      database.versions.push({
        id: version.versionId,
        agentId,
        sequence: index + 1,
        parentVersionId,
        kind: version.kind,
        snapshotHash: version.workspaceHash,
        liveStateHash: version.workspaceHash,
        pathPolicyHash: existing?.pathPolicyHash ?? "worker-authority",
        sourceRunId: version.kind === "INITIAL" ? null : version.transitionId,
        sourceReceiptId: version.receiptId,
        rollbackTargetVersionId: version.rollbackTargetVersionId,
        changedPaths: existing?.changedPaths ?? [],
        snapshotAvailable: true,
        generation: version.generation,
        viewId: version.viewId,
        transitionEventId: version.transitionId,
        createdAt: existing?.createdAt ?? now(),
      });
      parentVersionId = version.versionId;
    }
    const snapshotHashes = new Set(projection.versions.map((version) => version.snapshotId));
    database.snapshots = [
      ...database.snapshots.filter((snapshot) => snapshot.agentId !== agentId),
      ...[...snapshotHashes].map((hash) =>
        existingSnapshots.get(hash) ?? {
          agentId,
          hash,
          sizeBytes: 0,
          state: "available" as const,
          createdAt: now(),
        },
      ),
    ];
  }

  listAgents(): Agent[] {
    return this.store
      .snapshot()
      .agents.sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
  }

  getAgent(id: string): Agent {
    const agent = this.store.snapshot().agents.find((item) => item.id === id);
    if (!agent) throw new HttpError(404, "Agent not found");
    return agent;
  }

  getStateView(id: string) {
    return stateViewForAgent(this.getAgent(id));
  }

  async createAgent(input: CreateAgentInput): Promise<Agent> {
    const timestamp = now();
    const id = randomUUID();
    const workerHeadVersionId = this.commitGate?.mode === "worker"
      ? `initial-${randomUUID()}`
      : null;
    const agent: Agent = {
      id,
      name: input.name.trim(),
      description: input.description?.trim() ?? "",
      instructions: input.instructions?.trim() ?? "",
      status: "ready",
      workspacePath: this.workspaces.workspacePath(id),
      ...(this.commitGate?.mode === "worker"
        ? { workspaceRef: { authority: "transition-worker" as const, agentId: id } }
        : {}),
      codexThreadId: null,
      sessionEpoch: 0,
      needsReconciliation: false,
      headVersionId: workerHeadVersionId,
      stateGeneration: 1,
      currentViewId: "",
      currentVersionedHash: EMPTY_STATE_HASH,
      currentPlatformManagedHash: EMPTY_STATE_HASH,
      currentLiveStateHash: EMPTY_STATE_HASH,
      agentConfigVersion: 1,
      policyVersion: 1,
      activeRunLeaseId: null,
      recoveryRequired: false,
      lastError: null,
      createdAt: timestamp,
      updatedAt: timestamp,
    };
    refreshAgentViewId(agent);
    if (this.commitGate?.mode === "worker") {
      const projection = await this.commitGate.authority.initializeAgent({
        agentId: id,
        operationId: `initialize-${id}`,
        headVersionId: workerHeadVersionId!,
        generation: agent.stateGeneration,
        sessionEpoch: agent.sessionEpoch,
        agentConfigVersion: agent.agentConfigVersion,
        policyVersion: agent.policyVersion,
        name: agent.name,
        instructions: this.workspaces.renderInstructions(agent),
      });
      this.applyWorkerHead(agent, projection);
      await this.store.mutate((database) => {
        database.agents.push(agent);
        this.applyWorkerVersions(database, id, projection);
      });
      return structuredClone(agent);
    }
    await this.transitionWriter!.createAgentWorkspace(agent);
    let projection: VersionProjection | null = null;
    if (this.commitGate) {
      await this.commitGate.coordinator.initializeAgent(id, agent.workspacePath);
      const policy = await this.commitGate.coordinator.policyForAgent(id);
      projection = await this.projectVersions(
        id,
        (await buildManifest(agent.workspacePath, policy)).hash,
      );
      agent.headVersionId = projection.headVersionId;
      const hashes = await this.captureWorkspaceHashes(agent.workspacePath, policy);
      agent.currentVersionedHash = hashes.versionedHash;
      agent.currentPlatformManagedHash = hashes.platformManagedHash;
      agent.currentLiveStateHash = hashes.liveStateHash;
      agent.stateGeneration = Math.max(
        1,
        projection.versions.find((version) => version.id === projection?.headVersionId)?.generation ?? 1,
      );
      refreshAgentViewId(agent);
    }
    await this.store.mutate((database) => {
      database.agents.push(agent);
      if (projection) this.applyVersionProjection(database, id, projection);
    });
    return structuredClone(agent);
  }

  async updateAgent(id: string, input: UpdateAgentInput): Promise<Agent> {
    const current = this.getAgent(id);
    this.assertRecoveryReady(current);
    this.assertNoActiveMutation(id);
    if (current.status === "busy") {
      throw new HttpError(409, "Stop the active run before editing this Agent");
    }
    // Reserve across both the DB mutation and AGENTS.md regeneration.  Without
    // this span, delete could archive the workspace after the DB await but
    // before the platform-managed file write completes.
    this.activeConfigurationMutations.add(id);
    try {
      const next = structuredClone(current);
      if (input.name !== undefined) next.name = input.name.trim();
      if (input.description !== undefined) next.description = input.description.trim();
      if (input.instructions !== undefined) next.instructions = input.instructions.trim();
      next.codexThreadId = null;
      next.sessionEpoch += 1;
      next.agentConfigVersion += 1;
      next.stateGeneration += 1;
      next.needsReconciliation = true;
      next.lastError = null;
      next.updatedAt = now();
      if (this.commitGate?.mode === "worker") {
        const projection = await this.commitGate.authority.regeneratePlatformState({
          agentId: id,
          operationId: `config-${randomUUID()}`,
          expectedViewId: current.currentViewId,
          expectedWorkspaceHash: current.currentLiveStateHash,
          instructions: this.workspaces.renderInstructions(next),
          sessionEpoch: next.sessionEpoch,
          agentConfigVersion: next.agentConfigVersion,
          policyVersion: next.policyVersion,
        });
        this.applyWorkerHead(next, projection);
        const updated = await this.store.mutate((database) => {
          const index = database.agents.findIndex((item) => item.id === id);
          if (index < 0) throw new HttpError(404, "Agent not found");
          if (database.agents[index]!.currentViewId !== current.currentViewId) {
            throw new HttpError(409, "Agent view changed during configuration update", "HEAD_MISMATCH");
          }
          database.agents[index] = structuredClone(next);
          this.applyWorkerVersions(database, id, projection);
          return structuredClone(next);
        });
        await this.retireSessionFence(id);
        return updated;
      }
      await this.transitionWriter!.regeneratePlatformState(next);
      try {
        if (this.commitGate) {
          const policy = await this.commitGate.coordinator.policyForAgent(id);
          const hashes = await this.captureWorkspaceHashes(next.workspacePath, policy);
          next.currentVersionedHash = hashes.versionedHash;
          next.currentPlatformManagedHash = hashes.platformManagedHash;
          next.currentLiveStateHash = hashes.liveStateHash;
        }
        refreshAgentViewId(next);
        const updated = await this.store.mutate((database) => {
          const index = database.agents.findIndex((item) => item.id === id);
          if (index < 0) throw new HttpError(404, "Agent not found");
          const stored = database.agents[index]!;
          if (
            stored.currentViewId !== current.currentViewId ||
            stored.agentConfigVersion !== current.agentConfigVersion
          ) {
            throw new HttpError(409, "Agent view changed during configuration update", "HEAD_MISMATCH");
          }
          database.agents[index] = structuredClone(next);
          return structuredClone(next);
        });
        await this.retireSessionFence(id);
        return updated;
      } catch (error) {
        await this.transitionWriter!.regeneratePlatformState(current).catch(() => undefined);
        throw error;
      }
    } finally {
      this.activeConfigurationMutations.delete(id);
    }
  }

  async deleteAgent(id: string): Promise<{ archivedWorkspace: string }> {
    const agent = this.getAgent(id);
    this.assertRecoveryReady(agent);
    this.reserveLifecycleMutation(id);
    try {
      await this.cancelExecution(id);
      this.assertRecoveryReady(this.getAgent(id));
      const archivedWorkspace = this.commitGate?.mode === "worker"
        ? (
            await this.commitGate.authority.archiveAgent({
              agentId: id,
              operationId: `archive-${randomUUID()}`,
              expectedViewId: agent.currentViewId,
              expectedWorkspaceHash: agent.currentLiveStateHash,
            })
          ).lastEventId ?? `archived-${id}`
        : await this.transitionWriter!.archiveAgent(agent);
      if (this.commitGate && this.commitGate.mode !== "worker") {
        await this.transitionWriter!.archiveControlPlane(id);
      }
      await this.store.mutate((database) => {
        database.agents = database.agents.filter((item) => item.id !== id);
        database.messages = database.messages.filter((item) => item.agentId !== id);
        database.runs = database.runs.filter((item) => item.agentId !== id);
        database.versions = database.versions.filter((item) => item.agentId !== id);
        database.snapshots = database.snapshots.filter((item) => item.agentId !== id);
      });
      return { archivedWorkspace };
    } finally {
      this.activeLifecycleMutations.delete(id);
    }
  }

  async startAgent(id: string): Promise<Agent> {
    const agent = this.getAgent(id);
    this.assertRecoveryReady(agent);
    this.assertNoActiveMutation(id);
    return this.setStatus(id, "ready");
  }

  async stopAgent(id: string): Promise<Agent> {
    this.assertRecoveryReady(this.getAgent(id));
    this.reserveLifecycleMutation(id);
    try {
      await this.cancelExecution(id);
      return await this.setStatus(id, "stopped");
    } finally {
      this.activeLifecycleMutations.delete(id);
    }
  }

  getMessages(agentId: string): Message[] {
    this.getAgent(agentId);
    return this.store
      .snapshot()
      .messages.filter((message) => message.agentId === agentId)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
  }

  getRun(runId: string): AgentRun {
    const run = this.store.snapshot().runs.find((item) => item.id === runId);
    if (!run) throw new HttpError(404, "Run not found");
    return run;
  }

  getRuns(agentId: string): AgentRun[] {
    this.getAgent(agentId);
    return this.store
      .snapshot()
      .runs.filter((run) => run.agentId === agentId)
      .sort((left, right) => right.createdAt.localeCompare(left.createdAt));
  }

  private async handleCommitGateLifecycleEvent(
    event: CommitGateLifecycleEvent,
  ): Promise<void> {
    const snapshot = this.store.snapshot();
    const run = snapshot.runs.find((item) => item.id === event.runId);
    const agent = run
      ? snapshot.agents.find((item) => item.id === run.agentId)
      : undefined;
    if (
      !run ||
      !agent ||
      run.runLeaseId !== event.runLeaseId ||
      run.baseViewId !== event.baseViewId ||
      agent.activeRunLeaseId !== event.runLeaseId ||
      agent.currentViewId !== event.baseViewId ||
      agent.sessionEpoch !== event.sessionEpoch
    ) {
      await this.recordStaleCallback(
        agent?.id ?? run?.agentId ?? "unknown-agent",
        event.runId,
        "lifecycle-" + event.status.toLowerCase(),
        event.runLeaseId,
        event.baseViewId,
        event.sessionEpoch,
      );
      return;
    }

    let stale = false;
    await this.store.mutate((database) => {
      const storedRun = database.runs.find((item) => item.id === event.runId);
      const storedAgent = storedRun
        ? database.agents.find((item) => item.id === storedRun.agentId)
        : undefined;
      if (
        !storedRun ||
        !storedAgent ||
        storedRun.runLeaseId !== event.runLeaseId ||
        storedRun.baseViewId !== event.baseViewId ||
        storedAgent.activeRunLeaseId !== event.runLeaseId ||
        storedAgent.currentViewId !== event.baseViewId ||
        storedAgent.sessionEpoch !== event.sessionEpoch
      ) {
        stale = true;
        return;
      }
      const assistant = database.messages.find(
        (message) => message.runId === event.runId && message.role === "assistant",
      );
      if (event.status === "PROVISIONAL" && event.output !== undefined) {
        this.upsertAssistantMessage(database, {
          agentId: storedAgent.id,
          runId: event.runId,
          content: this.redactAgentText(event.output, this.config.codexMaxOutputBytes),
          authority: "PROVISIONAL",
          viewId: event.baseViewId,
          proposalId: event.proposalId ?? null,
          createdAt: now(),
        });
        storedRun.transactionStatus = "EXECUTING";
      } else if (assistant?.authority === "PROVISIONAL" && event.proposalId) {
        assistant.proposalId = event.proposalId;
        storedRun.proposalId = event.proposalId;
      }
    });
    if (stale) {
      await this.recordStaleCallback(
        agent.id,
        event.runId,
        "lifecycle-race-" + event.status.toLowerCase(),
        event.runLeaseId,
        event.baseViewId,
        event.sessionEpoch,
      );
    }
  }

  async getCommitGateReceipt(runId: string): Promise<GateReceipt> {
    const run = this.getRun(runId);
    if (!this.commitGate) throw new HttpError(404, "CommitGate receipt not found");
    if (this.commitGate.mode === "worker") {
      const projection = await this.commitGate.authority.getProjection(run.agentId);
      const terminal = projection.terminalReceipts.find(
        (item) => item.receiptId === run.id && item.transitionId === run.id,
      );
      if (terminal) {
        return this.receiptFromWorkerProjection(run, projection, terminal);
      }
      // A live run may expose a bounded pending receipt, but no terminal claim
      // is reconstructed from API memory. Once a terminal Worker event exists,
      // every authoritative field comes from the projection path above.
      const pending = this.commitGate.runner.getReceipt(run.id);
      if (!pending) throw new HttpError(404, "CommitGate receipt not found");
      if (pending.phase === "TERMINAL") {
        throw new HttpError(
          503,
          "API receipt is terminal but the Worker terminal event is missing",
          "RECEIPT_PROJECTION_MISMATCH",
        );
      }
      return {
        ...pending,
        effectProof: deriveEffectDispositionProof({
          decision: pending.decision,
          baseHash: pending.baseSnapshotHash,
          candidateHash: pending.candidateSnapshotHash,
          finalHash: pending.finalSnapshotHash,
        }),
      };
    }
    const receipt = await this.commitGate.receiptStore.get(run.agentId, run.id);
    if (!receipt) throw new HttpError(404, "CommitGate receipt not found");
    let effectProof = deriveEffectDispositionProof({
      decision: receipt.decision,
      baseHash: receipt.baseSnapshotHash,
      candidateHash: receipt.candidateSnapshotHash,
      finalHash: receipt.finalSnapshotHash,
    });
    return {
      ...receipt,
      effectProof,
    };
  }

  private receiptFromWorkerProjection(
    run: AgentRun,
    projection: WorkerProjection,
    terminal: ProjectedTerminalReceipt,
  ): GateReceipt {
    const transition = projection.transitions[terminal.transitionId];
    if (!transition?.baseViewId) {
      throw new HttpError(503, "Worker terminal transition is incomplete", "RECEIPT_PROJECTION_MISMATCH");
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
    if (
      terminal.decision === "COMMITTED" &&
      (!proposal || !evidence || !permit || permit.state !== "CONSUMED")
    ) {
      throw new HttpError(503, "Worker commit proof is incomplete", "RECEIPT_PROJECTION_MISMATCH");
    }
    const summary = this.summaryFromWorkerProjection(run, projection, terminal, false);
    const cached = this.commitGate?.mode === "worker"
      ? this.commitGate.runner.getReceipt(run.id)
      : null;
    const baseView =
      cached?.baseView?.viewId === transition.baseViewId &&
      cached.baseView.generation === transition.baseGeneration &&
      cached.baseView.liveStateHash === transition.baseWorkspaceHash
        ? cached.baseView
        : null;
    return {
      schemaVersion: 2,
      runId: run.id,
      agentId: run.agentId,
      phase: "TERMINAL",
      decision: terminal.decision,
      failureClass: summary.failureClass,
      reasonCodes: terminal.reasonCodes,
      baseSnapshotHash: transition.baseWorkspaceHash,
      candidateSnapshotHash: proposal?.artifactHash ?? null,
      patchHash: null,
      finalSnapshotHash: terminal.workspaceHash,
      policyHash: evidence?.policyHash ?? summary.policyHash,
      evidence: { trusted: evidence?.coverage ?? "unavailable" },
      checks: evidence?.checks.map((check) => ({
        id: check.id,
        status: check.status,
        exitCode: check.exitCode,
        durationMs: check.durationMs,
        output: "[redacted authority evidence]",
        timedOut: check.timedOut,
      })) ?? [],
      changedPaths: proposal?.changedPaths ?? [],
      threadDisposition: terminal.decision === "COMMITTED" ? "resumed" : "reset",
      candidateCleanup: summary.candidateCleanup,
      sessionEpoch: terminal.view.sessionEpoch,
      versionId: terminal.view.headVersionId,
      promotionPendingDatabaseAck: false,
      baseView,
      nextView: terminal.view,
      baseViewId: transition.baseViewId,
      finalViewId: terminal.view.viewId,
      baseGeneration: transition.baseGeneration,
      nextGeneration: terminal.view.generation,
      generation: terminal.view.generation,
      proposalId: proposal?.proposalId ?? null,
      evaluationContextHash: evidence?.evaluationContextHash ?? null,
      evidenceDigest: evidence?.evidenceDigest ?? null,
      permitId: permit?.permitId ?? null,
      permitState: permit?.state ?? null,
      transactionStatus: "TERMINAL",
      artifactRetention: summary.artifactRetention ?? "deferred",
      provider: run.provider,
      ...(summary.effectProof ? { effectProof: summary.effectProof } : {}),
      startedAt: run.startedAt ?? run.createdAt,
      completedAt: run.completedAt ?? now(),
    };
  }

  async getCommitGateProof(runId: string): Promise<AuthorityReceiptProofBundle> {
    const run = this.getRun(runId);
    return this.getCommitGateProofByReceipt(run.agentId, run.id);
  }

  /**
   * Reads any Worker-owned terminal receipt proof, including rollback receipts
   * that intentionally do not have an AgentRun row. The projection is selected
   * by Agent first, so a caller cannot use a receipt id as a cross-Agent oracle
   * or turn it into a filesystem path.
   */
  async getCommitGateProofByReceipt(
    agentId: string,
    receiptId: string,
  ): Promise<AuthorityReceiptProofBundle> {
    this.getAgent(agentId);
    if (!this.commitGate || this.commitGate.mode !== "worker") {
      throw new HttpError(404, "CommitGate receipt proof not found");
    }
    let projection = await this.commitGate.authority.getProjection(agentId);
    let terminal = projection.terminalReceipts.find(
      (candidate) => candidate.receiptId === receiptId,
    );
    if (!terminal) {
      throw new HttpError(404, "CommitGate receipt proof not found");
    }
    let compactProof = projection.receiptProofs[receiptId];
    if (!compactProof) {
      projection = await this.commitGate.runner.recoverAuthority(agentId, projection);
      terminal = projection.terminalReceipts.find(
        (candidate) => candidate.receiptId === receiptId,
      );
      compactProof = projection.receiptProofs[receiptId];
    }
    if (!terminal) {
      throw new HttpError(404, "CommitGate receipt proof not found");
    }
    if (!compactProof) {
      throw new HttpError(
        503,
        "CommitGate receipt is terminal but its proof is pending recovery",
        "RECEIPT_PROOF_PENDING",
      );
    }
    let bundle: AuthorityReceiptProofBundle;
    try {
      bundle = await this.commitGate.authority.getReceiptProof(agentId, receiptId);
    } catch (error) {
      const code =
        error && typeof error === "object" && "code" in error &&
          typeof error.code === "string"
          ? error.code
          : null;
      if (code === "RECEIPT_PROOF_PENDING") {
        throw new HttpError(
          503,
          "CommitGate receipt is terminal but its proof is pending recovery",
          "RECEIPT_PROOF_PENDING",
        );
      }
      throw error;
    }
    if (
      compactProof.receiptId !== receiptId ||
      compactProof.transitionId !== terminal.transitionId ||
      compactProof.terminalEventId !== terminal.eventId ||
      bundle.schemaVersion !== 3 ||
      !Array.isArray(bundle.eventChain) ||
      bundle.eventChain.length === 0 ||
      bundle.receipt.receiptId !== receiptId ||
      bundle.receipt.agentId !== agentId ||
      bundle.receipt.transitionId !== terminal.transitionId ||
      bundle.receipt.decision !== terminal.decision ||
      bundle.receipt.finalViewId !== terminal.viewId ||
      bundle.receipt.finalWorkspaceHash !== terminal.workspaceHash
    ) {
      throw new HttpError(
        503,
        "CommitGate receipt proof does not belong to the requested Agent receipt",
        "RECEIPT_PROOF_BINDING_MISMATCH",
      );
    }
    const verification = verifyAuthorityReceiptProof(bundle);
    if (!verification.valid) {
      throw new HttpError(
        503,
        `CommitGate receipt proof failed verification: ${verification.reason ?? "unknown"}`,
        "RECEIPT_PROOF_INVALID",
      );
    }
    return bundle;
  }

  private rebuildWorkerReceipt(run: AgentRun): GateReceipt | null {
    const summary = run.commitGate;
    if (!summary) return null;
    const database = this.store.snapshot();
    const agent = database.agents.find((item) => item.id === run.agentId);
    if (!agent) return null;
    const baseViewId = summary.baseViewId ?? run.baseViewId;
    const baseVersion = database.versions.find(
      (version) =>
        version.agentId === run.agentId &&
        version.viewId === baseViewId,
    );
    const baseGeneration =
      summary.baseGeneration ??
      baseVersion?.generation ??
      (summary.decision === "COMMITTED"
        ? Math.max(0, agent.stateGeneration - 1)
        : agent.stateGeneration);
    const nextGeneration = summary.nextGeneration ?? agent.stateGeneration;
    const baseView: StateViewRef = {
      schemaVersion: 1,
      viewId: baseViewId,
      agentId: run.agentId,
      headVersionId: baseVersion?.id ?? agent.headVersionId ?? "unknown-base",
      generation: baseGeneration,
      versionedHash: baseVersion?.snapshotHash ?? summary.baseHash,
      platformManagedHash: summary.baseHash,
      liveStateHash: summary.baseHash,
      sessionEpoch: summary.finalView?.sessionEpoch ?? agent.sessionEpoch,
      agentConfigVersion: summary.finalView?.agentConfigVersion ?? agent.agentConfigVersion,
      policyVersion: summary.finalView?.policyVersion ?? agent.policyVersion,
    };
    const finalView = summary.finalView ?? null;
    return {
      schemaVersion: 2,
      runId: run.id,
      agentId: run.agentId,
      phase: "TERMINAL",
      decision: summary.decision,
      failureClass: summary.failureClass,
      reasonCodes: summary.checks
        .map((check) => check.reasonCode)
        .filter((value): value is string => Boolean(value)),
      baseSnapshotHash: summary.baseHash,
      candidateSnapshotHash: summary.candidateHash,
      patchHash: null,
      finalSnapshotHash: summary.finalHash,
      policyHash: summary.policyHash,
      evidence: { projection: "partial" },
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
      sessionEpoch: finalView?.sessionEpoch ?? agent.sessionEpoch,
      versionId: finalView?.headVersionId ?? null,
      promotionPendingDatabaseAck: false,
      baseView,
      nextView: finalView,
      baseViewId,
      finalViewId: summary.nextViewId ?? null,
      baseGeneration,
      nextGeneration,
      generation: nextGeneration,
      proposalId: summary.proposalId ?? null,
      evaluationContextHash: summary.evaluationContextHash ?? null,
      evidenceDigest: summary.evidenceDigest ?? null,
      permitId: summary.permitId ?? null,
      permitState: summary.permitState ?? null,
      transactionStatus: "TERMINAL",
      artifactRetention: summary.artifactRetention ?? "deferred",
      provider: summary.provider ?? run.provider,
      effectProof:
        summary.effectProof ??
        deriveEffectDispositionProof({
          decision: summary.decision,
          baseHash: summary.baseHash,
          candidateHash: summary.candidateHash,
          finalHash: summary.finalHash,
        }),
      startedAt: run.startedAt ?? run.createdAt,
      completedAt: run.completedAt ?? now(),
    };
  }

  async attemptPromotionReplay(
    runId: string,
    permitId: string,
    expectedViewId: string,
  ): Promise<{
    code: "PERMIT_REPLAY";
    permitState: "CONSUMED";
    headUnchanged: true;
    currentViewId: string;
    currentGeneration: number;
  }> {
    const run = this.getRun(runId);
    const agent = this.getAgent(run.agentId);
    if (!this.commitGate) throw new HttpError(404, "CommitGate receipt not found");
    if (agent.currentViewId !== expectedViewId) {
      throw new HttpError(409, "Authoritative View changed", "HEAD_MISMATCH");
    }
    const receipt = await this.getCommitGateReceipt(runId);
    if (receipt.permitId !== permitId) {
      throw new HttpError(409, "Permit does not belong to this run", "HEAD_MISMATCH");
    }
    const beforeGeneration = agent.stateGeneration;
    let result: { code: "PERMIT_REPLAY"; permitState: "CONSUMED" };
    if (this.commitGate.mode === "worker") {
      try {
        await this.commitGate.authority.attemptPermitConsumption({
          agentId: run.agentId,
          transitionId: runId,
          permitId,
          expectedViewId,
        });
        throw new Error("PERMIT_REPLAY_WAS_ACCEPTED");
      } catch (error) {
        if (!(error && typeof error === "object" && "code" in error && error.code === "PERMIT_REPLAY")) {
          throw error;
        }
      }
      result = { code: "PERMIT_REPLAY", permitState: "CONSUMED" };
    } else {
      result = await this.commitGate.coordinator.attemptConsumedPermitReplay({
        agentId: run.agentId,
        runId,
        permitId,
        expectedCurrentViewId: expectedViewId,
      });
    }
    const after = this.getAgent(run.agentId);
    if (
      after.currentViewId !== expectedViewId ||
      after.stateGeneration !== beforeGeneration
    ) {
      throw new Error("PERMIT_REPLAY_CHANGED_AUTHORITATIVE_HEAD");
    }
    return {
      ...result,
      headUnchanged: true,
      currentViewId: after.currentViewId,
      currentGeneration: after.stateGeneration,
    };
  }

  getVersions(agentId: string, limit = 20, beforeSequence?: number): WorkspaceVersion[] {
    this.getAgent(agentId);
    return this.store
      .snapshot()
      .versions.filter(
        (version) =>
          version.agentId === agentId &&
          (beforeSequence === undefined || version.sequence < beforeSequence),
      )
      .sort((left, right) => right.sequence - left.sequence)
      .slice(0, Math.max(1, Math.min(100, limit)));
  }

  async rollback(
    agentId: string,
    targetVersionId: string,
    expectedHeadVersionId: string,
    expectedViewId?: string,
    expectedGeneration?: number,
  ): Promise<{ agent: Agent; version: WorkspaceVersion; sessionReset: true }> {
    this.assertRecoveryReady(this.getAgent(agentId));
    this.assertNoActiveMutation(agentId);
    const operation = this.performRollback(
      agentId,
      targetVersionId,
      expectedHeadVersionId,
      expectedViewId,
      expectedGeneration,
    );
    this.activeRollbacks.set(agentId, operation);
    try {
      return await operation;
    } finally {
      if (this.activeRollbacks.get(agentId) === operation) {
        this.activeRollbacks.delete(agentId);
      }
    }
  }

  private async performRollback(
    agentId: string,
    targetVersionId: string,
    expectedHeadVersionId: string,
    expectedViewId?: string,
    expectedGeneration?: number,
  ): Promise<{ agent: Agent; version: WorkspaceVersion; sessionReset: true }> {
    if (!this.commitGate) {
      throw new HttpError(503, "CommitGate is not available", "COMMITGATE_NOT_AVAILABLE");
    }
    let previousStatus: Agent["status"] = "ready";
    const agentAtStart = await this.store.mutate((database) => {
      const agent = database.agents.find((item) => item.id === agentId);
      if (!agent) throw new HttpError(404, "Agent not found");
      this.assertRecoveryReady(agent);
      if (agent.status === "busy") throw new HttpError(409, "Agent is busy", "AGENT_BUSY");
      if (agent.headVersionId !== expectedHeadVersionId) {
        throw new HttpError(409, "Expected head does not match", "HEAD_MISMATCH");
      }
      if (
        (expectedViewId !== undefined && agent.currentViewId !== expectedViewId) ||
        (expectedGeneration !== undefined && agent.stateGeneration !== expectedGeneration)
      ) {
        throw new HttpError(409, "Expected StateView does not match", "VIEW_MISMATCH");
      }
      previousStatus = agent.status;
      agent.status = "busy";
      agent.lastError = null;
      agent.updatedAt = now();
      return structuredClone(agent);
    });

    const rollbackRunId = "rollback-" + randomUUID();
    if (this.commitGate.mode === "worker") {
      return this.performWorkerRollback(
        agentAtStart,
        targetVersionId,
        rollbackRunId,
        previousStatus,
      );
    }
    let staged = false;
    let databaseCommitted = false;
    try {
      const policy = await this.commitGate.coordinator.policyForAgent(agentId);
      // Reconcile platform-managed state before computing the rollback base and
      // target hashes.  Mutating AGENTS.md after stageRollback would make the
      // database head differ from the durable journal target during an
      // ack-before-crash recovery window.
      await this.transitionWriter!.regeneratePlatformState(agentAtStart);
      const event = await this.commitGate.versionStore.stageRollback({
        agentId,
        workspacePath: agentAtStart.workspacePath,
        policy,
        targetVersionId,
        expectedHeadVersionId,
        runId: rollbackRunId,
      });
      staged = true;
      const liveHash = (await buildManifest(agentAtStart.workspacePath, policy)).hash;
      const hashes = await this.captureWorkspaceHashes(agentAtStart.workspacePath, policy);
      const projection = await this.projectVersions(agentId, liveHash);
      await this.store.mutate((database) => {
        this.applyVersionProjection(database, agentId, projection);
        const stored = database.agents.find((item) => item.id === agentId);
        if (!stored) throw new HttpError(404, "Agent not found");
        // Keep the durable admission lock until the journal/backup has reached
        // ACKNOWLEDGED.  Publishing ready here would let another run advance the
        // head while startup recovery could still roll this workspace back.
        stored.status = "busy";
        stored.codexThreadId = null;
        stored.sessionEpoch += 1;
        stored.stateGeneration += 1;
        stored.needsReconciliation = true;
        stored.headVersionId = event.id;
        stored.currentVersionedHash = hashes.versionedHash;
        stored.currentPlatformManagedHash = hashes.platformManagedHash;
        stored.currentLiveStateHash = hashes.liveStateHash;
        refreshAgentViewId(stored);
        const projectedEvent = database.versions.find((version) => version.id === event.id);
        if (projectedEvent) {
          projectedEvent.generation = stored.stateGeneration;
          projectedEvent.viewId = stored.currentViewId;
        }
        stored.lastError = null;
        stored.updatedAt = now();
      });
      databaseCommitted = true;
      await this.retireSessionFence(agentId);
      const version = this.store.snapshot().versions.find((item) => item.id === event.id);
      if (!version) throw new Error("Rollback version metadata was not persisted");
      try {
        await this.commitGate.versionStore.acknowledgeRollback(rollbackRunId);
      } catch (firstError) {
        try {
          await this.commitGate.versionStore.acknowledgeRollback(rollbackRunId);
        } catch (secondError) {
          throw new AggregateError(
            [firstError, secondError],
            "CommitGate rollback acknowledgement retry failed",
          );
        }
      }
      const agent = await this.store.mutate((database) => {
        const stored = database.agents.find((item) => item.id === agentId);
        if (!stored) throw new HttpError(404, "Agent not found");
        stored.status = previousStatus === "stopped" ? "stopped" : "ready";
        stored.lastError = null;
        stored.updatedAt = now();
        return structuredClone(stored);
      });
      return { agent, version, sessionReset: true };
    } catch (error) {
      let rollbackFailure: unknown = null;
      if (staged && !databaseCommitted) {
        try {
          await this.commitGate.versionStore.rollbackPendingRollback(rollbackRunId);
        } catch (candidateRollbackFailure) {
          rollbackFailure = candidateRollbackFailure;
        }
      }
      const finalError = rollbackFailure
        ? new AggregateError(
            [error, rollbackFailure],
            "Rollback database commit and fail-closed workspace restoration both failed",
          )
        : error;
      if (
        databaseCommitted ||
        rollbackFailure ||
        error instanceof CommitGateRecoveryRequiredError
      ) {
        this.recoveryReservations.add(agentId);
      }
      await this.store.mutate((database) => {
        const agent = database.agents.find((item) => item.id === agentId);
        if (!agent) return;
        if (
          databaseCommitted ||
          rollbackFailure ||
          error instanceof CommitGateRecoveryRequiredError
        ) {
          agent.status = "error";
          agent.recoveryRequired = true;
          agent.codexThreadId = null;
          agent.sessionEpoch = Math.max(agent.sessionEpoch, agentAtStart.sessionEpoch + 1);
          agent.needsReconciliation = true;
          agent.activeRunLeaseId = null;
          refreshAgentViewId(agent);
        } else {
          agent.status = previousStatus;
        }
        const detail = finalError instanceof Error ? finalError.message : String(finalError);
        agent.lastError = agent.recoveryRequired
          ? RECOVERY_REQUIRED_MESSAGE + ": " + this.redactAgentText(detail, 8_192)
          : detail;
        agent.updatedAt = now();
      });
      if (error instanceof VersionStoreError) {
        if (error.code === "VERSION_NOT_FOUND") {
          throw new HttpError(404, "Target version does not exist", error.code);
        }
        if (error.code === "SNAPSHOT_PRUNED") {
          throw new HttpError(410, "Target snapshot has been pruned", error.code);
        }
        throw new HttpError(409, "Expected head does not match", error.code);
      }
      throw finalError;
    }
  }

  private async performWorkerRollback(
    agentAtStart: Agent,
    targetVersionId: string,
    rollbackRunId: string,
    previousStatus: Agent["status"],
  ): Promise<{ agent: Agent; version: WorkspaceVersion; sessionReset: true }> {
    if (this.commitGate?.mode !== "worker") throw new Error("WORKER_AUTHORITY_REQUIRED");
    const target = this.store.snapshot().versions.find(
      (version) => version.agentId === agentAtStart.id && version.id === targetVersionId,
    );
    if (!target) throw new HttpError(404, "Target version does not exist", "VERSION_NOT_FOUND");
    if (!target.snapshotAvailable) {
      throw new HttpError(410, "Target snapshot has been pruned", "SNAPSHOT_PRUNED");
    }
    const versionId = randomUUID();
    try {
      await this.commitGate.authority.prepare({
        agentId: agentAtStart.id,
        transitionId: rollbackRunId,
        kind: "ROLLBACK",
        expectedViewId: agentAtStart.currentViewId,
        expectedWorkspaceHash: agentAtStart.currentLiveStateHash,
        baseGeneration: agentAtStart.stateGeneration,
      });
      const projection = await this.commitGate.authority.applyRollback({
        agentId: agentAtStart.id,
        transitionId: rollbackRunId,
        rollbackPermitId: `rollback-permit-${randomUUID()}`,
        targetSnapshotId: target.snapshotHash,
        targetVersionId,
        expectedViewId: agentAtStart.currentViewId,
        expectedWorkspaceHash: agentAtStart.currentLiveStateHash,
        versionId,
        receiptId: rollbackRunId,
      });
      const agent = await this.store.mutate((database) => {
        const stored = database.agents.find((item) => item.id === agentAtStart.id);
        if (!stored) throw new HttpError(404, "Agent not found");
        this.applyWorkerHead(stored, projection);
        this.applyWorkerVersions(database, stored.id, projection);
        stored.status = previousStatus === "stopped" ? "stopped" : "ready";
        stored.codexThreadId = null;
        stored.needsReconciliation = true;
        stored.activeRunLeaseId = null;
        stored.lastError = null;
        stored.updatedAt = now();
        return structuredClone(stored);
      });
      await this.retireSessionFence(agentAtStart.id);
      const version = this.store.snapshot().versions.find((item) => item.id === versionId);
      if (!version) throw new Error("WORKER_ROLLBACK_VERSION_MISSING");
      return { agent, version, sessionReset: true };
    } catch (error) {
      await this.store.mutate((database) => {
        const stored = database.agents.find((item) => item.id === agentAtStart.id);
        if (!stored) return;
        stored.status = previousStatus;
        stored.lastError = error instanceof Error ? error.message : String(error);
        stored.updatedAt = now();
      });
      throw error;
    }
  }

  async sendMessage(
    agentId: string,
    prompt: string,
  ): Promise<{ run: AgentRun; message: Message }> {
    // A terminal Run/Agent projection can become observable one microtask
    // before the execution Promise releases its in-memory mutation fence
    // (for example while session-home retirement is returning). A fresh
    // follow-up should wait for that already-terminal cleanup instead of
    // intermittently surfacing AGENT_BUSY. Truly running Agents remain
    // fail-fast below because they still own an active lease.
    await this.awaitTerminalExecutionCleanup(agentId);
    this.assertRecoveryReady(this.getAgent(agentId));
    this.assertNoActiveMutation(agentId);
    if (!isModelConfigured(this.config)) {
      throw new HttpError(
        503,
        "The model provider is not configured. Set MODEL_API_KEY and MODEL_ID, then restart.",
      );
    }
    if (this.config.commitGateEnabled && !this.commitGate) {
      throw new HttpError(
        503,
        "CommitGate protected runs require the container Runtime",
        "COMMITGATE_CONTAINER_REQUIRED",
      );
    }
    if (this.config.commitGateEnabled) {
      const system = await this.systemInfo();
      if (system.commitGateReady !== true || system.verifierAvailable !== true) {
        throw new HttpError(
          503,
          "CommitGate verifier or Runtime image is unavailable",
          "COMMITGATE_NOT_READY",
        );
      }
    }
    const timestamp = now();
    const runId = randomUUID();
    const runLeaseId = randomUUID();
    const submittedViewId = this.getAgent(agentId).currentViewId;
    const run: AgentRun = {
      id: runId,
      agentId,
      status: "queued",
      prompt,
      output: null,
      error: null,
      usage: null,
      commitGate: null,
      legacyReceipt: null,
      transactionStatus: "PREPARING",
      runLeaseId,
      submittedViewId,
      baseViewId: submittedViewId,
      proposalId: null,
      evaluationContextHash: null,
      permitId: null,
      retryOfRunId: null,
      staleCallback: false,
      provider: modelProviderIdentity(this.config),
      startedAt: null,
      completedAt: null,
      createdAt: timestamp,
    };
    const message: Message = {
      id: randomUUID(),
      agentId,
      runId,
      role: "user",
      content: prompt,
      authority: "INPUT",
      viewId: submittedViewId,
      proposalId: null,
      createdAt: timestamp,
    };
    const agentAtStart = await this.store.mutate((database) => {
      const storedAgent = database.agents.find((item) => item.id === agentId);
      if (!storedAgent) throw new HttpError(404, "Agent not found");
      this.assertRecoveryReady(storedAgent);
      this.assertNoActiveMutation(agentId);
      if (storedAgent.status === "stopped") {
        throw new HttpError(409, "Start the Agent before sending a message");
      }
      if (storedAgent.status === "error") {
        throw new HttpError(409, "Start the Agent before sending another message", "AGENT_ERROR");
      }
      if (storedAgent.status === "busy") {
        throw new HttpError(409, "This Agent is already running");
      }
      database.runs.push(run);
      database.messages.push(message);
      storedAgent.status = "busy";
      storedAgent.activeRunLeaseId = runLeaseId;
      storedAgent.lastError = null;
      storedAgent.updatedAt = timestamp;
      return structuredClone(storedAgent);
    });
    const execution = this.executeRun(agentAtStart, run);
    this.activeExecutions.set(agentId, execution);
    void execution
      .finally(() => {
        if (this.activeExecutions.get(agentId) === execution) {
          this.activeExecutions.delete(agentId);
        }
      })
      .catch(() => undefined);
    return { run, message };
  }

  async systemInfo(): Promise<Record<string, unknown>> {
    const available = await this.runner.isAvailable();
    // In Worker mode the API intentionally has no trusted-check mount. The
    // Broker owns that readonly bundle and its availability is covered by the
    // Broker health contract. Probing an API-local path would incorrectly
    // disable the product UI while the isolated verifier path is healthy.
    let trustedChecksAvailable = this.commitGate?.mode === "worker";
    // `mode` is optional only for legacy in-process test/embedder fixtures.
    if (this.commitGate && this.commitGate.mode !== "worker") {
      try {
        await access(
          path.join(this.config.commitGateTrustedChecksDirectory, "workspace-sanity.mjs"),
        );
        trustedChecksAvailable = true;
      } catch {
        trustedChecksAvailable = false;
      }
    }
    const verifierAvailable = Boolean(this.commitGate && available && trustedChecksAvailable);
    return {
      modelConfigured: isModelConfigured(this.config),
      modelProvider: this.config.modelProvider,
      modelGateway: this.config.modelRuntimeBaseUrl,
      modelId: this.config.modelId || null,
      modelAccessMode: this.config.modelAccessMode,
      // Legacy fields remain during the v3 UI migration.
      arkConfigured: this.config.modelProvider === "ark" && isModelConfigured(this.config),
      arkBaseUrl: this.config.arkBaseUrl,
      arkModel: this.config.arkModel || null,
      codexAvailable: available,
      codexSandboxMode: this.config.codexSandboxMode,
      runtimeProvider: this.config.runtimeProvider,
      processRole: this.config.processRole,
      transitionAuthority: this.commitGate?.mode === "worker" ? "worker" : "in-process",
      authorityWriteIsolation:
        this.commitGate?.mode === "worker" ? "os-enforced" : "in-process",
      authorityManifestSchemaVersion:
        this.workerAuthorityHealth?.manifestSchemaVersion ?? null,
      authorityFilesystemProfile:
        this.workerAuthorityHealth?.filesystemProfile ?? null,
      // This is captured independently before a Run and serves as the TOFU
      // anchor for the Worker-signed terminal receipt proof returned later.
      authorityReceiptSigningKeyId:
        this.workerAuthorityHealth?.signingKeyId ?? null,
      containerEngine:
        ["container", "broker"].includes(this.config.runtimeProvider) ? this.config.containerEngine : null,
      runtime:
        this.config.runtimeProvider === "broker"
          ? "Codex CLI via isolated Runtime Broker"
          : this.config.runtimeProvider === "container"
            ? "Codex CLI in " + this.config.containerEngine + " Runtime"
          : "Codex CLI in application container",
      commitGateEnabled: this.config.commitGateEnabled,
      commitGateReady:
        !this.config.commitGateEnabled || verifierAvailable,
      verifierAvailable,
    };
  }

  private async executeRun(agentAtSubmission: Agent, run: AgentRun): Promise<void> {
    const binding = await this.store.mutate((database) => {
      const storedRun = database.runs.find((item) => item.id === run.id);
      const storedAgent = database.agents.find((item) => item.id === run.agentId);
      if (!storedRun || !storedAgent) {
        throw new Error("Queued run or Agent disappeared before execution");
      }
      if (
        storedRun.status !== "queued" ||
        storedRun.runLeaseId !== run.runLeaseId ||
        storedAgent.activeRunLeaseId !== run.runLeaseId
      ) {
        throw new Error("Queued run no longer owns the active lease");
      }

      // Admission records the View that the user submitted against. A queued
      // follow-up can legitimately wait behind a transition, so bind the
      // actual execution to the then-current authoritative View instead of
      // replaying the stale one. Keep submittedViewId as immutable provenance.
      if (storedAgent.currentViewId !== storedRun.submittedViewId) {
        storedRun.baseViewId = storedAgent.currentViewId;
        const inputMessage = database.messages.find(
          (message) => message.runId === storedRun.id && message.role === "user",
        );
        if (inputMessage) inputMessage.viewId = storedAgent.currentViewId;

        // Provider continuations are scoped by sessionEpoch + ViewId. If a
        // reject/rollback/configuration change advanced the epoch while this
        // input was queued, an old remote thread must not be reused.
        if (storedAgent.sessionEpoch !== agentAtSubmission.sessionEpoch) {
          storedAgent.codexThreadId = null;
          storedAgent.needsReconciliation = true;
        }
      }
      storedRun.status = "running";
      storedRun.transactionStatus = "EXECUTING";
      storedRun.startedAt = now();
      return {
        agent: structuredClone(storedAgent),
        baseViewId: storedRun.baseViewId,
      };
    });
    const agentAtStart = binding.agent;
    run.baseViewId = binding.baseViewId;
    try {
      if (this.cancellationRequests.has(agentAtStart.id)) throw new RunCancelledError();
      const effectivePrompt = agentAtStart.needsReconciliation
        ? `${reconciliationPrefix(agentAtStart)}\n\n<user_request>\n${run.prompt}\n</user_request>`
        : run.prompt;
      const result = await this.runner.run({
        runId: run.id,
        agentId: agentAtStart.id,
        workspacePath: agentAtStart.workspacePath,
        prompt: effectivePrompt,
        threadId: agentAtStart.codexThreadId,
        sessionEpoch: agentAtStart.sessionEpoch,
        runLeaseId: run.runLeaseId,
        baseViewId: agentAtStart.currentViewId,
        stateGeneration: agentAtStart.stateGeneration,
        expectedHeadVersionId: agentAtStart.headVersionId,
        agentConfigVersion: agentAtStart.agentConfigVersion,
        policyVersion: agentAtStart.policyVersion,
        baseVersionedHash: agentAtStart.currentVersionedHash,
        basePlatformManagedHash: agentAtStart.currentPlatformManagedHash,
        baseLiveStateHash: agentAtStart.currentLiveStateHash,
        provider: run.provider,
      });

      if (result.commitGate && this.commitGate) {
        if (result.commitGate.decision === "COMMITTED") {
          if (this.commitGate.mode === "worker") {
            await this.persistWorkerCommittedRun(agentAtStart, run, result);
            return;
          }
          try {
            const staged = await this.commitGate.runner.stageAcknowledge(run.id);
            const projection = await this.projectVersions(
              agentAtStart.id,
              result.commitGate.finalHash,
              {
                runId: run.id,
                changedPaths: staged.receipt.changedPaths,
              },
            );
            const projected = await this.persistCompletedRun(
              agentAtStart,
              run,
              result,
              projection,
              false,
            );
            if (!projected) return;
          } catch (error) {
            try {
              await this.commitGate.runner.rollbackPending(run.id);
            } catch (rollbackError) {
              throw new CommitGateRecoveryRequiredError(
                "CommitGate database preparation and fail-closed rollback both failed",
                new AggregateError([error, rollbackError]),
              );
            }
            throw error;
          }
          let acknowledged: Awaited<ReturnType<CommitGateComponents["runner"]["acknowledge"]>> | null = null;
          try {
            acknowledged = await this.commitGate.runner.acknowledge(run.id);
          } catch (firstError) {
            try {
              acknowledged = await this.commitGate.runner.acknowledge(run.id);
            } catch (secondError) {
              const acknowledgementError = new AggregateError(
                [firstError, secondError],
                "CommitGate acknowledgement retry failed",
              );
              this.recoveryReservations.add(agentAtStart.id);
              await this.markRecoveryRequired(agentAtStart.id, acknowledgementError);
              await this.repairFailedAcknowledge(
                agentAtStart,
                run,
                acknowledgementError,
              );
            }
          }
          if (acknowledged) {
            await this.releaseCommittedAgent(agentAtStart.id, run, acknowledged);
          }
          return;
        }
        await this.persistRejectedRun(agentAtStart, run, result);
        return;
      }

      await this.persistCompletedRun(agentAtStart, run, result, null);
    } catch (error) {
      await this.persistRunFailure(agentAtStart, run, error);
    }
  }

  private async persistCompletedRun(
    agentAtStart: Agent,
    run: AgentRun,
    result: Awaited<ReturnType<AgentRunner["run"]>>,
    projection: VersionProjection | null,
    releaseAgent = true,
  ): Promise<boolean> {
    const completedAt = now();
    const sanitizedOutput = this.redactAgentText(result.output, this.config.codexMaxOutputBytes);
    let staleCallback = false;
    await this.store.mutate((database) => {
      const storedRun = database.runs.find((item) => item.id === run.id);
      const agent = database.agents.find((item) => item.id === agentAtStart.id);
      if (!storedRun || !agent) return;
      if (!this.leaseMatches(agent, storedRun, agentAtStart, run)) {
        staleCallback = true;
        return;
      }
      if (projection) this.applyVersionProjection(database, agentAtStart.id, projection);
      const head = projection?.versions.find(
        (version) => version.id === projection.headVersionId,
      );
      if (head) {
        agent.stateGeneration = Math.max(agent.stateGeneration + 1, head.generation);
        agent.currentVersionedHash = head.snapshotHash;
        agent.currentLiveStateHash = result.commitGate?.finalHash ?? head.liveStateHash;
        agent.headVersionId = head.id;
        refreshAgentViewId(agent);
        if (result.commitGate) {
          result.commitGate.baseViewId = agentAtStart.currentViewId;
          result.commitGate.nextViewId = agent.currentViewId;
          result.commitGate.baseGeneration = agentAtStart.stateGeneration;
          result.commitGate.nextGeneration = agent.stateGeneration;
        }
      }
      // A projected workspace is not a terminal COMMITTED run until journal
      // acknowledgement and terminal receipt persistence both succeed.
      storedRun.status = projection ? "running" : "completed";
      storedRun.output = sanitizedOutput;
      storedRun.usage = result.usage;
      storedRun.commitGate = result.commitGate ?? null;
      storedRun.transactionStatus = projection ? "PENDING_PROMOTION" : "TERMINAL";
      storedRun.proposalId = result.commitGate?.proposalId ?? null;
      storedRun.evaluationContextHash = result.commitGate?.evaluationContextHash ?? null;
      storedRun.permitId = result.commitGate?.permitId ?? null;
      storedRun.provider = result.commitGate?.provider ?? storedRun.provider;
      storedRun.completedAt = completedAt;
      this.upsertAssistantMessage(database, {
        agentId: agent.id,
        runId: run.id,
        content: sanitizedOutput,
        authority: "AUTHORITATIVE",
        viewId: agent.currentViewId,
        proposalId: result.commitGate?.proposalId ?? null,
        createdAt: completedAt,
      });
      agent.status = releaseAgent ? "ready" : "busy";
      agent.codexThreadId = result.threadId;
      agent.needsReconciliation = false;
      if (projection) agent.headVersionId = projection.headVersionId;
      if (releaseAgent) agent.activeRunLeaseId = null;
      agent.lastError = null;
      agent.updatedAt = completedAt;
    });
    if (staleCallback) {
      await this.recordStaleCallback(
        agentAtStart.id,
        run.id,
        "terminal-completed",
        run.runLeaseId,
        run.baseViewId,
        agentAtStart.sessionEpoch,
      );
      return false;
    }
    return true;
  }

  private async persistWorkerCommittedRun(
    agentAtStart: Agent,
    run: AgentRun,
    result: Awaited<ReturnType<AgentRunner["run"]>>,
  ): Promise<void> {
    if (this.commitGate?.mode !== "worker" || !result.commitGate?.finalView) {
      throw new Error("WORKER_COMMITTED_VIEW_MISSING");
    }
    const projection = await this.commitGate.authority.getProjection(agentAtStart.id);
    const terminalReceipt = projection.terminalReceipts.find(
      (receipt) => receipt.receiptId === run.id && receipt.transitionId === run.id,
    );
    if (!terminalReceipt || terminalReceipt.decision !== "COMMITTED") {
      throw new Error("WORKER_COMMITTED_RECEIPT_MISSING");
    }
    const finalView = terminalReceipt.view;
    if (
      projection.head?.view.viewId !== finalView.viewId ||
      result.commitGate.finalView.viewId !== finalView.viewId ||
      finalView.generation !== agentAtStart.stateGeneration + 1
    ) {
      throw new Error("WORKER_COMMITTED_PROJECTION_MISMATCH");
    }
    const authoritativeSummary = {
      ...this.summaryFromWorkerProjection(run, projection, terminalReceipt, false),
      provider: result.commitGate.provider ?? run.provider,
    };
    maybeInjectApiProjectionFault({
      point: API_PROJECTION_FAULT_POINT,
      source: "live-finalize",
      agentId: agentAtStart.id,
      runId: run.id,
      decision: terminalReceipt.decision,
      viewId: finalView.viewId,
      generation: finalView.generation,
      projectionDigest: projection.digest,
    });
    const completedAt = now();
    const sanitizedOutput = this.redactAgentText(result.output, this.config.codexMaxOutputBytes);
    let stale = false;
    await this.store.mutate((database) => {
      const storedRun = database.runs.find((item) => item.id === run.id);
      const agent = database.agents.find((item) => item.id === agentAtStart.id);
      if (!storedRun || !agent) return;
      if (!this.leaseMatches(agent, storedRun, agentAtStart, run)) {
        stale = true;
        return;
      }
      this.applyWorkerHead(agent, projection);
      this.applyWorkerVersions(database, agent.id, projection);
      storedRun.status = "completed";
      storedRun.output = sanitizedOutput;
      storedRun.usage = result.usage;
      storedRun.commitGate = authoritativeSummary;
      storedRun.transactionStatus = "TERMINAL";
      storedRun.proposalId = authoritativeSummary.proposalId ?? null;
      storedRun.evaluationContextHash = authoritativeSummary.evaluationContextHash ?? null;
      storedRun.permitId = authoritativeSummary.permitId ?? null;
      storedRun.provider = authoritativeSummary.provider ?? storedRun.provider;
      storedRun.completedAt = completedAt;
      this.upsertAssistantMessage(database, {
        agentId: agent.id,
        runId: run.id,
        content: sanitizedOutput,
        authority: "AUTHORITATIVE",
        viewId: finalView.viewId,
        proposalId: authoritativeSummary.proposalId ?? null,
        createdAt: completedAt,
      });
      agent.status = "ready";
      agent.codexThreadId = result.threadId;
      agent.needsReconciliation = false;
      agent.activeRunLeaseId = null;
      agent.lastError = null;
      agent.updatedAt = completedAt;
    });
    if (stale) {
      await this.recordStaleCallback(
        agentAtStart.id,
        run.id,
        "worker-terminal-committed",
        run.runLeaseId,
        run.baseViewId,
        agentAtStart.sessionEpoch,
      );
    }
  }

  private async persistRejectedRun(
    agentAtStart: Agent,
    run: AgentRun,
    result: Awaited<ReturnType<AgentRunner["run"]>>,
  ): Promise<void> {
    if (this.commitGate?.mode === "worker") {
      await this.persistWorkerNonCommitRun(agentAtStart, run, {
        output: result.output,
        usage: result.usage,
        gate: result.commitGate ?? null,
        cancelled: false,
      });
      return;
    }
    const gate = result.commitGate;
    if (!gate) throw new Error("CommitGate result is missing");
    const completedAt = now();
    const sanitizedOutput = this.redactAgentText(result.output, this.config.codexMaxOutputBytes);
    let resetEpoch: number | null = null;
    let staleCallback = false;
    await this.store.mutate((database) => {
      const storedRun = database.runs.find((item) => item.id === run.id);
      const agent = database.agents.find((item) => item.id === agentAtStart.id);
      if (!storedRun || !agent) return;
      if (!this.leaseMatches(agent, storedRun, agentAtStart, run)) {
        staleCallback = true;
        return;
      }
      agent.sessionEpoch = Math.max(agent.sessionEpoch + 1, agentAtStart.sessionEpoch + 1);
      resetEpoch = agent.sessionEpoch;
      refreshAgentViewId(agent);
      gate.baseViewId = agentAtStart.currentViewId;
      gate.nextViewId = agent.currentViewId;
      gate.baseGeneration = agentAtStart.stateGeneration;
      gate.nextGeneration = agent.stateGeneration;
      storedRun.status = gate.decision === "ABORTED" ? "failed" : "completed";
      storedRun.output = sanitizedOutput;
      storedRun.error = gate.decision === "ABORTED" ? gate.failureClass : null;
      storedRun.usage = result.usage;
      storedRun.commitGate = gate;
      storedRun.transactionStatus = "PENDING_DISPOSITION";
      storedRun.proposalId = gate.proposalId ?? null;
      storedRun.evaluationContextHash = gate.evaluationContextHash ?? null;
      storedRun.permitId = gate.permitId ?? null;
      storedRun.provider = gate.provider ?? storedRun.provider;
      storedRun.completedAt = completedAt;
      this.upsertAssistantMessage(database, {
        agentId: agent.id,
        runId: run.id,
        content: sanitizedOutput,
        authority: "REJECTED",
        viewId: agent.currentViewId,
        proposalId: gate.proposalId ?? null,
        createdAt: completedAt,
      });
      agent.status = gate.decision === "ABORTED" ? "error" : "ready";
      agent.codexThreadId = null;
      agent.needsReconciliation = true;
      agent.activeRunLeaseId = null;
      agent.lastError = gate.decision === "ABORTED" ? gate.failureClass : null;
      agent.updatedAt = completedAt;
    });
    if (staleCallback) {
      await this.recordStaleCallback(
        agentAtStart.id,
        run.id,
        "terminal-rejected",
        run.runLeaseId,
        run.baseViewId,
        agentAtStart.sessionEpoch,
      );
      return;
    }
    if (resetEpoch !== null) await retireCodexSessionHome(this.config, agentAtStart.id, resetEpoch);
    const finalization = await this.commitGate?.runner.finalizeDisposition(
      agentAtStart.id,
      run.id,
      stateViewForAgent(this.getAgent(agentAtStart.id)),
    );
    if (finalization) {
      await this.store.mutate((database) => {
        const storedRun = database.runs.find((item) => item.id === run.id);
        if (!storedRun) return;
        storedRun.transactionStatus = "TERMINAL";
        storedRun.commitGate = {
          ...finalization.summary,
          provider: storedRun.provider,
        };
      });
    }
  }

  /**
   * Terminalize a Worker-owned negative decision before publishing it in the
   * product database.  The append-only authority is the fact source; DB,
   * message and session state are a replayable projection.  A process kill
   * after Worker terminalization but before the mutation below is repaired by
   * initializeWorkerAuthorityProjection on restart.
   */
  private async persistWorkerNonCommitRun(
    agentAtStart: Agent,
    run: AgentRun,
    input: {
      output: string | null;
      usage: AgentRun["usage"];
      gate: CommitGateSummary | null;
      cancelled: boolean;
      errorMessage?: string | null;
    },
  ): Promise<void> {
    if (this.commitGate?.mode !== "worker" || !input.gate) {
      throw new Error("WORKER_NON_COMMIT_RESULT_MISSING");
    }
    const before = this.store.snapshot();
    const beforeRun = before.runs.find((item) => item.id === run.id);
    const beforeAgent = before.agents.find((item) => item.id === agentAtStart.id);
    if (
      !beforeRun ||
      !beforeAgent ||
      !this.leaseMatches(beforeAgent, beforeRun, agentAtStart, run)
    ) {
      await this.recordStaleCallback(
        agentAtStart.id,
        run.id,
        "worker-non-commit-before-authority",
        run.runLeaseId,
        run.baseViewId,
        agentAtStart.sessionEpoch,
      );
      return;
    }

    // The Worker derives the final non-commit View from its current HEAD. The
    // legacy StateView argument is ignored by WorkerCommitGateRunner and is
    // retained only for the in-process runner interface.
    await this.commitGate.runner.finalizeDisposition(
      agentAtStart.id,
      run.id,
      stateViewForAgent(beforeAgent),
    );
    const projection = await this.commitGate.authority.getProjection(agentAtStart.id);
    const terminalReceipt = projection.terminalReceipts.find(
      (receipt) => receipt.receiptId === run.id && receipt.transitionId === run.id,
    );
    if (!terminalReceipt || terminalReceipt.decision !== input.gate.decision) {
      throw new Error("WORKER_NON_COMMIT_RECEIPT_MISMATCH");
    }
    const authoritativeSummary = {
      ...this.summaryFromWorkerProjection(run, projection, terminalReceipt, false),
      provider: input.gate.provider ?? run.provider,
    };
    maybeInjectApiProjectionFault({
      point: API_PROJECTION_FAULT_POINT,
      source: "live-finalize",
      agentId: agentAtStart.id,
      runId: run.id,
      decision: terminalReceipt.decision,
      viewId: terminalReceipt.view.viewId,
      generation: terminalReceipt.view.generation,
      projectionDigest: projection.digest,
    });

    const completedAt = now();
    const sanitizedOutput = input.output === null
      ? null
      : this.redactAgentText(input.output, this.config.codexMaxOutputBytes);
    let staleCallback = false;
    await this.store.mutate((database) => {
      const storedRun = database.runs.find((item) => item.id === run.id);
      const agent = database.agents.find((item) => item.id === agentAtStart.id);
      if (!storedRun || !agent) return;
      if (!this.leaseMatches(agent, storedRun, agentAtStart, run)) {
        staleCallback = true;
        return;
      }
      this.applyWorkerHead(agent, projection);
      this.applyWorkerVersions(database, agent.id, projection);
      const cancelled = input.cancelled || terminalReceipt.reasonCodes.some(
        (code) => code.startsWith("RUN_CANCELLED"),
      );
      storedRun.status = this.workerRunStatus(terminalReceipt.decision, cancelled);
      storedRun.output = sanitizedOutput;
      storedRun.error =
        terminalReceipt.decision === "ABORTED" && !cancelled
          ? input.errorMessage ?? authoritativeSummary.failureClass ?? "infra_errored"
          : null;
      storedRun.usage = input.usage;
      storedRun.commitGate = authoritativeSummary;
      storedRun.transactionStatus = "TERMINAL";
      storedRun.proposalId = authoritativeSummary.proposalId ?? null;
      storedRun.evaluationContextHash = authoritativeSummary.evaluationContextHash ?? null;
      storedRun.permitId = authoritativeSummary.permitId ?? null;
      storedRun.provider = authoritativeSummary.provider ?? storedRun.provider;
      storedRun.completedAt = completedAt;
      if (sanitizedOutput !== null) {
        this.upsertAssistantMessage(database, {
          agentId: agent.id,
          runId: run.id,
          content: sanitizedOutput,
          authority: "REJECTED",
          viewId: terminalReceipt.view.viewId,
          proposalId: authoritativeSummary.proposalId ?? null,
          createdAt: completedAt,
        });
      }
      if (agent.status !== "stopped") {
        agent.status = terminalReceipt.decision === "ABORTED" && !cancelled
          ? "error"
          : "ready";
      }
      agent.codexThreadId = null;
      agent.needsReconciliation = true;
      agent.activeRunLeaseId = null;
      agent.lastError =
        terminalReceipt.decision === "ABORTED" && !cancelled
          ? authoritativeSummary.failureClass ?? "infra_errored"
          : null;
      agent.updatedAt = completedAt;
    });
    if (staleCallback) {
      await this.recordStaleCallback(
        agentAtStart.id,
        run.id,
        "worker-non-commit-after-authority",
        run.runLeaseId,
        run.baseViewId,
        agentAtStart.sessionEpoch,
      );
      return;
    }
    await this.retireSessionFence(agentAtStart.id);
  }

  private async persistRunFailure(
    agentAtStart: Agent,
    run: AgentRun,
    error: unknown,
  ): Promise<void> {
    const completedAt = now();
    const cancelled = error instanceof RunCancelledError;
    const message = this.redactAgentText(
      error instanceof Error ? error.message : String(error),
      16_384,
    );
    let receipt: GateReceipt | null = null;
    let receiptReadError: unknown = null;
    try {
      receipt = this.commitGate?.mode === "worker"
        ? this.commitGate.runner.getReceipt(run.id)
        : this.commitGate
          ? await this.commitGate.receiptStore.get(agentAtStart.id, run.id)
          : null;
    } catch (readError) {
      receiptReadError = readError;
    }
    let recoveryPending = Boolean(
      error instanceof CommitGateRecoveryRequiredError ||
        (receipt?.decision === "COMMITTED" && receipt.promotionPendingDatabaseAck) ||
        (this.commitGate?.mode === "worker" && !receipt && !cancelled),
    );
    if (recoveryPending) this.recoveryReservations.add(agentAtStart.id);
    const summary = receipt ? this.summaryFromReceipt(receipt) : null;
    if (
      this.commitGate?.mode === "worker" &&
      receipt?.phase === "PENDING_DISPOSITION" &&
      summary &&
      !recoveryPending
    ) {
      try {
        await this.persistWorkerNonCommitRun(agentAtStart, run, {
          output: null,
          usage: null,
          gate: summary,
          cancelled,
          errorMessage: message,
        });
        return;
      } catch (finalizationError) {
        // Do not publish a local terminal/session View when the authority did
        // not confirm one. Startup recovery will terminalize and replay the
        // Worker fact; the product row remains explicitly pending.
        recoveryPending = true;
        this.recoveryReservations.add(agentAtStart.id);
        error = new AggregateError(
          [error, finalizationError],
          "Worker non-commit terminalization is pending recovery",
        );
      }
    }
    let resetEpoch: number | null = null;
    let staleCallback = false;
    await this.store.mutate((database) => {
      const storedRun = database.runs.find((item) => item.id === run.id);
      const agent = database.agents.find((item) => item.id === agentAtStart.id);
      if (storedRun && agent && !this.leaseMatches(agent, storedRun, agentAtStart, run)) {
        staleCallback = true;
        return;
      }
      if (storedRun) {
        storedRun.status = cancelled ? "cancelled" : "failed";
        storedRun.error = message;
        storedRun.commitGate = summary;
        storedRun.transactionStatus =
          receipt?.phase === "PENDING_DISPOSITION" ? "PENDING_DISPOSITION" : "TERMINAL";
        storedRun.proposalId = summary?.proposalId ?? null;
        storedRun.evaluationContextHash = summary?.evaluationContextHash ?? null;
        storedRun.permitId = summary?.permitId ?? null;
        storedRun.completedAt = completedAt;
      }
      if (agent) {
        if (agent.status !== "stopped") {
          agent.status = cancelled && !recoveryPending ? "ready" : "error";
        }
        if (this.commitGate) {
          agent.codexThreadId = null;
          if (!(this.commitGate.mode === "worker" && recoveryPending)) {
            agent.sessionEpoch = Math.max(
              agent.sessionEpoch + 1,
              receipt?.sessionEpoch ?? agentAtStart.sessionEpoch + 1,
            );
            resetEpoch = agent.sessionEpoch;
            refreshAgentViewId(agent);
          }
          agent.needsReconciliation = true;
        }
        agent.activeRunLeaseId = null;
        if (recoveryPending) {
          agent.recoveryRequired = true;
          const receiptDetail = receiptReadError
            ? "; receipt read failed: " +
              this.redactAgentText(
                receiptReadError instanceof Error
                  ? receiptReadError.message
                  : String(receiptReadError),
                2_048,
              )
            : "";
          agent.lastError = RECOVERY_REQUIRED_MESSAGE + ": " + message + receiptDetail;
        } else {
          agent.lastError = cancelled ? null : message;
        }
        agent.updatedAt = completedAt;
      }
    });
    if (staleCallback) {
      await this.recordStaleCallback(
        agentAtStart.id,
        run.id,
        "terminal-failure",
        run.runLeaseId,
        run.baseViewId,
        agentAtStart.sessionEpoch,
      );
      return;
    }
    if (resetEpoch !== null) await retireCodexSessionHome(this.config, agentAtStart.id, resetEpoch);
    if (
      this.commitGate &&
      receipt?.phase === "PENDING_DISPOSITION" &&
      !recoveryPending
    ) {
      const finalization = await this.commitGate.runner.finalizeDisposition(
        agentAtStart.id,
        run.id,
        stateViewForAgent(this.getAgent(agentAtStart.id)),
      );
      await this.store.mutate((database) => {
        const storedRun = database.runs.find((item) => item.id === run.id);
        if (!storedRun) return;
        storedRun.transactionStatus = "TERMINAL";
        storedRun.commitGate = {
          ...finalization.summary,
          provider: storedRun.provider,
        };
      });
    }
  }

  private async repairFailedAcknowledge(
    agentAtStart: Agent,
    run: AgentRun,
    error: unknown,
  ): Promise<void> {
    if (!this.commitGate || this.commitGate.mode === "worker") {
      throw new Error("IN_PROCESS_ACKNOWLEDGEMENT_REQUIRED");
    }
    this.recoveryReservations.add(agentAtStart.id);
    let receipt: GateReceipt | null = null;
    let receiptError: unknown = null;
    try {
      receipt = (await this.commitGate.receiptStore.get(agentAtStart.id, run.id)) ?? null;
    } catch (error) {
      receiptError = error;
    }
    let projection: VersionProjection | null = null;
    let projectionError: unknown = null;
    if (this.commitGate) {
      try {
        projection = await this.projectVersions(
          agentAtStart.id,
          receipt?.finalSnapshotHash,
        );
      } catch (error) {
        projectionError = error;
      }
    }
    const message =
      "CommitGate acknowledgement cleanup failed; startup recovery will retry: " +
      this.redactAgentText(
        [error, receiptError, projectionError]
          .filter(Boolean)
          .map((item) => (item instanceof Error ? item.message : String(item)))
          .join("; "),
        8_192,
      );
    let resetEpoch: number | null = null;
    await this.store.mutate((database) => {
      if (projection) this.applyVersionProjection(database, agentAtStart.id, projection);
      const storedRun = database.runs.find((item) => item.id === run.id);
      const agent = database.agents.find((item) => item.id === agentAtStart.id);
      if (storedRun) {
        storedRun.status = "failed";
        storedRun.error = message;
        storedRun.commitGate = receipt ? this.summaryFromReceipt(receipt) : storedRun.commitGate;
      }
      if (agent) {
        const alreadyLocked = agent.recoveryRequired;
        agent.status = "error";
        agent.recoveryRequired = true;
        agent.codexThreadId = null;
        if (!alreadyLocked) agent.sessionEpoch += 1;
        resetEpoch = agent.sessionEpoch;
        agent.needsReconciliation = true;
        agent.activeRunLeaseId = null;
        refreshAgentViewId(agent);
        agent.headVersionId = projection?.headVersionId ?? agent.headVersionId;
        agent.lastError = RECOVERY_REQUIRED_MESSAGE + ": " + message;
        agent.updatedAt = now();
      }
    });
    if (resetEpoch !== null) await retireCodexSessionHome(this.config, agentAtStart.id, resetEpoch);
  }

  private async markRecoveryRequired(agentId: string, error: unknown): Promise<void> {
    this.recoveryReservations.add(agentId);
    const detail = this.redactAgentText(
      error instanceof Error ? error.message : String(error),
      8_192,
    );
    let resetEpoch: number | null = null;
    await this.store.mutate((database) => {
      const agent = database.agents.find((item) => item.id === agentId);
      if (!agent) return;
      agent.status = "error";
      agent.recoveryRequired = true;
      agent.codexThreadId = null;
      agent.sessionEpoch += 1;
      resetEpoch = agent.sessionEpoch;
      agent.needsReconciliation = true;
      agent.activeRunLeaseId = null;
      refreshAgentViewId(agent);
      agent.lastError = RECOVERY_REQUIRED_MESSAGE + ": " + detail;
      agent.updatedAt = now();
    });
    if (resetEpoch !== null) await retireCodexSessionHome(this.config, agentId, resetEpoch);
  }

  private async releaseCommittedAgent(
    agentId: string,
    run: AgentRun,
    finalization: Awaited<ReturnType<CommitGateComponents["runner"]["acknowledge"]>>,
  ): Promise<void> {
    let stale = false;
    await this.store.mutate((database) => {
      const agent = database.agents.find((item) => item.id === agentId);
      const storedRun = database.runs.find((item) => item.id === run.id);
      if (!agent || !storedRun) return;
      if (
        agent.recoveryRequired ||
        agent.activeRunLeaseId !== run.runLeaseId ||
        storedRun.runLeaseId !== run.runLeaseId ||
        storedRun.baseViewId !== run.baseViewId
      ) {
        stale = true;
        return;
      }
      storedRun.commitGate = {
        ...finalization.summary,
        provider: storedRun.provider,
      };
      storedRun.status = "completed";
      storedRun.transactionStatus = "TERMINAL";
      agent.status = "ready";
      agent.activeRunLeaseId = null;
      agent.lastError = null;
      agent.updatedAt = now();
    });
    if (stale) {
      await this.recordStaleCallback(
        agentId,
        run.id,
        "commit-acknowledgement",
        run.runLeaseId,
        run.baseViewId,
        this.getAgent(agentId).sessionEpoch,
      );
    }
  }

  private async projectVersions(
    agentId: string,
    currentLiveHash?: string,
    pendingChanges?: { runId: string; changedPaths: string[] },
  ): Promise<VersionProjection> {
    if (!this.commitGate) return { versions: [], snapshots: [], headVersionId: null };
    if (this.commitGate.mode === "worker") {
      const projection = await this.commitGate.authority.getProjection(agentId);
      let parentVersionId: string | null = null;
      const versions = projection.versions.map((version, index): WorkspaceVersion => {
        const projected: WorkspaceVersion = {
          id: version.versionId,
          agentId,
          sequence: index + 1,
          parentVersionId,
          kind: version.kind,
          snapshotHash: version.workspaceHash,
          liveStateHash: version.workspaceHash,
          pathPolicyHash: "worker-authority",
          sourceRunId: version.kind === "INITIAL" ? null : version.transitionId,
          sourceReceiptId: version.receiptId,
          rollbackTargetVersionId: version.rollbackTargetVersionId,
          changedPaths: pendingChanges?.runId === version.transitionId
            ? pendingChanges.changedPaths
            : [],
          snapshotAvailable: true,
          generation: version.generation,
          viewId: version.viewId,
          transitionEventId: version.transitionId,
          createdAt: now(),
        };
        parentVersionId = version.versionId;
        return projected;
      });
      const snapshots = [...new Set(projection.versions.map((version) => version.snapshotId))]
        .map((hash): SnapshotMetadata => ({
          agentId,
          hash,
          sizeBytes: 0,
          state: "available",
          createdAt: now(),
        }));
      return { versions, snapshots, headVersionId: projection.head?.view.headVersionId ?? null };
    }
    const index = await this.commitGate.versionStore.getIndex(agentId);
    const policy = await this.commitGate.coordinator.policyForAgent(agentId);
    const current = this.store.snapshot();
    const existing = new Map(
      current.versions
        .filter((version) => version.agentId === agentId)
        .map((version) => [version.id, version]),
    );
    const receiptChanges = new Map(
      current.runs
        .filter((run) => run.agentId === agentId && run.commitGate)
        .map((run) => [run.id, run.commitGate?.changedPaths ?? []]),
    );
    if (pendingChanges) {
      receiptChanges.set(pendingChanges.runId, pendingChanges.changedPaths);
    }
    const versions = index.versions.map((version): WorkspaceVersion => ({
      id: version.id,
      agentId,
      sequence: version.sequence,
      parentVersionId: version.parentVersionId,
      kind: version.kind,
      snapshotHash: version.snapshotHash,
      liveStateHash:
        version.id === index.headVersionId && currentLiveHash
          ? currentLiveHash
          : existing.get(version.id)?.liveStateHash ?? version.snapshotHash,
      pathPolicyHash:
        version.policyHash ??
        existing.get(version.id)?.pathPolicyHash ??
        policyHash(policy),
      sourceRunId: version.runId,
      sourceReceiptId: version.kind === "ROLLBACK" ? null : version.runId,
      rollbackTargetVersionId: version.rollbackTargetVersionId,
      changedPaths:
        receiptChanges.get(version.runId ?? "") ?? existing.get(version.id)?.changedPaths ?? [],
      snapshotAvailable: version.snapshotAvailable,
      generation: existing.get(version.id)?.generation ?? version.sequence,
      viewId: existing.get(version.id)?.viewId ?? null,
      transitionEventId: existing.get(version.id)?.transitionEventId ?? null,
      createdAt: version.createdAt,
    }));
    const snapshots = index.snapshots.map((snapshot): SnapshotMetadata => ({
      agentId,
      hash: snapshot.hash,
      sizeBytes: snapshot.sizeBytes,
      state: snapshot.prunedAt ? "pruned" : "available",
      createdAt: snapshot.createdAt,
    }));
    return { versions, snapshots, headVersionId: index.headVersionId };
  }

  private applyVersionProjection(
    database: Database,
    agentId: string,
    projection: VersionProjection,
  ): void {
    database.versions = [
      ...database.versions.filter((version) => version.agentId !== agentId),
      ...projection.versions,
    ];
    database.snapshots = [
      ...database.snapshots.filter((snapshot) => snapshot.agentId !== agentId),
      ...projection.snapshots,
    ];
    const agent = database.agents.find((item) => item.id === agentId);
    if (agent) agent.headVersionId = projection.headVersionId;
  }

  private summaryFromReceipt(receipt: GateReceipt): CommitGateSummary {
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
      effectProof:
        receipt.effectProof ??
        deriveEffectDispositionProof({
          decision: receipt.decision,
          baseHash: receipt.baseSnapshotHash,
          candidateHash: receipt.candidateSnapshotHash,
          finalHash: receipt.finalSnapshotHash,
        }),
    };
  }

  private redactAgentText(value: string, maxBytes: number): string {
    return redactReceiptText(
      value,
      maxBytes,
      [this.config.modelApiKey, this.config.modelRuntimeApiKey, this.config.modelRelayToken].filter(
        (secret) => secret.length > 0,
      ),
    );
  }

  private async setStatus(id: string, status: Agent["status"]): Promise<Agent> {
    return this.store.mutate((database) => {
      const agent = database.agents.find((item) => item.id === id);
      if (!agent) throw new HttpError(404, "Agent not found");
      this.assertRecoveryReady(agent);
      if (status === "ready" && agent.status === "busy") {
        throw new HttpError(409, "Stop the active run before starting this Agent");
      }
      agent.status = status;
      if (status === "ready") agent.lastError = null;
      agent.updatedAt = now();
      return structuredClone(agent);
    });
  }

  private assertRecoveryReady(agent: Agent): void {
    if (!agent.recoveryRequired && !this.recoveryReservations.has(agent.id)) return;
    throw new HttpError(
      409,
      "Restart the server so CommitGate can finish journal recovery",
      "COMMITGATE_RECOVERY_REQUIRED",
    );
  }

  private assertNoActiveMutation(agentId: string): void {
    if (
      !this.activeExecutions.has(agentId) &&
      !this.activeRollbacks.has(agentId) &&
      !this.activeLifecycleMutations.has(agentId) &&
      !this.activeConfigurationMutations.has(agentId)
    ) {
      return;
    }
    throw new HttpError(409, "Agent is busy", "AGENT_BUSY");
  }

  private async awaitTerminalExecutionCleanup(agentId: string): Promise<void> {
    const execution = this.activeExecutions.get(agentId);
    if (!execution) return;
    const agent = this.store.snapshot().agents.find((item) => item.id === agentId);
    if (!agent || agent.status === "busy" || agent.activeRunLeaseId !== null) return;
    await execution.catch(() => undefined);
  }

  private leaseMatches(
    agent: Agent,
    storedRun: AgentRun,
    agentAtStart: Agent,
    requestedRun: AgentRun,
  ): boolean {
    return (
      agent.activeRunLeaseId === requestedRun.runLeaseId &&
      storedRun.runLeaseId === requestedRun.runLeaseId &&
      requestedRun.baseViewId === agentAtStart.currentViewId &&
      storedRun.baseViewId === agentAtStart.currentViewId &&
      agent.currentViewId === agentAtStart.currentViewId &&
      agent.sessionEpoch === agentAtStart.sessionEpoch
    );
  }

  private upsertAssistantMessage(
    database: Database,
    input: {
      agentId: string;
      runId: string;
      content: string;
      authority: Message["authority"];
      viewId: string | null;
      proposalId: string | null;
      createdAt: string;
    },
  ): void {
    const existing = database.messages.find(
      (message) => message.runId === input.runId && message.role === "assistant",
    );
    if (existing) {
      existing.content = input.content;
      existing.authority = input.authority;
      existing.viewId = input.viewId;
      existing.proposalId = input.proposalId;
      return;
    }
    database.messages.push({
      id: randomUUID(),
      agentId: input.agentId,
      runId: input.runId,
      role: "assistant",
      content: input.content,
      authority: input.authority,
      viewId: input.viewId,
      proposalId: input.proposalId,
      createdAt: input.createdAt,
    });
  }

  private async recordStaleCallback(
    agentId: string,
    runId: string,
    callbackKind: string,
    runLeaseId: string,
    baseViewId: string,
    sessionEpoch: number,
  ): Promise<void> {
    await this.transitionEvents.append({
      agentId,
      transitionId: runId,
      type: "STALE_CALLBACK_RECORDED",
      payload: {
        callbackKind,
        runLeaseId,
        baseViewId,
        sessionEpoch,
      },
    });
  }

  private async captureWorkspaceHashes(
    workspacePath: string,
    policy: Awaited<ReturnType<CommitGateComponents["coordinator"]["policyForAgent"]>>,
  ): Promise<{
    versionedHash: string;
    platformManagedHash: string;
    liveStateHash: string;
  }> {
    const [versioned, platformManaged, live] = await Promise.all([
      buildManifest(workspacePath, policy, { include: new Set(["versioned"]) }),
      buildManifest(workspacePath, policy, { include: new Set(["platformManaged"]) }),
      buildManifest(workspacePath, policy),
    ]);
    return {
      versionedHash: versioned.hash,
      platformManagedHash: platformManaged.hash,
      liveStateHash: live.hash,
    };
  }

  private async retireSessionFence(agentId: string): Promise<void> {
    const agent = this.store.snapshot().agents.find((item) => item.id === agentId);
    if (!agent) return;
    await retireCodexSessionHome(this.config, agent.id, agent.sessionEpoch);
  }

  private reserveLifecycleMutation(agentId: string): void {
    if (
      this.activeRollbacks.has(agentId) ||
      this.activeLifecycleMutations.has(agentId) ||
      this.activeConfigurationMutations.has(agentId)
    ) {
      throw new HttpError(409, "Agent is busy", "AGENT_BUSY");
    }
    // Set synchronously before the first await in stop/delete.  Every other
    // mutating entry point consults this reservation, closing the reverse
    // delete->rollback/send TOCTOU window while cancellation or archive I/O is
    // pending.
    this.activeLifecycleMutations.add(agentId);
  }

  private async cancelExecution(agentId: string): Promise<void> {
    this.cancellationRequests.add(agentId);
    try {
      const snapshot = this.store.snapshot();
      const agent = snapshot.agents.find((item) => item.id === agentId);
      const activeRun = snapshot.runs.find(
        (run) =>
          run.agentId === agentId &&
          (run.status === "queued" || run.status === "running"),
      );
      await this.runner.cancel(
        agentId,
        agent && activeRun
          ? {
              runId: activeRun.id,
              runLeaseId: activeRun.runLeaseId,
              sessionEpoch: agent.sessionEpoch,
            }
          : undefined,
      );
      const execution = this.activeExecutions.get(agentId);
      if (execution) await execution;
    } finally {
      this.cancellationRequests.delete(agentId);
    }
  }
}
