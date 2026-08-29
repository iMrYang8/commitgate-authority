import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { AgentService } from "./agent-service.js";
import type { CommitGateRuntimeComponents } from "./commitgate-runtime.js";
import { loadConfig } from "./config.js";
import { JsonStore } from "./store.js";
import type { TransitionAuthorityClient } from "./transition-authority-client.js";
import type { WorkerProjection } from "./transition-worker/projection.js";
import { TransitionWorker, type TransitionWorkerConfig } from "./transition-worker/worker.js";
import { makeTreeWritable } from "./transition-worker/filesystem.js";
import type { AgentRunner, RunnerResult } from "./types.js";
import { WorkspaceManager } from "./workspace.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map(async (root) => {
      await makeTreeWritable(root).catch(() => undefined);
      await rm(root, { recursive: true, force: true });
    }),
  );
});

class RecoveryOnlyRunner implements AgentRunner {
  constructor(
    private readonly recover: (agentId: string) => Promise<WorkerProjection>,
  ) {}

  async run(): Promise<RunnerResult> {
    throw new Error("startup recovery must not execute the Agent");
  }

  async cancel(): Promise<boolean> {
    return false;
  }

  async isAvailable(): Promise<boolean> {
    return true;
  }

  getReceipt(): null {
    return null;
  }

  recoverAuthority(agentId: string): Promise<WorkerProjection> {
    return this.recover(agentId);
  }
}

function directAuthority(worker: TransitionWorker): TransitionAuthorityClient {
  return {
    mode: "worker",
    initialize: async () => ({ ...worker.health(), authority: "transition-worker" }),
    initializeAgent: (input) => worker.initializeAgent(input),
    adoptLegacyState: (input) => worker.adoptLegacyState(input),
    prepareRun: (input) => worker.prepareRun(input),
    recordRuntimeTeardown: (input) => worker.recordRuntimeTeardown(input),
    cancelRun: (input) => worker.cancelRun(input),
    prepare: (input) => worker.prepare(input),
    sealProposal: (input) => worker.sealProposal(input),
    exportProposal: (input) => worker.exportProposal(input),
    recordEvidence: (input) => worker.recordEvidence(input),
    issuePermit: (input) => worker.issuePermit(input),
    attemptPermitConsumption: (input) => worker.attemptPermitConsumption(input),
    applyPromotion: (input) => worker.applyPromotion(input),
    applyRollback: (input) => worker.applyRollback(input),
    disposeRun: (input) => worker.disposeRun(input),
    regeneratePlatformState: (input) => worker.regeneratePlatformState(input),
    archiveAgent: (input) => worker.archiveAgent(input),
    getProjection: (agentId) => worker.projection(agentId),
    getReceiptProof: (agentId, receiptId) => worker.getReceiptProof(agentId, receiptId),
    recover: (agentId) => worker.recoverAgent(agentId),
  };
}

async function fixture() {
  const root = await mkdtemp(path.join(tmpdir(), "worker-admission-recovery-"));
  roots.push(root);
  const workerConfig: TransitionWorkerConfig = {
    workspaceRoot: path.join(root, "authority"),
    controlRoot: path.join(root, "control"),
    inboxRoot: path.join(root, "exchange"),
    socketPath: path.join(root, "run", "worker.sock"),
  };
  const worker = new TransitionWorker(workerConfig);
  await worker.initialize();
  const config = loadConfig({
    NODE_ENV: "test",
    APP_DATA_DIR: path.join(root, "data"),
    AGENT_WORKSPACE_ROOT: path.join(root, "logical-workspaces"),
    CODEX_HOME: path.join(root, "codex-home"),
    COMMITGATE_ENABLED: "true",
    TRANSITION_AUTHORITY: "worker",
    TRANSITION_WORKER_SOCKET: workerConfig.socketPath,
    COMMITGATE_EXCHANGE_ROOT: workerConfig.inboxRoot,
    RUNTIME_PROVIDER: "broker",
    RUNTIME_BROKER_SOCKET: path.join(root, "broker.sock"),
    MODEL_PROVIDER: "ark",
    MODEL_ID: "test-model",
    MODEL_API_KEY: "test-key",
  });
  const store = new JsonStore(path.join(config.dataDirectory, "db.json"));
  const runner = new RecoveryOnlyRunner((agentId) => worker.recoverAgent(agentId));
  const authority = directAuthority(worker);
  const createService = () => new AgentService(
    config,
    store,
    new WorkspaceManager(config.workspaceRoot),
    runner,
    { mode: "worker", runner, authority } as unknown as CommitGateRuntimeComponents,
  );
  const seed = createService();
  await seed.initialize();
  const agent = await seed.createAgent({
    name: "Admission recovery",
    description: "",
    instructions: "Keep the workspace consistent.",
  });
  return { worker, store, createService, agent };
}

describe("AgentService Worker admission recovery", () => {
  it("terminalizes the DB-admitted/Worker-unprepared run through Worker cancellation", async () => {
    const { worker, store, createService, agent } = await fixture();
    const createdAt = "2026-08-29T00:00:00.000Z";
    const runId = "run-before-worker-prepare";
    const runLeaseId = "lease-before-worker-prepare";
    await store.mutate((database) => {
      database.runs.push({
        id: runId,
        agentId: agent.id,
        status: "queued",
        prompt: "change README",
        output: null,
        error: null,
        usage: null,
        commitGate: null,
        legacyReceipt: null,
        transactionStatus: "PREPARING",
        runLeaseId,
        submittedViewId: agent.currentViewId,
        baseViewId: agent.currentViewId,
        proposalId: null,
        evaluationContextHash: null,
        permitId: null,
        retryOfRunId: null,
        staleCallback: false,
        provider: null,
        startedAt: null,
        completedAt: null,
        createdAt,
      });
      database.messages.push({
        id: "input-before-worker-prepare",
        agentId: agent.id,
        runId,
        role: "user",
        content: "change README",
        authority: "INPUT",
        viewId: agent.currentViewId,
        proposalId: null,
        createdAt,
      });
      const stored = database.agents.find((candidate) => candidate.id === agent.id)!;
      stored.status = "busy";
      stored.activeRunLeaseId = runLeaseId;
      stored.codexThreadId = "thread-before-crash";
    });
    const beforeRecovery = await worker.projection(agent.id);
    expect(beforeRecovery.transitions[runId]).toBeUndefined();
    expect(store.snapshot().agents[0]).toMatchObject({
      activeRunLeaseId: runLeaseId,
      currentViewId: beforeRecovery.head!.view.viewId,
      currentLiveStateHash: beforeRecovery.head!.workspaceHash,
    });
    expect(store.snapshot().runs[0]).toMatchObject({
      runLeaseId,
      baseViewId: beforeRecovery.head!.view.viewId,
    });

    const recovered = createService();
    await recovered.initialize();

    const projection = await worker.projection(agent.id);
    expect(projection.transitions[runId]).toMatchObject({
      runId,
      runLeaseId,
      state: "ROLLED_BACK",
      artifactsDestroyed: true,
    });
    expect(projection.terminalReceipts).toContainEqual(expect.objectContaining({
      receiptId: runId,
      transitionId: runId,
      decision: "ABORTED",
      reasonCodes: ["RUN_CANCELLED_RECOVERED"],
    }));
    expect(recovered.getRun(runId)).toMatchObject({
      status: "cancelled",
      transactionStatus: "TERMINAL",
      error: null,
      commitGate: {
        decision: "ABORTED",
        threadDisposition: "reset",
        effectProof: {
          invariant: "NO_PERSISTENT_EFFECT",
          invariantSatisfied: true,
        },
      },
    });
    expect(recovered.getAgent(agent.id)).toMatchObject({
      status: "ready",
      activeRunLeaseId: null,
      codexThreadId: null,
      needsReconciliation: true,
      stateGeneration: agent.stateGeneration,
      sessionEpoch: agent.sessionEpoch + 1,
    });
    const once = store.snapshot();
    const restartedAgain = createService();
    await restartedAgain.initialize();
    expect(store.snapshot()).toEqual(once);
  });

  it("releases a rollback busy marker when the API died before Worker prepare", async () => {
    const { worker, store, createService, agent } = await fixture();
    await store.mutate((database) => {
      const stored = database.agents.find((candidate) => candidate.id === agent.id)!;
      // performRollback writes this marker before its first Worker RPC. There
      // is intentionally no AgentRun or transition to project in this window.
      stored.status = "busy";
      stored.activeRunLeaseId = null;
      stored.codexThreadId = "existing-thread";
    });
    const before = await worker.projection(agent.id);

    const recovered = createService();
    await recovered.initialize();

    expect(recovered.getAgent(agent.id)).toMatchObject({
      status: "ready",
      activeRunLeaseId: null,
      codexThreadId: "existing-thread",
      needsReconciliation: false,
      currentViewId: before.head!.view.viewId,
      stateGeneration: before.head!.view.generation,
      sessionEpoch: before.head!.view.sessionEpoch,
    });
    expect((await worker.projection(agent.id)).digest).toBe(before.digest);
  });

  it("projects a Worker-prepared rollback abort and releases the DB busy marker", async () => {
    const { worker, store, createService, agent } = await fixture();
    const transitionId = "rollback-after-worker-prepare";
    await worker.prepare({
      agentId: agent.id,
      transitionId,
      kind: "ROLLBACK",
      expectedViewId: agent.currentViewId,
      expectedWorkspaceHash: agent.currentLiveStateHash,
      baseGeneration: agent.stateGeneration,
    });
    await store.mutate((database) => {
      const stored = database.agents.find((candidate) => candidate.id === agent.id)!;
      stored.status = "busy";
      stored.activeRunLeaseId = null;
      stored.codexThreadId = "thread-before-rollback-crash";
    });

    const recovered = createService();
    await recovered.initialize();

    const projection = await worker.projection(agent.id);
    expect(projection.transitions[transitionId]).toMatchObject({
      kind: "ROLLBACK",
      state: "ROLLED_BACK",
      artifactsDestroyed: true,
    });
    expect(projection.terminalReceipts).toContainEqual(expect.objectContaining({
      transitionId,
      decision: "ABORTED",
      reasonCodes: ["INCOMPLETE_PREPARED_RECOVERED"],
    }));
    expect(recovered.getAgent(agent.id)).toMatchObject({
      status: "ready",
      activeRunLeaseId: null,
      codexThreadId: null,
      needsReconciliation: true,
      currentViewId: projection.head!.view.viewId,
      stateGeneration: agent.stateGeneration,
      sessionEpoch: agent.sessionEpoch + 1,
    });
  });
});
