import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { AgentService } from "./agent-service.js";
import type { CommitGateRuntimeComponents } from "./commitgate-runtime.js";
import { loadConfig } from "./config.js";
import { makeStateView } from "./state-view.js";
import { JsonStore } from "./store.js";
import { TransitionEventLog } from "./transition-log.js";
import type { WorkerProjection } from "./transition-worker/projection.js";
import type {
  Agent,
  AgentRun,
  AgentRunner,
  Database,
  RunnerResult,
} from "./types.js";
import { WorkspaceManager } from "./workspace.js";

const roots: string[] = [];
const createdAt = "2026-08-29T00:00:00.000Z";
const baseHash = "a".repeat(64);
const artifactHash = "b".repeat(64);

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

class ProjectionRunner implements AgentRunner {
  constructor(
    private readonly recover: (agentId: string) => Promise<WorkerProjection>,
  ) {}

  async run(): Promise<RunnerResult> {
    throw new Error("not used");
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

function fixtureState(decision: "COMMITTED" | "ABORTED") {
  const agentId = `agent-${decision.toLowerCase()}`;
  const runId = `run-${decision.toLowerCase()}`;
  const runLeaseId = `lease-${decision.toLowerCase()}`;
  const initialView = makeStateView({
    agentId,
    headVersionId: "version-initial",
    generation: 1,
    versionedHash: baseHash,
    platformManagedHash: baseHash,
    liveStateHash: baseHash,
    sessionEpoch: 0,
    agentConfigVersion: 1,
    policyVersion: 1,
  });
  const finalView = decision === "COMMITTED"
    ? makeStateView({
        agentId,
        headVersionId: "version-commit",
        generation: 2,
        versionedHash: artifactHash,
        platformManagedHash: artifactHash,
        liveStateHash: artifactHash,
        sessionEpoch: 0,
        agentConfigVersion: 1,
        policyVersion: 1,
      })
    : makeStateView({
        agentId,
        headVersionId: "version-initial",
        generation: 1,
        versionedHash: baseHash,
        platformManagedHash: baseHash,
        liveStateHash: baseHash,
        sessionEpoch: 1,
        agentConfigVersion: 1,
        policyVersion: 1,
      });
  const agent: Agent = {
    id: agentId,
    name: "Projection gap",
    description: "",
    instructions: "",
    status: "busy",
    workspacePath: `/logical/${agentId}`,
    workspaceRef: { authority: "transition-worker", agentId },
    codexThreadId: "pre-crash-thread",
    sessionEpoch: initialView.sessionEpoch,
    needsReconciliation: false,
    headVersionId: initialView.headVersionId,
    stateGeneration: initialView.generation,
    currentViewId: initialView.viewId,
    currentVersionedHash: initialView.versionedHash,
    currentPlatformManagedHash: initialView.platformManagedHash,
    currentLiveStateHash: initialView.liveStateHash,
    agentConfigVersion: initialView.agentConfigVersion,
    policyVersion: initialView.policyVersion,
    activeRunLeaseId: runLeaseId,
    recoveryRequired: false,
    lastError: null,
    createdAt,
    updatedAt: createdAt,
  };
  const run: AgentRun = {
    id: runId,
    agentId,
    status: "running",
    prompt: "change the workspace",
    output: null,
    error: null,
    usage: null,
    commitGate: null,
    legacyReceipt: null,
    transactionStatus: "EXECUTING",
    runLeaseId,
    submittedViewId: initialView.viewId,
    baseViewId: initialView.viewId,
    proposalId: null,
    evaluationContextHash: null,
    permitId: null,
    retryOfRunId: null,
    staleCallback: false,
    provider: null,
    startedAt: createdAt,
    completedAt: null,
    createdAt,
  };
  const proposalId = `proposal-${runId}`;
  const permitId = `permit-${runId}`;
  const projection: WorkerProjection = {
    schemaVersion: 2,
    agentId,
    head: {
      view: finalView,
      workspaceHash: finalView.liveStateHash,
      lastAppliedEventId: `terminal-${runId}`,
      lastAppliedSequence: decision === "COMMITTED" ? 7 : 4,
    },
    proposals: decision === "COMMITTED"
      ? {
          [proposalId]: {
            proposalId,
            transitionId: runId,
            baseViewId: initialView.viewId,
            artifactHash,
            manifestHash: artifactHash,
            changedPathsDigest: "changed-paths",
            runtimeTeardownDigest: "teardown",
            verifierInputHash: artifactHash,
            changedPaths: ["feature.ts"],
            staticFailures: [],
          },
        }
      : {},
    evidence: decision === "COMMITTED"
      ? {
          [proposalId]: {
            proposalId,
            transitionId: runId,
            evaluationContextHash: "evaluation-context",
            evidenceDigest: "evidence-digest",
            verifierInputHash: artifactHash,
            checkResultsHash: "check-results",
            coverage: "complete",
            requiredChecksPassed: true,
            checks: [{
              id: "workspace-sanity",
              status: "PASS",
              exitCode: 0,
              durationMs: 1,
              outputHash: "output-hash",
              timedOut: false,
            }],
            sourceRevision: "source-revision",
            policyHash: "policy-hash",
          },
        }
      : {},
    permits: decision === "COMMITTED"
      ? {
          [permitId]: {
            permitId,
            transitionId: runId,
            proposalId,
            baseViewId: initialView.viewId,
            targetArtifactHash: artifactHash,
            evaluationContextHash: "evaluation-context",
            evidenceDigest: "evidence-digest",
            expiresAt: "2099-01-01T00:00:00.000Z",
            state: "CONSUMED",
          },
        }
      : {},
    transitions: {
      [runId]: {
        transitionId: runId,
        kind: "AGENT_COMMIT",
        state: decision === "COMMITTED" ? "ACKNOWLEDGED" : "ROLLED_BACK",
        runId,
        runLeaseId,
        baseViewId: initialView.viewId,
        baseWorkspaceHash: baseHash,
        baseGeneration: 1,
        appliedView: decision === "COMMITTED" ? finalView : null,
        appliedWorkspaceHash: decision === "COMMITTED" ? artifactHash : null,
        proposalId: decision === "COMMITTED" ? proposalId : null,
        permitId: decision === "COMMITTED" ? permitId : null,
        artifactsDestroyed: true,
      },
    },
    versions: [
      {
        versionId: "version-initial",
        transitionId: "initialize",
        kind: "INITIAL",
        viewId: initialView.viewId,
        generation: 1,
        workspaceHash: baseHash,
        snapshotId: baseHash,
        receiptId: null,
        rollbackTargetVersionId: null,
      },
      ...(decision === "COMMITTED"
        ? [{
            versionId: "version-commit",
            transitionId: runId,
            kind: "AGENT_COMMIT" as const,
            viewId: finalView.viewId,
            generation: 2,
            workspaceHash: artifactHash,
            snapshotId: artifactHash,
            receiptId: runId,
            rollbackTargetVersionId: null,
          }]
        : []),
    ],
    terminalReceipts: [{
      receiptId: runId,
      transitionId: runId,
      decision,
      viewId: finalView.viewId,
      eventId: `terminal-${runId}`,
      sequence: decision === "COMMITTED" ? 7 : 4,
      view: finalView,
      workspaceHash: finalView.liveStateHash,
      reasonCodes: decision === "ABORTED" ? ["RUN_CANCELLED_RECOVERED"] : [],
    }],
    receiptProofs: {},
    archived: false,
    lastEventId: `terminal-${runId}`,
    lastSequence: decision === "COMMITTED" ? 7 : 4,
    digest: `projection-${decision}`,
  };
  const database: Database = {
    version: 3,
    agents: [agent],
    runs: [run],
    messages: [
      {
        id: `input-${runId}`,
        agentId,
        runId,
        role: "user",
        content: run.prompt,
        authority: "INPUT",
        viewId: initialView.viewId,
        proposalId: null,
        createdAt,
      },
      {
        id: `assistant-${runId}`,
        agentId,
        runId,
        role: "assistant",
        content: "provisional output",
        authority: "PROVISIONAL",
        viewId: initialView.viewId,
        proposalId: decision === "COMMITTED" ? proposalId : null,
        createdAt,
      },
    ],
    versions: [{
      id: "version-initial",
      agentId,
      sequence: 1,
      parentVersionId: null,
      kind: "INITIAL",
      snapshotHash: baseHash,
      liveStateHash: baseHash,
      pathPolicyHash: "worker-authority",
      sourceRunId: null,
      sourceReceiptId: null,
      rollbackTargetVersionId: null,
      changedPaths: [],
      snapshotAvailable: true,
      generation: 1,
      viewId: initialView.viewId,
      transitionEventId: "initialize",
      createdAt,
    }],
    snapshots: [{
      agentId,
      hash: baseHash,
      sizeBytes: 0,
      state: "available",
      createdAt,
    }],
  };
  return { agent, run, projection, database, initialView, finalView };
}

async function makeService(
  state: ReturnType<typeof fixtureState>,
  existingRoot?: string,
) {
  const root = existingRoot ?? await mkdtemp(path.join(tmpdir(), "worker-api-projection-"));
  if (!existingRoot) roots.push(root);
  const config = loadConfig({
    NODE_ENV: "test",
    APP_DATA_DIR: path.join(root, "data"),
    AGENT_WORKSPACE_ROOT: path.join(root, "logical-workspaces"),
    CODEX_HOME: path.join(root, "codex-home"),
    COMMITGATE_ENABLED: "true",
    TRANSITION_AUTHORITY: "worker",
    TRANSITION_WORKER_SOCKET: path.join(root, "worker.sock"),
    COMMITGATE_EXCHANGE_ROOT: path.join(root, "exchange"),
    RUNTIME_PROVIDER: "broker",
    RUNTIME_BROKER_SOCKET: path.join(root, "broker.sock"),
    MODEL_PROVIDER: "ark",
    MODEL_ID: "test-model",
    MODEL_API_KEY: "test-key",
  });
  const filePath = path.join(config.dataDirectory, "db.json");
  if (!existingRoot) {
    const seed = new JsonStore(filePath);
    await seed.initialize();
    await seed.mutate((database) => Object.assign(database, structuredClone(state.database)));
  }
  const authority = {
    initialize: async () => ({
      status: "ok",
      mode: "authority-v2",
      protocolVersion: 2,
      processUid: 10001,
      manifestSchemaVersion: 2,
      filesystemProfile: "linux-strong",
      signingKeyId: "0123456789abcdef01234567",
      authority: "transition-worker",
    }),
    recover: async () => structuredClone(state.projection),
    adoptLegacyState: async () => {
      throw new Error("unexpected legacy adoption");
    },
    getProjection: async () => structuredClone(state.projection),
  };
  const workerRunner = new ProjectionRunner(
    async () => structuredClone(state.projection),
  );
  const commitGate = {
    mode: "worker",
    runner: workerRunner,
    authority,
  } as unknown as CommitGateRuntimeComponents;
  const store = new JsonStore(filePath);
  const service = new AgentService(
    config,
    store,
    new WorkspaceManager(config.workspaceRoot),
    workerRunner,
    commitGate,
  );
  await service.initialize();
  return { root, config, store, service };
}

describe("AgentService Worker authority projection recovery", () => {
  it("projects a durable COMMITTED receipt after the API dies before DB projection", async () => {
    const state = fixtureState("COMMITTED");
    const first = await makeService(state);

    await expect(first.service.systemInfo()).resolves.toMatchObject({
      authorityReceiptSigningKeyId: "0123456789abcdef01234567",
    });

    expect(first.service.getAgent(state.agent.id)).toMatchObject({
      status: "ready",
      activeRunLeaseId: null,
      stateGeneration: 2,
      headVersionId: "version-commit",
      currentViewId: state.finalView.viewId,
      codexThreadId: null,
      needsReconciliation: true,
    });
    expect(first.service.getRun(state.run.id)).toMatchObject({
      status: "completed",
      transactionStatus: "TERMINAL",
      output: "provisional output",
      commitGate: {
        decision: "COMMITTED",
        baseGeneration: 1,
        nextGeneration: 2,
        baseViewId: state.initialView.viewId,
        nextViewId: state.finalView.viewId,
        threadDisposition: "reset",
        candidateCleanup: "deleted",
        artifactRetention: "version_snapshot",
      },
    });
    expect(first.service.getMessages(state.agent.id).at(-1)).toMatchObject({
      authority: "AUTHORITATIVE",
      viewId: state.finalView.viewId,
      proposalId: `proposal-${state.run.id}`,
    });
    expect(first.service.getVersions(state.agent.id)).toHaveLength(2);

    const afterFirstStart = first.store.snapshot();
    const second = await makeService(state, first.root);
    expect(second.store.snapshot()).toEqual(afterFirstStart);
  });

  it("projects durable cancellation recovery as ABORTED/cancelled without advancing generation", async () => {
    const state = fixtureState("ABORTED");
    const first = await makeService(state);

    expect(first.service.getAgent(state.agent.id)).toMatchObject({
      status: "ready",
      activeRunLeaseId: null,
      stateGeneration: 1,
      sessionEpoch: 1,
      currentViewId: state.finalView.viewId,
      codexThreadId: null,
      needsReconciliation: true,
      lastError: null,
    });
    expect(first.service.getRun(state.run.id)).toMatchObject({
      status: "cancelled",
      transactionStatus: "TERMINAL",
      error: null,
      commitGate: {
        decision: "ABORTED",
        baseGeneration: 1,
        nextGeneration: 1,
        finalHash: baseHash,
        threadDisposition: "reset",
        candidateCleanup: "deleted",
        artifactRetention: "destroyed",
      },
    });
    expect(first.service.getMessages(state.agent.id).at(-1)).toMatchObject({
      authority: "REJECTED",
      viewId: state.finalView.viewId,
    });
    expect(first.service.getVersions(state.agent.id)).toHaveLength(1);
    expect((await first.service.getCommitGateReceipt(state.run.id)).reasonCodes).toEqual([
      "RUN_CANCELLED_RECOVERED",
    ]);

    const afterFirstStart = first.store.snapshot();
    const second = await makeService(state, first.root);
    expect(second.store.snapshot()).toEqual(afterFirstStart);
  });

  it("does not manufacture cleanup success from a terminal ACK without RUN_ARTIFACTS_DESTROYED", async () => {
    const state = fixtureState("COMMITTED");
    state.projection.transitions[state.run.id]!.artifactsDestroyed = false;
    const fixture = await makeService(state);

    expect(fixture.service.getRun(state.run.id).commitGate).toMatchObject({
      decision: "COMMITTED",
      candidateCleanup: "deferred",
      artifactRetention: "deferred",
    });
    await expect(fixture.service.getCommitGateReceipt(state.run.id)).resolves.toMatchObject({
      decision: "COMMITTED",
      candidateCleanup: "deferred",
      artifactRetention: "deferred",
    });
  });

  it("fences a late committed callback after recovery and preserves a replacement lease", async () => {
    const state = fixtureState("COMMITTED");
    const fixture = await makeService(state);
    const recoveredRun = fixture.service.getRun(state.run.id);
    await fixture.store.mutate((database) => {
      const agent = database.agents.find((item) => item.id === state.agent.id)!;
      agent.status = "busy";
      agent.activeRunLeaseId = "replacement-lease";
      agent.codexThreadId = "replacement-thread";
    });
    const before = fixture.store.snapshot();
    const internal = fixture.service as unknown as {
      persistWorkerCommittedRun(
        agentAtStart: Agent,
        run: AgentRun,
        result: RunnerResult,
      ): Promise<void>;
    };
    await internal.persistWorkerCommittedRun(state.agent, state.run, {
      output: "late callback output",
      threadId: "late-thread",
      usage: null,
      commitGate: recoveredRun.commitGate!,
    });

    expect(fixture.service.getAgent(state.agent.id)).toMatchObject({
      status: "busy",
      activeRunLeaseId: "replacement-lease",
      codexThreadId: "replacement-thread",
      currentViewId: before.agents[0]!.currentViewId,
      stateGeneration: before.agents[0]!.stateGeneration,
    });
    expect(fixture.service.getRun(state.run.id)).toEqual(before.runs[0]);
    expect(fixture.service.getMessages(state.agent.id)).toEqual(before.messages);
    expect(
      await new TransitionEventLog(
        path.join(fixture.config.dataDirectory, "transition-events"),
      ).transition(state.agent.id, state.run.id),
    ).toEqual([
      expect.objectContaining({
        type: "STALE_CALLBACK_RECORDED",
        payload: expect.objectContaining({ callbackKind: "worker-terminal-committed" }),
      }),
    ]);
  });

  it("uses the same Worker terminal facts on the normal committed finalize path", async () => {
    const state = fixtureState("COMMITTED");
    const fixture = await makeService(state);
    const authoritativeSummary = fixture.service.getRun(state.run.id).commitGate!;
    // Recreate the API-side state immediately before its normal terminal DB
    // mutation while leaving the Worker projection durably COMMITTED.
    await fixture.store.mutate((database) => {
      Object.assign(database, structuredClone(state.database));
    });
    const internal = fixture.service as unknown as {
      persistWorkerCommittedRun(
        agentAtStart: Agent,
        run: AgentRun,
        result: RunnerResult,
      ): Promise<void>;
    };
    await internal.persistWorkerCommittedRun(state.agent, state.run, {
      output: "normal callback output",
      threadId: "committed-thread",
      usage: { inputTokens: 2, outputTokens: 3 },
      commitGate: authoritativeSummary,
    });

    expect(fixture.service.getRun(state.run.id)).toMatchObject({
      status: "completed",
      transactionStatus: "TERMINAL",
      output: "normal callback output",
      commitGate: {
        decision: "COMMITTED",
        baseGeneration: 1,
        nextGeneration: 2,
        nextViewId: state.finalView.viewId,
        effectProof: { invariantSatisfied: true },
      },
    });
    expect(fixture.service.getAgent(state.agent.id)).toMatchObject({
      status: "ready",
      activeRunLeaseId: null,
      stateGeneration: 2,
      currentViewId: state.finalView.viewId,
      codexThreadId: "committed-thread",
      needsReconciliation: false,
    });
    expect(fixture.service.getMessages(state.agent.id).at(-1)).toMatchObject({
      content: "normal callback output",
      authority: "AUTHORITATIVE",
      viewId: state.finalView.viewId,
    });
  });
});
