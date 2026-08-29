import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { AgentService } from "./agent-service.js";
import type { CommitGateRuntimeComponents } from "./commitgate-runtime.js";
import { loadConfig } from "./config.js";
import { JsonStore } from "./store.js";
import { makeTreeWritable } from "./transition-worker/filesystem.js";
import {
  TransitionWorker,
  type TransitionWorkerConfig,
} from "./transition-worker/worker.js";
import type { WorkerProjection } from "./transition-worker/projection.js";
import type { Agent, AgentRunner, Database, RunnerResult } from "./types.js";
import { WorkspaceManager } from "./workspace.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map(async (root) => {
    await makeTreeWritable(root).catch(() => undefined);
    await rm(root, { recursive: true, force: true });
  }));
});

class ReceiptProofRunner implements AgentRunner {
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

describe("AgentService Worker receipt proof access", () => {
  it("retrieves an Agent-owned rollback proof without requiring an AgentRun row", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "worker-rollback-proof-api-"));
    roots.push(root);
    const workerConfig: TransitionWorkerConfig = {
      workspaceRoot: path.join(root, "authority"),
      controlRoot: path.join(root, "control"),
      inboxRoot: path.join(root, "exchange"),
      socketPath: path.join(root, "run", "worker.sock"),
      sourceRevision: "a".repeat(40),
    };
    const worker = new TransitionWorker(workerConfig);
    await worker.initialize();
    const agentId = "11111111-1111-4111-8111-111111111111";
    const initialized = await worker.initializeAgent({
      agentId,
      operationId: "initialize-agent-proof",
      headVersionId: "initial-version",
      generation: 1,
      sessionEpoch: 0,
      agentConfigVersion: 1,
      policyVersion: 1,
      name: "Rollback proof",
      instructions: "# Trusted instructions\n",
    });
    const initialHead = initialized.head!;
    const receiptId = "rollback-22222222-2222-4222-8222-222222222222";
    await worker.prepare({
      agentId,
      transitionId: receiptId,
      kind: "ROLLBACK",
      expectedViewId: initialHead.view.viewId,
      expectedWorkspaceHash: initialHead.workspaceHash,
      baseGeneration: initialHead.view.generation,
    });
    const rolledBack = await worker.applyRollback({
      agentId,
      transitionId: receiptId,
      rollbackPermitId: "rollback-permit-proof",
      targetSnapshotId: initialHead.workspaceHash,
      targetVersionId: initialHead.view.headVersionId,
      expectedViewId: initialHead.view.viewId,
      expectedWorkspaceHash: initialHead.workspaceHash,
      versionId: "rollback-version-proof",
      receiptId,
    });
    const head = rolledBack.head!;
    expect(rolledBack.receiptProofs[receiptId]).toBeDefined();

    const timestamp = "2026-08-29T00:00:00.000Z";
    const agent: Agent = {
      id: agentId,
      name: "Rollback proof",
      description: "",
      instructions: "# Trusted instructions\n",
      status: "ready",
      workspacePath: `/logical/${agentId}`,
      workspaceRef: { authority: "transition-worker", agentId },
      codexThreadId: null,
      sessionEpoch: head.view.sessionEpoch,
      needsReconciliation: true,
      headVersionId: head.view.headVersionId,
      stateGeneration: head.view.generation,
      currentViewId: head.view.viewId,
      currentVersionedHash: head.view.versionedHash,
      currentPlatformManagedHash: head.view.platformManagedHash,
      currentLiveStateHash: head.view.liveStateHash,
      agentConfigVersion: head.view.agentConfigVersion,
      policyVersion: head.view.policyVersion,
      activeRunLeaseId: null,
      recoveryRequired: false,
      lastError: null,
      createdAt: timestamp,
      updatedAt: timestamp,
    };
    const database: Database = {
      version: 3,
      agents: [agent],
      runs: [],
      messages: [],
      versions: [],
      snapshots: [],
    };
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
      RUNTIME_BROKER_SOCKET: path.join(root, "run", "broker.sock"),
      MODEL_PROVIDER: "ark",
      MODEL_ID: "test-model",
      MODEL_API_KEY: "test-key",
    });
    const store = new JsonStore(path.join(config.dataDirectory, "db.json"));
    await store.initialize();
    await store.mutate((current) => Object.assign(current, structuredClone(database)));
    const authority = {
      initialize: async () => worker.health(),
      recover: async (requestedAgentId: string) => worker.recoverAgent(requestedAgentId),
      getProjection: async (requestedAgentId: string) => worker.projection(requestedAgentId),
      getReceiptProof: async (requestedAgentId: string, requestedReceiptId: string) =>
        worker.getReceiptProof(requestedAgentId, requestedReceiptId),
      adoptLegacyState: async () => {
        throw new Error("unexpected legacy adoption");
      },
    };
    const runner = new ReceiptProofRunner(
      (requestedAgentId) => worker.recoverAgent(requestedAgentId),
    );
    const commitGate = {
      mode: "worker",
      runner,
      authority,
    } as unknown as CommitGateRuntimeComponents;
    const service = new AgentService(
      config,
      store,
      new WorkspaceManager(config.workspaceRoot),
      runner,
      commitGate,
    );
    await service.initialize();

    await expect(service.getCommitGateProof(receiptId)).rejects.toMatchObject({
      statusCode: 404,
    });
    const proof = await service.getCommitGateProofByReceipt(agentId, receiptId);
    expect(proof).toMatchObject({
      schemaVersion: 3,
      receipt: {
        receiptId,
        agentId,
        transitionId: receiptId,
        decision: "COMMITTED",
        finalViewId: head.view.viewId,
        nextGeneration: head.view.generation,
        permitState: "CONSUMED",
      },
      proof: {
        signingKeyId: worker.health().signingKeyId,
        signatureAlgorithm: "Ed25519",
      },
      terminalEvent: {
        eventId: rolledBack.receiptProofs[receiptId]!.terminalEventId,
        transitionId: receiptId,
        type: "TRANSITION_ACKNOWLEDGED",
      },
    });
    await expect(
      service.getCommitGateProofByReceipt(
        "33333333-3333-4333-8333-333333333333",
        receiptId,
      ),
    ).rejects.toMatchObject({ statusCode: 404 });
  });
});
