import { rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { mkdtemp } from "node:fs/promises";
import { afterEach, describe, expect, it } from "vitest";
import { makeStateView } from "./state-view.js";
import type { TransitionAuthorityClient } from "./transition-authority-client.js";
import { TransitionWorker, type TransitionWorkerConfig } from "./transition-worker/worker.js";
import { makeTreeWritable } from "./transition-worker/filesystem.js";
import type { AgentRunner, RunnerRequest } from "./types.js";
import { WorkerCommitGateRunner } from "./worker-commitgate-runner.js";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map(async (root) => {
    await makeTreeWritable(root).catch(() => undefined);
    await rm(root, { recursive: true, force: true });
  }));
});

async function fixture(mode: "commit" | "protected" | "verifier-error") {
  const root = await mkdtemp(path.join(tmpdir(), "commitgate-worker-runner-"));
  roots.push(root);
  const config: TransitionWorkerConfig = {
    workspaceRoot: path.join(root, "workspaces"),
    controlRoot: path.join(root, "control"),
    inboxRoot: path.join(root, "exchange"),
    socketPath: path.join(root, "run", "worker.sock"),
  };
  const worker = new TransitionWorker(config);
  await worker.initialize();
  const initialized = await worker.initializeAgent({
    agentId: "agent",
    operationId: "init",
    headVersionId: "initial",
    generation: 1,
    sessionEpoch: 0,
    agentConfigVersion: 1,
    policyVersion: 1,
    name: "Agent",
    instructions: "# trusted\n",
  });
  const authority = {
    mode: "worker",
    initialize: async () => ({ ...worker.health(), authority: "transition-worker" }),
    initializeAgent: worker.initializeAgent.bind(worker),
    adoptLegacyState: worker.adoptLegacyState.bind(worker),
    prepareRun: worker.prepareRun.bind(worker),
    prepare: worker.prepare.bind(worker),
    sealProposal: worker.sealProposal.bind(worker),
    exportProposal: worker.exportProposal.bind(worker),
    recordEvidence: worker.recordEvidence.bind(worker),
    issuePermit: worker.issuePermit.bind(worker),
    applyPromotion: worker.applyPromotion.bind(worker),
    applyRollback: worker.applyRollback.bind(worker),
    disposeRun: worker.disposeRun.bind(worker),
    regeneratePlatformState: worker.regeneratePlatformState.bind(worker),
    archiveAgent: worker.archiveAgent.bind(worker),
    getProjection: worker.projection.bind(worker),
    recover: worker.recoverAgent.bind(worker),
  } as unknown as TransitionAuthorityClient;
  const broker = {
    async run(request: RunnerRequest) {
      const candidate = path.join(config.inboxRoot, request.workspaceRef!.relativeSubpath);
      if (mode === "protected") {
        await writeFile(path.join(candidate, "protected.txt"), "tampered\n");
      } else {
        await writeFile(path.join(candidate, "feature.ts"), "export const feature = true;\n");
      }
      return { output: "done", threadId: "thread", usage: null };
    },
    async cancel() { return true; },
    async isAvailable() { return true; },
    async attestCommitGateTeardown() {
      return {
        containerExited: true,
        containerRemoved: true,
        mountsReleased: true,
        resolvedModel: "resolved-worker-model",
      };
    },
    async runVerifier() {
      if (mode === "verifier-error") throw new Error("verifier unavailable");
      return {
        checks: [{
          id: "workspace-sanity",
          status: "PASS" as const,
          exitCode: 0,
          durationMs: 1,
          output: "ok",
          timedOut: false,
        }],
        environment: {
          imageReference: "runtime@sha256:test",
          imageId: "sha256:image",
          imageDigest: "a".repeat(64),
          configHash: "b".repeat(64),
          checkBundleHash: "c".repeat(64),
          resourcePolicyHash: "d".repeat(64),
          sourceRevision: "revision",
        },
      };
    },
  };
  const runner = new WorkerCommitGateRunner(
    broker as unknown as AgentRunner & typeof broker,
    authority,
    config.inboxRoot,
    "revision",
  );
  const head = initialized.head!;
  const request: RunnerRequest = {
    runId: "run-1",
    agentId: "agent",
    workspacePath: "/logical/agent",
    prompt: "implement",
    threadId: null,
    runLeaseId: "lease-1",
    sessionEpoch: 0,
    baseViewId: head.view.viewId,
    stateGeneration: head.view.generation,
    expectedHeadVersionId: head.view.headVersionId,
    agentConfigVersion: 1,
    policyVersion: 1,
    baseVersionedHash: head.view.versionedHash,
    basePlatformManagedHash: head.view.platformManagedHash,
    baseLiveStateHash: head.workspaceHash,
    provider: {
      providerId: "ark",
      gateway: "http://model-relay:3100/v1",
      requestedModel: "endpoint-id",
      resolvedModel: null,
    },
  };
  return { worker, runner, request, initialized };
}

describe("WorkerCommitGateRunner", () => {
  it("commits through proposal, evidence, permit and Worker generation CAS", async () => {
    const { worker, runner, request, initialized } = await fixture("commit");
    const result = await runner.run(request);
    expect(result.commitGate).toMatchObject({
      decision: "COMMITTED",
      baseGeneration: 1,
      nextGeneration: 2,
      permitState: "CONSUMED",
      provider: { resolvedModel: "resolved-worker-model" },
    });
    const projection = await worker.projection("agent");
    expect(projection.head?.view.generation).toBe(2);
    expect(projection.permits[`permit-${request.runId}`]?.state).toBe("CONSUMED");
    expect(projection.head?.view.viewId).not.toBe(initialized.head?.view.viewId);
  });

  it("quarantines a protected-path change without advancing workspace generation", async () => {
    const { worker, runner, request, initialized } = await fixture("protected");
    const result = await runner.run(request);
    expect(result.commitGate).toMatchObject({
      decision: "QUARANTINED",
      baseGeneration: 1,
      nextGeneration: 1,
    });
    const base = initialized.head!.view;
    const { schemaVersion: _schemaVersion, viewId: _viewId, ...viewInput } = base;
    const finalView = makeStateView({ ...viewInput, sessionEpoch: 1 });
    await runner.finalizeDisposition("agent", request.runId, finalView);
    const projection = await worker.projection("agent");
    expect(projection.head?.view.generation).toBe(1);
    expect(projection.head?.view.sessionEpoch).toBe(1);
    expect(projection.terminalReceipts.at(-1)?.decision).toBe("QUARANTINED");
  });

  it("records an ABORTED non-promotion receipt after a prepared verifier outage", async () => {
    const { worker, runner, request, initialized } = await fixture("verifier-error");
    const result = await runner.run(request);
    expect(result.commitGate).toMatchObject({
      decision: "ABORTED",
      baseGeneration: 1,
      nextGeneration: 1,
      failureClass: "infra_errored",
    });
    const base = initialized.head!.view;
    const { schemaVersion: _schemaVersion, viewId: _viewId, ...viewInput } = base;
    await runner.finalizeDisposition(
      "agent",
      request.runId,
      makeStateView({ ...viewInput, sessionEpoch: 1 }),
    );
    expect((await worker.projection("agent")).terminalReceipts.at(-1)?.decision)
      .toBe("ABORTED");
  });
});
