import { readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { mkdtemp } from "node:fs/promises";
import { afterEach, describe, expect, it } from "vitest";
import { makeStateView } from "./state-view.js";
import { verifyAuthorityReceiptProof } from "./research/receipt-proof.js";
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

interface RunnerFixtureHooks {
  afterVerifier?: () => Promise<void>;
  afterPermit?: () => Promise<void>;
  beforePromotion?: (worker: TransitionWorker) => Promise<void>;
  loseFirstPrepareResponse?: boolean;
  losePromotionResponse?: boolean;
  onAgentRun?: () => void;
  onReconcile?: (input: {
    runId: string;
    agentId: string;
    runLeaseId: string;
    sessionEpoch: number;
    scope: "AGENT" | "ALL";
  }) => void;
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  return {
    promise: new Promise<void>((settle) => {
      resolve = settle;
    }),
    resolve: () => resolve(),
  };
}

async function fixture(
  mode: "commit" | "protected" | "verifier-error" | "manifest-symlink" | "manifest-io",
  hooks: RunnerFixtureHooks = {},
) {
  const root = await mkdtemp(path.join(tmpdir(), "commitgate-worker-runner-"));
  roots.push(root);
  const config: TransitionWorkerConfig = {
    workspaceRoot: path.join(root, "workspaces"),
    controlRoot: path.join(root, "control"),
    inboxRoot: path.join(root, "exchange"),
    socketPath: path.join(root, "run", "worker.sock"),
    sourceRevision: "revision",
    requireRuntimeTeardownHandshake: true,
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
  let prepareResponseLost = false;
  const authority = {
    mode: "worker",
    initialize: async () => ({ ...worker.health(), authority: "transition-worker" }),
    initializeAgent: worker.initializeAgent.bind(worker),
    adoptLegacyState: worker.adoptLegacyState.bind(worker),
    prepareRun: async (input: Parameters<TransitionWorker["prepareRun"]>[0]) => {
      const prepared = await worker.prepareRun(input);
      if (hooks.loseFirstPrepareResponse && !prepareResponseLost) {
        prepareResponseLost = true;
        throw Object.assign(new Error("response lost after durable admission"), {
          code: "WORKER_RPC_TRUNCATED",
        });
      }
      return prepared;
    },
    recordRuntimeTeardown: worker.recordRuntimeTeardown.bind(worker),
    cancelRun: worker.cancelRun.bind(worker),
    prepare: worker.prepare.bind(worker),
    sealProposal: worker.sealProposal.bind(worker),
    exportProposal: worker.exportProposal.bind(worker),
    recordEvidence: worker.recordEvidence.bind(worker),
    issuePermit: async (input: Parameters<TransitionWorker["issuePermit"]>[0]) => {
      const projection = await worker.issuePermit(input);
      await hooks.afterPermit?.();
      return projection;
    },
    applyPromotion: async (input: Parameters<TransitionWorker["applyPromotion"]>[0]) => {
      await hooks.beforePromotion?.(worker);
      const projection = await worker.applyPromotion(input);
      if (hooks.losePromotionResponse) {
        throw Object.assign(new Error("response lost after durable acknowledgement"), {
          code: "WORKER_RPC_TRUNCATED",
        });
      }
      return projection;
    },
    applyRollback: worker.applyRollback.bind(worker),
    disposeRun: worker.disposeRun.bind(worker),
    regeneratePlatformState: worker.regeneratePlatformState.bind(worker),
    archiveAgent: worker.archiveAgent.bind(worker),
    getProjection: worker.projection.bind(worker),
    recover: worker.recoverAgent.bind(worker),
  } as unknown as TransitionAuthorityClient;
  const broker = {
    async run(request: RunnerRequest) {
      hooks.onAgentRun?.();
      const candidate = path.join(config.inboxRoot, request.workspaceRef!.relativeSubpath);
      if (mode === "protected") {
        await writeFile(path.join(candidate, "protected.txt"), "tampered\n");
      } else if (mode === "manifest-symlink") {
        await symlink("AGENTS.md", path.join(candidate, "agent-link"));
      } else if (mode === "manifest-io") {
        await rm(candidate, { recursive: true, force: true });
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
    async reconcileCommitGateRuntime(request: {
      runId: string;
      agentId: string;
      runLeaseId: string;
      sessionEpoch: number;
      scope: "AGENT" | "ALL";
    }) {
      hooks.onReconcile?.(request);
      return {
        schemaVersion: 1 as const,
        ...request,
        containerExited: true as const,
        containerRemoved: true as const,
        mountsReleased: true as const,
        source: "broker-reconciliation" as const,
      };
    },
    async runVerifier() {
      if (mode === "verifier-error") throw new Error("verifier unavailable");
      await hooks.afterVerifier?.();
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
  return { config, worker, runner, request, initialized };
}

describe("WorkerCommitGateRunner", () => {
  it("quiesces a Broker orphan before restart recovery destroys candidate bytes", async () => {
    const reconciliations: Array<{
      runId: string;
      agentId: string;
      runLeaseId: string;
      sessionEpoch: number;
      scope: "AGENT" | "ALL";
    }> = [];
    const { config, worker, runner, request, initialized } = await fixture("commit", {
      onReconcile: (input) => reconciliations.push(input),
    });
    await worker.prepareRun({
      agentId: request.agentId,
      transitionId: request.runId,
      runId: request.runId,
      runLeaseId: request.runLeaseId!,
      candidateVolumeId: `candidate-${request.runId}`,
      expectedViewId: initialized.head!.view.viewId,
      expectedWorkspaceHash: initialized.head!.workspaceHash,
      baseGeneration: initialized.head!.view.generation,
      sessionEpoch: request.sessionEpoch!,
    });
    const candidate = path.join(config.inboxRoot, `candidate-${request.runId}`);
    await writeFile(path.join(candidate, "late-write.ts"), "still mounted\n");

    const restarted = new TransitionWorker(config);
    await expect(restarted.initialize()).resolves.toBeUndefined();
    expect(await readFile(path.join(candidate, "late-write.ts"), "utf8"))
      .toContain("still mounted");
    expect((await restarted.projection(request.agentId)).terminalReceipts).toHaveLength(0);

    const recovered = await runner.recoverAuthority(
      request.agentId,
      await restarted.projection(request.agentId),
    );
    expect(reconciliations).toEqual([{
      runId: request.runId,
      agentId: request.agentId,
      runLeaseId: request.runLeaseId,
      sessionEpoch: request.sessionEpoch,
      scope: "ALL",
    }]);
    expect(recovered.terminalReceipts.at(-1)).toMatchObject({
      decision: "ABORTED",
      reasonCodes: ["INCOMPLETE_PREPARED_RECOVERED"],
    });
    expect(recovered.transitions[request.runId]).toMatchObject({
      artifactsDestroyed: true,
      runtimeTeardownAll: { source: "broker-reconciliation" },
    });
    await expect(readFile(path.join(candidate, "late-write.ts"), "utf8"))
      .rejects.toMatchObject({ code: "ENOENT" });
  });

  it("recovers an idempotent prepared admission after its RPC response is lost and never runs Agent code", async () => {
    let agentRuns = 0;
    const { worker, runner, request, initialized } = await fixture("commit", {
      loseFirstPrepareResponse: true,
      onAgentRun: () => { agentRuns += 1; },
    });

    const result = await runner.run(request);
    expect(agentRuns).toBe(0);
    expect(result.commitGate).toMatchObject({
      decision: "ABORTED",
      baseGeneration: 1,
      nextGeneration: 1,
    });
    const base = initialized.head!.view;
    const { schemaVersion: _schemaVersion, viewId: _viewId, ...baseInput } = base;
    await runner.finalizeDisposition(
      "agent",
      request.runId,
      makeStateView({ ...baseInput, sessionEpoch: base.sessionEpoch + 1 }),
    );
    const projection = await worker.projection("agent");
    expect(projection.head?.view.generation).toBe(1);
    expect(projection.terminalReceipts.at(-1)?.decision).toBe("ABORTED");
  });

  it("reconciles a committed terminal fact when the promotion acknowledgement response is lost", async () => {
    const { worker, runner, request } = await fixture("commit", {
      losePromotionResponse: true,
    });

    const result = await runner.run(request);
    expect(result.commitGate).toMatchObject({
      decision: "COMMITTED",
      baseGeneration: 1,
      nextGeneration: 2,
      permitState: "CONSUMED",
    });
    const projection = await worker.projection("agent");
    expect(projection.head?.view.generation).toBe(2);
    expect(projection.terminalReceipts.filter((receipt) => receipt.receiptId === request.runId))
      .toHaveLength(1);
  });

  it("commits through proposal, evidence, permit and Worker generation CAS", async () => {
    const { worker, runner, request, initialized } = await fixture("commit");
    const result = await runner.run(request);
    expect(result.commitGate).toMatchObject({
      decision: "COMMITTED",
      baseGeneration: 1,
      nextGeneration: 2,
      permitState: "CONSUMED",
      candidateCleanup: "deleted",
      artifactRetention: "version_snapshot",
      provider: { resolvedModel: "resolved-worker-model" },
    });
    const projection = await worker.projection("agent");
    expect(projection.head?.view.generation).toBe(2);
    expect(projection.permits[`permit-${request.runId}`]?.state).toBe("CONSUMED");
    expect(projection.head?.view.viewId).not.toBe(initialized.head?.view.viewId);
    const binding = result.commitGate?.effectProof;
    expect(binding?.invariantSatisfied).toBe(true);
    expect(new Set([
      binding?.sealedProposalHash,
      binding?.verifierInputHash,
      binding?.promotionSourceHash,
      binding?.finalAuthoritativeHash,
    ]).size).toBe(1);
  });

  it("quarantines a protected-path change without advancing workspace generation", async () => {
    const { config, worker, runner, request, initialized } = await fixture("protected");
    const result = await runner.run(request);
    expect(result.commitGate).toMatchObject({
      decision: "QUARANTINED",
      baseGeneration: 1,
      nextGeneration: 1,
      candidateCleanup: "deferred",
      artifactRetention: "deferred",
    });
    const base = initialized.head!.view;
    const { schemaVersion: _schemaVersion, viewId: _viewId, ...viewInput } = base;
    const finalView = makeStateView({ ...viewInput, sessionEpoch: 1 });
    const finalized = await runner.finalizeDisposition("agent", request.runId, finalView);
    expect(finalized.summary).toMatchObject({
      candidateCleanup: "deleted",
      artifactRetention: "destroyed",
    });
    expect(finalized.receipt).toMatchObject({
      candidateCleanup: "deleted",
      artifactRetention: "destroyed",
    });
    const projection = await worker.projection("agent");
    expect(projection.head?.view.generation).toBe(1);
    expect(projection.head?.view.sessionEpoch).toBe(1);
    expect(projection.terminalReceipts.at(-1)?.decision).toBe("QUARANTINED");
    expect(projection.proposals[`proposal-${request.runId}`]?.state).toBe("DESTROYED");
    expect(projection.transitions[request.runId]?.artifactsDestroyed).toBe(true);
    await expect(
      readFile(
        path.join(
          config.controlRoot,
          "proposals",
          "agent",
          `proposal-${request.runId}`,
          "protected.txt",
        ),
        "utf8",
      ),
    ).rejects.toMatchObject({ code: "ENOENT" });
    expect(projection.receiptProofs[request.runId]?.bundle).not.toHaveProperty("eventChain");
    const proof = await worker.getReceiptProof("agent", request.runId);
    expect(proof?.receipt).toMatchObject({
      runId: request.runId,
      decision: "QUARANTINED",
      baseGeneration: 1,
      nextGeneration: 1,
      baseWorkspaceHash: initialized.head?.workspaceHash,
      finalWorkspaceHash: initialized.head?.workspaceHash,
      permitState: null,
    });
    expect(verifyAuthorityReceiptProof(proof!)).toEqual({ valid: true, reason: null });
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

  it("quarantines deterministic candidate manifest violations but aborts missing storage", async () => {
    const rejected = await fixture("manifest-symlink");
    const rejectedResult = await rejected.runner.run(rejected.request);
    expect(rejectedResult.commitGate).toMatchObject({
      decision: "QUARANTINED",
      failureClass: "agent_wrong",
    });
    const rejectedBase = rejected.initialized.head!.view;
    const {
      schemaVersion: _rejectedSchema,
      viewId: _rejectedViewId,
      ...rejectedViewInput
    } = rejectedBase;
    const rejectedTerminal = await rejected.runner.finalizeDisposition(
      "agent",
      rejected.request.runId,
      makeStateView({
        ...rejectedViewInput,
        sessionEpoch: rejectedBase.sessionEpoch + 1,
      }),
    );
    expect(rejectedTerminal.receipt.reasonCodes).toContain(
      "POLICY_MANIFEST_SYMLINK_FILE",
    );
    expect((await rejected.worker.projection("agent")).head?.workspaceHash)
      .toBe(rejected.initialized.head?.workspaceHash);

    const unavailable = await fixture("manifest-io");
    const unavailableResult = await unavailable.runner.run(unavailable.request);
    expect(unavailableResult.commitGate).toMatchObject({
      decision: "ABORTED",
      failureClass: "infra_errored",
    });
    const unavailableBase = unavailable.initialized.head!.view;
    const {
      schemaVersion: _unavailableSchema,
      viewId: _unavailableViewId,
      ...unavailableViewInput
    } = unavailableBase;
    const unavailableTerminal = await unavailable.runner.finalizeDisposition(
      "agent",
      unavailable.request.runId,
      makeStateView({
        ...unavailableViewInput,
        sessionEpoch: unavailableBase.sessionEpoch + 1,
      }),
    );
    expect(unavailableTerminal.receipt.reasonCodes).not.toContain(
      "POLICY_MANIFEST_AUTHORITATIVE_ROOT_NOT_DIRECTORY",
    );
    expect((await unavailable.worker.projection("agent")).head?.workspaceHash)
      .toBe(unavailable.initialized.head?.workspaceHash);
  });

  it("maps a stale Worker View CAS to one durable CONFLICTED disposition before finalize", async () => {
    let winningView = "";
    const { worker, runner, request } = await fixture("commit", {
      beforePromotion: async (authorityWorker) => {
        const current = (await authorityWorker.projection("agent")).head!;
        const advanced = await authorityWorker.regeneratePlatformState({
          agentId: "agent",
          operationId: "concurrent-platform-change",
          expectedViewId: current.view.viewId,
          expectedWorkspaceHash: current.workspaceHash,
          instructions: "# concurrently advanced trusted instructions\n",
          sessionEpoch: current.view.sessionEpoch + 1,
          agentConfigVersion: current.view.agentConfigVersion + 1,
          policyVersion: current.view.policyVersion,
        });
        winningView = advanced.head!.view.viewId;
      },
    });

    const result = await runner.run(request);
    expect(result.commitGate).toMatchObject({
      decision: "CONFLICTED",
      failureClass: "state_conflict",
      baseGeneration: 1,
    });
    const beforeRunnerFinalize = await worker.projection("agent");
    expect(beforeRunnerFinalize.head?.view.viewId).not.toBe(winningView);
    expect(beforeRunnerFinalize.head?.view.generation).toBe(2);
    expect(beforeRunnerFinalize.head?.view.sessionEpoch).toBe(2);
    expect(beforeRunnerFinalize.versions).toHaveLength(1);
    expect(beforeRunnerFinalize.terminalReceipts.filter(
      (receipt) => receipt.receiptId === request.runId,
    )).toEqual([expect.objectContaining({
      decision: "CONFLICTED",
      dispositionBaseViewId: winningView,
      dispositionBaseGeneration: 2,
      workspaceHash: beforeRunnerFinalize.head?.workspaceHash,
      reasonCodes: ["VIEW_CAS_MISMATCH"],
    })]);

    // The CAS rejection is already terminal before AgentService calls
    // finalizeDisposition. Simulate a Runner/API crash at that exact gap;
    // recovery must not rewrite it as ABORTED or advance another epoch.
    await worker.recoverAgent("agent");
    const afterCrashRecovery = await worker.projection("agent");
    expect(afterCrashRecovery.head).toEqual(beforeRunnerFinalize.head);
    expect(afterCrashRecovery.terminalReceipts.filter(
      (receipt) => receipt.receiptId === request.runId,
    )).toHaveLength(1);

    const current = afterCrashRecovery.head!.view;
    const { schemaVersion: _schemaVersion, viewId: _viewId, ...currentInput } = current;
    const finalized = await runner.finalizeDisposition(
      "agent",
      request.runId,
      makeStateView({ ...currentInput, sessionEpoch: current.sessionEpoch + 1 }),
    );
    expect(finalized.summary.effectProof).toMatchObject({
      admissionBaseHash: request.baseLiveStateHash,
      authoritativeBeforeHash: beforeRunnerFinalize.head!.workspaceHash,
      authoritativeAfterHash: beforeRunnerFinalize.head!.workspaceHash,
      invariant: "NO_PERSISTENT_EFFECT",
      invariantSatisfied: true,
    });
    const afterDisposition = await worker.projection("agent");
    expect(afterDisposition.head?.view.generation).toBe(2);
    expect(afterDisposition.head).toEqual(beforeRunnerFinalize.head);
    expect(afterDisposition.head?.workspaceHash).toBe(beforeRunnerFinalize.head?.workspaceHash);
    expect(afterDisposition.versions).toHaveLength(1);
    expect(afterDisposition.terminalReceipts.at(-1)).toMatchObject({
      decision: "CONFLICTED",
      dispositionBaseViewId: winningView,
      dispositionBaseGeneration: beforeRunnerFinalize.head?.view.generation,
      dispositionBaseWorkspaceHash: beforeRunnerFinalize.head?.workspaceHash,
      workspaceHash: beforeRunnerFinalize.head?.workspaceHash,
    });
    expect(afterDisposition.terminalReceipts.filter(
      (receipt) => receipt.receiptId === request.runId,
    )).toHaveLength(1);
    const eventsBeforeFinalizeReplay = await worker.log.transition("agent", request.runId);
    const replayedFinalization = await runner.finalizeDisposition(
      "agent",
      request.runId,
      current,
    );
    expect(replayedFinalization.summary).toEqual(finalized.summary);
    expect(await worker.log.transition("agent", request.runId))
      .toHaveLength(eventsBeforeFinalizeReplay.length);
    expect(afterDisposition.receiptProofs[request.runId]?.bundle).not.toHaveProperty("eventChain");
    const proof = await worker.getReceiptProof("agent", request.runId);
    expect(proof.schemaVersion).toBe(3);
    expect(proof?.receipt).toMatchObject({
      schemaVersion: 2,
      decision: "CONFLICTED",
      baseViewId: request.baseViewId,
      baseGeneration: request.stateGeneration,
      baseWorkspaceHash: request.baseLiveStateHash,
      dispositionBaseViewId: winningView,
      dispositionBaseGeneration: beforeRunnerFinalize.head?.view.generation,
      dispositionBaseWorkspaceHash: beforeRunnerFinalize.head?.workspaceHash,
      finalWorkspaceHash: beforeRunnerFinalize.head?.workspaceHash,
    });
    expect(verifyAuthorityReceiptProof(proof!)).toEqual({ valid: true, reason: null });
  });

  for (const stage of ["verifier", "permit", "promotion"] as const) {
    it(`makes cancellation authoritative before ${stage}`, async () => {
      const reached = deferred();
      const release = deferred();
      const hooks: RunnerFixtureHooks = stage === "verifier"
        ? { afterVerifier: async () => { reached.resolve(); await release.promise; } }
        : stage === "permit"
          ? { afterPermit: async () => { reached.resolve(); await release.promise; } }
          : { beforePromotion: async () => { reached.resolve(); await release.promise; } };
      const { worker, runner, request, initialized } = await fixture("commit", hooks);
      const running = runner.run(request);
      await reached.promise;
      await expect(runner.cancel("agent", {
        runId: request.runId,
        runLeaseId: request.runLeaseId!,
        sessionEpoch: request.sessionEpoch!,
      })).resolves.toBe(true);
      release.resolve();
      await expect(running).rejects.toMatchObject({ name: "RunCancelledError" });

      const cancelled = await worker.projection("agent");
      expect(cancelled.transitions[request.runId]?.state).toBe("CANCELLED");
      expect(cancelled.head?.view.generation).toBe(1);
      expect(cancelled.versions).toHaveLength(1);
      const base = initialized.head!.view;
      const { schemaVersion: _schemaVersion, viewId: _viewId, ...baseInput } = base;
      if (stage === "verifier") {
        // Reproduce an API crash after the durable cancel event. Worker
        // recovery owns the ABORTED terminal receipt before live finalize
        // retries, which must then remain idempotent.
        await worker.recoverAgent("agent");
      }
      await runner.finalizeDisposition(
        "agent",
        request.runId,
        makeStateView({ ...baseInput, sessionEpoch: base.sessionEpoch + 1 }),
      );
      const terminal = await worker.projection("agent");
      expect(terminal.head?.view.generation).toBe(1);
      expect(terminal.head?.workspaceHash).toBe(initialized.head?.workspaceHash);
      expect(terminal.versions).toHaveLength(1);
      expect(terminal.terminalReceipts.at(-1)).toMatchObject({
        decision: "ABORTED",
      });
      expect(
        terminal.terminalReceipts.filter((receipt) => receipt.receiptId === request.runId),
      ).toHaveLength(1);
    });
  }
});
