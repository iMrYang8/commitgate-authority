import { chmod, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AgentService } from "./agent-service.js";
import { loadConfig } from "./config.js";
import {
  CommitGateCoordinator,
  CommitGateRunner,
  defaultCommitGatePolicy,
  FunctionVerifierRunner,
  ReceiptStore,
  VersionStore,
  WorkspaceTransaction,
  type CheckResult,
  type CommitGateComponents,
  type VerifierInput,
} from "./commitgate/index.js";
import { refreshAgentViewId } from "./state-view.js";
import { JsonStore } from "./store.js";
import { TransitionEventLog } from "./transition-log.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";
import { WorkspaceManager } from "./workspace.js";
import { writeJsonAtomic } from "./commitgate/atomic-json.js";

const roots: string[] = [];

async function makeWritable(root: string): Promise<void> {
  await chmod(root, 0o700);
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const item = path.join(root, entry.name);
    if (entry.isDirectory()) await makeWritable(item);
    else await chmod(item, 0o600);
  }
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map(async (root) => {
    await makeWritable(root).catch(() => undefined);
    await rm(root, { recursive: true, force: true });
  }));
});

class FailableStore extends JsonStore {
  private mutationsBeforeFailure: number | null = null;
  private consecutiveFailures = 0;

  failNextMutation(): void {
    this.mutationsBeforeFailure = 0;
  }

  failAfterSuccessfulMutations(count: number): void {
    this.mutationsBeforeFailure = count;
  }

  failNextMutations(count: number): void {
    this.consecutiveFailures = count;
  }

  override async mutate<T>(mutation: Parameters<JsonStore["mutate"]>[0]): Promise<T> {
    if (this.consecutiveFailures > 0) {
      this.consecutiveFailures -= 1;
      throw new Error("injected consecutive database write failure");
    }
    if (this.mutationsBeforeFailure === 0) {
      this.mutationsBeforeFailure = null;
      throw new Error("injected database write failure");
    }
    if (this.mutationsBeforeFailure !== null) this.mutationsBeforeFailure -= 1;
    return super.mutate(mutation) as Promise<T>;
  }
}

class CommitGateQueuedStartBarrierStore extends JsonStore {
  private armed = false;
  private entered = false;
  private enteredResolve: (() => void) | null = null;
  private releaseResolve: (() => void) | null = null;
  private enteredPromise: Promise<void> = Promise.resolve();
  private releasePromise: Promise<void> = Promise.resolve();

  armQueuedStart(): Promise<void> {
    this.armed = true;
    this.entered = false;
    this.enteredPromise = new Promise<void>((resolve) => {
      this.enteredResolve = resolve;
    });
    this.releasePromise = new Promise<void>((resolve) => {
      this.releaseResolve = resolve;
    });
    return this.enteredPromise;
  }

  releaseQueuedStart(): void {
    this.releaseResolve?.();
  }

  override async mutate<T>(mutation: Parameters<JsonStore["mutate"]>[0]): Promise<T> {
    if (
      this.armed &&
      !this.entered &&
      this.snapshot().runs.some((run) => run.status === "queued")
    ) {
      this.entered = true;
      this.armed = false;
      this.enteredResolve?.();
      await this.releasePromise;
    }
    return super.mutate(mutation) as Promise<T>;
  }
}

async function gatedFixture(
  run: (request: RunnerRequest) => Promise<RunnerResult>,
  storeFactory: (filePath: string) => JsonStore = (filePath) => new JsonStore(filePath),
  verify: (input: VerifierInput) => Promise<CheckResult[]> | CheckResult[] = () => [],
  transactionFactory: () => WorkspaceTransaction = () => new WorkspaceTransaction(),
) {
  const root = await mkdtemp(path.join(tmpdir(), "commitgate-service-"));
  roots.push(root);
  const workspaceRoot = path.join(root, "workspaces");
  const controlRoot = path.join(workspaceRoot, ".commitgate");
  const config = loadConfig({
    NODE_ENV: "test",
    APP_DATA_DIR: path.join(root, "data"),
    AGENT_WORKSPACE_ROOT: workspaceRoot,
    CODEX_HOME: path.join(root, "codex"),
    RUNTIME_PROVIDER: "container",
    COMMITGATE_ENABLED: "true",
    COMMITGATE_CONTROL_ROOT: controlRoot,
    COMMITGATE_TRUSTED_CHECKS_DIR: path.join(root, "trusted-checks"),
    ARK_API_KEY: "test-key",
    ARK_MODEL: "ep-test",
  });
  await import("node:fs/promises").then(async ({ mkdir, writeFile: writeTrusted }) => {
    await mkdir(config.commitGateTrustedChecksDirectory, { recursive: true });
    await writeTrusted(
      path.join(config.commitGateTrustedChecksDirectory, "workspace-sanity.mjs"),
      "console.log('fixture trusted check');\n",
      "utf8",
    );
  });
  const inner: AgentRunner = {
    run,
    cancel: async () => false,
    isAvailable: async () => true,
  };
  const transaction = transactionFactory();
  const receiptStore = new ReceiptStore(controlRoot);
  const versionStore = new VersionStore(controlRoot, {}, transaction);
  const coordinator = new CommitGateCoordinator({
    workspaceRoot,
    controlRoot,
    trustedChecksRoot: config.commitGateTrustedChecksDirectory,
    verifier: new FunctionVerifierRunner(verify),
    receiptStore,
    versionStore,
    transaction,
    sensitiveValues: [config.arkApiKey],
  });
  const gateRunner = new CommitGateRunner(inner, coordinator);
  const components: CommitGateComponents = {
    runner: gateRunner,
    coordinator,
    receiptStore,
    versionStore,
  };
  const store = storeFactory(path.join(root, "data", "db.json"));
  const workspaces = new WorkspaceManager(workspaceRoot);
  const service = new AgentService(
    config,
    store,
    workspaces,
    gateRunner,
    components,
  );
  await service.initialize();
  return { root, controlRoot, service, store, coordinator, gateRunner, workspaces };
}

describe("AgentService CommitGate product integration", () => {
  it("reports CommitGate not ready and rejects before model execution when trusted checks are missing", async () => {
    let modelCalls = 0;
    const fixture = await gatedFixture(async () => {
      modelCalls += 1;
      return { output: "unexpected", threadId: "thread", usage: null };
    });
    const agent = await fixture.service.createAgent({ name: "Gate" });
    await rm(path.join(fixture.root, "trusted-checks", "workspace-sanity.mjs"));

    await expect(fixture.service.systemInfo()).resolves.toMatchObject({
      commitGateReady: false,
      verifierAvailable: false,
    });
    await expect(fixture.service.sendMessage(agent.id, "do not run")).rejects.toMatchObject({
      statusCode: 503,
      code: "COMMITGATE_NOT_READY",
    });
    expect(modelCalls).toBe(0);
    expect(fixture.service.getRuns(agent.id)).toHaveLength(0);
  });

  it("persists a committed receipt and append-only version head", async () => {
    const fixture = await gatedFixture(async (request) => {
      await writeFile(path.join(request.workspacePath, "README.md"), "committed\n");
      return { output: "done", threadId: "thread-1", usage: null };
    });
    const agent = await fixture.service.createAgent({ name: "Gate" });
    const { run } = await fixture.service.sendMessage(agent.id, "change readme");
    await expect.poll(() => fixture.service.getRun(run.id).status).toBe("completed");

    expect(fixture.service.getRun(run.id).commitGate?.decision).toBe("COMMITTED");
    expect(await readFile(path.join(agent.workspacePath, "README.md"), "utf8")).toBe(
      "committed\n",
    );
    expect(fixture.service.getVersions(agent.id).map((version) => version.kind)).toEqual([
      "AGENT_COMMIT",
      "INITIAL",
    ]);
    expect(fixture.service.getAgent(agent.id)).toMatchObject({
      codexThreadId: "thread-1",
      needsReconciliation: false,
    });
    expect(await fixture.service.getCommitGateReceipt(run.id)).toMatchObject({
      decision: "COMMITTED",
      promotionPendingDatabaseAck: false,
    });
  });

  it("fences a stale callback whose active lease does not match without changing Run, Message, or head", async () => {
    let innerStarted!: () => void;
    let finishInner!: (result: RunnerResult) => void;
    const innerStartedPromise = new Promise<void>((resolve) => {
      innerStarted = resolve;
    });
    const innerResult = new Promise<RunnerResult>((resolve) => {
      finishInner = resolve;
    });
    const fixture = await gatedFixture(async () => {
      innerStarted();
      return innerResult;
    });
    const agent = await fixture.service.createAgent({ name: "Callback fence" });
    const { run } = await fixture.service.sendMessage(agent.id, "wait for callback");
    await innerStartedPromise;
    const running = fixture.service.getRun(run.id);
    const headBefore = fixture.service.getAgent(agent.id).headVersionId;
    const messagesBefore = fixture.service.getMessages(agent.id);

    await (
      fixture.service as unknown as {
        handleCommitGateLifecycleEvent(event: {
          runId: string;
          runLeaseId: string;
          baseViewId: string;
          sessionEpoch: number;
          status: "PROVISIONAL";
          output: string;
        }): Promise<void>;
      }
    ).handleCommitGateLifecycleEvent({
      runId: run.id,
      runLeaseId: "stale-active-lease",
      baseViewId: running.baseViewId,
      sessionEpoch: fixture.service.getAgent(agent.id).sessionEpoch,
      status: "PROVISIONAL",
      output: "stale provisional output",
    });

    const events = await new TransitionEventLog(
      path.join(fixture.controlRoot, "transition-events"),
    ).transition(agent.id, run.id);
    expect(events).toEqual([
      expect.objectContaining({
        type: "STALE_CALLBACK_RECORDED",
        payload: expect.objectContaining({
          callbackKind: "lifecycle-provisional",
          runLeaseId: "stale-active-lease",
        }),
      }),
    ]);
    expect(fixture.service.getRun(run.id)).toEqual(running);
    expect(fixture.service.getMessages(agent.id)).toEqual(messagesBefore);
    expect(fixture.service.getAgent(agent.id).headVersionId).toBe(headBefore);

    finishInner({ output: "authoritative", threadId: "current-thread", usage: null });
    await expect.poll(() => fixture.service.getRun(run.id).status).toBe("completed");
  });

  it("does not acknowledge or project a promotion whose terminal callback lease is stale", async () => {
    let release!: () => void;
    let started!: () => void;
    const barrier = new Promise<void>((resolve) => {
      release = resolve;
    });
    const entered = new Promise<void>((resolve) => {
      started = resolve;
    });
    const fixture = await gatedFixture(async (request) => {
      await writeFile(path.join(request.workspacePath, "README.md"), "stale terminal\n");
      started();
      await barrier;
      return { output: "stale result", threadId: "stale-thread", usage: null };
    });
    const acknowledge = vi.spyOn(fixture.gateRunner, "acknowledge");
    const agent = await fixture.service.createAgent({ name: "Terminal fence" });
    const initialHead = fixture.service.getAgent(agent.id).headVersionId;
    const { run } = await fixture.service.sendMessage(agent.id, "terminal fence");
    await entered;
    const messagesAfterAdmission = fixture.service.getMessages(agent.id);
    await fixture.store.mutate((database) => {
      const current = database.agents.find((item) => item.id === agent.id)!;
      current.activeRunLeaseId = "replacement-lease";
    });
    release();

    await expect
      .poll(async () =>
        (
          await new TransitionEventLog(
            path.join(fixture.controlRoot, "transition-events"),
          ).transition(agent.id, run.id)
        ).some(
          (event) =>
            event.type === "STALE_CALLBACK_RECORDED" &&
            event.payload.callbackKind === "terminal-completed",
        ),
      )
      .toBe(true);
    expect(acknowledge).not.toHaveBeenCalled();
    expect(fixture.service.getAgent(agent.id).headVersionId).toBe(initialHead);
    expect(fixture.service.getMessages(agent.id)).toEqual(messagesAfterAdmission);
    expect(fixture.service.getRun(run.id).transactionStatus).not.toBe("TERMINAL");
    await expect(fixture.service.getCommitGateReceipt(run.id)).resolves.toMatchObject({
      phase: "PENDING_PROMOTION",
      promotionPendingDatabaseAck: true,
    });
    await fixture.coordinator.rollbackPending(run.id);
  });

  it("rebinds a queued follow-up submittedViewId to the latest View before CommitGate execution", async () => {
    const requests: RunnerRequest[] = [];
    const fixture = await gatedFixture(
      async (request) => {
        requests.push(request);
        await writeFile(path.join(request.workspacePath, "README.md"), "queued rebound\n");
        return { output: "rebound", threadId: "fresh-thread", usage: null };
      },
      (filePath) => new CommitGateQueuedStartBarrierStore(filePath),
    );
    const store = fixture.store as CommitGateQueuedStartBarrierStore;
    const agent = await fixture.service.createAgent({ name: "Queued Gate" });
    await store.mutate((database) => {
      const storedAgent = database.agents.find((item) => item.id === agent.id)!;
      storedAgent.codexThreadId = "thread-for-submitted-view";
      storedAgent.needsReconciliation = false;
    });

    const queuedStartEntered = store.armQueuedStart();
    const { run } = await fixture.service.sendMessage(agent.id, "apply to latest View");
    await queuedStartEntered;
    const submittedViewId = fixture.service.getRun(run.id).submittedViewId;
    await store.mutate((database) => {
      const storedAgent = database.agents.find((item) => item.id === agent.id)!;
      storedAgent.sessionEpoch += 1;
      // Retain the stale continuation to prove the dispatcher, rather than
      // the transition producer, performs the fresh-session fence.
      storedAgent.needsReconciliation = false;
      refreshAgentViewId(storedAgent);
    });
    const reboundViewId = fixture.service.getAgent(agent.id).currentViewId;
    expect(reboundViewId).not.toBe(submittedViewId);
    store.releaseQueuedStart();

    await expect.poll(() => fixture.service.getRun(run.id).status).toBe("completed");
    expect(requests).toHaveLength(1);
    expect(requests[0]).toMatchObject({
      baseViewId: reboundViewId,
      sessionEpoch: 1,
      threadId: null,
    });
    expect(requests[0]?.prompt).toContain(`view_id=${reboundViewId}`);
    expect(fixture.service.getRun(run.id)).toMatchObject({
      submittedViewId,
      baseViewId: reboundViewId,
      status: "completed",
    });
    expect(await fixture.service.getCommitGateReceipt(run.id)).toMatchObject({
      decision: "COMMITTED",
      baseViewId: reboundViewId,
    });
    expect(
      fixture.service.getMessages(agent.id).find((message) => message.role === "user"),
    ).toMatchObject({ viewId: reboundViewId });
  });

  it("keeps all mutation admission locked until commit acknowledgement finishes", async () => {
    const fixture = await gatedFixture(async (request) => {
      await writeFile(path.join(request.workspacePath, "README.md"), "committed\n");
      return { output: "done", threadId: "thread-1", usage: null };
    });
    const agent = await fixture.service.createAgent({ name: "Gate" });
    const initial = fixture.service.getVersions(agent.id)[0]!;
    const originalAcknowledge = fixture.coordinator.acknowledge.bind(fixture.coordinator);
    let entered!: () => void;
    let release!: () => void;
    const enteredPromise = new Promise<void>((resolve) => { entered = resolve; });
    const releasePromise = new Promise<void>((resolve) => { release = resolve; });
    vi.spyOn(fixture.coordinator, "acknowledge").mockImplementation(async (runId) => {
      entered();
      await releasePromise;
      return originalAcknowledge(runId);
    });

    const { run } = await fixture.service.sendMessage(agent.id, "commit");
    await enteredPromise;
    expect(fixture.service.getRun(run.id)).toMatchObject({
      status: "running",
      transactionStatus: "PENDING_PROMOTION",
    });
    expect(fixture.service.getAgent(agent.id).status).toBe("busy");
    const committedHead = fixture.service.getAgent(agent.id).headVersionId!;
    expect(committedHead).not.toBe(initial.id);
    for (const operation of [
      () => fixture.service.sendMessage(agent.id, "second run"),
      () => fixture.service.updateAgent(agent.id, { name: "bypass" }),
      () => fixture.service.startAgent(agent.id),
      () => fixture.service.rollback(agent.id, initial.id, committedHead),
    ]) {
      await expect(operation()).rejects.toMatchObject({
        statusCode: 409,
        code: "AGENT_BUSY",
      });
    }

    release();
    await expect.poll(() => fixture.service.getRun(run.id).status).toBe("completed");
    await expect.poll(() => fixture.service.getAgent(agent.id).status).toBe("ready");
  });

  it("keeps an in-memory recovery lock when consecutive DB failures cannot persist it", async () => {
    const fixture = await gatedFixture(
      async (request) => {
        await writeFile(path.join(request.workspacePath, "README.md"), "committed\n");
        return { output: "done", threadId: "thread", usage: null };
      },
      (filePath) => new FailableStore(filePath),
    );
    const agent = await fixture.service.createAgent({ name: "Gate" });
    const initial = fixture.service.getVersions(agent.id)[0]!;
    const acknowledgement = vi
      .spyOn(fixture.coordinator, "acknowledge")
      .mockImplementation(async () => {
        if (acknowledgement.mock.calls.length === 1) {
          (fixture.store as FailableStore).failNextMutations(2);
        }
        throw new Error("injected acknowledgement failure");
      });

    await fixture.service.sendMessage(agent.id, "commit then fail lock persistence");
    await expect.poll(() => acknowledgement.mock.calls.length).toBe(2);
    await expect.poll(() =>
      (fixture.service as unknown as { activeExecutions: Map<string, unknown> })
        .activeExecutions.has(agent.id),
    ).toBe(false);
    // The durable writes that would normally persist the lock both failed.
    // The process-local reservation must still keep the unresolved journal
    // closed to every mutating operation.
    expect(fixture.service.getAgent(agent.id)).toMatchObject({
      status: "busy",
      recoveryRequired: false,
    });
    const head = fixture.service.getAgent(agent.id).headVersionId!;
    for (const operation of [
      () => fixture.service.startAgent(agent.id),
      () => fixture.service.stopAgent(agent.id),
      () => fixture.service.sendMessage(agent.id, "bypass"),
      () => fixture.service.updateAgent(agent.id, { name: "bypass" }),
      () => fixture.service.deleteAgent(agent.id),
      () => fixture.service.rollback(agent.id, initial.id, head),
    ]) {
      await expect(operation()).rejects.toMatchObject({
        statusCode: 409,
        code: "COMMITGATE_RECOVERY_REQUIRED",
      });
    }

    acknowledgement.mockRestore();
    await fixture.service.initialize();
    expect(fixture.service.getAgent(agent.id)).toMatchObject({
      status: "ready",
      recoveryRequired: false,
    });
    await expect(fixture.service.startAgent(agent.id)).resolves.toMatchObject({
      status: "ready",
    });
  });

  it("quarantines a protected edit and sends the next turn through a fresh reconciliation session", async () => {
    const requests: RunnerRequest[] = [];
    let call = 0;
    const fixture = await gatedFixture(async (request) => {
      requests.push(request);
      call += 1;
      if (call === 1) {
        await writeFile(path.join(request.workspacePath, "protected.txt"), "tampered\n");
      } else {
        await writeFile(path.join(request.workspacePath, "README.md"), "safe\n");
      }
      return { output: "done", threadId: "thread-" + call, usage: null };
    });
    const agent = await fixture.service.createAgent({ name: "Gate" });

    const first = await fixture.service.sendMessage(agent.id, "touch protected");
    await expect.poll(() => fixture.service.getRun(first.run.id).status).toBe("completed");
    expect(fixture.service.getRun(first.run.id).commitGate?.decision).toBe("QUARANTINED");
    expect(await readFile(path.join(agent.workspacePath, "protected.txt"), "utf8")).toBe(
      "TRUSTED_BASELINE\n",
    );
    expect(fixture.service.getAgent(agent.id)).toMatchObject({
      codexThreadId: null,
      needsReconciliation: true,
      sessionEpoch: 1,
    });

    const second = await fixture.service.sendMessage(agent.id, "make safe change");
    await expect.poll(() => fixture.service.getRun(second.run.id).status).toBe("completed");
    expect(requests[1]?.threadId).toBeNull();
    expect(requests[1]?.prompt).toContain("<commitgate_context>");
    expect(requests[1]?.prompt).toContain("make safe change");
    expect(fixture.service.getMessages(agent.id)[2]?.content).toBe("make safe change");
    expect(await fixture.service.getCommitGateReceipt(second.run.id)).toMatchObject({
      decision: "COMMITTED",
      sessionEpoch: 1,
    });
  });

  it("creates a new ROLLBACK event instead of moving history", async () => {
    const fixture = await gatedFixture(async (request) => {
      await writeFile(path.join(request.workspacePath, "README.md"), "v2\n");
      return { output: "done", threadId: "thread", usage: null };
    });
    const agent = await fixture.service.createAgent({ name: "Gate" });
    const initial = fixture.service.getVersions(agent.id)[0]!;
    const { run } = await fixture.service.sendMessage(agent.id, "make v2");
    await expect.poll(() => fixture.service.getRun(run.id).status).toBe("completed");
    const committedHead = fixture.service.getAgent(agent.id).headVersionId!;

    const result = await fixture.service.rollback(agent.id, initial.id, committedHead);
    expect(result.version).toMatchObject({
      kind: "ROLLBACK",
      parentVersionId: committedHead,
      rollbackTargetVersionId: initial.id,
    });
    expect(await readFile(path.join(agent.workspacePath, "README.md"), "utf8")).toContain(
      "# Gate workspace",
    );
    expect(result.agent).toMatchObject({
      codexThreadId: null,
      needsReconciliation: true,
    });
    expect(fixture.service.getVersions(agent.id)).toHaveLength(3);
  });

  it("restores the pre-rollback workspace and version head when the rollback database commit fails", async () => {
    const fixture = await gatedFixture(
      async (request) => {
        await writeFile(path.join(request.workspacePath, "README.md"), "v2\n");
        return { output: "done", threadId: "thread", usage: null };
      },
      (filePath) => new FailableStore(filePath),
    );
    const agent = await fixture.service.createAgent({ name: "Gate" });
    const initial = fixture.service.getVersions(agent.id)[0]!;
    const { run } = await fixture.service.sendMessage(agent.id, "make v2");
    await expect.poll(() => fixture.service.getRun(run.id).status).toBe("completed");
    const committedHead = fixture.service.getAgent(agent.id).headVersionId!;

    (fixture.store as FailableStore).failAfterSuccessfulMutations(1);
    await expect(
      fixture.service.rollback(agent.id, initial.id, committedHead),
    ).rejects.toThrow("injected database write failure");

    expect(await readFile(path.join(agent.workspacePath, "README.md"), "utf8")).toBe(
      "v2\n",
    );
    expect(fixture.service.getAgent(agent.id)).toMatchObject({
      status: "ready",
      headVersionId: committedHead,
    });
    expect(fixture.service.getVersions(agent.id).map((version) => version.kind)).toEqual([
      "AGENT_COMMIT",
      "INITIAL",
    ]);
    expect((await fixture.coordinator.versionStore.getIndex(agent.id)).versions).toHaveLength(2);
  });

  it("preserves stopped status after a successful rollback", async () => {
    const fixture = await gatedFixture(async (request) => {
      await writeFile(path.join(request.workspacePath, "README.md"), "v2\n");
      return { output: "done", threadId: "thread", usage: null };
    });
    const agent = await fixture.service.createAgent({ name: "Gate" });
    const initial = fixture.service.getVersions(agent.id)[0]!;
    const { run } = await fixture.service.sendMessage(agent.id, "make v2");
    await expect.poll(() => fixture.service.getRun(run.id).status).toBe("completed");
    const committedHead = fixture.service.getAgent(agent.id).headVersionId!;
    await fixture.service.stopAgent(agent.id);

    const result = await fixture.service.rollback(agent.id, initial.id, committedHead);
    expect(result.agent.status).toBe("stopped");
  });

  it("locks the Agent until startup recovery resolves rollback acknowledgement failure", async () => {
    const fixture = await gatedFixture(async (request) => {
      await writeFile(path.join(request.workspacePath, "README.md"), "v2\n");
      return { output: "done", threadId: "thread", usage: null };
    });
    const agent = await fixture.service.createAgent({ name: "Gate" });
    const initial = fixture.service.getVersions(agent.id)[0]!;
    const { run } = await fixture.service.sendMessage(agent.id, "make v2");
    await expect.poll(() => fixture.service.getRun(run.id).status).toBe("completed");
    const committedHead = fixture.service.getAgent(agent.id).headVersionId!;
    await writeFile(path.join(agent.workspacePath, "AGENTS.md"), "drifted platform state\n");
    const acknowledgement = vi
      .spyOn(fixture.coordinator.versionStore, "acknowledgeRollback")
      .mockRejectedValue(new Error("injected rollback acknowledgement failure"));

    await expect(
      fixture.service.rollback(agent.id, initial.id, committedHead),
    ).rejects.toThrow("CommitGate rollback acknowledgement retry failed");
    expect(fixture.service.getAgent(agent.id)).toMatchObject({
      status: "error",
      recoveryRequired: true,
      lastError: expect.stringContaining("CommitGate recovery required"),
    });
    await expect(fixture.service.startAgent(agent.id)).rejects.toMatchObject({
      statusCode: 409,
      code: "COMMITGATE_RECOVERY_REQUIRED",
    });
    await expect(
      fixture.service.rollback(agent.id, initial.id, committedHead),
    ).rejects.toMatchObject({
      statusCode: 409,
      code: "COMMITGATE_RECOVERY_REQUIRED",
    });

    acknowledgement.mockRestore();
    await fixture.service.initialize();
    expect(fixture.service.getAgent(agent.id)).toMatchObject({
      status: "ready",
      recoveryRequired: false,
      lastError: null,
    });
    expect(fixture.service.getVersions(agent.id)[0]?.kind).toBe("ROLLBACK");
    expect(await readFile(path.join(agent.workspacePath, "AGENTS.md"), "utf8")).toContain(
      "# Platform-managed Agent instructions",
    );
  });

  it("blocks stop and delete while a rollback transaction is active", async () => {
    const fixture = await gatedFixture(async (request) => {
      await writeFile(path.join(request.workspacePath, "README.md"), "v2\n");
      return { output: "done", threadId: "thread", usage: null };
    });
    const agent = await fixture.service.createAgent({ name: "Gate" });
    const initial = fixture.service.getVersions(agent.id)[0]!;
    const { run } = await fixture.service.sendMessage(agent.id, "make v2");
    await expect.poll(() => fixture.service.getRun(run.id).status).toBe("completed");
    const committedHead = fixture.service.getAgent(agent.id).headVersionId!;
    let release!: () => void;
    let entered!: () => void;
    const enteredPromise = new Promise<void>((resolve) => { entered = resolve; });
    const releasePromise = new Promise<void>((resolve) => { release = resolve; });
    const original = fixture.coordinator.versionStore.stageRollback.bind(
      fixture.coordinator.versionStore,
    );
    vi.spyOn(fixture.coordinator.versionStore, "stageRollback").mockImplementation(
      async (input) => {
        entered();
        await releasePromise;
        return original(input);
      },
    );

    const rollback = fixture.service.rollback(agent.id, initial.id, committedHead);
    await enteredPromise;
    await expect(fixture.service.stopAgent(agent.id)).rejects.toMatchObject({
      statusCode: 409,
      code: "AGENT_BUSY",
    });
    await expect(fixture.service.deleteAgent(agent.id)).rejects.toMatchObject({
      statusCode: 409,
      code: "AGENT_BUSY",
    });
    release();
    await rollback;
  });

  it("reserves delete across cancellation and archive awaits", async () => {
    const fixture = await gatedFixture(async () => ({
      output: "done",
      threadId: "thread",
      usage: null,
    }));
    const agent = await fixture.service.createAgent({ name: "Gate" });
    const initial = fixture.service.getVersions(agent.id)[0]!;
    let cancelEntered!: () => void;
    let releaseCancel!: () => void;
    let archiveEntered!: () => void;
    let releaseArchive!: () => void;
    const cancelEnteredPromise = new Promise<void>((resolve) => { cancelEntered = resolve; });
    const cancelReleasePromise = new Promise<void>((resolve) => { releaseCancel = resolve; });
    const archiveEnteredPromise = new Promise<void>((resolve) => { archiveEntered = resolve; });
    const archiveReleasePromise = new Promise<void>((resolve) => { releaseArchive = resolve; });
    vi.spyOn(fixture.gateRunner, "cancel").mockImplementation(async () => {
      cancelEntered();
      await cancelReleasePromise;
      return false;
    });
    const originalArchive = fixture.workspaces.archive.bind(fixture.workspaces);
    vi.spyOn(fixture.workspaces, "archive").mockImplementation(async (item) => {
      archiveEntered();
      await archiveReleasePromise;
      return originalArchive(item);
    });

    const deletion = fixture.service.deleteAgent(agent.id);
    await cancelEnteredPromise;
    for (const operation of [
      () => fixture.service.sendMessage(agent.id, "race"),
      () => fixture.service.updateAgent(agent.id, { name: "race" }),
      () => fixture.service.startAgent(agent.id),
      () => fixture.service.stopAgent(agent.id),
      () => fixture.service.rollback(agent.id, initial.id, initial.id),
    ]) {
      await expect(operation()).rejects.toMatchObject({
        statusCode: 409,
        code: "AGENT_BUSY",
      });
    }

    releaseCancel();
    await archiveEnteredPromise;
    await expect(
      fixture.service.rollback(agent.id, initial.id, initial.id),
    ).rejects.toMatchObject({ statusCode: 409, code: "AGENT_BUSY" });
    await expect(fixture.service.sendMessage(agent.id, "archive race")).rejects.toMatchObject({
      statusCode: 409,
      code: "AGENT_BUSY",
    });

    releaseArchive();
    await expect(deletion).resolves.toEqual({
      archivedWorkspace: expect.stringContaining(agent.id),
    });
    expect(() => fixture.service.getAgent(agent.id)).toThrow("Agent not found");
  });

  it("reserves configuration mutation through the platform instruction write", async () => {
    const fixture = await gatedFixture(async () => ({
      output: "done",
      threadId: "thread",
      usage: null,
    }));
    const agent = await fixture.service.createAgent({ name: "Gate" });
    const initial = fixture.service.getVersions(agent.id)[0]!;
    const originalWrite = fixture.workspaces.writeInstructions.bind(fixture.workspaces);
    let entered!: () => void;
    let release!: () => void;
    const enteredPromise = new Promise<void>((resolve) => { entered = resolve; });
    const releasePromise = new Promise<void>((resolve) => { release = resolve; });
    vi.spyOn(fixture.workspaces, "writeInstructions").mockImplementation(async (item) => {
      entered();
      await releasePromise;
      return originalWrite(item);
    });

    const update = fixture.service.updateAgent(agent.id, { instructions: "updated" });
    await enteredPromise;
    for (const operation of [
      () => fixture.service.sendMessage(agent.id, "race"),
      () => fixture.service.startAgent(agent.id),
      () => fixture.service.stopAgent(agent.id),
      () => fixture.service.deleteAgent(agent.id),
      () => fixture.service.rollback(agent.id, initial.id, initial.id),
    ]) {
      await expect(operation()).rejects.toMatchObject({
        statusCode: 409,
        code: "AGENT_BUSY",
      });
    }

    release();
    await expect(update).resolves.toMatchObject({ instructions: "updated" });
    expect(await readFile(path.join(agent.workspacePath, "AGENTS.md"), "utf8")).toContain(
      "updated",
    );
  });

  it("keeps all mutation admission locked until rollback acknowledgement finishes", async () => {
    const fixture = await gatedFixture(async (request) => {
      await writeFile(path.join(request.workspacePath, "README.md"), "v2\n");
      return { output: "done", threadId: "thread", usage: null };
    });
    const agent = await fixture.service.createAgent({ name: "Gate" });
    const initial = fixture.service.getVersions(agent.id)[0]!;
    const { run } = await fixture.service.sendMessage(agent.id, "make v2");
    await expect.poll(() => fixture.service.getRun(run.id).status).toBe("completed");
    await expect.poll(() => fixture.service.getAgent(agent.id).status).toBe("ready");
    const committedHead = fixture.service.getAgent(agent.id).headVersionId!;
    const originalAcknowledge = fixture.coordinator.versionStore.acknowledgeRollback.bind(
      fixture.coordinator.versionStore,
    );
    let entered!: () => void;
    let release!: () => void;
    const enteredPromise = new Promise<void>((resolve) => { entered = resolve; });
    const releasePromise = new Promise<void>((resolve) => { release = resolve; });
    vi.spyOn(fixture.coordinator.versionStore, "acknowledgeRollback").mockImplementation(
      async (runId) => {
        entered();
        await releasePromise;
        return originalAcknowledge(runId);
      },
    );

    const rollback = fixture.service.rollback(agent.id, initial.id, committedHead);
    await enteredPromise;
    const rollbackHead = fixture.service.getAgent(agent.id).headVersionId!;
    expect(fixture.service.getAgent(agent.id).status).toBe("busy");
    expect(fixture.service.getVersions(agent.id)[0]?.kind).toBe("ROLLBACK");
    for (const operation of [
      () => fixture.service.sendMessage(agent.id, "second run"),
      () => fixture.service.updateAgent(agent.id, { name: "bypass" }),
      () => fixture.service.startAgent(agent.id),
      () => fixture.service.rollback(agent.id, initial.id, rollbackHead),
    ]) {
      await expect(operation()).rejects.toMatchObject({
        statusCode: 409,
        code: "AGENT_BUSY",
      });
    }

    release();
    await expect(rollback).resolves.toMatchObject({
      agent: { status: "ready" },
      version: { kind: "ROLLBACK" },
    });
  });

  it("rolls back a promoted candidate if version projection fails before the product DB commit", async () => {
    const fixture = await gatedFixture(async (request) => {
      await writeFile(path.join(request.workspacePath, "README.md"), "candidate\n");
      return { output: "done", threadId: "thread", usage: null };
    });
    const agent = await fixture.service.createAgent({ name: "Gate" });
    const original = await readFile(path.join(agent.workspacePath, "README.md"), "utf8");
    vi.spyOn(fixture.coordinator.versionStore, "getIndex").mockRejectedValueOnce(
      new Error("injected projection failure"),
    );
    const { run } = await fixture.service.sendMessage(agent.id, "change");
    await expect.poll(() => fixture.service.getRun(run.id).status).toBe("failed");

    expect(await readFile(path.join(agent.workspacePath, "README.md"), "utf8")).toBe(original);
    expect(fixture.service.getRun(run.id).commitGate?.decision).toBe("ABORTED");
    expect(fixture.service.getVersions(agent.id)).toHaveLength(1);
  });

  it("quarantines exact credential bytes in binary output and redacts model output", async () => {
    let call = 0;
    const fixture = await gatedFixture(async (request) => {
      call += 1;
      if (call === 1) {
        await writeFile(
          path.join(request.workspacePath, "leak.bin"),
          Buffer.from([0, ...Buffer.from("test-key"), 255]),
        );
        return { output: "done", threadId: "thread", usage: null };
      }
      await writeFile(path.join(request.workspacePath, "README.md"), "safe\n");
      return { output: "model echoed test-key", threadId: "thread", usage: null };
    });
    const agent = await fixture.service.createAgent({ name: "Gate" });
    const leaked = await fixture.service.sendMessage(agent.id, "leak");
    await expect.poll(() => fixture.service.getRun(leaked.run.id).status).toBe("completed");
    expect(fixture.service.getRun(leaked.run.id).commitGate?.decision).toBe("QUARANTINED");

    const safe = await fixture.service.sendMessage(agent.id, "safe");
    await expect.poll(() => fixture.service.getRun(safe.run.id).status).toBe("completed");
    expect(fixture.service.getRun(safe.run.id).output).toContain("[REDACTED]");
    expect(fixture.service.getRun(safe.run.id).output).not.toContain("test-key");
  });

  it("records verifier-stage cancellation as RunStatus cancelled", async () => {
    let entered!: () => void;
    let release!: () => void;
    const enteredPromise = new Promise<void>((resolve) => { entered = resolve; });
    const releasePromise = new Promise<void>((resolve) => { release = resolve; });
    const fixture = await gatedFixture(
      async (request) => {
        await writeFile(path.join(request.workspacePath, "README.md"), "candidate\n");
        return { output: "done", threadId: "thread", usage: null };
      },
      (filePath) => new JsonStore(filePath),
      async () => {
        entered();
        await releasePromise;
        return [];
      },
    );
    const agent = await fixture.service.createAgent({ name: "Gate" });
    const { run } = await fixture.service.sendMessage(agent.id, "change");
    await enteredPromise;
    const stop = fixture.service.stopAgent(agent.id);
    release();
    await stop;
    expect(fixture.service.getRun(run.id).status).toBe("cancelled");
    expect(fixture.service.getRun(run.id).commitGate?.decision).toBe("ABORTED");
  });

  it("preserves a pending receipt and recovery-locks when cancellation rollback fails", async () => {
    const fixture = await gatedFixture(async (request) => {
      await writeFile(path.join(request.workspacePath, "README.md"), "promoted\n");
      return { output: "done", threadId: "thread", usage: null };
    });
    const agent = await fixture.service.createAgent({ name: "Gate" });
    const original = await readFile(path.join(agent.workspacePath, "README.md"), "utf8");
    const originalFinalize = fixture.coordinator.verifyAndFinalize.bind(
      fixture.coordinator,
    );
    let promoted!: () => void;
    let release!: () => void;
    const promotedPromise = new Promise<void>((resolve) => { promoted = resolve; });
    const releasePromise = new Promise<void>((resolve) => { release = resolve; });
    vi.spyOn(fixture.coordinator, "verifyAndFinalize").mockImplementation(
      async (...args) => {
        const result = await originalFinalize(...args);
        promoted();
        await releasePromise;
        return result;
      },
    );
    const rollbackPending = vi
      .spyOn(fixture.coordinator, "rollbackPending")
      .mockRejectedValue(new Error("injected pending rollback failure"));
    const { run } = await fixture.service.sendMessage(agent.id, "promote then cancel");
    await promotedPromise;
    const deletion = fixture.service.deleteAgent(agent.id);
    release();
    await expect(deletion).rejects.toMatchObject({
      statusCode: 409,
      code: "COMMITGATE_RECOVERY_REQUIRED",
    });
    await expect.poll(() => fixture.service.getRun(run.id).status).toBe("failed");

    expect(await fixture.service.getCommitGateReceipt(run.id)).toMatchObject({
      decision: "COMMITTED",
      promotionPendingDatabaseAck: true,
    });
    expect(await readFile(path.join(agent.workspacePath, "README.md"), "utf8")).toBe(
      "promoted\n",
    );
    expect(fixture.service.getAgent(agent.id)).toMatchObject({
      status: "error",
      recoveryRequired: true,
    });

    rollbackPending.mockRestore();
    await fixture.service.initialize();
    expect(await readFile(path.join(agent.workspacePath, "README.md"), "utf8")).toBe(
      original,
    );
    expect(fixture.service.getAgent(agent.id)).toMatchObject({
      status: "ready",
      recoveryRequired: false,
    });
    expect(await fixture.service.getCommitGateReceipt(run.id)).toMatchObject({
      decision: "ABORTED",
      promotionPendingDatabaseAck: false,
    });
  });

  it("recovery-locks a completed swap whose pending journal write failed", async () => {
    const fixture = await gatedFixture(
      async (request) => {
        await writeFile(path.join(request.workspacePath, "README.md"), "promoted\n");
        return { output: "done", threadId: "thread", usage: null };
      },
      (filePath) => new JsonStore(filePath),
      () => [],
      () =>
        new WorkspaceTransaction({
          writeJournal: async (filePath, journal) => {
            if (journal.state === "PROMOTED_PENDING_DB") {
              throw new Error("injected pending journal write failure");
            }
            await writeJsonAtomic(filePath, journal);
          },
        }),
    );
    const agent = await fixture.service.createAgent({ name: "Gate" });
    const original = await readFile(path.join(agent.workspacePath, "README.md"), "utf8");
    const { run } = await fixture.service.sendMessage(agent.id, "promote");
    await expect.poll(() => fixture.service.getRun(run.id).status).toBe("failed");

    expect(await readFile(path.join(agent.workspacePath, "README.md"), "utf8")).toBe(
      "promoted\n",
    );
    expect(fixture.service.getAgent(agent.id)).toMatchObject({
      status: "error",
      recoveryRequired: true,
    });
    expect(await fixture.service.getCommitGateReceipt(run.id)).toMatchObject({
      phase: "PENDING_PROMOTION",
      decision: "COMMITTED",
      promotionPendingDatabaseAck: true,
      proposalId: expect.any(String),
      evaluationContextHash: expect.any(String),
      evidenceDigest: expect.any(String),
      permitId: expect.any(String),
    });
    await expect(fixture.service.startAgent(agent.id)).rejects.toMatchObject({
      statusCode: 409,
      code: "COMMITGATE_RECOVERY_REQUIRED",
    });

    await fixture.service.initialize();
    expect(await readFile(path.join(agent.workspacePath, "README.md"), "utf8")).toBe(
      original,
    );
    expect(fixture.service.getAgent(agent.id)).toMatchObject({
      status: "ready",
      recoveryRequired: false,
    });
    expect(await fixture.coordinator.receiptStore.listRecoveryEvents(agent.id, run.id)).toEqual([
      expect.objectContaining({
        type: "RECOVERY_ROLLED_BACK",
        effectiveDecision: "ABORTED",
      }),
    ]);
  });

  it("rejects an authoritative assistant message when startup recovery rolls its view back", async () => {
    const fixture = await gatedFixture(async (request) => {
      await writeFile(path.join(request.workspacePath, "README.md"), "promoted\n");
      return { output: "the promoted change is complete", threadId: "thread", usage: null };
    });
    const agent = await fixture.service.createAgent({ name: "Gate" });
    const initial = fixture.service.getVersions(agent.id)[0]!;
    const acknowledge = vi
      .spyOn(fixture.coordinator, "acknowledge")
      .mockRejectedValue(new Error("injected acknowledgement outage"));
    const { run } = await fixture.service.sendMessage(agent.id, "promote");
    await expect.poll(() => fixture.service.getRun(run.id).status).toBe("failed");

    const authoritative = fixture.service
      .getMessages(agent.id)
      .find((message) => message.runId === run.id && message.role === "assistant");
    expect(authoritative).toMatchObject({ authority: "AUTHORITATIVE" });
    const failedEpoch = fixture.service.getAgent(agent.id).sessionEpoch;

    // Simulate loss of the product projection before restart. The durable
    // promotion journal and backup remain, so recovery must restore the base.
    await fixture.store.mutate((database) => {
      database.versions = database.versions.filter(
        (version) => version.agentId !== agent.id || version.id === initial.id,
      );
      const stored = database.agents.find((item) => item.id === agent.id)!;
      stored.headVersionId = initial.id;
      // Model an abrupt restart immediately after the authoritative product
      // projection, before the normal failure path could fence the session.
      stored.status = "busy";
      stored.recoveryRequired = false;
      stored.codexThreadId = "stale-promoted-thread";
      stored.sessionEpoch = Math.max(0, failedEpoch - 1);
      stored.needsReconciliation = false;
      refreshAgentViewId(stored);
    });
    const preRecoveryEpoch = fixture.service.getAgent(agent.id).sessionEpoch;
    acknowledge.mockRestore();
    await fixture.service.initialize();

    const recoveredAgent = fixture.service.getAgent(agent.id);
    const recoveredMessage = fixture.service
      .getMessages(agent.id)
      .find((message) => message.runId === run.id && message.role === "assistant");
    expect(recoveredAgent).toMatchObject({
      status: "error",
      recoveryRequired: false,
      codexThreadId: null,
      needsReconciliation: true,
      sessionEpoch: preRecoveryEpoch + 1,
    });
    expect(recoveredMessage).toMatchObject({
      authority: "REJECTED",
      viewId: recoveredAgent.currentViewId,
    });
    expect(fixture.service.getRun(run.id)).toMatchObject({
      status: "failed",
      transactionStatus: "TERMINAL",
      commitGate: {
        decision: "ABORTED",
        threadDisposition: "reset",
        nextViewId: recoveredAgent.currentViewId,
      },
    });
    expect(
      await fixture.coordinator.receiptStore.listRecoveryEvents(agent.id, run.id),
    ).toEqual([
      expect.objectContaining({
        type: "RECOVERY_ROLLED_BACK",
        originalDecision: "COMMITTED",
        effectiveDecision: "ABORTED",
      }),
    ]);
  });

  it("keeps the server available and marks only the affected Agent error for an invalid recovery policy", async () => {
    const fixture = await gatedFixture(async () => ({
      output: "done",
      threadId: "thread",
      usage: null,
    }));
    const agent = await fixture.service.createAgent({ name: "Gate" });
    await writeFile(
      path.join(
        fixture.root,
        "workspaces",
        ".commitgate",
        agent.id,
        "policy.json",
      ),
      "{broken",
      "utf8",
    );

    await expect(fixture.service.initialize()).resolves.toBeUndefined();
    expect(fixture.service.getAgent(agent.id)).toMatchObject({
      status: "error",
      codexThreadId: null,
      needsReconciliation: true,
      recoveryRequired: true,
      lastError: expect.stringContaining("CommitGate recovery required"),
    });
    for (const operation of [
      () => fixture.service.startAgent(agent.id),
      () => fixture.service.stopAgent(agent.id),
      () => fixture.service.updateAgent(agent.id, { name: "bypass" }),
      () => fixture.service.deleteAgent(agent.id),
      () => fixture.service.sendMessage(agent.id, "bypass"),
      () => fixture.service.rollback(agent.id, "target", "head"),
    ]) {
      await expect(operation()).rejects.toMatchObject({
        statusCode: 409,
        code: "COMMITGATE_RECOVERY_REQUIRED",
      });
    }

    await writeFile(
      path.join(
        fixture.root,
        "workspaces",
        ".commitgate",
        agent.id,
        "policy.json",
      ),
      JSON.stringify(defaultCommitGatePolicy),
      "utf8",
    );
    await fixture.service.initialize();
    expect(fixture.service.getAgent(agent.id)).toMatchObject({
      status: "ready",
      recoveryRequired: false,
      lastError: null,
    });
  });

  it("restores the base and records ABORTED when the product database commit fails", async () => {
    let release!: () => void;
    let entered!: () => void;
    const enteredPromise = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const releasePromise = new Promise<void>((resolve) => {
      release = resolve;
    });
    const fixture = await gatedFixture(
      async (request) => {
        await writeFile(path.join(request.workspacePath, "README.md"), "candidate\n");
        entered();
        await releasePromise;
        return { output: "done", threadId: "thread", usage: null };
      },
      (filePath) => new FailableStore(filePath),
    );
    const agent = await fixture.service.createAgent({ name: "Gate" });
    const original = await readFile(path.join(agent.workspacePath, "README.md"), "utf8");
    const { run } = await fixture.service.sendMessage(agent.id, "change");
    await enteredPromise;
    (fixture.store as FailableStore).failNextMutation();
    release();
    await expect.poll(() => fixture.service.getRun(run.id).status).toBe("failed");

    expect(await readFile(path.join(agent.workspacePath, "README.md"), "utf8")).toBe(original);
    expect(fixture.service.getRun(run.id).commitGate?.decision).toBe("ABORTED");
    expect(fixture.service.getVersions(agent.id)).toHaveLength(1);
  });

  it("returns AGENT_BUSY and HEAD_MISMATCH before starting rollback I/O", async () => {
    let entered!: () => void;
    let release!: () => void;
    const enteredPromise = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const releasePromise = new Promise<void>((resolve) => {
      release = resolve;
    });
    const fixture = await gatedFixture(async () => {
      entered();
      await releasePromise;
      return { output: "done", threadId: "thread", usage: null };
    });
    const agent = await fixture.service.createAgent({ name: "Gate" });
    const initial = fixture.service.getVersions(agent.id)[0]!;
    const { run } = await fixture.service.sendMessage(agent.id, "wait");
    await enteredPromise;
    await expect(
      fixture.service.rollback(agent.id, initial.id, initial.id),
    ).rejects.toMatchObject({ statusCode: 409, code: "AGENT_BUSY" });
    release();
    await expect.poll(() => fixture.service.getRun(run.id).status).toBe("completed");
    await expect(
      fixture.service.rollback(agent.id, initial.id, "stale-head"),
    ).rejects.toMatchObject({ statusCode: 409, code: "HEAD_MISMATCH" });
  });
});
