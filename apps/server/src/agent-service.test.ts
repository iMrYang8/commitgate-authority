import { mkdtemp } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { AgentService } from "./agent-service.js";
import { loadConfig } from "./config.js";
import { refreshAgentViewId } from "./state-view.js";
import { JsonStore } from "./store.js";
import { TransitionEventLog } from "./transition-log.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "./types.js";
import { WorkspaceManager } from "./workspace.js";

class FakeRunner implements AgentRunner {
  async run(request: RunnerRequest): Promise<RunnerResult> {
    return {
      output: "Completed: " + request.prompt,
      threadId: request.threadId ?? "fake-thread",
      usage: { inputTokens: 12, outputTokens: 5 },
    };
  }
  async cancel(): Promise<boolean> {
    return false;
  }
  async isAvailable(): Promise<boolean> {
    return true;
  }
}

const temporaryDirectories: string[] = [];

class QueuedStartBarrierStore extends JsonStore {
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

  override async mutate<T>(
    mutation: Parameters<JsonStore["mutate"]>[0],
  ): Promise<T> {
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

afterEach(async () => {
  const { rm } = await import("node:fs/promises");
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

async function makeFixture(
  runner: AgentRunner = new FakeRunner(),
  makeStore: (filePath: string) => JsonStore = (filePath) => new JsonStore(filePath),
) {
  const root = await mkdtemp(path.join(tmpdir(), "launchpad-test-"));
  temporaryDirectories.push(root);
  const config = loadConfig({
    NODE_ENV: "test",
    APP_DATA_DIR: path.join(root, "data"),
    AGENT_WORKSPACE_ROOT: path.join(root, "workspaces"),
    CODEX_HOME: path.join(root, "codex"),
    COMMITGATE_ENABLED: "false",
    ARK_API_KEY: "test-key",
    ARK_MODEL: "ep-test",
  });
  const store = makeStore(path.join(root, "data", "db.json"));
  const service = new AgentService(
    config,
    store,
    new WorkspaceManager(path.join(root, "workspaces")),
    runner,
  );
  await service.initialize();
  return { root, config, store, service };
}

async function makeService(runner: AgentRunner = new FakeRunner()): Promise<AgentService> {
  return (await makeFixture(runner)).service;
}

describe("Agent lifecycle", () => {
  it("creates, updates, stops, starts and deletes an Agent", async () => {
    const service = await makeService();
    const agent = await service.createAgent({ name: "Builder" });
    const initialView = agent.currentViewId;
    expect(service.listAgents()).toHaveLength(1);
    const updated = await service.updateAgent(agent.id, { description: "Builds apps" });
    expect(updated.description).toBe("Builds apps");
    expect(updated.currentViewId).not.toBe(initialView);
    expect(updated.stateGeneration).toBe(agent.stateGeneration + 1);
    expect((await service.stopAgent(agent.id)).status).toBe("stopped");
    expect((await service.startAgent(agent.id)).status).toBe("ready");
    await service.deleteAgent(agent.id);
    expect(service.listAgents()).toHaveLength(0);
  });

  it("persists a playground conversation", async () => {
    const service = await makeService();
    const agent = await service.createAgent({ name: "Coder" });
    const { run } = await service.sendMessage(agent.id, "write hello world");
    await expect.poll(() => service.getRun(run.id).status).toBe("completed");
    const messages = service.getMessages(agent.id);
    expect(messages.map((message) => message.role)).toEqual(["user", "assistant"]);
    expect(messages[1]?.content).toContain("write hello world");
    expect(messages.map((message) => message.authority)).toEqual([
      "INPUT",
      "AUTHORITATIVE",
    ]);
    expect(service.getRun(run.id)).toMatchObject({
      transactionStatus: "TERMINAL",
      staleCallback: false,
    });
    expect(service.getAgent(agent.id).codexThreadId).toBe("fake-thread");
  });

  it("atomically accepts only one concurrent run per Agent", async () => {
    let finish!: (result: RunnerResult) => void;
    const pending = new Promise<RunnerResult>((resolve) => {
      finish = resolve;
    });
    const runner: AgentRunner = {
      run: () => pending,
      cancel: async () => false,
      isAvailable: async () => true,
    };
    const service = await makeService(runner);
    const agent = await service.createAgent({ name: "Concurrent" });
    const attempts = await Promise.allSettled([
      service.sendMessage(agent.id, "first"),
      service.sendMessage(agent.id, "second"),
    ]);

    expect(attempts.filter((attempt) => attempt.status === "fulfilled")).toHaveLength(1);
    const rejected = attempts.find((attempt) => attempt.status === "rejected");
    expect(rejected).toMatchObject({ reason: { statusCode: 409 } });
    expect(service.getMessages(agent.id)).toHaveLength(1);

    finish({ output: "done", threadId: "thread", usage: null });
    const accepted = attempts.find((attempt) => attempt.status === "fulfilled");
    if (accepted?.status === "fulfilled") {
      await expect.poll(() => service.getRun(accepted.value.run.id).status).toBe("completed");
    }
  });

  it("does not let start reset a busy Agent and admit a second run", async () => {
    let finish!: (result: RunnerResult) => void;
    const pending = new Promise<RunnerResult>((resolve) => {
      finish = resolve;
    });
    const service = await makeService({
      run: () => pending,
      cancel: async () => false,
      isAvailable: async () => true,
    });
    const agent = await service.createAgent({ name: "Busy" });
    const { run } = await service.sendMessage(agent.id, "first");

    await expect(service.startAgent(agent.id)).rejects.toMatchObject({ statusCode: 409 });
    await expect(service.sendMessage(agent.id, "second")).rejects.toMatchObject({
      statusCode: 409,
    });

    finish({ output: "done", threadId: "thread", usage: null });
    await expect.poll(() => service.getRun(run.id).status).toBe("completed");
  });

  it("records a stale callback when the active lease has been replaced without mutating authoritative state", async () => {
    let started!: () => void;
    let finish!: (result: RunnerResult) => void;
    const startedPromise = new Promise<void>((resolve) => {
      started = resolve;
    });
    const pending = new Promise<RunnerResult>((resolve) => {
      finish = resolve;
    });
    const fixture = await makeFixture({
      run: async () => {
        started();
        return pending;
      },
      cancel: async () => false,
      isAvailable: async () => true,
    });
    const agent = await fixture.service.createAgent({ name: "Lease fence" });
    const { run } = await fixture.service.sendMessage(agent.id, "old callback");
    await startedPromise;

    const replacementLease = "replacement-active-lease";
    await fixture.store.mutate((database) => {
      const storedAgent = database.agents.find((item) => item.id === agent.id)!;
      storedAgent.activeRunLeaseId = replacementLease;
    });
    const headBeforeCallback = fixture.service.getAgent(agent.id).headVersionId;
    const viewBeforeCallback = fixture.service.getAgent(agent.id).currentViewId;

    finish({ output: "late result must be ignored", threadId: "late-thread", usage: null });
    const log = new TransitionEventLog(
      path.join(fixture.config.commitGateControlRoot, "transition-events"),
    );
    await expect
      .poll(async () => (await log.transition(agent.id, run.id)).length)
      .toBe(1);

    expect(await log.transition(agent.id, run.id)).toEqual([
      expect.objectContaining({
        type: "STALE_CALLBACK_RECORDED",
        payload: expect.objectContaining({
          callbackKind: "terminal-completed",
          runLeaseId: run.runLeaseId,
        }),
      }),
    ]);
    expect(fixture.service.getRun(run.id)).toMatchObject({
      status: "running",
      output: null,
      completedAt: null,
      staleCallback: false,
    });
    expect(fixture.service.getAgent(agent.id)).toMatchObject({
      status: "busy",
      activeRunLeaseId: replacementLease,
      headVersionId: headBeforeCallback,
      currentViewId: viewBeforeCallback,
    });
    expect(fixture.service.getMessages(agent.id).map((message) => message.role)).toEqual([
      "user",
    ]);
  });

  it("rebinds a queued follow-up from submittedViewId to the current View and fresh session", async () => {
    const requests: RunnerRequest[] = [];
    const fixture = await makeFixture(
      {
        run: async (request) => {
          requests.push(request);
          return { output: "rebound", threadId: "fresh-thread", usage: null };
        },
        cancel: async () => false,
        isAvailable: async () => true,
      },
      (filePath) => new QueuedStartBarrierStore(filePath),
    );
    const store = fixture.store as QueuedStartBarrierStore;
    const agent = await fixture.service.createAgent({ name: "Queued rebind" });
    await store.mutate((database) => {
      const storedAgent = database.agents.find((item) => item.id === agent.id)!;
      storedAgent.codexThreadId = "thread-bound-to-submitted-view";
      storedAgent.needsReconciliation = false;
    });

    const queuedStartEntered = store.armQueuedStart();
    const { run } = await fixture.service.sendMessage(agent.id, "follow current state");
    await queuedStartEntered;
    const submittedViewId = fixture.service.getRun(run.id).submittedViewId;

    await store.mutate((database) => {
      const storedAgent = database.agents.find((item) => item.id === agent.id)!;
      storedAgent.sessionEpoch += 1;
      storedAgent.stateGeneration += 1;
      // Deliberately retain the stale thread: the execution-time rebind must
      // fence it rather than relying on the transition producer to clear it.
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
    expect(requests[0]?.prompt).toContain("<commitgate_context>");
    expect(requests[0]?.prompt).toContain(`view_id=${reboundViewId}`);
    expect(fixture.service.getRun(run.id)).toMatchObject({
      submittedViewId,
      baseViewId: reboundViewId,
      status: "completed",
      staleCallback: false,
    });
    expect(
      fixture.service.getMessages(agent.id).find((message) => message.role === "user"),
    ).toMatchObject({ viewId: reboundViewId });
  });

  it("rejects a cross-Agent rollback version before reserving the target Agent", async () => {
    const fixture = await makeFixture();
    const agent = await fixture.service.createAgent({ name: "Rollback target" });
    await fixture.store.mutate((database) => {
      database.versions.push({
        id: "foreign-version",
        agentId: "different-agent",
        sequence: 1,
        parentVersionId: null,
        kind: "INITIAL",
        snapshotHash: "a".repeat(64),
        liveStateHash: "a".repeat(64),
        pathPolicyHash: "b".repeat(64),
        sourceRunId: null,
        sourceReceiptId: null,
        rollbackTargetVersionId: null,
        changedPaths: [],
        snapshotAvailable: true,
        generation: 1,
        viewId: null,
        transitionEventId: null,
        createdAt: new Date().toISOString(),
      });
    });

    await expect(
      fixture.service.rollback(agent.id, "foreign-version", "unused-head"),
    ).rejects.toMatchObject({ statusCode: 404, code: "VERSION_NOT_FOUND" });
    expect(fixture.service.getAgent(agent.id)).toMatchObject({ status: "ready" });
  });
});
