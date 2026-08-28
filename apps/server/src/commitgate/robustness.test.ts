import { execFile } from "node:child_process";
import { chmod, mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { AgentRunner, RunnerResult } from "../types.js";
import { CommitGateRunner } from "./commitgate-runner.js";
import { CommitGateCoordinator } from "./coordinator.js";
import { buildManifest } from "./manifest.js";
import { defaultCommitGatePolicy } from "./policy.js";
import { ReceiptStore } from "./receipt-store.js";
import { recoverCommitGate } from "./recovery.js";
import type { GateReceipt, VerifierRunner } from "./types.js";
import { validateCandidate } from "./validators.js";
import { FunctionVerifierRunner } from "./verifier-runner.js";
import { VersionStore } from "./version-store.js";
import { WorkspaceTransaction } from "./workspace-transaction.js";

const execFileAsync = promisify(execFile);
const roots: string[] = [];

async function makeWritable(root: string): Promise<void> {
  await chmod(root, 0o700);
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const item = path.join(root, entry.name);
    if (entry.isDirectory()) await makeWritable(item);
    else await chmod(item, 0o600);
  }
}

class FailableReceiptStore extends ReceiptStore {
  private failed = false;

  constructor(
    controlRoot: string,
    private readonly shouldFail: (receipt: GateReceipt) => boolean,
  ) {
    super(controlRoot);
  }

  override async put(receipt: GateReceipt): Promise<void> {
    if (!this.failed && this.shouldFail(receipt)) {
      this.failed = true;
      throw new Error("injected receipt write failure");
    }
    await super.put(receipt);
  }
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map(async (root) => {
    await makeWritable(root).catch(() => undefined);
    await rm(root, { recursive: true, force: true });
  }));
});

async function workspaceFixture() {
  const root = await mkdtemp(path.join(tmpdir(), "commitgate-robustness-"));
  roots.push(root);
  const workspaceRoot = path.join(root, "workspaces");
  const workspace = path.join(workspaceRoot, "agent");
  await mkdir(workspace, { recursive: true });
  await writeFile(path.join(workspace, "README.md"), "base\n");
  await writeFile(path.join(workspace, "AGENTS.md"), "managed\n");
  return { root, workspaceRoot, workspace };
}

describe("CommitGate fail-closed robustness", () => {
  it("rejects file budgets, canaries, and platform-managed edits together", async () => {
    const { workspace } = await workspaceFixture();
    const policy = {
      ...defaultCommitGatePolicy,
      maxChangedFiles: 1,
      canaryPatterns: ["CANARY_VALUE"],
    };
    const base = await buildManifest(workspace, policy);
    await writeFile(path.join(workspace, "one.txt"), "CANARY_VALUE\n");
    await writeFile(path.join(workspace, "two.txt"), "second\n");
    await writeFile(path.join(workspace, "AGENTS.md"), "candidate managed edit\n");
    const candidate = await buildManifest(workspace, policy);
    const validation = await validateCandidate(policy, base, candidate, workspace);
    expect(validation.failures).toEqual(
      expect.arrayContaining([
        "DIFF_FILE_BUDGET_EXCEEDED",
        "CANARY_DETECTED:one.txt",
        "PLATFORM_MANAGED_PATH_CHANGED:AGENTS.md",
      ]),
    );
  });

  it("aborts on missing verifier exit evidence", async () => {
    const { workspaceRoot, workspace } = await workspaceFixture();
    const coordinator = new CommitGateCoordinator({
      workspaceRoot,
      verifier: new FunctionVerifierRunner(() => [
        {
          id: "contract",
          status: "ERROR",
          exitCode: null,
          durationMs: 30_000,
          output: "no terminal exit status",
          timedOut: true,
        },
      ]),
    });
    const prepared = await coordinator.prepare({
      runId: "evidence-error",
      agentId: "agent",
      persistentPath: workspace,
      policy: {
        ...defaultCommitGatePolicy,
        requiredChecks: [{ id: "contract", runner: "node", entrypoint: "x.mjs", args: [], timeoutMs: 10_000, scratchBytes: 1_048_576 }],
      },
    });
    await writeFile(path.join(prepared.candidatePath, "README.md"), "candidate\n");
    const result = await coordinator.verifyAndFinalize(prepared);
    expect(result.receipt).toMatchObject({
      decision: "ABORTED",
      failureClass: "evidence_broken",
    });
    expect(result.receipt.reasonCodes).toContain("TRUSTED_CHECK_INCOMPLETE:contract");
  });

  it("aborts PASS without exit zero and duplicate results as broken evidence", async () => {
    const { workspaceRoot, workspace } = await workspaceFixture();
    const coordinator = new CommitGateCoordinator({
      workspaceRoot,
      verifier: new FunctionVerifierRunner(() => [
        {
          id: "first",
          status: "PASS",
          exitCode: null,
          durationMs: 1,
          output: "missing exit",
          timedOut: false,
        },
        {
          id: "first",
          status: "PASS",
          exitCode: 0,
          durationMs: 1,
          output: "duplicate",
          timedOut: false,
        },
      ]),
    });
    const prepared = await coordinator.prepare({
      runId: "invalid-check-set",
      agentId: "agent",
      persistentPath: workspace,
      policy: {
        ...defaultCommitGatePolicy,
        requiredChecks: [
          { id: "first", runner: "node", entrypoint: "first.mjs", args: [], timeoutMs: 10_000, scratchBytes: 1_048_576 },
          { id: "second", runner: "node", entrypoint: "second.mjs", args: [], timeoutMs: 10_000, scratchBytes: 1_048_576 },
        ],
      },
    });
    const result = await coordinator.verifyAndFinalize(prepared);
    expect(result.receipt).toMatchObject({
      decision: "ABORTED",
      failureClass: "evidence_broken",
      evidence: { trustedChecks: "partial" },
    });
    expect(result.receipt.reasonCodes).toEqual(
      expect.arrayContaining([
        "TRUSTED_CHECK_EVIDENCE_INVALID:first",
        "TRUSTED_CHECK_DUPLICATE:first",
        "TRUSTED_CHECK_RESULT_MISSING:second",
      ]),
    );
  });

  it("aborts when the verifier image or trusted context drifts after checks", async () => {
    const { workspaceRoot, workspace } = await workspaceFixture();
    let drifted = false;
    const verifier: VerifierRunner = {
      describeExecutionEnvironment: () => ({
        imageReference: "fixture:latest",
        imageId: drifted ? "image-b" : "image-a",
        imageDigest: drifted ? "digest-b" : "digest-a",
        configHash: "config",
        checkBundleHash: drifted ? "bundle-b" : "bundle-a",
      }),
      run: async () => {
        drifted = true;
        return [];
      },
    };
    const coordinator = new CommitGateCoordinator({ workspaceRoot, verifier });
    const prepared = await coordinator.prepare({
      runId: "context-drift",
      agentId: "agent",
      persistentPath: workspace,
    });
    await writeFile(path.join(prepared.candidatePath, "README.md"), "candidate\n");
    const result = await coordinator.verifyAndFinalize(prepared);
    expect(result.receipt).toMatchObject({
      decision: "ABORTED",
      failureClass: "evidence_broken",
    });
    expect(result.receipt.reasonCodes).toContain("EVALUATION_CONTEXT_CHANGED");
    expect(await readFile(path.join(workspace, "README.md"), "utf8")).toBe("base\n");
  });

  it("promotes sealed bytes even if the obsolete candidate path is recreated and modified", async () => {
    const { workspaceRoot, workspace } = await workspaceFixture();
    let candidatePath = "";
    const coordinator = new CommitGateCoordinator({
      workspaceRoot,
      verifier: new FunctionVerifierRunner(async () => {
        await mkdir(candidatePath, { recursive: true });
        await writeFile(path.join(candidatePath, "README.md"), "mutated during verify\n");
        return [];
      }),
    });
    const prepared = await coordinator.prepare({
      runId: "candidate-mutation",
      agentId: "agent",
      persistentPath: workspace,
    });
    candidatePath = prepared.candidatePath;
    await writeFile(path.join(candidatePath, "README.md"), "candidate before verify\n");
    const result = await coordinator.verifyAndFinalize(prepared);
    expect(result.receipt).toMatchObject({
      decision: "COMMITTED",
      failureClass: null,
      permitState: "CONSUMED",
    });
    expect(await readFile(path.join(workspace, "README.md"), "utf8")).toBe(
      "candidate before verify\n",
    );
    await coordinator.rollbackPending(prepared.runId);
  });

  it("makes repeated finalization idempotent", async () => {
    const { workspaceRoot, workspace } = await workspaceFixture();
    const coordinator = new CommitGateCoordinator({
      workspaceRoot,
      verifier: new FunctionVerifierRunner(() => []),
    });
    const prepared = await coordinator.prepare({
      runId: "idempotent",
      agentId: "agent",
      persistentPath: workspace,
    });
    await writeFile(path.join(prepared.candidatePath, "README.md"), "candidate\n");
    const first = await coordinator.verifyAndFinalize(prepared);
    const second = await coordinator.verifyAndFinalize(prepared);
    expect(second.receipt).toEqual(first.receipt);
    expect(second.receipt).toMatchObject({ decision: "COMMITTED", promotionPendingDatabaseAck: true });
    await coordinator.rollbackPending(prepared.runId);
  });

  it("aborts an already-cancelled verification and preserves the base", async () => {
    const { workspaceRoot, workspace } = await workspaceFixture();
    const coordinator = new CommitGateCoordinator({
      workspaceRoot,
      verifier: new FunctionVerifierRunner(() => []),
    });
    const prepared = await coordinator.prepare({
      runId: "cancelled",
      agentId: "agent",
      persistentPath: workspace,
    });
    await writeFile(path.join(prepared.candidatePath, "README.md"), "candidate\n");
    const controller = new AbortController();
    controller.abort(new Error("cancel requested"));
    const result = await coordinator.verifyAndFinalize(prepared, controller.signal);
    expect(result.receipt.decision).toBe("ABORTED");
    expect(await readFile(path.join(workspace, "README.md"), "utf8")).toBe("base\n");
  });

  it("redacts credential-shaped verifier output in persisted receipts", async () => {
    const { root } = await workspaceFixture();
    const store = new ReceiptStore(path.join(root, "control"), ["opaque-fixture-secret"]);
    const receipt: GateReceipt = {
      schemaVersion: 1,
      runId: "redaction",
      agentId: "agent",
      phase: "TERMINAL",
      decision: "QUARANTINED",
      failureClass: "evidence_broken",
      reasonCodes: ["verifier returned ARK_API_KEY=supersecretvalue"],
      baseSnapshotHash: "base",
      candidateSnapshotHash: "candidate",
      patchHash: "patch",
      finalSnapshotHash: "base",
      policyHash: "policy",
      evidence: { static: "complete", trustedChecks: "partial" },
      checks: [
        {
          id: "check",
          status: "ERROR",
          exitCode: null,
          durationMs: 1,
          output: "Bearer short-test-token and opaque-fixture-secret",
          timedOut: false,
        },
      ],
      changedPaths: [],
      threadDisposition: "reset",
      candidateCleanup: "deleted",
      sessionEpoch: 1,
      versionId: null,
      promotionPendingDatabaseAck: false,
      startedAt: new Date(0).toISOString(),
      completedAt: new Date(1).toISOString(),
    };
    await store.put(receipt);
    const stored = await store.get("agent", "redaction");
    expect(JSON.stringify(stored)).not.toContain("supersecretvalue");
    expect(JSON.stringify(stored)).not.toContain("short-test-token");
    expect(JSON.stringify(stored)).not.toContain("opaque-fixture-secret");
    expect(JSON.stringify(stored)).toContain("[REDACTED]");
  });

  it("cleans orphan candidate and verify directories during startup recovery", async () => {
    const { workspaceRoot } = await workspaceFixture();
    const agentRoot = path.join(workspaceRoot, ".commitgate", "agent");
    await mkdir(path.join(agentRoot, "candidates", "orphan"), { recursive: true });
    await mkdir(path.join(agentRoot, "verify", "orphan"), { recursive: true });
    await writeFile(
      path.join(agentRoot, "policy.json"),
      JSON.stringify(defaultCommitGatePolicy),
      "utf8",
    );
    const report = await recoverCommitGate({
      workspaceRoot,
      transaction: new WorkspaceTransaction(),
    });
    expect(report.healthy).toBe(true);
    expect(report.actions.filter((action) => action.action === "cleaned")).toHaveLength(2);
  });

  it("acknowledges a database-committed rollback without appending a fake commit event", async () => {
    const { workspaceRoot, workspace } = await workspaceFixture();
    const controlRoot = path.join(workspaceRoot, ".commitgate");
    const agentRoot = path.join(controlRoot, "agent");
    await mkdir(agentRoot, { recursive: true });
    await writeFile(
      path.join(agentRoot, "policy.json"),
      JSON.stringify(defaultCommitGatePolicy),
      "utf8",
    );
    const versions = new VersionStore(controlRoot, {}, new WorkspaceTransaction());
    const initial = await versions.initializeAgent(
      "agent",
      workspace,
      defaultCommitGatePolicy,
    );
    await writeFile(path.join(workspace, "README.md"), "v2\n");
    const commit = await versions.recordCommit(
      "agent",
      workspace,
      defaultCommitGatePolicy,
      "commit-v2",
    );
    const rollback = await versions.stageRollback({
      agentId: "agent",
      workspacePath: workspace,
      policy: defaultCommitGatePolicy,
      targetVersionId: initial.id,
      expectedHeadVersionId: commit.id,
      runId: "rollback-crash-after-db",
    });
    const databaseHeadHash = (await buildManifest(workspace, defaultCommitGatePolicy)).hash;

    const report = await recoverCommitGate({
      workspaceRoot,
      transaction: new WorkspaceTransaction(),
      getDatabaseHead: () => ({
        versionId: rollback.id,
        liveStateHash: databaseHeadHash,
        runId: "rollback-crash-after-db",
        kind: "ROLLBACK",
      }),
    });

    expect(report.healthy).toBe(true);
    expect(report.actions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          runId: "rollback-crash-after-db",
          action: "acknowledged",
        }),
      ]),
    );
    const index = await versions.getIndex("agent");
    expect(index.headVersionId).toBe(rollback.id);
    expect(index.versions.map((version) => version.kind)).toEqual([
      "INITIAL",
      "AGENT_COMMIT",
      "ROLLBACK",
    ]);
    expect(await readFile(path.join(workspace, "README.md"), "utf8")).toBe("base\n");
  });

  it("rolls back a no-op promotion when the database still points at the prior event", async () => {
    const { workspaceRoot, workspace } = await workspaceFixture();
    const coordinator = new CommitGateCoordinator({
      workspaceRoot,
      verifier: new FunctionVerifierRunner(() => []),
    });
    const prepared = await coordinator.prepare({
      runId: "noop-promotion-before-db",
      agentId: "agent",
      persistentPath: workspace,
    });
    await coordinator.verifyAndFinalize(prepared);
    await coordinator.stageAcknowledge(prepared.runId);
    const beforeRecovery = await coordinator.versionStore.getIndex("agent");
    const initial = beforeRecovery.versions.find((version) => version.kind === "INITIAL")!;
    expect(beforeRecovery.versions).toHaveLength(2);
    expect(beforeRecovery.versions[1]?.snapshotHash).toBe(initial.snapshotHash);
    const unchangedLiveHash = (await buildManifest(workspace, defaultCommitGatePolicy)).hash;
    expect(unchangedLiveHash).toBe(prepared.baseSnapshotHash);
    expect(
      JSON.parse(
        await readFile(
          path.join(
            workspaceRoot,
            ".commitgate",
            "agent",
            "journals",
            prepared.runId + ".json",
          ),
          "utf8",
        ),
      ).targetHash,
    ).toBe(unchangedLiveHash);

    const report = await recoverCommitGate({
      workspaceRoot,
      transaction: new WorkspaceTransaction(),
      getDatabaseHead: () => ({
        versionId: initial.id,
        liveStateHash: unchangedLiveHash,
        runId: null,
        kind: "INITIAL",
      }),
    });

    expect(report.actions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          runId: prepared.runId,
          action: "rolled_back",
        }),
      ]),
    );
    const afterRecovery = await coordinator.versionStore.getIndex("agent");
    expect(afterRecovery.headVersionId).toBe(initial.id);
    expect(afterRecovery.versions).toHaveLength(1);
  });

  it("rolls back a same-snapshot rollback when the database head event was not advanced", async () => {
    const { workspaceRoot, workspace } = await workspaceFixture();
    const controlRoot = path.join(workspaceRoot, ".commitgate");
    const agentRoot = path.join(controlRoot, "agent");
    await mkdir(agentRoot, { recursive: true });
    await writeFile(
      path.join(agentRoot, "policy.json"),
      JSON.stringify(defaultCommitGatePolicy),
      "utf8",
    );
    const versions = new VersionStore(controlRoot, {}, new WorkspaceTransaction());
    const initial = await versions.initializeAgent(
      "agent",
      workspace,
      defaultCommitGatePolicy,
    );
    const priorHead = await versions.recordCommit(
      "agent",
      workspace,
      defaultCommitGatePolicy,
      "noop-commit",
    );
    const staged = await versions.stageRollback({
      agentId: "agent",
      workspacePath: workspace,
      policy: defaultCommitGatePolicy,
      targetVersionId: initial.id,
      expectedHeadVersionId: priorHead.id,
      runId: "noop-rollback-before-db",
    });
    expect(staged.snapshotHash).toBe(priorHead.snapshotHash);
    const unchangedLiveHash = (await buildManifest(workspace, defaultCommitGatePolicy)).hash;
    expect(
      JSON.parse(
        await readFile(
          path.join(agentRoot, "journals", "noop-rollback-before-db.json"),
          "utf8",
        ),
      ).targetHash,
    ).toBe(unchangedLiveHash);

    const report = await recoverCommitGate({
      workspaceRoot,
      transaction: new WorkspaceTransaction(),
      getDatabaseHead: () => ({
        versionId: priorHead.id,
        liveStateHash: unchangedLiveHash,
        runId: priorHead.runId,
        kind: priorHead.kind,
      }),
    });

    expect(report.actions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          runId: "noop-rollback-before-db",
          action: "rolled_back",
        }),
      ]),
    );
    expect((await versions.head("agent"))?.id).toBe(priorHead.id);
  });

  it("restores the base before recording ABORTED when the first promoted receipt write fails", async () => {
    const { workspaceRoot, workspace } = await workspaceFixture();
    const controlRoot = path.join(workspaceRoot, ".commitgate");
    const receipts = new FailableReceiptStore(controlRoot, () => true);
    const coordinator = new CommitGateCoordinator({
      workspaceRoot,
      controlRoot,
      receiptStore: receipts,
      verifier: new FunctionVerifierRunner(() => []),
    });
    const prepared = await coordinator.prepare({
      runId: "receipt-before-db",
      agentId: "agent",
      persistentPath: workspace,
    });
    await writeFile(path.join(prepared.candidatePath, "README.md"), "candidate\n");

    const result = await coordinator.verifyAndFinalize(prepared);

    expect(result.receipt.decision).toBe("ABORTED");
    expect(result.receipt.finalSnapshotHash).toBe(prepared.baseSnapshotHash);
    expect(await readFile(path.join(workspace, "README.md"), "utf8")).toBe("base\n");
  });

  it("recovers forward after product DB commit when final receipt cleanup fails", async () => {
    const { workspaceRoot, workspace } = await workspaceFixture();
    const controlRoot = path.join(workspaceRoot, ".commitgate");
    const receipts = new FailableReceiptStore(
      controlRoot,
      (receipt) => receipt.promotionPendingDatabaseAck === false,
    );
    const coordinator = new CommitGateCoordinator({
      workspaceRoot,
      controlRoot,
      receiptStore: receipts,
      verifier: new FunctionVerifierRunner(() => []),
    });
    const prepared = await coordinator.prepare({
      runId: "receipt-after-db",
      agentId: "agent",
      persistentPath: workspace,
    });
    await writeFile(path.join(prepared.candidatePath, "README.md"), "candidate\n");
    const finalization = await coordinator.verifyAndFinalize(prepared);
    const staged = await coordinator.stageAcknowledge(prepared.runId);
    await expect(coordinator.acknowledge(prepared.runId)).rejects.toThrow(
      "injected receipt write failure",
    );

    expect(await readFile(path.join(workspace, "README.md"), "utf8")).toBe("candidate\n");
    expect((await coordinator.versionStore.list("agent"))[0]).toMatchObject({
      kind: "AGENT_COMMIT",
      runId: prepared.runId,
    });
    expect(await receipts.get("agent", prepared.runId)).toMatchObject({
      decision: "COMMITTED",
      promotionPendingDatabaseAck: true,
    });

    const report = await recoverCommitGate({
      workspaceRoot,
      transaction: new WorkspaceTransaction(),
      getDatabaseHead: () => ({
        versionId: staged.receipt.versionId!,
        liveStateHash: finalization.receipt.finalSnapshotHash,
        runId: prepared.runId,
        kind: "AGENT_COMMIT",
      }),
    });
    expect(report.healthy).toBe(true);
    expect(await receipts.get("agent", prepared.runId)).toMatchObject({
      decision: "COMMITTED",
      promotionPendingDatabaseAck: false,
    });
    expect((await coordinator.versionStore.list("agent"))).toHaveLength(2);
  });

  it("isolates a corrupt journal as manual intervention instead of aborting recovery", async () => {
    const { workspaceRoot } = await workspaceFixture();
    const agentRoot = path.join(workspaceRoot, ".commitgate", "agent");
    await mkdir(path.join(agentRoot, "journals"), { recursive: true });
    await writeFile(
      path.join(agentRoot, "policy.json"),
      JSON.stringify(defaultCommitGatePolicy),
      "utf8",
    );
    await writeFile(path.join(agentRoot, "journals", "broken.json"), "{truncated", "utf8");

    const report = await recoverCommitGate({
      workspaceRoot,
      transaction: new WorkspaceTransaction(),
    });

    expect(report.healthy).toBe(false);
    expect(report.actions).toContainEqual(
      expect.objectContaining({
        agentId: "agent",
        runId: "broken",
        action: "manual_intervention",
      }),
    );
  });

  it("rejects a FIFO special file without following or reading it", async () => {
    const { workspace } = await workspaceFixture();
    const fifo = path.join(workspace, "pipe");
    await execFileAsync("mkfifo", [fifo]);
    await expect(buildManifest(workspace, defaultCommitGatePolicy)).rejects.toThrow(
      "SPECIAL_FILE:pipe",
    );
  });

  it("keeps the generic trusted sanity check compatible with a v1 workspace", async () => {
    const { workspace } = await workspaceFixture();
    await writeFile(
      path.join(workspace, "AGENTS.md"),
      "# Platform-managed Agent instructions\n",
      "utf8",
    );
    const result = await execFileAsync(
      process.execPath,
      [
        fileURLToPath(
          new URL("../../../../eval/trusted-checks/workspace-sanity.mjs", import.meta.url),
        ),
      ],
      {
        env: { ...process.env, COMMITGATE_CANDIDATE_ROOT: workspace },
      },
    );
    expect(result.stdout).toContain("workspace-sanity: PASS");
  });

  it("cancels an active decorated runner and emits an ABORTED receipt", async () => {
    const { workspaceRoot, workspace } = await workspaceFixture();
    let finish!: (result: RunnerResult) => void;
    let entered!: () => void;
    const enteredPromise = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const pending = new Promise<RunnerResult>((resolve) => {
      finish = resolve;
    });
    const inner: AgentRunner = {
      run: async () => {
        entered();
        return pending;
      },
      cancel: async () => {
        finish({ output: "cancelled", threadId: "stale", usage: null });
        return true;
      },
      isAvailable: async () => true,
    };
    const coordinator = new CommitGateCoordinator({
      workspaceRoot,
      verifier: new FunctionVerifierRunner(() => []),
    });
    const runner = new CommitGateRunner(inner, coordinator);
    const run = runner.run({
      runId: "active-cancel",
      agentId: "agent",
      workspacePath: workspace,
      prompt: "work",
      threadId: "old",
    });
    await enteredPromise;
    expect(await runner.cancel("agent")).toBe(true);
    await expect(run).rejects.toMatchObject({ name: "RunCancelledError" });
    expect(await coordinator.receiptStore.get("agent", "active-cancel")).toMatchObject({
      decision: "ABORTED",
      threadDisposition: "reset",
    });
  });

  it("normalizes cancellation requested while candidate preparation is in flight", async () => {
    const { workspaceRoot, workspace } = await workspaceFixture();
    const inner: AgentRunner = {
      run: async () => ({ output: "unexpected", threadId: "stale", usage: null }),
      cancel: async () => false,
      isAvailable: async () => true,
    };
    const coordinator = new CommitGateCoordinator({
      workspaceRoot,
      verifier: new FunctionVerifierRunner(() => []),
    });
    const originalPrepare = coordinator.prepare.bind(coordinator);
    let entered!: () => void;
    let release!: () => void;
    const enteredPromise = new Promise<void>((resolve) => { entered = resolve; });
    const releasePromise = new Promise<void>((resolve) => { release = resolve; });
    vi.spyOn(coordinator, "prepare").mockImplementation(async (input) => {
      entered();
      await releasePromise;
      return originalPrepare(input);
    });
    const runner = new CommitGateRunner(inner, coordinator);
    const run = runner.run({
      runId: "prepare-cancel",
      agentId: "agent",
      workspacePath: workspace,
      prompt: "work",
      threadId: null,
    });
    await enteredPromise;
    expect(await runner.cancel("agent")).toBe(true);
    release();
    await expect(run).rejects.toMatchObject({ name: "RunCancelledError" });
    expect(await coordinator.receiptStore.get("agent", "prepare-cancel")).toMatchObject({
      decision: "ABORTED",
      threadDisposition: "reset",
    });
  });
});
