import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { defaultCommitGatePolicy } from "./policy.js";
import { VersionStore, VersionStoreError } from "./version-store.js";
import { WorkspaceTransaction } from "./workspace-transaction.js";

function makeVersionStore(
  controlRoot: string,
  options: ConstructorParameters<typeof VersionStore>[1] = {},
): VersionStore {
  return new VersionStore(controlRoot, options, new WorkspaceTransaction());
}

const roots: string[] = [];
afterEach(async () => {
  const { rm } = await import("node:fs/promises");
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("VersionStore", () => {
  it("creates append-only events, preserves managed state, and removes ephemeral state", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-version-"));
    roots.push(root);
    const workspaceRoot = path.join(root, "workspaces");
    const workspace = path.join(workspaceRoot, "agent");
    await mkdir(path.join(workspace, "node_modules"), { recursive: true });
    await writeFile(path.join(workspace, "app.txt"), "v1\n");
    await writeFile(path.join(workspace, "AGENTS.md"), "managed-v1\n");
    await writeFile(path.join(workspace, "node_modules", "cache"), "cache-v1\n");
    const store = makeVersionStore(path.join(workspaceRoot, ".commitgate"));
    const initial = await store.initializeAgent("agent", workspace, defaultCommitGatePolicy);
    await writeFile(path.join(workspace, "app.txt"), "v2\n");
    const commit = await store.recordCommit("agent", workspace, defaultCommitGatePolicy, "run-commit");
    await writeFile(path.join(workspace, "AGENTS.md"), "managed-current\n");
    await writeFile(path.join(workspace, "node_modules", "cache"), "cache-current\n");

    const rollback = await store.rollback({
      agentId: "agent",
      workspacePath: workspace,
      policy: defaultCommitGatePolicy,
      targetVersionId: initial.id,
      expectedHeadVersionId: commit.id,
      runId: "run-rollback",
    });
    expect(rollback.kind).toBe("ROLLBACK");
    expect(rollback.parentVersionId).toBe(commit.id);
    expect(rollback.rollbackTargetVersionId).toBe(initial.id);
    expect(await readFile(path.join(workspace, "app.txt"), "utf8")).toBe("v1\n");
    expect(await readFile(path.join(workspace, "AGENTS.md"), "utf8")).toBe("managed-current\n");
    await expect(
      readFile(path.join(workspace, "node_modules", "cache"), "utf8"),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("rejects stale expected heads", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-version-"));
    roots.push(root);
    const workspace = path.join(root, "workspaces", "agent");
    await mkdir(workspace, { recursive: true });
    await writeFile(path.join(workspace, "app.txt"), "v1\n");
    const store = makeVersionStore(path.join(root, "workspaces", ".commitgate"));
    const initial = await store.initializeAgent("agent", workspace, defaultCommitGatePolicy);
    await expect(
      store.rollback({
        agentId: "agent",
        workspacePath: workspace,
        policy: defaultCommitGatePolicy,
        targetVersionId: initial.id,
        expectedHeadVersionId: "stale",
        runId: "rollback",
      }),
    ).rejects.toMatchObject<Partial<VersionStoreError>>({ code: "HEAD_MISMATCH" });
  });

  it("records no-op commits as separate audit events while reusing one snapshot", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-version-"));
    roots.push(root);
    const workspace = path.join(root, "workspaces", "agent");
    await mkdir(workspace, { recursive: true });
    await writeFile(path.join(workspace, "app.txt"), "same\n");
    const store = makeVersionStore(path.join(root, "workspaces", ".commitgate"));
    await store.initializeAgent("agent", workspace, defaultCommitGatePolicy);
    await store.recordCommit("agent", workspace, defaultCommitGatePolicy, "run-noop-1");
    await store.recordCommit("agent", workspace, defaultCommitGatePolicy, "run-noop-2");
    const index = await store.getIndex("agent");
    expect(index.versions).toHaveLength(3);
    expect(new Set(index.versions.map((version) => version.id)).size).toBe(3);
    expect(index.snapshots).toHaveLength(1);
    expect(index.snapshots[0]?.refCount).toBe(3);
  });

  it("freezes the normalized policy hash on each append-only event", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-version-"));
    roots.push(root);
    const workspace = path.join(root, "workspaces", "agent");
    await mkdir(workspace, { recursive: true });
    await writeFile(path.join(workspace, "app.txt"), "same\n");
    const store = makeVersionStore(path.join(root, "workspaces", ".commitgate"));
    const initial = await store.initializeAgent(
      "agent",
      workspace,
      defaultCommitGatePolicy,
    );
    const changedPolicy = {
      ...defaultCommitGatePolicy,
      maxChangedFiles: defaultCommitGatePolicy.maxChangedFiles + 1,
    };
    const commit = await store.recordCommit(
      "agent",
      workspace,
      changedPolicy,
      "policy-change",
    );
    const index = await store.getIndex("agent");
    expect(index.versions.find((version) => version.id === initial.id)?.policyHash).toBe(
      initial.policyHash,
    );
    expect(commit.policyHash).not.toBe(initial.policyHash);
  });

  it("keeps pruned metadata but rejects rollback when its payload is gone", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-version-"));
    roots.push(root);
    const workspace = path.join(root, "workspaces", "agent");
    await mkdir(workspace, { recursive: true });
    const control = path.join(root, "workspaces", ".commitgate");
    const store = makeVersionStore(control, { maxUniqueSnapshots: 2 });
    await writeFile(path.join(workspace, "app.txt"), "v1\n");
    await store.initializeAgent("agent", workspace, defaultCommitGatePolicy);
    await writeFile(path.join(workspace, "app.txt"), "v2\n");
    const v2 = await store.recordCommit("agent", workspace, defaultCommitGatePolicy, "run-v2");
    await writeFile(path.join(workspace, "app.txt"), "v3\n");
    const head = await store.recordCommit("agent", workspace, defaultCommitGatePolicy, "run-v3");
    const pruned = (await store.list("agent", 20)).find((version) => version.id === v2.id);
    expect(pruned?.snapshotAvailable).toBe(false);
    await expect(
      store.rollback({
        agentId: "agent",
        workspacePath: workspace,
        policy: defaultCommitGatePolicy,
        targetVersionId: v2.id,
        expectedHeadVersionId: head.id,
        runId: "rollback-pruned",
      }),
    ).rejects.toMatchObject<Partial<VersionStoreError>>({ code: "SNAPSHOT_PRUNED" });

    await writeFile(path.join(workspace, "app.txt"), "v2\n");
    await store.recordCommit("agent", workspace, defaultCommitGatePolicy, "run-v2-again");
    expect(
      (await store.list("agent", 20)).find((version) => version.id === v2.id)
        ?.snapshotAvailable,
    ).toBe(true);
  });

  it("retains the parent snapshot until a staged rollback becomes terminal", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-version-"));
    roots.push(root);
    const workspace = path.join(root, "workspaces", "agent");
    await mkdir(workspace, { recursive: true });
    const store = makeVersionStore(path.join(root, "workspaces", ".commitgate"), {
      maxUniqueSnapshots: 1,
    });
    await writeFile(path.join(workspace, "app.txt"), "v1\n");
    const initial = await store.initializeAgent("agent", workspace, defaultCommitGatePolicy);
    await writeFile(path.join(workspace, "app.txt"), "v2\n");
    const head = await store.recordCommit(
      "agent",
      workspace,
      defaultCommitGatePolicy,
      "run-v2",
    );

    await store.stageRollback({
      agentId: "agent",
      workspacePath: workspace,
      policy: defaultCommitGatePolicy,
      targetVersionId: initial.id,
      expectedHeadVersionId: head.id,
      runId: "rollback-pending",
    });
    expect(
      (await store.list("agent", 20)).find((version) => version.id === head.id)
        ?.snapshotAvailable,
    ).toBe(true);

    await store.rollbackPendingRollback("rollback-pending");
    const restoredHead = await store.head("agent");
    expect(restoredHead?.id).toBe(head.id);
    expect(restoredHead?.snapshotAvailable).toBe(true);
    expect(await readFile(path.join(workspace, "app.txt"), "utf8")).toBe("v2\n");
  });

  it("defers promotion retention until acknowledgement and preserves a reverted head", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-version-"));
    roots.push(root);
    const workspace = path.join(root, "workspaces", "agent");
    await mkdir(workspace, { recursive: true });
    const store = makeVersionStore(path.join(root, "workspaces", ".commitgate"), {
      maxUniqueSnapshots: 2,
    });
    await writeFile(path.join(workspace, "app.txt"), "v1\n");
    await store.initializeAgent("agent", workspace, defaultCommitGatePolicy);
    await writeFile(path.join(workspace, "app.txt"), "v2\n");
    const parent = await store.recordCommit(
      "agent",
      workspace,
      defaultCommitGatePolicy,
      "run-v2",
    );
    await writeFile(path.join(workspace, "app.txt"), "v3\n");
    await store.recordCommit(
      "agent",
      workspace,
      defaultCommitGatePolicy,
      "run-v3",
      { deferPrune: true },
    );
    expect(
      (await store.list("agent", 20)).find((version) => version.id === parent.id)
        ?.snapshotAvailable,
    ).toBe(true);

    expect(await store.revertRunVersion("agent", "run-v3")).toBe(true);
    const restoredHead = await store.head("agent");
    expect(restoredHead?.id).toBe(parent.id);
    expect(restoredHead?.snapshotAvailable).toBe(true);
  });
});
