import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { RollbackPermitStore } from "./rollback-permit-store.js";

const roots: string[] = [];
afterEach(async () => {
  const { rm } = await import("node:fs/promises");
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

describe("dedicated rollback permit", () => {
  it("moves ISSUED to CONSUMING to CONSUMED and rejects permit replay", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "rollback-permit-"));
    roots.push(root);
    const controlPath = path.join(root, "agent-1");
    const snapshotPath = path.join(controlPath, "snapshots", "snapshot-a");
    await mkdir(snapshotPath, { recursive: true });
    await writeFile(path.join(snapshotPath, "README.md"), "v1\n");
    const store = new RollbackPermitStore(() => new Date("2026-01-01T00:00:00Z"));
    const permit = await store.issue({
      runId: "run-rollback",
      agentId: "agent-1",
      controlPath,
      targetVersionId: "version-1",
      targetSnapshotHash: "a".repeat(64),
      expectedHeadVersionId: "version-2",
      baseHash: "b".repeat(64),
    });
    const claim = {
      controlPath,
      rollbackPermitId: permit.rollbackPermitId,
      snapshotPath,
      targetVersionId: permit.targetVersionId,
      targetSnapshotHash: permit.targetSnapshotHash,
      expectedHeadVersionId: permit.expectedHeadVersionId,
      baseHash: permit.baseHash,
    };
    const capability = await store.claim(claim);
    expect(capability.permit.state).toBe("CONSUMING");
    await expect(store.claim(claim)).rejects.toThrow(/REPLAY/);
    expect((await capability.consume()).state).toBe("CONSUMED");
    await expect(capability.consume()).rejects.toThrow(/REPLAY/);
    expect((await store.markConsumed(controlPath, capability)).state).toBe("CONSUMED");
    await expect(store.claim(claim)).rejects.toThrow(/REPLAY/);
  });
});
