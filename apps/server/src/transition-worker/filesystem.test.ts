import { link, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildWorkerManifest } from "./filesystem.js";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});
describe("transition-worker authoritative filesystem closure", () => {
  it("hashes deterministic regular-file state", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "worker-manifest-"));
    roots.push(root);
    await mkdir(path.join(root, "src"));
    await writeFile(path.join(root, "src", "a.txt"), "a");
    const first = await buildWorkerManifest(root);
    const second = await buildWorkerManifest(root);
    expect(first.hash).toBe(second.hash);
  });

  it("fails closed for symlinks and hardlinks", async () => {
    const symlinkRoot = await mkdtemp(path.join(tmpdir(), "worker-symlink-"));
    roots.push(symlinkRoot);
    await writeFile(path.join(symlinkRoot, "source"), "x");
    await symlink("source", path.join(symlinkRoot, "alias"));
    await expect(buildWorkerManifest(symlinkRoot)).rejects.toThrow("SYMLINK_FILE");

    const hardlinkRoot = await mkdtemp(path.join(tmpdir(), "worker-hardlink-"));
    roots.push(hardlinkRoot);
    await writeFile(path.join(hardlinkRoot, "source"), "x");
    await link(path.join(hardlinkRoot, "source"), path.join(hardlinkRoot, "alias"));
    await expect(buildWorkerManifest(hardlinkRoot)).rejects.toThrow("HARDLINK_FILE");
  });
});
