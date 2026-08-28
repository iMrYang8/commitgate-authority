import { chmod, link, mkdir, mkdtemp, symlink, truncate, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { assertNoPathIdentityCollisions, buildManifest, diffManifests } from "./manifest.js";
import {
  classifyPath,
  defaultCommitGatePolicy,
  validatePolicy,
} from "./policy.js";

const roots: string[] = [];
afterEach(async () => {
  const { rm } = await import("node:fs/promises");
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function fixture(): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), "commitgate-manifest-"));
  roots.push(root);
  await mkdir(path.join(root, "src"));
  await writeFile(path.join(root, "src", "main.ts"), "export const n = 1;\n");
  await writeFile(path.join(root, "AGENTS.md"), "managed\n");
  await mkdir(path.join(root, "node_modules", "pkg"), { recursive: true });
  await writeFile(path.join(root, "node_modules", "pkg", "index.js"), "ignored");
  return root;
}

describe("canonical manifest and path policy", () => {
  it("is independent of mtime and ignores ephemeral trees", async () => {
    const root = await fixture();
    const first = await buildManifest(root, defaultCommitGatePolicy);
    await utimes(path.join(root, "src", "main.ts"), new Date(1), new Date(2));
    const second = await buildManifest(root, defaultCommitGatePolicy);
    expect(second.hash).toBe(first.hash);
    expect(first.entries.some((entry) => entry.path.includes("node_modules"))).toBe(false);
  });

  it("changes for content, executable mode, and deletion", async () => {
    const root = await fixture();
    const baseline = await buildManifest(root, defaultCommitGatePolicy);
    await writeFile(path.join(root, "src", "main.ts"), "export const n = 2;\n");
    const content = await buildManifest(root, defaultCommitGatePolicy);
    expect(content.hash).not.toBe(baseline.hash);
    await chmod(path.join(root, "src", "main.ts"), 0o755);
    const mode = await buildManifest(root, defaultCommitGatePolicy);
    expect(mode.hash).not.toBe(content.hash);
    const { rm } = await import("node:fs/promises");
    await rm(path.join(root, "src", "main.ts"));
    const deleted = await buildManifest(root, defaultCommitGatePolicy);
    expect(diffManifests(mode, deleted)).toEqual(
      expect.arrayContaining([expect.objectContaining({ path: "src/main.ts", kind: "deleted" })]),
    );
  });

  it("classifies platform and ephemeral paths by fixed trust rules", () => {
    expect(classifyPath("AGENTS.md", defaultCommitGatePolicy)).toBe("platformManaged");
    expect(classifyPath("src/node_modules/x.js", defaultCommitGatePolicy)).toBe("ignoredEphemeral");
    expect(classifyPath("src/index.ts", defaultCommitGatePolicy)).toBe("versioned");
  });

  it("rejects unsafe policy paths", () => {
    expect(() => validatePolicy({ ...defaultCommitGatePolicy, protectedPaths: ["../secret"] })).toThrow(/escapes/);
    expect(() => validatePolicy({ ...defaultCommitGatePolicy, protectedPaths: ["/etc/passwd"] })).toThrow(/relative/);
  });

  it("rejects authoritative symlinks and hardlinks", async () => {
    const source = await fixture();
    await symlink("src/main.ts", path.join(source, "link"));
    const { rm } = await import("node:fs/promises");
    await expect(buildManifest(source, defaultCommitGatePolicy)).rejects.toThrow("SYMLINK_FILE:link");
    await rm(path.join(source, "link"));
    await link(path.join(source, "src", "main.ts"), path.join(source, "hardlink"));
    await expect(buildManifest(source, defaultCommitGatePolicy)).rejects.toThrow(/HARDLINK_FILE/);
  });

  it("rejects case-fold and Unicode-normalization path aliases", () => {
    expect(() => assertNoPathIdentityCollisions(["Readme.md", "README.md"])).toThrow(
      /CASEFOLD_PATH_COLLISION/,
    );
    expect(() => assertNoPathIdentityCollisions(["caf\u00e9.txt", "cafe\u0301.txt"])).toThrow(
      /UNICODE_NORMALIZATION_COLLISION/,
    );
  });

  it.skipIf(process.platform !== "linux")(
    "rejects sparse authoritative files on the strong-guarantee platform",
    async () => {
      const root = await fixture();
      await writeFile(path.join(root, "sparse.bin"), "x");
      await truncate(path.join(root, "sparse.bin"), 8 * 1024 * 1024);
      await expect(buildManifest(root, defaultCommitGatePolicy)).rejects.toThrow(
        "SPARSE_FILE:sparse.bin",
      );
    },
  );
});
