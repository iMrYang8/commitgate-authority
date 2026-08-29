import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  rm,
  stat,
  symlink,
  truncate,
  writeFile,
} from "node:fs/promises";
import { execFile } from "node:child_process";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { buildManifest } from "../commitgate/manifest.js";
import { defaultCommitGatePolicy } from "../commitgate/policy.js";
import {
  assertNoWorkerPathIdentityCollisions,
  assertSameFilesystemSet,
  buildWorkerManifest,
  copyClosedTree,
  workerFilesystemSupportMatrix,
} from "./filesystem.js";
import {
  createLinuxExtendedMetadataInspector,
  linuxStrongWorkerManifestOptions,
} from "./linux-extended-metadata.js";

const roots: string[] = [];
const execFileAsync = promisify(execFile);

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function root(prefix = "worker-manifest-"): Promise<string> {
  const result = await mkdtemp(path.join(tmpdir(), prefix));
  roots.push(result);
  return result;
}

describe("transition-worker authoritative filesystem closure", () => {
  it("emits canonical schema v2 with the same authoritative hash as the core manifest", async () => {
    const workspace = await root();
    await mkdir(path.join(workspace, "src"));
    await writeFile(path.join(workspace, "src", "a.txt"), "a");
    await writeFile(path.join(workspace, "AGENTS.md"), "managed");

    const first = await buildWorkerManifest(workspace);
    const second = await buildWorkerManifest(workspace);
    const core = await buildManifest(workspace, defaultCommitGatePolicy);

    expect(first.schemaVersion).toBe(2);
    expect(first.entries.every((entry) => entry.type === "dir" || entry.type === "file")).toBe(true);
    expect(first.hash).toBe(second.hash);
    expect(first.hash).toBe(core.hash);
    expect(first.resourceUsage).toMatchObject({
      scannedEntries: 3,
      scannedFiles: 2,
      authoritativeEntries: 3,
      ignoredEntries: 0,
    });
  });

  it("excludes ignored names at any path depth while still charging their inode and byte usage", async () => {
    const workspace = await root();
    await mkdir(path.join(workspace, "src", "node_modules", "pkg"), { recursive: true });
    await writeFile(path.join(workspace, "src", "main.ts"), "export {};\n");
    await writeFile(path.join(workspace, "src", "node_modules", "pkg", "index.js"), "ignored");

    const before = await buildWorkerManifest(workspace);
    expect(before.entries.some((entry) => entry.path.includes("node_modules"))).toBe(false);
    expect(before.resourceUsage).toMatchObject({
      ignoredEntries: 3,
      ignoredFiles: 1,
      ignoredBytes: 7,
    });

    await writeFile(path.join(workspace, "src", "node_modules", "pkg", "index.js"), "changed");
    const after = await buildWorkerManifest(workspace);
    expect(after.hash).toBe(before.hash);
    expect(after.resourceUsage.ignoredBytes).toBe(7);

    const destination = await root("worker-copy-");
    await rm(destination, { recursive: true, force: true });
    const copied = await copyClosedTree(workspace, destination);
    expect(copied.hash).toBe(before.hash);
    expect(copied.entries.some((entry) => entry.path.includes("node_modules"))).toBe(false);
  });

  it("fails closed when ignored trees exceed file, byte, or single-file quotas", async () => {
    const workspace = await root();
    await mkdir(path.join(workspace, "nested", "coverage"), { recursive: true });
    await writeFile(path.join(workspace, "nested", "coverage", "a"), "1234");

    await expect(buildWorkerManifest(workspace, {
      resourceLimits: { maxIgnoredEntries: 1 },
    })).rejects.toThrow("IGNORED_EPHEMERAL_FILE_BUDGET_EXCEEDED");
    await expect(buildWorkerManifest(workspace, {
      resourceLimits: { maxIgnoredBytes: 3 },
    })).rejects.toThrow("IGNORED_EPHEMERAL_BYTE_BUDGET_EXCEEDED");
    await expect(buildWorkerManifest(workspace, {
      resourceLimits: { maxIgnoredSingleFileBytes: 3 },
    })).rejects.toThrow("IGNORED_EPHEMERAL_SINGLE_FILE_BUDGET_EXCEEDED");
  });

  it("fails closed when the complete candidate scan exceeds its total inode quota", async () => {
    const workspace = await root();
    await writeFile(path.join(workspace, "a"), "a");
    await writeFile(path.join(workspace, "b"), "b");
    await expect(buildWorkerManifest(workspace, {
      resourceLimits: { maxScannedEntries: 1 },
    })).rejects.toThrow("CANDIDATE_ENTRY_BUDGET_EXCEEDED");
  });

  it("fails closed when a manifest walk exceeds its wall-clock scan budget", async () => {
    const workspace = await root();
    await writeFile(path.join(workspace, "a"), "a");
    let clock = 0;
    await expect(buildWorkerManifest(workspace, {
      resourceLimits: { maxScanDurationMs: 30 },
      monotonicNow: () => {
        clock += 20;
        return clock;
      },
    })).rejects.toThrow("CANDIDATE_SCAN_TIME_BUDGET_EXCEEDED");
  });

  it("fails closed for symlinks and hardlinks, including inside ignored trees", async () => {
    const symlinkRoot = await root("worker-symlink-");
    await writeFile(path.join(symlinkRoot, "source"), "x");
    await symlink("source", path.join(symlinkRoot, "alias"));
    await expect(buildWorkerManifest(symlinkRoot)).rejects.toThrow("SYMLINK_FILE");

    const hardlinkRoot = await root("worker-hardlink-");
    await mkdir(path.join(hardlinkRoot, "node_modules"));
    await writeFile(path.join(hardlinkRoot, "node_modules", "source"), "x");
    await link(
      path.join(hardlinkRoot, "node_modules", "source"),
      path.join(hardlinkRoot, "node_modules", "alias"),
    );
    await expect(buildWorkerManifest(hardlinkRoot)).rejects.toThrow("HARDLINK_FILE");
  });

  it("rejects special files without opening or following them", async () => {
    const workspace = await root("worker-special-");
    await execFileAsync("mkfifo", [path.join(workspace, "agent.pipe")]);
    await expect(buildWorkerManifest(workspace)).rejects.toThrow("SPECIAL_FILE:agent.pipe");
  });

  it("rejects case-fold and Unicode-normalization aliases before filesystem access", () => {
    expect(() => assertNoWorkerPathIdentityCollisions(["Readme.md", "README.md"])).toThrow(
      "CASEFOLD_PATH_COLLISION",
    );
    expect(() =>
      assertNoWorkerPathIdentityCollisions(["caf\u00e9.txt", "cafe\u0301.txt"]),
    ).toThrow("UNICODE_NORMALIZATION_COLLISION");
  });

  it("enforces the expected root ownership across the complete tree", async () => {
    const workspace = await root("worker-metadata-");
    await writeFile(path.join(workspace, "tool"), "x");
    const uid = typeof process.getuid === "function" ? process.getuid() : 0;
    await expect(buildWorkerManifest(workspace, { expectedUid: uid + 1 })).rejects.toThrow(
      "OWNERSHIP_MISMATCH:.",
    );
  });

  it.skipIf(process.platform !== "linux")(
    "rejects non-normalized setuid, setgid, and sticky mode bits",
    async () => {
      const workspace = await root("worker-special-mode-");
      await writeFile(path.join(workspace, "tool"), "x");
      await chmod(path.join(workspace, "tool"), 0o4755);
      await expect(buildWorkerManifest(workspace)).rejects.toThrow("SPECIAL_MODE_BITS:tool");
    },
  );

  it("fails closed when extended metadata is required but unavailable or present", async () => {
    const workspace = await root("worker-extended-metadata-");
    await writeFile(path.join(workspace, "file"), "x");
    await expect(buildWorkerManifest(workspace, {
      requireExtendedMetadataInspection: true,
    })).rejects.toThrow("EXTENDED_METADATA_INSPECTION_UNAVAILABLE");

    await expect(buildWorkerManifest(workspace, {
      requireExtendedMetadataInspection: true,
      extendedMetadataInspector: async (absolute) => ({
        xattrs: absolute.endsWith("/file") ? ["user.fixture"] : [],
        aclEntries: [],
      }),
    })).rejects.toThrow("XATTR_NOT_ALLOWED:file");

    await expect(buildWorkerManifest(workspace, {
      requireExtendedMetadataInspection: true,
      extendedMetadataInspector: async (absolute) => ({
        xattrs: [],
        aclEntries: absolute.endsWith("/file") ? ["user:fixture:r--"] : [],
      }),
    })).rejects.toThrow("ACL_NOT_ALLOWED:file");
  });

  it("publishes an explicit support matrix instead of overstating portable guarantees", () => {
    const portable = workerFilesystemSupportMatrix();
    expect(portable.extendedAttributesAndAcl).toBe("unsupported-not-inspected");
    expect(portable.sparseFiles).toBe(process.platform === "linux" ? "enforced" : "unsupported");
    expect(workerFilesystemSupportMatrix({
      extendedMetadataInspector: async () => ({ xattrs: [], aclEntries: [] }),
    }).extendedAttributesAndAcl).toBe("enforced");
  });

  it("checks filesystem topology for all existing rename-swap roots", async () => {
    const left = await root("worker-fs-left-");
    const right = await root("worker-fs-right-");
    await expect(assertSameFilesystemSet([left, right])).resolves.toBeUndefined();
  });

  it.skipIf(process.platform !== "linux")(
    "rejects a real cross-device rename topology before promotion",
    async () => {
      const left = await root("worker-fs-local-");
      const right = await mkdtemp("/dev/shm/commitgate-fs-exdev-");
      roots.push(right);
      expect((await stat(left)).dev).not.toBe((await stat(right)).dev);
      await expect(assertSameFilesystemSet([left, right])).rejects.toThrow(
        "UNSUPPORTED_FILESYSTEM_EXDEV",
      );
    },
  );

  it.skipIf(process.platform !== "linux")(
    "rejects sparse files on the Linux strong-guarantee platform",
    async () => {
      const workspace = await root("worker-sparse-");
      await writeFile(path.join(workspace, "sparse.bin"), "x");
      await truncate(path.join(workspace, "sparse.bin"), 8 * 1024 * 1024);
      await expect(buildWorkerManifest(workspace)).rejects.toThrow("SPARSE_FILE:sparse.bin");
    },
  );

  it.skipIf(process.platform !== "linux")(
    "rejects a real Linux xattr without returning its value",
    async () => {
      const workspace = await root("worker-xattr-");
      const target = path.join(workspace, "file");
      await writeFile(target, "x");
      await execFileAsync("/usr/bin/setfattr", [
        "--name=user.commitgate-fixture",
        "--value=do-not-record-this-value",
        "--",
        target,
      ]);

      const inspector = createLinuxExtendedMetadataInspector();
      const metadata = await inspector(target);
      expect(metadata.xattrs).toContain("user.commitgate-fixture");
      expect(JSON.stringify(metadata)).not.toContain("do-not-record-this-value");
      await expect(
        buildWorkerManifest(workspace, linuxStrongWorkerManifestOptions()),
      ).rejects.toThrow("XATTR_NOT_ALLOWED:file");
    },
  );

  it.skipIf(process.platform !== "linux")(
    "rejects a real non-trivial Linux ACL while omitting mode-derived entries",
    async () => {
      const workspace = await root("worker-acl-");
      const target = path.join(workspace, "file");
      await writeFile(target, "x");
      await execFileAsync("/usr/bin/setfacl", ["--modify", "user:12345:r--", "--", target]);

      const inspector = createLinuxExtendedMetadataInspector();
      const metadata = await inspector(target);
      expect(metadata.xattrs).not.toContain("system.posix_acl_access");
      expect(metadata.aclEntries).toContain("user:12345:r--");
      expect(metadata.aclEntries).not.toContain("user::rw-");
      await expect(
        buildWorkerManifest(workspace, linuxStrongWorkerManifestOptions()),
      ).rejects.toThrow("ACL_NOT_ALLOWED:file");
    },
  );

  it.skipIf(process.platform !== "linux")(
    "fails closed when a required inspection tool is missing",
    async () => {
      const inspector = createLinuxExtendedMetadataInspector({
        getfattrPath: "/usr/bin/commitgate-missing-getfattr",
      });
      await expect(inspector("/tmp")).rejects.toThrow(
        "EXTENDED_METADATA_TOOL_UNAVAILABLE:getfattr",
      );
    },
  );
});
