#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { chmod, cp, lstat, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import {
  evidenceProvenance,
  executionIdentity,
  sourceTreeHash,
} from "./evidence-utils.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const reportPath = path.join(root, "eval", "independent-audit-report.json");
const source = await evidenceProvenance(root);
const identity = executionIdentity(root);

async function emitEarly(reason) {
  const report = {
    schemaVersion: 3,
    kind: "project-defined-clean-worktree-replay",
    generatedAt: new Date().toISOString(),
    status: "unverified",
    source,
    executionIdentity: identity,
    auditOrigin: "project-defined",
    externallyIndependent: false,
    cleanClone: false,
    readOnlySource: false,
    reason,
    results: [],
  };
  await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");
  console.log(`unverified: ${reason}`);
  console.log(`project-defined clean-worktree replay report: ${reportPath}`);
  process.exit(2);
}

if (!source.sourceRevision || !source.workingTreeCleanAtCapture) {
  await emitEarly("Independent replay requires a committed source revision with no source-tree changes");
}

// Keep the no-hardlink clone beneath the repository's ignored .local tree.
// Docker Desktop shares this workspace path with its VM, while macOS's
// /private/var/folders path is not consistently bind-mountable by the daemon.
const localScratchRoot = path.join(root, ".local");
await mkdir(localScratchRoot, { recursive: true });
const temporaryRoot = await mkdtemp(
  path.join(localScratchRoot, "commitgate-independent-"),
);
const cloneRoot = path.join(temporaryRoot, "repo");
const artifactRoot = path.join(root, "eval", "independent", source.sourceRevision.slice(0, 12));
const results = [];

function run(id, executable, arguments_, options = {}) {
  const started = Date.now();
  const result = spawnSync(executable, arguments_, {
    cwd: options.cwd ?? cloneRoot,
    env: options.env ?? process.env,
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
  });
  const status = result.status === 0 ? "verified" : result.status === 2 ? "unverified" : "failed";
  const entry = {
    id,
    status,
    command: [executable, ...arguments_].join(" "),
    exitCode: result.status,
    durationMs: Date.now() - started,
    stdoutTail: (result.stdout ?? "").slice(-4_096),
    stderrTail: (result.stderr ?? "").slice(-4_096),
  };
  results.push(entry);
  console.log(`${status.padEnd(10)} ${id} (${entry.durationMs} ms)`);
  return entry;
}

let readOnlySource = false;
let cloneHash = null;
let cloneRevision = null;
try {
  const cloned = run("clean-local-clone", "git", ["clone", "--local", "--no-hardlinks", "--no-checkout", root, cloneRoot], {
    cwd: temporaryRoot,
  });
  if (cloned.status !== "verified") throw new Error("git clone failed");
  if (run("checkout-source-revision", "git", ["checkout", "--detach", source.sourceRevision]).status !== "verified") {
    throw new Error("git checkout failed");
  }
  cloneRevision = spawnSync("git", ["rev-parse", "HEAD"], { cwd: cloneRoot, encoding: "utf8" }).stdout.trim();
  cloneHash = await sourceTreeHash(cloneRoot);
  if (cloneRevision !== source.sourceRevision || cloneHash.hash !== source.sourceTreeHash) {
    results.push({
      id: "clone-identity",
      status: "failed",
      expectedRevision: source.sourceRevision,
      actualRevision: cloneRevision,
      expectedSourceTreeHash: source.sourceTreeHash,
      actualSourceTreeHash: cloneHash.hash,
    });
    throw new Error("clean clone identity mismatch");
  }
  results.push({ id: "clone-identity", status: "verified" });

  if (run("npm-ci", "npm", ["ci"]).status !== "verified") throw new Error("npm ci failed");
  run("baseline-check", "npm", ["run", "check"]);

  const listed = spawnSync("git", ["ls-files", "-z"], { cwd: cloneRoot, encoding: "utf8" });
  if (listed.status !== 0) throw new Error("git ls-files failed");
  const protectedPrefixes = ["apps/", "scripts/", "docs/", "eval/fixtures/"];
  const protectedExact = new Set([
    "package.json",
    "package-lock.json",
    "tsconfig.base.json",
    "Dockerfile.runtime",
    "docker-compose.yml",
  ]);
  const protectedFiles = listed.stdout
    .split("\0")
    .filter(Boolean)
    .filter((relative) => protectedExact.has(relative) || protectedPrefixes.some((prefix) => relative.startsWith(prefix)));
  for (const relative of protectedFiles) {
    const absolute = path.join(cloneRoot, relative);
    const stats = await lstat(absolute);
    if (stats.isFile()) await chmod(absolute, stats.mode & ~0o222);
  }
  readOnlySource = (
    await Promise.all(
      protectedFiles.map(async (relative) => {
        const stats = await lstat(path.join(cloneRoot, relative));
        return !stats.isFile() || (stats.mode & 0o222) === 0;
      }),
    )
  ).every(Boolean);
  results.push({
    id: "read-only-source-files",
    status: readOnlySource ? "verified" : "failed",
    fileCount: protectedFiles.length,
  });

  for (const [id, command] of [
    ["protocol", "eval:protocol"],
    ["adversarial", "eval:adversarial"],
    ["recovery", "eval:recovery"],
    ["authority", "audit:authority"],
    ["container", "eval:container"],
    ["secrets", "check:secrets"],
  ]) {
    run(id, "npm", ["run", command]);
  }
  run("documentation", "npm", ["run", "audit:documentation"], {
    env: { ...process.env, COMMITGATE_INDEPENDENT_REVIEW: "1" },
  });

  const afterHash = await sourceTreeHash(cloneRoot);
  results.push({
    id: "source-unchanged-after-audit",
    status: afterHash.hash === cloneHash.hash ? "verified" : "failed",
    before: cloneHash.hash,
    after: afterHash.hash,
  });

  await mkdir(artifactRoot, { recursive: true });
  for (const relative of [
    "eval/evidence/check-report.json",
    "eval/protocol-report.json",
    "eval/adversarial-report.json",
    "eval/recovery-report.json",
    "eval/authority-report.json",
    "eval/container-report.json",
    "eval/evidence/secret-report.json",
    "eval/evidence/documentation-review.json",
  ]) {
    try {
      const destination = path.join(artifactRoot, path.basename(relative));
      await cp(path.join(cloneRoot, relative), destination);
    } catch {}
  }
  await cp(
    path.join(cloneRoot, "eval", "evidence", "documentation-review.json"),
    path.join(root, "eval", "evidence", "documentation-review.json"),
  );
} catch (error) {
  if (!results.some((entry) => entry.status === "failed")) {
    results.push({
      id: "independent-runner",
      status: "failed",
      error: error instanceof Error ? error.message : String(error),
    });
  }
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}

const status = results.some((entry) => entry.status === "failed")
  ? "failed"
  : results.some((entry) => entry.status === "unverified")
    ? "unverified"
    : "verified";
const report = {
  schemaVersion: 3,
  kind: "project-defined-clean-worktree-replay",
  generatedAt: new Date().toISOString(),
  status,
  source,
  executionIdentity: identity,
  auditOrigin: "project-defined",
  externallyIndependent: false,
  cleanClone: cloneRevision === source.sourceRevision && cloneHash?.hash === source.sourceTreeHash,
  readOnlySource,
  cloneRevision,
  cloneSourceTreeHash: cloneHash?.hash ?? null,
  results,
  copiedEvidenceDirectory: path.relative(root, artifactRoot),
  claimBoundary:
    "This team-authored script ran commands from a separate no-hardlink clone. Tracked application, script and documentation files were made read-only before protocol/adversarial/recovery/container/authority/secret evaluation. It is not an external independent audit.",
};
await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");
console.log(`${status}: project-defined clean-worktree replay report: ${reportPath}`);
process.exitCode = status === "verified" ? 0 : status === "unverified" ? 2 : 1;
