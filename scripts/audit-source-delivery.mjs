#!/usr/bin/env node
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { lstat, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { evidenceProvenance, executionIdentity } from "./evidence-utils.mjs";
import {
  ALLOWED_MIRROR_ONLY_AUDIT_PATHS,
  sourceProductPath,
} from "./source-delivery-contract.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const cli = process.argv.slice(2);
const option = (name) => {
  const inline = cli.find((value) => value.startsWith(`${name}=`));
  if (inline) return inline.slice(name.length + 1);
  const index = cli.indexOf(name);
  return index >= 0 ? cli[index + 1] ?? null : null;
};
const repository = option("--repository") ??
  process.env.COMMITGATE_DELIVERY_REPOSITORY ??
  "iMrYang8/commitgate-authority";
const mirror = path.resolve(
  option("--mirror") ??
    process.env.COMMITGATE_DELIVERY_MIRROR ??
    path.join(root, "..", "commitgate-github"),
);
const reviewerLogin = option("--reviewer-login") ??
  process.env.COMMITGATE_REVIEWER_GITHUB_LOGIN ??
  null;
const archivePathValue = option("--archive") ??
  process.env.COMMITGATE_SOURCE_ARCHIVE ??
  null;
const archivePath = archivePathValue ? path.resolve(archivePathValue) : null;
const archiveShaPath = archivePath
  ? path.resolve(option("--archive-sha-file") ?? `${archivePath}.sha256`)
  : null;
const reportPath = path.join(root, "eval", "evidence", "source-delivery-report.json");
const provenance = await evidenceProvenance(root);
const allowedMirrorOnlyAuditPaths = new Set(ALLOWED_MIRROR_ONLY_AUDIT_PATHS);

const run = (command, args, cwd = root, timeout = 30_000) => {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    timeout,
    env: process.env,
  });
  return {
    status: result.status ?? (result.error ? 1 : 0),
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? result.error?.message ?? "",
  };
};

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const normalizeRemote = (value) => value
  .trim()
  .replace(/^git@github\.com:/, "https://github.com/")
  .replace(/\.git$/, "")
  .replace(/\/$/, "")
  .toLowerCase();
const expectedRemote = `https://github.com/${repository}`.toLowerCase();
const triState = (condition, unavailable = false) =>
  unavailable ? "unverified" : condition ? "verified" : "failed";

function revisionFiles(repositoryRoot, revision) {
  const listed = run("git", ["ls-tree", "-r", "-z", revision], repositoryRoot);
  if (listed.status !== 0) throw new Error(listed.stderr || "git ls-tree failed");
  return listed.stdout
    .split("\0")
    .filter(Boolean)
    .map((line) => {
      const tab = line.indexOf("\t");
      const [mode, type, objectId] = line.slice(0, tab).split(" ");
      return { mode, type, objectId, path: line.slice(tab + 1) };
    });
}

function productDigest(repositoryRoot, revision, expectedPaths = null) {
  const entries = revisionFiles(repositoryRoot, revision)
    .filter((entry) => entry.type === "blob" && sourceProductPath(entry.path));
  const byPath = new Map(entries.map((entry) => [entry.path, entry]));
  const paths = expectedPaths ?? [...byPath.keys()].sort();
  const hash = createHash("sha256");
  const missing = [];
  for (const relative of paths) {
    const entry = byPath.get(relative);
    if (!entry) {
      missing.push(relative);
      continue;
    }
    const blob = execFileSync("git", ["show", `${revision}:${relative}`], {
      cwd: repositoryRoot,
      encoding: null,
      maxBuffer: 32 * 1024 * 1024,
    });
    hash.update(relative);
    hash.update("\0");
    hash.update(entry.mode);
    hash.update("\0");
    hash.update(blob);
    hash.update("\0");
  }
  return { hash: hash.digest("hex"), files: paths.length - missing.length, paths, missing };
}

let sourceRevision = provenance.sourceRevision;
let mirrorRevision = null;
let mirrorRemote = null;
let mirrorBranch = null;
let mirrorClean = false;
let sourceProduct = null;
let mirrorProduct = null;
let mirrorProductInventory = null;
let unauthorizedMirrorProductPaths = [];
let localCopyChecks = { status: "unverified", publicVocabulary: null, secretScan: null };
let mirrorError = null;
try {
  if (!sourceRevision) throw new Error("frozen source revision is unavailable");
  mirrorRevision = run("git", ["rev-parse", "HEAD"], mirror).stdout.trim();
  mirrorBranch = run("git", ["branch", "--show-current"], mirror).stdout.trim();
  mirrorRemote = run("git", ["remote", "get-url", "origin"], mirror).stdout.trim();
  mirrorClean = run("git", ["status", "--porcelain=v1", "--untracked-files=all"], mirror)
    .stdout.trim().length === 0;
  sourceProduct = productDigest(root, sourceRevision);
  mirrorProduct = productDigest(mirror, mirrorRevision, sourceProduct.paths);
  mirrorProductInventory = productDigest(mirror, mirrorRevision);
  const sourcePathSet = new Set(sourceProduct.paths);
  unauthorizedMirrorProductPaths = mirrorProductInventory.paths.filter(
    (relative) =>
      !sourcePathSet.has(relative) && !allowedMirrorOnlyAuditPaths.has(relative),
  );

  // Run the public vocabulary and secret checks in a disposable local clone so
  // generated reports cannot dirty or mutate the delivery checkout.
  const auditClone = await mkdtemp(path.join(tmpdir(), "commitgate-delivery-audit-"));
  try {
    const cloned = run(
      "git",
      ["clone", "--quiet", "--local", "--no-hardlinks", mirror, auditClone],
      root,
      60_000,
    );
    if (cloned.status !== 0) throw new Error(cloned.stderr || "local mirror clone failed");
    const publicVocabulary = run("node", ["scripts/check-public-copy.mjs"], auditClone, 60_000);
    const secretScan = run("node", ["scripts/check-secrets.mjs"], auditClone, 120_000);
    localCopyChecks = {
      status:
        publicVocabulary.status === 0 && secretScan.status === 0
          ? "verified"
          : "failed",
      publicVocabulary: {
        exitCode: publicVocabulary.status,
        summary: publicVocabulary.status === 0
          ? publicVocabulary.stdout.trim().split(/\r?\n/).at(-1) ?? "passed"
          : "public-copy vocabulary scan failed",
      },
      secretScan: {
        exitCode: secretScan.status,
        summary: secretScan.status === 0
          ? secretScan.stdout.trim().split(/\r?\n/).at(-2) ?? "passed"
          : "secret scan failed",
      },
    };
  } finally {
    await rm(auditClone, { recursive: true, force: true });
  }
} catch (error) {
  mirrorError = error instanceof Error ? error.message : String(error);
}

const productBindingVerified = Boolean(
  sourceProduct &&
  mirrorProduct &&
  mirrorProduct.missing.length === 0 &&
  mirrorProduct.files === sourceProduct.files &&
  mirrorProduct.hash === sourceProduct.hash &&
  unauthorizedMirrorProductPaths.length === 0,
);
const localMirrorChecks = [
  {
    id: "source-freeze-identifiable",
    status: /^[a-f0-9]{40}$/.test(sourceRevision ?? "") ? "verified" : "failed",
    detail: {
      sourceRevision,
      headRevision: provenance.headRevision,
    },
  },
  {
    id: "source-surface-clean",
    status: provenance.workingTreeCleanAtCapture ? "verified" : "failed",
    detail: {
      workingTreeCleanAtCapture: provenance.workingTreeCleanAtCapture,
      sourceTreeHash: provenance.sourceTreeHash,
      sourceFileCount: provenance.sourceFileCount,
    },
  },
  { id: "mirror-git-checkout", status: triState(Boolean(mirrorRevision), Boolean(mirrorError)), detail: mirrorError },
  { id: "mirror-worktree-clean", status: triState(mirrorClean, Boolean(mirrorError)), detail: mirrorClean },
  { id: "mirror-main-branch", status: triState(mirrorBranch === "main", Boolean(mirrorError)), detail: mirrorBranch },
  {
    id: "mirror-origin-bound",
    status: triState(normalizeRemote(mirrorRemote ?? "") === expectedRemote, Boolean(mirrorError)),
    detail: mirrorRemote,
  },
  {
    id: "source-product-bytes-bound",
    status: triState(productBindingVerified, Boolean(mirrorError)),
    detail: {
      sourceRevision,
      mirrorRevision,
      sourceProductHash: sourceProduct?.hash ?? null,
      mirrorProductHash: mirrorProduct?.hash ?? null,
      comparedFiles: sourceProduct?.files ?? 0,
      missingPaths: mirrorProduct?.missing ?? [],
      allowedMirrorOnlyAuditPaths: mirrorProductInventory?.paths.filter(
        (relative) => allowedMirrorOnlyAuditPaths.has(relative),
      ) ?? [],
      unauthorizedMirrorProductPaths,
    },
  },
  {
    id: "sanitized-copy-scans",
    status: localCopyChecks.status,
    detail: localCopyChecks,
  },
];
const localMirrorStatus = localMirrorChecks.some((entry) => entry.status === "failed")
  ? "failed"
  : localMirrorChecks.every((entry) => entry.status === "verified")
    ? "verified"
    : "unverified";

let repositoryMetadata = null;
let remoteRevision = null;
let workflow = null;
let reviewerPermission = null;
let reviewerPermissionQuery = null;
let githubUnavailable = false;
const repoView = run(
  "gh",
  ["repo", "view", repository, "--json", "nameWithOwner,isPrivate,url,defaultBranchRef"],
  root,
  30_000,
);
if (repoView.status === 0) {
  try {
    repositoryMetadata = JSON.parse(repoView.stdout);
    const remote = run("gh", ["api", `repos/${repository}/commits/main`, "--jq", ".sha"], root);
    if (remote.status === 0) remoteRevision = remote.stdout.trim();
    const actions = run(
      "gh",
      [
        "run", "list", "--repo", repository, "--branch", "main", "--limit", "1",
        "--json", "conclusion,headSha,status,url",
      ],
      root,
    );
    if (actions.status === 0) workflow = JSON.parse(actions.stdout)?.[0] ?? null;
    if (reviewerLogin) {
      const permission = run(
        "gh",
        ["api", `repos/${repository}/collaborators/${reviewerLogin}/permission`],
        root,
      );
      reviewerPermissionQuery = {
        exitCode: permission.status,
        notFound: /(?:HTTP\s+404|not found)/i.test(permission.stderr),
        unavailable: /(?:connect|network|timeout|authentication|login)/i.test(
          permission.stderr,
        ),
      };
      if (permission.status === 0) reviewerPermission = JSON.parse(permission.stdout);
    }
  } catch {
    githubUnavailable = true;
  }
} else {
  githubUnavailable = true;
}
const permission = reviewerPermission?.permission ?? reviewerPermission?.user?.permissions?.pull;
const reviewerCanRead = typeof permission === "string"
  ? ["read", "triage", "write", "maintain", "admin"].includes(permission)
  : permission === true;
const anonymousRemote = run(
  "git",
  ["-c", "credential.helper=", "ls-remote", `${expectedRemote}.git`, "refs/heads/main"],
  root,
  30_000,
);
const anonymousMain = anonymousRemote.status === 0
  ? anonymousRemote.stdout.trim().split(/\s+/)[0] ?? null
  : null;
const repositoryChecks = [
  {
    id: "remote-public-repository",
    status: triState(
      repositoryMetadata?.nameWithOwner?.toLowerCase() === repository.toLowerCase() &&
        repositoryMetadata?.isPrivate === false &&
        repositoryMetadata?.defaultBranchRef?.name === "main",
      githubUnavailable,
    ),
    detail: repositoryMetadata
      ? {
          nameWithOwner: repositoryMetadata.nameWithOwner,
          isPrivate: repositoryMetadata.isPrivate,
          url: repositoryMetadata.url,
          defaultBranch: repositoryMetadata.defaultBranchRef?.name ?? null,
        }
      : "GitHub metadata unavailable",
  },
  {
    id: "remote-main-matches-local-mirror",
    status: triState(
      Boolean(remoteRevision) && remoteRevision === mirrorRevision,
      githubUnavailable || !remoteRevision,
    ),
    detail: { remoteRevision, mirrorRevision },
  },
  {
    id: "remote-ci-passed-for-main",
    status: triState(
      workflow?.status === "completed" &&
        workflow?.conclusion === "success" &&
        workflow?.headSha === remoteRevision,
      githubUnavailable || !workflow,
    ),
    detail: workflow
      ? {
          status: workflow.status,
          conclusion: workflow.conclusion,
          headSha: workflow.headSha,
          url: workflow.url,
        }
      : "workflow metadata unavailable",
  },
  {
    id: "anonymous-public-read-access",
    status: triState(anonymousMain === remoteRevision && Boolean(remoteRevision), anonymousRemote.status !== 0),
    detail: {
      remote: `${expectedRemote}.git`,
      anonymousMain,
      remoteRevision,
      credentialHelperDisabled: true,
    },
  },
];
const repositoryDeliveryStatus =
  localMirrorStatus === "failed" || repositoryChecks.some((entry) => entry.status === "failed")
    ? "failed"
    : localMirrorStatus === "verified" &&
        repositoryChecks.every((entry) => entry.status === "verified")
      ? "verified"
      : "unverified";

let archive = null;
let archiveStatus = "unverified";
if (archivePath && archiveShaPath) {
  try {
    const info = await lstat(archivePath);
    if (!info.isFile() || info.isSymbolicLink()) throw new Error("archive is not a regular file");
    const bytes = await readFile(archivePath);
    const actualSha256 = sha256(bytes);
    const recordedLine = (await readFile(archiveShaPath, "utf8")).trim();
    const recordedSha256 = recordedLine.split(/\s+/)[0] ?? "";
    const generated = await mkdtemp(path.join(tmpdir(), "commitgate-source-archive-"));
    let expectedSha256 = null;
    try {
      const expectedArchive = path.join(generated, "expected.tar.gz");
      const archived = run(
        "git",
        ["archive", "--format=tar.gz", "--output", expectedArchive, mirrorRevision],
        mirror,
        120_000,
      );
      if (archived.status !== 0) throw new Error(archived.stderr || "git archive failed");
      expectedSha256 = sha256(await readFile(expectedArchive));
    } finally {
      await rm(generated, { recursive: true, force: true });
    }
    const filenameBound = recordedLine.includes(path.basename(archivePath));
    const valid =
      /^[a-f0-9]{64}$/.test(recordedSha256) &&
      recordedSha256 === actualSha256 &&
      expectedSha256 === actualSha256 &&
      filenameBound;
    archiveStatus = valid ? "verified" : "failed";
    archive = {
      path: path.basename(archivePath),
      bytes: info.size,
      sha256: actualSha256,
      sha256File: path.basename(archiveShaPath),
      recordedSha256,
      generatedFromMirrorHeadSha256: expectedSha256,
      filenameBound,
    };
  } catch (error) {
    archiveStatus = "failed";
    archive = {
      path: path.basename(archivePath),
      sha256File: path.basename(archiveShaPath),
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

const deliveryStatus = localMirrorStatus === "failed"
  ? "failed"
  : repositoryDeliveryStatus === "verified" ||
      (localMirrorStatus === "verified" && archiveStatus === "verified")
    ? "verified"
    : repositoryDeliveryStatus === "failed" && archiveStatus === "failed"
      ? "failed"
      : "unverified";
const report = {
  schemaVersion: 1,
  kind: "reviewer-source-delivery-audit",
  generatedAt: new Date().toISOString(),
  status: deliveryStatus,
  source: provenance,
  executionIdentity: executionIdentity(root),
  localMirror: {
    path: path.relative(root, mirror),
    status: localMirrorStatus,
    checks: localMirrorChecks,
  },
  repositoryDelivery: {
    repository,
    status: repositoryDeliveryStatus,
    checks: repositoryChecks,
    queryErrorRecorded: githubUnavailable,
    credentialsRecorded: false,
  },
  archiveDelivery: {
    status: archiveStatus,
    artifact: archive,
  },
  claimBoundary:
    "Verified requires an exact source-to-sanitized-product byte binding plus anonymous read access to the public repository at the matching successful-CI revision, or a byte-for-byte git archive with a matching SHA-256 companion file. Repository metadata alone is not anonymous access; archive existence alone is not provenance.",
};
await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");
for (const item of localMirrorChecks) {
  console.log(`${item.status.padEnd(10)} ${item.id}`);
}
for (const item of repositoryChecks) {
  console.log(`${item.status.padEnd(10)} ${item.id}`);
}
console.log(`${archiveStatus.padEnd(10)} sanitized-source-archive`);
console.log(`${deliveryStatus}: source delivery report: ${reportPath}`);
process.exitCode = deliveryStatus === "verified" ? 0 : deliveryStatus === "failed" ? 1 : 2;
