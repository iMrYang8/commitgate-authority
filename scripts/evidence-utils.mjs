import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { lstat, readFile, readlink } from "node:fs/promises";
import path from "node:path";

function git(root, args) {
  return spawnSync("git", args, {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
}

function isSourcePath(relative) {
  return (
    relative === "package.json" ||
    relative === "package-lock.json" ||
    relative === "README.md" ||
    relative === ".gitignore" ||
    relative === ".dockerignore" ||
    relative === ".env.example" ||
    relative === ".env.local.example" ||
    relative === "tsconfig.base.json" ||
    relative === "docker-compose.yml" ||
    /^docker-compose(?:\.[^/]+)?\.ya?ml$/.test(relative) ||
    relative === "Dockerfile" ||
    relative.startsWith("Dockerfile.") ||
    relative.startsWith(".github/") ||
    relative.startsWith("apps/") ||
    relative.startsWith("scripts/") ||
    relative.startsWith("docs/") ||
    relative.startsWith("eval/fixtures/") ||
    relative.startsWith("eval/trusted-checks/") ||
    relative === "eval/demo-policy.json"
  );
}

/**
 * Return the newest commit that changed the frozen product/source surface.
 *
 * Evidence is intentionally committed after the source freeze.  Using HEAD as
 * the source revision would therefore make every report stale as soon as an
 * evidence-only commit is created.  This path-scoped revision remains the
 * source commit while still advancing whenever code, evaluators, fixtures, or
 * product documentation changes.
 */
export function frozenSourceRevision(root) {
  const result = git(root, [
    "rev-list",
    "-1",
    "HEAD",
    "--",
    "package.json",
    "package-lock.json",
    "README.md",
    ".gitignore",
    ".dockerignore",
    ".env.example",
    ".env.local.example",
    "tsconfig.base.json",
    "Dockerfile*",
    "docker-compose*.yml",
    "docker-compose*.yaml",
    ".github",
    "apps",
    "scripts",
    "docs",
    "eval/fixtures",
    "eval/trusted-checks",
    "eval/demo-policy.json",
  ]);
  if (result.status !== 0) return null;
  const revision = result.stdout.trim();
  return /^[a-f0-9]{40}$/.test(revision) ? revision : null;
}

export async function sourceTreeHash(root) {
  const listed = git(root, [
    "ls-files",
    "-z",
    "--cached",
    "--others",
    "--exclude-standard",
  ]);
  if (listed.status !== 0) throw new Error(listed.stderr.trim() || "git ls-files failed");
  const files = listed.stdout
    .split("\0")
    .filter(Boolean)
    .filter(isSourcePath)
    .sort();
  const hash = createHash("sha256");
  for (const relative of files) {
    const absolute = path.join(root, relative);
    let stats;
    try {
      stats = await lstat(absolute);
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
      // Keep a deleted tracked source path in the identity. This lets callers
      // report a dirty/mismatching tree instead of crashing before the clean
      // source-surface gate can explain the deletion.
      hash.update(relative);
      hash.update("\0missing\0\0");
      continue;
    }
    const type = stats.isFile()
      ? "file"
      : stats.isSymbolicLink()
        ? "symlink"
        : "unsupported";
    if (type === "unsupported") {
      throw new Error(`Unsupported source entry type: ${relative}`);
    }
    hash.update(relative);
    hash.update("\0");
    hash.update(type);
    hash.update("\0");
    // Git/source identity tracks executability, not host umask or whether the
    // independent evaluator has removed write bits from its clone.
    hash.update((stats.mode & 0o111).toString(8));
    hash.update("\0");
    hash.update(type === "file" ? await readFile(absolute) : await readlink(absolute));
    hash.update("\0");
  }
  return { hash: hash.digest("hex"), files: files.length };
}

function changedPaths(root) {
  const status = git(root, ["status", "--porcelain=v1", "-z", "--untracked-files=all"]);
  if (status.status !== 0) return { ok: false, paths: [] };
  const entries = status.stdout.split("\0");
  const paths = [];
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    if (!entry) continue;
    const code = entry.slice(0, 2);
    paths.push(entry.slice(3));
    // In porcelain -z format a rename/copy is followed by the original path.
    // Considering both sides prevents a source -> generated-evidence rename
    // from being mistaken for a clean source surface.
    if (/[RC]/.test(code)) {
      const original = entries[index + 1];
      if (original) paths.push(original);
      index += 1;
    }
  }
  return { ok: true, paths };
}

export async function evidenceProvenance(root) {
  const revision = frozenSourceRevision(root);
  const headResult = git(root, ["rev-parse", "HEAD"]);
  const headCandidate = headResult.status === 0 ? headResult.stdout.trim() : "";
  const headRevision = /^[a-f0-9]{40}$/.test(headCandidate) ? headCandidate : null;
  const tree = await sourceTreeHash(root);
  const status = changedPaths(root);
  const dirtySourcePaths = status.paths.filter(isSourcePath);
  return {
    sourceRevision: revision,
    headRevision,
    sourceTreeHash: tree.hash,
    sourceFileCount: tree.files,
    workingTreeCleanAtCapture: status.ok && dirtySourcePaths.length === 0,
  };
}

function cleanEnvironment() {
  const environment = {};
  for (const name of [
    "PATH",
    "HOME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "DOCKER_HOST",
    "CONTAINER_HOST",
    "XDG_RUNTIME_DIR",
  ]) {
    if (process.env[name] !== undefined) environment[name] = process.env[name];
  }
  return environment;
}

function inspectImage(root, reference, engine) {
  const result = spawnSync(engine, ["image", "inspect", reference], {
    cwd: root,
    env: cleanEnvironment(),
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
    timeout: 10_000,
  });
  if (result.status !== 0) {
    return {
      reference,
      imageId: null,
      imageDigest: null,
      status: "unverified",
      reason: (result.stderr || result.stdout || "image inspection failed").trim(),
    };
  }
  try {
    const record = JSON.parse(result.stdout)?.[0];
    const imageId = typeof record?.Id === "string" ? record.Id : null;
    const repoDigests = Array.isArray(record?.RepoDigests)
      ? record.RepoDigests.filter((value) => typeof value === "string").sort()
      : [];
    const imageDigest = repoDigests[0]?.split("@").at(-1) ?? imageId;
    const valid = /^sha256:[a-f0-9]{64}$/.test(imageDigest ?? "");
    return {
      reference,
      imageId,
      imageDigest,
      status: valid ? "verified" : "failed",
      reason: valid ? null : "container engine returned no immutable sha256 identity",
    };
  } catch (error) {
    return {
      reference,
      imageId: null,
      imageDigest: null,
      status: "failed",
      reason: error instanceof Error ? error.message : String(error),
    };
  }
}

function configuredCredential(environment, providerId) {
  const generic = (environment.MODEL_API_KEY ?? "").trim();
  const legacy = providerId === "ark" ? (environment.ARK_API_KEY ?? "").trim() : "";
  const value = generic || legacy;
  return value.length > 0 && !value.startsWith("replace-");
}

/**
 * Captures only non-secret execution identity.  Every machine-readable report
 * uses this shape so reports from different revisions/images/providers cannot
 * be silently combined by the scorer.
 */
export function executionIdentity(root, options = {}) {
  const environment = options.environment ?? process.env;
  const providerId = options.providerId ?? environment.MODEL_PROVIDER ?? "not-applicable";
  const providerApplicable = providerId !== "not-applicable";
  const gateway = providerApplicable
    ? (
        environment.MODEL_BASE_URL ??
        (providerId === "openrouter"
          ? "https://openrouter.ai/api/v1"
          : environment.ARK_BASE_URL ?? "https://ark.cn-beijing.volces.com/api/v3")
      ).replace(/\/+$/, "")
    : null;
  const requestedModel = providerApplicable
    ? (environment.MODEL_ID ?? environment.ARK_MODEL ?? "").trim() || null
    : null;
  const engine = environment.CONTAINER_ENGINE || "docker";
  const runtimeReference = environment.CONTAINER_RUNTIME_IMAGE || "volc-agent-runtime:local";
  const verifierReference = environment.COMMITGATE_VERIFIER_IMAGE || runtimeReference;
  const workerReference =
    environment.COMMITGATE_TRANSITION_WORKER_IMAGE || "commitgate-transition-worker:local";
  const brokerReference =
    environment.COMMITGATE_RUNTIME_BROKER_IMAGE || "commitgate-runtime-broker:local";
  const runtimeImage = inspectImage(root, runtimeReference, engine);
  const verifierImage = verifierReference === runtimeReference
    ? { ...runtimeImage }
    : inspectImage(root, verifierReference, engine);
  const workerImage = inspectImage(root, workerReference, engine);
  const brokerImage = inspectImage(root, brokerReference, engine);
  return {
    schemaVersion: 2,
    containerEngine: engine,
    runtimeImage,
    verifierImage,
    workerImage,
    brokerImage,
    provider: {
      providerId,
      gateway,
      requestedModel,
      resolvedModel: null,
      wireApi: providerApplicable ? environment.MODEL_WIRE_API ?? "responses" : null,
      accessMode: providerApplicable ? environment.MODEL_ACCESS_MODE ?? "direct" : null,
      credentialConfigured: providerApplicable && configuredCredential(environment, providerId),
      credentialsRecorded: false,
    },
  };
}

export function parseFlag(arguments_, name) {
  const exact = `--${name}`;
  const prefix = `${exact}=`;
  const index = arguments_.indexOf(exact);
  if (index >= 0) return arguments_[index + 1] ?? null;
  const inline = arguments_.find((argument) => argument.startsWith(prefix));
  return inline ? inline.slice(prefix.length) : null;
}

export function revisionIsAncestor(root, revision) {
  if (!revision || !/^[a-f0-9]{40}$/.test(revision)) return false;
  return git(root, ["merge-base", "--is-ancestor", revision, "HEAD"]).status === 0;
}
