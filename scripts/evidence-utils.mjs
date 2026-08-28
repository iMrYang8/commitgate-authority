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
    relative === "Dockerfile.runtime" ||
    relative.startsWith("Dockerfile.") ||
    relative.startsWith(".github/") ||
    relative.startsWith("apps/") ||
    relative.startsWith("scripts/") ||
    relative.startsWith("docs/") ||
    relative.startsWith("eval/trusted-checks/") ||
    relative === "eval/demo-policy.json"
  );
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
    const stats = await lstat(absolute);
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

export async function evidenceProvenance(root) {
  const revisionResult = git(root, ["rev-parse", "HEAD"]);
  const revision = revisionResult.status === 0 ? revisionResult.stdout.trim() : null;
  const tree = await sourceTreeHash(root);
  const status = git(root, ["status", "--porcelain", "--untracked-files=all"]);
  const dirtySourcePaths = status.stdout
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => line.slice(3).split(" -> ").at(-1) ?? "")
    .filter(isSourcePath);
  return {
    sourceRevision: revision,
    sourceTreeHash: tree.hash,
    sourceFileCount: tree.files,
    workingTreeCleanAtCapture: status.status === 0 && dirtySourcePaths.length === 0,
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
  const providerId = options.providerId ?? environment.MODEL_PROVIDER ?? "ark";
  const gateway = (
    environment.MODEL_BASE_URL ??
    (providerId === "openrouter"
      ? "https://openrouter.ai/api/v1"
      : environment.ARK_BASE_URL ?? "https://ark.cn-beijing.volces.com/api/v3")
  ).replace(/\/+$/, "");
  const requestedModel = (environment.MODEL_ID ?? environment.ARK_MODEL ?? "").trim() || null;
  const engine = environment.CONTAINER_ENGINE || "docker";
  const runtimeReference = environment.CONTAINER_RUNTIME_IMAGE || "volc-agent-runtime:local";
  const verifierReference = environment.COMMITGATE_VERIFIER_IMAGE || runtimeReference;
  const runtimeImage = inspectImage(root, runtimeReference, engine);
  const verifierImage = verifierReference === runtimeReference
    ? { ...runtimeImage }
    : inspectImage(root, verifierReference, engine);
  return {
    schemaVersion: 1,
    containerEngine: engine,
    runtimeImage,
    verifierImage,
    provider: {
      providerId,
      gateway,
      requestedModel,
      resolvedModel: null,
      wireApi: environment.MODEL_WIRE_API ?? "responses",
      accessMode: environment.MODEL_ACCESS_MODE ?? "direct",
      credentialConfigured: configuredCredential(environment, providerId),
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
