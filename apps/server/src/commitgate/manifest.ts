import { createHash } from "node:crypto";
import { open } from "node:fs/promises";
import { lstat, readdir } from "node:fs/promises";
import path from "node:path";
import { classifyPath } from "./policy.js";
import type {
  CommitGatePolicy,
  ManifestChange,
  ManifestEntry,
  PathClass,
  SnapshotManifest,
} from "./types.js";

const sha256 = (value: string | Buffer): string =>
  createHash("sha256").update(value).digest("hex");

export function assertNoPathIdentityCollisions(paths: readonly string[]): void {
  const normalizedPaths = new Map<string, string>();
  const caseFoldedPaths = new Map<string, string>();
  for (const relative of paths) {
    const normalized = relative.normalize("NFC");
    const normalizedPrior = normalizedPaths.get(normalized);
    if (normalizedPrior && normalizedPrior !== relative) {
      throw new Error(`UNICODE_NORMALIZATION_COLLISION:${normalizedPrior}:${relative}`);
    }
    normalizedPaths.set(normalized, relative);
    const folded = normalized.toLowerCase();
    const casePrior = caseFoldedPaths.get(folded);
    if (casePrior && casePrior !== relative) {
      throw new Error(`CASEFOLD_PATH_COLLISION:${casePrior}:${relative}`);
    }
    caseFoldedPaths.set(folded, relative);
  }
}

async function sha256File(filePath: string): Promise<string> {
  const handle = await open(filePath, "r");
  try {
    const before = await handle.stat();
    if (!before.isFile()) throw new Error("FILE_TYPE_CHANGED_DURING_READ:" + filePath);
    const hash = createHash("sha256");
    for await (const chunk of handle.createReadStream({ autoClose: false })) {
      hash.update(chunk as Buffer);
    }
    const after = await handle.stat();
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mode !== after.mode ||
      before.nlink !== after.nlink ||
      before.mtimeMs !== after.mtimeMs ||
      before.ctimeMs !== after.ctimeMs
    ) {
      throw new Error("FILE_MUTATED_DURING_READ:" + filePath);
    }
    return hash.digest("hex");
  } finally {
    await handle.close();
  }
}

export interface ManifestOptions {
  include?: ReadonlySet<PathClass>;
}

export async function buildManifest(
  root: string,
  policy: CommitGatePolicy,
  options: ManifestOptions = {},
): Promise<SnapshotManifest> {
  const include = options.include ?? new Set<PathClass>(["versioned", "platformManaged"]);
  const entries: ManifestEntry[] = [];
  const authoritativePaths: string[] = [];
  const rootStats = await lstat(path.resolve(root));
  if (!rootStats.isDirectory() || rootStats.isSymbolicLink()) {
    throw new Error("AUTHORITATIVE_ROOT_INVALID");
  }

  function registerAuthoritativePath(relative: string): void {
    authoritativePaths.push(relative);
    assertNoPathIdentityCollisions(authoritativePaths);
  }

  async function walk(absoluteDirectory: string, relativeDirectory: string): Promise<void> {
    const names = (await readdir(absoluteDirectory)).sort((left, right) =>
      left < right ? -1 : left > right ? 1 : 0,
    );
    for (const name of names) {
      const relative = relativeDirectory ? relativeDirectory + "/" + name : name;
      const absolute = path.join(absoluteDirectory, name);
      const stats = await lstat(absolute);
      const pathClass = classifyPath(relative, policy);
      if (
        include.has(pathClass) &&
        (stats.uid !== rootStats.uid || stats.gid !== rootStats.gid)
      ) {
        throw new Error("OWNERSHIP_MISMATCH:" + relative);
      }
      if (stats.isSocket() || stats.isFIFO() || stats.isBlockDevice() || stats.isCharacterDevice()) {
        throw new Error("SPECIAL_FILE:" + relative);
      }
      if (stats.isDirectory()) {
        if (include.has(pathClass)) {
          registerAuthoritativePath(relative);
          entries.push({ path: relative, type: "dir", mode: stats.mode & 0o777, size: 0, pathClass });
        }
        if (pathClass !== "ignoredEphemeral" || include.has("ignoredEphemeral")) {
          await walk(absolute, relative);
        }
      } else if (stats.isFile()) {
        if (include.has(pathClass)) {
          registerAuthoritativePath(relative);
          if (stats.nlink > 1) throw new Error("HARDLINK_FILE:" + relative);
          if (
            process.platform === "linux" &&
            stats.size > 0 &&
            stats.blocks * 512 < stats.size
          ) {
            throw new Error("SPARSE_FILE:" + relative);
          }
          entries.push({
            path: relative,
            type: "file",
            mode: stats.mode & 0o777,
            size: stats.size,
            contentHash: await sha256File(absolute),
            pathClass,
          });
        }
      } else if (stats.isSymbolicLink()) {
        if (include.has(pathClass)) {
          throw new Error("SYMLINK_FILE:" + relative);
        }
      } else {
        throw new Error("SPECIAL_FILE:" + relative);
      }
    }
  }

  await walk(path.resolve(root), "");
  entries.sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  return { schemaVersion: 2, entries, hash: hashManifestEntries(entries) };
}

export function hashManifestEntries(entries: ManifestEntry[]): string {
  const canonical = entries.map((entry) => ({
    path: entry.path,
    type: entry.type,
    mode: entry.mode,
    size: entry.size,
    contentHash: entry.contentHash ?? null,
    linkTarget: entry.linkTarget ?? null,
    pathClass: entry.pathClass,
  }));
  return sha256(JSON.stringify(canonical));
}

function sameEntry(left: ManifestEntry, right: ManifestEntry): boolean {
  return (
    left.type === right.type &&
    left.mode === right.mode &&
    left.size === right.size &&
    left.contentHash === right.contentHash &&
    left.linkTarget === right.linkTarget &&
    left.pathClass === right.pathClass
  );
}

export function diffManifests(
  before: SnapshotManifest,
  after: SnapshotManifest,
): ManifestChange[] {
  const left = new Map(before.entries.map((entry) => [entry.path, entry]));
  const right = new Map(after.entries.map((entry) => [entry.path, entry]));
  const paths = [...new Set([...left.keys(), ...right.keys()])].sort((a, b) => a.localeCompare(b, "en"));
  const changes: ManifestChange[] = [];
  for (const itemPath of paths) {
    const oldEntry = left.get(itemPath) ?? null;
    const newEntry = right.get(itemPath) ?? null;
    if (!oldEntry && newEntry) changes.push({ path: itemPath, kind: "added", before: null, after: newEntry });
    else if (oldEntry && !newEntry) changes.push({ path: itemPath, kind: "deleted", before: oldEntry, after: null });
    else if (oldEntry && newEntry && !sameEntry(oldEntry, newEntry)) {
      changes.push({ path: itemPath, kind: "modified", before: oldEntry, after: newEntry });
    }
  }
  return changes;
}

export function patchHash(changes: ManifestChange[]): string {
  return sha256(
    JSON.stringify(
      changes.map((change) => ({
        path: change.path,
        kind: change.kind,
        before: change.before
          ? [change.before.type, change.before.mode, change.before.size, change.before.contentHash ?? null, change.before.linkTarget ?? null]
          : null,
        after: change.after
          ? [change.after.type, change.after.mode, change.after.size, change.after.contentHash ?? null, change.after.linkTarget ?? null]
          : null,
      })),
    ),
  );
}

export function changedByteCount(changes: ManifestChange[]): number {
  return changes.reduce((sum, change) => {
    const before = change.before?.type === "file" ? change.before.size : 0;
    const after = change.after?.type === "file" ? change.after.size : 0;
    return sum + Math.max(before, after);
  }, 0);
}
