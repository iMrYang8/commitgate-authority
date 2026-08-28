import { createHash } from "node:crypto";
import type { BigIntStats, Dirent } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import path from "node:path";

export interface WorkerManifestEntry {
  path: string;
  type: "directory" | "file";
  mode: number;
  size: number;
  hash: string | null;
}

export interface WorkerManifest {
  schemaVersion: 1;
  entries: WorkerManifestEntry[];
  hash: string;
}

const sha256 = (value: string | Buffer): string =>
  createHash("sha256").update(value).digest("hex");

const isSameReadIdentity = (
  before: BigIntStats,
  after: BigIntStats,
): boolean =>
  before.dev === after.dev &&
  before.ino === after.ino &&
  before.mode === after.mode &&
  before.size === after.size &&
  before.mtimeNs === after.mtimeNs &&
  before.ctimeNs === after.ctimeNs;

/**
 * Builds the transition-worker's closed authoritative-state manifest.
 * Directories and regular files are accepted; symlinks, special files and
 * multiply-linked files fail closed. File identity is checked before/after
 * each read so an inbox cannot be switched while it is imported.
 */
export async function buildWorkerManifest(root: string): Promise<WorkerManifest> {
  const entries: WorkerManifestEntry[] = [];
  const normalized = new Map<string, string>();
  const folded = new Map<string, string>();

  const visit = async (absoluteDirectory: string, relativeDirectory: string): Promise<void> => {
    const children = (await readdir(absoluteDirectory, { withFileTypes: true })).sort((a, b) =>
      a.name.localeCompare(b.name, "en"),
    );
    for (const child of children) {
      const relative = relativeDirectory
        ? `${relativeDirectory}/${child.name}`
        : child.name;
      const posixRelative = relative.split(path.sep).join("/");
      const nfc = posixRelative.normalize("NFC");
      const casefold = nfc.toLocaleLowerCase("und");
      const priorNormalized = normalized.get(nfc);
      if (priorNormalized && priorNormalized !== posixRelative) {
        throw new Error(`UNICODE_NORMALIZATION_COLLISION:${priorNormalized}:${posixRelative}`);
      }
      const priorFolded = folded.get(casefold);
      if (priorFolded && priorFolded !== posixRelative) {
        throw new Error(`CASEFOLD_PATH_COLLISION:${priorFolded}:${posixRelative}`);
      }
      normalized.set(nfc, posixRelative);
      folded.set(casefold, posixRelative);

      const absolute = path.join(absoluteDirectory, child.name);
      const before = await lstat(absolute, { bigint: true });
      const mode = Number(before.mode & 0o777n);
      if (before.isSymbolicLink()) throw new Error(`SYMLINK_FILE:${posixRelative}`);
      if (before.isDirectory()) {
        entries.push({ path: posixRelative, type: "directory", mode, size: 0, hash: null });
        await visit(absolute, posixRelative);
        continue;
      }
      if (!before.isFile()) throw new Error(`SPECIAL_FILE:${posixRelative}`);
      if (before.nlink > 1n) throw new Error(`HARDLINK_FILE:${posixRelative}`);
      const content = await readFile(absolute);
      const after = await lstat(absolute, { bigint: true });
      if (!isSameReadIdentity(before, after) || BigInt(content.byteLength) !== before.size) {
        throw new Error(`FILE_CHANGED_DURING_READ:${posixRelative}`);
      }
      entries.push({
        path: posixRelative,
        type: "file",
        mode,
        size: content.byteLength,
        hash: sha256(content),
      });
    }
  };

  const rootStat = await lstat(root, { bigint: true });
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    throw new Error("AUTHORITATIVE_ROOT_NOT_DIRECTORY");
  }
  await visit(root, "");
  entries.sort((left, right) => left.path.localeCompare(right.path, "en"));
  return {
    schemaVersion: 1,
    entries,
    hash: sha256(JSON.stringify({ schemaVersion: 1, entries })),
  };
}

export async function copyClosedTree(source: string, destination: string): Promise<WorkerManifest> {
  const before = await buildWorkerManifest(source);
  await rm(destination, { recursive: true, force: true });
  await mkdir(destination, { recursive: false, mode: 0o700 });
  try {
    for (const entry of before.entries) {
      const target = path.join(destination, ...entry.path.split("/"));
      const origin = path.join(source, ...entry.path.split("/"));
      if (entry.type === "directory") {
        await mkdir(target, { mode: entry.mode });
        continue;
      }
      const statBefore = await lstat(origin, { bigint: true });
      const content = await readFile(origin);
      const statAfter = await lstat(origin, { bigint: true });
      if (!isSameReadIdentity(statBefore, statAfter)) {
        throw new Error(`FILE_CHANGED_DURING_COPY:${entry.path}`);
      }
      await writeFile(target, content, { flag: "wx", mode: entry.mode });
    }
    // Apply directory modes after children have been materialized.
    for (const entry of [...before.entries].reverse()) {
      if (entry.type === "directory") {
        await chmod(path.join(destination, ...entry.path.split("/")), entry.mode);
      }
    }
    const [sourceAfter, copied] = await Promise.all([
      buildWorkerManifest(source),
      buildWorkerManifest(destination),
    ]);
    if (sourceAfter.hash !== before.hash || copied.hash !== before.hash) {
      throw new Error("TREE_CHANGED_DURING_COPY");
    }
    return copied;
  } catch (error) {
    await makeTreeWritable(destination).catch(() => undefined);
    await rm(destination, { recursive: true, force: true }).catch(() => undefined);
    throw error;
  }
}

export async function makeTreeReadonly(root: string): Promise<void> {
  // Entry modes are part of the artifact identity and must remain unchanged.
  // The tree root is omitted from the manifest, so making just that directory
  // non-writable gives the worker an application-level sealed boundary without
  // changing the proposal that will later be verified and promoted. OS-level
  // exclusion comes from the worker-only control-volume mount/UID.
  await chmod(root, 0o500);
}

export async function makeTreeWritable(root: string): Promise<void> {
  let children: Dirent[];
  try {
    await chmod(root, 0o700);
    children = await readdir(root, { withFileTypes: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  for (const child of children) {
    const absolute = path.join(root, child.name);
    const stat = await lstat(absolute);
    if (stat.isDirectory() && !stat.isSymbolicLink()) {
      await makeTreeWritable(absolute);
    } else {
      await chmod(absolute, 0o600).catch(() => undefined);
    }
  }
}

export async function assertSameFilesystem(left: string, right: string): Promise<void> {
  const [leftStat, rightStat] = await Promise.all([
    lstat(left, { bigint: true }),
    lstat(right, { bigint: true }),
  ]);
  if (leftStat.dev !== rightStat.dev) throw new Error("UNSUPPORTED_FILESYSTEM_EXDEV");
}
