import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  readFile,
  readdir,
  readlink,
  rm,
  symlink,
} from "node:fs/promises";
import path from "node:path";
import { classifyPath } from "./policy.js";
import type { CommitGatePolicy, PathClass } from "./types.js";
import type { SnapshotManifest } from "./types.js";

export function assertContained(parent: string, child: string, label = "path"): void {
  const root = path.resolve(parent);
  const resolved = path.resolve(child);
  if (resolved !== root && !resolved.startsWith(root + path.sep)) {
    throw new Error(label + " escapes its trusted root");
  }
}

export function assertSafeIdentifier(value: string, label: string): void {
  if (!/^[A-Za-z0-9_.-]{1,128}$/.test(value) || value === "." || value === "..") {
    throw new Error(label + " contains unsafe characters");
  }
}

export async function pathExists(value: string): Promise<boolean> {
  try {
    await lstat(value);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

export interface CopyWorkspaceOptions {
  include?: ReadonlySet<PathClass>;
  cleanDestination?: boolean;
}

export async function copyWorkspace(
  source: string,
  destination: string,
  policy: CommitGatePolicy,
  options: CopyWorkspaceOptions = {},
): Promise<void> {
  const sourceRoot = path.resolve(source);
  const destinationRoot = path.resolve(destination);
  if (sourceRoot === destinationRoot || destinationRoot.startsWith(sourceRoot + path.sep)) {
    throw new Error("Destination must not be inside source workspace");
  }
  if (options.cleanDestination !== false) await rm(destinationRoot, { recursive: true, force: true });
  await mkdir(destinationRoot, { recursive: true, mode: 0o700 });
  const include = options.include ?? new Set<PathClass>(["versioned", "platformManaged", "ignoredEphemeral"]);

  async function walk(sourceDirectory: string, relativeDirectory: string): Promise<void> {
    const names = (await readdir(sourceDirectory)).sort((a, b) => a.localeCompare(b, "en"));
    for (const name of names) {
      const relative = relativeDirectory ? relativeDirectory + "/" + name : name;
      const sourcePath = path.join(sourceDirectory, name);
      const destinationPath = path.join(destinationRoot, ...relative.split("/"));
      assertContained(destinationRoot, destinationPath, "copy destination");
      const stats = await lstat(sourcePath);
      const pathClass = classifyPath(relative, policy);
      if (stats.isSocket() || stats.isFIFO() || stats.isBlockDevice() || stats.isCharacterDevice()) {
        throw new Error("SPECIAL_FILE:" + relative);
      }
      if (stats.isDirectory()) {
        if (include.has(pathClass)) {
          await mkdir(destinationPath, { recursive: true, mode: 0o700 });
        }
        if (pathClass !== "ignoredEphemeral" || include.has("ignoredEphemeral")) {
          await walk(sourcePath, relative);
        }
        if (include.has(pathClass)) await chmod(destinationPath, stats.mode & 0o777);
      } else if (include.has(pathClass)) {
        await mkdir(path.dirname(destinationPath), { recursive: true, mode: 0o700 });
        if (stats.isFile()) {
          await copyFile(sourcePath, destinationPath);
          await chmod(destinationPath, stats.mode & 0o777);
        } else if (stats.isSymbolicLink()) {
          await rm(destinationPath, { recursive: true, force: true });
          await symlink(await readlink(sourcePath), destinationPath);
        } else {
          throw new Error("SPECIAL_FILE:" + relative);
        }
      }
    }
  }
  await walk(sourceRoot, "");
}

/** Restore the proposal's intended POSIX modes after copying from a read-only sealed tree. */
export async function applyManifestModes(
  root: string,
  manifest: SnapshotManifest,
  include: ReadonlySet<PathClass> = new Set(["versioned", "platformManaged"]),
): Promise<void> {
  const selected = manifest.entries.filter((entry) => include.has(entry.pathClass));
  const files = selected.filter((entry) => entry.type === "file");
  const directories = selected
    .filter((entry) => entry.type === "dir")
    .sort((left, right) => right.path.split("/").length - left.path.split("/").length);
  for (const entry of [...files, ...directories]) {
    const absolute = path.resolve(root, ...entry.path.split("/"));
    assertContained(root, absolute, "manifest mode path");
    await chmod(absolute, entry.mode & 0o777);
  }
}

export async function readChangedFileBuffers(
  root: string,
  paths: string[],
  maxBytes: number,
): Promise<Array<{ path: string; content: Buffer }>> {
  const result: Array<{ path: string; content: Buffer }> = [];
  for (const relative of paths) {
    const absolute = path.resolve(root, ...relative.split("/"));
    assertContained(root, absolute, "changed path");
    try {
      const stats = await lstat(absolute);
      if (!stats.isFile() || stats.size > maxBytes) continue;
      const buffer = await readFile(absolute);
      result.push({ path: relative, content: buffer });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
  return result;
}

export async function readChangedTextFiles(
  root: string,
  paths: string[],
  maxBytes: number,
): Promise<Array<{ path: string; content: string }>> {
  return (await readChangedFileBuffers(root, paths, maxBytes))
    .filter((file) => !file.content.includes(0))
    .map((file) => ({ path: file.path, content: file.content.toString("utf8") }));
}
