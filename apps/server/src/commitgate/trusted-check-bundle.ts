import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readdir,
  rename,
  rm,
} from "node:fs/promises";
import path from "node:path";
import { pathExists } from "./file-ops.js";
import { sha256Canonical } from "./protocol.js";
import type { RequiredCheckPolicy } from "./types.js";

export interface TrustedCheckBundleDescriptor {
  schemaVersion: 1;
  hash: string;
  entries: Array<{
    path: string;
    type: "file" | "dir";
    mode: number;
    size: number;
    contentHash?: string;
  }>;
}

export interface SealedTrustedCheckBundle {
  schemaVersion: 1;
  hash: string;
  payloadPath: string;
  descriptor: TrustedCheckBundleDescriptor;
}

export function assertTrustedCheckBundleDescriptor(
  descriptor: TrustedCheckBundleDescriptor,
): void {
  const collisionKeys = new Map<string, string>();
  for (const entry of descriptor.entries) {
    const collisionKey = entry.path.normalize("NFC").toLowerCase();
    const previous = collisionKeys.get(collisionKey);
    if (previous && previous !== entry.path) {
      throw new Error(
        `Trusted check bundle has a case/Unicode path collision: ${previous} and ${entry.path}`,
      );
    }
    collisionKeys.set(collisionKey, entry.path);
  }
  if (!descriptor.entries.some((entry) => entry.type === "file")) {
    throw new Error("Trusted check bundle must contain at least one regular file");
  }
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function assertSeparated(sourceRoot: string, storeRoot: string): void {
  if (
    sourceRoot === storeRoot ||
    sourceRoot.startsWith(storeRoot + path.sep) ||
    storeRoot.startsWith(sourceRoot + path.sep)
  ) {
    throw new Error("TRUSTED_CHECK_STORE_MUST_BE_SEPARATE_FROM_SOURCE");
  }
}

function contentIdentity(descriptor: TrustedCheckBundleDescriptor): string {
  return sha256Canonical(
    descriptor.entries.map(({ path: entryPath, type, size, contentHash }) => ({
      path: entryPath,
      type,
      size,
      contentHash: contentHash ?? null,
    })),
  );
}

function readonlyFileMode(sourceMode: number): number {
  return sourceMode & 0o111 ? 0o555 : 0o444;
}

async function copyTrustedFile(
  source: string,
  destination: string,
  expectedHash: string,
  sourceMode: number,
): Promise<void> {
  const sourceHandle = await open(source, constants.O_RDONLY | constants.O_NOFOLLOW);
  let destinationHandle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    const before = await sourceHandle.stat();
    if (!before.isFile() || before.nlink !== 1) {
      throw new Error("TRUSTED_CHECK_FILE_INVALID:" + source);
    }
    destinationHandle = await open(destination, "wx", readonlyFileMode(sourceMode));
    const hash = createHash("sha256");
    for await (const value of sourceHandle.createReadStream({ autoClose: false })) {
      const chunk = value as Buffer;
      hash.update(chunk);
      let offset = 0;
      while (offset < chunk.byteLength) {
        const { bytesWritten } = await destinationHandle.write(
          chunk,
          offset,
          chunk.byteLength - offset,
        );
        if (bytesWritten <= 0) {
          throw new Error("TRUSTED_CHECK_COPY_SHORT_WRITE:" + source);
        }
        offset += bytesWritten;
      }
    }
    const after = await sourceHandle.stat();
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mode !== after.mode ||
      before.mtimeMs !== after.mtimeMs ||
      before.ctimeMs !== after.ctimeMs
    ) {
      throw new Error("TRUSTED_CHECK_MUTATED_DURING_COPY:" + source);
    }
    if (hash.digest("hex") !== expectedHash) {
      throw new Error("TRUSTED_CHECK_COPY_DIGEST_MISMATCH:" + source);
    }
    await destinationHandle.chmod(readonlyFileMode(sourceMode));
  } finally {
    await destinationHandle?.close().catch(() => undefined);
    await sourceHandle.close();
  }
}

async function copyBundleFromDescriptor(
  sourceRoot: string,
  destinationRoot: string,
  descriptor: TrustedCheckBundleDescriptor,
): Promise<void> {
  await mkdir(destinationRoot, { recursive: false, mode: 0o700 });
  const entries = [...descriptor.entries].sort((left, right) =>
    compareStrings(left.path, right.path),
  );
  for (const entry of entries) {
    const destination = path.join(destinationRoot, ...entry.path.split("/"));
    const source = path.join(sourceRoot, ...entry.path.split("/"));
    if (entry.type === "dir") {
      await mkdir(destination, { recursive: true, mode: 0o700 });
      continue;
    }
    if (!entry.contentHash) {
      throw new Error("TRUSTED_CHECK_DESCRIPTOR_MISSING_HASH:" + entry.path);
    }
    await mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
    await copyTrustedFile(source, destination, entry.contentHash, entry.mode);
  }

  // Normalize every directory only after all descendants have been created.
  const directories = entries
    .filter((entry) => entry.type === "dir")
    .sort((left, right) => right.path.length - left.path.length);
  for (const directory of directories) {
    await chmod(path.join(destinationRoot, ...directory.path.split("/")), 0o555);
  }
  await chmod(destinationRoot, 0o555);
}

async function makeBundleMutable(root: string): Promise<void> {
  if (!(await pathExists(root))) return;
  await chmod(root, 0o700);
  const entries = await readdir(root, { withFileTypes: true });
  for (const entry of entries) {
    const child = path.join(root, entry.name);
    if (entry.isDirectory()) await makeBundleMutable(child);
    else await chmod(child, 0o600);
  }
}

async function hashFile(filePath: string): Promise<string> {
  const handle = await open(filePath, "r");
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.nlink > 1) {
      throw new Error("TRUSTED_CHECK_FILE_INVALID:" + filePath);
    }
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
      before.mtimeMs !== after.mtimeMs ||
      before.ctimeMs !== after.ctimeMs
    ) {
      throw new Error("TRUSTED_CHECK_MUTATED_DURING_HASH:" + filePath);
    }
    return hash.digest("hex");
  } finally {
    await handle.close();
  }
}

export async function describeTrustedCheckBundle(
  root: string,
): Promise<TrustedCheckBundleDescriptor> {
  const entries: TrustedCheckBundleDescriptor["entries"] = [];
  if (await pathExists(root)) {
    const rootStats = await lstat(root);
    if (!rootStats.isDirectory() || rootStats.isSymbolicLink()) {
      throw new Error("TRUSTED_CHECK_ROOT_INVALID:" + root);
    }
    const walk = async (directory: string, relativeDirectory: string): Promise<void> => {
      const names = (await readdir(directory)).sort((left, right) =>
        left < right ? -1 : left > right ? 1 : 0,
      );
      for (const name of names) {
        const relative = relativeDirectory ? `${relativeDirectory}/${name}` : name;
        const absolute = path.join(directory, name);
        const stats = await lstat(absolute);
        if (stats.isSymbolicLink()) throw new Error("TRUSTED_CHECK_SYMLINK:" + relative);
        if (stats.isDirectory()) {
          entries.push({ path: relative, type: "dir", mode: stats.mode & 0o777, size: 0 });
          await walk(absolute, relative);
        } else if (stats.isFile()) {
          if (stats.nlink > 1) throw new Error("TRUSTED_CHECK_HARDLINK:" + relative);
          entries.push({
            path: relative,
            type: "file",
            mode: stats.mode & 0o777,
            size: stats.size,
            contentHash: await hashFile(absolute),
          });
        } else {
          throw new Error("TRUSTED_CHECK_SPECIAL_FILE:" + relative);
        }
      }
    };
    await walk(path.resolve(root), "");
  }
  const unsigned = { schemaVersion: 1 as const, entries };
  return {
    ...unsigned,
    hash: createHash("sha256")
      .update(JSON.stringify(unsigned))
      .digest("hex"),
  };
}

/**
 * Imports administrator-managed checks into a gate-owned, content-addressed
 * tree. A run binds to this immutable payload, never to the mutable source
 * directory. Source changes therefore create a new hash for a later run rather
 * than changing the bytes mounted by an admitted run.
 */
export class TrustedCheckBundleStore {
  readonly sourceRoot: string;
  readonly storeRoot: string;

  constructor(sourceRoot: string, storeRoot: string) {
    this.sourceRoot = path.resolve(sourceRoot);
    this.storeRoot = path.resolve(storeRoot);
    assertSeparated(this.sourceRoot, this.storeRoot);
  }

  async seal(): Promise<SealedTrustedCheckBundle> {
    const sourceBefore = await describeTrustedCheckBundle(this.sourceRoot);
    assertTrustedCheckBundleDescriptor(sourceBefore);
    await mkdir(path.join(this.storeRoot, "tmp"), {
      recursive: true,
      mode: 0o700,
    });
    const tempPath = path.join(this.storeRoot, "tmp", randomUUID());
    try {
      await copyBundleFromDescriptor(this.sourceRoot, tempPath, sourceBefore);
      const [sourceAfter, sealedDescriptor] = await Promise.all([
        describeTrustedCheckBundle(this.sourceRoot),
        describeTrustedCheckBundle(tempPath),
      ]);
      assertTrustedCheckBundleDescriptor(sourceAfter);
      assertTrustedCheckBundleDescriptor(sealedDescriptor);
      if (sourceAfter.hash !== sourceBefore.hash) {
        throw new Error("TRUSTED_CHECK_BUNDLE_MUTATED_DURING_SEAL");
      }
      if (contentIdentity(sourceBefore) !== contentIdentity(sealedDescriptor)) {
        throw new Error("TRUSTED_CHECK_BUNDLE_SEALED_CONTENT_MISMATCH");
      }

      const payloadPath = path.join(
        this.storeRoot,
        "payloads",
        sealedDescriptor.hash,
      );
      await mkdir(path.dirname(payloadPath), { recursive: true, mode: 0o700 });
      if (await pathExists(payloadPath)) {
        const existing = await this.resolve(sealedDescriptor.hash);
        await makeBundleMutable(tempPath);
        await rm(tempPath, { recursive: true, force: true });
        return existing;
      }
      try {
        // macOS requires owner-write permission on a directory being moved.
        // Root mode is not a descriptor entry; descendants stay readonly and
        // the root is restored immediately after the atomic rename.
        await chmod(tempPath, 0o700);
        await rename(tempPath, payloadPath);
        await chmod(payloadPath, 0o555);
      } catch (error) {
        if (!(await pathExists(payloadPath))) throw error;
        const existing = await this.resolve(sealedDescriptor.hash);
        await makeBundleMutable(tempPath);
        await rm(tempPath, { recursive: true, force: true });
        return existing;
      }
      return {
        schemaVersion: 1,
        hash: sealedDescriptor.hash,
        payloadPath,
        descriptor: sealedDescriptor,
      };
    } catch (error) {
      await makeBundleMutable(tempPath).catch(() => undefined);
      await rm(tempPath, { recursive: true, force: true }).catch(() => undefined);
      throw error;
    }
  }

  async resolve(hash: string): Promise<SealedTrustedCheckBundle> {
    if (!/^[a-f0-9]{64}$/.test(hash)) {
      throw new Error("TRUSTED_CHECK_BUNDLE_HASH_INVALID");
    }
    const payloadPath = path.join(this.storeRoot, "payloads", hash);
    const rootBefore = await lstat(payloadPath);
    if (
      !rootBefore.isDirectory() ||
      rootBefore.isSymbolicLink() ||
      (rootBefore.mode & 0o222) !== 0
    ) {
      throw new Error("TRUSTED_CHECK_BUNDLE_ROOT_NOT_READONLY");
    }
    const descriptor = await describeTrustedCheckBundle(payloadPath);
    assertTrustedCheckBundleDescriptor(descriptor);
    if (descriptor.hash !== hash) {
      throw new Error("TRUSTED_CHECK_BUNDLE_PAYLOAD_CORRUPT");
    }
    const rootAfter = await lstat(payloadPath);
    if (
      rootAfter.dev !== rootBefore.dev ||
      rootAfter.ino !== rootBefore.ino ||
      rootAfter.mode !== rootBefore.mode ||
      rootAfter.ctimeMs !== rootBefore.ctimeMs ||
      (rootAfter.mode & 0o222) !== 0
    ) {
      throw new Error("TRUSTED_CHECK_BUNDLE_ROOT_CHANGED_DURING_RESOLVE");
    }
    return { schemaVersion: 1, hash, payloadPath, descriptor };
  }
}

export function computeCheckSpecHash(checks: readonly RequiredCheckPolicy[]): string {
  return sha256Canonical(
    checks.map((check) => ({
      id: check.id,
      runner: check.runner,
      entrypoint: check.entrypoint,
      args: check.args,
      timeoutMs: check.timeoutMs,
      scratchBytes: check.scratchBytes,
    })),
  );
}
