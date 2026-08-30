import { createHash } from "node:crypto";
import { constants, type BigIntStats, type Dirent } from "node:fs";
import { chmod, lstat, mkdir, open, opendir, readdir, rm } from "node:fs/promises";
import path from "node:path";
import { hashManifestEntries } from "../commitgate/manifest.js";
import {
  DEFAULT_CANDIDATE_RESOURCE_LIMITS,
  normalizeCandidateResourceLimits,
  type CandidateResourceLimits,
} from "../commitgate/resource-budget.js";
import {
  classifyPath,
  defaultCommitGatePolicy,
  DEFAULT_IGNORED_EPHEMERAL_NAMES,
} from "../commitgate/policy.js";
import type {
  CommitGatePolicy,
  ManifestEntry,
  SnapshotManifest,
} from "../commitgate/types.js";

export const WORKER_MANIFEST_SCHEMA_VERSION = 2 as const;

export type WorkerManifestEntry = ManifestEntry;

export interface WorkerResourceLimits extends CandidateResourceLimits {
  /** Includes authoritative and ignored directories/files. */
  maxScannedEntries: number;
  /** Logical bytes, not allocated blocks, across the complete candidate tree. */
  maxScannedBytes: number;
  /** Wall-clock budget for one complete manifest walk. */
  maxScanDurationMs: number;
}

export const DEFAULT_WORKER_RESOURCE_LIMITS: WorkerResourceLimits = Object.freeze({
  ...DEFAULT_CANDIDATE_RESOURCE_LIMITS,
  maxScannedEntries: 100_000,
  maxScannedBytes: 2 * 1024 * 1024 * 1024,
  maxScanDurationMs: 30_000,
});

export interface WorkerResourceUsage {
  scannedEntries: number;
  scannedFiles: number;
  scannedBytes: number;
  authoritativeEntries: number;
  authoritativeFiles: number;
  authoritativeBytes: number;
  ignoredEntries: number;
  ignoredFiles: number;
  ignoredBytes: number;
}

export interface WorkerExtendedMetadata {
  /** Names only. Values must never enter an event log or receipt. */
  xattrs: readonly string[];
  /** Only non-trivial ACL entries; the three POSIX mode-derived entries are omitted. */
  aclEntries: readonly string[];
}

export type WorkerExtendedMetadataInspector = (
  absolutePath: string,
) => Promise<WorkerExtendedMetadata>;

export interface WorkerManifestOptions {
  policy?: CommitGatePolicy;
  resourceLimits?: Partial<WorkerResourceLimits>;
  expectedUid?: number;
  expectedGid?: number;
  /** Reject when xattr/ACL inspection is unavailable instead of weakening the claim. */
  requireExtendedMetadataInspection?: boolean;
  extendedMetadataInspector?: WorkerExtendedMetadataInspector;
  /** Linux exposes allocated block counts used to reject sparse files. */
  requireSparseFileDetection?: boolean;
  /** Reject nested mount points as well as rename-swap across devices. */
  requireSingleFilesystem?: boolean;
  /** Deterministic test hook; production uses performance.now(). */
  monotonicNow?: () => number;
}

/**
 * Docker creates a missing tmpfs mount target as root before mounting it.  A
 * later manifest walk would therefore reject the engine-created directory as
 * foreign-owned even though the Agent itself ran as the normalized workspace
 * user.  Materialize the fixed root-level targets while the Worker still owns
 * the candidate so Docker only covers existing, normalized empty directories.
 *
 * These paths remain ignored ephemeral state: they are charged to resource
 * usage by buildWorkerManifest, but never enter the authoritative entry hash.
 */
export async function prepareRuntimeIgnoredMountpoints(root: string): Promise<void> {
  const absoluteRoot = path.resolve(root);
  const rootStat = await lstat(absoluteRoot, { bigint: true });
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    throw new Error("AUTHORITATIVE_ROOT_NOT_DIRECTORY");
  }

  for (const relative of DEFAULT_IGNORED_EPHEMERAL_NAMES) {
    const target = path.join(absoluteRoot, relative);
    try {
      await mkdir(target, { mode: 0o700 });
      // mkdir(2)'s mode is umask-filtered; normalize it explicitly.
      await chmod(target, 0o700);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }

    const targetStat = await lstat(target, { bigint: true });
    if (!targetStat.isDirectory() || targetStat.isSymbolicLink()) {
      throw new Error(`RUNTIME_IGNORED_MOUNTPOINT_NOT_DIRECTORY:${relative}`);
    }
    if (targetStat.uid !== rootStat.uid || targetStat.gid !== rootStat.gid) {
      throw new Error(`RUNTIME_IGNORED_MOUNTPOINT_OWNERSHIP_MISMATCH:${relative}`);
    }
    if (Number(targetStat.mode & 0o777n) !== 0o700) {
      throw new Error(`RUNTIME_IGNORED_MOUNTPOINT_MODE_MISMATCH:${relative}`);
    }
    if ((await readdir(target)).length !== 0) {
      throw new Error(`RUNTIME_IGNORED_MOUNTPOINT_NOT_EMPTY:${relative}`);
    }
  }
}

export interface WorkerFilesystemSupportMatrix {
  platform: NodeJS.Platform;
  regularFilesAndDirectoriesOnly: "enforced";
  symlinksAndHardlinks: "rejected";
  pathIdentityCollisions: "rejected";
  ownership: "enforced";
  posixMode: "enforced";
  singleFilesystem: "enforced" | "not-requested";
  sparseFiles: "enforced" | "unsupported";
  extendedAttributesAndAcl: "enforced" | "unsupported-not-inspected";
}

export interface WorkerManifest extends SnapshotManifest {
  schemaVersion: typeof WORKER_MANIFEST_SCHEMA_VERSION;
  entries: WorkerManifestEntry[];
  /** Audit-only usage. It is deliberately excluded from the authoritative hash. */
  resourceUsage: WorkerResourceUsage;
  filesystemSupport: WorkerFilesystemSupportMatrix;
}

const compareCanonicalPath = (left: string, right: string): number =>
  left < right ? -1 : left > right ? 1 : 0;

const isSameReadIdentity = (before: BigIntStats, after: BigIntStats): boolean =>
  before.dev === after.dev &&
  before.ino === after.ino &&
  before.mode === after.mode &&
  before.nlink === after.nlink &&
  before.uid === after.uid &&
  before.gid === after.gid &&
  before.size === after.size &&
  before.mtimeNs === after.mtimeNs &&
  before.ctimeNs === after.ctimeNs;

function normalizedWorkerResourceLimits(
  overrides: Partial<WorkerResourceLimits> = {},
): WorkerResourceLimits {
  const candidate = normalizeCandidateResourceLimits({
    maxIgnoredEntries:
      overrides.maxIgnoredEntries ?? DEFAULT_WORKER_RESOURCE_LIMITS.maxIgnoredEntries,
    maxIgnoredBytes:
      overrides.maxIgnoredBytes ?? DEFAULT_WORKER_RESOURCE_LIMITS.maxIgnoredBytes,
    maxIgnoredSingleFileBytes:
      overrides.maxIgnoredSingleFileBytes ??
      DEFAULT_WORKER_RESOURCE_LIMITS.maxIgnoredSingleFileBytes,
  });
  const result = {
    ...candidate,
    maxScannedEntries:
      overrides.maxScannedEntries ?? DEFAULT_WORKER_RESOURCE_LIMITS.maxScannedEntries,
    maxScannedBytes:
      overrides.maxScannedBytes ?? DEFAULT_WORKER_RESOURCE_LIMITS.maxScannedBytes,
    maxScanDurationMs:
      overrides.maxScanDurationMs ?? DEFAULT_WORKER_RESOURCE_LIMITS.maxScanDurationMs,
  };
  for (const [name, value] of Object.entries(result)) {
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new Error(`${name} must be a positive safe integer`);
    }
  }
  return result;
}

export function workerFilesystemSupportMatrix(
  options: WorkerManifestOptions = {},
): WorkerFilesystemSupportMatrix {
  return {
    platform: process.platform,
    regularFilesAndDirectoriesOnly: "enforced",
    symlinksAndHardlinks: "rejected",
    pathIdentityCollisions: "rejected",
    ownership: "enforced",
    posixMode: "enforced",
    singleFilesystem:
      options.requireSingleFilesystem === false ? "not-requested" : "enforced",
    sparseFiles: process.platform === "linux" ? "enforced" : "unsupported",
    extendedAttributesAndAcl: options.extendedMetadataInspector
      ? "enforced"
      : "unsupported-not-inspected",
  };
}

/**
 * Use this in a strong-guarantee preflight. Portable development can still
 * build manifests, while an evaluator that claims xattr/ACL closure must
 * provide an inspector and run on Linux.
 */
export function assertWorkerStrongFilesystemSupport(
  options: WorkerManifestOptions = {},
): void {
  const support = workerFilesystemSupportMatrix(options);
  if (support.sparseFiles !== "enforced") {
    throw new Error("SPARSE_FILE_DETECTION_UNAVAILABLE");
  }
  if (support.extendedAttributesAndAcl !== "enforced") {
    throw new Error("EXTENDED_METADATA_INSPECTION_UNAVAILABLE");
  }
  if (support.singleFilesystem !== "enforced") {
    throw new Error("SINGLE_FILESYSTEM_CHECK_DISABLED");
  }
}

export function assertNoWorkerPathIdentityCollisions(paths: readonly string[]): void {
  const normalized = new Map<string, string>();
  const folded = new Map<string, string>();
  for (const relative of paths) {
    registerWorkerPathIdentity(relative, normalized, folded);
  }
}

function registerWorkerPathIdentity(
  relative: string,
  normalized: Map<string, string>,
  folded: Map<string, string>,
): void {
  const nfc = relative.normalize("NFC");
  const priorNormalized = normalized.get(nfc);
  if (priorNormalized && priorNormalized !== relative) {
    throw new Error(`UNICODE_NORMALIZATION_COLLISION:${priorNormalized}:${relative}`);
  }
  const casefold = nfc.toLocaleLowerCase("und");
  const priorFolded = folded.get(casefold);
  if (priorFolded && priorFolded !== relative) {
    throw new Error(`CASEFOLD_PATH_COLLISION:${priorFolded}:${relative}`);
  }
  normalized.set(nfc, relative);
  folded.set(casefold, relative);
}

function assertSafePathSegment(name: string): void {
  if (
    name.length === 0 ||
    name === "." ||
    name === ".." ||
    name.includes("/") ||
    name.includes("\\") ||
    name.includes("\0")
  ) {
    throw new Error(`INVALID_PATH_SEGMENT:${JSON.stringify(name)}`);
  }
}

function safeSize(value: bigint, relative: string): number {
  if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`FILE_SIZE_UNREPRESENTABLE:${relative}`);
  }
  return Number(value);
}

function assertNormalizedMetadata(
  stats: BigIntStats,
  relative: string,
  expectedUid: bigint,
  expectedGid: bigint,
  rootDevice: bigint,
  requireSingleFilesystem: boolean,
): number {
  if (stats.uid !== expectedUid || stats.gid !== expectedGid) {
    throw new Error(`OWNERSHIP_MISMATCH:${relative}`);
  }
  if (requireSingleFilesystem && stats.dev !== rootDevice) {
    throw new Error(`UNSUPPORTED_FILESYSTEM_EXDEV:${relative}`);
  }
  if ((stats.mode & 0o7000n) !== 0n) {
    throw new Error(`SPECIAL_MODE_BITS:${relative}`);
  }
  return Number(stats.mode & 0o777n);
}

async function assertNoExtendedMetadata(
  absolute: string,
  relative: string,
  inspector: WorkerExtendedMetadataInspector | undefined,
): Promise<void> {
  if (!inspector) return;
  const metadata = await inspector(absolute);
  if (metadata.xattrs.length > 0) {
    throw new Error(`XATTR_NOT_ALLOWED:${relative}`);
  }
  if (metadata.aclEntries.length > 0) {
    throw new Error(`ACL_NOT_ALLOWED:${relative}`);
  }
}

async function hashBoundRegularFile(
  absolute: string,
  relative: string,
  before: BigIntStats,
): Promise<string> {
  const handle = await open(absolute, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || !isSameReadIdentity(before, opened)) {
      throw new Error(`FILE_CHANGED_DURING_OPEN:${relative}`);
    }
    const hash = createHash("sha256");
    for await (const chunk of handle.createReadStream({ autoClose: false })) {
      hash.update(chunk as Buffer);
    }
    const afterHandle = await handle.stat({ bigint: true });
    const afterPath = await lstat(absolute, { bigint: true });
    if (!isSameReadIdentity(opened, afterHandle) || !isSameReadIdentity(opened, afterPath)) {
      throw new Error(`FILE_CHANGED_DURING_READ:${relative}`);
    }
    return hash.digest("hex");
  } finally {
    await handle.close();
  }
}

/**
 * Builds the transition-worker's canonical manifest schema v2.
 *
 * The complete tree is streamed for collision, inode and resource checks.
 * Ephemeral path segments are never authoritative and never copied, but their
 * inode/byte usage is still charged to finite candidate quotas.
 */
export async function buildWorkerManifest(
  root: string,
  options: WorkerManifestOptions = {},
): Promise<WorkerManifest> {
  if (options.requireExtendedMetadataInspection && !options.extendedMetadataInspector) {
    throw new Error("EXTENDED_METADATA_INSPECTION_UNAVAILABLE");
  }
  if (options.requireSparseFileDetection && process.platform !== "linux") {
    throw new Error("SPARSE_FILE_DETECTION_UNAVAILABLE");
  }

  const policy = options.policy ?? defaultCommitGatePolicy;
  const limits = normalizedWorkerResourceLimits(options.resourceLimits);
  const requireSingleFilesystem = options.requireSingleFilesystem !== false;
  const absoluteRoot = path.resolve(root);
  const rootStat = await lstat(absoluteRoot, { bigint: true });
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    throw new Error("AUTHORITATIVE_ROOT_NOT_DIRECTORY");
  }
  const expectedUid = BigInt(options.expectedUid ?? Number(rootStat.uid));
  const expectedGid = BigInt(options.expectedGid ?? Number(rootStat.gid));
  assertNormalizedMetadata(
    rootStat,
    ".",
    expectedUid,
    expectedGid,
    rootStat.dev,
    requireSingleFilesystem,
  );
  await assertNoExtendedMetadata(absoluteRoot, ".", options.extendedMetadataInspector);

  const entries: WorkerManifestEntry[] = [];
  const normalizedPaths = new Map<string, string>();
  const foldedPaths = new Map<string, string>();
  const usage: WorkerResourceUsage = {
    scannedEntries: 0,
    scannedFiles: 0,
    scannedBytes: 0,
    authoritativeEntries: 0,
    authoritativeFiles: 0,
    authoritativeBytes: 0,
    ignoredEntries: 0,
    ignoredFiles: 0,
    ignoredBytes: 0,
  };
  const monotonicNow = options.monotonicNow ?? (() => performance.now());
  const scanDeadline = monotonicNow() + limits.maxScanDurationMs;
  const assertScanTimeBudget = (relative: string): void => {
    if (monotonicNow() > scanDeadline) {
      throw new Error(`CANDIDATE_SCAN_TIME_BUDGET_EXCEEDED:${relative}`);
    }
  };

  const charge = (relative: string, size: number, isFile: boolean, ignored: boolean): void => {
    assertScanTimeBudget(relative);
    usage.scannedEntries += 1;
    if (isFile) usage.scannedFiles += 1;
    if (usage.scannedEntries > limits.maxScannedEntries) {
      throw new Error(`CANDIDATE_ENTRY_BUDGET_EXCEEDED:${relative}`);
    }
    if (size > limits.maxScannedBytes - usage.scannedBytes) {
      throw new Error(`CANDIDATE_BYTE_BUDGET_EXCEEDED:${relative}`);
    }
    usage.scannedBytes += size;
    if (ignored) {
      usage.ignoredEntries += 1;
      if (isFile) usage.ignoredFiles += 1;
      if (usage.ignoredEntries > limits.maxIgnoredEntries) {
        throw new Error(`IGNORED_EPHEMERAL_FILE_BUDGET_EXCEEDED:${relative}`);
      }
      if (isFile && size > limits.maxIgnoredSingleFileBytes) {
        throw new Error(`IGNORED_EPHEMERAL_SINGLE_FILE_BUDGET_EXCEEDED:${relative}`);
      }
      if (size > limits.maxIgnoredBytes - usage.ignoredBytes) {
        throw new Error(`IGNORED_EPHEMERAL_BYTE_BUDGET_EXCEEDED:${relative}`);
      }
      usage.ignoredBytes += size;
      return;
    }
    usage.authoritativeEntries += 1;
    usage.authoritativeBytes += size;
    if (isFile) usage.authoritativeFiles += 1;
  };

  const visit = async (
    absoluteDirectory: string,
    relativeDirectory: string,
    directoryBefore: BigIntStats,
    inheritedIgnored: boolean,
  ): Promise<void> => {
    const directory = await opendir(absoluteDirectory);
    try {
      for await (const child of directory) {
        const name = child.name;
        assertSafePathSegment(name);
        const relative = relativeDirectory ? `${relativeDirectory}/${name}` : name;
        assertScanTimeBudget(relative);
        registerWorkerPathIdentity(relative, normalizedPaths, foldedPaths);

        const absolute = path.join(absoluteDirectory, name);
        const before = await lstat(absolute, { bigint: true });
        const ignored = inheritedIgnored || classifyPath(relative, policy) === "ignoredEphemeral";
        const mode = assertNormalizedMetadata(
          before,
          relative,
          expectedUid,
          expectedGid,
          rootStat.dev,
          requireSingleFilesystem,
        );
        await assertNoExtendedMetadata(absolute, relative, options.extendedMetadataInspector);

        if (before.isSymbolicLink()) {
          throw new Error(`SYMLINK_FILE:${relative}`);
        }
        if (before.isDirectory()) {
          charge(relative, 0, false, ignored);
          if (!ignored) {
            entries.push({
              path: relative,
              type: "dir",
              mode,
              size: 0,
              pathClass: classifyPath(relative, policy),
            });
          }
          await visit(absolute, relative, before, ignored);
          continue;
        }
        if (!before.isFile()) {
          throw new Error(`SPECIAL_FILE:${relative}`);
        }
        if (before.nlink > 1n) {
          throw new Error(`HARDLINK_FILE:${relative}`);
        }
        const size = safeSize(before.size, relative);
        if (
          process.platform === "linux" &&
          before.size > 0n &&
          before.blocks * 512n < before.size
        ) {
          throw new Error(`SPARSE_FILE:${relative}`);
        }
        charge(relative, size, true, ignored);
        if (!ignored) {
          entries.push({
            path: relative,
            type: "file",
            mode,
            size,
            contentHash: await hashBoundRegularFile(absolute, relative, before),
            pathClass: classifyPath(relative, policy),
          });
          assertScanTimeBudget(relative);
        }
      }
    } finally {
      await directory.close().catch(() => undefined);
    }
    const directoryAfter = await lstat(absoluteDirectory, { bigint: true });
    if (!isSameReadIdentity(directoryBefore, directoryAfter)) {
      throw new Error(`DIRECTORY_CHANGED_DURING_SCAN:${relativeDirectory || "."}`);
    }
  };

  await visit(absoluteRoot, "", rootStat, false);
  entries.sort((left, right) => compareCanonicalPath(left.path, right.path));
  return {
    schemaVersion: WORKER_MANIFEST_SCHEMA_VERSION,
    entries,
    hash: hashManifestEntries(entries),
    resourceUsage: usage,
    filesystemSupport: workerFilesystemSupportMatrix(options),
  };
}

async function copyBoundRegularFile(
  source: string,
  destination: string,
  relative: string,
  expectedMode: number,
): Promise<void> {
  const before = await lstat(source, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink > 1n) {
    throw new Error(`COPY_SOURCE_NOT_REGULAR:${relative}`);
  }
  const sourceHandle = await open(source, constants.O_RDONLY | constants.O_NOFOLLOW);
  let destinationHandle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    const opened = await sourceHandle.stat({ bigint: true });
    if (!isSameReadIdentity(before, opened)) {
      throw new Error(`FILE_CHANGED_DURING_COPY:${relative}`);
    }
    destinationHandle = await open(
      destination,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
      expectedMode,
    );
    const buffer = Buffer.allocUnsafe(64 * 1024);
    while (true) {
      const { bytesRead } = await sourceHandle.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      let offset = 0;
      while (offset < bytesRead) {
        const { bytesWritten } = await destinationHandle.write(
          buffer,
          offset,
          bytesRead - offset,
          null,
        );
        if (bytesWritten === 0) throw new Error(`FILE_COPY_STALLED:${relative}`);
        offset += bytesWritten;
      }
    }
    const afterHandle = await sourceHandle.stat({ bigint: true });
    const afterPath = await lstat(source, { bigint: true });
    if (!isSameReadIdentity(opened, afterHandle) || !isSameReadIdentity(opened, afterPath)) {
      throw new Error(`FILE_CHANGED_DURING_COPY:${relative}`);
    }
  } finally {
    await destinationHandle?.close().catch(() => undefined);
    await sourceHandle.close().catch(() => undefined);
  }
  // open(2)'s creation mode is umask-filtered; normalize it explicitly.
  await chmod(destination, expectedMode);
}

export async function copyClosedTree(
  source: string,
  destination: string,
  options: WorkerManifestOptions = {},
): Promise<WorkerManifest> {
  const before = await buildWorkerManifest(source, options);
  await rm(destination, { recursive: true, force: true });
  await mkdir(destination, { recursive: false, mode: 0o700 });
  try {
    for (const entry of before.entries) {
      const target = path.join(destination, ...entry.path.split("/"));
      const origin = path.join(source, ...entry.path.split("/"));
      if (entry.type === "dir") {
        // Parent directories may be read-only in the source. Materialize with
        // worker-only permissions and apply the canonical mode after children.
        await mkdir(target, { mode: 0o700 });
        continue;
      }
      if (entry.type !== "file") {
        throw new Error(`COPY_SOURCE_NOT_REGULAR:${entry.path}`);
      }
      await copyBoundRegularFile(origin, target, entry.path, entry.mode);
    }
    // Apply directory modes after children have been materialized.
    for (const entry of [...before.entries].reverse()) {
      if (entry.type === "dir") {
        await chmod(path.join(destination, ...entry.path.split("/")), entry.mode);
      }
    }
    const [sourceAfter, copied] = await Promise.all([
      buildWorkerManifest(source, options),
      buildWorkerManifest(destination, options),
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

export async function assertSameFilesystemSet(paths: readonly string[]): Promise<void> {
  if (paths.length < 2) return;
  const [first, ...rest] = paths;
  if (!first) return;
  for (const candidate of rest) {
    await assertSameFilesystem(first, candidate);
  }
}
