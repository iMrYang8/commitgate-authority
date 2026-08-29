import { createHash, randomUUID } from "node:crypto";
import {
  chmod,
  mkdir,
  open,
  readdir,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import path from "node:path";
import { canonicalJson } from "../commitgate/protocol.js";

const DEFAULT_MAX_BLOB_BYTES = 64 * 1024;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/;

export type EvidenceBlobStoreErrorCode =
  | "EVIDENCE_BLOB_INVALID_ID"
  | "EVIDENCE_BLOB_INVALID_VALUE"
  | "EVIDENCE_BLOB_TOO_LARGE"
  | "EVIDENCE_BLOB_NOT_FOUND"
  | "EVIDENCE_BLOB_NOT_REGULAR"
  | "EVIDENCE_BLOB_LINK_REJECTED"
  | "EVIDENCE_BLOB_MODE_INVALID"
  | "EVIDENCE_BLOB_TRUNCATED"
  | "EVIDENCE_BLOB_HASH_MISMATCH"
  | "EVIDENCE_BLOB_INVALID_JSON"
  | "EVIDENCE_BLOB_NON_CANONICAL"
  | "EVIDENCE_BLOB_CONTENT_MISMATCH";

export class EvidenceBlobStoreError extends Error {
  constructor(
    readonly code: EvidenceBlobStoreErrorCode,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "EvidenceBlobStoreError";
  }
}

export interface EvidenceBlobRef {
  schemaVersion: 1;
  blobId: string;
  sizeBytes: number;
}

export interface EvidenceBlobStoreOptions {
  maxBlobBytes?: number;
}

const sha256 = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

const errno = (error: unknown): string | undefined =>
  (error as NodeJS.ErrnoException | undefined)?.code;

/**
 * Worker-owned, content-addressed storage for bounded evidence payloads.
 *
 * A blob ID is the SHA-256 of its canonical UTF-8 JSON bytes. Callers receive
 * only the digest and size, never a control-root path. Reads validate file
 * shape, permissions, size, digest, JSON syntax, and canonical encoding before
 * returning a value.
 */
export class EvidenceBlobStore {
  private static readonly writeTails = new Map<string, Promise<void>>();
  readonly directory: string;
  readonly maxBlobBytes: number;

  constructor(
    controlRoot: string,
    options: EvidenceBlobStoreOptions = {},
  ) {
    const maxBlobBytes = options.maxBlobBytes ?? DEFAULT_MAX_BLOB_BYTES;
    if (!Number.isSafeInteger(maxBlobBytes) || maxBlobBytes <= 0) {
      throw new Error("maxBlobBytes must be a positive safe integer");
    }
    this.directory = path.join(controlRoot, "evidence-blobs");
    this.maxBlobBytes = maxBlobBytes;
  }

  async initialize(): Promise<void> {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    await chmod(this.directory, 0o700);
  }

  async put(value: unknown): Promise<EvidenceBlobRef> {
    let canonical: string;
    try {
      canonical = canonicalJson(value);
    } catch (error) {
      throw new EvidenceBlobStoreError(
        "EVIDENCE_BLOB_INVALID_VALUE",
        "Evidence value is not canonical-JSON serializable",
        { cause: error },
      );
    }
    if (typeof canonical !== "string") {
      throw new EvidenceBlobStoreError(
        "EVIDENCE_BLOB_INVALID_VALUE",
        "Evidence value has no canonical JSON representation",
      );
    }
    const bytes = Buffer.from(canonical, "utf8");
    this.assertBounded(bytes.byteLength);
    const blobId = sha256(bytes);
    const destination = this.blobPath(blobId);

    await this.initialize();
    return this.withExclusiveWrite(destination, async () => {
      if (await this.assertExistingMatches(destination, blobId, bytes)) {
        return { schemaVersion: 1, blobId, sizeBytes: bytes.byteLength };
      }

      const temporary = path.join(
        this.directory,
        `.${blobId}.${process.pid}.${randomUUID()}.tmp`,
      );
      try {
        await writeFile(temporary, bytes, { flag: "wx", mode: 0o600 });

        // The process-wide per-destination queue is the exclusive-create
        // fence for the sole Worker process. Recheck immediately before the
        // atomic rename so an existing blob is never silently replaced.
        if (await this.assertExistingMatches(destination, blobId, bytes)) {
          return { schemaVersion: 1, blobId, sizeBytes: bytes.byteLength };
        }

        await rename(temporary, destination);
        await chmod(destination, 0o600);
        const persisted = await this.readVerifiedBytes(blobId);
        if (!persisted.equals(bytes)) {
          throw new EvidenceBlobStoreError(
            "EVIDENCE_BLOB_CONTENT_MISMATCH",
            `Published evidence blob ${blobId} differs from its canonical input`,
          );
        }
        return { schemaVersion: 1, blobId, sizeBytes: bytes.byteLength };
      } finally {
        await rm(temporary, { force: true }).catch(() => undefined);
      }
    });
  }

  async get<T = unknown>(blobId: string): Promise<T> {
    const bytes = await this.readVerifiedBytes(blobId);
    let value: unknown;
    try {
      value = JSON.parse(bytes.toString("utf8"));
    } catch (error) {
      throw new EvidenceBlobStoreError(
        "EVIDENCE_BLOB_INVALID_JSON",
        `Evidence blob ${blobId} is not valid JSON`,
        { cause: error },
      );
    }
    let canonical: string;
    try {
      canonical = canonicalJson(value);
    } catch (error) {
      throw new EvidenceBlobStoreError(
        "EVIDENCE_BLOB_NON_CANONICAL",
        `Evidence blob ${blobId} cannot be canonicalized`,
        { cause: error },
      );
    }
    if (canonical !== bytes.toString("utf8")) {
      throw new EvidenceBlobStoreError(
        "EVIDENCE_BLOB_NON_CANONICAL",
        `Evidence blob ${blobId} is not stored as canonical JSON bytes`,
      );
    }
    return value as T;
  }

  /**
   * Startup-only mark-and-sweep for bytes that never became an immutable
   * EVIDENCE_RECORDED fact. Callers derive `referencedBlobIds` exclusively
   * from the verified event chain. This method is intentionally not exposed
   * over RPC and must run before the Worker accepts concurrent requests.
   */
  async pruneUnreferenced(referencedBlobIds: ReadonlySet<string>): Promise<string[]> {
    await this.initialize();
    const removed: string[] = [];
    for (const entry of await readdir(this.directory, { withFileTypes: true })) {
      if (entry.isFile() && /^\.[a-f0-9]{64}\..*\.tmp$/.test(entry.name)) {
        await rm(path.join(this.directory, entry.name), { force: true });
        removed.push(entry.name);
        continue;
      }
      const match = /^([a-f0-9]{64})\.json$/.exec(entry.name);
      if (!match || referencedBlobIds.has(match[1]!)) continue;
      await rm(path.join(this.directory, entry.name), { force: true });
      removed.push(match[1]!);
    }
    return removed.sort();
  }

  private blobPath(blobId: string): string {
    if (!DIGEST_PATTERN.test(blobId)) {
      throw new EvidenceBlobStoreError(
        "EVIDENCE_BLOB_INVALID_ID",
        "Evidence blob ID must be a lowercase SHA-256 digest",
      );
    }
    return path.join(this.directory, `${blobId}.json`);
  }

  private assertBounded(sizeBytes: number): void {
    if (sizeBytes > this.maxBlobBytes) {
      throw new EvidenceBlobStoreError(
        "EVIDENCE_BLOB_TOO_LARGE",
        `Evidence blob is ${sizeBytes} bytes; limit is ${this.maxBlobBytes}`,
      );
    }
  }

  private async withExclusiveWrite<T>(
    destination: string,
    operation: () => Promise<T>,
  ): Promise<T> {
    const previous = EvidenceBlobStore.writeTails.get(destination) ??
      Promise.resolve();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const tail = previous.then(() => gate);
    EvidenceBlobStore.writeTails.set(destination, tail);
    await previous;
    try {
      return await operation();
    } finally {
      release();
      if (EvidenceBlobStore.writeTails.get(destination) === tail) {
        EvidenceBlobStore.writeTails.delete(destination);
      }
    }
  }

  private async assertExistingMatches(
    destination: string,
    blobId: string,
    expected: Buffer,
  ): Promise<boolean> {
    try {
      await stat(destination);
    } catch (error) {
      if (errno(error) === "ENOENT") return false;
      throw error;
    }
    let actual: Buffer;
    try {
      actual = await this.readVerifiedBytes(blobId);
    } catch (error) {
      throw new EvidenceBlobStoreError(
        "EVIDENCE_BLOB_CONTENT_MISMATCH",
        `Existing evidence blob ${blobId} is invalid`,
        { cause: error },
      );
    }
    if (!actual.equals(expected)) {
      throw new EvidenceBlobStoreError(
        "EVIDENCE_BLOB_CONTENT_MISMATCH",
        `Existing evidence blob ${blobId} does not match canonical input`,
      );
    }
    return true;
  }

  private async readVerifiedBytes(blobId: string): Promise<Buffer> {
    const destination = this.blobPath(blobId);
    let handle;
    try {
      handle = await open(
        destination,
        fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0),
      );
    } catch (error) {
      if (errno(error) === "ENOENT") {
        throw new EvidenceBlobStoreError(
          "EVIDENCE_BLOB_NOT_FOUND",
          `Evidence blob ${blobId} does not exist`,
          { cause: error },
        );
      }
      if (errno(error) === "ELOOP") {
        throw new EvidenceBlobStoreError(
          "EVIDENCE_BLOB_NOT_REGULAR",
          `Evidence blob ${blobId} cannot be a symbolic link`,
          { cause: error },
        );
      }
      throw error;
    }
    try {
      const before = await handle.stat();
      if (!before.isFile()) {
        throw new EvidenceBlobStoreError(
          "EVIDENCE_BLOB_NOT_REGULAR",
          `Evidence blob ${blobId} is not a regular file`,
        );
      }
      if (before.nlink !== 1) {
        throw new EvidenceBlobStoreError(
          "EVIDENCE_BLOB_LINK_REJECTED",
          `Evidence blob ${blobId} has ${before.nlink} hard links`,
        );
      }
      if ((before.mode & 0o777) !== 0o600) {
        throw new EvidenceBlobStoreError(
          "EVIDENCE_BLOB_MODE_INVALID",
          `Evidence blob ${blobId} must have mode 0600`,
        );
      }
      this.assertBounded(before.size);
      const bytes = Buffer.alloc(before.size);
      let offset = 0;
      while (offset < bytes.byteLength) {
        const { bytesRead } = await handle.read(
          bytes,
          offset,
          bytes.byteLength - offset,
          offset,
        );
        if (bytesRead === 0) break;
        offset += bytesRead;
      }
      const after = await handle.stat();
      if (
        offset !== bytes.byteLength ||
        after.size !== before.size ||
        after.ino !== before.ino ||
        after.dev !== before.dev
      ) {
        throw new EvidenceBlobStoreError(
          "EVIDENCE_BLOB_TRUNCATED",
          `Evidence blob ${blobId} changed while being read`,
        );
      }
      if (sha256(bytes) !== blobId) {
        throw new EvidenceBlobStoreError(
          "EVIDENCE_BLOB_HASH_MISMATCH",
          `Evidence blob ${blobId} failed digest verification`,
        );
      }
      return bytes;
    } finally {
      await handle.close();
    }
  }
}
