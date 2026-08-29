import { createHash } from "node:crypto";
import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  EvidenceBlobStore,
  type EvidenceBlobStoreErrorCode,
} from "./evidence-blob-store.js";

const roots: string[] = [];
const sha256 = (value: string): string =>
  createHash("sha256").update(value).digest("hex");

async function fixture(maxBlobBytes = 64 * 1024) {
  const root = await mkdtemp(path.join(tmpdir(), "commitgate-evidence-blobs-"));
  roots.push(root);
  return {
    root,
    store: new EvidenceBlobStore(root, { maxBlobBytes }),
    blobPath: (blobId: string) =>
      path.join(root, "evidence-blobs", `${blobId}.json`),
  };
}

const rejectsWith = async (
  operation: Promise<unknown>,
  code: EvidenceBlobStoreErrorCode,
) => {
  await expect(operation).rejects.toMatchObject({ code });
};

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

describe("EvidenceBlobStore", () => {
  it("stores canonical JSON bytes under their SHA-256 ID with mode 0600", async () => {
    const { root, store, blobPath } = await fixture();
    const [first, ...duplicates] = await Promise.all([
      store.put({ z: 1, a: { y: 2, x: 3 }, omitted: undefined }),
      ...Array.from({ length: 7 }, () =>
        store.put({ a: { x: 3, y: 2 }, z: 1 })),
    ]);
    const expected = '{"a":{"x":3,"y":2},"z":1}';

    expect(first).toEqual({
      schemaVersion: 1,
      blobId: sha256(expected),
      sizeBytes: Buffer.byteLength(expected),
    });
    expect(duplicates).toEqual(Array.from({ length: 7 }, () => first));
    expect(await readFile(blobPath(first.blobId), "utf8")).toBe(expected);
    expect((await stat(blobPath(first.blobId))).mode & 0o777).toBe(0o600);
    expect((await stat(path.join(root, "evidence-blobs"))).mode & 0o777).toBe(
      0o700,
    );
    expect(await readdir(path.join(root, "evidence-blobs"))).toEqual([
      `${first.blobId}.json`,
    ]);
    expect(await store.get(first.blobId)).toEqual({ a: { x: 3, y: 2 }, z: 1 });
  });

  it("rejects values and files above the configured byte budget", async () => {
    const { root, store, blobPath } = await fixture(16);
    await rejectsWith(
      store.put({ payload: "this value is too large" }),
      "EVIDENCE_BLOB_TOO_LARGE",
    );

    const oversized = '{"payload":"oversized"}';
    const blobId = sha256(oversized);
    await mkdir(path.join(root, "evidence-blobs"), { recursive: true, mode: 0o700 });
    await writeFile(blobPath(blobId), oversized, { mode: 0o600 });
    await rejectsWith(store.get(blobId), "EVIDENCE_BLOB_TOO_LARGE");
  });

  it("fails closed when an existing content-addressed blob is inconsistent", async () => {
    const { store, blobPath } = await fixture();
    const value = { checks: [{ id: "trusted", status: "PASS" }] };
    const reference = await store.put(value);
    const tampered = '{"checks":[]}';
    await writeFile(blobPath(reference.blobId), tampered, { mode: 0o600 });

    await rejectsWith(
      store.put(value),
      "EVIDENCE_BLOB_CONTENT_MISMATCH",
    );
    expect(await readFile(blobPath(reference.blobId), "utf8")).toBe(tampered);
  });

  it("recomputes the digest on get and rejects post-write tampering", async () => {
    const { store, blobPath } = await fixture();
    const reference = await store.put({ evidence: "trusted" });
    await writeFile(blobPath(reference.blobId), '{"evidence":"changed"}', {
      mode: 0o600,
    });

    await rejectsWith(store.get(reference.blobId), "EVIDENCE_BLOB_HASH_MISMATCH");
  });

  it("rejects non-canonical or invalid JSON even when the filename digest matches", async () => {
    const { root, store, blobPath } = await fixture();
    await mkdir(path.join(root, "evidence-blobs"), { recursive: true, mode: 0o700 });

    const nonCanonical = '{"z":1, "a":2}';
    const nonCanonicalId = sha256(nonCanonical);
    await writeFile(blobPath(nonCanonicalId), nonCanonical, { mode: 0o600 });
    await rejectsWith(store.get(nonCanonicalId), "EVIDENCE_BLOB_NON_CANONICAL");

    const invalid = "{not-json}";
    const invalidId = sha256(invalid);
    await writeFile(blobPath(invalidId), invalid, { mode: 0o600 });
    await rejectsWith(store.get(invalidId), "EVIDENCE_BLOB_INVALID_JSON");
  });

  it("rejects invalid IDs, hardlinks, and permission changes", async () => {
    const { root, store, blobPath } = await fixture();
    await rejectsWith(store.get("../control"), "EVIDENCE_BLOB_INVALID_ID");

    const modeReference = await store.put({ id: "mode" });
    await chmod(blobPath(modeReference.blobId), 0o644);
    await rejectsWith(
      store.get(modeReference.blobId),
      "EVIDENCE_BLOB_MODE_INVALID",
    );

    const linkedReference = await store.put({ id: "linked" });
    const linkedPath = path.join(root, "linked-evidence.json");
    await link(blobPath(linkedReference.blobId), linkedPath);
    await rejectsWith(
      store.get(linkedReference.blobId),
      "EVIDENCE_BLOB_LINK_REJECTED",
    );
  });

  it("rejects non-JSON top-level values", async () => {
    const { store } = await fixture();
    await rejectsWith(store.put(undefined), "EVIDENCE_BLOB_INVALID_VALUE");
    await rejectsWith(
      store.put({ value: Number.POSITIVE_INFINITY }),
      "EVIDENCE_BLOB_INVALID_VALUE",
    );
  });
});
