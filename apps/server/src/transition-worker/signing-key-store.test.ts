import { createHash } from "node:crypto";
import { chmod, link, mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { verifyAuthorityReceiptProof, type AuthorityReceiptRecord } from "../research/receipt-proof.js";
import { WorkerSigningKeyStore } from "./signing-key-store.js";

const roots: string[] = [];
afterEach(async () => Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))));

describe("WorkerSigningKeyStore", () => {
  it("persists a Worker-only key and produces portable proofs", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-signing-"));
    roots.push(root);
    const first = new WorkerSigningKeyStore(root);
    await first.initialize();
    const receipt: AuthorityReceiptRecord = {
      schemaVersion: 1,
      receiptId: "receipt-1",
      runId: "run-1",
      agentId: "agent-1",
      transitionId: "transition-1",
      decision: "ABORTED",
      baseViewId: "a".repeat(64),
      finalViewId: "b".repeat(64),
      baseGeneration: 3,
      nextGeneration: 3,
      baseWorkspaceHash: "c".repeat(64),
      finalWorkspaceHash: "c".repeat(64),
      proposalId: null,
      proposalArtifactHash: null,
      verifierInputHash: null,
      promotionSourceHash: null,
      evaluationContextHash: null,
      evidenceDigest: null,
      permitId: null,
      permitState: null,
      sourceRevision: "source-revision",
    };
    const terminalUnsigned = {
      schemaVersion: 1 as const,
      eventId: "event-1",
      agentId: "agent-1",
      transitionId: "transition-1",
      sequence: 1,
      type: "NON_COMMIT_DISPOSITIONED",
      previousDigest: null,
      payload: {
        receiptId: "receipt-1",
        decision: "ABORTED",
        workspaceHash: "c".repeat(64),
        viewId: "b".repeat(64),
      },
      createdAt: "2026-08-29T00:00:00.000Z",
    };
    const terminal = {
      ...terminalUnsigned,
      digest: createHash("sha256").update(JSON.stringify(terminalUnsigned)).digest("hex"),
    };
    const proof = first.sign(receipt, terminal, [terminal]);
    expect(verifyAuthorityReceiptProof(proof)).toEqual({ valid: true, reason: null });
    expect((await stat(path.join(root, "signing", "ed25519-private.pem"))).mode & 0o777).toBe(0o600);
    expect(await readFile(path.join(root, "signing", "ed25519-public.pem"), "utf8"))
      .toBe(proof.publicKeyPem);

    const restarted = new WorkerSigningKeyStore(root);
    await restarted.initialize();
    expect(restarted.keyId).toBe(first.keyId);
  });

  it("fails closed when persisted private-key permissions are widened", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-signing-mode-"));
    roots.push(root);
    const store = new WorkerSigningKeyStore(root);
    await store.initialize();
    await chmod(path.join(root, "signing", "ed25519-private.pem"), 0o644);
    await expect(new WorkerSigningKeyStore(root).initialize()).rejects.toThrow(
      "WORKER_SIGNING_KEY_MODE_INVALID",
    );
  });

  it("fails closed when persisted private-key material has another hard link", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-signing-link-"));
    roots.push(root);
    const store = new WorkerSigningKeyStore(root);
    await store.initialize();
    const privatePath = path.join(root, "signing", "ed25519-private.pem");
    await link(privatePath, path.join(root, "signing", "unexpected-key-link"));
    await expect(new WorkerSigningKeyStore(root).initialize()).rejects.toThrow(
      "WORKER_SIGNING_KEY_FILE_INVALID",
    );
  });
});
