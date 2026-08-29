import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { verifyAuthorityReceiptProof } from "../research/receipt-proof.js";
import { makeTreeWritable } from "./filesystem.js";
import { TransitionWorker, type TransitionWorkerConfig } from "./worker.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map(async (root) => {
    await makeTreeWritable(root).catch(() => undefined);
    await rm(root, { recursive: true, force: true });
  }));
});

describe("receipt proof projection size", () => {
  it("keeps 21 compact receipts below the RPC cap and rebuilds one full v3 chain", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "worker-proof-projection-"));
    roots.push(root);
    const config: TransitionWorkerConfig = {
      workspaceRoot: path.join(root, "authority"),
      controlRoot: path.join(root, "control"),
      inboxRoot: path.join(root, "exchange"),
      socketPath: path.join(root, "run", "worker.sock"),
      sourceRevision: "a".repeat(40),
    };
    const worker = new TransitionWorker(config);
    await worker.initialize();
    let projection = await worker.initializeAgent({
      agentId: "proof-agent",
      operationId: "proof-initialize",
      headVersionId: "proof-initial-version",
      generation: 0,
      sessionEpoch: 0,
      agentConfigVersion: 1,
      policyVersion: 1,
      name: "Projection proof",
      instructions: "# Projection proof\n",
    });
    const initial = projection.versions[0]!;

    for (let index = 1; index <= 21; index += 1) {
      const head = projection.head!;
      const receiptId = `rollback-${index}`;
      await worker.prepare({
        agentId: "proof-agent",
        transitionId: receiptId,
        kind: "ROLLBACK",
        expectedViewId: head.view.viewId,
        expectedWorkspaceHash: head.workspaceHash,
        baseGeneration: head.view.generation,
      });
      projection = await worker.applyRollback({
        agentId: "proof-agent",
        transitionId: receiptId,
        rollbackPermitId: `rollback-permit-${index}`,
        targetSnapshotId: initial.snapshotId,
        targetVersionId: initial.versionId,
        expectedViewId: head.view.viewId,
        expectedWorkspaceHash: head.workspaceHash,
        versionId: `rollback-version-${index}`,
        receiptId,
      });
    }

    expect(Buffer.byteLength(JSON.stringify(projection), "utf8")).toBeLessThan(1_048_576);
    expect(Object.values(projection.receiptProofs)).toHaveLength(21);
    expect(
      Object.values(projection.receiptProofs).every(
        (entry) => entry.bundle.schemaVersion === 2 && !("eventChain" in entry.bundle),
      ),
    ).toBe(true);

    const proof = await worker.getReceiptProof("proof-agent", "rollback-21");
    expect(Buffer.byteLength(JSON.stringify(proof), "utf8")).toBeLessThan(1_048_576);
    expect(proof.schemaVersion).toBe(3);
    expect(proof.eventChain?.at(-1)?.eventId).toBe(proof.terminalEvent.eventId);
    expect(verifyAuthorityReceiptProof(proof)).toEqual({ valid: true, reason: null });
  }, 20_000);
});
