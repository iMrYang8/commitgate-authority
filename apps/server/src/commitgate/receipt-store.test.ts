import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ReceiptStore, redactReceiptText } from "./receipt-store.js";
import type { GateReceipt } from "./types.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

function receipt(overrides: Partial<GateReceipt> = {}): GateReceipt {
  return {
    schemaVersion: 1,
    runId: "run",
    agentId: "agent",
    phase: "TERMINAL",
    decision: "COMMITTED",
    failureClass: null,
    reasonCodes: [],
    baseSnapshotHash: "a".repeat(64),
    candidateSnapshotHash: "b".repeat(64),
    patchHash: "c".repeat(64),
    finalSnapshotHash: "b".repeat(64),
    policyHash: "d".repeat(64),
    evidence: { static: "complete", trustedChecks: "complete" },
    checks: [],
    changedPaths: ["README.md"],
    threadDisposition: "resumed",
    candidateCleanup: "deleted",
    sessionEpoch: 0,
    versionId: "version",
    promotionPendingDatabaseAck: false,
    provider: null,
    startedAt: new Date(0).toISOString(),
    completedAt: new Date(1).toISOString(),
    ...overrides,
  };
}

describe("receipt redaction", () => {
  it("redacts per-run Model Relay capabilities", () => {
    const capability = "cg1.eyJydW5JZCI6InJ1bi0xIn0.c2lnbmF0dXJlYnl0ZXM";
    expect(redactReceiptText(`credential=${capability}`)).toBe("credential=[REDACTED]");
  });
});

describe("terminal receipt history", () => {
  it("does not rewrite a legacy terminal receipt without transactionStatus", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-receipts-"));
    roots.push(root);
    const store = new ReceiptStore(root);
    const legacy = receipt();
    delete legacy.transactionStatus;
    await store.put(legacy);

    await expect(
      store.put({ ...legacy, decision: "ABORTED", reasonCodes: ["RECOVERY"] }),
    ).rejects.toThrow("TERMINAL_RECEIPT_IMMUTABLE");
    expect(await store.get("agent", "run")).toEqual(legacy);
  });

  it("appends and deduplicates recovery events without changing the receipt", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-receipts-"));
    roots.push(root);
    const store = new ReceiptStore(root);
    const terminal = receipt({ transactionStatus: "TERMINAL" });
    await store.put(terminal);
    const input = {
      agentId: "agent",
      runId: "run",
      type: "RECOVERY_ROLLED_BACK" as const,
      originalDecision: "COMMITTED" as const,
      effectiveDecision: "ABORTED" as const,
      reasonCode: "STARTUP_RECOVERY_ROLLBACK",
      finalSnapshotHash: terminal.baseSnapshotHash,
      threadDisposition: "reset" as const,
    };
    const first = await store.appendRecoveryEvent(input);
    const second = await store.appendRecoveryEvent(input);

    expect(second.eventId).toBe(first.eventId);
    expect(await store.listRecoveryEvents("agent", "run")).toEqual([first]);
    expect(await store.get("agent", "run")).toEqual(terminal);
  });

  it("deduplicates repeated permit replay audit events", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-receipts-"));
    roots.push(root);
    const store = new ReceiptStore(root);
    const input = {
      agentId: "agent",
      runId: "run",
      permitId: "permit",
      expectedViewId: "a".repeat(64),
    };
    const first = await store.appendPermitReplayEvent(input);
    const second = await store.appendPermitReplayEvent(input);
    expect(second.eventId).toBe(first.eventId);
    expect(await store.listPermitReplayEvents("agent", "run")).toEqual([first]);
  });
});
