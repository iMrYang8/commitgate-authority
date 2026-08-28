import { randomUUID } from "node:crypto";
import { mkdir, readdir } from "node:fs/promises";
import path from "node:path";
import { readJson, writeJsonAtomic } from "./atomic-json.js";
import { assertSafeIdentifier } from "./file-ops.js";
import type { GateReceipt } from "./types.js";

export interface ReceiptRecoveryEvent {
  schemaVersion: 1;
  eventId: string;
  agentId: string;
  runId: string;
  type: "RECOVERY_ACKNOWLEDGED" | "RECOVERY_ROLLED_BACK";
  originalDecision: GateReceipt["decision"] | null;
  effectiveDecision: "COMMITTED" | "ABORTED";
  reasonCode: string;
  finalSnapshotHash: string;
  threadDisposition: "resumed" | "reset";
  createdAt: string;
}

export interface PermitReplayAuditEvent {
  schemaVersion: 1;
  eventId: string;
  agentId: string;
  runId: string;
  type: "PERMIT_REPLAY_REJECTED";
  permitId: string;
  expectedViewId: string;
  permitState: "CONSUMED";
  createdAt: string;
}

const SECRET_PATTERNS = [
  /\b(?:sk|ak)-[A-Za-z0-9_-]{12,}\b/g,
  /\b(?:cg1|rt1)_[A-Za-z0-9_-]{12,}\b/g,
  /\bcg1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
  /\bBearer\s+[A-Za-z0-9._~+\/-]+=*\b/gi,
  /\bARK_API_KEY\s*=\s*[^\s]+/gi,
  /\b(?:api[_-]?key|token|secret|password)\s*[:=]\s*[^\s,;]+/gi,
];

export function redactReceiptText(
  value: string,
  maxBytes = 16_384,
  sensitiveValues: readonly string[] = [],
): string {
  let output = value;
  for (const sensitive of sensitiveValues) {
    if (sensitive) output = output.split(sensitive).join("[REDACTED]");
  }
  for (const pattern of SECRET_PATTERNS) output = output.replace(pattern, "[REDACTED]");
  const bytes = Buffer.from(output);
  if (bytes.byteLength <= maxBytes) return output;
  return bytes.subarray(0, maxBytes).toString("utf8") + "\n[TRUNCATED]";
}

export function sanitizeReceipt(
  receipt: GateReceipt,
  sensitiveValues: readonly string[] = [],
): GateReceipt {
  return {
    ...receipt,
    reasonCodes: receipt.reasonCodes.map((reason) =>
      redactReceiptText(reason, 512, sensitiveValues),
    ),
    checks: receipt.checks.map((check) => ({
      ...check,
      output: redactReceiptText(check.output, 16_384, sensitiveValues),
    })),
    changedPaths: receipt.changedPaths.map((changedPath) =>
      redactReceiptText(changedPath, 512, sensitiveValues),
    ),
    provider: receipt.provider
      ? {
          providerId: receipt.provider.providerId,
          gateway: redactReceiptText(receipt.provider.gateway, 2_048, sensitiveValues),
          requestedModel: redactReceiptText(
            receipt.provider.requestedModel,
            512,
            sensitiveValues,
          ),
          resolvedModel: receipt.provider.resolvedModel
            ? redactReceiptText(receipt.provider.resolvedModel, 512, sensitiveValues)
            : null,
        }
      : null,
  };
}

export class ReceiptStore {
  constructor(
    private readonly controlRoot: string,
    private readonly sensitiveValues: readonly string[] = [],
  ) {}

  receiptPath(agentId: string, runId: string): string {
    assertSafeIdentifier(agentId, "agentId");
    assertSafeIdentifier(runId, "runId");
    return path.join(this.controlRoot, agentId, "receipts", runId + ".json");
  }

  async put(receipt: GateReceipt): Promise<void> {
    const existing = await this.get(receipt.agentId, receipt.runId);
    const sanitized = sanitizeReceipt(receipt, this.sensitiveValues);
    // v1 receipts already used phase=TERMINAL but did not have a
    // transactionStatus field. Treat them as immutable terminal audit records
    // too; recovery records a sidecar event instead of rewriting history.
    if (existing?.phase === "TERMINAL" && JSON.stringify(existing) !== JSON.stringify(sanitized)) {
      throw new Error("TERMINAL_RECEIPT_IMMUTABLE");
    }
    await writeJsonAtomic(
      this.receiptPath(receipt.agentId, receipt.runId),
      sanitized,
    );
  }

  async appendRecoveryEvent(
    input: Omit<ReceiptRecoveryEvent, "schemaVersion" | "eventId" | "createdAt"> & {
      createdAt?: string;
    },
  ): Promise<ReceiptRecoveryEvent> {
    assertSafeIdentifier(input.agentId, "agentId");
    assertSafeIdentifier(input.runId, "runId");
    const existing = await this.listRecoveryEvents(input.agentId, input.runId);
    const duplicate = existing.find(
      (event) =>
        event.type === input.type &&
        event.reasonCode === input.reasonCode &&
        event.finalSnapshotHash === input.finalSnapshotHash &&
        event.effectiveDecision === input.effectiveDecision,
    );
    if (duplicate) return duplicate;
    const event: ReceiptRecoveryEvent = {
      schemaVersion: 1,
      eventId: `re-${randomUUID()}`,
      agentId: input.agentId,
      runId: input.runId,
      type: input.type,
      originalDecision: input.originalDecision,
      effectiveDecision: input.effectiveDecision,
      reasonCode: input.reasonCode,
      finalSnapshotHash: input.finalSnapshotHash,
      threadDisposition: input.threadDisposition,
      createdAt: input.createdAt ?? new Date().toISOString(),
    };
    await writeJsonAtomic(
      path.join(
        this.controlRoot,
        input.agentId,
        "receipt-events",
        input.runId,
        event.eventId + ".json",
      ),
      event,
    );
    return event;
  }

  async appendPermitReplayEvent(input: {
    agentId: string;
    runId: string;
    permitId: string;
    expectedViewId: string;
    createdAt?: string;
  }): Promise<PermitReplayAuditEvent> {
    assertSafeIdentifier(input.agentId, "agentId");
    assertSafeIdentifier(input.runId, "runId");
    assertSafeIdentifier(input.permitId, "permitId");
    const existing = await this.listPermitReplayEvents(input.agentId, input.runId);
    const duplicate = existing.find(
      (event) =>
        event.permitId === input.permitId &&
        event.expectedViewId === input.expectedViewId,
    );
    if (duplicate) return duplicate;
    const event: PermitReplayAuditEvent = {
      schemaVersion: 1,
      eventId: `se-${randomUUID()}`,
      agentId: input.agentId,
      runId: input.runId,
      type: "PERMIT_REPLAY_REJECTED",
      permitId: input.permitId,
      expectedViewId: input.expectedViewId,
      permitState: "CONSUMED",
      createdAt: input.createdAt ?? new Date().toISOString(),
    };
    await writeJsonAtomic(
      path.join(
        this.controlRoot,
        input.agentId,
        "security-events",
        input.runId,
        event.eventId + ".json",
      ),
      event,
    );
    return event;
  }

  async listPermitReplayEvents(
    agentId: string,
    runId: string,
  ): Promise<PermitReplayAuditEvent[]> {
    assertSafeIdentifier(agentId, "agentId");
    assertSafeIdentifier(runId, "runId");
    const directory = path.join(
      this.controlRoot,
      agentId,
      "security-events",
      runId,
    );
    try {
      const files = (await readdir(directory))
        .filter((name) => name.endsWith(".json"))
        .sort();
      return await Promise.all(
        files.map((name) =>
          readJson<PermitReplayAuditEvent>(path.join(directory, name)),
        ),
      );
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
  }

  async listRecoveryEvents(
    agentId: string,
    runId: string,
  ): Promise<ReceiptRecoveryEvent[]> {
    assertSafeIdentifier(agentId, "agentId");
    assertSafeIdentifier(runId, "runId");
    const directory = path.join(
      this.controlRoot,
      agentId,
      "receipt-events",
      runId,
    );
    try {
      const files = (await readdir(directory))
        .filter((name) => name.endsWith(".json"))
        .sort();
      return await Promise.all(
        files.map((name) =>
          readJson<ReceiptRecoveryEvent>(path.join(directory, name)),
        ),
      );
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
  }

  async get(agentId: string, runId: string): Promise<GateReceipt | null> {
    try {
      return await readJson<GateReceipt>(this.receiptPath(agentId, runId));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw error;
    }
  }

  async list(agentId: string): Promise<GateReceipt[]> {
    assertSafeIdentifier(agentId, "agentId");
    const directory = path.join(this.controlRoot, agentId, "receipts");
    try {
      await mkdir(directory, { recursive: true, mode: 0o700 });
      const files = (await readdir(directory)).filter((name) => name.endsWith(".json")).sort();
      return await Promise.all(files.map((name) => readJson<GateReceipt>(path.join(directory, name))));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
  }
}
