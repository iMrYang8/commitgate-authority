import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";

export interface BrokerRunBinding {
  runId: string;
  agentId: string;
  runLeaseId: string;
  sessionEpoch: number;
}

export type BrokerRunStage =
  | "AGENT_STARTED"
  | "AGENT_CLOSED"
  | "VERIFIER_STARTED"
  | "ALL_CLOSED";

export interface BrokerLifecycleRecord extends BrokerRunBinding {
  schemaVersion: 1;
  stage: BrokerRunStage;
  updatedAt: string;
}

const stageRank: Record<BrokerRunStage, number> = {
  AGENT_STARTED: 0,
  AGENT_CLOSED: 1,
  VERIFIER_STARTED: 2,
  ALL_CLOSED: 3,
};

function validateRecord(value: unknown): BrokerLifecycleRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("BROKER_LIFECYCLE_LEDGER_CORRUPT");
  }
  const record = value as Partial<BrokerLifecycleRecord>;
  if (
    record.schemaVersion !== 1 ||
    typeof record.runId !== "string" || record.runId.length === 0 ||
    typeof record.agentId !== "string" || record.agentId.length === 0 ||
    typeof record.runLeaseId !== "string" || record.runLeaseId.length === 0 ||
    typeof record.sessionEpoch !== "number" ||
    !Number.isInteger(record.sessionEpoch) || record.sessionEpoch < 0 ||
    typeof record.stage !== "string" || !(record.stage in stageRank) ||
    typeof record.updatedAt !== "string"
  ) {
    throw new Error("BROKER_LIFECYCLE_LEDGER_CORRUPT");
  }
  return record as BrokerLifecycleRecord;
}

function sameBinding(record: BrokerRunBinding, binding: BrokerRunBinding): boolean {
  return record.runId === binding.runId &&
    record.agentId === binding.agentId &&
    record.runLeaseId === binding.runLeaseId &&
    record.sessionEpoch === binding.sessionEpoch;
}

/**
 * Durable, monotonic Broker-side launch/closure memory. The file name is keyed
 * only by runId so the same run cannot be rebound to another Agent, lease, or
 * session after a Broker restart. Contents are written temp+rename and never
 * transition backwards.
 */
export class BrokerLifecycleLedger {
  private readonly tails = new Map<string, Promise<void>>();

  constructor(private readonly root: string) {}

  async beginAgent(binding: BrokerRunBinding): Promise<BrokerLifecycleRecord> {
    return this.exclusive(binding.runId, async () => {
      const current = await this.readByRunId(binding.runId);
      if (current) {
        this.assertBinding(current, binding);
        if (current.stage === "ALL_CLOSED") {
          throw new Error("BROKER_RUNTIME_ALL_CLOSED");
        }
        if (current.stage !== "AGENT_STARTED") {
          throw new Error("BROKER_AGENT_LIFECYCLE_CLOSED");
        }
        throw new Error("BROKER_AGENT_LAUNCH_REPLAY");
      }
      return this.write({
        schemaVersion: 1,
        ...binding,
        stage: "AGENT_STARTED",
        updatedAt: new Date().toISOString(),
      });
    });
  }

  async beginVerifier(binding: BrokerRunBinding): Promise<BrokerLifecycleRecord> {
    return this.exclusive(binding.runId, async () => {
      const current = await this.requireKnown(binding);
      if (current.stage === "ALL_CLOSED") {
        throw new Error("BROKER_RUNTIME_ALL_CLOSED");
      }
      if (current.stage !== "AGENT_CLOSED") {
        throw new Error("BROKER_VERIFIER_LAUNCH_NOT_ALLOWED");
      }
      return this.advance(current, "VERIFIER_STARTED");
    });
  }

  async assertKnown(binding: BrokerRunBinding): Promise<BrokerLifecycleRecord> {
    return this.exclusive(binding.runId, () => this.requireKnown(binding));
  }

  async markAgentClosed(binding: BrokerRunBinding): Promise<BrokerLifecycleRecord> {
    return this.exclusive(binding.runId, async () => {
      const current = await this.requireKnown(binding);
      if (current.stage === "AGENT_STARTED") {
        return this.advance(current, "AGENT_CLOSED");
      }
      // A later stage already carries the stronger fact that Agent launch is
      // permanently closed. Never downgrade it on a repeated AGENT close.
      return current;
    });
  }

  async markAllClosed(binding: BrokerRunBinding): Promise<BrokerLifecycleRecord> {
    return this.exclusive(binding.runId, async () => {
      const current = await this.requireKnown(binding);
      if (current.stage === "ALL_CLOSED") return current;
      return this.advance(current, "ALL_CLOSED");
    });
  }

  async get(binding: BrokerRunBinding): Promise<BrokerLifecycleRecord | null> {
    return this.exclusive(binding.runId, async () => {
      const current = await this.readByRunId(binding.runId);
      if (!current) return null;
      this.assertBinding(current, binding);
      return current;
    });
  }

  private async requireKnown(binding: BrokerRunBinding): Promise<BrokerLifecycleRecord> {
    const current = await this.readByRunId(binding.runId);
    if (!current) throw new Error("BROKER_RUNTIME_BINDING_UNKNOWN");
    this.assertBinding(current, binding);
    return current;
  }

  private assertBinding(record: BrokerLifecycleRecord, binding: BrokerRunBinding): void {
    if (!sameBinding(record, binding)) {
      throw new Error("BROKER_RUNTIME_BINDING_MISMATCH");
    }
  }

  private async advance(
    current: BrokerLifecycleRecord,
    next: BrokerRunStage,
  ): Promise<BrokerLifecycleRecord> {
    if (stageRank[next] < stageRank[current.stage]) {
      throw new Error("BROKER_LIFECYCLE_STAGE_REGRESSION");
    }
    if (next === current.stage) return current;
    return this.write({ ...current, stage: next, updatedAt: new Date().toISOString() });
  }

  private recordPath(runId: string): string {
    const digest = createHash("sha256").update(runId, "utf8").digest("hex");
    return path.join(this.root, `${digest}.json`);
  }

  private async readByRunId(runId: string): Promise<BrokerLifecycleRecord | null> {
    try {
      return validateRecord(JSON.parse(await readFile(this.recordPath(runId), "utf8")));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      if (error instanceof SyntaxError) throw new Error("BROKER_LIFECYCLE_LEDGER_CORRUPT");
      throw error;
    }
  }

  private async write(record: BrokerLifecycleRecord): Promise<BrokerLifecycleRecord> {
    await mkdir(this.root, { recursive: true, mode: 0o700 });
    const destination = this.recordPath(record.runId);
    const temporary = `${destination}.${process.pid}.${randomUUID()}.tmp`;
    await writeFile(temporary, JSON.stringify(record) + "\n", {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    await rename(temporary, destination);
    return record;
  }

  private async exclusive<T>(runId: string, action: () => Promise<T>): Promise<T> {
    const previous = this.tails.get(runId) ?? Promise.resolve();
    let release!: () => void;
    const next = new Promise<void>((resolve) => { release = resolve; });
    const tail = previous.then(() => next);
    this.tails.set(runId, tail);
    await previous;
    try {
      return await action();
    } finally {
      release();
      if (this.tails.get(runId) === tail) this.tails.delete(runId);
    }
  }
}
