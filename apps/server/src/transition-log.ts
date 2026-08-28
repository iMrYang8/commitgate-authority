import { createHash, randomUUID } from "node:crypto";
import { chmod, mkdir, readFile, readdir, rename, writeFile } from "node:fs/promises";
import path from "node:path";

export type TransitionEventType =
  | "AGENT_INITIALIZED"
  | "LEGACY_STATE_ADOPTED"
  | "TRANSITION_PREPARED"
  | "PROPOSAL_SEALED"
  | "EVIDENCE_RECORDED"
  | "PERMIT_ISSUED"
  | "PERMIT_CONSUMING"
  | "WORKSPACE_APPLIED"
  | "PLATFORM_STATE_REGENERATED"
  | "VIEW_DISPOSITIONED"
  | "TRANSITION_ACKNOWLEDGED"
  | "TRANSITION_ROLLED_BACK"
  | "AGENT_ARCHIVED"
  | "REPAIR_APPLIED"
  | "STALE_CALLBACK_RECORDED";

export interface TransitionEvent<TPayload = Record<string, unknown>> {
  schemaVersion: 1;
  eventId: string;
  agentId: string;
  transitionId: string;
  sequence: number;
  type: TransitionEventType;
  previousDigest: string | null;
  payload: TPayload;
  createdAt: string;
  digest: string;
}

export interface AppendTransitionEventInput<TPayload> {
  agentId: string;
  transitionId: string;
  type: TransitionEventType;
  payload: TPayload;
}

const digestEvent = (event: Omit<TransitionEvent, "digest">): string =>
  createHash("sha256").update(JSON.stringify(event)).digest("hex");

/**
 * Append-only, hash-chained transition log. A directory of immutable events is
 * used instead of JSONL so a killed process can leave at most an unreferenced
 * temporary file, never a partially parsed committed record. This is a
 * kill/restart protocol; it intentionally makes no power-loss/fsync claim.
 */
export class TransitionEventLog {
  private readonly tails = new Map<string, Promise<void>>();

  constructor(private readonly root: string) {}

  async append<TPayload extends Record<string, unknown>>(
    input: AppendTransitionEventInput<TPayload>,
  ): Promise<TransitionEvent<TPayload>> {
    return this.enqueue(input.agentId, async () => {
      const existing = await this.read(input.agentId);
      const sequence = (existing.at(-1)?.sequence ?? 0) + 1;
      const unsigned = {
        schemaVersion: 1 as const,
        eventId: randomUUID(),
        agentId: input.agentId,
        transitionId: input.transitionId,
        sequence,
        type: input.type,
        previousDigest: existing.at(-1)?.digest ?? null,
        payload: input.payload,
        createdAt: new Date().toISOString(),
      };
      const event: TransitionEvent<TPayload> = {
        ...unsigned,
        digest: digestEvent(unsigned),
      };
      const directory = this.agentDirectory(input.agentId);
      await mkdir(directory, { recursive: true, mode: 0o700 });
      const base = String(sequence).padStart(12, "0") + "-" + event.eventId + ".json";
      const destination = path.join(directory, base);
      const temporary = destination + ".tmp-" + randomUUID();
      await writeFile(temporary, JSON.stringify(event, null, 2) + "\n", {
        encoding: "utf8",
        mode: 0o600,
        flag: "wx",
      });
      await rename(temporary, destination);
      await chmod(destination, 0o400);
      return event;
    });
  }

  async read(agentId: string): Promise<TransitionEvent[]> {
    const directory = this.agentDirectory(agentId);
    let names: string[];
    try {
      names = (await readdir(directory)).filter((name) => /^\d{12}-.*\.json$/.test(name)).sort();
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
    const events: TransitionEvent[] = [];
    for (const name of names) {
      const event = JSON.parse(await readFile(path.join(directory, name), "utf8")) as TransitionEvent;
      this.assertEvent(event, events.at(-1) ?? null);
      events.push(event);
    }
    return events;
  }

  async transition(agentId: string, transitionId: string): Promise<TransitionEvent[]> {
    return (await this.read(agentId)).filter((event) => event.transitionId === transitionId);
  }

  async appendRepair(input: {
    agentId: string;
    transitionId: string;
    action: "forward" | "rollback";
    expectedViewId: string;
    expectedWorkspaceHash: string;
    actualViewId: string;
    actualWorkspaceHash: string;
  }): Promise<TransitionEvent> {
    if (
      input.expectedViewId !== input.actualViewId ||
      input.expectedWorkspaceHash !== input.actualWorkspaceHash
    ) {
      throw new Error("REPAIR_CAS_MISMATCH");
    }
    return this.append({
      agentId: input.agentId,
      transitionId: input.transitionId,
      type: "REPAIR_APPLIED",
      payload: {
        action: input.action,
        expectedViewId: input.expectedViewId,
        expectedWorkspaceHash: input.expectedWorkspaceHash,
      },
    });
  }

  private assertEvent(event: TransitionEvent, previous: TransitionEvent | null): void {
    if (event.schemaVersion !== 1 || event.sequence !== (previous?.sequence ?? 0) + 1) {
      throw new Error("TRANSITION_LOG_SEQUENCE_INVALID");
    }
    if (event.previousDigest !== (previous?.digest ?? null)) {
      throw new Error("TRANSITION_LOG_CHAIN_INVALID");
    }
    const { digest, ...unsigned } = event;
    if (digest !== digestEvent(unsigned)) throw new Error("TRANSITION_LOG_DIGEST_INVALID");
  }

  private agentDirectory(agentId: string): string {
    if (!/^[A-Za-z0-9_.-]{1,128}$/.test(agentId)) throw new Error("Invalid agentId");
    return path.join(this.root, agentId, "events");
  }

  private async enqueue<T>(agentId: string, operation: () => Promise<T>): Promise<T> {
    const previous = this.tails.get(agentId) ?? Promise.resolve();
    let result!: T;
    const current = previous.then(async () => {
      result = await operation();
    });
    this.tails.set(agentId, current.catch(() => undefined));
    await current;
    return result;
  }
}
