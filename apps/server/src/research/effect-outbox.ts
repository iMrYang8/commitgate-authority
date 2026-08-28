import { createHash, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { writeJsonAtomic } from "../commitgate/atomic-json.js";

export type EffectState =
  | "PREPARED"
  | "AUTHORIZED"
  | "DISPATCHED"
  | "SUCCEEDED"
  | "FAILED"
  | "COMPENSATED"
  | "CANCELLED";

export interface EffectIntent {
  schemaVersion: 1;
  effectId: string;
  viewId: string;
  proposalId: string;
  adapter: string;
  action: string;
  canonicalArgsDigest: string;
  idempotencyKey: string;
  reversibility: "reversible" | "irreversible";
  approvalRequirement: "policy" | "human";
  state: EffectState;
  createdAt: string;
  updatedAt: string;
  resultDigest: string | null;
  errorClass: string | null;
}

export interface EffectAdapter {
  id: string;
  actions: readonly string[];
  /**
   * At-least-once contract: implementations must deduplicate calls carrying
   * the same idempotencyKey. A process may stop after the effect but before
   * SUCCEEDED is persisted, leaving a DISPATCHED record to retry.
   */
  dispatch(input: {
    action: string;
    args: unknown;
    idempotencyKey: string;
  }): Promise<unknown>;
  compensate?(input: {
    action: string;
    resultDigest: string;
    idempotencyKey: string;
  }): Promise<unknown>;
}

export interface EffectOutboxHooks {
  /** Test/telemetry crash point after the side effect and before terminal persistence. */
  afterAdapterDispatch?(effect: Readonly<EffectIntent>): Promise<void> | void;
}

interface EffectOutboxFile {
  schemaVersion: 1;
  effects: EffectIntent[];
}

const sha256 = (value: unknown): string =>
  createHash("sha256").update(JSON.stringify(value) ?? "undefined").digest("hex");

const canonical = (value: unknown): unknown => {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right, "en"))
        .map(([key, item]) => [key, canonical(item)]),
    );
  }
  return value;
};

/**
 * A registered-adapter outbox. Preparing an intent has no external effect;
 * dispatch is possible only after an authoritative commit and explicit policy
 * or human approval. Arbitrary shell commands are intentionally not adapters.
 */
export class EffectOutbox {
  private tail: Promise<void> = Promise.resolve();
  private readonly adapters = new Map<string, EffectAdapter>();
  private readonly inFlight = new Set<string>();

  constructor(
    private readonly filePath: string,
    adapters: EffectAdapter[],
    private readonly now: () => Date = () => new Date(),
    private readonly hooks: EffectOutboxHooks = {},
  ) {
    for (const adapter of adapters) {
      if (this.adapters.has(adapter.id)) throw new Error(`Duplicate effect adapter ${adapter.id}`);
      this.adapters.set(adapter.id, adapter);
    }
  }

  async prepare(input: {
    viewId: string;
    proposalId: string;
    adapter: string;
    action: string;
    args: unknown;
    idempotencyKey: string;
    reversibility: EffectIntent["reversibility"];
    approvalRequirement: EffectIntent["approvalRequirement"];
  }): Promise<EffectIntent> {
    return this.mutate(async (file) => {
      const adapter = this.requireAdapter(input.adapter, input.action);
      void adapter;
      const prior = file.effects.find((item) => item.idempotencyKey === input.idempotencyKey);
      const argsDigest = sha256(canonical(input.args));
      if (prior) {
        if (
          prior.adapter !== input.adapter ||
          prior.action !== input.action ||
          prior.canonicalArgsDigest !== argsDigest
        ) {
          throw new Error("IDEMPOTENCY_KEY_REUSE");
        }
        return prior;
      }
      const timestamp = this.now().toISOString();
      const effect: EffectIntent = {
        schemaVersion: 1,
        effectId: randomUUID(),
        viewId: input.viewId,
        proposalId: input.proposalId,
        adapter: input.adapter,
        action: input.action,
        canonicalArgsDigest: argsDigest,
        idempotencyKey: input.idempotencyKey,
        reversibility: input.reversibility,
        approvalRequirement: input.approvalRequirement,
        state: "PREPARED",
        createdAt: timestamp,
        updatedAt: timestamp,
        resultDigest: null,
        errorClass: null,
      };
      file.effects.push(effect);
      return effect;
    });
  }

  async authorize(input: {
    effectId: string;
    committedViewId: string;
    proposalId: string;
    approval: "policy" | "human";
  }): Promise<EffectIntent> {
    return this.mutate(async (file) => {
      const effect = this.requireEffect(file, input.effectId);
      if (effect.state !== "PREPARED") throw new Error("EFFECT_NOT_PREPARED");
      if (effect.viewId !== input.committedViewId || effect.proposalId !== input.proposalId) {
        throw new Error("EFFECT_COMMIT_BINDING_MISMATCH");
      }
      if (effect.approvalRequirement !== input.approval) throw new Error("EFFECT_APPROVAL_MISMATCH");
      effect.state = "AUTHORIZED";
      effect.updatedAt = this.now().toISOString();
      return effect;
    });
  }

  async dispatch(effectId: string, args: unknown): Promise<EffectIntent> {
    if (this.inFlight.has(effectId)) throw new Error("EFFECT_DISPATCH_IN_FLIGHT");
    this.inFlight.add(effectId);
    try {
      // This mutation returns only after DISPATCHED is durably written. A crash
      // after this point leaves an explicit at-least-once retry record rather
      // than an ambiguous AUTHORIZED intent.
      const dispatched = await this.mutate(async (file) => {
        const effect = this.requireEffect(file, effectId);
        if (effect.state !== "AUTHORIZED" && effect.state !== "DISPATCHED") {
          throw new Error("EFFECT_NOT_AUTHORIZED");
        }
        if (effect.canonicalArgsDigest !== sha256(canonical(args))) {
          throw new Error("EFFECT_ARGS_DIGEST_MISMATCH");
        }
        this.requireAdapter(effect.adapter, effect.action);
        if (effect.state === "AUTHORIZED") {
          effect.state = "DISPATCHED";
          effect.updatedAt = this.now().toISOString();
        }
        return { ...effect };
      });

      const adapter = this.requireAdapter(dispatched.adapter, dispatched.action);
      let result: unknown;
      try {
        result = await adapter.dispatch({
          action: dispatched.action,
          args,
          // Retries after a DISPATCHED crash always retain this exact key. The
          // adapter is responsible for deduplicating the external effect.
          idempotencyKey: dispatched.idempotencyKey,
        });
      } catch (error) {
        return this.mutate(async (file) => {
          const effect = this.requireEffect(file, effectId);
          if (effect.state !== "DISPATCHED") throw new Error("EFFECT_DISPATCH_STATE_CHANGED");
          effect.state = "FAILED";
          effect.errorClass = error instanceof Error ? error.name : "UnknownError";
          effect.updatedAt = this.now().toISOString();
          return { ...effect };
        });
      }

      // A failure here intentionally leaves DISPATCHED on disk. Reopening the
      // outbox and dispatching again uses the same idempotency key.
      await this.hooks.afterAdapterDispatch?.(dispatched);
      const resultDigest = sha256(canonical(result));
      return this.mutate(async (file) => {
        const effect = this.requireEffect(file, effectId);
        if (effect.state !== "DISPATCHED") throw new Error("EFFECT_DISPATCH_STATE_CHANGED");
        effect.state = "SUCCEEDED";
        effect.resultDigest = resultDigest;
        effect.errorClass = null;
        effect.updatedAt = this.now().toISOString();
        return { ...effect };
      });
    } finally {
      this.inFlight.delete(effectId);
    }
  }

  async cancelForProposal(proposalId: string): Promise<number> {
    return this.mutate(async (file) => {
      let count = 0;
      for (const effect of file.effects) {
        if (effect.proposalId === proposalId && effect.state === "PREPARED") {
          effect.state = "CANCELLED";
          effect.updatedAt = this.now().toISOString();
          count += 1;
        }
      }
      return count;
    });
  }

  async compensate(effectId: string): Promise<EffectIntent> {
    return this.mutate(async (file) => {
      const effect = this.requireEffect(file, effectId);
      if (effect.state !== "SUCCEEDED" || effect.reversibility !== "reversible") {
        throw new Error("EFFECT_NOT_COMPENSATABLE");
      }
      const adapter = this.requireAdapter(effect.adapter, effect.action);
      if (!adapter.compensate || !effect.resultDigest) throw new Error("EFFECT_ADAPTER_NO_COMPENSATION");
      await adapter.compensate({
        action: effect.action,
        resultDigest: effect.resultDigest,
        idempotencyKey: effect.idempotencyKey,
      });
      effect.state = "COMPENSATED";
      effect.updatedAt = this.now().toISOString();
      return effect;
    });
  }

  async list(): Promise<EffectIntent[]> {
    return (await this.read()).effects.map((effect) => ({ ...effect }));
  }

  private requireAdapter(adapterId: string, action: string): EffectAdapter {
    const adapter = this.adapters.get(adapterId);
    if (!adapter || !adapter.actions.includes(action)) throw new Error("UNREGISTERED_EFFECT_ADAPTER");
    return adapter;
  }

  private requireEffect(file: EffectOutboxFile, effectId: string): EffectIntent {
    const effect = file.effects.find((item) => item.effectId === effectId);
    if (!effect) throw new Error("EFFECT_NOT_FOUND");
    return effect;
  }

  private async read(): Promise<EffectOutboxFile> {
    try {
      const parsed = JSON.parse(await readFile(this.filePath, "utf8")) as EffectOutboxFile;
      if (parsed.schemaVersion !== 1 || !Array.isArray(parsed.effects)) throw new Error("OUTBOX_INVALID");
      return parsed;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        return { schemaVersion: 1, effects: [] };
      }
      throw error;
    }
  }

  private async mutate<T>(operation: (file: EffectOutboxFile) => Promise<T>): Promise<T> {
    let result!: T;
    const current = this.tail.then(async () => {
      const file = await this.read();
      result = await operation(file);
      await writeJsonAtomic(this.filePath, file);
    });
    this.tail = current.catch(() => undefined);
    await current;
    return result;
  }
}
