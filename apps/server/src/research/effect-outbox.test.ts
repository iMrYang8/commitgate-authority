import { mkdtemp } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import { EffectOutbox, type EffectAdapter } from "./effect-outbox.js";

describe("effect outbox", () => {
  it("does not dispatch before a proposal is committed and approved", async () => {
    const dispatch = vi.fn(async () => ({ ok: true }));
    const adapter: EffectAdapter = { id: "mock-kv", actions: ["put"], dispatch };
    const root = await mkdtemp(path.join(os.tmpdir(), "effect-outbox-"));
    const outbox = new EffectOutbox(path.join(root, "outbox.json"), [adapter]);
    const effect = await outbox.prepare({
      viewId: "v-next",
      proposalId: "p1",
      adapter: "mock-kv",
      action: "put",
      args: { key: "a", value: "b" },
      idempotencyKey: "fixture-1",
      reversibility: "reversible",
      approvalRequirement: "policy",
    });

    await expect(outbox.dispatch(effect.effectId, { key: "a", value: "b" })).rejects.toThrow(
      "EFFECT_NOT_AUTHORIZED",
    );
    expect(dispatch).not.toHaveBeenCalled();
    await expect(
      outbox.authorize({
        effectId: effect.effectId,
        committedViewId: "wrong-view",
        proposalId: "p1",
        approval: "policy",
      }),
    ).rejects.toThrow("EFFECT_COMMIT_BINDING_MISMATCH");

    await outbox.authorize({
      effectId: effect.effectId,
      committedViewId: "v-next",
      proposalId: "p1",
      approval: "policy",
    });
    const terminal = await outbox.dispatch(effect.effectId, { value: "b", key: "a" });
    expect(terminal.state).toBe("SUCCEEDED");
    expect(dispatch).toHaveBeenCalledTimes(1);
  });

  it("cancels uncommitted effects without calling an adapter", async () => {
    const dispatch = vi.fn(async () => undefined);
    const root = await mkdtemp(path.join(os.tmpdir(), "effect-outbox-"));
    const outbox = new EffectOutbox(path.join(root, "outbox.json"), [
      { id: "mock-webhook", actions: ["send"], dispatch },
    ]);
    await outbox.prepare({
      viewId: "v1",
      proposalId: "rejected-p",
      adapter: "mock-webhook",
      action: "send",
      args: { event: "hello" },
      idempotencyKey: "fixture-2",
      reversibility: "irreversible",
      approvalRequirement: "human",
    });
    expect(await outbox.cancelForProposal("rejected-p")).toBe(1);
    expect((await outbox.list())[0]?.state).toBe("CANCELLED");
    expect(dispatch).not.toHaveBeenCalled();
  });

  it("persists DISPATCHED before invoking the adapter", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "effect-outbox-"));
    const filePath = path.join(root, "outbox.json");
    let observedState: string | undefined;
    const outbox = new EffectOutbox(filePath, [
      {
        id: "mock-webhook",
        actions: ["send"],
        dispatch: async () => {
          // A separately opened instance represents another process observing
          // the durable record while the adapter is executing.
          observedState = (await new EffectOutbox(filePath, []).list())[0]?.state;
          return { delivered: true };
        },
      },
    ]);
    const effect = await outbox.prepare({
      viewId: "v2",
      proposalId: "p2",
      adapter: "mock-webhook",
      action: "send",
      args: { event: "committed" },
      idempotencyKey: "durable-dispatch-1",
      reversibility: "irreversible",
      approvalRequirement: "policy",
    });
    await outbox.authorize({
      effectId: effect.effectId,
      committedViewId: "v2",
      proposalId: "p2",
      approval: "policy",
    });

    expect((await outbox.dispatch(effect.effectId, { event: "committed" })).state).toBe(
      "SUCCEEDED",
    );
    expect(observedState).toBe("DISPATCHED");
  });

  it("retries a crash-left DISPATCHED record with the same idempotency key", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "effect-outbox-"));
    const filePath = path.join(root, "outbox.json");
    const appliedKeys = new Set<string>();
    const attempts: string[] = [];
    let externalEffectCount = 0;
    const adapter: EffectAdapter = {
      id: "mock-kv",
      actions: ["put"],
      dispatch: async ({ idempotencyKey }) => {
        attempts.push(idempotencyKey);
        if (!appliedKeys.has(idempotencyKey)) {
          appliedKeys.add(idempotencyKey);
          externalEffectCount += 1;
        }
        return { stored: true };
      },
    };
    const crashing = new EffectOutbox(
      filePath,
      [adapter],
      () => new Date("2026-01-01T00:00:00.000Z"),
      {
        afterAdapterDispatch: () => {
          throw new Error("SIMULATED_PROCESS_CRASH_BEFORE_TERMINAL_PERSIST");
        },
      },
    );
    const effect = await crashing.prepare({
      viewId: "v3",
      proposalId: "p3",
      adapter: "mock-kv",
      action: "put",
      args: { key: "a", value: "b" },
      idempotencyKey: "stable-idempotency-key",
      reversibility: "reversible",
      approvalRequirement: "policy",
    });
    await crashing.authorize({
      effectId: effect.effectId,
      committedViewId: "v3",
      proposalId: "p3",
      approval: "policy",
    });
    await expect(
      crashing.dispatch(effect.effectId, { key: "a", value: "b" }),
    ).rejects.toThrow("SIMULATED_PROCESS_CRASH");
    expect((await new EffectOutbox(filePath, [adapter]).list())[0]?.state).toBe(
      "DISPATCHED",
    );

    const recovered = new EffectOutbox(filePath, [adapter]);
    const terminal = await recovered.dispatch(effect.effectId, {
      value: "b",
      key: "a",
    });
    expect(terminal.state).toBe("SUCCEEDED");
    expect(attempts).toEqual([
      "stable-idempotency-key",
      "stable-idempotency-key",
    ]);
    expect(externalEffectCount).toBe(1);
  });
});
