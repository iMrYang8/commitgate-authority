import { describe, expect, it } from "vitest";
import { computeStateViewId, makeStateView } from "./state-view.js";

const base = {
  agentId: "agent-1",
  headVersionId: "v1",
  generation: 1,
  versionedHash: "a".repeat(64),
  platformManagedHash: "b".repeat(64),
  liveStateHash: "c".repeat(64),
  sessionEpoch: 1,
  agentConfigVersion: 1,
  policyVersion: 1,
};

describe("StateView", () => {
  it("is deterministic and schema-bound", () => {
    expect(computeStateViewId(base)).toBe(computeStateViewId({ ...base }));
    expect(makeStateView(base)).toMatchObject({ schemaVersion: 1, ...base });
  });

  it.each([
    ["generation", { generation: 2 }],
    ["session epoch", { sessionEpoch: 2 }],
    ["configuration", { agentConfigVersion: 2 }],
    ["policy", { policyVersion: 2 }],
    ["head", { headVersionId: "v2" }],
    ["content", { liveStateHash: "d".repeat(64) }],
  ])("changes when %s changes", (_label, patch) => {
    expect(computeStateViewId({ ...base, ...patch })).not.toBe(computeStateViewId(base));
  });

  it("fences an ABA even when the live hash returns to H0", () => {
    const original = computeStateViewId(base);
    const aba = computeStateViewId({ ...base, generation: 3 });
    expect(aba).not.toBe(original);
  });
});
