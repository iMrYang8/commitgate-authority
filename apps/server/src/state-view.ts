import { createHash } from "node:crypto";
import type { Agent, StateViewRef } from "./types.js";

export const EMPTY_STATE_HASH = "0".repeat(64);

export type StateViewInput = Omit<StateViewRef, "schemaVersion" | "viewId">;

/**
 * State views deliberately use a fixed field order instead of a generic object
 * serializer. Adding a field therefore requires a schema-version change and
 * cannot silently invalidate already recorded view identifiers.
 */
export function computeStateViewId(input: StateViewInput): string {
  const canonical = {
    schemaVersion: 1 as const,
    agentId: input.agentId,
    headVersionId: input.headVersionId,
    generation: input.generation,
    versionedHash: input.versionedHash,
    platformManagedHash: input.platformManagedHash,
    liveStateHash: input.liveStateHash,
    sessionEpoch: input.sessionEpoch,
    agentConfigVersion: input.agentConfigVersion,
    policyVersion: input.policyVersion,
  };
  return createHash("sha256").update(JSON.stringify(canonical)).digest("hex");
}

export function makeStateView(input: StateViewInput): StateViewRef {
  return {
    schemaVersion: 1,
    viewId: computeStateViewId(input),
    ...input,
  };
}

export function stateViewForAgent(agent: Agent): StateViewRef {
  return makeStateView({
    agentId: agent.id,
    headVersionId: agent.headVersionId ?? "uninitialized",
    generation: agent.stateGeneration,
    versionedHash: agent.currentVersionedHash || EMPTY_STATE_HASH,
    platformManagedHash: agent.currentPlatformManagedHash || EMPTY_STATE_HASH,
    liveStateHash: agent.currentLiveStateHash || EMPTY_STATE_HASH,
    sessionEpoch: agent.sessionEpoch,
    agentConfigVersion: agent.agentConfigVersion,
    policyVersion: agent.policyVersion,
  });
}

export function refreshAgentViewId(agent: Agent): void {
  agent.currentViewId = stateViewForAgent(agent).viewId;
}
