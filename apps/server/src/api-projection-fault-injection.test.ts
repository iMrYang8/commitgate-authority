import { describe, expect, it, vi } from "vitest";
import {
  API_PROJECTION_FAULT_POINT,
  maybeInjectApiProjectionFault,
  resolveApiProjectionFaultInjection,
} from "./api-projection-fault-injection.js";

const ref = {
  point: API_PROJECTION_FAULT_POINT,
  source: "startup-recovery" as const,
  agentId: "agent-1",
  runId: "run-1",
  decision: "COMMITTED" as const,
  viewId: "a".repeat(64),
  generation: 2,
  projectionDigest: "b".repeat(64),
};

describe("API projection process fault injection", () => {
  it("rejects the enabled switch outside NODE_ENV=test", () => {
    expect(() => resolveApiProjectionFaultInjection({
      NODE_ENV: "production",
      COMMITGATE_FAULT_INJECTION: "true",
      COMMITGATE_API_FAULT_POINT: API_PROJECTION_FAULT_POINT,
    })).toThrow("API_FAULT_INJECTION_REQUIRES_TEST_ENV");
  });

  it("requires the exact API point and validates filters", () => {
    expect(() => resolveApiProjectionFaultInjection({
      NODE_ENV: "test",
      COMMITGATE_FAULT_INJECTION: "true",
      COMMITGATE_API_FAULT_POINT: "OTHER",
    })).toThrow("API_FAULT_INJECTION_POINT_INVALID");
    expect(() => resolveApiProjectionFaultInjection({
      NODE_ENV: "test",
      COMMITGATE_FAULT_INJECTION: "true",
      COMMITGATE_API_FAULT_POINT: API_PROJECTION_FAULT_POINT,
      COMMITGATE_API_FAULT_RUN_ID: "../escape",
    })).toThrow("API_FAULT_INJECTION_FILTER_INVALID");
  });

  it("fires only for the matching terminal projection", () => {
    const terminate = vi.fn();
    const environment = {
      NODE_ENV: "test",
      COMMITGATE_FAULT_INJECTION: "true",
      COMMITGATE_API_FAULT_POINT: API_PROJECTION_FAULT_POINT,
      COMMITGATE_API_FAULT_AGENT_ID: ref.agentId,
      COMMITGATE_API_FAULT_RUN_ID: ref.runId,
    };
    expect(maybeInjectApiProjectionFault(ref, environment, terminate)).toBe(true);
    expect(terminate).toHaveBeenCalledWith(ref);
    expect(maybeInjectApiProjectionFault(
      { ...ref, runId: "other-run" },
      environment,
      terminate,
    )).toBe(false);
  });
});
