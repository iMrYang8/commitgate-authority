import { describe, expect, it, vi } from "vitest";
import {
  maybeInjectWorkerEventFault,
  resolveWorkerFaultInjection,
} from "./fault-injection.js";

const event = {
  type: "PERMIT_CONSUMING" as const,
  agentId: "agent-a",
  transitionId: "run-a",
  sequence: 7,
  digest: "a".repeat(64),
};

describe("transition-worker process fault injection", () => {
  it("is inert unless both the test environment and explicit switch are set", () => {
    expect(resolveWorkerFaultInjection({ NODE_ENV: "test" })).toBeNull();
    expect(() => resolveWorkerFaultInjection({
      NODE_ENV: "production",
      COMMITGATE_FAULT_INJECTION: "true",
      COMMITGATE_FAULT_POINT: "PERMIT_CONSUMING",
    })).toThrow("FAULT_INJECTION_REQUIRES_TEST_ENV");
  });

  it("rejects unknown points and unsafe filters before startup", () => {
    expect(() => resolveWorkerFaultInjection({
      NODE_ENV: "test",
      COMMITGATE_FAULT_INJECTION: "true",
      COMMITGATE_FAULT_POINT: "ARBITRARY_CODE",
    })).toThrow("FAULT_INJECTION_POINT_INVALID");
    expect(() => resolveWorkerFaultInjection({
      NODE_ENV: "test",
      COMMITGATE_FAULT_INJECTION: "true",
      COMMITGATE_FAULT_POINT: "PERMIT_CONSUMING",
      COMMITGATE_FAULT_TRANSITION_ID: "../escape",
    })).toThrow("FAULT_INJECTION_FILTER_INVALID");
  });

  it("terminates only for an exact durable event and optional binding filters", () => {
    const terminate = vi.fn();
    const environment = {
      NODE_ENV: "test",
      COMMITGATE_FAULT_INJECTION: "true",
      COMMITGATE_FAULT_POINT: "PERMIT_CONSUMING",
      COMMITGATE_FAULT_AGENT_ID: "agent-a",
      COMMITGATE_FAULT_TRANSITION_ID: "run-a",
    };
    expect(maybeInjectWorkerEventFault(event, environment, terminate)).toBe(true);
    expect(terminate).toHaveBeenCalledWith("SIGKILL", event);
    expect(maybeInjectWorkerEventFault(
      { ...event, transitionId: "run-b" },
      environment,
      terminate,
    )).toBe(false);
  });
});
