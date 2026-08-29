export const API_PROJECTION_FAULT_POINT = "API_PROJECTION_PENDING" as const;

export interface ApiProjectionFaultRef {
  point: typeof API_PROJECTION_FAULT_POINT;
  source: "live-finalize" | "startup-recovery";
  agentId: string;
  runId: string;
  decision: "COMMITTED" | "QUARANTINED" | "CONFLICTED" | "ABORTED";
  viewId: string;
  generation: number;
  projectionDigest: string;
}

interface ApiProjectionFaultConfig {
  runId: string | null;
  agentId: string | null;
}

type FaultEnvironment = Readonly<Record<string, string | undefined>>;

export function resolveApiProjectionFaultInjection(
  environment: FaultEnvironment = process.env,
): ApiProjectionFaultConfig | null {
  if (environment.COMMITGATE_FAULT_INJECTION !== "true") return null;
  if (environment.NODE_ENV !== "test") {
    throw new Error("API_FAULT_INJECTION_REQUIRES_TEST_ENV");
  }
  if (environment.COMMITGATE_API_FAULT_POINT !== API_PROJECTION_FAULT_POINT) {
    // Worker-only fault injection may share the global enable flag. The API
    // hook stays dormant unless its own exact point is explicitly selected.
    if (!environment.COMMITGATE_API_FAULT_POINT) return null;
    throw new Error("API_FAULT_INJECTION_POINT_INVALID");
  }
  const filter = (name: "COMMITGATE_API_FAULT_AGENT_ID" | "COMMITGATE_API_FAULT_RUN_ID") => {
    const value = environment[name]?.trim();
    if (!value) return null;
    if (!/^[A-Za-z0-9_.-]{1,128}$/.test(value)) {
      throw new Error(`API_FAULT_INJECTION_FILTER_INVALID:${name}`);
    }
    return value;
  };
  return {
    agentId: filter("COMMITGATE_API_FAULT_AGENT_ID"),
    runId: filter("COMMITGATE_API_FAULT_RUN_ID"),
  };
}

export type ApiProjectionFaultTerminator = (ref: ApiProjectionFaultRef) => void;

const waitForExternalKill: ApiProjectionFaultTerminator = (ref) => {
  process.stderr.write(`${JSON.stringify({
    kind: "commitgate-api-projection-fault-injection",
    action: "AWAIT_EXTERNAL_SIGKILL",
    ...ref,
  })}\n`);
  // The evaluator issues docker kill --signal KILL from the parent namespace.
  // Blocking here gives an exact post-Worker/pre-product-DB crash boundary.
  const latch = new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT));
  Atomics.wait(latch, 0, 0);
};

export function maybeInjectApiProjectionFault(
  ref: ApiProjectionFaultRef,
  environment: FaultEnvironment = process.env,
  terminate: ApiProjectionFaultTerminator = waitForExternalKill,
): boolean {
  const config = resolveApiProjectionFaultInjection(environment);
  if (
    !config ||
    (config.agentId !== null && config.agentId !== ref.agentId) ||
    (config.runId !== null && config.runId !== ref.runId)
  ) {
    return false;
  }
  terminate(ref);
  return true;
}
