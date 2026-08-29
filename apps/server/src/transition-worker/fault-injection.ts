import type { TransitionEventType } from "../transition-log.js";

export const WORKER_EVENT_FAULT_POINTS = [
  "AGENT_INITIALIZATION_PREPARED",
  "LEGACY_ADOPTION_PREPARED",
  "TRANSITION_PREPARED",
  "PROPOSAL_SEAL_PREPARED",
  "PROPOSAL_SEALED",
  "PROPOSAL_EXPORT_PREPARED",
  "EVIDENCE_RECORDED",
  "PERMIT_ISSUED",
  "PERMIT_CONSUMING",
  "BACKUP_CREATED",
  "WORKSPACE_APPLIED",
  "ROLLBACK_APPLIED",
  "PLATFORM_STATE_REGENERATION_PREPARED",
  "PLATFORM_STATE_REGENERATED",
  "TRANSITION_ACKNOWLEDGED",
  "TRANSITION_ROLLED_BACK",
  "AGENT_ARCHIVE_PREPARED",
  "AGENT_ARCHIVED",
] as const satisfies readonly TransitionEventType[];

export type WorkerEventFaultPoint = (typeof WORKER_EVENT_FAULT_POINTS)[number];

export interface WorkerFaultInjectionConfig {
  point: WorkerEventFaultPoint;
  agentId: string | null;
  transitionId: string | null;
}

type FaultEnvironment = Readonly<Record<string, string | undefined>>;

const enabled = (environment: FaultEnvironment): boolean =>
  environment.COMMITGATE_FAULT_INJECTION === "true";

/**
 * Validates the dangerous test-only switch before the worker opens its socket.
 * A production process with the switch set fails startup instead of silently
 * carrying a latent kill primitive.
 */
export function resolveWorkerFaultInjection(
  environment: FaultEnvironment = process.env,
): WorkerFaultInjectionConfig | null {
  if (!enabled(environment)) return null;
  if (environment.NODE_ENV !== "test") {
    throw new Error("FAULT_INJECTION_REQUIRES_TEST_ENV");
  }
  const rawPoint = environment.COMMITGATE_FAULT_POINT;
  if (!WORKER_EVENT_FAULT_POINTS.includes(rawPoint as WorkerEventFaultPoint)) {
    throw new Error("FAULT_INJECTION_POINT_INVALID");
  }
  const filter = (name: "COMMITGATE_FAULT_AGENT_ID" | "COMMITGATE_FAULT_TRANSITION_ID") => {
    const value = environment[name]?.trim();
    if (!value) return null;
    if (!/^[A-Za-z0-9_.-]{1,128}$/.test(value)) {
      throw new Error(`FAULT_INJECTION_FILTER_INVALID:${name}`);
    }
    return value;
  };
  return {
    point: rawPoint as WorkerEventFaultPoint,
    agentId: filter("COMMITGATE_FAULT_AGENT_ID"),
    transitionId: filter("COMMITGATE_FAULT_TRANSITION_ID"),
  };
}

export interface WorkerFaultEventRef {
  type: TransitionEventType;
  agentId: string;
  transitionId: string;
  sequence: number;
  digest: string;
}

export type WorkerFaultTerminator = (
  signal: "SIGKILL",
  event: WorkerFaultEventRef,
) => void;

const terminateProcess: WorkerFaultTerminator = (_signal, event) => {
  process.stderr.write(`${JSON.stringify({
    kind: "commitgate-worker-fault-injection",
    action: "AWAIT_EXTERNAL_SIGKILL",
    point: event.type,
    agentId: event.agentId,
    transitionId: event.transitionId,
    sequence: event.sequence,
    eventDigest: event.digest,
  })}\n`);
  // A PID-namespace init process cannot reliably SIGKILL itself. Freeze at
  // the exact post-append boundary so the evaluator can issue a real
  // `docker kill --signal KILL` from the parent namespace.
  const latch = new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT));
  Atomics.wait(latch, 0, 0);
};

/** Called only after the event file has been atomically renamed and chmodded. */
export function maybeInjectWorkerEventFault(
  event: WorkerFaultEventRef,
  environment: FaultEnvironment = process.env,
  terminate: WorkerFaultTerminator = terminateProcess,
): boolean {
  const config = resolveWorkerFaultInjection(environment);
  if (
    !config ||
    config.point !== event.type ||
    (config.agentId !== null && config.agentId !== event.agentId) ||
    (config.transitionId !== null && config.transitionId !== event.transitionId)
  ) {
    return false;
  }
  terminate("SIGKILL", event);
  return true;
}
