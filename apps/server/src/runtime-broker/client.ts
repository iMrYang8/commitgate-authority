import { randomUUID } from "node:crypto";
import { createConnection } from "node:net";
import { RunCancelledError } from "../errors.js";
import type { AgentRunner, RunnerCancellation, RunnerRequest, RunnerResult } from "../types.js";
import type {
  BrokerRpcRequestInput,
  BrokerRpcResponse,
  BrokerVerifierRequest,
  BrokerVerifierResult,
  BrokerReconcileRequest,
  BrokerTeardownRequest,
  SignedBrokerRuntimeTeardownAttestation,
  RuntimeReconciliationAttestation,
  RuntimeBrokerHealth,
} from "./contracts.js";

const MAX_RPC_BYTES = 4 * 1024 * 1024;
export const VERIFIER_RPC_TEARDOWN_GRACE_MS = 30_000;

export function verifierRpcTimeoutMs(globalVerifierBudgetMs: number): number {
  if (!Number.isSafeInteger(globalVerifierBudgetMs) || globalVerifierBudgetMs < 1_000) {
    throw new RuntimeBrokerFault(
      "BROKER_VERIFIER_TIMEOUT_INVALID",
      "Verifier RPC timeout requires a positive global verifier budget",
    );
  }
  return globalVerifierBudgetMs + VERIFIER_RPC_TEARDOWN_GRACE_MS;
}

export class RuntimeBrokerFault extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "RuntimeBrokerFault";
  }
}

export class RuntimeBrokerRpcClient {
  constructor(private readonly socketPath: string) {}

  async request<T>(request: BrokerRpcRequestInput, timeoutMs = 15_000): Promise<T> {
    const id = request.id ?? randomUUID();
    const wire = JSON.stringify({ ...request, id }) + "\n";
    if (Buffer.byteLength(wire, "utf8") > MAX_RPC_BYTES) throw new Error("RPC_REQUEST_TOO_LARGE");
    return new Promise<T>((resolve, reject) => {
      const socket = createConnection(this.socketPath);
      socket.setEncoding("utf8");
      let buffered = "";
      let settled = false;
      const finish = (operation: () => void) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        operation();
      };
      const timeout = setTimeout(() => {
        socket.destroy();
        finish(() => reject(new RuntimeBrokerFault(
          "BROKER_RPC_TIMEOUT",
          `Runtime Broker RPC timed out after ${timeoutMs} ms`,
        )));
      }, timeoutMs);
      timeout.unref();
      socket.once("connect", () => socket.write(wire));
      socket.on("data", (chunk: string) => {
        buffered += chunk;
        if (Buffer.byteLength(buffered, "utf8") > MAX_RPC_BYTES) {
          socket.destroy();
          finish(() => reject(new Error("RPC_RESPONSE_TOO_LARGE")));
          return;
        }
        const newline = buffered.indexOf("\n");
        if (newline < 0) return;
        socket.end();
        try {
          const response = JSON.parse(buffered.slice(0, newline)) as BrokerRpcResponse;
          if (response.id !== id) throw new Error("RPC_RESPONSE_ID_MISMATCH");
          if (!response.ok) {
            if (response.error.code === "RUN_CANCELLED") {
              finish(() => reject(new RunCancelledError()));
            } else {
              finish(() => reject(new RuntimeBrokerFault(response.error.code, response.error.message)));
            }
            return;
          }
          finish(() => resolve(response.result as T));
        } catch (error) {
          finish(() => reject(error));
        }
      });
      socket.once("error", (error) => finish(() => reject(error)));
    });
  }
}

export class RuntimeBrokerRunner implements AgentRunner {
  private readonly rpc: RuntimeBrokerRpcClient;

  constructor(
    socketPath: string,
    private readonly runTimeoutMs = 15 * 60_000,
  ) {
    this.rpc = new RuntimeBrokerRpcClient(socketPath);
  }

  run(request: RunnerRequest): Promise<RunnerResult> {
    if (request.workspaceRef) {
      const { workspacePath: _untrustedWorkspacePath, ...opaqueRequest } = request;
      return this.rpc.request(
        { method: "runAgent", request: opaqueRequest },
        this.runTimeoutMs,
      );
    }
    return this.rpc.request({ method: "runAgent", request }, this.runTimeoutMs);
  }

  cancel(agentId: string, cancellation?: RunnerCancellation): Promise<boolean> {
    if (!cancellation) {
      return Promise.reject(new RuntimeBrokerFault(
        "BROKER_CANCEL_BINDING_REQUIRED",
        "Runtime Broker cancellation requires run, lease and session bindings",
      ));
    }
    return this.rpc.request({ method: "cancel", agentId, cancellation });
  }

  async isAvailable(): Promise<boolean> {
    try {
      const result = await this.rpc.request<RuntimeBrokerHealth>({ method: "health" });
      return result.ready && result.runtimeAvailable;
    } catch {
      return false;
    }
  }

  attestCommitGateTeardown(
    request: BrokerTeardownRequest,
  ): Promise<SignedBrokerRuntimeTeardownAttestation> {
    return this.rpc.request({ method: "teardown", request });
  }

  reconcileCommitGateRuntime(
    request: BrokerReconcileRequest,
  ): Promise<RuntimeReconciliationAttestation> {
    return this.rpc.request({ method: "reconcile", request }, 30_000);
  }

  runVerifier(request: BrokerVerifierRequest): Promise<BrokerVerifierResult> {
    // The RPC client must outlive the complete verifier budget plus bounded
    // container teardown. Otherwise the caller could fail first while a
    // Broker-owned verifier container continues running in the background.
    return this.rpc.request(
      { method: "runVerifier", request },
      verifierRpcTimeoutMs(request.timeoutMs),
    );
  }
}
