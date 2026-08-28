import { randomUUID } from "node:crypto";
import { chmod, lstat, rm } from "node:fs/promises";
import { createConnection, createServer, type Server, type Socket } from "node:net";
import {
  rpcRequestSchema,
  type WorkerRpcRequestInput,
  type WorkerRpcResponse,
} from "./contracts.js";
import { TransitionWorker, WorkerFault } from "./worker.js";

const MAX_RPC_BYTES = 1_048_576;

const errorCode = (error: unknown): string => {
  if (error instanceof WorkerFault) return error.code;
  if (error && typeof error === "object" && "issues" in error) return "RPC_SCHEMA_INVALID";
  return "WORKER_INTERNAL_ERROR";
};

const errorMessage = (error: unknown): string =>
  error instanceof Error ? error.message : String(error);

async function removeStaleSocket(socketPath: string): Promise<void> {
  try {
    const current = await lstat(socketPath);
    if (!current.isSocket()) throw new Error("TRANSITION_WORKER_SOCKET_PATH_NOT_SOCKET");
    await rm(socketPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

export async function startTransitionWorkerRpc(
  worker: TransitionWorker,
): Promise<Server> {
  await worker.initialize();
  await removeStaleSocket(worker.config.socketPath);
  const server = createServer((socket) => handleConnection(worker, socket));
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(worker.config.socketPath, () => {
      server.off("error", reject);
      resolve();
    });
  });
  await chmod(worker.config.socketPath, 0o660);
  return server;
}

function handleConnection(worker: TransitionWorker, socket: Socket): void {
  socket.setEncoding("utf8");
  let buffered = "";
  let chain = Promise.resolve();
  socket.on("data", (chunk: string) => {
    buffered += chunk;
    if (Buffer.byteLength(buffered, "utf8") > MAX_RPC_BYTES) {
      socket.destroy(new Error("RPC_REQUEST_TOO_LARGE"));
      return;
    }
    while (buffered.includes("\n")) {
      const newline = buffered.indexOf("\n");
      const line = buffered.slice(0, newline);
      buffered = buffered.slice(newline + 1);
      if (!line.trim()) continue;
      chain = chain.then(async () => {
        let id = "invalid";
        let response: WorkerRpcResponse;
        try {
          const raw = JSON.parse(line) as { id?: unknown };
          if (typeof raw.id === "string") id = raw.id;
          const request = rpcRequestSchema.parse(raw);
          const result = await worker.dispatch(request);
          response = { id: request.id, ok: true, result };
        } catch (error) {
          response = {
            id,
            ok: false,
            error: { code: errorCode(error), message: errorMessage(error) },
          };
        }
        if (!socket.destroyed) socket.write(JSON.stringify(response) + "\n");
      });
    }
  });
}

export class TransitionWorkerRpcClient {
  constructor(private readonly socketPath: string) {}

  async request<T = unknown>(
    request: WorkerRpcRequestInput,
    timeoutMs = 30_000,
  ): Promise<T> {
    const id = request.id ?? randomUUID();
    const wire = JSON.stringify({ ...request, id }) + "\n";
    if (Buffer.byteLength(wire, "utf8") > MAX_RPC_BYTES) throw new Error("RPC_REQUEST_TOO_LARGE");
    return new Promise<T>((resolve, reject) => {
      const socket = createConnection(this.socketPath);
      socket.setEncoding("utf8");
      let buffered = "";
      let settled = false;
      const finish = (operation: () => void): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        operation();
      };
      const timeout = setTimeout(() => {
        socket.destroy();
        finish(() => reject(new WorkerFault(
          "WORKER_RPC_TIMEOUT",
          `Transition Worker RPC timed out after ${timeoutMs} ms`,
        )));
      }, timeoutMs);
      timeout.unref();
      socket.once("connect", () => socket.write(wire));
      socket.on("data", (chunk: string) => {
        buffered += chunk;
        if (Buffer.byteLength(buffered, "utf8") > MAX_RPC_BYTES) {
          socket.destroy();
          finish(() => reject(new WorkerFault(
            "RPC_RESPONSE_TOO_LARGE",
            "Transition Worker RPC response exceeded the byte limit",
          )));
          return;
        }
        const newline = buffered.indexOf("\n");
        if (newline < 0) return;
        socket.end();
        try {
          const response = JSON.parse(buffered.slice(0, newline)) as WorkerRpcResponse;
          if (response.id !== id) throw new Error("RPC_RESPONSE_ID_MISMATCH");
          if (!response.ok) {
            const error = new WorkerFault(response.error.code, response.error.message);
            finish(() => reject(error));
            return;
          }
          finish(() => resolve(response.result as T));
        } catch (error) {
          finish(() => reject(error));
        }
      });
      socket.once("end", () => {
        if (!settled && !buffered.includes("\n")) {
          finish(() => reject(new WorkerFault(
            "WORKER_RPC_TRUNCATED",
            "Transition Worker closed the connection before a complete response",
          )));
        }
      });
      socket.once("error", (error) => finish(() => reject(error)));
    });
  }
}
