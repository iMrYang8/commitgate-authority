import path from "node:path";
import { chmod, lstat, realpath, rm } from "node:fs/promises";
import { createServer, type Server, type Socket } from "node:net";
import type { AppConfig } from "../config.js";
import { ContainerCodexRunner } from "../container-codex-runner.js";
import { DockerVerifierRunner } from "../commitgate/verifier-runner.js";
import { RunCancelledError } from "../errors.js";
import type { RunnerCancellation, RunnerRequest } from "../types.js";
import {
  brokerRpcRequestSchema,
  brokerVerifierRequestSchema,
  type BrokerRunWireRequest,
  type BrokerVerifierRequest,
  type BrokerVerifierResult,
  type BrokerRpcResponse,
  type RuntimeBrokerDispatch,
  type RuntimeBrokerHealth,
} from "./contracts.js";

const MAX_RPC_BYTES = 4 * 1024 * 1024;

function isContained(root: string, candidate: string): boolean {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative === "" || (!relative.startsWith(".." + path.sep) && relative !== "..");
}

export function validateBrokerRunRequest(config: AppConfig, request: BrokerRunWireRequest): void {
  if (!request || typeof request !== "object") throw new Error("BROKER_REQUEST_INVALID");
  for (const [name, value] of [
    ["runId", request.runId],
    ["agentId", request.agentId],
    ["prompt", request.prompt],
  ] as const) {
    if (typeof value !== "string" || value.length === 0) {
      throw new Error(`BROKER_REQUEST_INVALID:${name}`);
    }
  }
  if (config.transitionAuthority === "worker") {
    if (request.workspacePath || !request.workspaceRef) {
      throw new Error("BROKER_OPAQUE_WORKSPACE_REF_REQUIRED");
    }
    const expectedVolumeId = `candidate-${request.runId}`;
    if (
      request.workspaceRef.agentId !== request.agentId ||
      request.workspaceRef.runId !== request.runId ||
      request.workspaceRef.volumeId !== expectedVolumeId ||
      request.workspaceRef.relativeSubpath !== expectedVolumeId
    ) {
      throw new Error("BROKER_WORKSPACE_REF_BINDING_MISMATCH");
    }
    return;
  }
  if (!request.workspacePath || request.workspaceRef) {
    throw new Error("BROKER_LEGACY_WORKSPACE_PATH_REQUIRED");
  }
  const expected = path.join(
    config.commitGateControlRoot,
    request.agentId,
    "candidates",
    request.runId,
  );
  if (
    !isContained(config.commitGateControlRoot, request.workspacePath) ||
    path.resolve(request.workspacePath) !== path.resolve(expected)
  ) {
    throw new Error("BROKER_WORKSPACE_NOT_RUN_CANDIDATE");
  }
}

export async function validateBrokerWorkspaceIdentity(
  config: AppConfig,
  request: BrokerRunWireRequest,
): Promise<string> {
  validateBrokerRunRequest(config, request);
  const expected = request.workspaceRef
    ? path.join(config.commitGateExchangeRoot, request.workspaceRef.relativeSubpath)
    : path.join(config.commitGateControlRoot, request.agentId, "candidates", request.runId);
  const stats = await lstat(expected);
  if (!stats.isDirectory() || stats.isSymbolicLink()) {
    throw new Error("BROKER_WORKSPACE_NOT_DIRECTORY");
  }
  const [controlIdentity, candidateIdentity] = await Promise.all([
    realpath(request.workspaceRef ? config.commitGateExchangeRoot : config.commitGateControlRoot),
    realpath(expected),
  ]);
  if (
    (!request.workspaceRef &&
      path.resolve(candidateIdentity) !== path.resolve(await realpath(request.workspacePath!))) ||
    !isContained(controlIdentity, candidateIdentity)
  ) {
    throw new Error("BROKER_WORKSPACE_IDENTITY_MISMATCH");
  }
  return candidateIdentity;
}

export class RuntimeBroker implements RuntimeBrokerDispatch {
  private readonly runner: ContainerCodexRunner;
  private readonly verifier: DockerVerifierRunner;
  private readonly activeRuns = new Set<string>();

  constructor(private readonly config: AppConfig) {
    this.runner = new ContainerCodexRunner(config);
    this.verifier = new DockerVerifierRunner({
      engine: config.containerEngine,
      image: config.containerRuntimeImage,
      cpuLimit: config.containerCpuLimit,
      memoryLimit: config.containerMemoryLimit,
      pidsLimit: config.containerPidsLimit,
      user: config.containerUser,
      instanceId: config.runtimeInstanceId,
      trustedChecksPath: config.commitGateTrustedChecksDirectory,
      trustedCheckStorePath: path.join(config.commitGateTrustedChecksVolumeRoot, "store"),
      trustedChecksVolume: config.commitGateTrustedChecksVolume,
      trustedChecksVolumeRoot: config.commitGateTrustedChecksVolumeRoot,
      proposalVolume: config.commitGateExchangeVolume,
      runTimeoutMs: config.commitGateVerifierTimeoutMs,
      maxOutputBytes: config.commitGateVerifierMaxOutputBytes,
      sourceRevision: config.commitGateSourceRevision,
    });
  }

  async health(): Promise<RuntimeBrokerHealth> {
    const runtimeAvailable = await this.runner.isAvailable();
    return { ready: runtimeAvailable, runtimeAvailable, activeRuns: this.activeRuns.size };
  }

  async runAgent(request: BrokerRunWireRequest) {
    this.assertRequest(request);
    const workspacePath = await validateBrokerWorkspaceIdentity(this.config, request);
    const resolved: RunnerRequest = { ...request, workspacePath };
    this.activeRuns.add(request.runId);
    try {
      return await this.runner.run(resolved);
    } finally {
      this.activeRuns.delete(request.runId);
    }
  }

  async runVerifier(request: BrokerVerifierRequest): Promise<BrokerVerifierResult> {
    const parsed = brokerVerifierRequestSchema.parse(request) as BrokerVerifierRequest;
    const verifyPath = path.join(
      this.config.commitGateExchangeRoot,
      parsed.workspaceRef.relativeSubpath,
    );
    const stats = await lstat(verifyPath);
    if (!stats.isDirectory() || stats.isSymbolicLink()) {
      throw new Error("BROKER_VERIFIER_WORKSPACE_NOT_DIRECTORY");
    }
    const [exchangeIdentity, verifierIdentity] = await Promise.all([
      realpath(this.config.commitGateExchangeRoot),
      realpath(verifyPath),
    ]);
    if (!isContained(exchangeIdentity, verifierIdentity)) {
      throw new Error("BROKER_VERIFIER_WORKSPACE_IDENTITY_MISMATCH");
    }
    const environment = await this.verifier.describeExecutionEnvironment(parsed.runId);
    const checks = await this.verifier.run({
      runId: parsed.runId,
      agentId: parsed.agentId,
      verifyPath: verifierIdentity,
      workspaceRef: parsed.workspaceRef,
      trustedChecksPath: this.config.commitGateTrustedChecksDirectory,
      checks: parsed.checks,
      timeoutMs: parsed.timeoutMs,
      maxOutputBytes: parsed.maxOutputBytes,
      proposalId: parsed.proposalId,
      checkBundleHash: environment.checkBundleHash,
    });
    return { checks, environment };
  }

  cancel(agentId: string, cancellation: RunnerCancellation) {
    return this.runner.cancel(agentId, cancellation);
  }

  teardown(runId: string) {
    return this.runner.attestCommitGateTeardown(runId);
  }

  private assertRequest(request: BrokerRunWireRequest): void {
    validateBrokerRunRequest(this.config, request);
  }
}

async function removeStaleSocket(socketPath: string): Promise<void> {
  try {
    if (!(await lstat(socketPath)).isSocket()) throw new Error("BROKER_SOCKET_PATH_NOT_SOCKET");
    await rm(socketPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

function errorCode(error: unknown): string {
  if (error instanceof RunCancelledError) return "RUN_CANCELLED";
  if (error && typeof error === "object" && "issues" in error) return "RPC_SCHEMA_INVALID";
  const message = error instanceof Error ? error.message : String(error);
  if (/^BROKER_[A-Z_]+/.test(message)) return message.split(":", 1)[0] ?? "BROKER_ERROR";
  return "BROKER_RUNTIME_ERROR";
}

function handleConnection(broker: RuntimeBrokerDispatch, socket: Socket): void {
  socket.setEncoding("utf8");
  let buffered = "";
  socket.on("data", (chunk: string) => {
    buffered += chunk;
    if (Buffer.byteLength(buffered, "utf8") > MAX_RPC_BYTES) {
      socket.destroy(new Error("RPC_REQUEST_TOO_LARGE"));
      return;
    }
    const newline = buffered.indexOf("\n");
    if (newline < 0) return;
    const line = buffered.slice(0, newline);
    buffered = "";
    void (async () => {
      let id = "invalid";
      let response: BrokerRpcResponse;
      try {
        const raw = JSON.parse(line) as { id?: unknown };
        if (typeof raw.id === "string") id = raw.id;
        const request = brokerRpcRequestSchema.parse(raw);
        const result = request.method === "health"
          ? await broker.health()
          : request.method === "runAgent"
            ? await broker.runAgent(request.request as BrokerRunWireRequest)
            : request.method === "runVerifier"
              ? await broker.runVerifier(request.request as BrokerVerifierRequest)
            : request.method === "cancel"
              ? await broker.cancel(request.agentId, request.cancellation)
              : await broker.teardown(request.runId);
        response = { id: request.id, ok: true, result };
      } catch (error) {
        response = {
          id,
          ok: false,
          error: {
            code: errorCode(error),
            message: error instanceof Error ? error.message : String(error),
          },
        };
      }
      if (!socket.destroyed) socket.end(JSON.stringify(response) + "\n");
    })();
  });
}

export async function startRuntimeBrokerRpc(
  broker: RuntimeBrokerDispatch,
  socketPath: string,
): Promise<Server> {
  await removeStaleSocket(socketPath);
  const server = createServer((socket) => handleConnection(broker, socket));
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => {
      server.off("error", reject);
      resolve();
    });
  });
  await chmod(socketPath, 0o660);
  return server;
}
