import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import path from "node:path";
import { chmod, lstat, realpath, rm } from "node:fs/promises";
import { createServer, type Server, type Socket } from "node:net";
import { promisify } from "node:util";
import type { AppConfig } from "../config.js";
import { ContainerCodexRunner } from "../container-codex-runner.js";
import { DockerVerifierRunner } from "../commitgate/verifier-runner.js";
import { RunCancelledError } from "../errors.js";
import type { RunnerCancellation, RunnerRequest } from "../types.js";
import { sha256Canonical } from "../commitgate/protocol.js";
import { computeCheckSpecHash } from "../commitgate/trusted-check-bundle.js";
import { buildWorkerManifest } from "../transition-worker/filesystem.js";
import { signBrokerAttestation } from "./attestation.js";
import {
  BrokerLifecycleLedger,
  type BrokerRunBinding,
} from "./lifecycle-ledger.js";
import {
  brokerRpcRequestSchema,
  brokerReconcileRequestSchema,
  brokerVerifierRequestSchema,
  brokerTeardownRequestSchema,
  type BrokerReconcileRequest,
  type BrokerRunWireRequest,
  type BrokerVerifierRequest,
  type BrokerVerifierResult,
  type BrokerRecordedCheck,
  type BrokerTeardownRequest,
  type BrokerRpcResponse,
  type RuntimeBrokerDispatch,
  type RuntimeBrokerHealth,
  type RuntimeReconciliationAttestation,
} from "./contracts.js";

const MAX_RPC_BYTES = 4 * 1024 * 1024;
const execFileAsync = promisify(execFile);

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
    if (!request.runLeaseId || request.sessionEpoch === undefined) {
      throw new Error("BROKER_RUNTIME_BINDING_REQUIRED");
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
  private readonly lifecycle: BrokerLifecycleLedger;
  private readonly activeRuns = new Set<string>();
  private readonly activeVerifiers = new Map<
    string,
    BrokerRunBinding & { controller: AbortController }
  >();

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
    this.lifecycle = new BrokerLifecycleLedger(
      path.join(config.commitGateSessionVolumeRoot, ".runtime-broker-ledger"),
    );
  }

  async health(): Promise<RuntimeBrokerHealth> {
    const runtimeAvailable = await this.runner.isAvailable();
    return {
      ready: runtimeAvailable,
      runtimeAvailable,
      activeRuns: new Set([...this.activeRuns, ...this.activeVerifiers.keys()]).size,
    };
  }

  async runAgent(request: BrokerRunWireRequest) {
    this.assertRequest(request);
    const workspacePath = await validateBrokerWorkspaceIdentity(this.config, request);
    const binding = this.lifecycleBinding(request);
    if (binding) await this.lifecycle.beginAgent(binding);
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
    if (this.activeVerifiers.has(parsed.runId)) {
      throw new Error("BROKER_VERIFIER_RUN_ALREADY_ACTIVE");
    }
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
    const binding = this.bindingFromRequired(parsed);
    const controller = new AbortController();
    try {
      const environment = await this.verifier.describeExecutionEnvironment(parsed.runId);
      const beforeManifest = await buildWorkerManifest(verifierIdentity);
      if (beforeManifest.hash !== parsed.verifierInputHash) {
        throw new Error("BROKER_VERIFIER_INPUT_HASH_MISMATCH");
      }
      const computedCheckSpecHash = computeCheckSpecHash(parsed.checks);
      if (computedCheckSpecHash !== parsed.checkSpecHash) {
        throw new Error("BROKER_VERIFIER_CHECK_SPEC_HASH_MISMATCH");
      }
      if (this.config.transitionAuthority === "worker") {
        await this.lifecycle.beginVerifier(binding);
      }
      this.activeVerifiers.set(parsed.runId, { ...binding, controller });
      const checks = await this.verifier.run({
        runId: parsed.runId,
        agentId: parsed.agentId,
        runLeaseId: parsed.runLeaseId,
        sessionEpoch: parsed.sessionEpoch,
        verifyPath: verifierIdentity,
        workspaceRef: parsed.workspaceRef,
        trustedChecksPath: this.config.commitGateTrustedChecksDirectory,
        checks: parsed.checks,
        timeoutMs: parsed.timeoutMs,
        maxOutputBytes: parsed.maxOutputBytes,
        proposalId: parsed.proposalId,
        checkBundleHash: environment.checkBundleHash,
        signal: controller.signal,
      });
      const afterManifest = await buildWorkerManifest(verifierIdentity);
      if (afterManifest.hash !== beforeManifest.hash) {
        throw new Error("BROKER_VERIFIER_INPUT_MUTATED");
      }
      const recordedChecks: BrokerRecordedCheck[] = checks.map((check) => ({
        id: check.id,
        status: check.status,
        exitCode: check.exitCode,
        durationMs: check.durationMs,
        outputHash: createHash("sha256").update(check.output).digest("hex"),
        timedOut: check.timedOut,
      }));
      const requiredIds = new Set(parsed.checks.map((check) => check.id));
      const observedIds = new Set(recordedChecks.map((check) => check.id));
      const coverage =
        recordedChecks.length === parsed.checks.length &&
        observedIds.size === requiredIds.size &&
        [...requiredIds].every((id) => observedIds.has(id))
          ? "complete" as const
          : recordedChecks.length > 0
            ? "partial" as const
            : "unavailable" as const;
      const attestation = signBrokerAttestation({
        schemaVersion: 1 as const,
        kind: "verifier-result" as const,
        scope: "VERIFIER" as const,
        runId: parsed.runId,
        agentId: parsed.agentId,
        runLeaseId: parsed.runLeaseId,
        sessionEpoch: parsed.sessionEpoch,
        proposalId: parsed.proposalId,
        verifierInputHash: beforeManifest.hash,
        checkSpecHash: computedCheckSpecHash,
        checkResultsHash: sha256Canonical(recordedChecks),
        coverage,
        checks: recordedChecks,
        environment: {
          checkBundleHash: environment.checkBundleHash,
          verifierImageDigest: environment.imageDigest,
          verifierConfigHash: environment.configHash,
          resourcePolicyHash: environment.resourcePolicyHash ?? "unverified",
          sourceRevision: environment.sourceRevision ?? "unverified",
        },
      }, this.config.brokerAttestationKey);
      return { checks, environment, attestation };
    } finally {
      if (this.activeVerifiers.get(parsed.runId)?.controller === controller) {
        this.activeVerifiers.delete(parsed.runId);
      }
    }
  }

  async cancel(agentId: string, cancellation: RunnerCancellation): Promise<boolean> {
    const verifier = this.activeVerifiers.get(cancellation.runId);
    const verifierCancelled = verifier?.agentId === agentId &&
      verifier.runLeaseId === cancellation.runLeaseId &&
      verifier.sessionEpoch === cancellation.sessionEpoch;
    if (verifierCancelled) verifier.controller.abort(new RunCancelledError());
    const agentCancelled = await this.runner.cancel(agentId, cancellation);
    return agentCancelled || verifierCancelled;
  }

  async teardown(request: BrokerTeardownRequest) {
    const parsed = brokerTeardownRequestSchema.parse(request);
    const binding = this.bindingFromRequired(parsed);
    if (this.config.transitionAuthority === "worker") {
      await this.lifecycle.assertKnown(binding);
    }
    const agentKnown = this.runner.hasCommitGateTeardown(parsed.runId);
    const [agent, verifier] = await Promise.all([
      this.runner.attestCommitGateTeardown(parsed.runId, binding),
      parsed.scope === "ALL"
        ? this.verifier.attestCommitGateTeardown(parsed.runId, binding)
        : Promise.resolve(null),
    ]);
    // A normal protected run can own an Agent container and later one or more
    // Verifier containers under the same runId. The public attestation closes
    // only when every known Broker-owned container and its mounts are gone.
    const teardown = !verifier
      ? agent
      : !agentKnown
        ? verifier
        : {
            ...agent,
            containerExited: agent.containerExited && verifier.containerExited,
            containerRemoved: agent.containerRemoved && verifier.containerRemoved,
            mountsReleased: agent.mountsReleased && verifier.mountsReleased,
          };
    if (!teardown.containerExited || !teardown.containerRemoved || !teardown.mountsReleased) {
      throw new Error("BROKER_RUNTIME_TEARDOWN_INCOMPLETE");
    }
    if (this.config.transitionAuthority === "worker") {
      if (parsed.scope === "AGENT") await this.lifecycle.markAgentClosed(binding);
      else await this.lifecycle.markAllClosed(binding);
    }
    return signBrokerAttestation({
      schemaVersion: 1 as const,
      kind: "runtime-teardown" as const,
      runId: parsed.runId,
      agentId: parsed.agentId,
      runLeaseId: parsed.runLeaseId,
      sessionEpoch: parsed.sessionEpoch,
      scope: parsed.scope,
      containerExited: true as const,
      containerRemoved: true as const,
      mountsReleased: true as const,
      source: "runtime-attestation" as const,
      ...(teardown.resolvedModel !== undefined
        ? { resolvedModel: teardown.resolvedModel }
        : {}),
    }, this.config.brokerAttestationKey);
  }

  /**
   * Rediscover and quiesce Broker-owned containers after a process restart.
   * Ownership comes from exact run/lease/session labels, never a caller path.
   * The Worker has no Docker socket and persists only this negative
   * container/mount observation before touching exchange artifacts.
   */
  async reconcile(
    request: BrokerReconcileRequest,
  ): Promise<RuntimeReconciliationAttestation> {
    const parsed = brokerReconcileRequestSchema.parse(request);
    const binding = this.bindingFromRequired(parsed);
    if (this.config.transitionAuthority === "worker") {
      await this.lifecycle.assertKnown(binding);
    }
    await this.cancel(parsed.agentId, {
      runId: parsed.runId,
      runLeaseId: parsed.runLeaseId,
      sessionEpoch: parsed.sessionEpoch,
    }).catch(() => false);

    const kinds: Array<"agent" | "verifier"> =
      parsed.scope === "AGENT" ? ["agent"] : ["agent", "verifier"];
    for (const kind of kinds) {
      for (const containerId of await this.listBoundContainers(parsed, kind)) {
        try {
          await execFileAsync(this.config.containerEngine, ["rm", "--force", containerId], {
            timeout: 10_000,
            env: this.runtimeEnvironment(),
          });
        } catch {
          // An --rm container may disappear between list and force-remove.
          // The bounded negative query below decides whether release is true.
        }
      }
    }

    for (let attempt = 0; attempt < 20; attempt += 1) {
      const remaining = (
        await Promise.all(kinds.map((kind) => this.listBoundContainers(parsed, kind)))
      ).flat();
      if (remaining.length === 0) {
        if (this.config.transitionAuthority === "worker") {
          if (parsed.scope === "AGENT") await this.lifecycle.markAgentClosed(binding);
          else await this.lifecycle.markAllClosed(binding);
        }
        return signBrokerAttestation({
          schemaVersion: 1,
          kind: "runtime-teardown",
          ...parsed,
          containerExited: true,
          containerRemoved: true,
          mountsReleased: true,
          source: "broker-reconciliation",
        }, this.config.brokerAttestationKey);
      }
      await new Promise<void>((resolve) => setTimeout(resolve, 100));
    }
    throw new Error("BROKER_RECONCILIATION_INCOMPLETE");
  }

  private async listBoundContainers(
    request: BrokerReconcileRequest,
    kind: "agent" | "verifier",
  ): Promise<string[]> {
    const ownershipLabel = kind === "agent"
      ? "io.commitgate.runtime=agent-runtime"
      : "io.commitgate.runtime=verifier";
    let stdout: string;
    try {
      const result = await execFileAsync(
        this.config.containerEngine,
        [
          "container",
          "ls",
          "--all",
          "--quiet",
          "--filter", `label=${ownershipLabel}`,
          "--filter", `label=io.commitgate.instance-id=${this.config.runtimeInstanceId}`,
          "--filter", `label=io.commitgate.agent-id=${request.agentId}`,
          "--filter", `label=io.commitgate.run-id=${request.runId}`,
          "--filter", `label=io.commitgate.run-lease-id=${request.runLeaseId}`,
          "--filter", `label=io.commitgate.session-epoch=${request.sessionEpoch}`,
        ],
        { timeout: 8_000, env: this.runtimeEnvironment(), encoding: "utf8" },
      );
      stdout = String(result.stdout);
    } catch (error) {
      throw new Error(
        `BROKER_RECONCILIATION_QUERY_FAILED:${error instanceof Error ? error.message : String(error)}`,
      );
    }
    const ids = stdout.split(/\s+/).filter(Boolean);
    if (!ids.every((value) => /^[a-f0-9]{12,64}$/i.test(value))) {
      throw new Error("BROKER_RECONCILIATION_RESPONSE_INVALID");
    }
    return ids;
  }

  private runtimeEnvironment(): NodeJS.ProcessEnv {
    const environment: NodeJS.ProcessEnv = { NO_COLOR: "1" };
    for (const name of [
      "PATH",
      "HOME",
      "TMPDIR",
      "LANG",
      "LC_ALL",
      "DOCKER_API_VERSION",
    ] as const) {
      if (process.env[name] !== undefined) environment[name] = process.env[name];
    }
    return environment;
  }

  private assertRequest(request: BrokerRunWireRequest): void {
    validateBrokerRunRequest(this.config, request);
  }

  private lifecycleBinding(request: BrokerRunWireRequest): BrokerRunBinding | null {
    if (this.config.transitionAuthority !== "worker") return null;
    if (!request.runLeaseId || request.sessionEpoch === undefined) {
      throw new Error("BROKER_RUNTIME_BINDING_REQUIRED");
    }
    return {
      runId: request.runId,
      agentId: request.agentId,
      runLeaseId: request.runLeaseId,
      sessionEpoch: request.sessionEpoch,
    };
  }

  private bindingFromRequired(request: {
    runId: string;
    agentId: string;
    runLeaseId: string;
    sessionEpoch: number;
  }): BrokerRunBinding {
    return {
      runId: request.runId,
      agentId: request.agentId,
      runLeaseId: request.runLeaseId,
      sessionEpoch: request.sessionEpoch,
    };
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
              : request.method === "reconcile"
                ? await broker.reconcile(request.request)
                : await broker.teardown(request.request);
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
