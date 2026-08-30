import { execFile, spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, readdir, rm } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import type { AppConfig } from "./config.js";
import { DEFAULT_IGNORED_EPHEMERAL_NAMES } from "./commitgate/policy.js";
import { buildCodexArgs, parseCodexEventLine } from "./codex-runner.js";
import { RunCancelledError } from "./errors.js";
import {
  activateModelRelayCapability,
  codexConfigPath,
  codexSessionHome,
  modelCredentialForRun,
  prepareCodexSessionHome,
  redactModelCredential,
  revokeModelRelayCapability,
} from "./model-provider.js";
import type {
  AgentRunner,
  RunnerCancellation,
  RunUsage,
  RunnerRequest,
  RunnerResult,
} from "./types.js";

const execFileAsync = promisify(execFile);

/**
 * Every default root-level ignored path is redirected to a bounded tmpfs.
 * Arbitrary nested ignored-path names remain covered by the post-run streaming
 * audit; a hard aggregate quota for every /workspace write requires the P1
 * per-run volume/filesystem boundary rather than a host bind mount.
 */
export const BOUNDED_ROOT_IGNORED_PATHS = DEFAULT_IGNORED_EPHEMERAL_NAMES;

function tmpfsOwnership(containerUser: string): string {
  const [uid, gid, extra] = containerUser.split(":");
  if (
    extra !== undefined ||
    !uid ||
    !gid ||
    !/^\d+$/.test(uid) ||
    !/^\d+$/.test(gid)
  ) {
    throw new Error("CONTAINER_USER_NUMERIC_UID_GID_REQUIRED");
  }
  return `uid=${uid},gid=${gid},mode=0700`;
}

interface ActiveContainer {
  child: ChildProcess;
  containerName: string;
  cancelled: boolean;
  timedOut: boolean;
  outputExceeded: boolean;
  settled: Promise<void>;
  termination: Promise<void> | null;
  runId: string;
  runLeaseId: string;
  sessionEpoch: number;
}

interface ParsedEvents {
  messages: string[];
  threadId: string | null;
  usage: RunUsage | null;
  errors: string[];
}

export interface RuntimeTeardownAttestation {
  containerExited: boolean;
  containerRemoved: boolean;
  mountsReleased: boolean;
  relayCapabilityRequired?: boolean;
  relayCapabilityRevoked?: boolean;
  resolvedModel?: string | null;
  containerId?: string;
}

export interface RuntimeTeardownBinding {
  runId: string;
  agentId: string;
  runLeaseId: string;
  sessionEpoch: number;
}

interface StoredTeardownAttestation extends RuntimeTeardownAttestation {
  containerName: string;
  binding: RuntimeTeardownBinding;
}

export function containerName(agentId: string, instanceId = "default"): string {
  const safeInstance = instanceId.replace(/[^a-zA-Z0-9_.-]/g, "-").slice(0, 32);
  const safeAgent = agentId.replace(/[^a-zA-Z0-9_.-]/g, "-").slice(0, 48);
  return "launchpad-" + safeInstance + "-" + safeAgent;
}

export function buildContainerRunArgs(
  request: RunnerRequest,
  config: AppConfig,
  options: { cidFile?: string } = {},
): string[] {
  const name = containerName(request.agentId, config.runtimeInstanceId);
  const engineName = config.containerEngine.split(/[\\/]/).at(-1)?.toLowerCase();
  const sessionHome = codexSessionHome(
    config,
    request.agentId,
    request.sessionEpoch ?? 0,
  );
  const workerSessionRelative = path.relative(
    config.commitGateSessionVolumeRoot,
    sessionHome,
  ).split(path.sep).join("/");
  if (
    request.workspaceRef &&
    (!workerSessionRelative ||
      workerSessionRelative === ".." ||
      workerSessionRelative.startsWith("../") ||
      path.posix.isAbsolute(workerSessionRelative))
  ) {
    throw new Error("BROKER_SESSION_HOME_OUTSIDE_FIXED_VOLUME");
  }
  const ignoredBytesPerMount = Math.max(
    1,
    Math.floor(
      config.containerAgentIgnoredBytes / BOUNDED_ROOT_IGNORED_PATHS.length,
    ),
  );
  const ignoredFilesPerMount = Math.max(
    1,
    Math.floor(
      config.containerAgentIgnoredFiles / BOUNDED_ROOT_IGNORED_PATHS.length,
    ),
  );
  // Docker inherits an existing tmpfs target's mode but mounts it as root
  // unless ownership is explicit. Worker-owned ignored mountpoints are 0700,
  // so omitting uid/gid makes the non-root Agent fail before Codex can even
  // inspect `/workspace/.codex`. Bind every ephemeral tmpfs to the same
  // numeric identity that owns the candidate; the underlying empty directory
  // remains Worker-owned after teardown and therefore stays manifest-safe.
  const ignoredTmpfsOwnership = tmpfsOwnership(config.containerUser);
  return [
    "run",
    "--rm",
    "--init",
    "--name",
    name,
    ...(options.cidFile ? ["--cidfile", options.cidFile] : []),
    "--label",
    "io.commitgate.runtime=agent-runtime",
    "--label",
    "io.commitgate.agent-id=" + request.agentId,
    "--label",
    "io.commitgate.instance-id=" + config.runtimeInstanceId,
    "--label",
    "io.commitgate.run-id=" + request.runId,
    "--label",
    "io.commitgate.run-lease-id=" + (request.runLeaseId ?? request.runId),
    "--label",
    "io.commitgate.session-epoch=" + String(request.sessionEpoch ?? 0),
    ...(engineName === "podman" ? ["--userns", "keep-id"] : []),
    "--network",
    config.containerAgentNetwork,
    "--read-only",
    "--security-opt",
    "no-new-privileges",
    "--cap-drop",
    "ALL",
    "--cpus",
    String(config.containerCpuLimit),
    "--memory",
    config.containerMemoryLimit,
    "--pids-limit",
    String(config.containerPidsLimit),
    "--user",
    config.containerUser,
    "--tmpfs",
    `/scratch:rw,nosuid,nodev,size=${config.containerAgentScratchBytes},nr_inodes=${config.containerAgentScratchFiles}`,
    "--tmpfs",
    "/tmp:rw,nosuid,nodev,size=67108864,nr_inodes=2048",
    ...BOUNDED_ROOT_IGNORED_PATHS.flatMap((relative) => [
      "--tmpfs",
      `/workspace/${relative}:rw,nosuid,nodev,size=${ignoredBytesPerMount},nr_inodes=${ignoredFilesPerMount},${ignoredTmpfsOwnership}`,
    ]),
    "--env",
    "MODEL_API_KEY",
    "--env",
    "CODEX_HOME=/codex-home",
    "--env",
    "HOME=/scratch",
    "--env",
    "TMPDIR=/scratch",
    "--env",
    "NO_COLOR=1",
    "--env",
    "NPM_CONFIG_CACHE=/scratch/cache/npm",
    "--env",
    "YARN_CACHE_FOLDER=/scratch/cache/yarn",
    "--env",
    "PNPM_HOME=/scratch/cache/pnpm",
    "--env",
    "PIP_CACHE_DIR=/scratch/cache/pip",
    "--env",
    "XDG_CACHE_HOME=/scratch/cache/xdg",
    ...(config.modelAccessMode === "relay"
      ? [
          "--env",
          "HTTP_PROXY=",
          "--env",
          "HTTPS_PROXY=",
          "--env",
          "ALL_PROXY=",
          "--env",
          "NO_PROXY=*",
        ]
      : []),
    "--mount",
    request.workspaceRef
      ? [
          "type=volume",
          "src=" + config.commitGateExchangeVolume,
          "dst=/workspace",
          "volume-subpath=" + request.workspaceRef.relativeSubpath,
        ].join(",")
      : "type=bind,src=" + request.workspacePath + ",dst=/workspace",
    "--mount",
    request.workspaceRef
      ? [
          "type=volume",
          "src=" + config.commitGateSessionVolume,
          "dst=/codex-home",
          "volume-subpath=" + workerSessionRelative,
        ].join(",")
      : "type=bind,src=" + sessionHome + ",dst=/codex-home",
    "--mount",
    request.workspaceRef
      ? [
          "type=volume",
          "src=" + config.commitGateSessionVolume,
          "dst=/codex-home/config.toml",
          "readonly",
          "volume-subpath=config.toml",
        ].join(",")
      : "type=bind,src=" + codexConfigPath(config) + ",dst=/codex-home/config.toml,readonly",
    "--workdir",
    "/workspace",
    config.containerRuntimeImage,
    "codex",
    ...buildCodexArgs(request, config.codexSandboxMode, "/workspace"),
  ];
}

export function buildWorkerSessionCleanupArgs(
  request: Pick<RunnerRequest, "agentId" | "sessionEpoch" | "workspaceRef">,
  config: Pick<
    AppConfig,
    | "codexHome"
    | "commitGateSessionVolumeRoot"
    | "commitGateSessionVolume"
    | "containerRuntimeImage"
    | "containerUser"
  >,
  targetEpoch: string,
  cleanupUser = config.containerUser,
): string[] {
  if (!request.workspaceRef) throw new Error("BROKER_SESSION_CLEANUP_OPAQUE_REF_REQUIRED");
  const sessionHome = codexSessionHome(config, request.agentId, request.sessionEpoch ?? 0);
  const agentRoot = path.dirname(sessionHome);
  const relative = path.relative(config.commitGateSessionVolumeRoot, agentRoot)
    .split(path.sep)
    .join("/");
  if (!relative || relative === ".." || relative.startsWith("../") || path.posix.isAbsolute(relative)) {
    throw new Error("BROKER_SESSION_CLEANUP_OUTSIDE_FIXED_VOLUME");
  }
  if (!/^epoch-\d+$/.test(targetEpoch) || targetEpoch === path.basename(sessionHome)) {
    throw new Error("BROKER_SESSION_CLEANUP_TARGET_INVALID");
  }
  return [
    "run",
    "--rm",
    "--network",
    "none",
    "--read-only",
    "--security-opt",
    "no-new-privileges",
    "--cap-drop",
    "ALL",
    "--user",
    cleanupUser,
    "--mount",
    `type=volume,src=${config.commitGateSessionVolume},dst=/session-agent,volume-subpath=${relative}`,
    config.containerRuntimeImage,
    "rm",
    "-rf",
    "--",
    `/session-agent/${targetEpoch}`,
  ];
}

export class ContainerCodexRunner implements AgentRunner {
  private readonly active = new Map<string, ActiveContainer>();
  private readonly completedTeardowns = new Map<string, StoredTeardownAttestation>();

  constructor(private readonly config: AppConfig) {}

  async isAvailable(): Promise<boolean> {
    try {
      await execFileAsync(this.config.containerEngine, ["version"], {
        timeout: 5_000,
        env: this.childEnvironment(false),
      });
      await execFileAsync(
        this.config.containerEngine,
        ["image", "inspect", this.config.containerRuntimeImage],
        { timeout: 5_000, env: this.childEnvironment(false) },
      );
      await execFileAsync(
        this.config.containerEngine,
        [
          "run",
          "--rm",
          "--network",
          "none",
          this.config.containerRuntimeImage,
          "codex",
          "--version",
        ],
        { timeout: 10_000, env: this.childEnvironment(false) },
      );
      return true;
    } catch {
      return false;
    }
  }

  async cancel(agentId: string, cancellation?: RunnerCancellation): Promise<boolean> {
    const active = this.active.get(agentId);
    if (!active) return false;
    if (
      cancellation &&
      (active.runId !== cancellation.runId ||
        active.runLeaseId !== cancellation.runLeaseId ||
        active.sessionEpoch !== cancellation.sessionEpoch)
    ) {
      return false;
    }

    active.cancelled = true;
    await this.removeContainer(active);
    await active.settled;
    return true;
  }

  async attestCommitGateTeardown(
    runId: string,
    expectedBinding?: RuntimeTeardownBinding,
  ): Promise<RuntimeTeardownAttestation> {
    const stored = this.completedTeardowns.get(runId);
    if (!stored) {
      return {
        containerExited: false,
        containerRemoved: false,
        mountsReleased: false,
      };
    }
    if (
      expectedBinding &&
      (stored.binding.runId !== expectedBinding.runId ||
        stored.binding.agentId !== expectedBinding.agentId ||
        stored.binding.runLeaseId !== expectedBinding.runLeaseId ||
        stored.binding.sessionEpoch !== expectedBinding.sessionEpoch)
    ) {
      throw new Error("BROKER_RUNTIME_TEARDOWN_BINDING_MISMATCH");
    }
    const removed = await this.isContainerRemoved(
      stored.containerId ?? stored.containerName,
    );
    return {
      containerExited: stored.containerExited,
      containerRemoved: stored.containerRemoved && removed,
      mountsReleased: stored.mountsReleased && removed,
      ...(stored.relayCapabilityRequired !== undefined
        ? { relayCapabilityRequired: stored.relayCapabilityRequired }
        : {}),
      ...(stored.relayCapabilityRevoked !== undefined
        ? { relayCapabilityRevoked: stored.relayCapabilityRevoked }
        : {}),
      ...(stored.resolvedModel !== undefined
        ? { resolvedModel: stored.resolvedModel }
        : {}),
      ...(stored.containerId ? { containerId: stored.containerId } : {}),
    };
  }

  hasCommitGateTeardown(runId: string): boolean {
    return this.completedTeardowns.has(runId);
  }

  private removeContainer(active: ActiveContainer): Promise<void> {
    if (!active.termination) {
      active.termination = execFileAsync(
        this.config.containerEngine,
        ["rm", "--force", active.containerName],
        { timeout: 8_000, env: this.childEnvironment(false) },
      )
        .then(() => undefined)
        .catch(() => {
          active.child.kill("SIGTERM");
          const forceKill = setTimeout(() => active.child.kill("SIGKILL"), 3_000);
          forceKill.unref();
        });
    }
    return active.termination;
  }

  async run(request: RunnerRequest): Promise<RunnerResult> {
    if (this.active.has(request.agentId)) {
      throw new Error("Agent already has an active Runtime container");
    }

    await this.assertProductionRelayNetwork();

    if (request.workspaceRef) {
      const agentRoot = path.dirname(
        codexSessionHome(this.config, request.agentId, request.sessionEpoch ?? 0),
      );
      await mkdir(agentRoot, { recursive: true, mode: 0o770 });
      await chmod(agentRoot, 0o770);
      const currentEpoch = `epoch-${request.sessionEpoch ?? 0}`;
      const configuredUser = Number.parseInt(this.config.containerUser.split(":", 1)[0] ?? "", 10);
      const configuredGroup = this.config.containerUser.split(":")[1] ?? "20000";
      const brokerUser = process.getuid?.();
      if (!Number.isSafeInteger(configuredUser) || !Number.isSafeInteger(brokerUser)) {
        throw new Error("BROKER_SESSION_CLEANUP_IDENTITY_INVALID");
      }
      const cleanupUsers = [
        `${configuredUser}:${configuredGroup}`,
        `${brokerUser}:${configuredGroup}`,
      ].filter((value, index, values) => values.indexOf(value) === index);
      for (const entry of await readdir(agentRoot, { withFileTypes: true })) {
        if (!entry.isDirectory() || !/^epoch-\d+$/.test(entry.name) || entry.name === currentEpoch) {
          continue;
        }
        let lastError: unknown;
        let removed = false;
        for (const cleanupUser of cleanupUsers) {
          try {
            await execFileAsync(
              this.config.containerEngine,
              buildWorkerSessionCleanupArgs(
                request,
                this.config,
                entry.name,
                cleanupUser,
              ),
              { timeout: 15_000, env: this.childEnvironment(false) },
            );
            removed = true;
            break;
          } catch (error) {
            lastError = error;
          }
        }
        if (!removed) throw lastError ?? new Error("BROKER_SESSION_CLEANUP_FAILED");
      }
    }
    await prepareCodexSessionHome(this.config, request, false);
    const cidFile = this.runtimeCidFile(request.runId);
    await mkdir(path.dirname(cidFile), { recursive: true, mode: 0o700 });
    await rm(cidFile, { force: true });

    const modelCredential = modelCredentialForRun(this.config, request);
    if (this.config.modelAccessMode === "relay") {
      const activated = await activateModelRelayCapability(
        this.config,
        modelCredential,
      );
      if (!activated) {
        await revokeModelRelayCapability(this.config, modelCredential);
        await rm(cidFile, { force: true }).catch(() => undefined);
        throw new Error("Model Relay capability activation failed");
      }
    }
    let child: ChildProcess;
    try {
      child = spawn(
        this.config.containerEngine,
        buildContainerRunArgs(request, this.config, { cidFile }),
        {
          cwd: containerProcessCwd(request, this.config),
          env: this.childEnvironment(true, modelCredential),
          stdio: ["ignore", "pipe", "pipe"],
        },
      );
    } catch (error) {
      if (this.config.modelAccessMode === "relay") {
        await revokeModelRelayCapability(this.config, modelCredential);
      }
      await rm(cidFile, { force: true }).catch(() => undefined);
      throw error;
    }
    if (!child.stdout || !child.stderr) {
      child.kill("SIGKILL");
      if (this.config.modelAccessMode === "relay") {
        await revokeModelRelayCapability(this.config, modelCredential);
      }
      await rm(cidFile, { force: true }).catch(() => undefined);
      throw new Error("Container Runtime did not expose isolated output pipes");
    }
    const settled = new Promise<void>((resolve) => {
      child.once("close", () => resolve());
      child.once("error", () => resolve());
    });
    const active: ActiveContainer = {
      child,
      containerName: containerName(request.agentId, this.config.runtimeInstanceId),
      cancelled: false,
      timedOut: false,
      outputExceeded: false,
      settled,
      termination: null,
      runId: request.runId,
      runLeaseId: request.runLeaseId ?? request.runId,
      sessionEpoch: request.sessionEpoch ?? 0,
    };
    this.active.set(request.agentId, active);

    const parsed: ParsedEvents = {
      messages: [],
      threadId: request.threadId,
      usage: null,
      errors: [],
    };
    let stdout = "";
    let stderr = "";
    let totalBytes = 0;

    const consume = (chunk: Buffer, target: "stdout" | "stderr") => {
      totalBytes += chunk.byteLength;
      if (totalBytes > this.config.codexMaxOutputBytes) {
        active.outputExceeded = true;
        void this.removeContainer(active);
        return;
      }
      if (target === "stdout") {
        stdout += chunk.toString("utf8");
        const lines = stdout.split(/\r?\n/);
        stdout = lines.pop() ?? "";
        for (const line of lines) parseCodexEventLine(line, parsed);
      } else {
        stderr += chunk.toString("utf8");
        if (stderr.length > 16_384) stderr = stderr.slice(-16_384);
      }
    };

    child.stdout.on("data", (chunk: Buffer) => consume(chunk, "stdout"));
    child.stderr.on("data", (chunk: Buffer) => consume(chunk, "stderr"));

    const timeout = setTimeout(() => {
      active.timedOut = true;
      void this.removeContainer(active);
    }, this.config.codexTimeoutMs);
    timeout.unref();
    let containerExited = false;

    try {
      const exitCode = await new Promise<number>((resolve, reject) => {
        child.once("error", reject);
        child.once("close", (code) => {
          containerExited = true;
          resolve(code ?? 1);
        });
      });
      if (stdout.trim()) parseCodexEventLine(stdout.trim(), parsed);
      if (active.cancelled) throw new RunCancelledError();
      if (active.timedOut) {
        throw new Error("Runtime timed out after " + this.config.codexTimeoutMs + " ms");
      }
      if (active.outputExceeded) {
        throw new Error("Codex output exceeded CODEX_MAX_OUTPUT_BYTES");
      }
      if (exitCode !== 0) {
        const detail = redactModelCredential(
          parsed.errors.at(-1) ?? stderr.trim() ?? "No error detail",
          modelCredential,
        );
        throw new Error(
          this.config.containerEngine +
            " Runtime exited with code " +
            exitCode +
            ": " +
            detail,
        );
      }
      const rawOutput = parsed.messages.at(-1)?.trim();
      const output = rawOutput
        ? redactModelCredential(rawOutput, modelCredential)
        : rawOutput;
      if (!output) throw new Error("Codex completed without an agent message");
      return { output, threadId: parsed.threadId, usage: parsed.usage };
    } finally {
      clearTimeout(timeout);
      await active.termination?.catch(() => undefined);
      await active.settled;
      let containerId: string | undefined;
      try {
        containerId = (await readFile(cidFile, "utf8")).trim() || undefined;
      } catch {
        containerId = undefined;
      }
      const removed = await this.isContainerRemoved(containerId ?? active.containerName);
      const relayCapabilityRequired = this.config.modelAccessMode === "relay";
      const relayDisposition = relayCapabilityRequired
        ? await revokeModelRelayCapability(this.config, modelCredential)
        : { revoked: true, resolvedModel: null };
      this.completedTeardowns.set(request.runId, {
        containerName: active.containerName,
        binding: {
          runId: request.runId,
          agentId: request.agentId,
          runLeaseId: active.runLeaseId,
          sessionEpoch: active.sessionEpoch,
        },
        containerExited,
        containerRemoved: removed,
        mountsReleased: removed,
        relayCapabilityRequired,
        relayCapabilityRevoked: relayDisposition.revoked,
        resolvedModel: relayDisposition.resolvedModel,
        ...(containerId ? { containerId } : {}),
      });
      while (this.completedTeardowns.size > 1_024) {
        const oldest = this.completedTeardowns.keys().next().value as string | undefined;
        if (!oldest) break;
        this.completedTeardowns.delete(oldest);
      }
      await rm(cidFile, { force: true }).catch(() => undefined);
      this.active.delete(request.agentId);
    }
  }

  private runtimeCidFile(runId: string): string {
    const prefix = runId.replace(/[^a-zA-Z0-9_.-]/g, "-").slice(0, 32) || "run";
    const digest = createHash("sha256").update(runId).digest("hex").slice(0, 16);
    return path.join(this.config.codexHome, "runtime-attest", `${prefix}-${digest}.cid`);
  }

  private async isContainerRemoved(containerIdOrName: string): Promise<boolean> {
    try {
      await execFileAsync(
        this.config.containerEngine,
        ["container", "inspect", containerIdOrName],
        {
          timeout: 5_000,
          env: this.childEnvironment(false),
        },
      );
      return false;
    } catch (error) {
      const candidate = error as Error & { stderr?: string | Buffer };
      const detail =
        candidate.message +
        "\n" +
        (typeof candidate.stderr === "string"
          ? candidate.stderr
          : candidate.stderr?.toString("utf8") ?? "");
      return /no such (?:object|container)|no container with name or id|does not exist/i.test(
        detail,
      );
    }
  }

  private async assertProductionRelayNetwork(): Promise<void> {
    if (
      this.config.nodeEnv !== "production" ||
      (!this.config.commitGateEnabled && this.config.processRole !== "runtime-broker")
    ) {
      return;
    }
    if (
      this.config.modelAccessMode !== "relay" ||
      this.config.modelRuntimeApiKey.length > 0
    ) {
      throw new Error(
        "Production CommitGate Runtime may receive only a relay capability, never a direct Provider key",
      );
    }
    const result = await execFileAsync(
      this.config.containerEngine,
      ["network", "inspect", this.config.containerAgentNetwork],
      {
        timeout: 5_000,
        encoding: "utf8",
        env: this.childEnvironment(false),
      },
    );
    assertInternalAgentNetworkInspection(
      String(result.stdout),
      this.config.containerAgentNetwork,
    );
  }

  private childEnvironment(
    includeModelCredential = true,
    modelCredential = this.config.modelRuntimeApiKey,
  ): NodeJS.ProcessEnv {
    const environment: NodeJS.ProcessEnv = {
      NO_COLOR: "1",
    };
    if (includeModelCredential) {
      environment.MODEL_API_KEY = modelCredential;
    }
    for (const name of [
      "PATH",
      "HOME",
      "TMPDIR",
      "LANG",
      "LC_ALL",
      "XDG_RUNTIME_DIR",
      // Compatibility-only Docker client setting. It carries no credential or
      // host routing authority and is required when an older broker CLI talks
      // to Docker Engine 29 (minimum API 1.44).
      "DOCKER_API_VERSION",
    ] as const) {
      if (process.env[name] !== undefined) environment[name] = process.env[name];
    }
    return environment;
  }
}

export function containerProcessCwd(
  request: Pick<RunnerRequest, "workspacePath" | "workspaceRef">,
  config: Pick<AppConfig, "commitGateExchangeRoot">,
): string {
  // For an opaque Worker volume the Broker may intentionally lack traversal
  // rights on the candidate subdirectory. Docker mounts that subpath for the
  // Agent, so the Broker process must launch from the exchange root rather
  // than attempting a host-side chdir into the candidate.
  return request.workspaceRef ? config.commitGateExchangeRoot : request.workspacePath;
}

export function assertInternalAgentNetworkInspection(
  output: string,
  expectedName: string,
): void {
  let parsed: unknown;
  try {
    parsed = JSON.parse(output);
  } catch {
    throw new Error("Container network inspect returned malformed JSON");
  }
  const record = Array.isArray(parsed) ? parsed[0] : undefined;
  if (!record || typeof record !== "object") {
    throw new Error("Container network inspect returned no network");
  }
  const candidate = record as {
    Name?: unknown;
    name?: unknown;
    Internal?: unknown;
    internal?: unknown;
  };
  const name = candidate.Name ?? candidate.name;
  const internal = candidate.Internal ?? candidate.internal;
  if (name !== expectedName || internal !== true) {
    throw new Error(
      "Production CommitGate Agent network must be the configured Docker/Podman internal network",
    );
  }
}
