import { execFile, spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import {
  assertTrustedCheckBundleDescriptor,
  describeTrustedCheckBundle,
  TrustedCheckBundleStore,
} from "./trusted-check-bundle.js";
import type {
  CheckResult,
  RequiredCheckPolicy,
  VerifierExecutionEnvironment,
  VerifierInput,
  VerifierRunner,
} from "./types.js";

const execFileAsync = promisify(execFile);
const DEFAULT_SCRATCH_BYTES = 64 * 1024 * 1024;
const DEFAULT_SCRATCH_FILES = 4_096;

export interface DockerVerifierConfig {
  engine: string;
  image: string;
  cpuLimit: number;
  memoryLimit: string;
  pidsLimit: number;
  user?: string;
  instanceId?: string;
  scratchBytes?: number;
  scratchFiles?: number;
  trustedChecksPath?: string;
  runTimeoutMs?: number;
  maxOutputBytes?: number;
  sourceRevision?: string;
  trustedCheckStorePath?: string;
  proposalVolume?: string;
  trustedChecksVolume?: string;
  trustedChecksVolumeRoot?: string;
}

interface ImageIdentity {
  imageId: string;
  imageDigest: string;
}

interface VerifierRunBinding {
  identity: ImageIdentity;
  checkBundleHash: string;
  checkBundlePath: string;
  state: "PENDING_RUN" | "EXECUTED";
  createdAt: number;
}

interface DockerVerifierDependencies {
  inspectImage?: (engine: string, image: string) => Promise<ImageIdentity>;
  spawnProcess?: typeof spawn;
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function safeName(value: string, max: number): string {
  return value.replace(/[^a-zA-Z0-9_.-]/g, "-").slice(0, max);
}

function sortStrings(values: string[]): string[] {
  return values.sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
}

export function verifierContainerName(
  agentId: string,
  runId: string,
  checkId: string,
  instanceId = "default",
): string {
  return [
    "commitgate-verify",
    safeName(instanceId, 16),
    safeName(agentId, 24),
    safeName(runId, 24),
    safeName(checkId, 20),
  ].join("-");
}

export function verifierConfigHash(config: DockerVerifierConfig): string {
  return sha256(
    JSON.stringify({
      schemaVersion: 1,
      engine: path.basename(config.engine),
      imageReference: config.image,
      network: "none",
      rootFilesystem: "readonly",
      proposalMount: "/proposal:readonly",
      trustedChecksMount: "content-addressed-sealed:/checks:readonly",
      scratchMount: "/scratch:tmpfs",
      environment: "env-i",
      capabilities: "drop-all",
      noNewPrivileges: true,
      user: config.user ?? null,
      scratchBytes: config.scratchBytes ?? DEFAULT_SCRATCH_BYTES,
      scratchFiles: config.scratchFiles ?? DEFAULT_SCRATCH_FILES,
      runTimeoutMs: config.runTimeoutMs ?? null,
      maxOutputBytes: config.maxOutputBytes ?? null,
    }),
  );
}

export function verifierResourcePolicyHash(config: DockerVerifierConfig): string {
  return sha256(
    JSON.stringify({
      schemaVersion: 1,
      cpuLimit: config.cpuLimit,
      memoryLimit: config.memoryLimit,
      pidsLimit: config.pidsLimit,
      scratchBytes: config.scratchBytes ?? DEFAULT_SCRATCH_BYTES,
      scratchFiles: config.scratchFiles ?? DEFAULT_SCRATCH_FILES,
      runTimeoutMs: config.runTimeoutMs ?? null,
      maxOutputBytes: config.maxOutputBytes ?? null,
    }),
  );
}

export async function hashTrustedCheckBundle(root: string): Promise<string> {
  const descriptor = await describeTrustedCheckBundle(path.resolve(root));
  assertTrustedCheckBundleDescriptor(descriptor);
  return descriptor.hash;
}

async function inspectImage(engine: string, image: string): Promise<ImageIdentity> {
  const result = await execFileAsync(engine, ["image", "inspect", image], {
    timeout: 8_000,
    encoding: "utf8",
    env: verifierHostEnvironment(),
  });
  const parsed = JSON.parse(String(result.stdout)) as Array<{
    Id?: unknown;
    RepoDigests?: unknown;
  }>;
  const record = parsed[0];
  if (!record || typeof record.Id !== "string" || record.Id.length === 0) {
    throw new Error("Container image inspect returned no image ID");
  }
  const repoDigests = Array.isArray(record.RepoDigests)
    ? record.RepoDigests.filter((value): value is string => typeof value === "string")
    : [];
  const repoDigest = sortStrings(repoDigests)[0];
  return {
    imageId: record.Id,
    imageDigest: repoDigest?.split("@").at(-1) ?? record.Id,
  };
}

function verifierHostEnvironment(): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {};
  for (const name of [
    "PATH",
    "HOME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "DOCKER_HOST",
    "CONTAINER_HOST",
    "XDG_RUNTIME_DIR",
  ] as const) {
    if (process.env[name] !== undefined) environment[name] = process.env[name];
  }
  return environment;
}

export function buildVerifierContainerArgs(
  input: VerifierInput,
  check: RequiredCheckPolicy,
  config: DockerVerifierConfig,
): string[] {
  assertTrustedCheckSpec(check);
  const name = verifierContainerName(
    input.agentId,
    input.runId,
    check.id,
    config.instanceId,
  );
  const engineName = config.engine.split(/[\\/]/).at(-1)?.toLowerCase();
  const requestedScratch = check.scratchBytes;
  const mountedEntrypoint = "/checks/" + check.entrypoint;
  const command =
    check.runner === "node"
      ? ["node", mountedEntrypoint, ...check.args]
      : check.runner === "python"
        ? ["python3", mountedEntrypoint, ...check.args]
        : [mountedEntrypoint, ...check.args];
  const proposalMount = input.workspaceRef && config.proposalVolume
    ? [
        "type=volume",
        "src=" + config.proposalVolume,
        "dst=/proposal",
        "readonly",
        "volume-subpath=" + input.workspaceRef.relativeSubpath,
      ].join(",")
    : "type=bind,src=" + input.verifyPath + ",dst=/proposal,readonly";
  let trustedChecksMount = "type=bind,src=" + input.trustedChecksPath + ",dst=/checks,readonly";
  if (config.trustedChecksVolume && config.trustedChecksVolumeRoot) {
    const relative = path.relative(
      path.resolve(config.trustedChecksVolumeRoot),
      path.resolve(input.trustedChecksPath),
    );
    if (!relative || relative === ".." || relative.startsWith(".." + path.sep) || path.isAbsolute(relative)) {
      throw new Error("TRUSTED_CHECK_BUNDLE_OUTSIDE_VOLUME");
    }
    trustedChecksMount = [
      "type=volume",
      "src=" + config.trustedChecksVolume,
      "dst=/checks",
      "readonly",
      "volume-subpath=" + relative.split(path.sep).join("/"),
    ].join(",");
  }
  return [
    "run",
    "--rm",
    "--init",
    "--name",
    name,
    "--label",
    "io.commitgate.commitgate=verifier",
    ...(engineName === "podman" ? ["--userns", "keep-id"] : []),
    "--network",
    "none",
    "--read-only",
    "--security-opt",
    "no-new-privileges",
    "--cap-drop",
    "ALL",
    "--cpus",
    String(config.cpuLimit),
    "--memory",
    config.memoryLimit,
    "--pids-limit",
    String(config.pidsLimit),
    ...(config.user ? ["--user", config.user] : []),
    "--tmpfs",
    "/tmp:rw,noexec,nosuid,nodev,size=16m,nr_inodes=1024",
    "--tmpfs",
    `/scratch:rw,nosuid,nodev,size=${requestedScratch},nr_inodes=${config.scratchFiles ?? DEFAULT_SCRATCH_FILES}`,
    "--mount",
    proposalMount,
    "--mount",
    trustedChecksMount,
    "--workdir",
    "/proposal",
    "--entrypoint",
    "/usr/bin/env",
    config.image,
    "-i",
    "HOME=/scratch",
    "TMPDIR=/scratch",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "NO_COLOR=1",
    ...command,
  ];
}

export function assertTrustedCheckSpec(check: RequiredCheckPolicy): void {
  if (!["node", "python", "binary"].includes(check.runner)) {
    throw new Error(`Trusted check ${check.id} has an unsupported runner`);
  }
  const normalized = path.posix.normalize(check.entrypoint);
  if (
    normalized !== check.entrypoint ||
    normalized === "." ||
    path.posix.isAbsolute(normalized) ||
    normalized === ".." ||
    normalized.startsWith("../") ||
    normalized.includes("\0")
  ) {
    throw new Error(`Trusted check ${check.id} has an invalid entrypoint`);
  }
  if (!Number.isSafeInteger(check.timeoutMs) || check.timeoutMs <= 0) {
    throw new Error(`Trusted check ${check.id} has an invalid timeout`);
  }
  if (!Number.isSafeInteger(check.scratchBytes) || check.scratchBytes <= 0) {
    throw new Error(`Trusted check ${check.id} has an invalid scratch budget`);
  }
}

export class VerifierRunBudget {
  private readonly startedAt: number;
  private consumedOutputBytes = 0;
  private outputLimitExceeded = false;

  constructor(
    private readonly timeoutMs: number,
    private readonly maxOutputBytes: number,
    startedAt = Date.now(),
  ) {
    this.startedAt = startedAt;
  }

  remainingTimeMs(now = Date.now()): number {
    return Math.max(0, this.timeoutMs - (now - this.startedAt));
  }

  remainingOutputBytes(): number {
    return Math.max(0, this.maxOutputBytes - this.consumedOutputBytes);
  }

  consumeOutput(bytes: number): number {
    const accepted = Math.min(bytes, this.remainingOutputBytes());
    if (bytes > accepted) this.outputLimitExceeded = true;
    this.consumedOutputBytes += accepted;
    return accepted;
  }

  outputExceeded(): boolean {
    return this.outputLimitExceeded;
  }
}

export class DockerVerifierRunner implements VerifierRunner {
  private readonly inspectImageFn: (
    engine: string,
    image: string,
  ) => Promise<ImageIdentity>;
  private readonly spawnProcess: typeof spawn;
  private readonly bindings = new Map<string, VerifierRunBinding>();
  private readonly bundleStore: TrustedCheckBundleStore | null;

  constructor(
    private readonly config: DockerVerifierConfig,
    dependencies: DockerVerifierDependencies = {},
  ) {
    this.inspectImageFn = dependencies.inspectImage ?? inspectImage;
    this.spawnProcess = dependencies.spawnProcess ?? spawn;
    this.bundleStore = config.trustedChecksPath
      ? new TrustedCheckBundleStore(
          config.trustedChecksPath,
          config.trustedCheckStorePath ??
            path.join(
              path.dirname(path.resolve(config.trustedChecksPath)),
              ".commitgate-trusted-check-bundles",
            ),
        )
      : null;
  }

  async describeExecutionEnvironment(
    runId?: string,
  ): Promise<VerifierExecutionEnvironment> {
    if (!this.config.trustedChecksPath) {
      throw new Error("Verifier trustedChecksPath is required for evidence binding");
    }
    this.pruneBindings();
    const existing = runId ? this.bindings.get(runId) : undefined;
    if (existing) {
      return this.executionEnvironment(existing.identity, existing.checkBundleHash);
    }
    if (!this.bundleStore) {
      throw new Error("Verifier trusted check bundle store is unavailable");
    }
    const [identity, checkBundle] = await Promise.all([
      this.inspectImageFn(this.config.engine, this.config.image),
      this.bundleStore.seal(),
    ]);
    if (runId) {
      this.bindings.set(runId, {
        identity,
        checkBundleHash: checkBundle.hash,
        checkBundlePath: checkBundle.payloadPath,
        state: "PENDING_RUN",
        createdAt: Date.now(),
      });
    }
    return this.executionEnvironment(identity, checkBundle.hash);
  }

  releaseExecutionEnvironment(runId: string): void {
    this.bindings.delete(runId);
  }

  private executionEnvironment(
    identity: ImageIdentity,
    checkBundleHash: string,
  ): VerifierExecutionEnvironment {
    return {
      imageReference: this.config.image,
      imageId: identity.imageId,
      imageDigest: identity.imageDigest,
      configHash: verifierConfigHash(this.config),
      checkBundleHash,
      resourcePolicyHash: verifierResourcePolicyHash(this.config),
      sourceRevision:
        this.config.sourceRevision ?? process.env.GIT_REVISION ?? "unverified",
    };
  }

  private pruneBindings(): void {
    const cutoff = Date.now() - 60 * 60 * 1_000;
    for (const [runId, binding] of this.bindings) {
      if (binding.createdAt < cutoff) this.bindings.delete(runId);
    }
    while (this.bindings.size > 1_024) {
      const oldest = this.bindings.keys().next().value as string | undefined;
      if (!oldest) break;
      this.bindings.delete(oldest);
    }
  }

  async run(input: VerifierInput): Promise<CheckResult[]> {
    if (input.checks.length === 0) {
      throw new Error("Protected CommitGate verification requires at least one trusted check");
    }
    if (
      this.config.trustedChecksPath &&
      path.resolve(input.trustedChecksPath) !== path.resolve(this.config.trustedChecksPath)
    ) {
      throw new Error("Verifier input attempted to replace the trusted check bundle");
    }
    input.checks.forEach(assertTrustedCheckSpec);
    let binding = this.bindings.get(input.runId);
    if (!binding) {
      if (!this.bundleStore) {
        throw new Error("Verifier trusted check bundle store is unavailable");
      }
      const [identity, checkBundle] = await Promise.all([
        this.inspectImageFn(this.config.engine, this.config.image),
        this.bundleStore.seal(),
      ]);
      binding = {
        identity,
        checkBundleHash: checkBundle.hash,
        checkBundlePath: checkBundle.payloadPath,
        state: "PENDING_RUN",
        createdAt: Date.now(),
      };
      this.bindings.set(input.runId, binding);
    }
    if (
      input.checkBundleHash &&
      input.checkBundleHash !== binding.checkBundleHash
    ) {
      binding.state = "EXECUTED";
      throw new Error("Verifier input check bundle hash does not match the sealed bundle");
    }
    const trustedRoot = binding.checkBundlePath;
    for (const check of input.checks) {
      const entrypoint = path.join(trustedRoot, ...check.entrypoint.split("/"));
      const stats = await lstat(entrypoint);
      if (!stats.isFile() || stats.isSymbolicLink() || stats.nlink !== 1) {
        throw new Error(`Trusted check ${check.id} entrypoint is not a regular bundle file`);
      }
    }
    const currentBundleHash = await hashTrustedCheckBundle(trustedRoot);
    if (currentBundleHash !== binding.checkBundleHash) {
      binding.state = "EXECUTED";
      throw new Error("Trusted check bundle changed after evidence binding");
    }

    const budget = new VerifierRunBudget(input.timeoutMs, input.maxOutputBytes);
    const results: CheckResult[] = [];
    const pinnedConfig = { ...this.config, image: binding.identity.imageId };
    const pinnedInput = { ...input, trustedChecksPath: trustedRoot };
    try {
      for (const check of input.checks) {
        if (input.signal?.aborted) {
          throw input.signal.reason ?? new Error("Verification aborted");
        }
        if (budget.remainingTimeMs() === 0 || budget.remainingOutputBytes() === 0) {
          results.push({
            id: check.id,
            status: "ERROR",
            exitCode: null,
            durationMs: 0,
            output: "[VERIFIER_RUN_BUDGET_EXHAUSTED]",
            timedOut: budget.remainingTimeMs() === 0,
          });
          continue;
        }
        results.push(await this.runOne(pinnedInput, check, budget, pinnedConfig));
      }
      if ((await hashTrustedCheckBundle(trustedRoot)) !== binding.checkBundleHash) {
        throw new Error("Trusted check bundle changed during verification");
      }
      return results;
    } finally {
      const current = this.bindings.get(input.runId);
      if (current) current.state = "EXECUTED";
    }
  }

  private async runOne(
    input: VerifierInput,
    check: RequiredCheckPolicy,
    budget: VerifierRunBudget,
    executionConfig: DockerVerifierConfig,
  ): Promise<CheckResult> {
    const started = Date.now();
    const name = verifierContainerName(
      input.agentId,
      input.runId,
      check.id,
      this.config.instanceId,
    );
    const child = this.spawnProcess(
      this.config.engine,
      buildVerifierContainerArgs(input, check, executionConfig),
      {
        env: verifierHostEnvironment(),
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    let output = "";
    let timedOut = false;
    let outputExceeded = false;
    const consume = (chunk: Buffer) => {
      const accepted = budget.consumeOutput(chunk.byteLength);
      if (accepted > 0) output += chunk.subarray(0, accepted).toString("utf8");
      if (budget.outputExceeded()) {
        outputExceeded = true;
        void this.forceRemove(name, child);
      }
    };
    child.stdout.on("data", consume);
    child.stderr.on("data", consume);

    const timeoutMs = Math.max(
      1,
      Math.min(check.timeoutMs, input.timeoutMs, budget.remainingTimeMs()),
    );
    const timer = setTimeout(() => {
      timedOut = true;
      void this.forceRemove(name, child);
    }, timeoutMs);
    timer.unref();
    const abort = () => void this.forceRemove(name, child);
    input.signal?.addEventListener("abort", abort, { once: true });
    try {
      const exitCode = await new Promise<number | null>((resolve, reject) => {
        child.once("error", reject);
        child.once("close", (code) => resolve(code));
      });
      if (input.signal?.aborted) {
        throw input.signal.reason ?? new Error("Verification aborted");
      }
      const status =
        timedOut || outputExceeded || exitCode === null
          ? "ERROR"
          : exitCode === 0
            ? "PASS"
            : "FAIL";
      const suffix = timedOut
        ? "\n[VERIFIER_RUN_TIMEOUT]"
        : outputExceeded
          ? "\n[VERIFIER_RUN_OUTPUT_LIMIT_EXCEEDED]"
          : "";
      return {
        id: check.id,
        status,
        exitCode,
        durationMs: Date.now() - started,
        output: output + suffix,
        timedOut,
      };
    } catch (error) {
      if (input.signal?.aborted) throw error;
      return {
        id: check.id,
        status: "ERROR",
        exitCode: null,
        durationMs: Date.now() - started,
        output: error instanceof Error ? error.message : "Verifier process failed",
        timedOut,
      };
    } finally {
      clearTimeout(timer);
      input.signal?.removeEventListener("abort", abort);
    }
  }

  private async forceRemove(name: string, child?: ChildProcess): Promise<void> {
    child?.kill("SIGTERM");
    try {
      await execFileAsync(this.config.engine, ["rm", "--force", name], {
        timeout: 8_000,
        env: verifierHostEnvironment(),
      });
    } catch {
      child?.kill("SIGKILL");
      // The container may already have exited and been removed.
    }
  }
}

export class FunctionVerifierRunner implements VerifierRunner {
  constructor(
    private readonly callback: (
      input: VerifierInput,
    ) => Promise<CheckResult[]> | CheckResult[],
  ) {}

  async run(input: VerifierInput): Promise<CheckResult[]> {
    return await this.callback(input);
  }
}
