import { execFile, spawn, type ChildProcess } from "node:child_process";
import { mkdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  buildVerifierContainerArgs,
  DockerVerifierRunner,
  verifierContainerName,
} from "../apps/server/src/commitgate/verifier-runner.js";
import { computeCheckSpecHash } from "../apps/server/src/commitgate/trusted-check-bundle.js";
import type { VerifierInput } from "../apps/server/src/commitgate/types.js";
import { loadConfig, writeCodexConfig } from "../apps/server/src/config.js";
import { containerName } from "../apps/server/src/container-codex-runner.js";
import { RuntimeBrokerRunner } from "../apps/server/src/runtime-broker/client.js";
import {
  RuntimeBroker,
  startRuntimeBrokerRpc,
} from "../apps/server/src/runtime-broker/server.js";
import type { RunnerCancellation, RunnerRequest } from "../apps/server/src/types.js";
import {
  buildWorkerManifest,
  makeTreeWritable,
} from "../apps/server/src/transition-worker/filesystem.js";
import { evidenceProvenance, executionIdentity } from "./evidence-utils.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const evidenceDir = path.join(root, "eval", "evidence");
const tempRoot = path.join(root, "eval", `.container-${process.pid}`);
const candidate = path.join(tempRoot, "candidate");
const checks = path.join(tempRoot, "checks");
const reportPath = path.join(root, "eval", "container-report.json");
const engine = process.env.CONTAINER_ENGINE || "docker";
const image = process.env.CONTAINER_RUNTIME_IMAGE || "volc-agent-runtime:local";
const cancellationImage = `commitgate-container-cancel-eval:${process.pid}`;
const cancellationFixtureRoot = path.join(root, "eval", "fixtures", "container-cancel");
const execFileAsync = promisify(execFile);
const user =
  typeof process.getuid === "function" && typeof process.getgid === "function"
    ? `${process.getuid()}:${process.getgid()}`
    : undefined;
await mkdir(candidate, { recursive: true });
await mkdir(checks, { recursive: true });
await mkdir(evidenceDir, { recursive: true });

type CancellationObservation = {
  status: "verified" | "failed" | "unverified";
  runId: string;
  agentId: string;
  containerName: string;
  containerId: string | null;
  containerObservedRunning: boolean;
  wrongBindingRejected: boolean;
  cancelAccepted: boolean;
  promiseCancelled: boolean;
  cancellationErrorName: string | null;
  forceRemoved: boolean;
  teardown: {
    containerExited: boolean;
    containerRemoved: boolean;
    mountsReleased: boolean;
    source: "runtime-attestation" | "container-inspect";
  };
  error: string | null;
};

type ProcessKillObservation = {
  status: "verified" | "failed" | "unverified";
  workload: "agent" | "verifier";
  runId: string;
  agentId: string;
  containerName: string;
  containerId: string | null;
  containerObservedRunning: boolean;
  killSignal: "KILL";
  killAccepted: boolean;
  promiseRejected: boolean;
  errorName: string | null;
  errorCode: string | null;
  errorMessage: string | null;
  checkStatus: "PASS" | "FAIL" | "ERROR" | "SKIPPED" | null;
  checkExitCode: number | null;
  passObserved: boolean;
  failClosed: boolean;
  forceRemoved: boolean;
  teardown: {
    containerExited: boolean;
    containerRemoved: boolean;
    mountsReleased: boolean;
    source: "runtime-attestation";
  };
  error: string | null;
};

type BrokerRestartReconciliationObservation = {
  status: "verified" | "failed" | "unverified";
  point: "RUNTIME_BROKER_PROCESS_SIGKILL_ORPHAN_RECONCILIATION";
  workload: "agent";
  runId: string;
  agentId: string;
  runLeaseId: string;
  sessionEpoch: number;
  scope: "ALL";
  containerName: string;
  containerId: string | null;
  broker: {
    launchMode: "separate-node-process";
    firstPid: number | null;
    firstReady: boolean;
    killSignal: "SIGKILL";
    killAccepted: boolean;
    firstExitCode: number | null;
    firstExitSignal: NodeJS.Signals | null;
    restartedPid: number | null;
    restartedReady: boolean;
  };
  exactBinding: {
    labels: Record<string, string>;
    queryArguments: string[];
    matchingContainerIdsBeforeReconcile: string[];
    wrongLeaseQueryContainerIds: string[];
    exactLabelsObserved: boolean;
  };
  orphan: {
    runningBeforeBrokerKill: boolean;
    runningAfterBrokerSigkill: boolean;
    sameContainerAfterBrokerSigkill: boolean;
  };
  reconciliation: {
    invokedThroughRestartedBrokerRpc: boolean;
    forceRemovedByReconcile: boolean;
    negativeQueryArguments: string[];
    remainingContainerIds: string[];
    containerAbsentByInspect: boolean;
    attestation: {
      schemaVersion: number;
      containerExited: boolean;
      containerRemoved: boolean;
      mountsReleased: boolean;
      source: string;
      runId: string;
      agentId: string;
      runLeaseId: string;
      sessionEpoch: number;
      scope: string;
    } | null;
  };
  error: string | null;
  brokerLogTail: string;
};

function isContainerEnvironmentUnavailable(reason: string): boolean {
  return /permission denied|cannot connect|is the docker daemon running|not found|no such image|ENOENT/i
    .test(reason);
}

async function inspectContainer(name: string): Promise<{ id: string; running: boolean } | null> {
  try {
    const result = await execFileAsync(
      engine,
      ["container", "inspect", name, "--format", "{{.Id}}|{{.State.Running}}"],
      { timeout: 5_000 },
    );
    const [id, running] = result.stdout.trim().split("|");
    return id ? { id, running: running === "true" } : null;
  } catch {
    return null;
  }
}

async function waitForContainer(
  name: string,
  expectedPresent: boolean,
  timeoutMs = 15_000,
): Promise<{ id: string; running: boolean } | null> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const current = await inspectContainer(name);
    if (expectedPresent ? current?.running === true : current === null) return current;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  return inspectContainer(name);
}

async function cancellationOutcome(promise: Promise<unknown>): Promise<{
  cancelled: boolean;
  errorName: string | null;
}> {
  try {
    await promise;
    return { cancelled: false, errorName: null };
  } catch (reason) {
    const errorName = reason instanceof Error ? reason.name : null;
    return { cancelled: errorName === "RunCancelledError", errorName };
  }
}

function cancellationStatus(
  observation: Omit<CancellationObservation, "status">,
): CancellationObservation["status"] {
  return observation.error === null &&
    observation.containerObservedRunning &&
    observation.wrongBindingRejected &&
    observation.cancelAccepted &&
    observation.promiseCancelled &&
    observation.forceRemoved &&
    observation.teardown.containerExited &&
    observation.teardown.containerRemoved &&
    observation.teardown.mountsReleased
    ? "verified"
    : "failed";
}

function processKillStatus(
  observation: Omit<ProcessKillObservation, "status">,
): ProcessKillObservation["status"] {
  const workloadDisposition = observation.workload === "agent"
    ? observation.promiseRejected &&
      observation.errorName !== "RunCancelledError" &&
      observation.errorCode === "BROKER_RUNTIME_ERROR"
    : observation.checkStatus === "ERROR" && observation.checkExitCode === 137;
  return observation.error === null &&
    observation.containerObservedRunning &&
    observation.killAccepted &&
    observation.failClosed &&
    !observation.passObserved &&
    workloadDisposition &&
    observation.forceRemoved &&
    observation.teardown.containerExited &&
    observation.teardown.containerRemoved &&
    observation.teardown.mountsReleased
    ? "verified"
    : "failed";
}

async function killContainer(name: string): Promise<boolean> {
  await execFileAsync(engine, ["kill", "--signal", "KILL", name], {
    timeout: 10_000,
  });
  return true;
}

const pause = (milliseconds: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, milliseconds));

async function waitForChildExit(
  child: ChildProcess,
  timeoutMs = 10_000,
): Promise<{ exitCode: number | null; signal: NodeJS.Signals | null }> {
  if (child.exitCode !== null || child.signalCode !== null) {
    return { exitCode: child.exitCode, signal: child.signalCode };
  }
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error(`Broker process ${child.pid ?? "unknown"} did not exit`));
    }, timeoutMs);
    const onExit = (exitCode: number | null, signal: NodeJS.Signals | null) => {
      cleanup();
      resolve({ exitCode, signal });
    };
    const onError = (reason: Error) => {
      cleanup();
      reject(reason);
    };
    const cleanup = () => {
      clearTimeout(timeout);
      child.off("exit", onExit);
      child.off("error", onError);
    };
    child.once("exit", onExit);
    child.once("error", onError);
  });
}

async function waitForBrokerReady(
  child: ChildProcess,
  socketPath: string,
  timeoutMs = 30_000,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  const client = new RuntimeBrokerRunner(socketPath, 120_000);
  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error(
        `Runtime Broker exited before readiness (code=${child.exitCode}, signal=${child.signalCode})`,
      );
    }
    const socket = await stat(socketPath).catch(() => null);
    if (socket?.isSocket() && await client.isAvailable()) return true;
    await pause(100);
  }
  throw new Error("Runtime Broker did not become ready before timeout");
}

function exactBrokerOwnershipLabels(input: {
  instanceId: string;
  agentId: string;
  runId: string;
  runLeaseId: string;
  sessionEpoch: number;
}): Record<string, string> {
  return {
    "io.commitgate.runtime": "agent-runtime",
    "io.commitgate.instance-id": input.instanceId,
    "io.commitgate.agent-id": input.agentId,
    "io.commitgate.run-id": input.runId,
    "io.commitgate.run-lease-id": input.runLeaseId,
    "io.commitgate.session-epoch": String(input.sessionEpoch),
  };
}

async function queryContainersByLabels(
  labels: Record<string, string>,
): Promise<{ arguments: string[]; ids: string[] }> {
  const args = [
    "container",
    "ls",
    "--all",
    "--quiet",
    ...Object.entries(labels).flatMap(([name, value]) => [
      "--filter",
      `label=${name}=${value}`,
    ]),
  ];
  const result = await execFileAsync(engine, args, { timeout: 8_000 });
  const ids = result.stdout.trim().split(/\s+/).filter(Boolean);
  if (!ids.every((value) => /^[a-f0-9]{12,64}$/i.test(value))) {
    throw new Error("Evaluator received an invalid Docker container ID");
  }
  return { arguments: args, ids };
}

async function inspectContainerLabels(containerId: string): Promise<Record<string, string>> {
  const result = await execFileAsync(
    engine,
    ["container", "inspect", containerId, "--format", "{{json .Config.Labels}}"],
    { timeout: 8_000 },
  );
  const parsed = JSON.parse(result.stdout.trim()) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Evaluator received invalid Docker labels");
  }
  return Object.fromEntries(
    Object.entries(parsed).filter((entry): entry is [string, string] =>
      typeof entry[1] === "string"
    ),
  );
}

function brokerRestartStatus(
  observation: Omit<BrokerRestartReconciliationObservation, "status">,
): BrokerRestartReconciliationObservation["status"] {
  const attestation = observation.reconciliation.attestation;
  const queriedContainerMatches =
    observation.containerId !== null &&
    observation.exactBinding.matchingContainerIdsBeforeReconcile.some(
      (value) => observation.containerId === value || observation.containerId?.startsWith(value),
    );
  return observation.error === null &&
    observation.broker.firstReady &&
    observation.broker.killAccepted &&
    observation.broker.firstExitCode === null &&
    observation.broker.firstExitSignal === "SIGKILL" &&
    observation.broker.restartedReady &&
    observation.orphan.runningBeforeBrokerKill &&
    observation.orphan.runningAfterBrokerSigkill &&
    observation.orphan.sameContainerAfterBrokerSigkill &&
    observation.exactBinding.exactLabelsObserved &&
    observation.exactBinding.matchingContainerIdsBeforeReconcile.length === 1 &&
    queriedContainerMatches &&
    observation.exactBinding.wrongLeaseQueryContainerIds.length === 0 &&
    observation.reconciliation.invokedThroughRestartedBrokerRpc &&
    observation.reconciliation.forceRemovedByReconcile &&
    observation.reconciliation.remainingContainerIds.length === 0 &&
    observation.reconciliation.containerAbsentByInspect &&
    attestation?.schemaVersion === 1 &&
    attestation.runId === observation.runId &&
    attestation.agentId === observation.agentId &&
    attestation.runLeaseId === observation.runLeaseId &&
    attestation.sessionEpoch === observation.sessionEpoch &&
    attestation.scope === observation.scope &&
    attestation.containerExited === true &&
    attestation.containerRemoved === true &&
    attestation.mountsReleased === true &&
    attestation.source === "broker-reconciliation"
    ? "verified"
    : "failed";
}

async function evaluateBrokerProcessRestart(input: {
  cancellationRoot: string;
  controlRoot: string;
  exchangeRoot: string;
  codexHome: string;
  trustedChecks: string;
  instanceId: string;
}): Promise<BrokerRestartReconciliationObservation> {
  const point = "RUNTIME_BROKER_PROCESS_SIGKILL_ORPHAN_RECONCILIATION" as const;
  const agentId = "restart-orphan-agent";
  const runId = "restart-orphan-run";
  const runLeaseId = "restart-orphan-lease";
  const sessionEpoch = 11;
  const scope = "ALL" as const;
  const brokerSocket = path.join(tmpdir(), `cg-broker-restart-${process.pid}.sock`);
  const candidatePath = path.join(input.controlRoot, agentId, "candidates", runId);
  const name = containerName(agentId, input.instanceId);
  const labels = exactBrokerOwnershipLabels({
    instanceId: input.instanceId,
    agentId,
    runId,
    runLeaseId,
    sessionEpoch,
  });
  const emptyQuery = await queryContainersByLabels(labels).catch(() => ({
    arguments: ["container", "ls", "--all", "--quiet"],
    ids: [] as string[],
  }));
  let firstBroker: ChildProcess | null = null;
  let restartedBroker: ChildProcess | null = null;
  let logTail = "";
  let firstReady = false;
  let firstPid: number | null = null;
  let firstExitCode: number | null = null;
  let firstExitSignal: NodeJS.Signals | null = null;
  let brokerKillAccepted = false;
  let restartedPid: number | null = null;
  let restartedReady = false;
  let containerId: string | null = null;
  let runningBeforeBrokerKill = false;
  let runningAfterBrokerSigkill = false;
  let sameContainerAfterBrokerSigkill = false;
  let queryArguments = emptyQuery.arguments;
  let matchingContainerIdsBeforeReconcile: string[] = [];
  let wrongLeaseQueryContainerIds: string[] = [];
  let exactLabelsObserved = false;
  let invokedThroughRestartedBrokerRpc = false;
  let forceRemovedByReconcile = false;
  let negativeQueryArguments = emptyQuery.arguments;
  let remainingContainerIds: string[] = [];
  let containerAbsentByInspect = false;
  let attestation: BrokerRestartReconciliationObservation["reconciliation"]["attestation"] = null;
  let error: string | null = null;

  const appendLog = (chunk: Buffer | string) => {
    logTail = (logTail + chunk.toString()).slice(-8_192);
  };
  const environment: NodeJS.ProcessEnv = { ...process.env };
  for (const name of [
    "MODEL_API_KEY",
    "ARK_API_KEY",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
    "MODEL_RELAY_TOKEN",
  ]) delete environment[name];
  Object.assign(environment, {
    NODE_ENV: "test",
    APP_DATA_DIR: path.join(input.cancellationRoot, "broker-process-data"),
    AGENT_WORKSPACE_ROOT: input.controlRoot,
    CODEX_HOME: input.codexHome,
    RUNTIME_BROKER_SOCKET: brokerSocket,
    CONTAINER_ENGINE: engine,
    CONTAINER_RUNTIME_IMAGE: cancellationImage,
    CONTAINER_AGENT_NETWORK: "none",
    CONTAINER_CPU_LIMIT: "1",
    CONTAINER_MEMORY_LIMIT: "256m",
    CONTAINER_PIDS_LIMIT: "64",
    CODEX_TIMEOUT_MS: "120000",
    CODEX_MAX_OUTPUT_BYTES: "65536",
    COMMITGATE_CONTROL_ROOT: input.controlRoot,
    COMMITGATE_EXCHANGE_ROOT: input.exchangeRoot,
    COMMITGATE_TRUSTED_CHECKS_DIR: input.trustedChecks,
    RUNTIME_INSTANCE_ID: input.instanceId,
    MODEL_ACCESS_MODE: "direct",
    ...(user ? { CONTAINER_USER: user } : {}),
  });
  const tsxCli = path.join(root, "node_modules", "tsx", "dist", "cli.mjs");
  const spawnBroker = (): ChildProcess => {
    const child = spawn(
      process.execPath,
      [tsxCli, "apps/server/src/runtime-broker/main.ts"],
      { cwd: root, env: environment, stdio: ["ignore", "pipe", "pipe"] },
    );
    child.stdout?.on("data", appendLog);
    child.stderr?.on("data", appendLog);
    return child;
  };

  try {
    await mkdir(candidatePath, { recursive: true });
    await writeFile(path.join(candidatePath, "value.txt"), "broker restart fixture\n", "utf8");
    await rm(brokerSocket, { force: true });
    firstBroker = spawnBroker();
    firstPid = firstBroker.pid ?? null;
    firstReady = await waitForBrokerReady(firstBroker, brokerSocket);
    const firstClient = new RuntimeBrokerRunner(brokerSocket, 120_000);
    const running = firstClient.run({
      runId,
      agentId,
      workspacePath: candidatePath,
      prompt: "remain alive across Runtime Broker SIGKILL",
      threadId: null,
      runLeaseId,
      sessionEpoch,
    });
    // A Broker SIGKILL intentionally breaks this RPC before it can answer.
    void running.catch(() => undefined);
    const beforeKill = await waitForContainer(name, true);
    if (!beforeKill?.running) throw new Error("Broker child Agent container was not observed running");
    containerId = beforeKill.id;
    runningBeforeBrokerKill = true;

    brokerKillAccepted = firstBroker.kill("SIGKILL");
    const firstExit = await waitForChildExit(firstBroker);
    firstExitCode = firstExit.exitCode;
    firstExitSignal = firstExit.signal;
    await pause(300);
    const orphan = await inspectContainer(name);
    runningAfterBrokerSigkill = orphan?.running === true;
    sameContainerAfterBrokerSigkill = orphan?.id === containerId;
    if (!runningAfterBrokerSigkill || !sameContainerAfterBrokerSigkill) {
      throw new Error("Agent child did not remain alive after Runtime Broker SIGKILL");
    }

    const exactBefore = await queryContainersByLabels(labels);
    queryArguments = exactBefore.arguments;
    matchingContainerIdsBeforeReconcile = exactBefore.ids;
    const wrongLease = await queryContainersByLabels({
      ...labels,
      "io.commitgate.run-lease-id": `${runLeaseId}-wrong`,
    });
    wrongLeaseQueryContainerIds = wrongLease.ids;
    const observedLabels = await inspectContainerLabels(containerId);
    exactLabelsObserved = Object.entries(labels).every(
      ([label, value]) => observedLabels[label] === value,
    );

    restartedBroker = spawnBroker();
    restartedPid = restartedBroker.pid ?? null;
    restartedReady = await waitForBrokerReady(restartedBroker, brokerSocket);
    const restartedClient = new RuntimeBrokerRunner(brokerSocket, 120_000);
    const result = await restartedClient.reconcileCommitGateRuntime({
      runId,
      agentId,
      runLeaseId,
      sessionEpoch,
      scope,
    });
    invokedThroughRestartedBrokerRpc = true;
    attestation = result;
    const after = await queryContainersByLabels(labels);
    negativeQueryArguments = after.arguments;
    remainingContainerIds = after.ids;
    containerAbsentByInspect = (await waitForContainer(name, false)) === null;
    forceRemovedByReconcile =
      matchingContainerIdsBeforeReconcile.some(
        (value) => containerId === value || containerId?.startsWith(value),
      ) &&
      remainingContainerIds.length === 0 &&
      containerAbsentByInspect;
  } catch (reason) {
    error = reason instanceof Error ? reason.message : String(reason);
  } finally {
    if (restartedBroker && restartedBroker.exitCode === null && restartedBroker.signalCode === null) {
      restartedBroker.kill("SIGTERM");
      await waitForChildExit(restartedBroker).catch(() => undefined);
    }
    if (firstBroker && firstBroker.exitCode === null && firstBroker.signalCode === null) {
      firstBroker.kill("SIGTERM");
      await waitForChildExit(firstBroker).catch(() => undefined);
    }
    await execFileAsync(engine, ["rm", "--force", name], { timeout: 8_000 })
      .catch(() => undefined);
    await rm(brokerSocket, { force: true }).catch(() => undefined);
  }

  const observation: Omit<BrokerRestartReconciliationObservation, "status"> = {
    point,
    workload: "agent",
    runId,
    agentId,
    runLeaseId,
    sessionEpoch,
    scope,
    containerName: name,
    containerId,
    broker: {
      launchMode: "separate-node-process",
      firstPid,
      firstReady,
      killSignal: "SIGKILL",
      killAccepted: brokerKillAccepted,
      firstExitCode,
      firstExitSignal,
      restartedPid,
      restartedReady,
    },
    exactBinding: {
      labels,
      queryArguments,
      matchingContainerIdsBeforeReconcile,
      wrongLeaseQueryContainerIds,
      exactLabelsObserved,
    },
    orphan: {
      runningBeforeBrokerKill,
      runningAfterBrokerSigkill,
      sameContainerAfterBrokerSigkill,
    },
    reconciliation: {
      invokedThroughRestartedBrokerRpc,
      forceRemovedByReconcile,
      negativeQueryArguments,
      remainingContainerIds,
      containerAbsentByInspect,
      attestation,
    },
    error,
    brokerLogTail: logTail,
  };
  return {
    ...observation,
    status:
      error && isContainerEnvironmentUnavailable(error)
        ? "unverified"
        : brokerRestartStatus(observation),
  };
}

async function evaluateBrokerCancellation(): Promise<{
  fixtureImage: { reference: string; imageId: string | null };
  evidenceBoundary: {
    agentBinding: string;
    verifierBinding: string;
    verifierAdapter: string;
    rpcTransport: "unix-rpc";
  };
  agent: CancellationObservation;
  verifier: CancellationObservation;
  processKill: {
    agent: ProcessKillObservation;
    verifier: ProcessKillObservation;
    brokerRestartReconciliation: BrokerRestartReconciliationObservation;
  };
}> {
  const build = await execFileAsync(
    engine,
    ["build", "-t", cancellationImage, cancellationFixtureRoot],
    { cwd: root, timeout: 10 * 60_000, maxBuffer: 16 * 1024 * 1024 },
  );
  void build;
  const fixtureImageId = (
    await execFileAsync(engine, ["image", "inspect", cancellationImage, "--format", "{{.Id}}"], {
      timeout: 10_000,
    })
  ).stdout.trim();

  const cancellationRoot = path.join(tempRoot, "broker-cancellation");
  const controlRoot = path.join(cancellationRoot, "control");
  const exchangeRoot = path.join(cancellationRoot, "exchange");
  const codexHome = path.join(cancellationRoot, "codex-home");
  const trustedChecks = path.join(cancellationRoot, "trusted-checks");
  const trustedStore = path.join(cancellationRoot, "trusted-store");
  const instanceId = `cancel-${process.pid}`;
  await Promise.all([
    mkdir(controlRoot, { recursive: true }),
    mkdir(exchangeRoot, { recursive: true }),
    mkdir(codexHome, { recursive: true }),
    mkdir(trustedChecks, { recursive: true }),
    mkdir(trustedStore, { recursive: true }),
  ]);
  await writeFile(
    path.join(trustedChecks, "wait-for-cancel.mjs"),
    [
      'process.on("SIGTERM", () => undefined);',
      'process.stderr.write("verifier-cancellation-fixture: ready\\n");',
      "setInterval(() => undefined, 1_000);",
      "",
    ].join("\n"),
    "utf8",
  );

  const config = loadConfig({
    NODE_ENV: "test",
    PROCESS_ROLE: "runtime-broker",
    COMMITGATE_ENABLED: "true",
    TRANSITION_AUTHORITY: "in-process",
    RUNTIME_PROVIDER: "container",
    CONTAINER_ENGINE: engine,
    CONTAINER_RUNTIME_IMAGE: cancellationImage,
    CONTAINER_AGENT_NETWORK: "none",
    CONTAINER_CPU_LIMIT: "1",
    CONTAINER_MEMORY_LIMIT: "256m",
    CONTAINER_PIDS_LIMIT: "64",
    CODEX_HOME: codexHome,
    CODEX_TIMEOUT_MS: "60000",
    CODEX_MAX_OUTPUT_BYTES: "65536",
    COMMITGATE_CONTROL_ROOT: controlRoot,
    COMMITGATE_EXCHANGE_ROOT: exchangeRoot,
    COMMITGATE_TRUSTED_CHECKS_DIR: trustedChecks,
    COMMITGATE_VERIFIER_TIMEOUT_MS: "60000",
    COMMITGATE_VERIFIER_MAX_OUTPUT_BYTES: "65536",
    RUNTIME_INSTANCE_ID: instanceId,
    ...(user ? { CONTAINER_USER: user } : {}),
  });
  const broker = new RuntimeBroker(config);
  await writeCodexConfig(config);
  // On the host evaluator there is no named-volume mount at the Broker's
  // filesystem path. Replace only the Verifier adapter configuration with the
  // same production DockerVerifierRunner using readonly bind fixtures; the
  // RuntimeBroker runId map and cancellation path remain unchanged.
  (broker as unknown as { verifier: DockerVerifierRunner }).verifier =
    new DockerVerifierRunner({
      engine,
      image: cancellationImage,
      cpuLimit: 1,
      memoryLimit: "256m",
      pidsLimit: 64,
      ...(user ? { user } : {}),
      instanceId,
      trustedChecksPath: trustedChecks,
      trustedCheckStorePath: trustedStore,
      runTimeoutMs: 60_000,
      maxOutputBytes: 65_536,
      sourceRevision: "container-cancellation-eval",
    });
  // Darwin limits AF_UNIX paths to roughly one hundred bytes; keep the
  // evaluator socket short while all mounted fixture paths remain contained.
  const rpcSocket = path.join(tmpdir(), `cg-container-eval-${process.pid}.sock`);
  const rpcServer = await startRuntimeBrokerRpc(broker, rpcSocket);
  const client = new RuntimeBrokerRunner(rpcSocket, 120_000);

  const agentId = "cancel-agent";
  const agentRunId = "cancel-agent-run";
  const runLeaseId = "cancel-agent-lease";
  const candidatePath = path.join(controlRoot, agentId, "candidates", agentRunId);
  await mkdir(candidatePath, { recursive: true });
  await writeFile(path.join(candidatePath, "value.txt"), "agent fixture\n", "utf8");
  const agentRequest: RunnerRequest = {
    runId: agentRunId,
    agentId,
    workspacePath: candidatePath,
    prompt: "wait until cancellation",
    threadId: null,
    runLeaseId,
    sessionEpoch: 3,
  };
  const agentContainerName = containerName(agentId, instanceId);
  let agentObservation: Omit<CancellationObservation, "status">;
  try {
    const running = client.run(agentRequest);
    // Attach a handler immediately so an early Runtime setup error is observed
    // by the evaluator rather than becoming an unhandled rejection while the
    // container-presence poll is still running.
    void running.catch(() => undefined);
    const observed = await waitForContainer(agentContainerName, true);
    const wrongRun = await client.cancel(agentId, {
      runId: `${agentRunId}-stale`,
      runLeaseId,
      sessionEpoch: 3,
    });
    const wrongLease = await client.cancel(agentId, {
      runId: agentRunId,
      runLeaseId: `${runLeaseId}-stale`,
      sessionEpoch: 3,
    });
    const remainedAfterWrongBinding =
      (await inspectContainer(agentContainerName))?.running === true;
    const cancellation: RunnerCancellation = { runId: agentRunId, runLeaseId, sessionEpoch: 3 };
    const accepted = await client.cancel(agentId, cancellation);
    const outcome = await cancellationOutcome(running);
    const removed = (await waitForContainer(agentContainerName, false)) === null;
    const teardown = await client.attestCommitGateTeardown({
      runId: agentRunId,
      agentId,
      runLeaseId,
      sessionEpoch: 3,
      scope: "AGENT",
    });
    agentObservation = {
      runId: agentRunId,
      agentId,
      containerName: agentContainerName,
      containerId: observed?.id ?? null,
      containerObservedRunning: observed?.running === true,
      wrongBindingRejected:
        wrongRun === false && wrongLease === false && remainedAfterWrongBinding,
      cancelAccepted: accepted,
      promiseCancelled: outcome.cancelled,
      cancellationErrorName: outcome.errorName,
      forceRemoved: removed,
      teardown: {
        containerExited: teardown.containerExited,
        containerRemoved: teardown.containerRemoved,
        mountsReleased: teardown.mountsReleased,
        source: "runtime-attestation",
      },
      error: null,
    };
  } catch (reason) {
    await execFileAsync(engine, ["rm", "--force", agentContainerName], { timeout: 8_000 })
      .catch(() => undefined);
    agentObservation = {
      runId: agentRunId,
      agentId,
      containerName: agentContainerName,
      containerId: null,
      containerObservedRunning: false,
      wrongBindingRejected: false,
      cancelAccepted: false,
      promiseCancelled: false,
      cancellationErrorName: null,
      forceRemoved: (await inspectContainer(agentContainerName)) === null,
      teardown: {
        containerExited: false,
        containerRemoved: false,
        mountsReleased: false,
        source: "runtime-attestation",
      },
      error: reason instanceof Error ? reason.message : String(reason),
    };
  }

  const verifierAgentId = "cancel-verifier-agent";
  const verifierRunId = "cancel-verifier-run";
  const checkId = "wait-for-cancel";
  const verifyPath = path.join(exchangeRoot, `verify-${verifierRunId}`);
  await mkdir(verifyPath, { recursive: true });
  await writeFile(path.join(verifyPath, "value.txt"), "verifier fixture\n", "utf8");
  const verifierName = verifierContainerName(
    verifierAgentId,
    verifierRunId,
    checkId,
    instanceId,
  );
  let verifierObservation: Omit<CancellationObservation, "status">;
  try {
    const verifierChecks = [{
      id: checkId,
      runner: "node" as const,
      entrypoint: "wait-for-cancel.mjs",
      args: [],
      timeoutMs: 60_000,
      scratchBytes: 16 * 1024 * 1024,
    }];
    const verifying = client.runVerifier({
      runId: verifierRunId,
      agentId: verifierAgentId,
      runLeaseId: "cancel-verifier-lease",
      sessionEpoch: 5,
      proposalId: "cancel-verifier-proposal",
      verifierInputHash: (await buildWorkerManifest(verifyPath)).hash,
      checkSpecHash: computeCheckSpecHash(verifierChecks),
      workspaceRef: {
        volumeId: `verify-${verifierRunId}`,
        relativeSubpath: `verify-${verifierRunId}`,
        runId: verifierRunId,
        agentId: verifierAgentId,
      },
      checks: verifierChecks,
      timeoutMs: 60_000,
      maxOutputBytes: 65_536,
    });
    void verifying.catch(() => undefined);
    const observed = await waitForContainer(verifierName, true);
    const wrongRun = await client.cancel(verifierAgentId, {
      runId: `${verifierRunId}-stale`,
      runLeaseId: "cancel-verifier-lease",
      sessionEpoch: 5,
    });
    const wrongAgent = await client.cancel(`${verifierAgentId}-stale`, {
      runId: verifierRunId,
      runLeaseId: "cancel-verifier-lease",
      sessionEpoch: 5,
    });
    const remainedAfterWrongBinding =
      (await inspectContainer(verifierName))?.running === true;
    const accepted = await client.cancel(verifierAgentId, {
      runId: verifierRunId,
      runLeaseId: "cancel-verifier-lease",
      sessionEpoch: 5,
    });
    const outcome = await cancellationOutcome(verifying);
    const removed = (await waitForContainer(verifierName, false)) === null;
    const teardown = await client.attestCommitGateTeardown({
      runId: verifierRunId,
      agentId: verifierAgentId,
      runLeaseId: "cancel-verifier-lease",
      sessionEpoch: 5,
      scope: "ALL",
    });
    verifierObservation = {
      runId: verifierRunId,
      agentId: verifierAgentId,
      containerName: verifierName,
      containerId: observed?.id ?? null,
      containerObservedRunning: observed?.running === true,
      wrongBindingRejected:
        wrongRun === false && wrongAgent === false && remainedAfterWrongBinding,
      cancelAccepted: accepted,
      promiseCancelled: outcome.cancelled,
      cancellationErrorName: outcome.errorName,
      forceRemoved: removed,
      teardown: {
        containerExited: teardown.containerExited,
        containerRemoved: teardown.containerRemoved,
        mountsReleased: teardown.mountsReleased,
        source: "runtime-attestation",
      },
      error: null,
    };
  } catch (reason) {
    await execFileAsync(engine, ["rm", "--force", verifierName], { timeout: 8_000 })
      .catch(() => undefined);
    verifierObservation = {
      runId: verifierRunId,
      agentId: verifierAgentId,
      containerName: verifierName,
      containerId: null,
      containerObservedRunning: false,
      wrongBindingRejected: false,
      cancelAccepted: false,
      promiseCancelled: false,
      cancellationErrorName: null,
      forceRemoved: (await inspectContainer(verifierName)) === null,
      teardown: {
        containerExited: false,
        containerRemoved: false,
        mountsReleased: false,
        source: "runtime-attestation",
      },
      error: reason instanceof Error ? reason.message : String(reason),
    };
  }

  const killedAgentId = "kill-agent";
  const killedAgentRunId = "kill-agent-run";
  const killedAgentLeaseId = "kill-agent-lease";
  const killedAgentCandidate = path.join(
    controlRoot,
    killedAgentId,
    "candidates",
    killedAgentRunId,
  );
  await mkdir(killedAgentCandidate, { recursive: true });
  await writeFile(path.join(killedAgentCandidate, "value.txt"), "agent kill fixture\n", "utf8");
  const killedAgentName = containerName(killedAgentId, instanceId);
  let killedAgentObservation: Omit<ProcessKillObservation, "status">;
  try {
    const running = client.run({
      runId: killedAgentRunId,
      agentId: killedAgentId,
      workspacePath: killedAgentCandidate,
      prompt: "wait until externally killed",
      threadId: null,
      runLeaseId: killedAgentLeaseId,
      sessionEpoch: 7,
    });
    void running.catch(() => undefined);
    const observed = await waitForContainer(killedAgentName, true);
    if (!observed?.running) throw new Error("Agent container was not observed running");
    const killAccepted = await killContainer(killedAgentName);
    let promiseRejected = false;
    let runErrorName: string | null = null;
    let runErrorCode: string | null = null;
    let runErrorMessage: string | null = null;
    let successfulOutput = false;
    try {
      await running;
      successfulOutput = true;
    } catch (reason) {
      promiseRejected = true;
      runErrorName = reason instanceof Error ? reason.name : null;
      runErrorCode =
        reason && typeof reason === "object" && "code" in reason &&
          typeof reason.code === "string"
          ? reason.code
          : null;
      runErrorMessage = reason instanceof Error ? reason.message : String(reason);
    }
    const removed = (await waitForContainer(killedAgentName, false)) === null;
    const teardown = await client.attestCommitGateTeardown({
      runId: killedAgentRunId,
      agentId: killedAgentId,
      runLeaseId: killedAgentLeaseId,
      sessionEpoch: 7,
      scope: "AGENT",
    });
    killedAgentObservation = {
      workload: "agent",
      runId: killedAgentRunId,
      agentId: killedAgentId,
      containerName: killedAgentName,
      containerId: observed.id,
      containerObservedRunning: true,
      killSignal: "KILL",
      killAccepted,
      promiseRejected,
      errorName: runErrorName,
      errorCode: runErrorCode,
      errorMessage: runErrorMessage,
      checkStatus: null,
      checkExitCode: null,
      passObserved: successfulOutput,
      failClosed:
        promiseRejected &&
        runErrorName !== "RunCancelledError" &&
        !successfulOutput,
      forceRemoved: removed,
      teardown: {
        containerExited: teardown.containerExited,
        containerRemoved: teardown.containerRemoved,
        mountsReleased: teardown.mountsReleased,
        source: "runtime-attestation",
      },
      error: null,
    };
  } catch (reason) {
    await execFileAsync(engine, ["rm", "--force", killedAgentName], { timeout: 8_000 })
      .catch(() => undefined);
    killedAgentObservation = {
      workload: "agent",
      runId: killedAgentRunId,
      agentId: killedAgentId,
      containerName: killedAgentName,
      containerId: null,
      containerObservedRunning: false,
      killSignal: "KILL",
      killAccepted: false,
      promiseRejected: false,
      errorName: null,
      errorCode: null,
      errorMessage: null,
      checkStatus: null,
      checkExitCode: null,
      passObserved: false,
      failClosed: false,
      forceRemoved: (await inspectContainer(killedAgentName)) === null,
      teardown: {
        containerExited: false,
        containerRemoved: false,
        mountsReleased: false,
        source: "runtime-attestation",
      },
      error: reason instanceof Error ? reason.message : String(reason),
    };
  }

  const killedVerifierAgentId = "kill-verifier-agent";
  const killedVerifierRunId = "kill-verifier-run";
  const killedVerifierCheckId = "wait-for-cancel";
  const killedVerifierPath = path.join(exchangeRoot, `verify-${killedVerifierRunId}`);
  await mkdir(killedVerifierPath, { recursive: true });
  await writeFile(
    path.join(killedVerifierPath, "value.txt"),
    "verifier kill fixture\n",
    "utf8",
  );
  const killedVerifierName = verifierContainerName(
    killedVerifierAgentId,
    killedVerifierRunId,
    killedVerifierCheckId,
    instanceId,
  );
  let killedVerifierObservation: Omit<ProcessKillObservation, "status">;
  try {
    const killedVerifierChecks = [{
      id: killedVerifierCheckId,
      runner: "node" as const,
      entrypoint: "wait-for-cancel.mjs",
      args: [],
      timeoutMs: 60_000,
      scratchBytes: 16 * 1024 * 1024,
    }];
    const verifying = client.runVerifier({
      runId: killedVerifierRunId,
      agentId: killedVerifierAgentId,
      runLeaseId: "kill-verifier-lease",
      sessionEpoch: 6,
      proposalId: "kill-verifier-proposal",
      verifierInputHash: (await buildWorkerManifest(killedVerifierPath)).hash,
      checkSpecHash: computeCheckSpecHash(killedVerifierChecks),
      workspaceRef: {
        volumeId: `verify-${killedVerifierRunId}`,
        relativeSubpath: `verify-${killedVerifierRunId}`,
        runId: killedVerifierRunId,
        agentId: killedVerifierAgentId,
      },
      checks: killedVerifierChecks,
      timeoutMs: 60_000,
      maxOutputBytes: 65_536,
    });
    void verifying.catch(() => undefined);
    const observed = await waitForContainer(killedVerifierName, true);
    if (!observed?.running) throw new Error("Verifier container was not observed running");
    const killAccepted = await killContainer(killedVerifierName);
    let promiseRejected = false;
    let verificationErrorName: string | null = null;
    let verificationErrorCode: string | null = null;
    let verificationErrorMessage: string | null = null;
    let checkStatus: "PASS" | "FAIL" | "ERROR" | "SKIPPED" | null = null;
    let checkExitCode: number | null = null;
    try {
      const result = await verifying;
      const check = result.checks[0];
      checkStatus = check?.status ?? null;
      checkExitCode = check?.exitCode ?? null;
    } catch (reason) {
      promiseRejected = true;
      verificationErrorName = reason instanceof Error ? reason.name : null;
      verificationErrorCode =
        reason && typeof reason === "object" && "code" in reason &&
          typeof reason.code === "string"
          ? reason.code
          : null;
      verificationErrorMessage = reason instanceof Error ? reason.message : String(reason);
    }
    const removed = (await waitForContainer(killedVerifierName, false)) === null;
    const teardown = await client.attestCommitGateTeardown({
      runId: killedVerifierRunId,
      agentId: killedVerifierAgentId,
      runLeaseId: "kill-verifier-lease",
      sessionEpoch: 6,
      scope: "ALL",
    });
    const passObserved = checkStatus === "PASS";
    const failClosed =
      !passObserved &&
      (checkStatus === "ERROR" ||
        (promiseRejected && verificationErrorName !== "RunCancelledError"));
    killedVerifierObservation = {
      workload: "verifier",
      runId: killedVerifierRunId,
      agentId: killedVerifierAgentId,
      containerName: killedVerifierName,
      containerId: observed.id,
      containerObservedRunning: true,
      killSignal: "KILL",
      killAccepted,
      promiseRejected,
      errorName: verificationErrorName,
      errorCode: verificationErrorCode,
      errorMessage: verificationErrorMessage,
      checkStatus,
      checkExitCode,
      passObserved,
      failClosed,
      forceRemoved: removed,
      teardown: {
        containerExited: teardown.containerExited,
        containerRemoved: teardown.containerRemoved,
        mountsReleased: teardown.mountsReleased,
        source: "runtime-attestation",
      },
      error: null,
    };
  } catch (reason) {
    await execFileAsync(engine, ["rm", "--force", killedVerifierName], { timeout: 8_000 })
      .catch(() => undefined);
    killedVerifierObservation = {
      workload: "verifier",
      runId: killedVerifierRunId,
      agentId: killedVerifierAgentId,
      containerName: killedVerifierName,
      containerId: null,
      containerObservedRunning: false,
      killSignal: "KILL",
      killAccepted: false,
      promiseRejected: false,
      errorName: null,
      errorCode: null,
      errorMessage: null,
      checkStatus: null,
      checkExitCode: null,
      passObserved: false,
      failClosed: false,
      forceRemoved: (await inspectContainer(killedVerifierName)) === null,
      teardown: {
        containerExited: false,
        containerRemoved: false,
        mountsReleased: false,
        source: "runtime-attestation",
      },
      error: reason instanceof Error ? reason.message : String(reason),
    };
  }

  await new Promise<void>((resolve, reject) => {
    rpcServer.close((reason) => reason ? reject(reason) : resolve());
  });
  await rm(rpcSocket, { force: true }).catch(() => undefined);
  const brokerRestartReconciliation = await evaluateBrokerProcessRestart({
    cancellationRoot,
    controlRoot,
    exchangeRoot,
    codexHome,
    trustedChecks,
    instanceId,
  });
  return {
    fixtureImage: { reference: cancellationImage, imageId: fixtureImageId || null },
    evidenceBoundary: {
      agentBinding: "agentId+runId+runLeaseId+sessionEpoch",
      verifierBinding: "agentId+runId (Verifier request has no lease/session fields)",
      verifierAdapter: "production DockerVerifierRunner with evaluator-only readonly bind fixtures",
      rpcTransport: "unix-rpc",
    },
    agent: { ...agentObservation, status: cancellationStatus(agentObservation) },
    verifier: { ...verifierObservation, status: cancellationStatus(verifierObservation) },
    processKill: {
      agent: {
        ...killedAgentObservation,
        status: processKillStatus(killedAgentObservation),
      },
      verifier: {
        ...killedVerifierObservation,
        status: processKillStatus(killedVerifierObservation),
      },
      brokerRestartReconciliation,
    },
  };
}

const checkSource = `
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { lookup } from "node:dns/promises";

assert.equal(process.env.ARK_API_KEY, undefined, "Ark key leaked into verifier");
assert.equal(process.env.MODEL_API_KEY, undefined, "Generic provider key leaked into verifier");
assert.equal(process.env.MODEL_RELAY_TOKEN, undefined, "Relay token leaked into verifier");
assert.equal(process.env.OPENAI_API_KEY, undefined, "OpenAI-compatible key leaked into verifier");
assert.equal(process.env.CODEX_HOME, undefined, "Codex home leaked into verifier");
assert.equal(process.env.NODE_OPTIONS, undefined, "NODE_OPTIONS leaked into verifier");
assert.equal(process.env.PYTHONPATH, undefined, "PYTHONPATH leaked into verifier");
assert.equal(await readFile("/proposal/value.txt", "utf8"), "ok\\n");
let networkResolved = false;
try { await lookup("example.com"); networkResolved = true; } catch {}
assert.equal(networkResolved, false, "Verifier unexpectedly resolved the public network");
let checksWritable = true;
try { await writeFile("/checks/write-probe", "bad"); } catch { checksWritable = false; }
assert.equal(checksWritable, false, "Trusted checks mount is writable");
let proposalWritable = true;
try { await writeFile("/proposal/write-probe", "bad"); } catch { proposalWritable = false; }
assert.equal(proposalWritable, false, "Proposal mount is writable");
console.log("isolated-contract: PASS");
`;
await writeFile(path.join(checks, "isolated-contract.mjs"), checkSource, "utf8");
await writeFile(path.join(candidate, "value.txt"), "ok\n", "utf8");

const config = {
  engine,
  image,
  cpuLimit: 1,
  memoryLimit: "512m",
  pidsLimit: 64,
  ...(user ? { user } : {}),
  instanceId: "eval",
  trustedChecksPath: checks,
  runTimeoutMs: 20_000,
  maxOutputBytes: 65_536,
  sourceRevision: "container-eval",
};
const policyCheck = {
  id: "isolated-contract",
  runner: "node" as const,
  entrypoint: "isolated-contract.mjs",
  args: [],
  timeoutMs: 20_000,
  scratchBytes: 64 * 1024 * 1024,
};
const input: VerifierInput = {
  runId: "container-eval",
  agentId: "fixture-agent",
  verifyPath: candidate,
  trustedChecksPath: checks,
  checks: [policyCheck],
  timeoutMs: 20_000,
  maxOutputBytes: 65_536,
};
const args = buildVerifierContainerArgs(input, policyCheck, config);
const imageIndex = args.indexOf(image);
const commandTail = imageIndex >= 0 ? args.slice(imageIndex + 1) : [];
const joinedArguments = args.join(" ");
const structural = {
  networkNone: args.includes("none") && args[args.indexOf("--network") + 1] === "none",
  readOnlyRoot: args.includes("--read-only"),
  capsDropped: args.includes("ALL") && args.includes("--cap-drop"),
  noNewPrivileges: args.includes("no-new-privileges"),
  proposalReadOnly: args.some((arg) => arg.includes("dst=/proposal,readonly")),
  trustedChecksReadOnly: args.some((arg) => arg.includes("dst=/checks,readonly")),
  scratchOnlyWritableMount: args.some((arg) => arg.startsWith("/scratch:rw")),
  isolatedEnvironment:
    args[args.indexOf("--entrypoint") + 1] === "/usr/bin/env" && commandTail[0] === "-i",
  noProviderCredentialArgument:
    !/ARK_API_KEY|MODEL_API_KEY|MODEL_RELAY_TOKEN|OPENAI_API_KEY|OPENROUTER_API_KEY/.test(joinedArguments),
  noCodexHome: !args.some((arg) => arg.includes("dst=/codex-home")),
  noPersistentMount: !args.some((arg) => arg.includes("dst=/workspace")),
  noShellWrapper:
    commandTail.includes("node") &&
    commandTail.includes("/checks/isolated-contract.mjs") &&
    !commandTail.some((arg) => /^(?:sh|bash|zsh|-c)$/.test(arg)),
};

let positive = null;
let negative = null;
let error: string | null = null;
let imageId: string | null = null;
let cancellationError: string | null = null;
const unavailableCancellation = (
  kind: "agent" | "verifier",
  reason: string | null,
): CancellationObservation => ({
  status: "unverified",
  runId: `cancel-${kind}-run`,
  agentId: `cancel-${kind}-agent`,
  containerName: "unverified",
  containerId: null,
  containerObservedRunning: false,
  wrongBindingRejected: false,
  cancelAccepted: false,
  promiseCancelled: false,
  cancellationErrorName: null,
  forceRemoved: false,
  teardown: {
    containerExited: false,
    containerRemoved: false,
    mountsReleased: false,
    source: kind === "agent" ? "runtime-attestation" : "container-inspect",
  },
  error: reason,
});
const unavailableProcessKill = (
  kind: "agent" | "verifier",
  reason: string | null,
): ProcessKillObservation => ({
  status: "unverified",
  workload: kind,
  runId: `kill-${kind}-run`,
  agentId: `kill-${kind}-agent`,
  containerName: "unverified",
  containerId: null,
  containerObservedRunning: false,
  killSignal: "KILL",
  killAccepted: false,
  promiseRejected: false,
  errorName: null,
  errorCode: null,
  errorMessage: null,
  checkStatus: null,
  checkExitCode: null,
  passObserved: false,
  failClosed: false,
  forceRemoved: false,
  teardown: {
    containerExited: false,
    containerRemoved: false,
    mountsReleased: false,
    source: "runtime-attestation",
  },
  error: reason,
});
const unavailableBrokerRestartReconciliation = (
  reason: string,
  status: "failed" | "unverified" = "unverified",
): BrokerRestartReconciliationObservation => ({
  status,
  point: "RUNTIME_BROKER_PROCESS_SIGKILL_ORPHAN_RECONCILIATION",
  workload: "agent",
  runId: "restart-orphan-run",
  agentId: "restart-orphan-agent",
  runLeaseId: "restart-orphan-lease",
  sessionEpoch: 11,
  scope: "ALL",
  containerName: "unverified",
  containerId: null,
  broker: {
    launchMode: "separate-node-process",
    firstPid: null,
    firstReady: false,
    killSignal: "SIGKILL",
    killAccepted: false,
    firstExitCode: null,
    firstExitSignal: null,
    restartedPid: null,
    restartedReady: false,
  },
  exactBinding: {
    labels: {},
    queryArguments: [],
    matchingContainerIdsBeforeReconcile: [],
    wrongLeaseQueryContainerIds: [],
    exactLabelsObserved: false,
  },
  orphan: {
    runningBeforeBrokerKill: false,
    runningAfterBrokerSigkill: false,
    sameContainerAfterBrokerSigkill: false,
  },
  reconciliation: {
    invokedThroughRestartedBrokerRpc: false,
    forceRemovedByReconcile: false,
    negativeQueryArguments: [],
    remainingContainerIds: [],
    containerAbsentByInspect: false,
    attestation: null,
  },
  error: reason,
  brokerLogTail: "",
});
let brokerCancellation: {
  fixtureImage: { reference: string; imageId: string | null };
  evidenceBoundary: {
    agentBinding: string;
    verifierBinding: string;
    verifierAdapter: string;
    rpcTransport: "unix-rpc" | "not-exercised";
  };
  agent: CancellationObservation;
  verifier: CancellationObservation;
} = {
  fixtureImage: { reference: cancellationImage, imageId: null },
  evidenceBoundary: {
    agentBinding: "unverified",
    verifierBinding: "unverified",
    verifierAdapter: "unverified",
    rpcTransport: "not-exercised",
  },
  agent: unavailableCancellation("agent", "Cancellation evaluator did not run"),
  verifier: unavailableCancellation("verifier", "Cancellation evaluator did not run"),
};
let brokerProcessKill: {
  agent: ProcessKillObservation;
  verifier: ProcessKillObservation;
  brokerRestartReconciliation: BrokerRestartReconciliationObservation;
} = {
  agent: unavailableProcessKill("agent", "Process-kill evaluator did not run"),
  verifier: unavailableProcessKill("verifier", "Process-kill evaluator did not run"),
  brokerRestartReconciliation: unavailableBrokerRestartReconciliation(
    "Broker-process restart evaluator did not run",
  ),
};
try {
  imageId = (
    await execFileAsync(engine, ["image", "inspect", image, "--format", "{{.Id}}"], {
      timeout: 10_000,
    })
  ).stdout.trim();
  const runner = new DockerVerifierRunner(config);
  positive = (await runner.run(input))[0] ?? null;
  await writeFile(path.join(candidate, "value.txt"), "tampered\n", "utf8");
  negative = (await runner.run({ ...input, runId: "container-eval-negative" }))[0] ?? null;
} catch (reason) {
  error = reason instanceof Error ? reason.message : String(reason);
}
try {
  const brokerLifecycle = await evaluateBrokerCancellation();
  const { processKill, ...cancellation } = brokerLifecycle;
  brokerCancellation = cancellation;
  brokerProcessKill = processKill;
} catch (reason) {
  cancellationError = reason instanceof Error ? reason.message : String(reason);
  brokerCancellation = {
    fixtureImage: { reference: cancellationImage, imageId: null },
    evidenceBoundary: {
      agentBinding: "unverified",
      verifierBinding: "unverified",
      verifierAdapter: "unverified",
      rpcTransport: "not-exercised",
    },
    agent: unavailableCancellation("agent", cancellationError),
    verifier: unavailableCancellation("verifier", cancellationError),
  };
  brokerProcessKill = {
    agent: unavailableProcessKill("agent", cancellationError),
    verifier: unavailableProcessKill("verifier", cancellationError),
    brokerRestartReconciliation: unavailableBrokerRestartReconciliation(
      cancellationError,
      isContainerEnvironmentUnavailable(cancellationError) ? "unverified" : "failed",
    ),
  };
}

const environmentUnavailable = Boolean(
  ((error || cancellationError) &&
    isContainerEnvironmentUnavailable(`${error ?? ""}\n${cancellationError ?? ""}`)) ||
    (brokerProcessKill.brokerRestartReconciliation.status === "unverified" &&
      isContainerEnvironmentUnavailable(
        brokerProcessKill.brokerRestartReconciliation.error ?? "",
      )),
);
const status =
  !error &&
  !cancellationError &&
  Object.values(structural).every(Boolean) &&
  positive?.status === "PASS" &&
  negative?.status === "FAIL" &&
  brokerCancellation.agent.status === "verified" &&
  brokerCancellation.verifier.status === "verified" &&
  brokerProcessKill.agent.status === "verified" &&
  brokerProcessKill.verifier.status === "verified" &&
  brokerProcessKill.brokerRestartReconciliation.status === "verified"
    ? "verified"
    : environmentUnavailable
      ? "unverified"
      : "failed";
const report = {
  schemaVersion: 2,
  kind: "container-verifier-evaluation",
  generatedAt: new Date().toISOString(),
  status,
  source: await evidenceProvenance(root),
  executionIdentity: executionIdentity(root),
  provenance: {
    realContainerExecution: Boolean(imageId && positive && negative),
    realProviderRequest: false,
    image,
    imageId,
    engine,
  },
  structural,
  positive,
  negative,
  brokerCancellation,
  brokerProcessKill,
  error,
  cancellationError,
  command: {
    executable: engine,
    arguments: args.map((argument) => argument.replaceAll(root, "<REPO>")),
    note: "Temporary mount fixtures are recreated by npm run eval:container.",
  },
};
await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");
await execFileAsync(engine, ["image", "rm", "--force", cancellationImage], {
  timeout: 30_000,
}).catch(() => undefined);
await makeTreeWritable(tempRoot).catch(() => undefined);
await rm(tempRoot, { recursive: true, force: true });
console.log(`container report: ${reportPath}`);
if (positive) console.log(`positive trusted check: ${positive.status}`);
if (negative) console.log(`negative trusted check: ${negative.status}`);
console.log(`agent cancellation: ${brokerCancellation.agent.status}`);
console.log(`verifier cancellation: ${brokerCancellation.verifier.status}`);
console.log(`agent unexpected SIGKILL: ${brokerProcessKill.agent.status}`);
console.log(`verifier unexpected SIGKILL: ${brokerProcessKill.verifier.status}`);
console.log(
  `broker SIGKILL orphan reconciliation: ${brokerProcessKill.brokerRestartReconciliation.status}`,
);
const exitCode = status === "verified" ? 0 : status === "unverified" ? 2 : 1;
// Every container, RPC server, socket, image, and temporary directory has
// already been disposed above. A deliberately interrupted Broker RPC can keep
// a client-side timeout handle referenced after its expected rejection; do not
// let that evaluator-only handle turn a completed result into a multi-minute
// hang. Flush the final report lines, then terminate with the computed status.
await new Promise<void>((resolve) => setImmediate(resolve));
process.exit(exitCode);
