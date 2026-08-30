#!/usr/bin/env node
import { execFile } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { evidenceProvenance, executionIdentity } from "./evidence-utils.mjs";
import { assertEvaluationRecord, evaluationRecord } from "./evaluation-record.mjs";

const execFileAsync = promisify(execFile);
const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const engine = process.env.CONTAINER_ENGINE || "docker";
const suffix = `${process.pid}-${Date.now()}`;
const explicitWorkerImage = process.env.COMMITGATE_TRANSITION_WORKER_IMAGE?.trim();
// The canonical evaluator builds the same product image used by the release
// topology.  A freeze run may provide an already inspected immutable image and
// skip the rebuild.  Either way, executionIdentity and the exercised recovery
// Worker now refer to the same digest as every other image-bound report.
const image = explicitWorkerImage || "commitgate-transition-worker:local";
const apiImage = `commitgate-recovery-api:${suffix}`;
const driver = path.join(root, "scripts", "recovery-docker-driver.mjs");
const maxBuffer = 32 * 1024 * 1024;
const source = await evidenceProvenance(root);
if (!/^[a-f0-9]{40}$/.test(source.sourceRevision ?? "")) {
  throw new Error("Docker recovery requires a frozen 40-hex source revision");
}

async function command(args, options = {}) {
  try {
    const result = await execFileAsync(engine, args, {
      cwd: root,
      encoding: "utf8",
      maxBuffer,
      timeout: options.timeout ?? 120_000,
    });
    return { status: 0, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
  } catch (error) {
    // Node may surface an execFile timeout with `code: 0` plus `killed` or a
    // terminating signal. Treat it as an interrupted command, never success.
    const interrupted = error?.killed === true || typeof error?.signal === "string";
    const exitCode = Number.isInteger(error?.code) && error.code !== 0 ? error.code : 1;
    return {
      status: interrupted ? 124 : exitCode,
      stdout: String(error?.stdout ?? ""),
      stderr: String(error?.stderr ?? error?.message ?? error),
    };
  }
}

async function waitForState(container, desired, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const result = await command(["inspect", "--format", "{{.State.Status}}|{{.State.ExitCode}}", container]);
    if (result.status === 0) {
      const [status, exitCode] = result.stdout.trim().split("|");
      if (desired.includes(status)) return { status, exitCode: Number(exitCode) };
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  return null;
}

// A rollback recovery has more durable state to replay than an empty or
// pre-promotion transition.  Cold Docker Desktop/Colima volumes can make that
// replay exceed 20 seconds even though the Worker is still progressing.  Use
// one release-grade budget for every recovery point so the evaluator measures
// recovery correctness rather than host cache temperature.
async function waitForReady(container, timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  let last = "";
  while (Date.now() < deadline) {
    const result = await command([
      "exec", container, "node", "/app/recovery-docker-driver.mjs", "health",
    ], { timeout: 5_000 });
    const health = result.status === 0 ? tryParseLastJson(result.stdout) : null;
    // Docker Desktop can transiently report a successful `docker exec` with
    // no captured stdout immediately after a container restart.  Exit status
    // alone is therefore not a readiness proof: require the typed Worker
    // health payload before issuing an inspection RPC.
    if (
      health?.status === "ok" &&
      health?.authority === "transition-worker" &&
      /^[a-f0-9]{24}$/.test(health.signingKeyId ?? "")
    ) return true;
    last = `${result.stdout}${result.stderr}`;
    const state = await waitForState(container, ["exited", "dead"], 50);
    if (state) throw new Error(`worker exited before readiness: ${last}`);
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  const logs = await command(["logs", container], { timeout: 5_000 });
  const diagnostic = `${last}\n${logs.stdout}${logs.stderr}`.trim().slice(-4_096);
  throw new Error(`worker readiness timeout: ${diagnostic}`);
}

async function waitForApiReady(container, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  let last = "";
  while (Date.now() < deadline) {
    const result = await command([
      "exec", container, "node", "-e",
      "fetch('http://127.0.0.1:3000/api/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))",
    ], { timeout: 5_000 });
    if (result.status === 0) return true;
    last = `${result.stdout}${result.stderr}`;
    const state = await waitForState(container, ["exited", "dead"], 50);
    if (state) throw new Error(`API exited before readiness: ${last}`);
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`API readiness timeout: ${last}`);
}

async function waitForLogMarker(container, marker, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  let output = "";
  while (Date.now() < deadline) {
    const logs = await command(["logs", container], { timeout: 5_000 });
    output = `${logs.stdout}${logs.stderr}`;
    if (output.includes(marker)) return output;
    const state = await waitForState(container, ["exited", "dead"], 50);
    if (state) throw new Error(`container exited before marker ${marker}: ${output}`);
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`marker timeout ${marker}: ${output}`);
}

function tryParseLastJson(output) {
  const lines = output.trim().split(/\r?\n/).filter(Boolean);
  for (const line of lines.reverse()) {
    try {
      return JSON.parse(line);
    } catch {}
  }
  return null;
}

function parseLastJson(output) {
  const parsed = tryParseLastJson(output);
  if (parsed !== null) return parsed;
  throw new Error("RECOVERY_INSPECTION_JSON_MISSING");
}

async function inspectScenarioState(container, transitionId, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  let lastOutput = "";
  while (Date.now() < deadline) {
    const inspected = await command([
      "exec", container, "node", "/app/recovery-docker-driver.mjs",
      "inspect", transitionId,
    ], { timeout: 30_000 });
    if (inspected.status !== 0) {
      // A real driver/RPC failure is evidence, not a retryable capture race.
      throw new Error(inspected.stderr || inspected.stdout);
    }
    const parsed = tryParseLastJson(inspected.stdout);
    if (parsed !== null) return parsed;

    // Retry only the observed Docker CLI anomaly: exit 0 with an empty or
    // malformed capture while the restarted Worker is still running.
    lastOutput = `${inspected.stdout}${inspected.stderr}`;
    const stopped = await waitForState(container, ["exited", "dead"], 50);
    if (stopped) {
      throw new Error(
        `RECOVERY_INSPECTION_CONTAINER_EXITED:${stopped.status}:${stopped.exitCode}`,
      );
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(
    `RECOVERY_INSPECTION_JSON_MISSING:${lastOutput.slice(-512)}`,
  );
}

const scenarios = [
  {
    id: "prepared-recovers-aborted",
    point: "TRANSITION_PREPARED",
    action: "run-commit",
    transitionId: "run-prepared",
    expectedState: "ROLLED_BACK",
    expectedGeneration: 1,
    expectedPermitState: null,
    expectedVersions: 1,
    candidatePresent: false,
    expectedTerminalDecision: "ABORTED",
    expectedSessionEpoch: 1,
  },
  {
    id: "sealed-recovers-aborted",
    point: "PROPOSAL_SEALED",
    action: "run-commit",
    transitionId: "run-sealed",
    expectedState: "ROLLED_BACK",
    expectedGeneration: 1,
    expectedPermitState: null,
    expectedVersions: 1,
    candidatePresent: false,
    expectedTerminalDecision: "ABORTED",
    expectedSessionEpoch: 1,
  },
  {
    id: "evidenced-recovers-aborted",
    point: "EVIDENCE_RECORDED",
    action: "run-commit",
    transitionId: "run-evidenced",
    expectedState: "ROLLED_BACK",
    expectedGeneration: 1,
    expectedPermitState: null,
    expectedVersions: 1,
    candidatePresent: false,
    expectedTerminalDecision: "ABORTED",
    expectedSessionEpoch: 1,
  },
  {
    id: "permit-issued-recovers-aborted",
    point: "PERMIT_ISSUED",
    action: "run-commit",
    transitionId: "run-permit-issued",
    expectedState: "ROLLED_BACK",
    expectedGeneration: 1,
    expectedPermitState: "REVOKED",
    expectedVersions: 1,
    candidatePresent: false,
    expectedTerminalDecision: "ABORTED",
    expectedSessionEpoch: 1,
  },
  {
    id: "permit-consuming-rolls-back",
    point: "PERMIT_CONSUMING",
    action: "run-commit",
    transitionId: "run-permit-consuming",
    expectedState: "ROLLED_BACK",
    expectedGeneration: 1,
    expectedPermitState: "REVOKED",
    expectedVersions: 1,
    candidatePresent: false,
    expectedTerminalDecision: "ABORTED",
    expectedSessionEpoch: 1,
  },
  {
    id: "backup-created-rolls-back",
    point: "BACKUP_CREATED",
    action: "run-commit",
    transitionId: "run-backup-created",
    expectedState: "ROLLED_BACK",
    expectedGeneration: 1,
    expectedPermitState: "REVOKED",
    expectedVersions: 1,
    candidatePresent: false,
    expectedTerminalDecision: "ABORTED",
    expectedSessionEpoch: 1,
  },
  {
    id: "workspace-applied-recovers-forward",
    point: "WORKSPACE_APPLIED",
    action: "run-commit",
    transitionId: "run-workspace-applied",
    expectedState: "ACKNOWLEDGED",
    expectedGeneration: 2,
    expectedPermitState: "CONSUMED",
    expectedVersions: 2,
    candidatePresent: false,
    expectedTerminalDecision: "COMMITTED",
    expectedSessionEpoch: 0,
  },
  {
    id: "rollback-applied-recovers-forward",
    point: "ROLLBACK_APPLIED",
    action: "run-rollback",
    transitionId: "rollback-1",
    expectedState: "ACKNOWLEDGED",
    expectedGeneration: 3,
    expectedPermitState: "CONSUMED",
    expectedVersions: 3,
    candidatePresent: false,
    expectedKind: "ROLLBACK",
    expectedTerminalDecision: "COMMITTED",
    expectedSessionEpoch: 1,
  },
  {
    id: "ack-durable-and-cleaned",
    point: "TRANSITION_ACKNOWLEDGED",
    action: "run-commit",
    transitionId: "run-ack",
    expectedState: "ACKNOWLEDGED",
    expectedGeneration: 2,
    expectedPermitState: "CONSUMED",
    expectedVersions: 2,
    candidatePresent: false,
    expectedTerminalDecision: "COMMITTED",
    expectedSessionEpoch: 0,
  },
  {
    id: "rollback-ack-durable-and-cleaned",
    point: "TRANSITION_ACKNOWLEDGED",
    action: "run-rollback",
    transitionId: "rollback-1",
    expectedState: "ACKNOWLEDGED",
    expectedGeneration: 3,
    expectedPermitState: "CONSUMED",
    expectedVersions: 3,
    candidatePresent: false,
    expectedKind: "ROLLBACK",
    expectedTerminalDecision: "COMMITTED",
    expectedSessionEpoch: 1,
  },
];

let imageIdentity = null;
let apiImageIdentity = null;
const results = [];
let environmentFailure = null;
let apiEnvironmentFailure = null;
let workerImageBuilt = false;

async function removeScenarioResources(container, volumes) {
  await command(["rm", "--force", container], { timeout: 30_000 });
  for (const volume of volumes) await command(["volume", "rm", "--force", volume]);
}

async function evaluateScenario(scenario) {
  const prefix = `cg-recovery-${suffix}-${scenario.id}`.replace(/[^a-zA-Z0-9_.-]/g, "-");
  const container = `${prefix}-worker`;
  const volumes = ["authority", "control", "exchange", "sockets"].map(
    (name) => `${prefix}-${name}`,
  );
  const [authority, control, exchange, sockets] = volumes;
  for (const volume of volumes) {
    const created = await command(["volume", "create", volume]);
    if (created.status !== 0) throw new Error(created.stderr || "volume create failed");
  }
  try {
    const initialized = await command([
      "run", "--rm", "--user", "0:0", "--network", "none",
      "--mount", `source=${authority},target=/var/lib/commitgate/workspaces`,
      "--mount", `source=${control},target=/var/lib/commitgate/control`,
      "--mount", `source=${exchange},target=/var/lib/commitgate/exchange`,
      "--mount", `source=${sockets},target=/run/commitgate`,
      image,
      "sh", "-ec",
      "chown -R 10001:20000 /var/lib/commitgate/workspaces /var/lib/commitgate/control /var/lib/commitgate/exchange /run/commitgate && chmod 0770 /var/lib/commitgate/workspaces /var/lib/commitgate/control /var/lib/commitgate/exchange /run/commitgate",
    ], { timeout: 30_000 });
    if (initialized.status !== 0) {
      throw new Error(initialized.stderr || initialized.stdout || "volume ownership init failed");
    }
    const started = await command([
      "run", "--detach", "--name", container,
      "--user", "10001:20000",
      "--read-only",
      "--network", "none",
      "--tmpfs", "/tmp:rw,size=32m,noexec,nosuid,nodev",
      "--security-opt", "no-new-privileges:true",
      "--cap-drop", "ALL",
      "--pids-limit", "64",
      "--memory", "512m",
      "--cpus", "0.5",
      "-e", "NODE_ENV=test",
      "-e", "COMMITGATE_TRANSITION_WORKER=enabled",
      "-e", "COMMITGATE_FAULT_INJECTION=true",
      "-e", `COMMITGATE_FAULT_POINT=${scenario.point}`,
      "-e", "COMMITGATE_FAULT_AGENT_ID=recovery-agent",
      "-e", `COMMITGATE_FAULT_TRANSITION_ID=${scenario.transitionId}`,
      "-e", "RECOVERY_AGENT_ID=recovery-agent",
      "-e", `COMMITGATE_SOURCE_REVISION=${source.sourceRevision}`,
      "-e", "TRANSITION_WORKER_WORKSPACE_ROOT=/var/lib/commitgate/workspaces",
      "-e", "TRANSITION_WORKER_CONTROL_ROOT=/var/lib/commitgate/control",
      "-e", "TRANSITION_WORKER_INBOX_ROOT=/var/lib/commitgate/exchange",
      "-e", "TRANSITION_WORKER_SOCKET=/run/commitgate/transition-worker.sock",
      "--mount", `source=${authority},target=/var/lib/commitgate/workspaces`,
      "--mount", `source=${control},target=/var/lib/commitgate/control`,
      "--mount", `source=${exchange},target=/var/lib/commitgate/exchange`,
      "--mount", `source=${sockets},target=/run/commitgate`,
      "--mount", `type=bind,src=${driver},dst=/app/recovery-docker-driver.mjs,readonly`,
      image,
    ], { timeout: 30_000 });
    if (started.status !== 0) throw new Error(started.stderr || started.stdout);
    await waitForReady(container);

    const anchored = await command([
      "exec", container, "node", "/app/recovery-docker-driver.mjs", "key-anchor",
    ], { timeout: 10_000 });
    if (anchored.status !== 0) throw new Error(anchored.stderr || anchored.stdout);
    const preCrashSigningKey = parseLastJson(anchored.stdout);
    if (
      !/^[a-f0-9]{24}$/.test(preCrashSigningKey?.keyId ?? "") ||
      !/^[a-f0-9]{64}$/.test(preCrashSigningKey?.publicKeySha256 ?? "")
    ) {
      throw new Error("RECOVERY_SIGNING_KEY_ANCHOR_INVALID");
    }

    const trigger = await command([
      "exec", container, "node", "/app/recovery-docker-driver.mjs",
      scenario.action, scenario.transitionId,
    ], { timeout: 2_000 });
    // A rollback fixture first creates a committed version to roll back to.
    // That setup can outlive the short-lived docker-exec capture, so a single
    // immediate log read can race ahead of the durable fault event. Wait for
    // the exact post-append marker before issuing SIGKILL; otherwise the
    // evaluator would mistake the still-running fault latch for a restarted
    // Worker readiness failure.
    const armedOutput = await waitForLogMarker(
      container,
      `"point":"${scenario.point}"`,
      60_000,
    );
    const faultArmed =
      armedOutput.includes('"action":"AWAIT_EXTERNAL_SIGKILL"') &&
      armedOutput.includes(`"agentId":"recovery-agent"`) &&
      armedOutput.includes(`"transitionId":"${scenario.transitionId}"`);
    const killed = faultArmed
      ? await command(["kill", "--signal", "KILL", container], { timeout: 10_000 })
      : { status: 1, stdout: "", stderr: "fault hook was not armed" };
    const stopped = await waitForState(container, ["exited", "dead"]);
    const crashObserved = killed.status === 0 && stopped?.exitCode === 137;
    const restart = await command(["start", container], { timeout: 30_000 });
    if (restart.status !== 0) throw new Error(restart.stderr || restart.stdout);
    await waitForReady(container);

    const state = await inspectScenarioState(container, scenario.transitionId);
    const pointEvent = state.events.find(
      (event) => event.type === scenario.point && event.transitionId === scenario.transitionId,
    );
    const sequenceValid = state.events.every(
      (event, index) => event.sequence === index + 1 && /^[a-f0-9]{64}$/.test(event.digest),
    );
    const assertions = {
      sigkillExit137: crashObserved,
      exactEventHookArmed: faultArmed,
      // recovery-docker-driver always emits one JSON line on normal RPC
      // completion. macOS Docker CLI can report exit 0 when its timed child is
      // terminated, so absence of that terminal result is the portable proof
      // that the in-flight authority call did not complete.
      rpcInterrupted: trigger.status !== 0 || trigger.stdout.trim().length === 0,
      faultEventDurable: Boolean(pointEvent),
      eventChainValid: state.eventChainVerified === true && sequenceValid,
      transitionState: state.transition?.state === scenario.expectedState,
      transitionKind: !scenario.expectedKind || state.transition?.kind === scenario.expectedKind,
      generation: state.projection.head?.view?.generation === scenario.expectedGeneration,
      versions: state.projection.versions?.length === scenario.expectedVersions,
      permitState:
        scenario.expectedPermitState === null
          ? state.permit === null
          : state.permit?.state === scenario.expectedPermitState,
      terminalDecision:
        state.terminalReceipt?.decision === scenario.expectedTerminalDecision,
      terminalReceiptProof:
        state.terminalProofPresent === true &&
        state.terminalProof?.schemaVersion === 3 &&
        state.terminalProof?.valid === true &&
        state.terminalProof?.reason === null &&
        state.terminalProof?.sourceRevision === source.sourceRevision &&
        state.terminalProof?.expectedSourceRevision === source.sourceRevision &&
        state.terminalProof?.trustAnchorMatches === true &&
        state.terminalProof?.fullEventChain === true &&
        state.terminalProof?.terminalEventBound === true,
      signingKeyStableAcrossRestart:
        state.terminalProof?.signingKeyAnchor === preCrashSigningKey.keyId,
      sessionEpoch:
        state.projection.head?.view?.sessionEpoch === scenario.expectedSessionEpoch,
      workspaceMatchesHead: state.workspaceHashMatchesHead === true,
      projectionMarkerRebuilt: state.markerMatchesProjection === true,
      candidateDisposition: state.cleanup.candidatePresent === scenario.candidatePresent,
      runArtifactsDestroyed: state.transition?.artifactsDestroyed === true,
      proposalMetadataDestroyed:
        state.proposal === null || state.proposal?.state === "DESTROYED",
      noProposalResidue: state.cleanup.proposalPresent === false,
      noStagingResidue: state.cleanup.stagingPresent === false,
      noBackupResidue: state.cleanup.backupPresent === false,
    };
    const status = Object.values(assertions).every(Boolean) ? "verified" : "failed";
    const logs = await command(["logs", container], { timeout: 10_000 });
    return {
      id: scenario.id,
      faultPoint: scenario.point,
      transitionId: scenario.transitionId,
      action: scenario.action,
      status,
      containerExitCode: stopped?.exitCode ?? null,
      assertions,
      observed: {
        transitionState: state.transition?.state ?? null,
        transitionKind: state.transition?.kind ?? null,
        generation: state.projection.head?.view?.generation ?? null,
        workspaceHash: state.projection.head?.workspaceHash ?? null,
        workspaceManifestHash: state.workspaceManifestHash,
        permitState: state.permit?.state ?? null,
        terminalDecision: state.terminalReceipt?.decision ?? null,
        terminalReceiptId: state.terminalReceipt?.receiptId ?? null,
        terminalProofPresent: state.terminalProofPresent,
        terminalProof: state.terminalProof,
        preCrashSigningKey,
        versions: state.projection.versions?.length ?? null,
        lastEventSequence: state.projection.lastSequence,
        lastEventDigest: state.events.at(-1)?.digest ?? null,
        cleanup: state.cleanup,
      },
      faultLog: `${logs.stdout}${logs.stderr}`.split(/\r?\n/)
        .filter((line) => line.includes("commitgate-worker-fault-injection"))
        .slice(-1)[0] ?? null,
      triggerStatus: trigger.status,
      triggerError: `${trigger.stdout}${trigger.stderr}`.slice(-2_048),
    };
  } finally {
    await removeScenarioResources(container, volumes);
  }
}

async function evaluateApiProjectionScenario() {
  const scenario = {
    id: "api-projection-pending",
    point: "API_PROJECTION_PENDING",
    transitionId: "api-projection-run",
  };
  const prefix = `cg-recovery-${suffix}-${scenario.id}`.replace(/[^a-zA-Z0-9_.-]/g, "-");
  const worker = `${prefix}-worker`;
  const faultedApi = `${prefix}-api-faulted`;
  const recoveredApi = `${prefix}-api-recovered`;
  const repeatedApi = `${prefix}-api-repeated`;
  const volumes = ["authority", "control", "exchange", "sockets", "data", "sessions"].map(
    (name) => `${prefix}-${name}`,
  );
  const [authority, control, exchange, sockets, data, sessions] = volumes;
  const agentId = "api-projection-agent";
  for (const volume of volumes) {
    const created = await command(["volume", "create", volume]);
    if (created.status !== 0) throw new Error(created.stderr || "volume create failed");
  }

  const workerRunArgs = [
    "run", "--detach", "--name", worker,
    "--user", "10001:20000",
    "--read-only",
    "--network", "none",
    "--tmpfs", "/tmp:rw,size=32m,noexec,nosuid,nodev",
    "--security-opt", "no-new-privileges:true",
    "--cap-drop", "ALL",
    "--pids-limit", "64",
    "--memory", "512m",
    "--cpus", "0.5",
    "-e", "NODE_ENV=test",
    "-e", "COMMITGATE_TRANSITION_WORKER=enabled",
    "-e", `RECOVERY_AGENT_ID=${agentId}`,
    "-e", "TRANSITION_WORKER_WORKSPACE_ROOT=/var/lib/commitgate/workspaces",
    "-e", "TRANSITION_WORKER_CONTROL_ROOT=/var/lib/commitgate/control",
    "-e", "TRANSITION_WORKER_INBOX_ROOT=/var/lib/commitgate/exchange",
    "-e", "TRANSITION_WORKER_SOCKET=/run/commitgate/transition-worker.sock",
    "-e", `COMMITGATE_SOURCE_REVISION=${source.sourceRevision}`,
    "--mount", `source=${authority},target=/var/lib/commitgate/workspaces`,
    "--mount", `source=${control},target=/var/lib/commitgate/control`,
    "--mount", `source=${exchange},target=/var/lib/commitgate/exchange`,
    "--mount", `source=${sockets},target=/run/commitgate`,
    "--mount", `type=bind,src=${driver},dst=/app/recovery-docker-driver.mjs,readonly`,
    image,
  ];
  const apiRunArgs = (name, injectFault) => [
    "run", "--detach", "--name", name,
    "--user", "1000:1000",
    "--group-add", "20000",
    "--read-only",
    "--network", "none",
    "--tmpfs", "/tmp:rw,size=32m,noexec,nosuid,nodev",
    "--security-opt", "no-new-privileges:true",
    "--cap-drop", "ALL",
    "--pids-limit", "96",
    "--memory", "512m",
    "--cpus", "0.5",
    "-e", "NODE_ENV=test",
    "-e", "PROCESS_ROLE=api",
    "-e", "HOST=127.0.0.1",
    "-e", "PORT=3000",
    "-e", "APP_DATA_DIR=/app/data",
    "-e", "AGENT_WORKSPACE_ROOT=/logical-workspaces",
    "-e", "CODEX_HOME=/app/codex-home",
    "-e", "COMMITGATE_SESSION_VOLUME_ROOT=/app/codex-home",
    "-e", "COMMITGATE_ENABLED=true",
    "-e", "TRANSITION_AUTHORITY=worker",
    "-e", "TRANSITION_WORKER_SOCKET=/run/commitgate/transition-worker.sock",
    "-e", "COMMITGATE_EXCHANGE_ROOT=/exchange",
    "-e", "RUNTIME_PROVIDER=broker",
    "-e", "RUNTIME_BROKER_SOCKET=/run/commitgate/runtime-broker-unavailable.sock",
    "-e", "MODEL_PROVIDER=ark",
    "-e", "MODEL_ID=evaluator-model",
    "-e", `COMMITGATE_SOURCE_REVISION=${source.sourceRevision}`,
    ...(injectFault
      ? [
          "-e", "COMMITGATE_FAULT_INJECTION=true",
          "-e", "COMMITGATE_API_FAULT_POINT=API_PROJECTION_PENDING",
          "-e", `COMMITGATE_API_FAULT_AGENT_ID=${agentId}`,
          "-e", `COMMITGATE_API_FAULT_RUN_ID=${scenario.transitionId}`,
        ]
      : []),
    "--mount", `source=${data},target=/app/data`,
    "--mount", `source=${sessions},target=/app/codex-home`,
    "--mount", `source=${sockets},target=/run/commitgate`,
    "--mount", `type=bind,src=${driver},dst=/app/recovery-docker-driver.mjs,readonly`,
    apiImage,
  ];
  const inspectState = async () => {
    const inspected = await command([
      "run", "--rm", "--user", "0:0", "--network", "none",
      "-e", `RECOVERY_AGENT_ID=${agentId}`,
      "-e", "TRANSITION_WORKER_SOCKET=/run/commitgate/transition-worker.sock",
      "-e", "TRANSITION_WORKER_CONTROL_ROOT=/var/lib/commitgate/control",
      "-e", "API_DATA_FILE=/app/data/launchpad.json",
      "-e", `COMMITGATE_SOURCE_REVISION=${source.sourceRevision}`,
      "--mount", `source=${data},target=/app/data,readonly`,
      "--mount", `source=${control},target=/var/lib/commitgate/control,readonly`,
      "--mount", `source=${sockets},target=/run/commitgate`,
      "--mount", `type=bind,src=${driver},dst=/app/recovery-docker-driver.mjs,readonly`,
      apiImage,
      "node", "/app/recovery-docker-driver.mjs", "inspect-api-projection",
      scenario.transitionId,
    ], { timeout: 30_000 });
    if (inspected.status !== 0) throw new Error(inspected.stderr || inspected.stdout);
    return parseLastJson(inspected.stdout);
  };

  try {
    const initialized = await command([
      "run", "--rm", "--user", "0:0", "--network", "none",
      "--mount", `source=${authority},target=/var/lib/commitgate/workspaces`,
      "--mount", `source=${control},target=/var/lib/commitgate/control`,
      "--mount", `source=${exchange},target=/var/lib/commitgate/exchange`,
      "--mount", `source=${sockets},target=/run/commitgate`,
      "--mount", `source=${data},target=/app/data`,
      "--mount", `source=${sessions},target=/app/codex-home`,
      image,
      "sh", "-ec",
      "chown -R 10001:20000 /var/lib/commitgate/workspaces /var/lib/commitgate/control /var/lib/commitgate/exchange /run/commitgate && chmod 0770 /var/lib/commitgate/workspaces /var/lib/commitgate/control /var/lib/commitgate/exchange /run/commitgate && chown -R 1000:1000 /app/data /app/codex-home && chmod 0700 /app/data /app/codex-home",
    ], { timeout: 30_000 });
    if (initialized.status !== 0) throw new Error(initialized.stderr || initialized.stdout);

    const startedWorker = await command(workerRunArgs, { timeout: 30_000 });
    if (startedWorker.status !== 0) throw new Error(startedWorker.stderr || startedWorker.stdout);
    await waitForReady(worker);

    const seeded = await command([
      "run", "--rm", "--user", "0:0", "--network", "none",
      "-e", `RECOVERY_AGENT_ID=${agentId}`,
      "-e", "TRANSITION_WORKER_SOCKET=/run/commitgate/transition-worker.sock",
      "-e", "API_DATA_FILE=/app/data/launchpad.json",
      "-e", `COMMITGATE_SOURCE_REVISION=${source.sourceRevision}`,
      "--mount", `source=${data},target=/app/data`,
      "--mount", `source=${sockets},target=/run/commitgate`,
      "--mount", `type=bind,src=${driver},dst=/app/recovery-docker-driver.mjs,readonly`,
      apiImage,
      "node", "/app/recovery-docker-driver.mjs", "seed-api-projection",
      scenario.transitionId,
    ], { timeout: 60_000 });
    if (seeded.status !== 0) throw new Error(seeded.stderr || seeded.stdout);
    const seedState = parseLastJson(seeded.stdout);

    const faultStarted = await command(apiRunArgs(faultedApi, true), { timeout: 30_000 });
    if (faultStarted.status !== 0) throw new Error(faultStarted.stderr || faultStarted.stdout);
    const faultLogs = await waitForLogMarker(
      faultedApi,
      '"kind":"commitgate-api-projection-fault-injection"',
    );
    const killed = await command(["kill", "--signal", "KILL", faultedApi], { timeout: 10_000 });
    const stopped = await waitForState(faultedApi, ["exited", "dead"]);
    const crashObserved = killed.status === 0 && stopped?.exitCode === 137;
    await command(["rm", "--force", faultedApi], { timeout: 30_000 });

    const recoveredStart = await command(apiRunArgs(recoveredApi, false), { timeout: 30_000 });
    if (recoveredStart.status !== 0) throw new Error(recoveredStart.stderr || recoveredStart.stdout);
    await waitForApiReady(recoveredApi);
    const first = await inspectState();
    await command(["stop", "--time", "5", recoveredApi], { timeout: 15_000 });
    await command(["rm", "--force", recoveredApi], { timeout: 30_000 });

    const repeatedStart = await command(apiRunArgs(repeatedApi, false), { timeout: 30_000 });
    if (repeatedStart.status !== 0) throw new Error(repeatedStart.stderr || repeatedStart.stdout);
    await waitForApiReady(repeatedApi);
    const second = await inspectState();

    const assertions = {
      sigkillExit137: crashObserved,
      exactApiHookArmed:
        faultLogs.includes('"point":"API_PROJECTION_PENDING"') &&
        faultLogs.includes('"source":"startup-recovery"'),
      workerTerminalFactDurable:
        seedState.terminalReceipt?.decision === "COMMITTED" &&
        seedState.receiptProofPresent === true,
      runProjected:
        first.run?.status === "completed" &&
        first.run?.transactionStatus === "TERMINAL" &&
        first.run?.decision === "COMMITTED" &&
        first.run?.baseGeneration === 1 &&
        first.run?.nextGeneration === 2 &&
        first.run?.effectInvariantSatisfied === true,
      agentHeadProjected:
        first.agent?.status === "ready" &&
        first.agent?.activeRunLeaseId === null &&
        first.agent?.generation === 2 &&
        first.agent?.viewId === first.worker?.headViewId &&
        first.agent?.liveStateHash === first.worker?.headWorkspaceHash,
      sessionFenced:
        first.agent?.codexThreadId === null &&
        first.agent?.needsReconciliation === true,
      messageProjected:
        first.assistant?.authority === "AUTHORITATIVE" &&
        first.assistant?.viewId === first.worker?.headViewId,
      versionsProjected:
        first.versions?.length === 2 &&
        first.versions.at(-1)?.generation === 2 &&
        first.versions.at(-1)?.viewId === first.worker?.headViewId,
      proofAndEventConsistent:
        first.worker?.proofPresent === true &&
        first.worker?.proofValid === true &&
        first.worker?.proofTerminalEventBound === true,
      repeatedStartupIdempotent: first.databaseDigest === second.databaseDigest,
      workerFactsUnchanged:
        first.worker?.eventCount === second.worker?.eventCount &&
        first.worker?.lastEventDigest === second.worker?.lastEventDigest &&
        first.worker?.proofDigest === second.worker?.proofDigest &&
        first.worker?.projectionDigest === second.worker?.projectionDigest,
    };
    const status = Object.values(assertions).every(Boolean) ? "verified" : "failed";
    return {
      id: scenario.id,
      faultPoint: scenario.point,
      transitionId: scenario.transitionId,
      action: "api-startup-projection",
      status,
      containerExitCode: stopped?.exitCode ?? null,
      assertions,
      observed: {
        generation: first.agent?.generation ?? null,
        workspaceHash: first.worker?.headWorkspaceHash ?? null,
        versions: first.versions?.length ?? null,
        permitState: "CONSUMED",
        lastEventSequence: first.worker?.eventCount ?? null,
        lastEventDigest: first.worker?.lastEventDigest ?? null,
        databaseDigest: first.databaseDigest,
        repeatedDatabaseDigest: second.databaseDigest,
        proofDigest: first.worker?.proofDigest ?? null,
        sessionEpoch: first.agent?.sessionEpoch ?? null,
        messageAuthority: first.assistant?.authority ?? null,
      },
      faultLog: faultLogs.split(/\r?\n/)
        .filter((line) => line.includes("commitgate-api-projection-fault-injection"))
        .slice(-1)[0] ?? null,
    };
  } finally {
    for (const container of [faultedApi, recoveredApi, repeatedApi, worker]) {
      await command(["rm", "--force", container], { timeout: 30_000 });
    }
    for (const volume of volumes) await command(["volume", "rm", "--force", volume]);
  }
}

try {
  const available = await command(["info", "--format", "{{.ServerVersion}}"], { timeout: 15_000 });
  if (available.status !== 0) throw new Error(available.stderr || available.stdout || "container engine unavailable");
  if (!explicitWorkerImage) {
    const built = await command([
      "build", "-f", "Dockerfile.transition-worker",
      // Keep the evaluator image byte-identical to the product Compose image;
      // without this label Docker creates a config-only digest variant.
      "--label", "com.docker.compose.image.builder=classic",
      "-t", image, ".",
    ], { timeout: 10 * 60_000 });
    if (built.status !== 0) {
      throw new Error(built.stderr || built.stdout || "worker image build failed");
    }
  }
  const identity = await command(["image", "inspect", "--format", "{{.Id}}", image]);
  if (identity.status !== 0) {
    throw new Error(identity.stderr || identity.stdout || "worker image unavailable");
  }
  imageIdentity = identity.status === 0 ? identity.stdout.trim() : null;
  workerImageBuilt = true;

  for (const scenario of scenarios) {
    try {
      results.push(await evaluateScenario(scenario));
    } catch (error) {
      results.push({
        id: scenario.id,
        faultPoint: scenario.point,
        transitionId: scenario.transitionId,
        action: scenario.action,
        status: "failed",
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }
} catch (error) {
  environmentFailure = error instanceof Error ? error.message : String(error);
  for (const scenario of scenarios) {
    results.push({
      id: scenario.id,
      faultPoint: scenario.point,
      transitionId: scenario.transitionId,
      action: scenario.action,
      status: "unverified",
      reason: environmentFailure,
    });
  }
}

if (workerImageBuilt) {
  try {
    const builtApi = await command([
      "build", "-f", "Dockerfile.api-recovery-eval", "-t", apiImage, ".",
    ], { timeout: 10 * 60_000 });
    if (builtApi.status !== 0) {
      throw new Error(builtApi.stderr || builtApi.stdout || "API evaluator image build failed");
    }
    const identity = await command(["image", "inspect", "--format", "{{.Id}}", apiImage]);
    apiImageIdentity = identity.status === 0 ? identity.stdout.trim() : null;
    results.push(await evaluateApiProjectionScenario());
  } catch (error) {
    apiEnvironmentFailure = error instanceof Error ? error.message : String(error);
    results.push({
      id: "api-projection-pending",
      faultPoint: "API_PROJECTION_PENDING",
      transitionId: "api-projection-run",
      action: "api-startup-projection",
      status: "failed",
      error: apiEnvironmentFailure,
    });
  }
} else {
  apiEnvironmentFailure = environmentFailure ?? "transition-worker image unavailable";
  results.push({
    id: "api-projection-pending",
    faultPoint: "API_PROJECTION_PENDING",
    transitionId: "api-projection-run",
    action: "api-startup-projection",
    status: "unverified",
    reason: apiEnvironmentFailure,
  });
}

const verified = results.filter((result) => result.status === "verified").length;
const failed = results.filter((result) => result.status === "failed").length;
const unverified = results.filter((result) => result.status === "unverified").length;
const status = failed > 0 ? "failed" : unverified > 0 ? "unverified" : "verified";
const identity = executionIdentity(root, {
  environment: {
    ...process.env,
    COMMITGATE_TRANSITION_WORKER_IMAGE: image,
  },
});
const report = {
  schemaVersion: 1,
  kind: "docker-process-recovery-evaluation",
  generatedAt: new Date().toISOString(),
  status,
  source,
  containerEngine: engine,
  transitionWorkerImage: {
    reference: image,
    imageId: imageIdentity,
    imageDigest: imageIdentity,
  },
  transitionWorkerImageBuild: {
    performed: !explicitWorkerImage,
    source: explicitWorkerImage ? "caller-frozen-image" : "current-source-product-build",
  },
  apiEvaluatorImage: {
    reference: apiImage,
    imageId: apiImageIdentity,
    imageDigest: apiImageIdentity,
  },
  executionIdentity: {
    ...identity,
    transitionWorkerImage: {
      reference: image,
      imageId: imageIdentity,
      imageDigest: imageIdentity,
      status: /^sha256:[a-f0-9]{64}$/.test(imageIdentity ?? "")
        ? "verified"
        : "failed",
    },
    apiEvaluatorImage: {
      reference: apiImage,
      imageId: apiImageIdentity,
      imageDigest: apiImageIdentity,
      status: /^sha256:[a-f0-9]{64}$/.test(apiImageIdentity ?? "")
        ? "verified"
        : "failed",
    },
  },
  faultInjectionGate: {
    nodeEnv: "test",
    enabled: true,
    action: "SIGKILL",
    productionExposure: false,
  },
  metrics: {
    scenarios: results.length,
    verified,
    failed,
    unverified,
    crashRecoveryInvariantPassRate: results.length === 0 ? 0 : verified / results.length,
  },
  scenarios: results,
  crossReportCoverage: [
    {
      point: "AGENT_OR_VERIFIER_CONTAINER_RUNNING_AND_BROKER_RESTART",
      status: "covered-by-container-evaluator",
      evidenceFile: "eval/container-report.json",
      reason: "Broker-owned child SIGKILL and Broker-process restart reconciliation are exercised by the real container evaluator; this report isolates Worker/API transaction crash points.",
    },
  ],
  environmentFailure,
  apiEnvironmentFailure,
  evaluationRecords: results.map((scenario) => assertEvaluationRecord(evaluationRecord({
    source,
    provider: null,
    surface: "recovery",
    scenario: {
      id: `docker-recovery:${scenario.id}`,
      status: scenario.status,
      runId: scenario.transitionId,
      nextGeneration: scenario.observed?.generation,
      permitState: scenario.observed?.permitState,
      eventSequence: scenario.observed?.lastEventSequence,
      eventDigest: scenario.observed?.lastEventDigest,
    },
  }))),
};

const evidenceRoot = process.env.COMMITGATE_EVIDENCE_DIR
  ? path.resolve(process.env.COMMITGATE_EVIDENCE_DIR)
  : path.join(root, "eval", "evidence");
await mkdir(evidenceRoot, { recursive: true });
const reportPath = path.join(evidenceRoot, "docker-recovery-report.json");
await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
await command(["image", "rm", "--force", apiImage], { timeout: 60_000 });
// Keep the product Worker image available so later evidence commands inspect
// the exact digest exercised by this recovery matrix.
console.log(`${status}: Docker process recovery ${verified}/${results.length}`);
console.log(`report: ${reportPath}`);
if (status === "failed") process.exitCode = 1;
else if (status === "unverified") process.exitCode = 2;
