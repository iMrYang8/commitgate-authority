#!/usr/bin/env node
import { execFileSync, spawnSync } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { evidenceProvenance, executionIdentity } from "./evidence-utils.mjs";
import { assertEvaluationRecord, evaluationRecord } from "./evaluation-record.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const source = await evidenceProvenance(root);
const sourceRevision = process.env.COMMITGATE_SOURCE_REVISION || source.sourceRevision;
if (!sourceRevision) throw new Error("FROZEN_SOURCE_REVISION_UNAVAILABLE");
const checks = [];
const add = (id, status, detail) => checks.push({ id, status, detail });
const composeProject = process.env.COMMITGATE_COMPOSE_PROJECT || "commitgate";
const compose = (...args) => spawnSync(
  "docker",
  ["compose", "--project-name", composeProject, ...args],
  {
    cwd: root,
    encoding: "utf8",
    env: {
      ...process.env,
      MODEL_ID: process.env.MODEL_ID || "topology-audit",
      COMMITGATE_SOURCE_REVISION: sourceRevision,
    },
  },
);

const config = compose("config");
add(
  "authority-v2-compose",
  config.status === 0 && /transition-worker:/.test(config.stdout) && /runtime-broker:/.test(config.stdout),
  config.status === 0 ? "Unified Compose declares Worker, Broker, Relay and API." : config.stderr.trim(),
);

const services = ["api", "transition-worker", "runtime-broker", "model-relay"];
const inspections = {};
let live = true;
for (const service of services) {
  const id = compose("ps", "-q", service).stdout.trim();
  if (!id) {
    live = false;
    add(`${service}-live`, "unverified", "Service is not running; run npm run demo first.");
    continue;
  }
  const record = JSON.parse(execFileSync("docker", ["inspect", id], { encoding: "utf8" }))[0];
  inspections[service] = {
    id,
    user: record?.Config?.User ?? "",
    readOnlyRootfs: record?.HostConfig?.ReadonlyRootfs === true,
    capDrop: record?.HostConfig?.CapDrop ?? [],
    envNames: (record?.Config?.Env ?? []).map((item) => String(item).split("=", 1)[0]).sort(),
    mounts: (record?.Mounts ?? []).map((mount) => ({
      type: mount.Type,
      name: mount.Name ?? null,
      source: mount.Source,
      destination: mount.Destination,
      rw: mount.RW,
    })),
    networks: Object.keys(record?.NetworkSettings?.Networks ?? {}).sort(),
  };
}

if (live) {
  const api = inspections.api;
  const worker = inspections["transition-worker"];
  const broker = inspections["runtime-broker"];
  const relay = inspections["model-relay"];
  const byDestination = (record, target) => record.mounts.find((mount) => mount.destination === target);
  const hasControl = (record) => record.mounts.some((mount) =>
    ["/authority", "/control", "/var/lib/commitgate/workspaces", "/var/lib/commitgate/control"]
      .includes(mount.destination),
  );

  const authorityMount = byDestination(api, "/authority");
  const controlMount = byDestination(api, "/control");
  add(
    "api-authority-control-read-only",
    authorityMount?.rw === false && controlMount?.rw === false ? "verified" : "failed",
    JSON.stringify({ authority: authorityMount, control: controlMount }),
  );
  for (const [id, target] of [["authority", "/authority"], ["control", "/control"]]) {
    const attempt = compose("exec", "-T", "api", "sh", "-c", `printf denied > ${target}/.api-write-probe`);
    const detail = `${attempt.stdout}\n${attempt.stderr}`.trim();
    add(
      `api-${id}-write-denied-live`,
      attempt.status !== 0 && /read-only|permission denied|operation not permitted/i.test(detail)
        ? "verified"
        : "failed",
      detail || `exit=${attempt.status}`,
    );
  }
  const privateKeyRead = compose(
    "exec",
    "-T",
    "api",
    "sh",
    "-c",
    "cat /control/signing/ed25519-private.pem >/dev/null",
  );
  const privateKeyReadDetail = `${privateKeyRead.stdout}\n${privateKeyRead.stderr}`.trim();
  add(
    "api-receipt-private-key-read-denied-live",
    privateKeyRead.status !== 0 && /permission denied|operation not permitted/i.test(privateKeyReadDetail)
      ? "verified"
      : "failed",
    privateKeyReadDetail || `exit=${privateKeyRead.status}`,
  );
  add(
    "worker-exclusive-authority-rw",
    byDestination(worker, "/var/lib/commitgate/workspaces")?.rw === true &&
      byDestination(worker, "/var/lib/commitgate/control")?.rw === true &&
      !hasControl(broker) && !hasControl(relay),
    "Worker is the only service with authority/control RW; Broker and Relay have neither mount.",
  );
  const workerHealthResult = compose(
    "exec",
    "-T",
    "transition-worker",
    "node",
    "apps/server/dist/transition-worker/cli.js",
    "health",
  );
  let workerHealth = null;
  try {
    workerHealth = JSON.parse(workerHealthResult.stdout);
  } catch {
    workerHealth = null;
  }
  add(
    "worker-linux-strong-manifest-v2",
    workerHealthResult.status === 0 &&
      workerHealth?.manifestSchemaVersion === 2 &&
      workerHealth?.filesystemProfile === "linux-strong"
      ? "verified"
      : "failed",
    workerHealth
      ? JSON.stringify({
          manifestSchemaVersion: workerHealth.manifestSchemaVersion,
          filesystemProfile: workerHealth.filesystemProfile,
        })
      : (workerHealthResult.stderr || workerHealthResult.stdout || "Worker health unavailable").trim(),
  );
  const workspaceIdentityResult = compose(
    "exec",
    "-T",
    "transition-worker",
    "node",
    "-e",
    "console.log(JSON.stringify({uid:process.getuid(),gid:process.getgid()}))",
  );
  const agentIdentityResult = compose(
    "exec",
    "-T",
    "runtime-broker",
    "node",
    "-e",
    "console.log(process.env.CONTAINER_USER||'')",
  );
  const brokerIdentityResult = compose(
    "exec",
    "-T",
    "runtime-broker",
    "node",
    "-e",
    "console.log(JSON.stringify({uid:process.getuid(),gid:process.getgid()}))",
  );
  let workspaceIdentity = null;
  let brokerIdentity = null;
  try {
    workspaceIdentity = JSON.parse(workspaceIdentityResult.stdout);
  } catch {
    workspaceIdentity = null;
  }
  try {
    brokerIdentity = JSON.parse(brokerIdentityResult.stdout);
  } catch {
    brokerIdentity = null;
  }
  add(
    "worker-broker-agent-artifact-identity-aligned",
    workspaceIdentityResult.status === 0 &&
      workspaceIdentity?.uid === 10001 &&
      workspaceIdentity?.gid === 20000 &&
      brokerIdentityResult.status === 0 &&
      brokerIdentity?.uid === 10001 &&
      brokerIdentity?.gid === 20002 &&
      agentIdentityResult.status === 0 &&
      agentIdentityResult.stdout.trim() === "10001:20000"
      ? "verified"
      : "failed",
    JSON.stringify({
      worker: workspaceIdentity,
      broker: brokerIdentity,
      agentUser: agentIdentityResult.stdout.trim(),
      boundary: "shared artifact UID; disjoint socket groups and mounts",
    }),
  );
  const socketOwners = services.filter((service) =>
    inspections[service].mounts.some((mount) => mount.destination === "/var/run/docker.sock"),
  );
  add(
    "docker-socket-only-broker",
    socketOwners.length === 1 && socketOwners[0] === "runtime-broker" ? "verified" : "failed",
    `holders=${socketOwners.join(",") || "none"}`,
  );
  const providerKeyHolders = services.filter((service) =>
    inspections[service].envNames.includes("MODEL_API_KEY") ||
    inspections[service].envNames.includes("MODEL_API_KEY_FILE"),
  );
  add(
    "provider-key-only-relay",
    providerKeyHolders.length === 1 && providerKeyHolders[0] === "model-relay" ? "verified" : "failed",
    `holders=${providerKeyHolders.join(",") || "none"}`,
  );
  const attestationKeyEnvHolders = services.filter((service) =>
    inspections[service].envNames.includes("BROKER_ATTESTATION_KEY") ||
    inspections[service].envNames.includes("BROKER_ATTESTATION_KEY_FILE"),
  );
  const attestationSecretMountHolders = services.filter((service) =>
    inspections[service].mounts.some(
      (mount) => mount.destination === "/run/secrets/broker_attestation_key",
    ),
  );
  const expectedAttestationHolders = ["runtime-broker", "transition-worker"];
  const apiHasAttestationCredential =
    api.envNames.includes("BROKER_ATTESTATION_KEY") ||
    api.envNames.includes("BROKER_ATTESTATION_KEY_FILE") ||
    api.mounts.some(
      (mount) => mount.destination === "/run/secrets/broker_attestation_key",
    );
  add(
    "broker-attestation-key-only-worker-and-broker",
    JSON.stringify(attestationKeyEnvHolders.sort()) ===
        JSON.stringify(expectedAttestationHolders) &&
      JSON.stringify(attestationSecretMountHolders.sort()) ===
        JSON.stringify(expectedAttestationHolders) &&
      !apiHasAttestationCredential
      ? "verified"
      : "failed",
    JSON.stringify({
      envFileHolders: attestationKeyEnvHolders,
      secretMountHolders: attestationSecretMountHolders,
      apiHasAttestationCredential,
    }),
  );
  add(
    "relay-no-workspace",
    !hasControl(relay) && !relay.mounts.some((mount) => /exchange|session/i.test(mount.destination)),
    "Relay has no workspace, control, exchange, or session mount.",
  );
  add(
    "broker-no-authority",
    !hasControl(broker),
    "Broker has exchange/session/check volumes and Docker socket, but no authority/control mount.",
  );
  const exchangeMount = byDestination(broker, "/var/lib/commitgate/exchange");
  const exchangeOwnershipScript = [
    "const s=require('node:fs').lstatSync('/var/lib/commitgate/exchange');",
    "console.log(JSON.stringify({uid:s.uid,gid:s.gid,mode:s.mode&0o777}));",
  ].join("");
  const workerExchangeOwnershipResult = compose(
    "exec",
    "-T",
    "transition-worker",
    "node",
    "-e",
    exchangeOwnershipScript,
  );
  const brokerExchangeOwnershipResult = compose(
    "exec",
    "-T",
    "runtime-broker",
    "node",
    "-e",
    exchangeOwnershipScript,
  );
  let workerExchangeOwnership = null;
  let brokerExchangeOwnership = null;
  try {
    workerExchangeOwnership = JSON.parse(workerExchangeOwnershipResult.stdout);
  } catch {
    workerExchangeOwnership = null;
  }
  try {
    brokerExchangeOwnership = JSON.parse(brokerExchangeOwnershipResult.stdout);
  } catch {
    brokerExchangeOwnership = null;
  }
  const expectedExchangeOwnership = { uid: 10001, gid: 20000, mode: 0o770 };
  add(
    "exchange-volume-owner-aligned",
    workerExchangeOwnershipResult.status === 0 &&
      brokerExchangeOwnershipResult.status === 0 &&
      [workerExchangeOwnership, brokerExchangeOwnership].every(
        (entry) => entry?.uid === expectedExchangeOwnership.uid &&
          entry?.gid === expectedExchangeOwnership.gid &&
          entry?.mode === expectedExchangeOwnership.mode,
      )
      ? "verified"
      : "failed",
    JSON.stringify({
      expected: expectedExchangeOwnership,
      worker: workerExchangeOwnership,
      broker: brokerExchangeOwnership,
      workerExit: workerExchangeOwnershipResult.status,
      brokerExit: brokerExchangeOwnershipResult.status,
    }),
  );
  const exchangeStat = compose(
    "exec",
    "-T",
    "runtime-broker",
    "node",
    "-e",
    [
      "const s=require('node:fs').statfsSync('/var/lib/commitgate/exchange',{bigint:true});",
      "console.log(JSON.stringify({type:s.type.toString(16),capacityBytes:(s.blocks*s.bsize).toString(),files:s.files.toString()}));",
    ].join(""),
  );
  let exchangeFilesystem = null;
  try {
    exchangeFilesystem = JSON.parse(exchangeStat.stdout);
  } catch {
    exchangeFilesystem = null;
  }
  const exchangeCapacity = Number(exchangeFilesystem?.capacityBytes ?? NaN);
  const exchangeInodes = Number(exchangeFilesystem?.files ?? NaN);
  add(
    "exchange-volume-kernel-bounded",
    exchangeMount?.type === "volume" &&
      exchangeStat.status === 0 &&
      exchangeFilesystem?.type === "1021994" &&
      Number.isFinite(exchangeCapacity) &&
      exchangeCapacity > 0 &&
      exchangeCapacity <= Number(process.env.COMMITGATE_EXCHANGE_BYTES ?? 536_870_912) &&
      Number.isFinite(exchangeInodes) &&
      exchangeInodes > 0 &&
      exchangeInodes <= Number(process.env.COMMITGATE_EXCHANGE_INODES ?? 100_000)
      ? "verified"
      : "failed",
    JSON.stringify({ mount: exchangeMount, statfs: exchangeFilesystem }),
  );
  const transitionSocketDestination = "/run/commitgate/transition";
  const brokerSocketDestination = "/run/commitgate/broker";
  const apiTransitionSocket = byDestination(api, transitionSocketDestination);
  const apiBrokerSocket = byDestination(api, brokerSocketDestination);
  const workerTransitionSocket = byDestination(worker, transitionSocketDestination);
  const brokerOwnSocket = byDestination(broker, brokerSocketDestination);
  add(
    "rpc-socket-volumes-separated",
    apiTransitionSocket?.rw === false &&
      apiBrokerSocket?.rw === false &&
      workerTransitionSocket?.rw === true &&
      brokerOwnSocket?.rw === true &&
      !byDestination(worker, brokerSocketDestination) &&
      !byDestination(broker, transitionSocketDestination) &&
      apiTransitionSocket.name !== apiBrokerSocket.name &&
      workerTransitionSocket.name === apiTransitionSocket.name &&
      brokerOwnSocket.name === apiBrokerSocket.name
      ? "verified"
      : "failed",
    JSON.stringify({
      apiTransitionSocket,
      apiBrokerSocket,
      workerTransitionSocket,
      brokerOwnSocket,
    }),
  );

  const brokerToWorker = compose(
    "exec",
    "-T",
    "runtime-broker",
    "node",
    "-e",
    [
      "const n=require('node:net');",
      `const s=n.connect('${transitionSocketDestination}/transition-worker.sock');`,
      "s.on('connect',()=>{console.error('UNEXPECTED_CONNECT');s.end();process.exit(42)});",
      "s.on('error',e=>{console.error(e.code||e.message);process.exit(['ENOENT','EACCES'].includes(e.code)?0:1)});",
    ].join(""),
  );
  add(
    "broker-cannot-connect-transition-worker-socket",
    brokerToWorker.status === 0 && /ENOENT|EACCES/.test(`${brokerToWorker.stdout}\n${brokerToWorker.stderr}`)
      ? "verified"
      : "failed",
    `${brokerToWorker.stdout}\n${brokerToWorker.stderr}`.trim() || `exit=${brokerToWorker.status}`,
  );

  for (const [id, socketPath] of [
    ["transition-worker", `${transitionSocketDestination}/transition-worker.sock`],
    ["runtime-broker", `${brokerSocketDestination}/runtime-broker.sock`],
  ]) {
    const apiConnect = compose(
      "exec",
      "-T",
      "api",
      "node",
      "-e",
      `const n=require('node:net'),s=n.connect('${socketPath}');s.on('connect',()=>{s.end();process.exit(0)});s.on('error',e=>{console.error(e.code||e.message);process.exit(1)});`,
    );
    add(
      `api-connects-${id}-socket`,
      apiConnect.status === 0 ? "verified" : "failed",
      `${apiConnect.stdout}\n${apiConnect.stderr}`.trim() || `exit=${apiConnect.status}`,
    );
  }
}

for (const check of checks) {
  if (typeof check.status === "boolean") check.status = check.status ? "verified" : "failed";
}
const status = checks.some((item) => item.status === "failed")
  ? "failed"
  : checks.some((item) => item.status === "unverified")
    ? "unverified"
    : "verified";
const identity = executionIdentity(root);
const report = {
  schemaVersion: 2,
  kind: "runtime-topology-audit",
  generatedAt: new Date().toISOString(),
  status,
  source,
  executionIdentity: identity,
  checks,
  inspections,
  evaluationRecords: checks.map((check) => assertEvaluationRecord(evaluationRecord({
    source,
    provider: identity.provider,
    executionIdentity: identity,
    surface: "topology",
    scenario: { id: check.id, status: check.status },
  }))),
  claimBoundary: "Live Docker mount and write-denial evidence for the Authority V2 process-isolation topology; it does not cover a host/root adversary.",
};
const reportPath = path.join(root, "eval", "evidence", "topology-report.json");
await mkdir(path.dirname(reportPath), { recursive: true });
await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n");
for (const item of checks) console.log(`${String(item.status).padEnd(10)} ${item.id}`);
console.log(`report: ${reportPath}`);
process.exitCode = status === "failed" ? 1 : 0;
