#!/usr/bin/env node
import { execFileSync, spawnSync } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { evidenceProvenance, executionIdentity } from "./evidence-utils.mjs";
import { assertEvaluationRecord, evaluationRecord } from "./evaluation-record.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const checks = [];
const add = (id, status, detail) => checks.push({ id, status, detail });
const compose = (...args) => spawnSync(
  "docker",
  ["compose", "--project-name", "commitgate", ...args],
  {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, MODEL_ID: process.env.MODEL_ID || "topology-audit" },
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
  add(
    "worker-exclusive-authority-rw",
    byDestination(worker, "/var/lib/commitgate/workspaces")?.rw === true &&
      byDestination(worker, "/var/lib/commitgate/control")?.rw === true &&
      !hasControl(broker) && !hasControl(relay),
    "Worker is the only service with authority/control RW; Broker and Relay have neither mount.",
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
}

for (const check of checks) {
  if (typeof check.status === "boolean") check.status = check.status ? "verified" : "failed";
}
const status = checks.some((item) => item.status === "failed")
  ? "failed"
  : checks.some((item) => item.status === "unverified")
    ? "unverified"
    : "verified";
const source = await evidenceProvenance(root);
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
