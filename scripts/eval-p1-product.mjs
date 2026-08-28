#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { evidenceProvenance, executionIdentity } from "./evidence-utils.mjs";
import { assertEvaluationRecord, evaluationRecord } from "./evaluation-record.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const read = (file) => readFile(path.join(root, file), "utf8");
const topologyReportPath = process.env.TOPOLOGY_REPORT_PATH
  ? path.resolve(process.env.TOPOLOGY_REPORT_PATH)
  : path.join(root, "eval", "evidence", "topology-report.json");
const checks = [];
const add = (id, status, detail) => checks.push({ id, status, detail });

const [config, factory, launcher, composeFile, worker, broker, service, runtime, topologyText] = await Promise.all([
  read("apps/server/src/config.ts"),
  read("apps/server/src/runner-factory.ts"),
  read("scripts/demo-stack.sh"),
  read("docker-compose.yml"),
  read("apps/server/src/transition-worker/worker.ts"),
  read("apps/server/src/runtime-broker/server.ts"),
  read("apps/server/src/agent-service.ts"),
  read("apps/server/src/commitgate-runtime.ts"),
  readFile(topologyReportPath, "utf8").catch(() => ""),
]);
const topology = topologyText ? JSON.parse(topologyText) : null;

add(
  "production-runtime-broker-required",
  /Production CommitGate requires RUNTIME_PROVIDER=broker/.test(config) &&
    /docker compose/.test(launcher) && /RUNTIME_PROVIDER: broker/.test(composeFile)
    ? "verified" : "failed",
  "Production config and one-command launcher select the Unix RPC Runtime Broker.",
);
add(
  "api-runner-uses-broker-client",
  /new RuntimeBrokerRunner/.test(factory) ? "verified" : "failed",
  "RunnerFactory routes production Agent execution through RuntimeBrokerRunner.",
);
add(
  "broker-path-confinement",
  /BROKER_OPAQUE_WORKSPACE_REF_REQUIRED/.test(broker) ? "verified" : "failed",
  "Broker accepts only Worker-bound opaque candidate volume references.",
);
add(
  "transition-worker-append-only-engine",
  /class TransitionWorker/.test(worker) && /this\.log\.append/.test(worker) ? "verified" : "failed",
  "Transition worker implementation and append-only projection machinery are present.",
);
add(
  "transition-worker-default-authority",
  /createWorkerCommitGateComponents/.test(factory) &&
    /WorkerTransitionAuthorityClient/.test(runtime) &&
    /commitGate\.authority\.initializeAgent/.test(service) &&
    /commitGate\.authority\.applyRollback/.test(service)
    ? "verified" : "failed",
  "Production RunnerFactory and AgentService use Worker RPC for initialize, run transitions, and rollback.",
);
add(
  "api-authoritative-volume-read-only",
  topology?.status === "verified" &&
    topology.checks?.some((item) => item.id === "api-authority-write-denied-live" && item.status === "verified") &&
    topology.checks?.some((item) => item.id === "api-control-write-denied-live" && item.status === "verified")
    ? "verified" : "unverified",
  topology?.status === "verified"
    ? "Live Docker exec probes returned EROFS for API writes to both Authority and Control."
    : "Run npm run demo and npm run audit:topology to collect live EROFS evidence.",
);

const test = spawnSync("npm", ["run", "test", "-w", "@launchpad/server", "--", "src/runtime-broker/rpc.test.ts", "src/transition-worker/worker.test.ts"], {
  cwd: root,
  env: process.env,
  encoding: "utf8",
  maxBuffer: 16 * 1024 * 1024,
});
add(
  "broker-worker-tests",
  test.status === 0 ? "verified" : "failed",
  (test.stdout + test.stderr).slice(-8_192),
);

const status = checks.some((item) => item.status === "failed")
  ? "failed"
  : checks.some((item) => item.status === "unverified")
    ? "unverified"
    : "verified";
const source = await evidenceProvenance(root);
const identity = executionIdentity(root);
const report = {
  schemaVersion: 1,
  kind: "p1-product-authority-evaluation",
  generatedAt: new Date().toISOString(),
  status,
  source,
  executionIdentity: identity,
  checks,
  evaluationRecords: checks.map((check) => assertEvaluationRecord(evaluationRecord({
    source,
    provider: identity.provider,
    executionIdentity: identity,
    surface: "p1-product",
    scenario: { id: check.id, status: check.status },
  }))),
  claimBoundary: "Authority V2 covers Linux Docker process isolation, single-Agent serial filesystem transitions, and process kill/restart; not host/root adversaries or external effects.",
};
const reportPath = path.join(root, "eval", "evidence", "p1-product-report.json");
await mkdir(path.dirname(reportPath), { recursive: true });
await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n");
for (const item of checks) console.log(`${item.status.padEnd(10)} ${item.id}`);
console.log(`report: ${reportPath}`);
process.exitCode = status === "failed" ? 1 : 0;
