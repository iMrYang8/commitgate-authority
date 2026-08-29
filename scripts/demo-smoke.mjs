#!/usr/bin/env node
import { execFile, spawn } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { evidenceProvenance } from "./evidence-utils.mjs";

const execFileAsync = promisify(execFile);
const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
// A smoke run is an evaluator, not the user's durable demo deployment. Give
// it an isolated Compose project, volumes and networks so a previous local
// HEAD (or a deliberately damaged recovery fixture) cannot contaminate the
// clean-clone claim or be destroyed by smoke cleanup.
const smokeSuffix = `${process.pid}-${Date.now()}`;
const smokeProject = `commitgate-smoke-${smokeSuffix}`;
const subnetOctet = 64 + (process.pid % 128);
const smokeEnvironment = {
  ...process.env,
  COMMITGATE_COMPOSE_PROJECT: smokeProject,
  COMMITGATE_STACK_ID: smokeProject,
  COMMITGATE_DEFAULT_NETWORK: `${smokeProject}-default`,
  COMMITGATE_AGENT_SUBNET: `10.${subnetOctet}.0.0/24`,
  COMMITGATE_DEFAULT_SUBNET: `10.${subnetOctet}.1.0/24`,
};
const run = (args) => execFileAsync("npm", args, {
  cwd: root,
  env: smokeEnvironment,
  maxBuffer: 32 * 1024 * 1024,
});
const baseUrl = `http://127.0.0.1:${process.env.PUBLIC_PORT || process.env.PORT || "3000"}`;
const startupTimeoutMs = Number(process.env.COMMITGATE_DEMO_SMOKE_TIMEOUT_MS ?? "1200000");
if (!Number.isFinite(startupTimeoutMs) || startupTimeoutMs < 180_000) {
  throw new Error("COMMITGATE_DEMO_SMOKE_TIMEOUT_MS must be at least 180000");
}
let status = "failed";
let detail = "";
let demo = null;
let checks = [];
try {
  demo = spawn("npm", ["run", "demo"], {
    cwd: root,
    env: smokeEnvironment,
    stdio: ["ignore", "pipe", "pipe"],
    // npm -> shell -> demo-stack -> compose logs is a process tree. Keep it in
    // one group so the smoke evaluator can terminate the complete foreground
    // tree after validation instead of orphaning `compose logs --follow`.
    detached: process.platform !== "win32",
  });
  let output = "";
  demo.stdout?.on("data", (chunk) => { output = (output + chunk).slice(-32_768); });
  demo.stderr?.on("data", (chunk) => { output = (output + chunk).slice(-32_768); });
  // A clean clone has no cached Runtime/Broker/Worker/Relay/API layers. The
  // one-command contract includes those builds, so readiness must not fail
  // merely because dependency installation exceeds three minutes. This is an
  // evaluator timeout, not the three-minute narrated-video duration.
  const deadline = Date.now() + startupTimeoutMs;
  let ready = false;
  while (Date.now() < deadline) {
    ready = await fetch(`${baseUrl}/api/health`)
      .then((response) => response.ok)
      .catch(() => false);
    if (ready) break;
    if (demo.exitCode !== null) throw new Error(`demo exited early: ${output}`);
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  if (!ready) throw new Error(`demo readiness timed out: ${output}`);
  const token = (await readFile(path.join(root, ".demo-state", "secrets", "app_auth_token"), "utf8")).trim();
  const health = await fetch(`${baseUrl}/api/health`);
  const system = await fetch(`${baseUrl}/api/system`, {
    headers: { authorization: `Bearer ${token}` },
  });
  const systemBody = await system.json();
  // API health becomes ready before the foreground launcher completes its
  // preflight and demo-agent seed. Observe the complete one-command contract,
  // not merely the first healthy HTTP response.
  const seedDeadline = Date.now() + 60_000;
  let agents = null;
  let body = null;
  while (Date.now() < seedDeadline) {
    agents = await fetch(`${baseUrl}/api/agents`, {
      headers: { authorization: `Bearer ${token}` },
    });
    body = await agents.json();
    if (agents.ok && Array.isArray(body.agents) && body.agents.length > 0) break;
    if (demo.exitCode !== null) throw new Error(`demo exited before seeding: ${output}`);
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  if (!agents || !body) throw new Error("demo agent seed was not observable");
  checks = [
    { id: "health", passed: health.ok },
    { id: "system-api", passed: system.ok },
    { id: "agents-api", passed: agents.ok },
    { id: "commitgate-ready", passed: systemBody.commitGateReady === true },
    { id: "verifier-ready", passed: systemBody.verifierAvailable === true },
    { id: "worker-authority", passed: systemBody.transitionAuthority === "worker" },
    { id: "broker-runtime", passed: systemBody.runtimeProvider === "broker" },
    { id: "relay-model-access", passed: systemBody.modelAccessMode === "relay" },
    { id: "os-write-isolation", passed: systemBody.authorityWriteIsolation === "os-enforced" },
    { id: "manifest-v2", passed: systemBody.authorityManifestSchemaVersion === 2 },
    { id: "linux-strong-filesystem", passed: systemBody.authorityFilesystemProfile === "linux-strong" },
    {
      id: "pre-run-receipt-key-anchor",
      passed: /^[a-f0-9]{24}$/.test(systemBody.authorityReceiptSigningKeyId ?? ""),
    },
    { id: "demo-agent-seeded", passed: agents.ok && Array.isArray(body.agents) && body.agents.length > 0 },
  ];
  let statusCommand;
  try {
    statusCommand = await run(["run", "demo:status"]);
    const statusLines = statusCommand.stdout.trim().split(/\r?\n/).reverse();
    let statusBody = null;
    for (const line of statusLines) {
      try {
        const candidate = JSON.parse(line);
        if (candidate && typeof candidate === "object") {
          statusBody = candidate;
          break;
        }
      } catch {
        // Compose prints a table before the authenticated API JSON line.
      }
    }
    checks.push({
      id: "authenticated-demo-status",
      passed:
        statusBody?.transitionAuthority === "worker" &&
        statusBody?.runtimeProvider === "broker" &&
        statusBody?.commitGateReady === true,
      detail: statusBody
        ? {
            transitionAuthority: statusBody.transitionAuthority,
            runtimeProvider: statusBody.runtimeProvider,
            commitGateReady: statusBody.commitGateReady,
          }
        : "npm run demo:status returned no parseable system projection",
    });
  } catch (error) {
    checks.push({
      id: "authenticated-demo-status",
      passed: false,
      detail: error && typeof error === "object"
        ? String(error.stderr || error.stdout || error.message || error)
        : String(error),
    });
  }
  let topology;
  try {
    topology = await run(["run", "audit:topology"]);
  } catch (error) {
    const output = error && typeof error === "object"
      ? String(error.stderr || error.stdout || error.message || error)
      : String(error);
    checks.push({ id: "live-topology-audit", passed: false, detail: output.trim() });
    throw new Error(`audit:topology failed: ${output.trim()}`);
  }
  checks.push({
    id: "live-topology-audit",
    // `execFile` rejects on a non-zero exit. Reaching this point is therefore
    // part of the smoke-test result rather than a best-effort side effect.
    passed: true,
    detail: topology.stdout.trim().split("\n").at(-1) || "audit:topology exited 0",
  });
  status = checks.every((check) => check.passed) ? "verified" : "failed";
  const failedChecks = checks.filter((check) => !check.passed).map((check) => check.id);
  detail = [
    `health=${health.status}`,
    `system=${system.status}`,
    `agents=${agents.status}`,
    `commitGateReady=${systemBody.commitGateReady}`,
    `runtime=${systemBody.runtimeProvider}`,
    `modelAccess=${systemBody.modelAccessMode}`,
    `authority=${systemBody.transitionAuthority}`,
    `isolation=${systemBody.authorityWriteIsolation}`,
    `manifest=v${systemBody.authorityManifestSchemaVersion}`,
    `filesystem=${systemBody.authorityFilesystemProfile}`,
    `receiptKeyAnchor=${/^[a-f0-9]{24}$/.test(systemBody.authorityReceiptSigningKeyId ?? "") ? "present" : "missing-or-malformed"}`,
    `topology=verified`,
    ...(failedChecks.length > 0 ? [`failedChecks=${failedChecks.join(",")}`] : []),
  ].join(" ");
} catch (error) {
  status = "failed";
  detail = error instanceof Error ? error.message : String(error);
} finally {
  if (demo?.exitCode === null) {
    try {
      if (process.platform !== "win32" && demo.pid) process.kill(-demo.pid, "SIGTERM");
      else demo.kill("SIGTERM");
    } catch {
      // The foreground launcher may have exited between the check and signal.
    }
    await Promise.race([
      new Promise((resolve) => demo.once("exit", resolve)),
      new Promise((resolve) => setTimeout(resolve, 3_000)),
    ]);
  }
  // A smoke evaluator owns an isolated Compose project and must not leave its
  // authority/control/exchange volumes behind. The durable user-facing
  // `demo:down` deliberately preserves state, whereas `demo:reset` removes the
  // evaluator's uniquely named volumes after the process tree is stopped.
  await run(["run", "demo:reset"]).catch(() => undefined);
}
const report = {
  schemaVersion: 1,
  kind: "one-command-demo-smoke",
  generatedAt: new Date().toISOString(),
  status,
  source: await evidenceProvenance(root),
  baseUrl,
  startupTimeoutMs,
  isolatedComposeProject: smokeProject,
  checks,
  detail,
};
const reportPath = path.join(root, "eval", "evidence", "demo-smoke-report.json");
await mkdir(path.dirname(reportPath), { recursive: true });
await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");
console.log(`${status}: ${detail}`);
console.log(`report: ${reportPath}`);
process.exitCode = status === "verified" ? 0 : 1;
