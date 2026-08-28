#!/usr/bin/env node
import { execFile, spawn } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { evidenceProvenance } from "./evidence-utils.mjs";

const execFileAsync = promisify(execFile);
const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const run = (args) => execFileAsync("npm", args, { cwd: root, maxBuffer: 32 * 1024 * 1024 });
let status = "failed";
let detail = "";
let demo = null;
try {
  demo = spawn("npm", ["run", "demo"], {
    cwd: root,
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
    // npm -> shell -> demo-stack -> compose logs is a process tree. Keep it in
    // one group so the smoke evaluator can terminate the complete foreground
    // tree after validation instead of orphaning `compose logs --follow`.
    detached: process.platform !== "win32",
  });
  let output = "";
  demo.stdout?.on("data", (chunk) => { output = (output + chunk).slice(-32_768); });
  demo.stderr?.on("data", (chunk) => { output = (output + chunk).slice(-32_768); });
  const deadline = Date.now() + 180_000;
  let ready = false;
  while (Date.now() < deadline) {
    ready = await fetch("http://127.0.0.1:3000/api/health")
      .then((response) => response.ok)
      .catch(() => false);
    if (ready) break;
    if (demo.exitCode !== null) throw new Error(`demo exited early: ${output}`);
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  if (!ready) throw new Error(`demo readiness timed out: ${output}`);
  const token = (await readFile(path.join(root, ".demo-state", "secrets", "app_auth_token"), "utf8")).trim();
  const health = await fetch("http://127.0.0.1:3000/api/health");
  const system = await fetch("http://127.0.0.1:3000/api/system", {
    headers: { authorization: `Bearer ${token}` },
  });
  const systemBody = await system.json();
  const agents = await fetch("http://127.0.0.1:3000/api/agents", {
    headers: { authorization: `Bearer ${token}` },
  });
  const body = await agents.json();
  status = health.ok && system.ok && agents.ok && systemBody.runtimeProvider === "broker" &&
    systemBody.modelAccessMode === "relay" && systemBody.transitionAuthority === "worker" &&
    systemBody.authorityWriteIsolation === "os-enforced" &&
    Array.isArray(body.agents) && body.agents.length > 0
    ? "verified"
    : "failed";
  detail = `health=${health.status} system=${system.status} agents=${agents.status} runtime=${systemBody.runtimeProvider} modelAccess=${systemBody.modelAccessMode} authority=${systemBody.transitionAuthority} isolation=${systemBody.authorityWriteIsolation}`;
  await run(["run", "audit:topology"]);
} catch (error) {
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
  await run(["run", "demo:down"]).catch(() => undefined);
}
const report = {
  schemaVersion: 1,
  kind: "one-command-demo-smoke",
  generatedAt: new Date().toISOString(),
  status,
  source: await evidenceProvenance(root),
  detail,
};
const reportPath = path.join(root, "eval", "evidence", "demo-smoke-report.json");
await mkdir(path.dirname(reportPath), { recursive: true });
await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");
console.log(`${status}: ${detail}`);
console.log(`report: ${reportPath}`);
process.exitCode = status === "verified" ? 0 : 1;
