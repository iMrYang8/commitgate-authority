#!/usr/bin/env node
import { execFile } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { evidenceProvenance, executionIdentity } from "./evidence-utils.mjs";
import { assertEvaluationRecord, evaluationRecord } from "./evaluation-record.mjs";

const execFileAsync = promisify(execFile);
const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const engine = process.env.CONTAINER_ENGINE || "docker";
const image = `commitgate-linux-fs-eval:${process.pid}`;
let output = "";
let status = "failed";
try {
  await execFileAsync(engine, ["build", "-f", "Dockerfile.linux-eval", "-t", image, "."], {
    cwd: root,
    maxBuffer: 16 * 1024 * 1024,
  });
  const result = await execFileAsync(engine, [
    "run", "--rm", "--read-only", "--tmpfs", "/tmp:size=128m", image,
  ], { cwd: root, maxBuffer: 16 * 1024 * 1024 });
  output = result.stdout + result.stderr;
  const plainOutput = output.replace(/\u001b\[[0-9;]*m/g, "");
  status = /Test Files\s+4 passed/.test(plainOutput) && /Tests\s+17 passed/.test(plainOutput)
    ? "verified"
    : "failed";
} catch (error) {
  output = String(error?.stdout ?? "") + String(error?.stderr ?? "") + String(error?.message ?? error);
} finally {
  await execFileAsync(engine, ["image", "rm", "--force", image]).catch(() => undefined);
}
const source = await evidenceProvenance(root);
const identity = executionIdentity(root);
const report = {
  schemaVersion: 1,
  kind: "linux-filesystem-closure",
  generatedAt: new Date().toISOString(),
  status,
  source,
  executionIdentity: identity,
  platform: "linux-container",
  tests: [
    "transition-worker/filesystem.test.ts",
    "transition-worker/rpc.test.ts",
    "runtime-broker/rpc.test.ts",
    "commitgate/manifest.test.ts",
  ],
  output: output.slice(-32_768),
  evaluationRecords: [assertEvaluationRecord(evaluationRecord({
    source,
    provider: identity.provider,
    executionIdentity: identity,
    surface: "filesystem",
    scenario: { id: "linux-filesystem-closure", status },
  }))],
};
const reportPath = path.join(root, "eval", "evidence", "linux-filesystem-report.json");
await mkdir(path.dirname(reportPath), { recursive: true });
await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");
console.log(`${status}: Linux filesystem closure`);
console.log(`report: ${reportPath}`);
process.exitCode = status === "verified" ? 0 : 1;
