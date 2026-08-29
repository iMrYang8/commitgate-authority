#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { evidenceProvenance, executionIdentity } from "./evidence-utils.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const evidenceDir = path.join(root, "eval", "evidence");
await mkdir(evidenceDir, { recursive: true });

const commands = [
  ["npm", ["run", "typecheck"]],
  ["npm", ["run", "test"]],
  ["npm", ["run", "test:evaluator-cleanup"]],
  ["npm", ["run", "test:evidence-provenance"]],
  ["npm", ["run", "test:release-contracts"]],
  ["npm", ["run", "build"]],
];
const results = [];

function parseTestSummary(output) {
  const plain = output.replace(/\u001b\[[0-9;]*m/g, "");
  const vitestFiles = /Test Files\s+(\d+)\s+passed(?:\s+\|\s+(\d+)\s+failed)?/.exec(plain);
  const vitestTests = /Tests\s+(\d+)\s+passed(?:\s+\|\s+(\d+)\s+failed)?(?:\s+\|\s+(\d+)\s+skipped)?/.exec(plain);
  if (vitestTests) {
    const passed = Number(vitestTests[1]);
    const failed = Number(vitestTests[2] ?? 0);
    const skipped = Number(vitestTests[3] ?? 0);
    return {
      framework: "vitest",
      filesPassed: Number(vitestFiles?.[1] ?? 0),
      filesFailed: Number(vitestFiles?.[2] ?? 0),
      passed,
      failed,
      skipped,
      total: passed + failed + skipped,
    };
  }
  const tapTests = /(?:^|\n)(?:ℹ\s+)?tests\s+(\d+)\s*(?:\n|$)/.exec(plain);
  const tapPassed = /(?:^|\n)(?:ℹ\s+)?pass\s+(\d+)\s*(?:\n|$)/.exec(plain);
  const tapFailed = /(?:^|\n)(?:ℹ\s+)?fail\s+(\d+)\s*(?:\n|$)/.exec(plain);
  const tapSkipped = /(?:^|\n)(?:ℹ\s+)?skipped\s+(\d+)\s*(?:\n|$)/.exec(plain);
  if (tapTests && tapPassed && tapFailed && tapSkipped) {
    return {
      framework: "node-test",
      filesPassed: null,
      filesFailed: null,
      passed: Number(tapPassed[1]),
      failed: Number(tapFailed[1]),
      skipped: Number(tapSkipped[1]),
      total: Number(tapTests[1]),
    };
  }
  return null;
}

for (const [command, args] of commands) {
  const started = Date.now();
  const result = spawnSync(command, args, {
    cwd: root,
    env: process.env,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  results.push({
    command: [command, ...args].join(" "),
    exitCode: result.status,
    durationMs: Date.now() - started,
    status: result.status === 0 ? "verified" : "failed",
    testSummary: parseTestSummary(output),
  });
  if (result.status !== 0) break;
}

const testResults = results.filter((item) => item.testSummary !== null);
const aggregateTestSummary = testResults.length === 0
  ? null
  : {
      commands: testResults.length,
      passed: testResults.reduce((sum, item) => sum + item.testSummary.passed, 0),
      failed: testResults.reduce((sum, item) => sum + item.testSummary.failed, 0),
      skipped: testResults.reduce((sum, item) => sum + item.testSummary.skipped, 0),
      total: testResults.reduce((sum, item) => sum + item.testSummary.total, 0),
    };

const report = {
  schemaVersion: 1,
  kind: "baseline-regression-check",
  generatedAt: new Date().toISOString(),
  node: process.version,
  source: await evidenceProvenance(root),
  executionIdentity: executionIdentity(root),
  testSummary: aggregateTestSummary,
  status: results.length === commands.length && results.every((item) => item.status === "verified")
    ? "verified"
    : "failed",
  results,
};
await writeFile(
  path.join(evidenceDir, "check-report.json"),
  JSON.stringify(report, null, 2) + "\n",
  "utf8",
);
console.log(`check report: ${path.join(evidenceDir, "check-report.json")}`);
process.exitCode = report.status === "verified" ? 0 : 1;
