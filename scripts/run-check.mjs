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
  ["npm", ["run", "build"]],
];
const results = [];

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
  results.push({
    command: [command, ...args].join(" "),
    exitCode: result.status,
    durationMs: Date.now() - started,
    status: result.status === 0 ? "verified" : "failed",
  });
  if (result.status !== 0) break;
}

const report = {
  schemaVersion: 1,
  kind: "baseline-regression-check",
  generatedAt: new Date().toISOString(),
  node: process.version,
  source: await evidenceProvenance(root),
  executionIdentity: executionIdentity(root),
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
