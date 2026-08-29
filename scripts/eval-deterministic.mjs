#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { evidenceProvenance, executionIdentity } from "./evidence-utils.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const evidenceDir = path.join(root, "eval", "evidence");
const rawPath = path.join(evidenceDir, "vitest-deterministic.json");
const reportPath = path.join(root, "eval", "deterministic-report.json");
await mkdir(evidenceDir, { recursive: true });

const args = [
  "run",
  "test",
  "-w",
  "@launchpad/server",
  "--",
  "--reporter=json",
  `--outputFile=${rawPath}`,
];
const started = Date.now();
const result = spawnSync("npm", args, {
  cwd: root,
  env: process.env,
  encoding: "utf8",
  maxBuffer: 16 * 1024 * 1024,
});
if (result.stdout) process.stdout.write(result.stdout);
if (result.stderr) process.stderr.write(result.stderr);

let raw = {};
try {
  raw = JSON.parse(await readFile(rawPath, "utf8"));
} catch {
  raw = {};
}
const assertions = (raw.testResults ?? []).flatMap((suite) => suite.assertionResults ?? []);
const passingNames = assertions
  .filter((assertion) => assertion.status === "passed")
  .map((assertion) => assertion.fullName || assertion.title || "");
const claim = (id, patterns) => {
  const matching = passingNames.filter((name) => patterns.some((pattern) => name.includes(pattern)));
  return {
    id,
    status: patterns.every((pattern) => passingNames.some((name) => name.includes(pattern)))
      ? "verified"
      : "failed",
    evidence: matching,
  };
};
const claims = [
  claim("canonical-manifest-and-policy", ["independent of mtime", "changes for content"]),
  claim("valid-candidate-commit", ["promotes a valid candidate"]),
  claim("protected-change-quarantine", ["quarantines protected changes"]),
  claim("trusted-check-not-candidate-test", ["trusted check exit evidence"]),
  claim("persistent-conflict", ["persistent-state conflict"]),
  claim("crash-recovery", [
    "crash before database acknowledgement",
    "recovers forward after product DB commit",
    "database-committed rollback",
    "no-op promotion when the database still points",
    "same-snapshot rollback when the database head event was not advanced",
    "restores the backup when the staging rename fails",
    "raises recovery-required when both staging rename and backup restore fail",
    "leaves startup recovery evidence when the pending journal write fails after swap",
    "recovery-locks a completed swap whose pending journal write failed",
    "keeps an in-memory recovery lock when consecutive DB failures cannot persist it",
  ]),
  claim("session-reconciliation", ["fresh reconciliation session"]),
  claim("append-only-rollback", ["new ROLLBACK event"]),
  claim("database-failure-rollback", [
    "product database commit fails",
    "rollback database commit fails",
    "version projection fails",
  ]),
  claim("fail-closed-evidence", [
    "missing verifier exit evidence",
    "PASS without exit zero and duplicate results",
    "verifier image or trusted context drifts after checks",
  ]),
  claim("cancellation", [
    "cancels an active decorated runner",
    "verifier-stage cancellation",
    "candidate preparation is in flight",
    "preserves a pending receipt and recovery-locks",
  ]),
  claim("orphan-cleanup", ["cleans orphan candidate and verify"]),
  claim("receipt-redaction", [
    "redacts credential-shaped verifier output",
    "exact credential bytes",
  ]),
  claim("snapshot-pruning", [
    "keeps pruned metadata",
    "retains the parent snapshot until a staged rollback",
  ]),
  claim("v1-to-v2-migration", [
    "migrates a version 1 database",
    "generic trusted sanity check compatible with a v1 workspace",
  ]),
  claim("verifier-argument-isolation", ["mounts an immutable proposal and checks bundle with an isolated scratch"]),
  claim("promotion-finalization-atomicity", ["first promoted receipt write fails"]),
  claim("rollback-operation-lock", [
    "blocks stop and delete while a rollback",
    "locks the Agent until startup recovery resolves rollback acknowledgement failure",
  ]),
  claim("transaction-admission-lock", [
    "keeps all mutation admission locked until commit acknowledgement finishes",
    "keeps all mutation admission locked until rollback acknowledgement finishes",
    "reserves delete across cancellation and archive awaits",
    "reserves configuration mutation through the platform instruction write",
  ]),
  claim("recovery-corrupt-journal", [
    "corrupt journal as manual intervention",
    "marks only the affected Agent error for an invalid recovery policy",
  ]),
];
const overallPassed = result.status === 0 && raw.success !== false;
const report = {
  schemaVersion: 1,
  kind: "deterministic-evaluation",
  generatedAt: new Date().toISOString(),
  durationMs: Date.now() - started,
  status: overallPassed && claims.every((item) => item.status === "verified")
    ? "verified"
    : "failed",
  source: await evidenceProvenance(root),
  executionIdentity: executionIdentity(root),
  provenance: {
    runner: "Vitest + FakeRunner/function verifier + real local filesystem",
    realProviderRequest: false,
    containerExecution: false,
    claimBoundary:
      "This report verifies deterministic middleware semantics; it is not evidence of a real Provider request.",
  },
  testFiles: raw.testResults?.length ?? null,
  tests: {
    total: raw.numTotalTests ?? assertions.length,
    passed: raw.numPassedTests ?? passingNames.length,
    failed: raw.numFailedTests ?? null,
  },
  claims,
  evidenceFiles: [path.relative(root, rawPath)],
};
await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");
console.log(`deterministic report: ${reportPath}`);
process.exitCode = report.status === "verified" ? 0 : 1;
