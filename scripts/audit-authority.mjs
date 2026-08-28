#!/usr/bin/env node
import { readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { evidenceProvenance, executionIdentity } from "./evidence-utils.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const sourceRoot = path.join(root, "apps", "server", "src");
const reportPath = path.join(root, "eval", "authority-report.json");
const mutationPattern = /\b(writeFile|appendFile|copyFile|cp|rename|rm|mkdir|chmod|symlink|link)\s*\(/g;
const productionFiles = [];

async function walk(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) await walk(absolute);
    else if (entry.isFile() && entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts")) {
      productionFiles.push(absolute);
    }
  }
}
await walk(sourceRoot);

const inventory = [];
const violations = [];
const allowedLowLevelWriters = new Set([
  "apps/server/src/workspace.ts",
  "apps/server/src/workspace-transition-writer.ts",
  "apps/server/src/commitgate/workspace-transaction.ts",
  "apps/server/src/commitgate/recovery.ts",
  "apps/server/src/commitgate/file-ops.ts",
]);
const isAuthorityImplementation = (relative) =>
  allowedLowLevelWriters.has(relative) || relative.startsWith("apps/server/src/transition-worker/");

for (const absolute of productionFiles.sort()) {
  const relative = path.relative(root, absolute).split(path.sep).join("/");
  const source = await readFile(absolute, "utf8");
  for (const [index, line] of source.split(/\r?\n/).entries()) {
    mutationPattern.lastIndex = 0;
    for (const match of line.matchAll(mutationPattern)) {
      inventory.push({
        file: relative,
        line: index + 1,
        operation: match[1],
        classification: isAuthorityImplementation(relative)
          ? "authority-implementation"
          : "non-authoritative-or-control-state",
      });
      if (
        /(agent\.workspacePath|persistentPath|authoritative|workspaceRoot)/.test(line) &&
        !isAuthorityImplementation(relative)
      ) {
        violations.push({
          file: relative,
          line: index + 1,
          rule: "persistent-path-fs-mutation-outside-authority-implementation",
          operation: match[1],
        });
      }
    }
  }

  if (relative !== "apps/server/src/workspace-transition-writer.ts" && relative !== "apps/server/src/workspace.ts") {
    for (const [index, line] of source.split(/\r?\n/).entries()) {
      if (/\.(create|writeInstructions|archive)\s*\(/.test(line) && /workspaces?\b/.test(line)) {
        violations.push({
          file: relative,
          line: index + 1,
          rule: "workspace-manager-mutation-bypasses-transition-writer",
        });
      }
    }
  }

  if (
    relative !== "apps/server/src/workspace-transition-writer.ts" &&
    /new\s+WorkspaceTransaction\s*\(/.test(source)
  ) {
    const lines = source.split(/\r?\n/);
    lines.forEach((line, index) => {
      if (new RegExp("new\\s+WorkspaceTransaction\\s*\\(").test(line)) {
        violations.push({
          file: relative,
          line: index + 1,
          rule: "workspace-transaction-constructed-outside-transition-writer",
        });
      }
    });
  }

  if (
    relative !== "apps/server/src/workspace-transition-writer.ts" &&
    relative !== "apps/server/src/commitgate/recovery.ts" &&
    /\brecoverCommitGate\s*\(/.test(source)
  ) {
    source.split(/\r?\n/).forEach((line, index) => {
      if (/\brecoverCommitGate\s*\(/.test(line)) {
        violations.push({
          file: relative,
          line: index + 1,
          rule: "startup-recovery-bypasses-transition-writer",
        });
      }
    });
  }
}

const requiredAuthoritySurface = [
  "createAgentWorkspace",
  "materializeCandidate",
  "sealProposal",
  "regeneratePlatformState",
  "archiveAgent",
  "applyPromotion",
  "applyRollback",
  "recoverTransition",
  "applyRepair",
];
const writerPath = path.join(sourceRoot, "workspace-transition-writer.ts");
let writerSource = "";
try {
  writerSource = await readFile(writerPath, "utf8");
} catch {}
const surface = requiredAuthoritySurface.map((method) => ({
  method,
  status: new RegExp(`\\b${method}\\s*\\(`).test(writerSource) ? "verified" : "unverified",
}));

const status = violations.length > 0
  ? "failed"
  : surface.some((entry) => entry.status !== "verified")
    ? "unverified"
    : "verified";
const report = {
  schemaVersion: 2,
  kind: "persistent-authority-static-audit",
  generatedAt: new Date().toISOString(),
  status,
  source: await evidenceProvenance(root),
  executionIdentity: executionIdentity(root),
  scannedRoot: "apps/server/src",
  scannedProductionFiles: productionFiles.length,
  filesystemMutationCallsites: inventory.length,
  inventory,
  authoritySurface: surface,
  unauthorizedPersistentWriteCount: violations.length,
  violations,
  method:
    "Static callsite inventory plus explicit checks for raw persistent-path writes, WorkspaceManager mutation bypasses, transaction construction, and startup recovery outside WorkspaceTransitionWriter.",
  limitation:
    "This source audit is a mechanical CI fence, not an OS permission proof. P1 requires an independently mounted worker volume and UID evidence.",
};
await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");
console.log(`${status}: ${inventory.length} mutation callsite(s), ${violations.length} unauthorized persistent write point(s)`);
for (const violation of violations) {
  console.log(`failed     ${violation.file}:${violation.line} ${violation.rule}`);
}
for (const entry of surface) console.log(`${entry.status.padEnd(10)} writer.${entry.method}`);
console.log(`authority report: ${reportPath}`);
process.exitCode = status === "verified" ? 0 : status === "unverified" ? 2 : 1;
