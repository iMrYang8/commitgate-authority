#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { evidenceProvenance, executionIdentity } from "./evidence-utils.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const reportPath = path.join(root, "eval", "evidence", "documentation-review.json");
const source = await evidenceProvenance(root);
const reviewerIndependent =
  process.env.COMMITGATE_INDEPENDENT_REVIEW === "1" &&
  source.workingTreeCleanAtCapture === true;

const documents = {
  README: await readFile(path.join(root, "README.md"), "utf8"),
  architecture: await readFile(path.join(root, "docs", "ARCHITECTURE.md"), "utf8"),
  "three-minute-script": await readFile(
    path.join(root, "docs", "DEMO_3_MINUTES.md"),
    "utf8",
  ),
  limitations: await readFile(path.join(root, "docs", "LIMITATIONS.md"), "utf8"),
};

const requirements = {
  README: [
    /one-shot, evidence-bound capability/i,
    /pre-effect admission transaction for\s+filesystem state/i,
    /Ark \/ ModelArk.*official competition path/is,
    /OpenRouter.*alternate-provider path/is,
    /\*\*10\/10\*\* browser steps/i,
    /old\s+repository `100\/100`[\s\S]{0,320}not\s+an organizer score/i,
  ],
  architecture: [
    /interface StateViewRef/,
    /interface SealedProposal/,
    /EvaluationContextHash/,
    /one-shot `PromotionPermit`/,
    /P1 hardened` is not\s+claimed/i,
  ],
  "three-minute-script": [
    /## 0:00–0:20/,
    /## 0:20–1:05/,
    /## 1:05–1:45/,
    /## 1:45–2:15/,
    /## 2:15–2:40/,
    /## 2:40–3:00/,
    /npm run demo:verify-video/,
    /POST \/api\/runs\/:id\/commitgate\/promotion-attempts/i,
    /P1 hardened/i,
    /process kill\/restart/i,
  ],
  limitations: [
    /filesystem effects under the authoritative Agent workspace/i,
    /process kill\/restart recovery/i,
    /not power-loss durability/i,
    /not product-wired/i,
    /OpenRouter evidence must never be reported as `realModelArk`/i,
    /current machine report[\s\S]{0,220}official Ark[\s\S]{0,120}10\/10 browser steps/i,
    /old\s+repository `100\/100`[\s\S]{0,360}not\s+an organizer-issued\s+score/i,
  ],
};

const items = Object.entries(requirements).map(([id, patterns]) => {
  const text = documents[id];
  const checks = patterns.map((pattern) => ({
    pattern: pattern.source,
    matched: pattern.test(text),
  }));
  return {
    id,
    status: checks.every((check) => check.matched) ? "verified" : "failed",
    checks,
  };
});

const status =
  reviewerIndependent && items.every((item) => item.status === "verified")
    ? "verified"
    : items.some((item) => item.status === "failed")
      ? "failed"
      : "unverified";
const report = {
  schemaVersion: 2,
  kind: "independent-documentation-review",
  generatedAt: new Date().toISOString(),
  status,
  source,
  executionIdentity: executionIdentity(root),
  reviewerIndependent,
  method:
    "Semantic invariant audit from the read-only no-hardlink clone; checks protocol claim, timed demo, provider status and non-goal boundaries rather than file presence alone.",
  items,
};
await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");
for (const item of items) console.log(`${item.status.padEnd(10)} ${item.id}`);
console.log(`${status}: documentation review: ${reportPath}`);
process.exitCode = status === "verified" ? 0 : status === "unverified" ? 2 : 1;
