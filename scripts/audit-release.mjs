#!/usr/bin/env node
import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  evidenceProvenance,
  executionIdentity,
  revisionIsAncestor,
  sourceTreeHash,
} from "./evidence-utils.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const required = [
  "eval/evidence/check-report.json",
  "eval/protocol-report.json",
  "eval/adversarial-report.json",
  "eval/recovery-report.json",
  "eval/container-report.json",
  "eval/evidence/p1-product-report.json",
  "eval/evidence/linux-filesystem-report.json",
  "eval/evidence/topology-report.json",
  "eval/evidence/demo-smoke-report.json",
  "eval/browser-clean-clone-report.json",
  "eval/evidence/secret-report.json",
  "eval/evidence/demo-video-report.json",
];
const imageBoundReports = new Set([
  "eval/protocol-report.json",
  "eval/adversarial-report.json",
  "eval/recovery-report.json",
  "eval/container-report.json",
  "eval/evidence/p1-product-report.json",
  "eval/evidence/linux-filesystem-report.json",
  "eval/evidence/topology-report.json",
  "eval/browser-clean-clone-report.json",
]);
const currentTree = await sourceTreeHash(root);
const shaImage = (value) => /^sha256:[a-f0-9]{64}$/.test(value ?? "");
let releaseRuntimeDigest = null;
let releaseVerifierDigest = null;

function validateBinding(file, parsed) {
  const source = parsed?.source;
  if (
    source?.sourceTreeHash !== currentTree.hash ||
    source?.sourceFileCount !== currentTree.files ||
    source?.workingTreeCleanAtCapture !== true ||
    !revisionIsAncestor(root, source?.sourceRevision)
  ) {
    return "source identity is stale, dirty, or not an ancestor of the release";
  }
  if (!imageBoundReports.has(file)) return null;
  const runtime = parsed?.executionIdentity?.runtimeImage?.imageDigest;
  const verifier = parsed?.executionIdentity?.verifierImage?.imageDigest;
  if (!shaImage(runtime) || !shaImage(verifier)) {
    return "Runtime or Verifier image digest is not mechanically verified";
  }
  releaseRuntimeDigest ??= runtime;
  releaseVerifierDigest ??= verifier;
  if (runtime !== releaseRuntimeDigest || verifier !== releaseVerifierDigest) {
    return "image identity differs from the release evidence set";
  }
  if (parsed?.executionIdentity?.provider?.credentialsRecorded !== false) {
    return "provider evidence does not explicitly exclude recorded credentials";
  }
  return null;
}
const items = [];
for (const file of required) {
  const absolute = path.join(root, file);
  try {
    await access(absolute);
    const parsed = JSON.parse(await readFile(absolute, "utf8"));
    const declared = ["verified", "failed", "unverified"].includes(parsed.status)
      ? parsed.status
      : "unverified";
    const bindingError = validateBinding(file, parsed);
    items.push({
      file,
      status: declared === "failed" ? "failed" : bindingError ? "unverified" : declared,
      generatedAt: parsed.generatedAt ?? null,
      ...(bindingError ? { reason: bindingError } : {}),
    });
  } catch {
    items.push({ file, status: "unverified", generatedAt: null });
  }
}
const source = await evidenceProvenance(root);
if (!source.workingTreeCleanAtCapture) items.push({ file: "git working tree", status: "unverified", generatedAt: null });
const status = items.some((item) => item.status === "failed") ? "failed" : items.some((item) => item.status === "unverified") ? "unverified" : "verified";
const report = {
  schemaVersion: 1,
  kind: "release-evidence-audit",
  generatedAt: new Date().toISOString(),
  status,
  source,
  executionIdentity: executionIdentity(root),
  items,
  claimBoundary: "This is a release evidence completeness audit, not an official score. Missing, stale, dirty-tree, or non-verified inputs remain unverified.",
};
const reportPath = path.join(root, "eval", "evidence", "release-audit-report.json");
await mkdir(path.dirname(reportPath), { recursive: true });
await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n");
for (const item of items) console.log(`${item.status.padEnd(10)} ${item.file}`);
console.log(`report: ${reportPath}`);
process.exitCode = status === "verified" ? 0 : status === "unverified" ? 2 : 1;
