#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { access, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { evidenceProvenance, executionIdentity } from "./evidence-utils.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const evidenceDir = path.join(root, "eval", "evidence");
const engine = process.env.CONTAINER_ENGINE || "docker";
const image = process.env.CONTAINER_RUNTIME_IMAGE || "volc-agent-runtime:local";
const pinned = "8d0bd4f14ad1e453d984149aebcdd0bcb4f74178";
const sanitizedSourceCopy = process.env.COMMITGATE_SANITIZED_SOURCE_COPY === "1";
const source = await evidenceProvenance(root);

function command(name, args) {
  return spawnSync(name, args, { cwd: root, env: process.env, encoding: "utf8" });
}

const checks = [];
const add = (id, ok, detail, required = true) =>
  checks.push({ id, status: ok ? "verified" : required ? "failed" : "unverified", detail });

const nodeMajor = Number(process.versions.node.split(".")[0]);
add("node-22-plus", nodeMajor >= 22, process.version);

const npm = command("npm", ["--version"]);
const npmMajor = Number(npm.stdout.trim().split(".")[0]);
add("npm", npm.status === 0 && npmMajor >= 10, npm.stdout.trim() || npm.stderr.trim());

const docker = command(engine, ["version", "--format", "{{.Server.Version}}"]);
add("container-engine", docker.status === 0, docker.stdout.trim() || docker.stderr.trim());

const inspect = command(engine, ["image", "inspect", image, "--format", "{{.Id}}"]);
add("runtime-image", inspect.status === 0, inspect.stdout.trim() || `${image} is not built`);

const base = command("git", ["rev-list", "--max-parents=0", "HEAD"]);
add(
  "pinned-starter-base",
  base.status === 0 && base.stdout.trim() === pinned,
  sanitizedSourceCopy
    ? `${base.stdout.trim()}; sanitized source copy explicitly declared`
    : base.stdout.trim(),
  !sanitizedSourceCopy,
);

const branch = command("git", ["branch", "--show-current"]);
add(
  "feature-branch",
  ["feature/commitgate", "feature/commitgate-sealed-view", "feature/commitgate-94", "feature/commitgate-authority-v2", "feature/commitgate-proof-closure", "feature/commitgate-policy-release"].includes(
    branch.stdout.trim(),
  ),
  branch.stdout.trim() || "detached HEAD",
  false,
);

const trackedImplementation = command("git", [
  "ls-files",
  "--error-unmatch",
  "apps/server/src/commitgate/coordinator.ts",
  "apps/server/src/commitgate/protocol.ts",
  "apps/server/src/commitgate/sealed-proposal-store.ts",
  "apps/server/src/commitgate/promotion-permit-store.ts",
  "apps/server/src/workspace-transition-writer.ts",
  "scripts/eval-suite.mjs",
  "scripts/audit-authority.mjs",
  "scripts/score.mjs",
  "scripts/demo-auth.mjs",
]);
add(
  "implementation-tracked",
  trackedImplementation.status === 0,
  trackedImplementation.status === 0
    ? "CommitGate core, evidence-checklist, and Demo-auth scripts are part of the checked-out revision"
    : trackedImplementation.stderr.trim(),
);

add(
  "source-tree-clean",
  source.workingTreeCleanAtCapture,
  source.workingTreeCleanAtCapture
    ? "source files match the captured tree hash"
    : "source files have uncommitted changes",
  false,
);

const trustedCheckFiles = ["workspace-contract.mjs", "workspace-sanity.mjs"];
let trustedCheck = true;
for (const file of trustedCheckFiles) {
  try {
    await access(path.join(root, "eval", "trusted-checks", file));
  } catch {
    trustedCheck = false;
  }
}
add(
  "trusted-checks",
  trustedCheck,
  trustedCheckFiles.map((file) => `eval/trusted-checks/${file}`).join(", "),
);

const ignored = command("git", ["check-ignore", "-q", ".env.local"]);
add("local-secret-file-ignored", ignored.status === 0, ".env.local");

const modelProvider = process.env.MODEL_PROVIDER ?? "ark";
const modelKey = (
  process.env.MODEL_API_KEY ?? (modelProvider === "ark" ? process.env.ARK_API_KEY : "") ?? ""
).trim();
const modelId = (
  process.env.MODEL_ID ?? (modelProvider === "ark" ? process.env.ARK_MODEL : "") ?? ""
).trim();
const modelConfigured = Boolean(
  modelKey && !modelKey.startsWith("replace-") && modelId && !modelId.includes("replace-"),
);
add(
  "model-provider-credentials",
  modelConfigured,
  modelConfigured
    ? `${modelProvider}/${modelId}; credential value not recorded`
    : `${modelProvider} is not configured`,
  false,
);

const status = checks.some((item) => item.status === "failed") ? "failed" : "verified";
const report = {
  schemaVersion: 1,
  kind: "demo-preflight",
  generatedAt: new Date().toISOString(),
  status,
  source,
  executionIdentity: executionIdentity(root),
  credentialIndependentReady: status === "verified",
  providerReady: status === "verified" && modelConfigured,
  providerId: modelProvider,
  checks,
};
await mkdir(evidenceDir, { recursive: true });
await writeFile(
  path.join(evidenceDir, "preflight-report.json"),
  JSON.stringify(report, null, 2) + "\n",
  "utf8",
);
for (const item of checks) console.log(`${item.status.padEnd(10)} ${item.id}: ${item.detail}`);
console.log(`preflight report: ${path.join(evidenceDir, "preflight-report.json")}`);
process.exitCode = status === "verified" ? 0 : 1;
