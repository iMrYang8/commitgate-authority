#!/usr/bin/env node
import { createHash } from "node:crypto";
import { copyFile, mkdir, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { evidenceProvenance } from "./evidence-utils.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const destinationRoot = path.join(root, "evidence", "current");
const files = [];
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

const copySanitized = async (source, relative) => {
  const info = await stat(source).catch(() => null);
  if (!info?.isFile()) return;
  const destination = path.join(destinationRoot, relative);
  await mkdir(path.dirname(destination), { recursive: true });
  if (/\.(?:json|md|txt)$/i.test(source)) {
    const text = (await readFile(source, "utf8"))
      .replaceAll(root, "<REPO_ROOT>")
      .replaceAll(os.homedir(), "<HOME>");
    if (/(?:MODEL_API_KEY|APP_AUTH_TOKEN|MODEL_RELAY_TOKEN)\s*["'=:\s]+(?!\[?REDACTED\]?|null|false)[A-Za-z0-9_.-]{12,}/i.test(text)) {
      throw new Error(`PUBLIC_EVIDENCE_SECRET_VALUE_REJECTED:${source}`);
    }
    await writeFile(destination, text, "utf8");
  } else {
    await copyFile(source, destination);
  }
  const bytes = await readFile(destination);
  files.push({ path: relative.replaceAll(path.sep, "/"), bytes: bytes.length, sha256: digest(bytes) });
};

await rm(destinationRoot, { recursive: true, force: true });
await mkdir(destinationRoot, { recursive: true });
await copySanitized(
  path.join(root, "RELEASE_PROVENANCE.json"),
  "RELEASE_PROVENANCE.json",
);

for (const name of [
  "adversarial-report.json",
  "authority-report.json",
  "browser-clean-clone-report.json",
  "container-report.json",
  "independent-audit-report.json",
  "protocol-report.json",
  "provider-ark-report.json",
  "provider-openrouter-report.json",
  "recovery-report.json",
]) {
  await copySanitized(path.join(root, "eval", name), path.join("reports", name));
}
for (const entry of await readdir(path.join(root, "eval", "evidence"), { withFileTypes: true }).catch(() => [])) {
  if (!entry.isFile() || !/\.(?:json|md|txt)$/i.test(entry.name)) continue;
  await copySanitized(
    path.join(root, "eval", "evidence", entry.name),
    path.join("reports", "evidence", entry.name),
  );
}

const browserReport = JSON.parse(
  await readFile(path.join(root, "eval", "browser-clean-clone-report.json"), "utf8"),
);
const screenshotKinds = new Set([
  "committed-exact-proposal-screenshot",
  "quarantined-no-effect-screenshot",
  "permit-replay-head-unchanged-screenshot",
]);
for (const artifact of browserReport.artifacts ?? []) {
  if (!screenshotKinds.has(artifact.kind) || typeof artifact.path !== "string") continue;
  await copySanitized(
    path.join(root, artifact.path),
    path.join("screenshots", path.basename(artifact.path)),
  );
}

files.sort((left, right) => left.path.localeCompare(right.path));
await writeFile(
  path.join(destinationRoot, "SHA256SUMS.txt"),
  files.map((entry) => `${entry.sha256}  ${entry.path}`).join("\n") + "\n",
  "utf8",
);
const source = await evidenceProvenance(root);
await writeFile(
  path.join(destinationRoot, "EVIDENCE_INDEX.md"),
  [
    "# Current Evidence Snapshot",
    "",
    `- Source revision: \`${source.sourceRevision}\``,
    `- Source tree hash: \`${source.sourceTreeHash}\``,
    `- Files: ${files.length}`,
    "",
    "This is a sanitized, project-generated evidence snapshot. It is not an organizer score or external audit.",
    "Runtime commands regenerate their working reports under `eval/`; they do not overwrite this snapshot.",
    "",
  ].join("\n"),
  "utf8",
);
console.log(`public evidence snapshot: ${destinationRoot}`);
console.log(`files: ${files.length}`);
