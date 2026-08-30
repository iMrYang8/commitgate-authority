#!/usr/bin/env node
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { evidenceProvenance } from "./evidence-utils.mjs";

const execFileAsync = promisify(execFile);
const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const outputRoot = path.join(root, "eval", "packages");
const source = await evidenceProvenance(root);
if (!source.sourceRevision) throw new Error("SOURCE_REVISION_UNAVAILABLE");
const shortRevision = source.sourceRevision.slice(0, 12);
const baseName = `CommitGate_Evidence_${shortRevision}`;
const archivePath = path.join(outputRoot, `${baseName}.tar.gz`);
const digestPath = `${archivePath}.sha256`;
const temporary = await mkdtemp(path.join(os.tmpdir(), "commitgate-evidence-"));
const staging = path.join(temporary, baseName);
const files = [];
const textArtifactPattern = /\.(?:json|md|txt)$/i;

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const copy = async (sourcePath, relative) => {
  const absolute = path.resolve(sourcePath);
  const rootRelative = path.relative(root, absolute);
  if (rootRelative.startsWith("..") || path.isAbsolute(rootRelative)) {
    throw new Error(`EVIDENCE_PATH_OUTSIDE_REPOSITORY:${absolute}`);
  }
  if (
    /(?:^|\.)\.env(?:\.|$)|model[_-]?api[_-]?key|app[_-]?auth[_-]?token|relay[_-]?token|broker[_-]?attestation[_-]?key|credential/i.test(
      path.basename(absolute),
    )
  ) {
    throw new Error(`EVIDENCE_SENSITIVE_PATH_REJECTED:${rootRelative}`);
  }
  if (!(await stat(absolute)).isFile()) return;
  const destination = path.join(staging, relative);
  await mkdir(path.dirname(destination), { recursive: true });
  if (textArtifactPattern.test(absolute)) {
    const sanitized = (await readFile(absolute, "utf8"))
      .replaceAll(root, "<REPO_ROOT>")
      .replaceAll(os.homedir(), "<HOME>");
    if (
      /(?:MODEL_API_KEY|APP_AUTH_TOKEN|MODEL_RELAY_TOKEN)\s*["'=:\s]+(?!\[?REDACTED\]?|null|false)[A-Za-z0-9_.-]{12,}/i.test(
        sanitized,
      )
    ) {
      throw new Error(`EVIDENCE_SECRET_VALUE_REJECTED:${rootRelative}`);
    }
    await writeFile(destination, sanitized, "utf8");
  } else {
    await copyFile(absolute, destination);
  }
  const bytes = await readFile(destination);
  files.push({ path: relative.replaceAll(path.sep, "/"), bytes: bytes.length, sha256: digest(bytes) });
};

try {
  await mkdir(staging, { recursive: true });
  const releaseProvenance = path.join(root, "RELEASE_PROVENANCE.json");
  if (await stat(releaseProvenance).catch(() => null)) {
    await copy(releaseProvenance, path.join("provenance", "RELEASE_PROVENANCE.json"));
  }
  const reportNames = [
    "adversarial-report.json",
    "authority-report.json",
    "browser-clean-clone-report.json",
    "container-report.json",
    "independent-audit-report.json",
    "protocol-report.json",
    "provider-ark-report.json",
    "recovery-report.json",
  ];
  for (const name of reportNames) {
    const candidate = path.join(root, "eval", name);
    if (await stat(candidate).catch(() => null)) await copy(candidate, path.join("reports", name));
  }
  const evidenceRoot = path.join(root, "eval", "evidence");
  for (const entry of await readdir(evidenceRoot, { withFileTypes: true }).catch(() => [])) {
    if (!entry.isFile() || !/\.(?:json|md|txt)$/i.test(entry.name)) continue;
    await copy(path.join(evidenceRoot, entry.name), path.join("reports", "evidence", entry.name));
  }

  const browserReportPath = path.join(root, "eval", "browser-clean-clone-report.json");
  const browserReport = JSON.parse(await readFile(browserReportPath, "utf8"));
  const allowedKinds = new Set([
    "committed-exact-proposal-screenshot",
    "quarantined-no-effect-screenshot",
    "permit-replay-head-unchanged-screenshot",
    "playwright-video",
  ]);
  for (const artifact of browserReport.artifacts ?? []) {
    if (!allowedKinds.has(artifact.kind) || typeof artifact.path !== "string") continue;
    await copy(
      path.join(root, artifact.path),
      path.join("artifacts", path.basename(artifact.path)),
    );
  }

  const formalVideo = process.env.DEMO_VIDEO?.trim();
  if (formalVideo) {
    const resolved = path.resolve(formalVideo);
    if (!(await stat(resolved)).isFile()) throw new Error("DEMO_VIDEO_NOT_FOUND");
    const destination = path.join(staging, "artifacts", path.basename(resolved));
    await mkdir(path.dirname(destination), { recursive: true });
    await copyFile(resolved, destination);
    const bytes = await readFile(destination);
    files.push({
      path: path.relative(staging, destination).replaceAll(path.sep, "/"),
      bytes: bytes.length,
      sha256: digest(bytes),
    });
  }

  files.sort((left, right) => left.path.localeCompare(right.path));
  const sums = files.map((file) => `${file.sha256}  ${file.path}`).join("\n") + "\n";
  await writeFile(path.join(staging, "SHA256SUMS.txt"), sums, "utf8");
  const index = [
    "# CommitGate Evidence Index",
    "",
    `- Source revision: \`${source.sourceRevision}\``,
    `- Source tree hash: \`${source.sourceTreeHash}\``,
    `- Packaged at: \`${new Date().toISOString()}\``,
    `- Formal narrated video: ${formalVideo ? "included" : "deferred"}`,
    "",
    "This package contains machine-generated reports and selected review artifacts.",
    "It excludes environment files, credentials, raw host paths and transient session state.",
    "",
    "## Files",
    "",
    ...files.map((file) => `- \`${file.path}\` — ${file.bytes} bytes`),
    "",
  ].join("\n");
  await writeFile(path.join(staging, "EVIDENCE_INDEX.md"), index, "utf8");

  await mkdir(outputRoot, { recursive: true });
  await execFileAsync("tar", ["-czf", archivePath, "-C", temporary, baseName]);
  const archiveBytes = await readFile(archivePath);
  const archiveDigest = digest(archiveBytes);
  await writeFile(digestPath, `${archiveDigest}  ${path.basename(archivePath)}\n`, "utf8");
  console.log(`evidence package: ${archivePath}`);
  console.log(`sha256: ${archiveDigest}`);
  console.log(`formal video: ${formalVideo ? "included" : "deferred"}`);
} finally {
  await rm(temporary, { recursive: true, force: true });
}
