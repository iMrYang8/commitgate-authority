#!/usr/bin/env node
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { readFile, writeFile, mkdir, rm } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { evidenceProvenance } from "./evidence-utils.mjs";
import {
  DEMO_VIDEO_REVIEW_CHECK_IDS,
  verifyDemoVideoReviewAttestation,
} from "./video-review-attestation.mjs";

const execFileAsync = promisify(execFile);
const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const cli = process.argv.slice(2);
const option = (name) => {
  const inline = cli.find((value) => value.startsWith(`${name}=`));
  if (inline) return inline.slice(name.length + 1);
  const index = cli.indexOf(name);
  return index >= 0 ? cli[index + 1] ?? null : null;
};
const manualReview = {
  narration: cli.includes("--manual-narration-review"),
  realAgentRun: cli.includes("--manual-agent-run-review"),
  secrets: cli.includes("--manual-secret-review"),
};
const reviewAttestationInput = option("--review-attestation") ??
  process.env.COMMITGATE_DEMO_REVIEW_ATTESTATION ?? null;
const expectedReviewerId = option("--expected-reviewer-id") ??
  process.env.COMMITGATE_DEMO_REVIEWER_ID?.trim() ?? null;
const expectedReviewerKeyId = option("--expected-reviewer-key-id") ??
  process.env.COMMITGATE_DEMO_REVIEWER_KEY_ID?.trim() ?? null;
const input = option("--file") ??
  cli.find((argument, index) =>
    !argument.startsWith("--") && cli[index - 1] !== "--file") ??
  process.env.DEMO_VIDEO;
if (!input) {
  throw new Error(
    "Usage: npm run demo:verify-video -- --file /absolute/path/demo.mp4",
  );
}
const videoPath = path.resolve(input);
const { stdout } = await execFileAsync("ffprobe", [
  "-v", "error",
  "-show_entries", "format=duration:stream=codec_type,width,height",
  "-of", "json",
  videoPath,
]);
const probe = JSON.parse(stdout);
const duration = Number(probe.format?.duration ?? 0);
const video = probe.streams?.find((stream) => stream.codec_type === "video");
const audio = probe.streams?.find((stream) => stream.codec_type === "audio");
const technicalChecks = [
  { id: "duration-165-185-seconds", status: duration >= 165 && duration <= 185 ? "verified" : "failed", detail: duration },
  { id: "video-stream", status: video ? "verified" : "failed", detail: video ?? null },
  { id: "audio-stream", status: audio ? "verified" : "failed", detail: audio ?? null },
  {
    id: "resolution-1280x720-minimum",
    status: Number(video?.width ?? 0) >= 1280 && Number(video?.height ?? 0) >= 720 ? "verified" : "failed",
    detail: video ? `${video.width}x${video.height}` : "missing",
  },
];
const bytes = await readFile(videoPath);
const videoSha256 = createHash("sha256").update(bytes).digest("hex");
const attestationStorePath = path.join(
  root,
  "eval",
  "evidence",
  "demo-video-review-attestation.json",
);
let attestation = null;
let attestationBytes = null;
let attestationParseError = null;
if (reviewAttestationInput) {
  try {
    attestationBytes = await readFile(path.resolve(reviewAttestationInput));
    attestation = JSON.parse(attestationBytes.toString("utf8"));
  } catch (error) {
    attestationParseError = error instanceof Error ? error.message : String(error);
  }
}
const reviewVerification = verifyDemoVideoReviewAttestation(attestation, {
  videoSha256,
  expectedReviewerId,
  expectedSigningKeyId: expectedReviewerKeyId,
});
if (reviewVerification.valid && attestationBytes) {
  await mkdir(path.dirname(attestationStorePath), { recursive: true });
  await writeFile(attestationStorePath, attestationBytes, { mode: 0o644 });
} else {
  // Never let a stale attestation for older video bytes satisfy a later run.
  await rm(attestationStorePath, { force: true });
}
const attestedChecks = new Map(
  (reviewVerification.checks ?? []).map((entry) => [entry.id, entry]),
);
const manualChecks = new Map([
  ["narrated-audio-content-review", manualReview.narration],
  ["real-agent-run-content-review", manualReview.realAgentRun],
  ["visual-secret-content-review", manualReview.secrets],
]);
const manualReviewComplete = [...manualChecks.values()].every(Boolean);
const contentReview = DEMO_VIDEO_REVIEW_CHECK_IDS.map((id) => ({
  id,
  status:
    reviewVerification.valid && attestedChecks.get(id)?.status === "verified"
      ? "verified"
      : manualChecks.get(id)
        ? "verified"
        : "unverified",
  detail: reviewVerification.valid
    ? `Externally signed review by ${reviewVerification.reviewerId}`
    : manualChecks.get(id)
      ? "Submitter reviewed the complete video and declared this official content check satisfied"
      : attestationParseError ?? "Required submitter content review flag was not supplied",
}));
const technicalStatus = technicalChecks.some((check) => check.status === "failed")
  ? "failed"
  : "verified";
const officialSubmissionReady =
  technicalStatus === "verified" && (reviewVerification.valid || manualReviewComplete);
const externalReviewVerified = reviewVerification.valid
  ? "verified"
  : reviewVerification.status === "failed"
    ? "failed"
    : "unverified";
const report = {
  schemaVersion: 3,
  kind: "three-minute-demo-video-verification",
  generatedAt: new Date().toISOString(),
  status: technicalStatus === "failed" ? "failed" : officialSubmissionReady ? "verified" : "unverified",
  technicalStatus,
  officialSubmissionReady,
  externalReviewVerified,
  source: await evidenceProvenance(root),
  artifact: {
    path: path.basename(videoPath),
    pathRecordedAs: "basename-only",
    bytes: bytes.byteLength,
    sha256: videoSha256,
  },
  technicalChecks,
  contentReview: {
    status: officialSubmissionReady ? "verified" : "unverified",
    method:
      reviewVerification.valid
        ? "external signed full-video review"
        : manualReviewComplete
          ? "submitter full-video content review"
          : "submitter full-video content review required",
    submitterDeclarations: manualReview,
    attestation: reviewVerification.valid && attestationBytes
      ? {
          path: "eval/evidence/demo-video-review-attestation.json",
          sha256: createHash("sha256").update(attestationBytes).digest("hex"),
          reviewerId: reviewVerification.reviewerId,
          reviewerMethod: reviewVerification.reviewerMethod,
          reviewedAt: reviewVerification.reviewedAt,
          signingKeyId: reviewVerification.signingKeyId,
          signatureValid: reviewVerification.signatureValid,
          videoSha256,
        }
      : null,
    checks: contentReview,
  },
  claimBoundary:
    "officialSubmissionReady covers the official media envelope plus an explicit submitter review of narration, a visible real Agent Run, and sensitive information. externalReviewVerified is a separate optional Ed25519-signed independent review and never blocks the official submission result.",
};
const reportPath = path.join(root, "eval", "evidence", "demo-video-report.json");
await mkdir(path.dirname(reportPath), { recursive: true });
await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");
for (const check of technicalChecks) {
  console.log(`${check.status.padEnd(10)} ${check.id}: ${JSON.stringify(check.detail)}`);
}
for (const check of contentReview) {
  console.log(`${check.status.padEnd(10)} ${check.id}: ${JSON.stringify(check.detail)}`);
}
console.log(`${reviewVerification.status.padEnd(10)} external-review-attestation: ${JSON.stringify(reviewVerification.reason)}`);
console.log(`${String(officialSubmissionReady).padEnd(10)} official-submission-ready`);
console.log(`${externalReviewVerified.padEnd(10)} external-review-verified`);
console.log(`video report: ${reportPath}`);
process.exitCode = report.status === "failed" ? 1 : report.status === "unverified" ? 2 : 0;
