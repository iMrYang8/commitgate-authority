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
const legacyManualSecretFlag = cli.includes("--manual-secret-review");
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
const contentReview = DEMO_VIDEO_REVIEW_CHECK_IDS.map((id) => ({
  id,
  status:
    reviewVerification.valid && attestedChecks.get(id)?.status === "verified"
      ? "verified"
      : reviewVerification.status,
  detail: reviewVerification.valid
    ? `Externally signed review by ${reviewVerification.reviewerId}`
    : attestationParseError ?? reviewVerification.reason,
}));
const technicalStatus = technicalChecks.some((check) => check.status === "failed")
  ? "failed"
  : "verified";
const report = {
  schemaVersion: 2,
  kind: "three-minute-demo-video-verification",
  generatedAt: new Date().toISOString(),
  // This tool mechanically verifies only the media envelope. It deliberately
  // keeps the release result unverified until a real reviewer watches the
  // recording; a self-declared CLI flag is not independent evidence.
  status:
    technicalStatus === "failed" || reviewVerification.status === "failed"
      ? "failed"
      : technicalStatus === "verified" && reviewVerification.status === "verified"
        ? "verified"
        : "unverified",
  technicalStatus,
  source: await evidenceProvenance(root),
  artifact: {
    path: path.basename(videoPath),
    pathRecordedAs: "basename-only",
    bytes: bytes.byteLength,
    sha256: videoSha256,
  },
  technicalChecks,
  contentReview: {
    status: reviewVerification.status,
    method:
      reviewVerification.valid
        ? "external signed full-video review"
        : "external signed full-video review required",
    legacyManualSecretFlagReceived: legacyManualSecretFlag,
    legacyManualSecretFlagAffectsStatus: false,
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
    "Technical verification measures the supplied media bytes. Content becomes verified only through a separate Ed25519-signed human review attestation bound to the video SHA-256 and an externally supplied reviewer identity/key anchor; a CLI assertion alone has no effect.",
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
if (legacyManualSecretFlag) {
  console.log(
    "unverified legacy-manual-flag: --manual-secret-review was recorded but does not convert a manual content claim into verified evidence",
  );
}
console.log(`${reviewVerification.status.padEnd(10)} external-review-attestation: ${JSON.stringify(reviewVerification.reason)}`);
console.log(`video report: ${reportPath}`);
process.exitCode = report.status === "failed" ? 1 : report.status === "unverified" ? 2 : 0;
