#!/usr/bin/env node
import { createHash, sign } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import {
  canonicalDemoVideoReviewAttestation,
  DEMO_VIDEO_REVIEW_CHECK_IDS,
  reviewerSigningKeyId,
} from "./video-review-attestation.mjs";

const cli = process.argv.slice(2);
const option = (name) => {
  const inline = cli.find((value) => value.startsWith(`${name}=`));
  if (inline) return inline.slice(name.length + 1);
  const index = cli.indexOf(name);
  return index >= 0 ? cli[index + 1] ?? null : null;
};
const videoPath = option("--file");
const reviewerId = option("--reviewer-id");
const privateKeyPath = option("--private-key");
const publicKeyPath = option("--public-key");
const outputPath = option("--output");
if (![videoPath, reviewerId, privateKeyPath, publicKeyPath, outputPath].every(Boolean)) {
  console.error(
    "Usage: npm run demo:sign-review -- --file VIDEO --reviewer-id ID --private-key PRIVATE.pem --public-key PUBLIC.pem --output ATTESTATION.json",
  );
  process.exit(2);
}
const [videoBytes, privateKeyPem, publicKeyPem] = await Promise.all([
  readFile(path.resolve(videoPath)),
  readFile(path.resolve(privateKeyPath), "utf8"),
  readFile(path.resolve(publicKeyPath), "utf8"),
]);
const signingKeyId = reviewerSigningKeyId(publicKeyPem);
const unsigned = {
  schemaVersion: 1,
  kind: "external-demo-video-review-attestation",
  videoSha256: createHash("sha256").update(videoBytes).digest("hex"),
  reviewer: { id: reviewerId, method: "human-full-video-review" },
  reviewedAt: new Date().toISOString(),
  checks: DEMO_VIDEO_REVIEW_CHECK_IDS.map((id) => ({ id, status: "verified" })),
  signingKeyId,
  signatureAlgorithm: "Ed25519",
  publicKeyPem,
};
const attestation = {
  ...unsigned,
  signature: sign(
    null,
    canonicalDemoVideoReviewAttestation(unsigned),
    privateKeyPem,
  ).toString("base64url"),
};
await writeFile(path.resolve(outputPath), JSON.stringify(attestation, null, 2) + "\n", {
  encoding: "utf8",
  mode: 0o644,
});
console.log(`reviewer signing key id: ${signingKeyId}`);
console.log(`attestation: ${path.resolve(outputPath)}`);
