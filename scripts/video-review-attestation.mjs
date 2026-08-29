import { createHash, createPublicKey, verify } from "node:crypto";

export const DEMO_VIDEO_REVIEW_CHECK_IDS = Object.freeze([
  "narrated-audio-content-review",
  "real-agent-run-content-review",
  "visual-secret-content-review",
]);

export function reviewerSigningKeyId(publicKeyPem) {
  const der = createPublicKey(publicKeyPem).export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex").slice(0, 24);
}

export function canonicalDemoVideoReviewAttestation(attestation) {
  const checks = Array.isArray(attestation?.checks)
    ? [...attestation.checks]
      .map((entry) => ({ id: entry?.id, status: entry?.status }))
      .sort((left, right) => String(left.id).localeCompare(String(right.id)))
    : [];
  return Buffer.from(JSON.stringify({
    schemaVersion: attestation?.schemaVersion,
    kind: attestation?.kind,
    videoSha256: attestation?.videoSha256,
    reviewer: {
      id: attestation?.reviewer?.id,
      method: attestation?.reviewer?.method,
    },
    reviewedAt: attestation?.reviewedAt,
    checks,
    signingKeyId: attestation?.signingKeyId,
    signatureAlgorithm: attestation?.signatureAlgorithm,
  }), "utf8");
}

export function verifyDemoVideoReviewAttestation(
  attestation,
  { videoSha256, expectedReviewerId, expectedSigningKeyId },
) {
  if (!attestation || typeof attestation !== "object") {
    return { status: "unverified", valid: false, reason: "external reviewer attestation is missing" };
  }
  if (!expectedReviewerId || !expectedSigningKeyId) {
    return {
      status: "unverified",
      valid: false,
      reason: "external reviewer id or signing-key trust anchor is missing",
    };
  }
  const checks = Array.isArray(attestation.checks) ? attestation.checks : [];
  const checkIds = checks.map((entry) => entry?.id);
  const exactChecks =
    checks.length === DEMO_VIDEO_REVIEW_CHECK_IDS.length &&
    new Set(checkIds).size === checkIds.length &&
    DEMO_VIDEO_REVIEW_CHECK_IDS.every((id) =>
      checks.some((entry) => entry?.id === id && entry?.status === "verified"));
  const reviewedAt = Date.parse(attestation.reviewedAt ?? "");
  let observedKeyId = null;
  let signatureValid = false;
  try {
    observedKeyId = reviewerSigningKeyId(attestation.publicKeyPem);
    signatureValid = verify(
      null,
      canonicalDemoVideoReviewAttestation(attestation),
      attestation.publicKeyPem,
      Buffer.from(attestation.signature ?? "", "base64url"),
    );
  } catch {
    signatureValid = false;
  }
  const bindingsValid =
    attestation.schemaVersion === 1 &&
    attestation.kind === "external-demo-video-review-attestation" &&
    /^[a-f0-9]{64}$/.test(videoSha256 ?? "") &&
    attestation.videoSha256 === videoSha256 &&
    attestation.reviewer?.id === expectedReviewerId &&
    attestation.reviewer?.method === "human-full-video-review" &&
    Number.isFinite(reviewedAt) &&
    reviewedAt <= Date.now() + 5 * 60_000 &&
    observedKeyId === expectedSigningKeyId &&
    attestation.signingKeyId === expectedSigningKeyId &&
    attestation.signatureAlgorithm === "Ed25519" &&
    exactChecks;
  const valid = bindingsValid && signatureValid;
  return {
    status: valid ? "verified" : "failed",
    valid,
    reason: valid ? null : "reviewer signature or video/reviewer/check binding is invalid",
    reviewerId: attestation.reviewer?.id ?? null,
    reviewerMethod: attestation.reviewer?.method ?? null,
    reviewedAt: attestation.reviewedAt ?? null,
    signingKeyId: observedKeyId,
    signatureValid,
    bindingsValid,
    checks,
  };
}
