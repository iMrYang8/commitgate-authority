import { createHash, createPublicKey, sign, verify } from "node:crypto";

export interface ReceiptProofBody {
  schemaVersion: 1;
  runId: string;
  proposalId: string;
  logSequence: number;
  previousDigest: string | null;
  eventDigest: string;
  evaluationContextHash: string;
  evidenceDigest: string;
  permitId: string;
  decision: "COMMITTED" | "QUARANTINED" | "CONFLICTED" | "ABORTED";
}

export interface SignedReceiptProof extends ReceiptProofBody {
  signingKeyId: string;
  signatureAlgorithm: "Ed25519";
  signature: string;
}

const canonicalBytes = (body: ReceiptProofBody): Buffer =>
  Buffer.from(
    JSON.stringify({
      schemaVersion: body.schemaVersion,
      runId: body.runId,
      proposalId: body.proposalId,
      logSequence: body.logSequence,
      previousDigest: body.previousDigest,
      eventDigest: body.eventDigest,
      evaluationContextHash: body.evaluationContextHash,
      evidenceDigest: body.evidenceDigest,
      permitId: body.permitId,
      decision: body.decision,
    }),
    "utf8",
  );

export function receiptSigningKeyId(publicKeyPem: string): string {
  const der = createPublicKey(publicKeyPem).export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex").slice(0, 24);
}

export function signReceiptProof(
  body: ReceiptProofBody,
  privateKeyPem: string,
  publicKeyPem: string,
): SignedReceiptProof {
  const signature = sign(null, canonicalBytes(body), privateKeyPem).toString("base64url");
  return {
    ...body,
    signingKeyId: receiptSigningKeyId(publicKeyPem),
    signatureAlgorithm: "Ed25519",
    signature,
  };
}

export function verifyReceiptProof(
  proof: SignedReceiptProof,
  publicKeyPem: string,
): { valid: boolean; reason: string | null } {
  if (proof.schemaVersion !== 1 || proof.signatureAlgorithm !== "Ed25519") {
    return { valid: false, reason: "unsupported proof schema or algorithm" };
  }
  if (proof.signingKeyId !== receiptSigningKeyId(publicKeyPem)) {
    return { valid: false, reason: "signing key id mismatch" };
  }
  const { signingKeyId: _keyId, signatureAlgorithm: _algorithm, signature, ...body } = proof;
  try {
    const valid = verify(
      null,
      canonicalBytes(body),
      publicKeyPem,
      Buffer.from(signature, "base64url"),
    );
    return { valid, reason: valid ? null : "signature mismatch" };
  } catch {
    return { valid: false, reason: "malformed signature" };
  }
}
