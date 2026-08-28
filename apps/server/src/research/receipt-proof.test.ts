import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { signReceiptProof, verifyReceiptProof, type ReceiptProofBody } from "./receipt-proof.js";

describe("signed receipt proof", () => {
  it("detects terminal proof tampering", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const body: ReceiptProofBody = {
      schemaVersion: 1,
      runId: "run-1",
      proposalId: "proposal-1",
      logSequence: 9,
      previousDigest: "a".repeat(64),
      eventDigest: "b".repeat(64),
      evaluationContextHash: "c".repeat(64),
      evidenceDigest: "d".repeat(64),
      permitId: "permit-1",
      decision: "COMMITTED",
    };
    const proof = signReceiptProof(body, privatePem, publicPem);
    expect(verifyReceiptProof(proof, publicPem)).toEqual({ valid: true, reason: null });
    expect(
      verifyReceiptProof({ ...proof, decision: "ABORTED" }, publicPem),
    ).toEqual({ valid: false, reason: "signature mismatch" });
  });
});
