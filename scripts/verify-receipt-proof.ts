import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  receiptSigningKeyId,
  verifyReceiptProof,
  type SignedReceiptProof,
} from "../apps/server/src/research/receipt-proof.js";
import { evidenceProvenance, executionIdentity } from "./evidence-utils.mjs";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const reportPath = resolve(root, "eval", "evidence", "receipt-verification-report.json");

const [proofPath, publicKeyPath] = process.argv.slice(2);
if (!proofPath || !publicKeyPath) {
  console.error("Usage: npm run receipt:verify -- PROOF_JSON PUBLIC_KEY_PEM");
  process.exit(2);
}

const proofBytes = await readFile(resolve(proofPath));
const proof = JSON.parse(proofBytes.toString("utf8")) as SignedReceiptProof;
const publicKey = await readFile(resolve(publicKeyPath), "utf8");
const result = verifyReceiptProof(proof, publicKey);
const report = {
  schemaVersion: 2,
  kind: "offline-receipt-proof-verification",
  generatedAt: new Date().toISOString(),
  status: result.valid ? "verified" : "failed",
  source: await evidenceProvenance(root),
  executionIdentity: executionIdentity(root),
  proof: {
    path: relative(root, resolve(proofPath)),
    sha256: createHash("sha256").update(proofBytes).digest("hex"),
    runId: proof.runId,
    proposalId: proof.proposalId,
    logSequence: proof.logSequence,
    eventDigest: proof.eventDigest,
    signingKeyId: proof.signingKeyId,
  },
  publicKey: {
    path: relative(root, resolve(publicKeyPath)),
    signingKeyId: receiptSigningKeyId(publicKey),
    contentsRecorded: false,
  },
  verification: result,
};
await mkdir(dirname(reportPath), { recursive: true });
await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");
console.log(JSON.stringify(report, null, 2));
if (!result.valid) process.exitCode = 1;
