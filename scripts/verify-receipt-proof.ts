import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  verifyAuthorityReceiptProof,
  receiptSigningKeyId,
  verifyReceiptProof,
  type AuthorityReceiptProofBundle,
  type SignedReceiptProof,
} from "../apps/server/src/research/receipt-proof.js";
import { evidenceProvenance, executionIdentity } from "./evidence-utils.mjs";
import { validateTerminalReceiptProofSetContract } from "./receipt-proof-set-contract.mjs";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const reportPath = resolve(root, "eval", "evidence", "receipt-verification-report.json");

const cli = process.argv.slice(2);
const positional = cli.filter((value) => !value.startsWith("--"));
const option = (name: string): string | null => {
  const inline = cli.find((value) => value.startsWith(`${name}=`));
  if (inline) return inline.slice(name.length + 1);
  const index = cli.indexOf(name);
  return index >= 0 ? cli[index + 1] ?? null : null;
};
const requestedProofPath = option("--proof") ?? positional[0];
const publicKeyPath = option("--public-key") ?? positional[1];
const proofPath = requestedProofPath ??
  resolve(root, "eval", "evidence", "terminal-receipt-proof-bundles.json");
const proofSetRequested = !requestedProofPath ||
  resolve(proofPath).endsWith("terminal-receipt-proof-bundles.json");
const defaultKeyIdPath = resolve(root, "eval", "evidence", "receipt-proof-key-id.txt");
const expectedKeyIdPath = option("--expected-key-id-file") ?? defaultKeyIdPath;
let expectedKeyId = option("--expected-key-id") ??
  process.env.COMMITGATE_EXPECTED_RECEIPT_KEY_ID?.trim() ?? null;
if (!expectedKeyId) {
  try {
    expectedKeyId = (await readFile(resolve(expectedKeyIdPath), "utf8")).trim();
  } catch {
    expectedKeyId = null;
  }
}

let proofBytes: Buffer;
try {
  proofBytes = await readFile(resolve(proofPath));
} catch (error) {
  const report = {
    schemaVersion: proofSetRequested ? 3 : 2,
    kind: proofSetRequested
      ? "offline-terminal-receipt-proof-set-verification"
      : "offline-receipt-proof-verification",
    generatedAt: new Date().toISOString(),
    status: "unverified",
    source: await evidenceProvenance(root),
    executionIdentity: executionIdentity(root),
    proof: { path: relative(root, resolve(proofPath)), receiptHash: null, eventDigest: null },
    verification: {
      valid: false,
      reason: `proof bundle unavailable: ${error instanceof Error ? error.message : String(error)}`,
    },
  };
  await mkdir(dirname(reportPath), { recursive: true });
  await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");
  console.log(JSON.stringify(report, null, 2));
  process.exit(2);
}
interface AuthorityReceiptProofSet {
  schemaVersion: 1;
  kind: "authority-terminal-receipt-proof-set";
  sourceRevision: string;
  signingKeyId: string;
  proofs: Array<{
    label: string;
    expectedDecision: "COMMITTED" | "QUARANTINED" | "ABORTED";
    bundle: AuthorityReceiptProofBundle;
  }>;
}

let parsed: AuthorityReceiptProofBundle | SignedReceiptProof | AuthorityReceiptProofSet;
try {
  parsed = JSON.parse(proofBytes.toString("utf8")) as
    | AuthorityReceiptProofBundle
    | SignedReceiptProof
    | AuthorityReceiptProofSet;
} catch (error) {
  const report = {
    schemaVersion: proofSetRequested ? 3 : 2,
    kind: proofSetRequested
      ? "offline-terminal-receipt-proof-set-verification"
      : "offline-receipt-proof-verification",
    generatedAt: new Date().toISOString(),
    status: "failed",
    source: await evidenceProvenance(root),
    executionIdentity: executionIdentity(root),
    proof: {
      path: relative(root, resolve(proofPath)),
      sha256: createHash("sha256").update(proofBytes).digest("hex"),
      receiptHash: null,
      eventDigest: null,
    },
    verification: {
      valid: false,
      reason: `proof bundle is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
      cryptographic: { valid: false, reason: "malformed proof bundle" },
      semanticBindings: { valid: false, reason: "malformed proof bundle" },
    },
  };
  await mkdir(dirname(reportPath), { recursive: true });
  await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");
  console.log(JSON.stringify(report, null, 2));
  process.exit(1);
}
const authorityProofSet =
  typeof parsed === "object" &&
  parsed !== null &&
  "kind" in parsed &&
  parsed.kind === "authority-terminal-receipt-proof-set";
if (authorityProofSet) {
  const proofSet = parsed as AuthorityReceiptProofSet;
  const provenance = await evidenceProvenance(root);
  const proofEntries = Array.isArray(proofSet.proofs) ? proofSet.proofs : [];
  const proofSetContract = validateTerminalReceiptProofSetContract(proofSet, {
    sourceRevision: provenance.sourceRevision,
    signingKeyId: expectedKeyId,
  });
  const labels = proofSetContract.labels;
  const records = proofEntries.map((entry) => {
    const contractRecord = proofSetContract.records.find(
      (candidate) => candidate.label === entry.label,
    );
    let observedKeyId: string | null = null;
    let verification: { valid: boolean; reason: string | null };
    try {
      observedKeyId = receiptSigningKeyId(entry.bundle.publicKeyPem);
      verification = verifyAuthorityReceiptProof(entry.bundle);
    } catch {
      verification = { valid: false, reason: "malformed proof or public key" };
    }
    const receipt = entry.bundle?.receipt;
    const bindingsValid =
      contractRecord?.valid === true &&
      receipt?.decision === contractRecord.expectedDecision &&
      receipt?.sourceRevision === provenance.sourceRevision &&
      observedKeyId === proofSet.signingKeyId &&
      observedKeyId === expectedKeyId;
    return {
      label: entry.label,
      expectedDecision: contractRecord?.expectedDecision ?? null,
      declaredExpectedDecision: entry.expectedDecision,
      observedDecision: receipt?.decision ?? null,
      receiptId: receipt?.receiptId ?? null,
      runId: receipt?.runId ?? null,
      transitionId: receipt?.transitionId ?? null,
      signingKeyId: observedKeyId,
      receiptHash: entry.bundle?.proof?.receiptHash ?? null,
      eventDigest: entry.bundle?.proof?.eventDigest ?? null,
      bundleSchemaVersion: entry.bundle?.schemaVersion ?? null,
      eventChainLength: Array.isArray(entry.bundle?.eventChain)
        ? entry.bundle.eventChain.length
        : 0,
      fullEventChainValid: contractRecord?.fullEventChainValid === true,
      rollbackTargetVersionId: contractRecord?.rollbackTargetVersionId ?? null,
      sourceRevision: receipt?.sourceRevision ?? null,
      status: verification.valid && bindingsValid ? "verified" : "failed",
      verification: {
        valid: verification.valid && bindingsValid,
        reason:
          verification.reason ??
          (bindingsValid ? null : "proof-set decision, revision, or trust-anchor binding mismatch"),
        cryptographicAndSemantic: verification,
        setBindings: { valid: bindingsValid },
      },
    };
  });
  const structureValid = proofSetContract.valid;
  const allVerified =
    structureValid && records.every((record) => record.status === "verified");
  const missingTrustAnchor = expectedKeyId === null;
  const report = {
    schemaVersion: 3,
    kind: "offline-terminal-receipt-proof-set-verification",
    generatedAt: new Date().toISOString(),
    status: allVerified ? "verified" : missingTrustAnchor ? "unverified" : "failed",
    source: provenance,
    executionIdentity: executionIdentity(root),
    proofSet: {
      path: relative(root, resolve(proofPath)),
      sha256: createHash("sha256").update(proofBytes).digest("hex"),
      sourceRevision: proofSet.sourceRevision,
      signingKeyId: proofSet.signingKeyId,
      expectedSigningKeyId: expectedKeyId,
      proofCount: records.length,
      requiredLabels: proofSetContract.requiredLabels,
      labels,
      structureValid,
      identityUnique: proofSetContract.identityUnique,
      contractReason: proofSetContract.reason,
    },
    records,
    verification: {
      valid: allVerified,
      reason: allVerified
        ? null
        : missingTrustAnchor
          ? "release signing key id is missing"
          : "one or more terminal receipt proofs or proof-set bindings failed",
      allTerminalReceiptsVerified: allVerified,
      proofSetContractValid: proofSetContract.valid,
      trustAnchor: {
        valid: proofSet.signingKeyId === expectedKeyId,
        expectedSigningKeyId: expectedKeyId,
      },
    },
    claimBoundary:
      "Verifies every terminal receipt observed by the frozen browser scenario. This finite fixture set is not a claim about unobserved runs.",
  };
  await mkdir(dirname(reportPath), { recursive: true });
  await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");
  console.log(JSON.stringify(report, null, 2));
  process.exit(allVerified ? 0 : missingTrustAnchor ? 2 : 1);
}
const authorityBundle =
  typeof parsed === "object" && parsed !== null && "receipt" in parsed && "proof" in parsed;
const publicKey = authorityBundle
  ? (parsed as AuthorityReceiptProofBundle).publicKeyPem
  : publicKeyPath
    ? await readFile(resolve(publicKeyPath), "utf8")
    : "";
if (!authorityBundle && !publicKeyPath) {
  console.error("Legacy proof verification also requires PUBLIC_KEY_PEM");
  process.exit(2);
}
let cryptographicResult: { valid: boolean; reason: string | null };
try {
  cryptographicResult = authorityBundle
    ? verifyAuthorityReceiptProof(parsed as AuthorityReceiptProofBundle)
    : verifyReceiptProof(parsed as SignedReceiptProof, publicKey);
} catch {
  cryptographicResult = { valid: false, reason: "malformed proof or public key" };
}
let observedKeyId: string | null = null;
try {
  observedKeyId = receiptSigningKeyId(publicKey);
} catch {
  // cryptographicResult already reports malformed key material.
}
let trustAnchorResult: { valid: boolean; reason: string | null };
if (!authorityBundle) {
  trustAnchorResult = publicKeyPath
    ? { valid: true, reason: null }
    : { valid: false, reason: "external public key is missing" };
} else if (!expectedKeyId || !/^[a-f0-9]{24}$/.test(expectedKeyId)) {
  trustAnchorResult = {
    valid: false,
    reason: "release signing key id is missing or malformed",
  };
} else {
  trustAnchorResult = {
    valid: observedKeyId === expectedKeyId,
    reason: observedKeyId === expectedKeyId ? null : "release signing key id mismatch",
  };
}
const proof = authorityBundle
  ? (parsed as AuthorityReceiptProofBundle).proof
  : (parsed as SignedReceiptProof);
const provenance = await evidenceProvenance(root);
const digestPattern = /^[a-f0-9]{64}$/;
let semanticResult: { valid: boolean; reason: string | null } = {
  valid: true,
  reason: null,
};
if (authorityBundle) {
  const bundle = parsed as AuthorityReceiptProofBundle;
  const receipt = bundle.receipt;
  const committed = receipt.decision === "COMMITTED";
  const dispositionBase = receipt.schemaVersion === 2
    ? {
        viewId: receipt.dispositionBaseViewId,
        generation: receipt.dispositionBaseGeneration,
        workspaceHash: receipt.dispositionBaseWorkspaceHash,
      }
    : {
        viewId: receipt.baseViewId,
        generation: receipt.baseGeneration,
        workspaceHash: receipt.baseWorkspaceHash,
      };
  const proposalBaseMatchesDisposition =
    receipt.baseViewId === dispositionBase.viewId &&
    receipt.baseGeneration === dispositionBase.generation &&
    receipt.baseWorkspaceHash === dispositionBase.workspaceHash;
  const eventBound =
    Number.isSafeInteger(bundle.proof.logSequence) &&
    bundle.proof.logSequence > 0 &&
    digestPattern.test(bundle.proof.eventDigest) &&
    (bundle.proof.previousDigest === null ||
      digestPattern.test(bundle.proof.previousDigest));
  const stateBound =
    digestPattern.test(receipt.baseViewId) &&
    digestPattern.test(receipt.finalViewId) &&
    digestPattern.test(receipt.baseWorkspaceHash) &&
    digestPattern.test(receipt.finalWorkspaceHash) &&
    digestPattern.test(dispositionBase.viewId) &&
    Number.isSafeInteger(dispositionBase.generation) &&
    dispositionBase.generation >= 0 &&
    digestPattern.test(dispositionBase.workspaceHash) &&
    (committed
      ? proposalBaseMatchesDisposition &&
        receipt.nextGeneration === dispositionBase.generation + 1 &&
        receipt.proposalId !== null &&
        receipt.proposalArtifactHash === receipt.verifierInputHash &&
        receipt.proposalArtifactHash === receipt.promotionSourceHash &&
        receipt.proposalArtifactHash === receipt.finalWorkspaceHash &&
        digestPattern.test(receipt.evaluationContextHash ?? "") &&
        digestPattern.test(receipt.evidenceDigest ?? "") &&
        receipt.permitId !== null &&
        receipt.permitState === "CONSUMED"
      : receipt.nextGeneration === dispositionBase.generation &&
        receipt.finalWorkspaceHash === dispositionBase.workspaceHash &&
        receipt.permitState !== "CONSUMED" &&
        (receipt.schemaVersion === 1
          ? receipt.decision !== "CONFLICTED"
          : receipt.decision === "CONFLICTED"
            ? !proposalBaseMatchesDisposition
            : proposalBaseMatchesDisposition));
  const sourceBound =
    /^[a-f0-9]{40}$/.test(receipt.sourceRevision) &&
    receipt.sourceRevision === provenance.sourceRevision;
  if (!eventBound) {
    semanticResult = { valid: false, reason: "terminal event-chain anchor is malformed" };
  } else if (!stateBound) {
    semanticResult = { valid: false, reason: "receipt state/proposal/evidence/permit binding is invalid" };
  } else if (!sourceBound) {
    semanticResult = { valid: false, reason: "receipt source revision does not match the current checkout" };
  }
}
const result = {
  valid: cryptographicResult.valid && semanticResult.valid && trustAnchorResult.valid,
  reason: cryptographicResult.reason ?? semanticResult.reason ?? trustAnchorResult.reason,
};
const missingTrustAnchor = authorityBundle && expectedKeyId === null;
const report = {
  schemaVersion: 2,
  kind: "offline-receipt-proof-verification",
  generatedAt: new Date().toISOString(),
  status: result.valid ? "verified" : missingTrustAnchor ? "unverified" : "failed",
  source: provenance,
  executionIdentity: executionIdentity(root),
  proof: {
    path: relative(root, resolve(proofPath)),
    sha256: createHash("sha256").update(proofBytes).digest("hex"),
    runId: proof.runId,
    proposalId: authorityBundle
      ? (parsed as AuthorityReceiptProofBundle).receipt.proposalId
      : (proof as SignedReceiptProof).proposalId,
    logSequence: proof.logSequence,
    eventDigest: proof.eventDigest,
    signingKeyId: proof.signingKeyId,
    format: authorityBundle
      ? `authority-receipt-bundle-v${(parsed as AuthorityReceiptProofBundle).schemaVersion}`
      : "legacy-proof-v1",
    receiptHash: authorityBundle
      ? (parsed as AuthorityReceiptProofBundle).proof.receiptHash
      : null,
  },
  publicKey: {
    path: authorityBundle ? null : relative(root, resolve(publicKeyPath!)),
    signingKeyId: observedKeyId,
    expectedSigningKeyId: expectedKeyId,
    expectedKeyIdPath: authorityBundle ? relative(root, resolve(expectedKeyIdPath)) : null,
    contentsRecorded: false,
  },
  verification: {
    ...result,
    cryptographic: cryptographicResult,
    semanticBindings: semanticResult,
    trustAnchor: trustAnchorResult,
  },
};
await mkdir(dirname(reportPath), { recursive: true });
await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");
console.log(JSON.stringify(report, null, 2));
if (!result.valid) process.exitCode = missingTrustAnchor ? 2 : 1;
