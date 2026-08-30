import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  activeEvidenceReportInventory,
  resolveActiveProviderReport,
} from "./evidence-inventory.mjs";
import {
  BROWSER_CLEAN_CLONE_ARTIFACT_KINDS,
  BROWSER_CLEAN_CLONE_PRECONDITION_IDS,
  BROWSER_CLEAN_CLONE_STEP_IDS,
  REAL_PROVIDER_E2E_SCENARIO_IDS,
  TERMINAL_RECEIPT_PROOF_CONTRACT,
  declaredCurrentProviderE2EStatus,
  validateBrowserCleanCloneContract,
  validateBrowserReceiptArtifactBinding,
  validateRealProviderE2EContract,
  validateTerminalReceiptProofSetContract,
} from "./receipt-proof-set-contract.mjs";
import {
  canonicalDemoVideoReviewAttestation,
  DEMO_VIDEO_REVIEW_CHECK_IDS,
  reviewerSigningKeyId,
  verifyDemoVideoReviewAttestation,
} from "./video-review-attestation.mjs";
import {
  EFFECT_CAPABLE_NEGATIVE_FIXTURES,
  validateInvariantReportContract,
} from "./invariant-contract.mjs";
import {
  WORKER_MICROBENCHMARK_ITERATIONS,
  WORKER_MICROBENCHMARK_PHASES,
  WORKER_MICROBENCHMARK_SIZES,
  validatePerformanceReportContract,
} from "./performance-contract.mjs";
import {
  ALLOWED_MIRROR_ONLY_AUDIT_PATHS,
  sourceProductPath,
} from "./source-delivery-contract.mjs";

const digest = (character) => character.repeat(64);

function proofSetFixture() {
  return {
    schemaVersion: 1,
    kind: "authority-terminal-receipt-proof-set",
    sourceRevision: "1".repeat(40),
    signingKeyId: "2".repeat(24),
    proofs: Object.entries(TERMINAL_RECEIPT_PROOF_CONTRACT).map(
      ([label, contract], index) => {
        const eventDigest = digest(String(index + 3));
        const terminalEvent = {
          eventId: `event-${index}`,
          sequence: index + 1,
          digest: eventDigest,
          type: contract.rollback ? "TRANSITION_ACKNOWLEDGED" : "NON_COMMIT_DISPOSITIONED",
          payload: contract.rollback
            ? { rollbackTargetVersionId: "version-initial" }
            : {},
        };
        return {
          label,
          expectedDecision: contract.decision,
          bundle: {
            schemaVersion: 3,
            receipt: {
              receiptId: `receipt-${index}`,
              runId: `run-${index}`,
              transitionId: `transition-${index}`,
              decision: contract.decision,
            },
            proof: { eventDigest },
            terminalEvent,
            eventChain: [structuredClone(terminalEvent)],
          },
        };
      },
    ),
  };
}

function browserReportFixture() {
  const proofSetSha256 = digest("a");
  const keyIdSha256 = digest("b");
  const stateHash = digest("c");
  const proposalHash = digest("d");
  const baseStep = (id) => ({ id, status: "verified" });
  const steps = BROWSER_CLEAN_CLONE_STEP_IDS.map(baseStep);
  const setEvidence = (id, evidence) => {
    steps.find((entry) => entry.id === id).evidence = evidence;
  };
  setEvidence("browser-positive-committed", {
    decision: "COMMITTED",
    receiptProofVerified: true,
    baseGeneration: 1,
    nextGeneration: 2,
    effectProof: {
      invariant: "PROMOTED_EXACT_PROPOSAL",
      invariantSatisfied: true,
      sealedProposalHash: proposalHash,
      verifierInputHash: proposalHash,
      promotionSourceHash: proposalHash,
      finalAuthoritativeHash: proposalHash,
    },
  });
  const nonEffect = {
    invariant: "NO_PERSISTENT_EFFECT",
    invariantSatisfied: true,
    authoritativeBeforeHash: stateHash,
    authoritativeAfterHash: stateHash,
    baseGeneration: 2,
    nextGeneration: 2,
    receiptProofVerified: true,
  };
  setEvidence("browser-protected-quarantined", structuredClone(nonEffect));
  setEvidence("browser-provider-or-verifier-aborted", structuredClone(nonEffect));
  setEvidence("browser-fresh-follow-up", {
    decision: "COMMITTED",
    receiptProofVerified: true,
  });
  setEvidence("stale-permit-replay-rejected", {
    errorCode: "PERMIT_REPLAY",
    headUnchanged: true,
    beforeHash: stateHash,
    afterHash: stateHash,
    beforeGeneration: 3,
    afterGeneration: 3,
  });
  setEvidence("browser-manual-rollback", {
    rollbackReceiptProofVerified: true,
    rollbackProofCryptographicValid: true,
    rollbackProofSourceRevisionMatches: true,
    rollbackProofSigningKeyMatchesPreRunAnchor: true,
    rollbackReceiptId: "receipt-rollback",
    rollbackVersionSourceReceiptId: "receipt-rollback",
    rollbackProofTargetVersionId: "version-target",
    rollbackTargetVersionId: "version-target",
    rollbackProofFinalWorkspaceHash: stateHash,
    rollbackAuthoritativeAfterHash: stateHash,
    rollbackProofSigningKeyId: "e".repeat(24),
    rollbackProofTerminalEventDigest: digest("f"),
    rollbackProofReceiptHash: digest("1"),
  });
  const artifacts = BROWSER_CLEAN_CLONE_ARTIFACT_KINDS.map((kind, index) => {
    const sha256 = kind === "terminal-receipt-proof-set"
      ? proofSetSha256
      : kind === "receipt-proof-key-id"
        ? keyIdSha256
        : digest(String((index + 2) % 10));
    const evidencePaths = {
      "receipt-proof-bundle": "eval/evidence/receipt-proof-bundle.json",
      "receipt-proof-key-id": "eval/evidence/receipt-proof-key-id.txt",
      "rollback-receipt-proof-bundle":
        "eval/evidence/rollback-receipt-proof-bundle.json",
      "terminal-receipt-proof-set":
        "eval/evidence/terminal-receipt-proof-bundles.json",
    };
    return {
      kind,
      path: evidencePaths[kind] ?? `eval/artifacts/browser/${kind}`,
      sha256,
      sizeBytes: 10 + index,
      ...(kind === "driver-report"
        ? {}
        : { driverSha256: sha256, hashMatchesDriver: true }),
    };
  });
  return {
    report: {
      schemaVersion: 2,
      kind: "browser-clean-clone-evaluation",
      status: "verified",
      providerE2EVerified: "verified",
      provider: { providerId: "ark", credentialsRecorded: false },
      preconditions: BROWSER_CLEAN_CLONE_PRECONDITION_IDS.map((id) => ({
        id,
        status: "verified",
        detail: `${id} verified`,
      })),
      steps,
      artifacts,
    },
    proofSetSha256,
    keyIdSha256,
  };
}

function invariantReportFixture() {
  const observations = (failureField) => EFFECT_CAPABLE_NEGATIVE_FIXTURES.map(
    (fixture, index) => ({
      id: fixture.id,
      expectedOutcome: fixture.expectedOutcome,
      observedOutcome:
        fixture.evidenceMode === "raw-hash" ? fixture.expectedOutcome : null,
      evidenceMode: fixture.evidenceMode,
      rawHashesObserved: fixture.evidenceMode === "raw-hash",
      authoritativeBeforeHash:
        fixture.evidenceMode === "raw-hash" ? digest(String(index + 1)) : null,
      authoritativeAfterHash:
        fixture.evidenceMode === "raw-hash" ? digest(String(index + 1)) : null,
      hashEqualityAssertion:
        fixture.evidenceMode === "assertion-backed" ? true : null,
      assertionTest:
        fixture.evidenceMode === "assertion-backed"
          ? fixture.testPattern.replaceAll(".*", "one durable")
              .replace(/\$$/, "")
          : null,
      assertionClaimId:
        fixture.evidenceMode === "assertion-backed" ? fixture.sourceId : null,
      assertionContract:
        fixture.evidenceMode === "assertion-backed"
          ? fixture.assertionContract
          : null,
      [failureField]: false,
      status: "verified",
    }),
  );
  const allPassed = (id, denominator) => ({
    id,
    status: "verified",
    value: 1,
    numerator: denominator,
    denominator,
  });
  return {
    schemaVersion: 3,
    kind: "commitgate-invariant-evaluation",
    status: "verified",
    effectCapableNegativeFixtureRegistry: structuredClone(
      EFFECT_CAPABLE_NEGATIVE_FIXTURES,
    ),
    metrics: [
      {
        id: "false-commit-rate",
        status: "verified",
        value: 0,
        numerator: 0,
        denominator: EFFECT_CAPABLE_NEGATIVE_FIXTURES.length,
        evidence: observations("falseCommit"),
      },
      {
        id: "rejected-run-persistent-mutation-rate",
        status: "verified",
        value: 0,
        numerator: 0,
        denominator: EFFECT_CAPABLE_NEGATIVE_FIXTURES.length,
        evidence: observations("persistentMutation"),
      },
      allPassed("receipt-validation-rate", 5),
      allPassed("crash-recovery-invariant-pass-rate", 11),
      allPassed("conflict-detection-rate", 3),
      allPassed("cancellation-safety-rate", 7),
    ],
    adversarialCoverage: Array.from({ length: 10 }, (_, index) => ({
      id: `adversarial-${index}`,
      status: "verified",
    })),
  };
}

function performanceReportFixture() {
  return {
    schemaVersion: 1,
    kind: "commitgate-linux-gate-overhead",
    status: "verified",
    command: { exitCode: 0, timedOut: false },
    validation: {
      schemaAndOrder: true,
      workerImageDigest: true,
      productVerifierContainerMeasured: false,
    },
    benchmark: {
      schemaVersion: 1,
      filesystemProfile: "linux-strong",
      manifestSchemaVersion: 2,
      measurementProfile: "worker-local-filesystem-protocol",
      verificationMeasurement: {
        mode: "manifest-and-fixed-file-deterministic-probe",
        brokerRpcIncluded: false,
        verifierContainerIncluded: false,
        trustedCheckBundleProcessIncluded: false,
        modelInferenceIncluded: false,
      },
      iterations: WORKER_MICROBENCHMARK_ITERATIONS,
      sizes: [...WORKER_MICROBENCHMARK_SIZES],
      results: WORKER_MICROBENCHMARK_SIZES.map((sizeBytes) => ({
        sizeBytes,
        iterations: WORKER_MICROBENCHMARK_ITERATIONS,
        phases: Object.fromEntries(
          WORKER_MICROBENCHMARK_PHASES.map((phase) => [
            phase,
            { p50Ms: 1, p95Ms: 2 },
          ]),
        ),
      })),
    },
  };
}

test("terminal proof-set labels have fixed semantics and unique terminal identities", () => {
  const fixture = proofSetFixture();
  assert.equal(validateTerminalReceiptProofSetContract(fixture, {
    sourceRevision: fixture.sourceRevision,
    signingKeyId: fixture.signingKeyId,
  }).valid, true);

  const duplicate = structuredClone(fixture);
  duplicate.proofs[3].bundle = structuredClone(duplicate.proofs[0].bundle);
  assert.equal(validateTerminalReceiptProofSetContract(duplicate).valid, false);

  const relabeled = structuredClone(fixture);
  relabeled.proofs[1].expectedDecision = "COMMITTED";
  assert.equal(validateTerminalReceiptProofSetContract(relabeled).valid, false);

  const fakeRollback = structuredClone(fixture);
  delete fakeRollback.proofs.at(-1).bundle.terminalEvent.payload.rollbackTargetVersionId;
  assert.equal(validateTerminalReceiptProofSetContract(fakeRollback).valid, false);

  const compactV2 = structuredClone(fixture);
  compactV2.proofs[0].bundle.schemaVersion = 2;
  delete compactV2.proofs[0].bundle.eventChain;
  assert.equal(validateTerminalReceiptProofSetContract(compactV2).valid, false);

  const unrelatedChain = structuredClone(fixture);
  unrelatedChain.proofs[0].bundle.eventChain[0].eventId = "different-terminal";
  assert.equal(validateTerminalReceiptProofSetContract(unrelatedChain).valid, false);
});

test("browser report byte-binds the proof set and pre-run signing-key anchor", () => {
  const proofSetSha256 = digest("a");
  const keyIdSha256 = digest("b");
  const artifacts = [
    {
      kind: "terminal-receipt-proof-set",
      sha256: proofSetSha256,
      driverSha256: proofSetSha256,
      hashMatchesDriver: true,
      sizeBytes: 1024,
    },
    {
      kind: "receipt-proof-key-id",
      sha256: keyIdSha256,
      driverSha256: keyIdSha256,
      hashMatchesDriver: true,
      sizeBytes: 25,
    },
  ];
  assert.equal(validateBrowserReceiptArtifactBinding(artifacts, {
    proofSetSha256,
    keyIdSha256,
  }).valid, true);
  const replaced = structuredClone(artifacts);
  replaced[0].sha256 = digest("c");
  assert.equal(validateBrowserReceiptArtifactBinding(replaced, {
    proofSetSha256,
    keyIdSha256,
  }).valid, false);
});

test("active Provider status ignores legacy official/competition/alternate flags", () => {
  assert.equal(declaredCurrentProviderE2EStatus({
    status: "verified",
    officialProviderE2E: "verified",
    competitionVerified: true,
    alternateProviderVerified: true,
  }), "unverified");
  assert.equal(declaredCurrentProviderE2EStatus({
    providerE2EVerified: "verified",
    officialProviderE2E: "failed",
  }), "verified");
});

test("invariant release contract requires every fixed negative fixture and preserves evidence modes", () => {
  const fixture = invariantReportFixture();
  assert.equal(validateInvariantReportContract(fixture).valid, true);

  const missingFixture = structuredClone(fixture);
  missingFixture.effectCapableNegativeFixtureRegistry.pop();
  assert.equal(validateInvariantReportContract(missingFixture).valid, false);

  const missingObservation = structuredClone(fixture);
  missingObservation.metrics[0].evidence.pop();
  assert.equal(validateInvariantReportContract(missingObservation).valid, false);

  const inventedRawHash = structuredClone(fixture);
  const assertion = inventedRawHash.metrics[1].evidence.find(
    (entry) => entry.evidenceMode === "assertion-backed",
  );
  assertion.rawHashesObserved = true;
  assertion.authoritativeBeforeHash = digest("a");
  assertion.authoritativeAfterHash = digest("a");
  assert.equal(validateInvariantReportContract(inventedRawHash).valid, false);

  const missingRawHash = structuredClone(fixture);
  const raw = missingRawHash.metrics[1].evidence.find(
    (entry) => entry.evidenceMode === "raw-hash",
  );
  raw.authoritativeAfterHash = null;
  assert.equal(validateInvariantReportContract(missingRawHash).valid, false);
});

test("performance release contract is Worker-only and rejects verifier-latency relabeling", () => {
  const fixture = performanceReportFixture();
  assert.equal(validatePerformanceReportContract(fixture).valid, true);

  const legacyPhase = structuredClone(fixture);
  for (const row of legacyPhase.benchmark.results) {
    row.phases.trustedVerificationMs = row.phases.deterministicProbeMs;
    delete row.phases.deterministicProbeMs;
  }
  assert.equal(validatePerformanceReportContract(legacyPhase).valid, false);

  const productVerifierClaim = structuredClone(fixture);
  productVerifierClaim.benchmark.verificationMeasurement.verifierContainerIncluded = true;
  assert.equal(validatePerformanceReportContract(productVerifierClaim).valid, false);
});

test("browser checklist and release audit share the exact 10-step evidence contract", () => {
  const fixture = browserReportFixture();
  const expected = {
    providerId: "ark",
    proofSetSha256: fixture.proofSetSha256,
    keyIdSha256: fixture.keyIdSha256,
  };
  assert.equal(
    validateBrowserCleanCloneContract(fixture.report, expected).valid,
    true,
  );

  const missingPrecondition = structuredClone(fixture.report);
  missingPrecondition.preconditions.pop();
  assert.deepEqual(
    validateBrowserCleanCloneContract(missingPrecondition, expected).failedChecks,
    ["preconditions"],
  );

  const nineSteps = structuredClone(fixture.report);
  nineSteps.steps.pop();
  assert.equal(
    validateBrowserCleanCloneContract(nineSteps, expected).checks.steps,
    false,
  );

  const missingArtifact = structuredClone(fixture.report);
  missingArtifact.artifacts = missingArtifact.artifacts.filter(
    (entry) => entry.kind !== "playwright-video",
  );
  assert.equal(
    validateBrowserCleanCloneContract(missingArtifact, expected).checks.artifacts,
    false,
  );

  const legacyOnly = structuredClone(fixture.report);
  delete legacyOnly.providerE2EVerified;
  legacyOnly.officialProviderE2E = "verified";
  legacyOnly.competitionVerified = true;
  legacyOnly.alternateProviderVerified = true;
  assert.equal(
    validateBrowserCleanCloneContract(legacyOnly, expected).checks.provider,
    false,
  );
});

test("external video review requires the exact video, reviewer, key anchor and signature", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const keyId = reviewerSigningKeyId(publicKeyPem);
  const unsigned = {
    schemaVersion: 1,
    kind: "external-demo-video-review-attestation",
    videoSha256: digest("a"),
    reviewer: { id: "reviewer-1", method: "human-full-video-review" },
    reviewedAt: new Date().toISOString(),
    checks: DEMO_VIDEO_REVIEW_CHECK_IDS.map((id) => ({ id, status: "verified" })),
    signingKeyId: keyId,
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
  assert.equal(verifyDemoVideoReviewAttestation(attestation, {
    videoSha256: unsigned.videoSha256,
    expectedReviewerId: "reviewer-1",
    expectedSigningKeyId: keyId,
  }).valid, true);
  assert.equal(verifyDemoVideoReviewAttestation(attestation, {
    videoSha256: digest("b"),
    expectedReviewerId: "reviewer-1",
    expectedSigningKeyId: keyId,
  }).valid, false);
  assert.equal(verifyDemoVideoReviewAttestation(attestation, {
    videoSha256: unsigned.videoSha256,
    expectedReviewerId: null,
    expectedSigningKeyId: null,
  }).status, "unverified");
});

test("active evidence inventory rejects stale report files outside the release allowlist", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "commitgate-active-evidence-"));
  try {
    await mkdir(path.join(root, "eval", "evidence"), { recursive: true });
    await writeFile(path.join(root, "eval", "protocol-report.json"), "{}\n");
    await writeFile(path.join(root, "eval", "real-report.json"), "{}\n");
    await writeFile(path.join(root, "eval", "evidence", "check-report.json"), "{}\n");
    await mkdir(path.join(root, "eval", "unexpected"), { recursive: true });
    await writeFile(path.join(root, "eval", "unexpected", "stale-report.json"), "{}\n");
    const inventory = await activeEvidenceReportInventory(root, [
      "eval/protocol-report.json",
      "eval/evidence/check-report.json",
    ]);
    assert.deepEqual(inventory.unexpected, [
      "eval/real-report.json",
      "eval/unexpected/stale-report.json",
    ]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("active Provider report selection is source-bound and ambiguity fails closed", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "commitgate-provider-evidence-"));
  const sourceRevision = "a".repeat(40);
  const source = {
    sourceRevision,
    sourceTreeHash: "c".repeat(64),
    sourceFileCount: 42,
  };
  const report = (providerId, revision = sourceRevision) => JSON.stringify({
    schemaVersion: 2,
    kind: "real-provider-evaluation",
    status: "verified",
    source: {
      sourceRevision: revision,
      sourceTreeHash: source.sourceTreeHash,
      sourceFileCount: source.sourceFileCount,
      workingTreeCleanAtCapture: true,
    },
    provider: {
      providerId,
      credentialsRecorded: false,
    },
  }) + "\n";
  try {
    await mkdir(path.join(root, "eval"), { recursive: true });
    await writeFile(
      path.join(root, "eval", "provider-ark-report.json"),
      report("ark"),
    );
    await writeFile(
      path.join(root, "eval", "provider-openrouter-report.json"),
      report("openrouter", "b".repeat(40)),
    );
    const uniqueSelection = await resolveActiveProviderReport(root, { source });
    assert.equal(uniqueSelection, "eval/provider-ark-report.json");
    assert.deepEqual(
      (await activeEvidenceReportInventory(root, [uniqueSelection])).unexpected,
      ["eval/provider-openrouter-report.json"],
    );

    await writeFile(
      path.join(root, "eval", "provider-openrouter-report.json"),
      report("openrouter"),
    );
    const ambiguousSelection = await resolveActiveProviderReport(root, { source });
    assert.equal(ambiguousSelection, "eval/provider-current-report.json");
    assert.deepEqual(
      (await activeEvidenceReportInventory(root, [ambiguousSelection])).unexpected,
      ["eval/provider-ark-report.json", "eval/provider-openrouter-report.json"],
    );
    const browserSelection = await resolveActiveProviderReport(root, {
      browserProviderId: "openrouter",
      source,
    });
    assert.equal(browserSelection, "eval/provider-openrouter-report.json");
    assert.deepEqual(
      (await activeEvidenceReportInventory(root, [browserSelection])).unexpected,
      ["eval/provider-ark-report.json"],
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("source-delivery byte binding covers every Compose Dockerfile", () => {
  for (const relative of [
    "Dockerfile",
    "Dockerfile.runtime",
    "Dockerfile.runtime-broker",
    "Dockerfile.transition-worker",
    "Dockerfile.model-relay",
    "Dockerfile.api-recovery-eval",
  ]) {
    assert.equal(sourceProductPath(relative), true, relative);
  }
  assert.equal(sourceProductPath("docker-compose.yml"), true);
  assert.equal(sourceProductPath("docker-compose.transition-worker.yml"), true);
  assert.equal(sourceProductPath("README.md"), false);
  assert.deepEqual(ALLOWED_MIRROR_ONLY_AUDIT_PATHS, [
    "scripts/check-drawio.py",
    "scripts/check-public-copy.mjs",
    "scripts/render-drawio-preview.py",
  ]);
});

test("real Provider evaluator binds its frozen source revision into its isolated API", async () => {
  const evaluator = await readFile(
    path.join(import.meta.dirname, "eval-real.ts"),
    "utf8",
  );
  assert.match(evaluator, /const sourceRevision = source\.sourceRevision/);
  assert.match(evaluator, /COMMITGATE_SOURCE_REVISION:\s*sourceRevision/);
  assert.match(evaluator, /provider-\$\{provider\}-report\.json/);
  assert.doesNotMatch(
    evaluator,
    /path\.join\(root,\s*"eval",\s*"real-report\.json"\)/s,
  );
  for (const id of REAL_PROVIDER_E2E_SCENARIO_IDS) {
    assert.match(evaluator, new RegExp(`id: ["']${id}["']`));
  }
});

test("real Provider compatibility and browser frontend remain separate contracts", () => {
  const providerId = "ark";
  const report = {
    schemaVersion: 2,
    kind: "real-provider-evaluation",
    status: "verified",
    providerE2EVerified: "verified",
    provider: {
      providerId,
      resolvedModel: "resolved-model",
      credentialsRecorded: false,
    },
    provenance: {
      realProviderRequest: true,
      realCodexContainer: true,
      frontendAssetServed: false,
    },
    scenario: REAL_PROVIDER_E2E_SCENARIO_IDS.map((id) => ({
      id,
      status: "verified",
    })),
  };
  assert.equal(validateRealProviderE2EContract(report, { providerId }).valid, true);
  report.scenario[0] = { id: "frontend-served", status: "verified" };
  assert.equal(validateRealProviderE2EContract(report, { providerId }).valid, false);
});

test("Docker recovery evaluator exercises the frozen product Worker image", async () => {
  const evaluator = await readFile(
    path.join(import.meta.dirname, "eval-recovery-docker.mjs"),
    "utf8",
  );
  assert.match(
    evaluator,
    /process\.env\.COMMITGATE_TRANSITION_WORKER_IMAGE\?\.trim\(\)/,
  );
  assert.match(
    evaluator,
    /explicitWorkerImage\s*\|\|\s*"commitgate-transition-worker:local"/,
  );
  assert.match(evaluator, /source:\s*explicitWorkerImage\s*\?\s*"caller-frozen-image"/);
  assert.match(evaluator, /health\?\.status\s*===\s*"ok"/);
  assert.match(evaluator, /health\?\.authority\s*===\s*"transition-worker"/);
  assert.match(evaluator, /async function inspectScenarioState/);
  assert.match(
    evaluator,
    /if \(inspected\.status !== 0\)[\s\S]*throw new Error\(inspected\.stderr \|\| inspected\.stdout\)/,
  );
  assert.match(evaluator, /const parsed = tryParseLastJson\(inspected\.stdout\)/);
  assert.match(evaluator, /waitForState\(container, \["exited", "dead"\], 50\)/);
  assert.doesNotMatch(
    evaluator,
    /command\(\["image",\s*"rm",\s*"--force",\s*image\]/,
  );

  const driver = await readFile(
    path.join(import.meta.dirname, "recovery-docker-driver.mjs"),
    "utf8",
  );
  assert.match(driver, /RECOVERY_RPC_TIMEOUT_MS\s*\?\?\s*"30000"/);
  assert.match(driver, /WorkerTransitionAuthorityClient\(socketPath,\s*rpcTimeoutMs\)/);
});
