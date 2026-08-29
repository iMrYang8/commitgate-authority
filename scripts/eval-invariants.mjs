#!/usr/bin/env node
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { evidenceProvenance, executionIdentity } from "./evidence-utils.mjs";
import { EFFECT_CAPABLE_NEGATIVE_FIXTURES } from "./invariant-contract.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const outputPath = path.join(root, "eval", "evidence", "invariants-report.json");

async function load(relativePath) {
  try {
    return JSON.parse(await readFile(path.join(root, relativePath), "utf8"));
  } catch {
    return null;
  }
}

const protocol = await load("eval/protocol-report.json");
const adversarial = await load("eval/adversarial-report.json");
const recovery = await load("eval/recovery-report.json");
const container = await load("eval/container-report.json");
const browser = await load("eval/browser-clean-clone-report.json");
const dockerRecovery = await load("eval/evidence/docker-recovery-report.json");
const receiptVerification = await load("eval/evidence/receipt-verification-report.json");

const claim = (report, id) => report?.claims?.find((item) => item.id === id) ?? null;
const browserStep = (id) => browser?.steps?.find((item) => item.id === id)?.evidence ?? null;
const passedClaimAssertions = (report, id) => {
  const value = claim(report, id);
  return Array.isArray(value?.evidence)
    ? value.evidence.map((entry, index) => ({
        id: `${id}:${index + 1}`,
        status:
          value.status === "verified" && entry.status === "passed"
            ? "verified"
            : entry.status === "failed" || value.status === "failed"
              ? "failed"
              : "unverified",
        test: entry.test ?? null,
      }))
    : [];
};
const classify = (observations) =>
  observations.some((entry) => entry.status === "failed")
    ? "failed"
    : observations.length === 0 || observations.some((entry) => entry.status === "unverified")
      ? "unverified"
      : "verified";
const rateMetric = ({ id, observations, failureRate = false, unit }) => {
  const status = classify(observations);
  const passed = observations.filter((entry) => entry.status === "verified").length;
  const failed = observations.filter((entry) => entry.status === "failed").length;
  return {
    id,
    status,
    value: status === "unverified"
      ? null
      : failureRate
        ? failed / observations.length
        : passed / observations.length,
    unit,
    numerator: status === "unverified" ? null : failureRate ? failed : passed,
    denominator: observations.length,
    evidence: observations,
  };
};

const reportsByName = { protocol, adversarial, recovery };
const digestPattern = /^[a-f0-9]{64}$/;

function resolveAssertionFixture(fixture) {
  const report = reportsByName[fixture.sourceReport];
  const evidenceClaim = claim(report, fixture.sourceId);
  const entries = Array.isArray(evidenceClaim?.evidence) ? evidenceClaim.evidence : [];
  const matcher = new RegExp(fixture.testPattern, "i");
  const matches = entries.filter((entry) => matcher.test(entry?.test ?? ""));
  const assertion = matches.length === 1 ? matches[0] : null;
  const status = !report
    ? "unverified"
    : evidenceClaim?.status === "failed" || matches.some((entry) => entry.status === "failed")
      ? "failed"
      : evidenceClaim?.status === "verified" &&
          matches.length === 1 &&
          assertion?.status === "passed"
        ? "verified"
        : "failed";
  return {
    status,
    assertionTest: assertion?.test ?? null,
    assertionClaimId: fixture.sourceId,
    assertionContract: fixture.assertionContract,
    rawHashesObserved: false,
    authoritativeBeforeHash: null,
    authoritativeAfterHash: null,
    hashEqualityAssertion: status === "verified" ? true : null,
  };
}

function resolveRawFixture(fixture) {
  const value = browserStep(fixture.sourceId);
  const replay = fixture.expectedOutcome === "PERMIT_REPLAY";
  const observedOutcome = replay ? value?.errorCode ?? null : value?.decision ?? null;
  const beforeHash = replay
    ? value?.beforeHash ?? null
    : value?.authoritativeBeforeHash ?? null;
  const afterHash = replay
    ? value?.afterHash ?? null
    : value?.authoritativeAfterHash ?? null;
  const beforeGeneration = replay
    ? value?.beforeGeneration ?? null
    : value?.baseGeneration ?? null;
  const afterGeneration = replay
    ? value?.afterGeneration ?? null
    : value?.nextGeneration ?? null;
  const outcomeStatus = !value
    ? "unverified"
    : value.status === "verified" && observedOutcome === fixture.expectedOutcome
      ? "verified"
      : "failed";
  const nonEffectStatus = outcomeStatus !== "verified"
    ? outcomeStatus
    : digestPattern.test(beforeHash ?? "") &&
        beforeHash === afterHash &&
        Number.isSafeInteger(beforeGeneration) &&
        beforeGeneration === afterGeneration &&
        (replay
          ? value.headUnchanged === true
          : value.invariant === "NO_PERSISTENT_EFFECT" &&
            value.invariantSatisfied === true)
      ? "verified"
      : "failed";
  return {
    outcomeStatus,
    nonEffectStatus,
    observedOutcome,
    runId: value?.runId ?? null,
    rawHashesObserved: true,
    authoritativeBeforeHash: beforeHash,
    authoritativeAfterHash: afterHash,
    beforeGeneration,
    afterGeneration,
    hashEqualityAssertion: null,
    assertionTest: null,
  };
}

const resolvedNegativeFixtures = EFFECT_CAPABLE_NEGATIVE_FIXTURES.map((fixture) => ({
  fixture,
  evidence: fixture.sourceKind === "browser-step"
    ? resolveRawFixture(fixture)
    : resolveAssertionFixture(fixture),
}));

const negativeRunObservations = resolvedNegativeFixtures.map(({ fixture, evidence }) => {
  const status = fixture.evidenceMode === "raw-hash"
    ? evidence.outcomeStatus
    : evidence.status;
  return {
    id: fixture.id,
    expectedOutcome: fixture.expectedOutcome,
    observedOutcome: evidence.observedOutcome ?? null,
    runId: evidence.runId ?? null,
    evidenceMode: fixture.evidenceMode,
    rawHashesObserved: evidence.rawHashesObserved,
    authoritativeBeforeHash: evidence.authoritativeBeforeHash,
    authoritativeAfterHash: evidence.authoritativeAfterHash,
    hashEqualityAssertion: evidence.hashEqualityAssertion,
    assertionTest: evidence.assertionTest,
    assertionClaimId: evidence.assertionClaimId ?? null,
    assertionContract: evidence.assertionContract ?? null,
    falseCommit: status === "verified" ? false : evidence.observedOutcome === "COMMITTED" ? true : null,
    status,
  };
});

const nonEffectObservations = resolvedNegativeFixtures.map(({ fixture, evidence }) => {
  const status = fixture.evidenceMode === "raw-hash"
    ? evidence.nonEffectStatus
    : evidence.status;
  const rawMutation = fixture.evidenceMode === "raw-hash" &&
    digestPattern.test(evidence.authoritativeBeforeHash ?? "") &&
    digestPattern.test(evidence.authoritativeAfterHash ?? "")
      ? evidence.authoritativeBeforeHash !== evidence.authoritativeAfterHash
      : null;
  return {
    id: fixture.id,
    expectedOutcome: fixture.expectedOutcome,
    observedOutcome: evidence.observedOutcome ?? null,
    evidenceMode: fixture.evidenceMode,
    rawHashesObserved: evidence.rawHashesObserved,
    authoritativeBeforeHash: evidence.authoritativeBeforeHash,
    authoritativeAfterHash: evidence.authoritativeAfterHash,
    beforeGeneration: evidence.beforeGeneration ?? null,
    afterGeneration: evidence.afterGeneration ?? null,
    hashEqualityAssertion: evidence.hashEqualityAssertion,
    assertionTest: evidence.assertionTest,
    assertionClaimId: evidence.assertionClaimId ?? null,
    assertionContract: evidence.assertionContract ?? null,
    persistentMutation: status === "verified"
      ? false
      : rawMutation,
    status,
  };
});

const failureRateMetric = ({ id, observations, failureField, unit }) => {
  const status = classify(observations);
  const complete = observations.every((entry) => typeof entry[failureField] === "boolean");
  const numerator = complete
    ? observations.filter((entry) => entry[failureField] === true).length
    : null;
  return {
    id,
    status,
    value: complete ? numerator / observations.length : null,
    unit,
    numerator,
    denominator: observations.length,
    evidence: observations,
  };
};

const expectedReceiptProofLabels = [
  "positive-commit",
  "protected-path-quarantine",
  "provider-or-verifier-abort",
  "fresh-follow-up-commit",
  "manual-rollback",
];
const receiptRecords = new Map(
  (receiptVerification?.records ?? []).map((entry) => [entry.label, entry]),
);
const receiptObservations = expectedReceiptProofLabels.map((label) => {
  const record = receiptRecords.get(label);
  return {
    id: `offline-terminal-receipt-proof:${label}`,
    receiptId: record?.receiptId ?? null,
    signingKeyId: record?.signingKeyId ?? null,
    terminalEventDigest: record?.eventDigest ?? null,
    status: !record || receiptVerification?.status === "unverified"
      ? "unverified"
      : receiptVerification?.schemaVersion === 3 &&
          receiptVerification?.kind ===
            "offline-terminal-receipt-proof-set-verification" &&
          receiptVerification?.verification?.allTerminalReceiptsVerified === true &&
          record.status === "verified" &&
          record.verification?.valid === true &&
          /^[a-f0-9]{24}$/.test(record.signingKeyId ?? "") &&
          /^[a-f0-9]{64}$/.test(record.eventDigest ?? "") &&
          /^[a-f0-9]{64}$/.test(record.receiptHash ?? "")
        ? "verified"
        : "failed",
  };
});

const dockerScenarios = dockerRecovery?.faultPoints ?? dockerRecovery?.scenarios ?? [];
const crashObservations = Array.isArray(dockerScenarios)
  ? dockerScenarios.map((entry) => ({
      id: entry.id ?? "unnamed-crash-point",
      faultPoint: entry.faultPoint ?? null,
      decision: entry.observed?.terminalDecision ?? null,
      status:
        entry.status === "verified" &&
        entry.assertions &&
        Object.values(entry.assertions).every(Boolean)
          ? "verified"
          : entry.status === "failed"
            ? "failed"
            : "unverified",
    }))
  : [];

const conflictObservations = [
  ...passedClaimAssertions(protocol, "view-cas-conflict"),
  ...passedClaimAssertions(protocol, "worker-cas-conflict-decision"),
];
const cancellationObservations = [
  ...passedClaimAssertions(protocol, "worker-cancellation-fence"),
  ...passedClaimAssertions(recovery, "worker-cancellation-race"),
  ...["agent", "verifier"].map((workload) => {
    const entry = container?.brokerCancellation?.[workload];
    return {
      id: `broker-${workload}-container-cancellation`,
      status:
        entry?.status === "verified" &&
        entry.cancelAccepted === true &&
        entry.promiseCancelled === true &&
        entry.forceRemoved === true &&
        entry.teardown?.containerExited === true &&
        entry.teardown?.containerRemoved === true &&
        entry.teardown?.mountsReleased === true
          ? "verified"
          : entry?.status === "failed"
            ? "failed"
            : "unverified",
    };
  }),
];

const adversarialCoverageIds = [
  "path-budget-canary-platform",
  "malformed-evidence-fail-closed",
  "candidate-mutation-detected",
  "candidate-test-runner-bypass",
  "trusted-bundle-link-rejection",
  "verifier-clean-environment",
  "late-write-after-runtime",
  "sealed-source-tamper",
  "ignored-path-dos",
  "worker-owned-permit-policy",
];
const adversarialCoverage = adversarialCoverageIds.map((id) => ({
  id,
  status: claim(adversarial, id)?.status ?? "unverified",
  assertions: claim(adversarial, id)?.evidence?.length ?? 0,
}));

const metrics = [
  failureRateMetric({
    id: "false-commit-rate",
    observations: negativeRunObservations,
    failureField: "falseCommit",
    unit: "false-commits/fixed-effect-capable-negative-fixture",
  }),
  failureRateMetric({
    id: "rejected-run-persistent-mutation-rate",
    observations: nonEffectObservations,
    failureField: "persistentMutation",
    unit: "mutations/fixed-effect-capable-negative-fixture",
  }),
  rateMetric({
    id: "receipt-validation-rate",
    observations: receiptObservations,
    unit: "verified/terminal-receipt-proof",
  }),
  rateMetric({
    id: "crash-recovery-invariant-pass-rate",
    observations: crashObservations,
    unit: "verified/docker-process-fault-point",
  }),
  rateMetric({
    id: "conflict-detection-rate",
    observations: conflictObservations,
    unit: "passed/explicit-conflict-assertion",
  }),
  rateMetric({
    id: "cancellation-safety-rate",
    observations: cancellationObservations,
    unit: "passed/cancellation-fence-or-container-observation",
  }),
];

const status = metrics.some((metric) => metric.status === "failed") ||
    adversarialCoverage.some((entry) => entry.status === "failed")
  ? "failed"
  : metrics.every((metric) => metric.status === "verified") &&
      adversarialCoverage.every((entry) => entry.status === "verified")
    ? "verified"
    : "unverified";
const report = {
  schemaVersion: 3,
  kind: "commitgate-invariant-evaluation",
  generatedAt: new Date().toISOString(),
  status,
  source: await evidenceProvenance(root),
  executionIdentity: executionIdentity(root),
  effectCapableNegativeFixtureRegistry: EFFECT_CAPABLE_NEGATIVE_FIXTURES,
  metrics,
  adversarialCoverage,
  claimBoundary:
    "Rates are results over one fixed, finite effect-capable negative-fixture registry, not universal probabilities. Browser quarantine, abort, and permit replay carry observed raw before/after hashes. CONFLICTED and accepted-cancellation fixtures are explicitly assertion-backed: their revision-bound Vitest cases compare authoritative state, but this report leaves raw hash fields null rather than inventing hash values. Missing registry evidence fails the contract. Broader adversarial coverage remains separate and does not inflate these denominators.",
};
await mkdir(path.dirname(outputPath), { recursive: true });
await writeFile(outputPath, JSON.stringify(report, null, 2) + "\n", "utf8");
for (const metric of metrics) console.log(`${metric.status.padEnd(10)} ${metric.id}`);
console.log(`${status}: invariant report: ${outputPath}`);
process.exitCode = status === "verified" ? 0 : status === "unverified" ? 2 : 1;
