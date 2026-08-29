export const EFFECT_CAPABLE_NEGATIVE_FIXTURES = Object.freeze([
  Object.freeze({
    id: "browser-protected-quarantined",
    sourceKind: "browser-step",
    sourceReport: "browser",
    sourceId: "browser-protected-quarantined",
    expectedOutcome: "QUARANTINED",
    evidenceMode: "raw-hash",
  }),
  Object.freeze({
    id: "browser-provider-or-verifier-aborted",
    sourceKind: "browser-step",
    sourceReport: "browser",
    sourceId: "browser-provider-or-verifier-aborted",
    expectedOutcome: "ABORTED",
    evidenceMode: "raw-hash",
  }),
  Object.freeze({
    id: "browser-stale-permit-replay",
    sourceKind: "browser-step",
    sourceReport: "browser",
    sourceId: "stale-permit-replay-rejected",
    expectedOutcome: "PERMIT_REPLAY",
    evidenceMode: "raw-hash",
  }),
  Object.freeze({
    id: "worker-h0-h1-view-cas-conflicted",
    sourceKind: "claim-test",
    sourceReport: "protocol",
    sourceId: "worker-cas-conflict-decision",
    testPattern:
      "durably conflicts an H0 proposal after H1 wins without changing workspace, generation, or versions$",
    expectedOutcome: "CONFLICTED",
    evidenceMode: "assertion-backed",
    assertionContract:
      "Vitest asserts the stale H0 proposal becomes CONFLICTED while the winning H1 workspace hash, generation, and versions remain unchanged.",
  }),
  Object.freeze({
    id: "worker-workspace-cas-conflicted",
    sourceKind: "claim-test",
    sourceReport: "protocol",
    sourceId: "worker-cas-conflict-decision",
    testPattern:
      "durably classifies a stale promotion workspace hash as CONFLICTED$",
    expectedOutcome: "CONFLICTED",
    evidenceMode: "assertion-backed",
    assertionContract:
      "Vitest asserts a stale workspace-hash promotion becomes CONFLICTED while authoritative workspace hash, generation, and versions remain unchanged.",
  }),
  Object.freeze({
    id: "worker-runner-view-cas-conflicted",
    sourceKind: "claim-test",
    sourceReport: "protocol",
    sourceId: "worker-cas-conflict-decision",
    testPattern:
      "maps a stale Worker View CAS to one durable CONFLICTED disposition before finalize$",
    expectedOutcome: "CONFLICTED",
    evidenceMode: "assertion-backed",
    assertionContract:
      "Vitest asserts one durable CONFLICTED receipt and equality of the disposition-time Worker HEAD hash before and after Runner finalization.",
  }),
  ...["verifier", "permit", "promotion"].map((stage) => Object.freeze({
    id: `worker-cancel-before-${stage}`,
    sourceKind: "claim-test",
    sourceReport: "protocol",
    sourceId: "worker-cancellation-fence",
    testPattern: `makes cancellation authoritative before ${stage}$`,
    expectedOutcome: "ABORTED",
    evidenceMode: "assertion-backed",
    assertionContract:
      "Vitest asserts accepted cancellation, an ABORTED terminal receipt, unchanged Worker workspace hash and generation, and no new version.",
  })),
  Object.freeze({
    id: "worker-cancel-before-permit-consumption",
    sourceKind: "claim-test",
    sourceReport: "recovery",
    sourceId: "worker-cancellation-race",
    testPattern: "fences an accepted run cancellation before permit consumption$",
    expectedOutcome: "ABORTED",
    evidenceMode: "assertion-backed",
    assertionContract:
      "Vitest asserts accepted Worker cancellation, an ABORTED terminal receipt, unchanged generation, and no new version.",
  }),
]);

export const EFFECT_CAPABLE_NEGATIVE_FIXTURE_IDS = Object.freeze(
  EFFECT_CAPABLE_NEGATIVE_FIXTURES.map((fixture) => fixture.id),
);

export const INVARIANT_METRIC_IDS = Object.freeze([
  "false-commit-rate",
  "rejected-run-persistent-mutation-rate",
  "receipt-validation-rate",
  "crash-recovery-invariant-pass-rate",
  "conflict-detection-rate",
  "cancellation-safety-rate",
]);

const digestPattern = /^[a-f0-9]{64}$/;
const exactUniqueIds = (entries, ids) =>
  Array.isArray(entries) &&
  entries.length === ids.length &&
  new Set(entries.map((entry) => entry?.id)).size === ids.length &&
  ids.every((id) => entries.some((entry) => entry?.id === id));

function rawHashObservationValid(entry, fixture) {
  return entry?.evidenceMode === "raw-hash" &&
    entry?.observedOutcome === fixture.expectedOutcome &&
    entry?.rawHashesObserved === true &&
    digestPattern.test(entry?.authoritativeBeforeHash ?? "") &&
    entry.authoritativeBeforeHash === entry.authoritativeAfterHash &&
    entry?.hashEqualityAssertion === null &&
    entry?.assertionTest === null;
}

function assertionBackedObservationValid(entry, fixture) {
  const matcher = new RegExp(fixture.testPattern, "i");
  return entry?.evidenceMode === "assertion-backed" &&
    entry?.observedOutcome === null &&
    entry?.rawHashesObserved === false &&
    entry?.authoritativeBeforeHash === null &&
    entry?.authoritativeAfterHash === null &&
    entry?.hashEqualityAssertion === true &&
    typeof entry?.assertionTest === "string" &&
    matcher.test(entry.assertionTest) &&
    entry?.assertionClaimId === fixture.sourceId &&
    entry?.assertionContract === fixture.assertionContract;
}

/**
 * One release/checklist contract for the finite set of product-effect-capable
 * negative fixtures. Assertion-backed observations are accepted only when they
 * stay explicitly distinct from raw before/after hashes.
 */
export function validateInvariantReportContract(report) {
  const registry = report?.effectCapableNegativeFixtureRegistry;
  const metrics = Array.isArray(report?.metrics) ? report.metrics : [];
  const metricMap = new Map(metrics.map((metric) => [metric?.id, metric]));
  const falseCommit = metricMap.get("false-commit-rate");
  const nonEffect = metricMap.get("rejected-run-persistent-mutation-rate");
  const registryExact =
    exactUniqueIds(registry, EFFECT_CAPABLE_NEGATIVE_FIXTURE_IDS) &&
    EFFECT_CAPABLE_NEGATIVE_FIXTURES.every((expected) => {
      const actual = registry.find((entry) => entry.id === expected.id);
      return actual?.sourceKind === expected.sourceKind &&
        actual?.sourceReport === expected.sourceReport &&
        actual?.sourceId === expected.sourceId &&
        actual?.expectedOutcome === expected.expectedOutcome &&
        actual?.evidenceMode === expected.evidenceMode &&
        (expected.testPattern === undefined || actual?.testPattern === expected.testPattern) &&
        (expected.assertionContract === undefined ||
          actual?.assertionContract === expected.assertionContract);
    });
  const fixtureMetricValid = (metric, failureField) =>
    metric?.status === "verified" &&
    metric?.value === 0 &&
    metric?.numerator === 0 &&
    metric?.denominator === EFFECT_CAPABLE_NEGATIVE_FIXTURE_IDS.length &&
    exactUniqueIds(metric?.evidence, EFFECT_CAPABLE_NEGATIVE_FIXTURE_IDS) &&
    EFFECT_CAPABLE_NEGATIVE_FIXTURES.every((fixture) => {
      const entry = metric.evidence.find((candidate) => candidate.id === fixture.id);
      if (
        entry?.status !== "verified" ||
        entry?.expectedOutcome !== fixture.expectedOutcome ||
        entry?.[failureField] !== false
      ) {
        return false;
      }
      return fixture.evidenceMode === "raw-hash"
        ? rawHashObservationValid(entry, fixture)
        : assertionBackedObservationValid(entry, fixture);
    });
  const otherMinimums = new Map([
    ["receipt-validation-rate", 5],
    ["crash-recovery-invariant-pass-rate", 11],
    ["conflict-detection-rate", 2],
    ["cancellation-safety-rate", 7],
  ]);
  const otherMetricsValid = [...otherMinimums].every(([id, minimum]) => {
    const metric = metricMap.get(id);
    return metric?.status === "verified" &&
      metric?.value === 1 &&
      metric?.numerator === metric?.denominator &&
      metric?.denominator >= minimum;
  });
  const exactMetrics = exactUniqueIds(metrics, INVARIANT_METRIC_IDS);
  const adversarialCoverageValid =
    Array.isArray(report?.adversarialCoverage) &&
    report.adversarialCoverage.length >= 10 &&
    report.adversarialCoverage.every((entry) => entry?.status === "verified");
  const valid =
    report?.schemaVersion === 3 &&
    report?.kind === "commitgate-invariant-evaluation" &&
    report?.status === "verified" &&
    registryExact &&
    exactMetrics &&
    fixtureMetricValid(falseCommit, "falseCommit") &&
    fixtureMetricValid(nonEffect, "persistentMutation") &&
    otherMetricsValid &&
    adversarialCoverageValid;
  return {
    valid,
    reason: valid
      ? null
      : "invariant report does not contain the exact negative-fixture registry and evidence-mode-safe metrics",
    checks: {
      registryExact,
      exactMetrics,
      falseCommit: fixtureMetricValid(falseCommit, "falseCommit"),
      nonEffect: fixtureMetricValid(nonEffect, "persistentMutation"),
      otherMetrics: otherMetricsValid,
      adversarialCoverage: adversarialCoverageValid,
    },
  };
}
