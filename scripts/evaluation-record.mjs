/**
 * NiceEval-inspired adapter: every evaluator can emit the same compact record
 * without pretending that deterministic, browser and Provider runs are the
 * same execution surface.
 */
export function evaluationRecord({ source, provider, scenario, surface = "browser-clean-clone", executionIdentity = null }) {
  return {
    schemaVersion: 1,
    recordId: String(scenario.id),
    revision: source.sourceRevision,
    sourceTreeHash: source.sourceTreeHash,
    runId: typeof scenario.runId === "string" ? scenario.runId : null,
    provider: provider?.providerId ?? null,
    model: provider?.resolvedModel ?? provider?.requestedModel ?? null,
    baseViewId: scenario.baseViewId ?? null,
    finalViewId: scenario.nextViewId ?? null,
    baseGeneration: Number.isInteger(scenario.baseGeneration)
      ? scenario.baseGeneration
      : null,
    nextGeneration: Number.isInteger(scenario.nextGeneration)
      ? scenario.nextGeneration
      : null,
    proposalId: scenario.proposalId ?? null,
    evidenceDigest: scenario.evidenceDigest ?? null,
    evaluationContextHash: scenario.evaluationContextHash ?? null,
    permitId: scenario.permitId ?? null,
    permitState: scenario.permitState ?? null,
    policyProfile: scenario.policyProfile ?? null,
    policyVersion: Number.isInteger(scenario.policyVersion) ? scenario.policyVersion : null,
    policyHash: scenario.policyHash ?? null,
    checkSpecHash: scenario.checkSpecHash ?? null,
    eventSequence: Number.isInteger(scenario.eventSequence) ? scenario.eventSequence : null,
    eventDigest: scenario.eventDigest ?? null,
    decision: scenario.decision ?? null,
    exitStatus:
      scenario.status === "verified" ? 0 : scenario.status === "unverified" ? 2 : 1,
    surface,
    runtimeImageDigest: executionIdentity?.runtimeImage?.imageDigest ?? null,
    verifierImageDigest: executionIdentity?.verifierImage?.imageDigest ?? null,
  };
}

export function assertEvaluationRecord(record) {
  if (
    record?.schemaVersion !== 1 ||
    typeof record.recordId !== "string" ||
    !record.recordId ||
    typeof record.revision !== "string" ||
    (!/^[a-f0-9]{40}$/.test(record.sourceTreeHash ?? "") &&
      !/^[a-f0-9]{64}$/.test(record.sourceTreeHash ?? "")) ||
    ![0, 1, 2].includes(record.exitStatus) ||
    !["protocol", "adversarial", "recovery", "container", "filesystem", "topology", "browser-clean-clone", "p1-product"].includes(record.surface)
  ) {
    throw new Error("EVALUATION_RECORD_INVALID");
  }
  if (
    record.surface === "browser-clean-clone" &&
    record.decision !== null &&
    (typeof record.runtimeImageDigest !== "string" ||
      typeof record.verifierImageDigest !== "string" ||
      !Number.isInteger(record.eventSequence) ||
      !/^[a-f0-9]{64}$/.test(record.eventDigest ?? "") ||
      !["workspace-default", "deployment-protected"].includes(record.policyProfile) ||
      !Number.isInteger(record.policyVersion) ||
      !/^[a-f0-9]{64}$/.test(record.policyHash ?? "") ||
      !/^[a-f0-9]{64}$/.test(record.checkSpecHash ?? ""))
  ) {
    throw new Error("EVALUATION_RECORD_TERMINAL_IDENTITY_INCOMPLETE");
  }
  return record;
}
