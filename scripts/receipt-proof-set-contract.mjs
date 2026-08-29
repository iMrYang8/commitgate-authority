const idPattern = /^[A-Za-z0-9_.-]{1,128}$/;
const digestPattern = /^[a-f0-9]{64}$/;

export const BROWSER_CLEAN_CLONE_STEP_IDS = Object.freeze([
  "clean-clone-npm-ci-and-image-build",
  "browser-create-agent",
  "browser-positive-committed",
  "browser-candidate-runner-cannot-self-verify",
  "browser-protected-quarantined",
  "browser-provider-or-verifier-aborted",
  "browser-fresh-follow-up",
  "provider-identity-bound",
  "stale-permit-replay-rejected",
  "browser-manual-rollback",
]);

export const BROWSER_CLEAN_CLONE_PRECONDITION_IDS = Object.freeze([
  "committed-clean-source",
  "provider-credentials",
  "git-client",
  "container-engine",
  "checked-in-playwright-driver",
]);

export const BROWSER_CLEAN_CLONE_ARTIFACT_KINDS = Object.freeze([
  "playwright-trace",
  "playwright-video",
  "final-screenshot",
  "receipt-proof-bundle",
  "receipt-proof-key-id",
  "rollback-receipt-proof-bundle",
  "terminal-receipt-proof-set",
  "driver-report",
]);

/**
 * Active reports must make the Provider-neutral declaration explicitly. Legacy
 * brand/path flags remain readable as historical data but have no authority to
 * turn a current release/checklist item green.
 */
export function declaredCurrentProviderE2EStatus(report) {
  return ["verified", "failed", "unverified"].includes(
    report?.providerE2EVerified,
  )
    ? report.providerE2EVerified
    : "unverified";
}

export const TERMINAL_RECEIPT_PROOF_CONTRACT = Object.freeze({
  "positive-commit": Object.freeze({ decision: "COMMITTED", rollback: false }),
  "protected-path-quarantine": Object.freeze({
    decision: "QUARANTINED",
    rollback: false,
  }),
  "provider-or-verifier-abort": Object.freeze({ decision: "ABORTED", rollback: false }),
  "fresh-follow-up-commit": Object.freeze({ decision: "COMMITTED", rollback: false }),
  "manual-rollback": Object.freeze({ decision: "COMMITTED", rollback: true }),
});

const unique = (values) =>
  values.length > 0 && values.every((value) => typeof value === "string") &&
  new Set(values).size === values.length;

/**
 * Validate the finite browser proof-set envelope independently from signature
 * verification.  In particular, labels are protocol fields, not caller-authored
 * descriptions: each label has one fixed decision/rollback meaning and every
 * terminal fact must be distinct.
 */
export function validateTerminalReceiptProofSetContract(
  proofSet,
  { sourceRevision = null, signingKeyId = null } = {},
) {
  const requiredLabels = Object.keys(TERMINAL_RECEIPT_PROOF_CONTRACT);
  const proofs = Array.isArray(proofSet?.proofs) ? proofSet.proofs : [];
  const labels = proofs.map((entry) => entry?.label);
  const records = proofs.map((entry) => {
    const contract = TERMINAL_RECEIPT_PROOF_CONTRACT[entry?.label] ?? null;
    const receipt = entry?.bundle?.receipt;
    const terminalEvent = entry?.bundle?.terminalEvent;
    const eventChain = entry?.bundle?.eventChain;
    const chainTerminal = Array.isArray(eventChain) ? eventChain.at(-1) : null;
    const fullEventChainValid =
      entry?.bundle?.schemaVersion === 3 &&
      Array.isArray(eventChain) &&
      eventChain.length > 0 &&
      typeof terminalEvent?.eventId === "string" &&
      chainTerminal?.eventId === terminalEvent.eventId &&
      chainTerminal?.sequence === terminalEvent.sequence &&
      chainTerminal?.digest === terminalEvent.digest;
    const rollbackTargetVersionId = terminalEvent?.payload?.rollbackTargetVersionId;
    const rollbackShapeValid = contract?.rollback === true
      ? terminalEvent?.type === "TRANSITION_ACKNOWLEDGED" &&
        idPattern.test(rollbackTargetVersionId ?? "")
      : rollbackTargetVersionId === undefined;
    return {
      label: entry?.label ?? null,
      expectedDecision: contract?.decision ?? null,
      declaredExpectedDecision: entry?.expectedDecision ?? null,
      observedDecision: receipt?.decision ?? null,
      receiptId: receipt?.receiptId ?? null,
      runId: receipt?.runId ?? null,
      transitionId: receipt?.transitionId ?? null,
      eventDigest: entry?.bundle?.proof?.eventDigest ?? null,
      bundleSchemaVersion: entry?.bundle?.schemaVersion ?? null,
      eventChainLength: Array.isArray(eventChain) ? eventChain.length : 0,
      fullEventChainValid,
      rollbackTargetVersionId: rollbackTargetVersionId ?? null,
      valid:
        contract !== null &&
        fullEventChainValid &&
        entry?.expectedDecision === contract.decision &&
        receipt?.decision === contract.decision &&
        idPattern.test(receipt?.receiptId ?? "") &&
        idPattern.test(receipt?.runId ?? "") &&
        idPattern.test(receipt?.transitionId ?? "") &&
        digestPattern.test(entry?.bundle?.proof?.eventDigest ?? "") &&
        rollbackShapeValid,
    };
  });
  const receiptIds = records.map((record) => record.receiptId);
  const runIds = records.map((record) => record.runId);
  const transitionIds = records.map((record) => record.transitionId);
  const eventDigests = records.map((record) => record.eventDigest);
  const exactLabels =
    labels.length === requiredLabels.length &&
    new Set(labels).size === labels.length &&
    requiredLabels.every((label) => labels.includes(label));
  const identityUnique =
    unique(receiptIds) && unique(runIds) && unique(transitionIds) && unique(eventDigests);
  const envelopeValid =
    proofSet?.schemaVersion === 1 &&
    proofSet?.kind === "authority-terminal-receipt-proof-set" &&
    (sourceRevision === null || proofSet?.sourceRevision === sourceRevision) &&
    /^[a-f0-9]{24}$/.test(proofSet?.signingKeyId ?? "") &&
    (signingKeyId === null || proofSet?.signingKeyId === signingKeyId);
  const valid =
    envelopeValid && exactLabels && identityUnique && records.every((record) => record.valid);
  const reasons = [];
  if (!envelopeValid) reasons.push("proof-set envelope, source revision, or signing key mismatch");
  if (!exactLabels) reasons.push("terminal proof labels are missing, duplicated, or unexpected");
  if (!identityUnique) reasons.push("terminal receipt/run/transition/event identities are not unique");
  if (records.some((record) => !record.valid)) {
    reasons.push(
      "schema-v3 full event chain, fixed label-to-decision, or rollback-target contract mismatch",
    );
  }
  return {
    valid,
    reason: valid ? null : reasons.join("; "),
    requiredLabels,
    labels,
    identityUnique,
    records,
  };
}

/** Bind the proof-set and pre-run signing-key anchor bytes to the exact browser run. */
export function validateBrowserReceiptArtifactBinding(
  artifacts,
  { proofSetSha256, keyIdSha256 },
) {
  const list = Array.isArray(artifacts) ? artifacts : [];
  const proof = list.filter((entry) => entry?.kind === "terminal-receipt-proof-set");
  const key = list.filter((entry) => entry?.kind === "receipt-proof-key-id");
  const validDigest = (value) => /^[a-f0-9]{64}$/.test(value ?? "");
  const entryValid = (entry, expected) =>
    entry &&
    validDigest(expected) &&
    entry.sha256 === expected &&
    entry.driverSha256 === expected &&
    entry.hashMatchesDriver === true &&
    Number.isSafeInteger(entry.sizeBytes) &&
    entry.sizeBytes > 0;
  const valid =
    proof.length === 1 &&
    key.length === 1 &&
    entryValid(proof[0], proofSetSha256) &&
    entryValid(key[0], keyIdSha256);
  return {
    valid,
    reason: valid
      ? null
      : "browser artifacts do not byte-bind the terminal proof set and signing-key anchor",
  };
}

/**
 * One shared semantic contract for the active browser report. Both the release
 * audit and evidence checklist call this function so a weaker checklist cannot
 * accept evidence that the release gate rejects.
 */
export function validateBrowserCleanCloneContract(
  report,
  { providerId = null, proofSetSha256 = null, keyIdSha256 = null } = {},
) {
  const steps = Array.isArray(report?.steps) ? report.steps : [];
  const preconditions = Array.isArray(report?.preconditions)
    ? report.preconditions
    : [];
  const artifacts = Array.isArray(report?.artifacts) ? report.artifacts : [];
  const stepIds = steps.map((entry) => entry?.id);
  const preconditionIds = preconditions.map((entry) => entry?.id);
  const exactIds = (observed, required) =>
    observed.length === required.length &&
    new Set(observed).size === observed.length &&
    required.every((id) => observed.includes(id));
  const artifactRecords = BROWSER_CLEAN_CLONE_ARTIFACT_KINDS.map((kind) => ({
    kind,
    entries: artifacts.filter((entry) => entry?.kind === kind),
  }));
  const evidenceArtifactPaths = Object.freeze({
    "receipt-proof-bundle": "eval/evidence/receipt-proof-bundle.json",
    "receipt-proof-key-id": "eval/evidence/receipt-proof-key-id.txt",
    "rollback-receipt-proof-bundle":
      "eval/evidence/rollback-receipt-proof-bundle.json",
    "terminal-receipt-proof-set":
      "eval/evidence/terminal-receipt-proof-bundles.json",
  });
  const artifactsComplete = artifactRecords.every(({ kind, entries }) => {
    if (entries.length !== 1) return false;
    const entry = entries[0];
    const expectedEvidencePath = evidenceArtifactPaths[kind];
    const pathValid =
      typeof entry.path === "string" &&
      !entry.path.startsWith("/") &&
      !entry.path.includes("\\") &&
      !entry.path.split("/").includes("..") &&
      (expectedEvidencePath
        ? entry.path === expectedEvidencePath
        : entry.path.startsWith("eval/artifacts/"));
    const commonValid =
      pathValid &&
      digestPattern.test(entry.sha256 ?? "") &&
      Number.isSafeInteger(entry.sizeBytes) &&
      entry.sizeBytes > 0;
    if (!commonValid) return false;
    return kind === "driver-report" ||
      (entry.driverSha256 === entry.sha256 && entry.hashMatchesDriver === true);
  });
  const artifactBinding = validateBrowserReceiptArtifactBinding(artifacts, {
    proofSetSha256,
    keyIdSha256,
  });

  const byId = new Map(steps.map((entry) => [entry?.id, entry]));
  const positive = byId.get("browser-positive-committed")?.evidence;
  const protectedRun = byId.get("browser-protected-quarantined")?.evidence;
  const abortedRun = byId.get("browser-provider-or-verifier-aborted")?.evidence;
  const followUp = byId.get("browser-fresh-follow-up")?.evidence;
  const replay = byId.get("stale-permit-replay-rejected")?.evidence;
  const rollback = byId.get("browser-manual-rollback")?.evidence;
  const exactCommit = positive?.effectProof;
  const nonEffect = (entry) =>
    entry?.invariant === "NO_PERSISTENT_EFFECT" &&
    entry?.invariantSatisfied === true &&
    digestPattern.test(entry?.authoritativeBeforeHash ?? "") &&
    entry.authoritativeBeforeHash === entry.authoritativeAfterHash &&
    Number.isSafeInteger(entry.baseGeneration) &&
    entry.baseGeneration === entry.nextGeneration;
  const exactCommitHashes = [
    exactCommit?.sealedProposalHash,
    exactCommit?.verifierInputHash,
    exactCommit?.promotionSourceHash,
    exactCommit?.finalAuthoritativeHash,
  ];
  const expectedProvider =
    typeof providerId === "string" && providerId.length > 0
      ? providerId
      : report?.provider?.providerId;

  const checks = {
    envelope:
      report?.schemaVersion === 2 &&
      report?.kind === "browser-clean-clone-evaluation" &&
      report?.status === "verified",
    provider:
      typeof expectedProvider === "string" &&
      expectedProvider.length > 0 &&
      report?.provider?.providerId === expectedProvider &&
      report?.provider?.credentialsRecorded === false &&
      declaredCurrentProviderE2EStatus(report) === "verified",
    preconditions:
      exactIds(preconditionIds, BROWSER_CLEAN_CLONE_PRECONDITION_IDS) &&
      preconditions.every(
        (entry) =>
          entry?.status === "verified" &&
          typeof entry?.detail === "string" &&
          entry.detail.trim().length > 0,
      ),
    steps:
      exactIds(stepIds, BROWSER_CLEAN_CLONE_STEP_IDS) &&
      steps.every((entry) => entry?.status === "verified"),
    artifacts: artifactsComplete,
    receiptArtifactBinding: artifactBinding.valid === true,
    exactCommit:
      positive?.decision === "COMMITTED" &&
      positive?.receiptProofVerified === true &&
      Number.isSafeInteger(positive?.baseGeneration) &&
      positive?.nextGeneration === positive.baseGeneration + 1 &&
      exactCommit?.invariant === "PROMOTED_EXACT_PROPOSAL" &&
      exactCommit?.invariantSatisfied === true &&
      exactCommitHashes.every((hash) => digestPattern.test(hash ?? "")) &&
      new Set(exactCommitHashes).size === 1,
    protectedNonEffect:
      nonEffect(protectedRun) && protectedRun?.receiptProofVerified === true,
    abortedNonEffect:
      nonEffect(abortedRun) && abortedRun?.receiptProofVerified === true,
    followUp:
      followUp?.decision === "COMMITTED" &&
      followUp?.receiptProofVerified === true,
    replay:
      replay?.errorCode === "PERMIT_REPLAY" &&
      replay?.headUnchanged === true &&
      digestPattern.test(replay?.beforeHash ?? "") &&
      replay?.beforeHash === replay?.afterHash &&
      Number.isSafeInteger(replay?.beforeGeneration) &&
      replay?.beforeGeneration === replay?.afterGeneration,
    rollback:
      rollback?.rollbackReceiptProofVerified === true &&
      rollback?.rollbackProofCryptographicValid === true &&
      rollback?.rollbackProofSourceRevisionMatches === true &&
      rollback?.rollbackProofSigningKeyMatchesPreRunAnchor === true &&
      rollback?.rollbackReceiptId === rollback?.rollbackVersionSourceReceiptId &&
      rollback?.rollbackProofTargetVersionId ===
        rollback?.rollbackTargetVersionId &&
      rollback?.rollbackProofFinalWorkspaceHash ===
        rollback?.rollbackAuthoritativeAfterHash &&
      /^[a-f0-9]{24}$/.test(rollback?.rollbackProofSigningKeyId ?? "") &&
      digestPattern.test(rollback?.rollbackProofTerminalEventDigest ?? "") &&
      digestPattern.test(rollback?.rollbackProofReceiptHash ?? ""),
  };
  const failedChecks = Object.entries(checks)
    .filter(([, valid]) => !valid)
    .map(([id]) => id);
  return {
    valid: failedChecks.length === 0,
    reason:
      failedChecks.length === 0
        ? null
        : `browser clean-clone contract failed: ${failedChecks.join(", ")}`,
    checks,
    failedChecks,
  };
}
