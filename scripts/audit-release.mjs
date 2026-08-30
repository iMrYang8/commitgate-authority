#!/usr/bin/env node
import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  evidenceProvenance,
  executionIdentity,
  sourceTreeHash,
} from "./evidence-utils.mjs";
import { activeEvidenceReportInventory } from "./evidence-inventory.mjs";
import { validateInvariantReportContract } from "./invariant-contract.mjs";
import { validatePerformanceReportContract } from "./performance-contract.mjs";
import {
  validateBrowserCleanCloneContract,
  validateRealProviderE2EContract,
  validateTerminalReceiptProofSetContract,
} from "./receipt-proof-set-contract.mjs";
import { verifyDemoVideoReviewAttestation } from "./video-review-attestation.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const checkOnly = process.argv.includes("--check");
const required = [
  "eval/evidence/check-report.json",
  "eval/protocol-report.json",
  "eval/adversarial-report.json",
  "eval/recovery-report.json",
  "eval/container-report.json",
  "eval/evidence/p1-product-report.json",
  "eval/evidence/linux-filesystem-report.json",
  "eval/evidence/topology-report.json",
  "eval/evidence/demo-smoke-report.json",
  "eval/browser-clean-clone-report.json",
  "eval/evidence/invariants-report.json",
  "eval/evidence/docker-recovery-report.json",
  "eval/evidence/receipt-verification-report.json",
  "eval/evidence/performance-report.json",
  "eval/evidence/documentation-review.json",
  "eval/evidence/architecture-report.json",
  "eval/authority-report.json",
  "eval/independent-audit-report.json",
  "eval/evidence/evidence-checklist-report.json",
  "eval/evidence/source-delivery-report.json",
  "eval/evidence/secret-report.json",
  "eval/evidence/demo-video-report.json",
];
const imageBoundReports = new Set([
  "eval/protocol-report.json",
  "eval/adversarial-report.json",
  "eval/recovery-report.json",
  "eval/container-report.json",
  "eval/evidence/p1-product-report.json",
  "eval/evidence/linux-filesystem-report.json",
  "eval/evidence/topology-report.json",
  "eval/browser-clean-clone-report.json",
  "eval/evidence/invariants-report.json",
  "eval/evidence/docker-recovery-report.json",
  "eval/evidence/receipt-verification-report.json",
  "eval/evidence/performance-report.json",
]);
let browserProviderId = null;
try {
  const browser = JSON.parse(
    await readFile(path.join(root, "eval", "browser-clean-clone-report.json"), "utf8"),
  );
  const candidate = browser?.provider?.providerId;
  if (typeof candidate === "string" && /^[a-z0-9_-]+$/i.test(candidate)) {
    browserProviderId = candidate;
  }
} catch {
  // The missing browser report is already an explicit unverified release item.
}
const providerEvidenceFile = browserProviderId
  ? `eval/provider-${browserProviderId}-report.json`
  : "eval/provider-current-report.json";
required.push(providerEvidenceFile);
imageBoundReports.add(providerEvidenceFile);
const currentTree = await sourceTreeHash(root);
const currentSource = await evidenceProvenance(root);
const shaImage = (value) => /^sha256:[a-f0-9]{64}$/.test(value ?? "");
let releaseRuntimeDigest = null;
let releaseVerifierDigest = null;
let releaseWorkerDigest = null;
let releaseBrokerDigest = null;
const terminalProofSetPath = path.join(
  root,
  "eval",
  "evidence",
  "terminal-receipt-proof-bundles.json",
);
let terminalProofSetDigest = null;
let terminalProofSet = null;
let expectedReceiptSigningKeyId = null;
let receiptProofKeyIdDigest = null;
try {
  const bytes = await readFile(terminalProofSetPath);
  terminalProofSetDigest = createHash("sha256").update(bytes).digest("hex");
  terminalProofSet = JSON.parse(bytes.toString("utf8"));
} catch {
  // The receipt-verification semantic check below reports this as incomplete.
}
try {
  const keyBytes = await readFile(
    path.join(root, "eval", "evidence", "receipt-proof-key-id.txt"),
  );
  receiptProofKeyIdDigest = createHash("sha256").update(keyBytes).digest("hex");
  const candidate = keyBytes.toString("utf8").trim();
  if (/^[a-f0-9]{24}$/.test(candidate)) expectedReceiptSigningKeyId = candidate;
} catch {
  // The receipt proof semantic gate below requires this pre-run TOFU anchor.
}
const videoReviewAttestationPath = path.join(
  root,
  "eval",
  "evidence",
  "demo-video-review-attestation.json",
);
let videoReviewAttestation = null;
let videoReviewAttestationDigest = null;
try {
  const bytes = await readFile(videoReviewAttestationPath);
  videoReviewAttestationDigest = createHash("sha256").update(bytes).digest("hex");
  videoReviewAttestation = JSON.parse(bytes.toString("utf8"));
} catch {
  // A missing external attestation keeps the narrated-video gate unverified.
}
const expectedVideoReviewerId =
  process.env.COMMITGATE_DEMO_REVIEWER_ID?.trim() || null;
const expectedVideoReviewerKeyId =
  process.env.COMMITGATE_DEMO_REVIEWER_KEY_ID?.trim() || null;

function validateBinding(file, parsed) {
  const source = parsed?.source;
  if (
    source?.sourceTreeHash !== currentTree.hash ||
    source?.sourceFileCount !== currentTree.files ||
    source?.workingTreeCleanAtCapture !== true ||
    source?.sourceRevision !== currentSource.sourceRevision
  ) {
    return "source identity is stale, dirty, or not the exact frozen source revision";
  }
  if (!imageBoundReports.has(file)) return null;
  if (parsed?.executionIdentity?.schemaVersion !== 2) {
    return "execution identity does not use the four-image schema v2 contract";
  }
  const runtime = parsed?.executionIdentity?.runtimeImage?.imageDigest;
  const verifier = parsed?.executionIdentity?.verifierImage?.imageDigest;
  const worker = parsed?.executionIdentity?.workerImage?.imageDigest;
  const broker = parsed?.executionIdentity?.brokerImage?.imageDigest;
  if (![runtime, verifier, worker, broker].every(shaImage)) {
    return "Runtime, Verifier, Worker, or Broker image digest is not mechanically verified";
  }
  releaseRuntimeDigest ??= runtime;
  releaseVerifierDigest ??= verifier;
  releaseWorkerDigest ??= worker;
  releaseBrokerDigest ??= broker;
  if (
    runtime !== releaseRuntimeDigest ||
    verifier !== releaseVerifierDigest ||
    worker !== releaseWorkerDigest ||
    broker !== releaseBrokerDigest
  ) {
    return "image identity differs from the release evidence set";
  }
  if (parsed?.executionIdentity?.provider?.credentialsRecorded !== false) {
    return "provider evidence does not explicitly exclude recorded credentials";
  }
  return null;
}

async function validateSemantics(file, parsed) {
  if (parsed?.status !== "verified") return null;
  if (file === "eval/browser-clean-clone-report.json") {
    const browserContract = validateBrowserCleanCloneContract(parsed, {
      providerId: browserProviderId,
      proofSetSha256: terminalProofSetDigest,
      keyIdSha256: receiptProofKeyIdDigest,
    });
    if (!browserContract.valid) {
      return browserContract.reason;
    }
    for (const artifact of parsed.artifacts) {
      try {
        const absolute = path.resolve(root, artifact.path);
        if (!absolute.startsWith(`${root}${path.sep}`)) {
          return "browser artifact path escapes the frozen evidence root";
        }
        const bytes = await readFile(absolute);
        if (createHash("sha256").update(bytes).digest("hex") !== artifact.sha256) {
          return "browser artifact bytes do not match the report digest";
        }
      } catch {
        return "browser report names a missing or unreadable required artifact";
      }
    }
  }
  if (file === providerEvidenceFile) {
    if (!validateRealProviderE2EContract(parsed, {
      providerId: browserProviderId,
    }).valid) {
      return "real Provider report does not match the browser Provider identity";
    }
  }
  if (file === "eval/evidence/invariants-report.json") {
    if (!validateInvariantReportContract(parsed).valid) {
      return "invariant metrics do not satisfy the release contract";
    }
  }
  if (file === "eval/evidence/topology-report.json") {
    const requiredTopologyChecks = [
      "api-authority-control-read-only",
      "api-authority-write-denied-live",
      "api-control-write-denied-live",
      "api-receipt-private-key-read-denied-live",
      "worker-exclusive-authority-rw",
      "worker-linux-strong-manifest-v2",
      "worker-broker-agent-artifact-identity-aligned",
      "docker-socket-only-broker",
      "provider-key-only-relay",
      "relay-no-workspace",
      "broker-no-authority",
      "exchange-volume-owner-aligned",
      "exchange-volume-kernel-bounded",
      "rpc-socket-volumes-separated",
      "broker-cannot-connect-transition-worker-socket",
      "api-connects-transition-worker-socket",
      "api-connects-runtime-broker-socket",
    ];
    const topologyChecks = new Map(
      (parsed.checks ?? []).map((entry) => [entry.id, entry]),
    );
    if (
      parsed.schemaVersion !== 2 ||
      parsed.kind !== "runtime-topology-audit" ||
      !requiredTopologyChecks.every(
        (id) => topologyChecks.get(id)?.status === "verified",
      )
    ) {
      return "topology report does not verify separate Worker/Broker RPC socket TCBs and the live least-authority probes";
    }
  }
  if (file === "eval/evidence/docker-recovery-report.json") {
    const observations = parsed.faultPoints ?? parsed.scenarios ?? parsed.checks ?? [];
    const requiredScenarios = new Map([
      ["prepared-recovers-aborted", "TRANSITION_PREPARED"],
      ["sealed-recovers-aborted", "PROPOSAL_SEALED"],
      ["evidenced-recovers-aborted", "EVIDENCE_RECORDED"],
      ["permit-issued-recovers-aborted", "PERMIT_ISSUED"],
      ["permit-consuming-rolls-back", "PERMIT_CONSUMING"],
      ["backup-created-rolls-back", "BACKUP_CREATED"],
      ["workspace-applied-recovers-forward", "WORKSPACE_APPLIED"],
      ["rollback-applied-recovers-forward", "ROLLBACK_APPLIED"],
      ["ack-durable-and-cleaned", "TRANSITION_ACKNOWLEDGED"],
      ["rollback-ack-durable-and-cleaned", "TRANSITION_ACKNOWLEDGED"],
      ["api-projection-pending", "API_PROJECTION_PENDING"],
    ]);
    const observationsById = new Map(
      observations.map((entry) => [entry.id, entry]),
    );
    if (
      parsed.schemaVersion !== 1 ||
      parsed.kind !== "docker-process-recovery-evaluation" ||
      observations.length < requiredScenarios.size ||
      !observations.every(
        (entry) =>
          entry.status === "verified" &&
          entry.assertions &&
          Object.values(entry.assertions).every(Boolean),
      ) ||
      ![...requiredScenarios].every(([id, point]) => {
        const observation = observationsById.get(id);
        return observation?.faultPoint === point && observation?.status === "verified";
      })
    ) {
      return "Docker recovery report does not verify the ten Worker crash scenarios plus API_PROJECTION_PENDING";
    }
  }
  if (file === "eval/container-report.json") {
    const cancellation = parsed.brokerCancellation;
    const processKill = parsed.brokerProcessKill;
    const cancellationVerified = (entry) =>
      entry?.status === "verified" &&
      entry.containerObservedRunning === true &&
      entry.wrongBindingRejected === true &&
      entry.cancelAccepted === true &&
      entry.promiseCancelled === true &&
      entry.cancellationErrorName === "RunCancelledError" &&
      entry.forceRemoved === true &&
      entry.teardown?.containerExited === true &&
      entry.teardown?.containerRemoved === true &&
      entry.teardown?.mountsReleased === true &&
      entry.teardown?.source === "runtime-attestation";
    const processKillCommon = (entry) =>
      entry?.status === "verified" &&
      entry.containerObservedRunning === true &&
      entry.killSignal === "KILL" &&
      entry.killAccepted === true &&
      entry.failClosed === true &&
      entry.passObserved === false &&
      entry.forceRemoved === true &&
      entry.teardown?.containerExited === true &&
      entry.teardown?.containerRemoved === true &&
      entry.teardown?.mountsReleased === true &&
      entry.teardown?.source === "runtime-attestation";
    const agentProcessKillVerified = (entry) =>
      processKillCommon(entry) &&
      entry.workload === "agent" &&
      entry.promiseRejected === true &&
      entry.errorName !== "RunCancelledError" &&
      entry.errorCode === "BROKER_RUNTIME_ERROR";
    const verifierProcessKillVerified = (entry) =>
      processKillCommon(entry) &&
      entry.workload === "verifier" &&
      entry.checkStatus === "ERROR" &&
      entry.checkExitCode === 137;
    const brokerRestart = processKill?.brokerRestartReconciliation;
    const brokerRestartVerified = (() => {
      const labels = brokerRestart?.exactBinding?.labels ?? {};
      const expectedLabels = {
        "io.commitgate.runtime": "agent-runtime",
        "io.commitgate.instance-id": labels["io.commitgate.instance-id"],
        "io.commitgate.agent-id": brokerRestart?.agentId,
        "io.commitgate.run-id": brokerRestart?.runId,
        "io.commitgate.run-lease-id": brokerRestart?.runLeaseId,
        "io.commitgate.session-epoch": String(brokerRestart?.sessionEpoch),
      };
      const query = brokerRestart?.exactBinding?.queryArguments ?? [];
      const negativeQuery = brokerRestart?.reconciliation?.negativeQueryArguments ?? [];
      const expectedFilters = Object.entries(expectedLabels)
        .map(([name, value]) => `label=${name}=${value}`);
      const attestation = brokerRestart?.reconciliation?.attestation;
      return (
        brokerRestart?.point === "RUNTIME_BROKER_PROCESS_SIGKILL_ORPHAN_RECONCILIATION" &&
        brokerRestart?.status === "verified" &&
        brokerRestart?.workload === "agent" &&
        brokerRestart?.error === null &&
        brokerRestart?.broker?.launchMode === "separate-node-process" &&
        brokerRestart?.broker?.firstReady === true &&
        brokerRestart?.broker?.killSignal === "SIGKILL" &&
        brokerRestart?.broker?.killAccepted === true &&
        brokerRestart?.broker?.firstExitSignal === "SIGKILL" &&
        brokerRestart?.broker?.restartedReady === true &&
        brokerRestart?.exactBinding?.exactLabelsObserved === true &&
        Object.keys(labels).length === Object.keys(expectedLabels).length &&
        Object.entries(expectedLabels).every(([name, value]) => labels[name] === value) &&
        expectedFilters.every((filter) => query.includes(filter) && negativeQuery.includes(filter)) &&
        brokerRestart?.exactBinding?.matchingContainerIdsBeforeReconcile?.length > 0 &&
        brokerRestart?.exactBinding?.wrongLeaseQueryContainerIds?.length === 0 &&
        brokerRestart?.orphan?.runningBeforeBrokerKill === true &&
        brokerRestart?.orphan?.runningAfterBrokerSigkill === true &&
        brokerRestart?.orphan?.sameContainerAfterBrokerSigkill === true &&
        brokerRestart?.reconciliation?.invokedThroughRestartedBrokerRpc === true &&
        brokerRestart?.reconciliation?.forceRemovedByReconcile === true &&
        brokerRestart?.reconciliation?.remainingContainerIds?.length === 0 &&
        brokerRestart?.reconciliation?.containerAbsentByInspect === true &&
        attestation?.runId === brokerRestart?.runId &&
        attestation?.agentId === brokerRestart?.agentId &&
        attestation?.runLeaseId === brokerRestart?.runLeaseId &&
        attestation?.sessionEpoch === brokerRestart?.sessionEpoch &&
        attestation?.scope === "ALL" &&
        attestation?.containerExited === true &&
        attestation?.containerRemoved === true &&
        attestation?.mountsReleased === true &&
        attestation?.source === "broker-reconciliation"
      );
    })();
    if (
      parsed.schemaVersion !== 2 ||
      parsed.kind !== "container-verifier-evaluation" ||
      parsed.provenance?.realContainerExecution !== true ||
      parsed.positive?.status !== "PASS" ||
      parsed.negative?.status !== "FAIL" ||
      !Object.values(parsed.structural ?? {}).every((value) => value === true) ||
      !/^sha256:[a-f0-9]{64}$/.test(cancellation?.fixtureImage?.imageId ?? "") ||
      !cancellationVerified(cancellation?.agent) ||
      !cancellationVerified(cancellation?.verifier) ||
      !agentProcessKillVerified(processKill?.agent) ||
      !verifierProcessKillVerified(processKill?.verifier) ||
      !brokerRestartVerified
    ) {
      return "container report does not verify isolation, cancellation, Agent/Verifier SIGKILL teardown, and Broker-restart orphan reconciliation";
    }
  }
  if (file === "eval/evidence/receipt-verification-report.json") {
    const proofSetContract = validateTerminalReceiptProofSetContract(terminalProofSet, {
      sourceRevision: currentSource.sourceRevision,
      signingKeyId: expectedReceiptSigningKeyId,
    });
    const expectedLabels = proofSetContract.requiredLabels;
    const records = parsed.records ?? [];
    if (
      parsed.schemaVersion !== 3 ||
      parsed.kind !== "offline-terminal-receipt-proof-set-verification" ||
      parsed.status !== "verified" ||
      parsed.verification?.valid !== true ||
      parsed.verification?.allTerminalReceiptsVerified !== true ||
      parsed.verification?.trustAnchor?.valid !== true ||
      parsed.verification?.trustAnchor?.expectedSigningKeyId !==
        expectedReceiptSigningKeyId ||
      parsed.proofSet?.signingKeyId !== expectedReceiptSigningKeyId ||
      parsed.proofSet?.sha256 !== terminalProofSetDigest ||
      parsed.proofSet?.proofCount !== expectedLabels.length ||
      parsed.proofSet?.structureValid !== true ||
      parsed.proofSet?.identityUnique !== true ||
      parsed.verification?.proofSetContractValid !== true ||
      proofSetContract.valid !== true ||
      terminalProofSet?.kind !== "authority-terminal-receipt-proof-set" ||
      terminalProofSet?.sourceRevision !== currentSource.sourceRevision ||
      !expectedLabels.every((label) => parsed.proofSet?.labels?.includes(label)) ||
      records.length !== expectedLabels.length ||
      new Set(records.map((record) => record.receiptId)).size !== expectedLabels.length ||
      new Set(records.map((record) => record.runId)).size !== expectedLabels.length ||
      new Set(records.map((record) => record.eventDigest)).size !== expectedLabels.length ||
      !records.every(
        (record) =>
          record.status === "verified" &&
          record.verification?.valid === true &&
          record.bundleSchemaVersion === 3 &&
          Number.isSafeInteger(record.eventChainLength) &&
          record.eventChainLength > 0 &&
          record.fullEventChainValid === true &&
          /^[a-f0-9]{64}$/.test(record.eventDigest ?? "") &&
          /^[a-f0-9]{64}$/.test(record.receiptHash ?? ""),
      )
    ) {
      return "offline proof set does not re-verify every browser terminal receipt against the frozen artifact and trust anchor";
    }
  }
  if (file === "eval/evidence/performance-report.json") {
    if (!validatePerformanceReportContract(parsed).valid) {
      return "performance report is missing the exact Worker-only 30-run Linux deterministic-probe matrix";
    }
  }
  if (file === "eval/evidence/demo-smoke-report.json") {
    const requiredChecks = [
      "health",
      "system-api",
      "agents-api",
      "commitgate-ready",
      "verifier-ready",
      "worker-authority",
      "broker-runtime",
      "relay-model-access",
      "os-write-isolation",
      "manifest-v2",
      "linux-strong-filesystem",
      "pre-run-receipt-key-anchor",
      "demo-agent-seeded",
      "live-topology-audit",
      "authenticated-demo-status",
    ];
    const checks = new Map((parsed.checks ?? []).map((entry) => [entry.id, entry]));
    if (
      parsed.schemaVersion !== 1 ||
      parsed.kind !== "one-command-demo-smoke" ||
      !requiredChecks.every((id) => checks.get(id)?.passed === true)
    ) {
      return "one-command smoke did not prove ready Worker/Broker topology, TOFU receipt key, and propagated live topology success";
    }
  }
  if (file === "eval/evidence/documentation-review.json") {
    if (
      parsed.schemaVersion !== 3 ||
      parsed.kind !== "documentation-contract-audit" ||
      parsed.auditOrigin !== "project-defined" ||
      parsed.externallyIndependent !== false ||
      parsed.readOnlyCleanSource !== true ||
      !Array.isArray(parsed.items) ||
      parsed.items.length === 0 ||
      !parsed.items.every((entry) => entry.status === "verified")
    ) {
      return "project-defined documentation contract audit is stale, dirty, or incomplete";
    }
  }
  if (file === "eval/evidence/architecture-report.json") {
    if (
      parsed.schemaVersion !== 1 ||
      parsed.kind !== "architecture-artifact-audit" ||
      !Array.isArray(parsed.checks) ||
      parsed.checks.length < 7 ||
      !parsed.checks.every((entry) => entry.status === "verified") ||
      parsed.artifacts?.drawio?.sha256 !== parsed.artifacts?.submissionDrawio?.sha256 ||
      parsed.artifacts?.svg?.sha256 !== parsed.artifacts?.submissionSvg?.sha256
    ) {
      return "architecture source, embedded SVG, or submission copies are inconsistent";
    }
  }
  if (file === "eval/evidence/demo-video-report.json") {
    const attestationVerification = verifyDemoVideoReviewAttestation(
      videoReviewAttestation,
      {
        videoSha256: parsed.artifact?.sha256 ?? null,
        expectedReviewerId: expectedVideoReviewerId,
        expectedSigningKeyId: expectedVideoReviewerKeyId,
      },
    );
    if (
      parsed.schemaVersion !== 2 ||
      parsed.kind !== "three-minute-demo-video-verification" ||
      parsed.technicalStatus !== "verified" ||
      parsed.contentReview?.status !== "verified" ||
      !Array.isArray(parsed.technicalChecks) ||
      !parsed.technicalChecks.every((entry) => entry.status === "verified") ||
      !Array.isArray(parsed.contentReview?.checks) ||
      !parsed.contentReview.checks.every((entry) => entry.status === "verified") ||
      parsed.contentReview?.method !== "external signed full-video review" ||
      parsed.contentReview?.attestation?.path !==
        "eval/evidence/demo-video-review-attestation.json" ||
      parsed.contentReview?.attestation?.sha256 !== videoReviewAttestationDigest ||
      parsed.contentReview?.attestation?.reviewerId !== expectedVideoReviewerId ||
      parsed.contentReview?.attestation?.signingKeyId !== expectedVideoReviewerKeyId ||
      attestationVerification.status !== "verified" ||
      attestationVerification.valid !== true
    ) {
      return "video envelope or externally anchored signed content review is incomplete";
    }
  }
  if (file === "eval/authority-report.json") {
    if (
      parsed.schemaVersion !== 2 ||
      parsed.kind !== "persistent-authority-static-audit" ||
      parsed.unauthorizedPersistentWriteCount !== 0 ||
      !Array.isArray(parsed.authoritySurface) ||
      !parsed.authoritySurface.every((entry) => entry.status === "verified")
    ) {
      return "persistent-authority static fence is incomplete or reports an unauthorized writer";
    }
  }
  if (file === "eval/independent-audit-report.json") {
    if (
      parsed.schemaVersion !== 3 ||
      parsed.kind !== "project-defined-clean-worktree-replay" ||
      parsed.auditOrigin !== "project-defined" ||
      parsed.externallyIndependent !== false ||
      parsed.cleanClone !== true ||
      parsed.readOnlySource !== true ||
      !Array.isArray(parsed.results) ||
      !parsed.results.every((entry) => entry.status === "verified")
    ) {
      return "project-defined read-only clean-worktree replay is stale, mislabeled, or incomplete";
    }
  }
  if (file === "eval/evidence/evidence-checklist-report.json") {
    if (
      parsed.schemaVersion !== 3 ||
      parsed.kind !== "commitgate-evidence-checklist" ||
      parsed.organizerScore !== null ||
      !Array.isArray(parsed.sections) ||
      parsed.sections.length === 0 ||
      !parsed.sections.every(
        (section) =>
          section.status === "verified" &&
          Array.isArray(section.items) &&
          section.items.every((entry) => entry.status === "verified"),
      )
    ) {
      return "evidence checklist is incomplete or attempts to assign an organizer score";
    }
  }
  if (file === "eval/evidence/source-delivery-report.json") {
    if (
      parsed.schemaVersion !== 1 ||
      parsed.kind !== "reviewer-source-delivery-audit" ||
      parsed.localMirror?.status !== "verified" ||
      ![parsed.repositoryDelivery?.status, parsed.archiveDelivery?.status]
        .includes("verified") ||
      parsed.repositoryDelivery?.credentialsRecorded !== false
    ) {
      return "reviewer source delivery is not byte-bound to an accessible private repository or SHA-256 archive";
    }
  }
  return null;
}
const items = [];
for (const file of required) {
  const absolute = path.join(root, file);
  try {
    await access(absolute);
    const parsed = JSON.parse(await readFile(absolute, "utf8"));
    const declared = ["verified", "failed", "unverified"].includes(parsed.status)
      ? parsed.status
      : "unverified";
    const bindingError = validateBinding(file, parsed);
    const semanticError = await validateSemantics(file, parsed);
    items.push({
      file,
      status:
        bindingError
          ? "unverified"
          : declared === "failed" || semanticError
            ? "failed"
            : declared,
      generatedAt: parsed.generatedAt ?? null,
      ...(semanticError || bindingError
        ? { reason: bindingError ?? semanticError }
        : {}),
    });
  } catch {
    items.push({ file, status: "unverified", generatedAt: null });
  }
}
const activeInventory = await activeEvidenceReportInventory(root, [
  ...required,
  "eval/evidence/release-audit-report.json",
]);
items.push({
  file: "active evidence report inventory",
  status: activeInventory.unexpected.length === 0 ? "verified" : "failed",
  generatedAt: null,
  ...(activeInventory.unexpected.length > 0
    ? {
        reason:
          `unexpected active reports must move below eval/history/<SOURCE_REVISION>/: ${activeInventory.unexpected.join(", ")}`,
      }
    : {}),
});
const source = currentSource;
if (!source.workingTreeCleanAtCapture) items.push({ file: "git working tree", status: "unverified", generatedAt: null });
const status = items.some((item) => item.status === "failed") ? "failed" : items.some((item) => item.status === "unverified") ? "unverified" : "verified";
const report = {
  schemaVersion: 1,
  kind: "release-evidence-audit",
  generatedAt: new Date().toISOString(),
  status,
  source,
  executionIdentity: executionIdentity(root),
  items,
  claimBoundary: "This is a release evidence completeness audit, not an official score. Missing, stale, dirty-tree, or non-verified inputs remain unverified.",
};
const reportPath = path.join(root, "eval", "evidence", "release-audit-report.json");
await mkdir(path.dirname(reportPath), { recursive: true });
if (!checkOnly) {
  await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n");
}
for (const item of items) console.log(`${item.status.padEnd(10)} ${item.file}`);
console.log(checkOnly ? "release audit dry run: report not written" : `report: ${reportPath}`);
process.exitCode = status === "verified" ? 0 : status === "unverified" ? 2 : 1;
