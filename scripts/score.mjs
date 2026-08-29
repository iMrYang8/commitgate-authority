#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import {
  evidenceProvenance,
  executionIdentity,
  sourceTreeHash,
} from "./evidence-utils.mjs";
import {
  declaredCurrentProviderE2EStatus,
  validateBrowserCleanCloneContract,
} from "./receipt-proof-set-contract.mjs";
import { validateInvariantReportContract } from "./invariant-contract.mjs";
import { validatePerformanceReportContract } from "./performance-contract.mjs";
import { verifyDemoVideoReviewAttestation } from "./video-review-attestation.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const checkOnly = process.argv.includes("--check");
const reportPath = path.join(root, "eval", "evidence", "evidence-checklist-report.json");
const markdownPath = path.join(root, "eval", "evidence", "evidence-checklist-report.md");

async function json(relative) {
  try {
    return JSON.parse(await readFile(path.join(root, relative), "utf8"));
  } catch {
    return null;
  }
}

async function artifact(relative) {
  try {
    const content = await readFile(path.join(root, relative));
    const info = await stat(path.join(root, relative));
    return {
      sha256: createHash("sha256").update(content).digest("hex"),
      sizeBytes: info.size,
    };
  } catch {
    return null;
  }
}

const reports = {
  protocol: await json("eval/protocol-report.json"),
  adversarial: await json("eval/adversarial-report.json"),
  recovery: await json("eval/recovery-report.json"),
  authority: await json("eval/authority-report.json"),
  container: await json("eval/container-report.json"),
  check: await json("eval/evidence/check-report.json"),
  secrets: await json("eval/evidence/secret-report.json"),
  ark: await json("eval/provider-ark-report.json"),
  openrouter: await json("eval/provider-openrouter-report.json"),
  browser: await json("eval/browser-clean-clone-report.json"),
  independent: await json("eval/independent-audit-report.json"),
  documentation: await json("eval/evidence/documentation-review.json"),
  p1: await json("eval/evidence/p1-product-report.json"),
  filesystem: await json("eval/evidence/linux-filesystem-report.json"),
  topology: await json("eval/evidence/topology-report.json"),
  demoSmoke: await json("eval/evidence/demo-smoke-report.json"),
  demoVideo: await json("eval/evidence/demo-video-report.json"),
  invariants: await json("eval/evidence/invariants-report.json"),
  dockerRecovery: await json("eval/evidence/docker-recovery-report.json"),
  performance: await json("eval/evidence/performance-report.json"),
  receiptVerification: await json("eval/evidence/receipt-verification-report.json"),
  sourceDelivery: await json("eval/evidence/source-delivery-report.json"),
  architecture: await json("eval/evidence/architecture-report.json"),
};
const demoVideoReviewAttestation = await json(
  "eval/evidence/demo-video-review-attestation.json",
);
const demoVideoReviewAttestationArtifact = await artifact(
  "eval/evidence/demo-video-review-attestation.json",
);
const terminalReceiptProofSetArtifact = await artifact(
  "eval/evidence/terminal-receipt-proof-bundles.json",
);
const receiptProofKeyIdArtifact = await artifact(
  "eval/evidence/receipt-proof-key-id.txt",
);

const currentSource = await sourceTreeHash(root);
const currentProvenance = await evidenceProvenance(root);
const currentIdentity = executionIdentity(root);
const triState = (value) =>
  ["verified", "failed", "unverified"].includes(value) ? value : null;
const shaIdentity = (value) => /^sha256:[a-f0-9]{64}$/.test(value ?? "");
const sourceBound = (report) =>
  report?.source?.sourceTreeHash === currentSource.hash &&
  report?.source?.sourceFileCount === currentSource.files &&
  report?.source?.workingTreeCleanAtCapture === true &&
  report?.source?.sourceRevision === currentProvenance.sourceRevision;
const imageBound = (report) => {
  if (report?.executionIdentity?.schemaVersion !== 2) return false;
  const runtime = report?.executionIdentity?.runtimeImage?.imageDigest;
  const verifier = report?.executionIdentity?.verifierImage?.imageDigest;
  const worker = report?.executionIdentity?.workerImage?.imageDigest;
  const broker = report?.executionIdentity?.brokerImage?.imageDigest;
  if (![runtime, verifier, worker, broker].every(shaIdentity)) return false;
  if (
    shaIdentity(currentIdentity.runtimeImage.imageDigest) &&
    runtime !== currentIdentity.runtimeImage.imageDigest
  ) {
    return false;
  }
  if (
    shaIdentity(currentIdentity.verifierImage.imageDigest) &&
    verifier !== currentIdentity.verifierImage.imageDigest
  ) {
    return false;
  }
  if (
    shaIdentity(currentIdentity.workerImage.imageDigest) &&
    worker !== currentIdentity.workerImage.imageDigest
  ) {
    return false;
  }
  if (
    shaIdentity(currentIdentity.brokerImage.imageDigest) &&
    broker !== currentIdentity.brokerImage.imageDigest
  ) {
    return false;
  }
  return report?.executionIdentity?.provider?.credentialsRecorded === false;
};
const baseReport = (report, kind, schemaVersion, needsImages = true) =>
  report?.schemaVersion === schemaVersion &&
  report?.kind === kind &&
  typeof report?.generatedAt === "string" &&
  Number.isFinite(Date.parse(report.generatedAt)) &&
  sourceBound(report) &&
  (!needsImages || imageBound(report));
const semanticStatus = (
  report,
  kind,
  schemaVersion,
  predicate = () => true,
  needsImages = true,
) => {
  if (!baseReport(report, kind, schemaVersion, needsImages)) return "unverified";
  if (report.status === "failed") return "failed";
  if (report.status !== "verified") return "unverified";
  return predicate(report) ? "verified" : "failed";
};
const combine = (...statuses) =>
  statuses.includes("failed")
    ? "failed"
    : statuses.every((status) => status === "verified")
      ? "verified"
      : "unverified";
const claimStatus = (report, kind, id) => {
  if (!baseReport(report, kind, 2)) return "unverified";
  if (report.command?.status === "failed") return "failed";
  return (
    triState(report.claims?.find((entry) => entry.id === id)?.status) ??
    "unverified"
  );
};

function providerStatus(providerId) {
  const report = reports[providerId];
  return semanticStatus(report, "real-provider-evaluation", 2, (candidate) => {
    const required = [
      "frontend-served",
      "provider-identity-bound",
      "real-positive-commit",
      "real-protected-quarantine",
      "fresh-session-follow-up",
      "manual-history-rollback",
    ];
    const byId = new Map(
      (candidate.scenario ?? []).map((entry) => [entry.id, entry]),
    );
    return (
      candidate.provider?.providerId === providerId &&
      candidate.provider?.credentialsRecorded === false &&
      typeof candidate.provider?.resolvedModel === "string" &&
      candidate.provider.resolvedModel.length > 0 &&
      candidate.provenance?.realProviderRequest === true &&
      candidate.provenance?.realCodexContainer === true &&
      declaredCurrentProviderE2EStatus(candidate) === "verified" &&
      required.every((id) => byId.get(id)?.status === "verified")
    );
  });
}

const providerStatuses = {
  ark: providerStatus("ark"),
  openrouter: providerStatus("openrouter"),
};

async function browserStatus() {
  const status = semanticStatus(
    reports.browser,
    "browser-clean-clone-evaluation",
    2,
    (report) =>
      validateBrowserCleanCloneContract(report, {
        providerId: report.provider?.providerId ?? null,
        proofSetSha256: terminalReceiptProofSetArtifact?.sha256 ?? null,
        keyIdSha256: receiptProofKeyIdArtifact?.sha256 ?? null,
      }).valid,
  );
  if (status !== "verified") return status;
  for (const entry of reports.browser.artifacts) {
    if (
      typeof entry.path !== "string" ||
      !/^[a-f0-9]{64}$/.test(entry.sha256 ?? "")
    ) {
      return "failed";
    }
    const actual = await artifact(entry.path);
    if (!actual || actual.sha256 !== entry.sha256) return "failed";
  }
  return "verified";
}

const protocolStatus = semanticStatus(
  reports.protocol,
  "commitgate-protocol-evaluation",
  2,
  (report) => report.command?.exitCode === 0 && report.tests?.failed === 0,
);
const adversarialStatus = semanticStatus(
  reports.adversarial,
  "commitgate-adversarial-evaluation",
  2,
  (report) => report.command?.exitCode === 0 && report.tests?.failed === 0,
);
const recoveryStatus = semanticStatus(
  reports.recovery,
  "commitgate-recovery-evaluation",
  2,
  (report) => report.command?.exitCode === 0 && report.tests?.failed === 0,
);
const checkStatus = semanticStatus(
  reports.check,
  "baseline-regression-check",
  1,
  (report) =>
    report.results?.length > 0 &&
    report.results.every(
      (entry) => entry.status === "verified" && entry.exitCode === 0,
    ),
  false,
);
const authorityStatus = semanticStatus(
  reports.authority,
  "persistent-authority-static-audit",
  2,
  (report) => report.unauthorizedPersistentWriteCount === 0,
);
const containerStatus = semanticStatus(
  reports.container,
  "container-verifier-evaluation",
  2,
  (report) =>
    report.provenance?.realContainerExecution === true &&
    report.positive?.status === "PASS" &&
    report.negative?.status === "FAIL",
);
const brokerRestartStatus = semanticStatus(
  reports.container,
  "container-verifier-evaluation",
  2,
  (report) => {
    const observation = report.brokerProcessKill?.brokerRestartReconciliation;
    const attestation = observation?.reconciliation?.attestation;
    return observation?.status === "verified" &&
      observation?.broker?.killSignal === "SIGKILL" &&
      observation?.broker?.firstExitSignal === "SIGKILL" &&
      observation?.broker?.restartedReady === true &&
      observation?.orphan?.runningAfterBrokerSigkill === true &&
      observation?.orphan?.sameContainerAfterBrokerSigkill === true &&
      observation?.exactBinding?.exactLabelsObserved === true &&
      observation?.exactBinding?.wrongLeaseQueryContainerIds?.length === 0 &&
      observation?.reconciliation?.remainingContainerIds?.length === 0 &&
      observation?.reconciliation?.containerAbsentByInspect === true &&
      attestation?.source === "broker-reconciliation" &&
      attestation?.containerExited === true &&
      attestation?.containerRemoved === true &&
      attestation?.mountsReleased === true;
  },
);
const secretStatus = semanticStatus(
  reports.secrets,
  "secret-scan",
  1,
  (report) => Array.isArray(report.findings) && report.findings.length === 0,
  false,
);
const p1Status = semanticStatus(
  reports.p1,
  "p1-product-authority-evaluation",
  1,
  (report) => report.checks?.every((entry) => entry.status === "verified"),
);
const filesystemStatus = semanticStatus(
  reports.filesystem,
  "linux-filesystem-closure",
  1,
);
const topologyStatus = semanticStatus(
  reports.topology,
  "runtime-topology-audit",
  2,
  (report) => report.checks?.every((entry) => entry.status === "verified"),
);
const demoSmokeStatus = semanticStatus(
  reports.demoSmoke,
  "one-command-demo-smoke",
  1,
  (report) => {
    const required = new Set([
      "commitgate-ready",
      "worker-authority",
      "broker-runtime",
      "pre-run-receipt-key-anchor",
      "live-topology-audit",
      "authenticated-demo-status",
    ]);
    return Array.isArray(report.checks) &&
      [...required].every((id) =>
        report.checks.some((entry) => entry.id === id && entry.passed === true));
  },
  false,
);
const demoVideoStatus = semanticStatus(
  reports.demoVideo,
  "three-minute-demo-video-verification",
  2,
  (report) => {
    const verification = verifyDemoVideoReviewAttestation(
      demoVideoReviewAttestation,
      {
        videoSha256: report.artifact?.sha256 ?? null,
        expectedReviewerId: process.env.COMMITGATE_DEMO_REVIEWER_ID?.trim() || null,
        expectedSigningKeyId:
          process.env.COMMITGATE_DEMO_REVIEWER_KEY_ID?.trim() || null,
      },
    );
    return report.technicalStatus === "verified" &&
      report.contentReview?.status === "verified" &&
      report.contentReview?.attestation?.sha256 ===
        demoVideoReviewAttestationArtifact?.sha256 &&
      verification.valid === true;
  },
  false,
);
const invariantStatus = semanticStatus(
  reports.invariants,
  "commitgate-invariant-evaluation",
  3,
  (report) => validateInvariantReportContract(report).valid,
);
const dockerRecoveryStatus = semanticStatus(
  reports.dockerRecovery,
  "docker-process-recovery-evaluation",
  1,
  (report) => {
    const required = new Set([
      "prepared-recovers-aborted",
      "sealed-recovers-aborted",
      "evidenced-recovers-aborted",
      "permit-issued-recovers-aborted",
      "permit-consuming-rolls-back",
      "backup-created-rolls-back",
      "workspace-applied-recovers-forward",
      "rollback-applied-recovers-forward",
      "ack-durable-and-cleaned",
      "rollback-ack-durable-and-cleaned",
      "api-projection-pending",
    ]);
    const observations = report.scenarios ?? report.faultPoints ?? report.checks ?? [];
    return observations.length >= required.size &&
      [...required].every((id) => observations.some(
        (entry) => entry.id === id &&
          entry.status === "verified" &&
          entry.assertions &&
          Object.values(entry.assertions).every(Boolean),
      ));
  },
);
const performanceStatus = semanticStatus(
  reports.performance,
  "commitgate-linux-gate-overhead",
  1,
  (report) => validatePerformanceReportContract(report).valid,
);
const receiptVerificationStatus = semanticStatus(
  reports.receiptVerification,
  "offline-terminal-receipt-proof-set-verification",
  3,
  (report) =>
    report.verification?.valid === true &&
    report.verification?.allTerminalReceiptsVerified === true &&
    report.verification?.trustAnchor?.valid === true &&
    report.proofSet?.proofCount === 5 &&
    report.records?.every(
      (entry) =>
        entry.status === "verified" &&
        entry.bundleSchemaVersion === 3 &&
        Number.isSafeInteger(entry.eventChainLength) &&
        entry.eventChainLength > 0 &&
        entry.fullEventChainValid === true,
    ),
);
const independentStatus = semanticStatus(
  reports.independent,
  "project-defined-clean-worktree-replay",
  3,
  (report) =>
    report.auditOrigin === "project-defined" &&
    report.externallyIndependent === false &&
    report.cleanClone === true &&
    report.readOnlySource === true,
);
const sourceDeliveryStatus = semanticStatus(
  reports.sourceDelivery,
  "reviewer-source-delivery-audit",
  1,
  (report) =>
    report.localMirror?.status === "verified" &&
    (report.repositoryDelivery?.status === "verified" ||
      report.archiveDelivery?.status === "verified"),
  false,
);
const documentationStatus = semanticStatus(
  reports.documentation,
  "documentation-contract-audit",
  3,
  (report) =>
    report.auditOrigin === "project-defined" &&
    report.externallyIndependent === false &&
    report.readOnlyCleanSource === true &&
    report.items?.every((entry) => entry.status === "verified"),
  false,
);
const architectureStatus = semanticStatus(
  reports.architecture,
  "architecture-artifact-audit",
  1,
  (report) =>
    Array.isArray(report.checks) &&
    report.checks.length >= 7 &&
    report.checks.every((entry) => entry.status === "verified") &&
    report.artifacts?.drawio?.sha256 === report.artifacts?.submissionDrawio?.sha256 &&
    report.artifacts?.svg?.sha256 === report.artifacts?.submissionSvg?.sha256,
  false,
);
const cleanBrowserStatus = await browserStatus();
const browserProviderId = reports.browser?.provider?.providerId ?? null;
const browserProviderStatus =
  browserProviderId && providerStatuses[browserProviderId]
    ? providerStatuses[browserProviderId]
    : "unverified";
const providerE2EVerified = combine(browserProviderStatus, cleanBrowserStatus);

const protocolClaim = (id) =>
  claimStatus(reports.protocol, "commitgate-protocol-evaluation", id);
const adversarialClaim = (id) =>
  claimStatus(reports.adversarial, "commitgate-adversarial-evaluation", id);
const recoveryClaim = (id) =>
  claimStatus(reports.recovery, "commitgate-recovery-evaluation", id);
const item = (id, label, status, evidence) => ({ id, label, status, evidence });

const sections = [
  {
    id: "behavior",
    label: "End-to-end middleware behavior",
    items: [
      item("provider-browser", "Real Provider browser path", providerE2EVerified, ["eval/provider-<provider>-report.json", "eval/browser-clean-clone-report.json"]),
      item("commit", "Sealed proposal and one-shot commit", combine(protocolClaim("sealed-proposal-single-source"), protocolClaim("one-shot-promotion-permit")), ["eval/protocol-report.json"]),
      item("quarantine", "Protected-path rejection", combine(protocolClaim("terminal-decision-semantics"), adversarialClaim("path-budget-canary-platform")), ["eval/protocol-report.json", "eval/adversarial-report.json"]),
      item("session", "View and session continuation fence", combine(protocolClaim("message-authority-fence"), adversarialClaim("session-home-isolation")), ["eval/protocol-report.json", "eval/adversarial-report.json"]),
      item("rollback", "Append-only rollback and recovery", combine(protocolClaim("append-only-rollback"), recoveryClaim("rollback-crash-recovery")), ["eval/protocol-report.json", "eval/recovery-report.json"]),
      item("regression", "Starter behavior and build regression", checkStatus, ["eval/evidence/check-report.json"]),
    ],
  },
  {
    id: "design",
    label: "Technical design and integration",
    items: [
      item("protocol", "State-view, proposal, evidence and permit protocol", protocolStatus, ["eval/protocol-report.json"]),
      item("authority", "Persistent write authority audit", authorityStatus, ["eval/authority-report.json"]),
      item("p1", "Worker and Broker product wiring", p1Status, ["eval/evidence/p1-product-report.json"]),
      item("topology", "Live least-authority topology", topologyStatus, ["eval/evidence/topology-report.json"]),
    ],
  },
  {
    id: "robustness",
    label: "Verification and robustness",
    items: [
      item("automated", "Protocol, adversarial and recovery suites", combine(protocolStatus, adversarialStatus, recoveryStatus), ["eval/protocol-report.json", "eval/adversarial-report.json", "eval/recovery-report.json"]),
      item("container", "Credential-free verifier container", containerStatus, ["eval/container-report.json"]),
      item("broker-restart", "Broker SIGKILL orphan reconciliation", brokerRestartStatus, ["eval/container-report.json"]),
      item("filesystem", "Linux filesystem contract", filesystemStatus, ["eval/evidence/linux-filesystem-report.json"]),
      item("docker-recovery", "Docker process kill/restart matrix", dockerRecoveryStatus, ["eval/evidence/docker-recovery-report.json"]),
      item("invariants", "Machine-readable non-effect and safety invariants", invariantStatus, ["eval/evidence/invariants-report.json"]),
      item("receipt-proof", "Offline receipt and event binding verification", receiptVerificationStatus, ["eval/evidence/receipt-verification-report.json"]),
      item("performance", "Linux Worker protocol microbenchmark p50/p95 disclosure", performanceStatus, ["eval/evidence/performance-report.json"]),
      item("bypass", "Candidate and environment bypass protection", combine(adversarialClaim("candidate-test-runner-bypass"), adversarialClaim("candidate-mutation-detected"), adversarialClaim("trusted-bundle-link-rejection")), ["eval/adversarial-report.json"]),
      item("secrets", "Secret scanning and redaction", combine(secretStatus, adversarialClaim("receipt-redaction")), ["eval/evidence/secret-report.json", "eval/adversarial-report.json"]),
    ],
  },
  {
    id: "demo",
    label: "Demo and reproducibility",
    items: [
      item("one-command", "One-command product smoke test", demoSmokeStatus, ["eval/evidence/demo-smoke-report.json"]),
      item("browser", "Clean-clone browser replay", cleanBrowserStatus, ["eval/browser-clean-clone-report.json"]),
      item("documentation", "Revision-bound documentation review", documentationStatus, ["eval/evidence/documentation-review.json"]),
      item("architecture", "Editable architecture artifact integrity", architectureStatus, ["eval/evidence/architecture-report.json"]),
      item("clean-replay", "Read-only clean-worktree replay", independentStatus, ["eval/independent-audit-report.json"]),
      item("source-delivery", "Reviewer-accessible source or hash-bound archive", sourceDeliveryStatus, ["eval/evidence/source-delivery-report.json"]),
      item("video", "Narrated three-minute video", demoVideoStatus, ["eval/evidence/demo-video-report.json"]),
    ],
  },
];

for (const section of sections) {
  section.status = combine(...section.items.map((entry) => entry.status));
}
const status = combine(...sections.map((section) => section.status));
const totals = sections
  .flatMap((section) => section.items)
  .reduce(
    (result, entry) => {
      result[entry.status] += 1;
      return result;
    },
    { verified: 0, failed: 0, unverified: 0 },
  );

const report = {
  schemaVersion: 3,
  kind: "commitgate-evidence-checklist",
  generatedAt: new Date().toISOString(),
  status,
  organizerScore: null,
  providerE2EVerified,
  providerId: browserProviderId,
  source: currentProvenance,
  executionIdentity: currentIdentity,
  totals,
  sections,
  legacyInputCompatibility: {
    acceptedReadOnlyFields: [
      "officialProviderE2E",
      "alternateProviderVerified",
      "competitionVerified",
    ],
    affectsScoring: false,
  },
  claimBoundary:
    "This checklist indexes revision-bound verified, failed, and unverified evidence. It assigns no organizer score and gives no preference to a model Provider.",
};
if (!checkOnly) {
  await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");
}

const lines = [
  "# CommitGate evidence checklist",
  "",
  `- Status: **${status}**`,
  `- Provider E2E: **${providerE2EVerified}**${browserProviderId ? ` (${browserProviderId})` : ""}`,
  `- Items: **${totals.verified} verified / ${totals.failed} failed / ${totals.unverified} unverified**`,
  "- Organizer score: **not assigned**",
  "",
  "> This is a machine-readable evidence index, not an official or predicted score.",
  "",
  ...sections.flatMap((section) => [
    `## ${section.label} — ${section.status}`,
    "",
    ...section.items.map(
      (entry) =>
        `- \`${entry.status}\` — ${entry.label}; evidence: ${entry.evidence.join(", ")}`,
    ),
    "",
  ]),
  "## Claim boundary",
  "",
  report.claimBoundary,
  "",
];
if (!checkOnly) {
  await writeFile(markdownPath, lines.join("\n"), "utf8");
}

console.log("Evidence checklist mode: no numeric or organizer score is produced.");
for (const section of sections) {
  console.log(`${section.status.padEnd(10)} ${section.label}`);
  for (const entry of section.items) {
    console.log(`  ${entry.status.padEnd(10)} ${entry.label}`);
  }
}
console.log(
  `TOTAL: ${totals.verified} verified / ${totals.failed} failed / ${totals.unverified} unverified`,
);
console.log(
  checkOnly
    ? "evidence checklist dry run: reports not written"
    : `evidence checklist: ${reportPath}`,
);
process.exitCode = status === "verified" ? 0 : status === "failed" ? 1 : 2;
