#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import {
  evidenceProvenance,
  executionIdentity,
  revisionIsAncestor,
  sourceTreeHash,
} from "./evidence-utils.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const reportPath = path.join(root, "eval", "score-report.json");
const markdownPath = path.join(root, "eval", "score-report.md");

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
      path: relative,
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
};
const currentSource = await sourceTreeHash(root);
const currentProvenance = await evidenceProvenance(root);
const currentIdentity = executionIdentity(root);

const shaIdentity = (value) => /^sha256:[a-f0-9]{64}$/.test(value ?? "");
const sourceBound = (report) =>
  report?.source?.sourceTreeHash === currentSource.hash &&
  report?.source?.sourceFileCount === currentSource.files &&
  report?.source?.workingTreeCleanAtCapture === true &&
  revisionIsAncestor(root, report?.source?.sourceRevision);
const imageBound = (report) => {
  const runtime = report?.executionIdentity?.runtimeImage?.imageDigest;
  const verifier = report?.executionIdentity?.verifierImage?.imageDigest;
  if (!shaIdentity(runtime) || !shaIdentity(verifier)) return false;
  if (shaIdentity(currentIdentity.runtimeImage.imageDigest) && runtime !== currentIdentity.runtimeImage.imageDigest) {
    return false;
  }
  if (shaIdentity(currentIdentity.verifierImage.imageDigest) && verifier !== currentIdentity.verifierImage.imageDigest) {
    return false;
  }
  return report?.executionIdentity?.provider?.credentialsRecorded === false;
};
const baseReport = (report, kind, schemaVersion) =>
  report?.schemaVersion === schemaVersion &&
  report?.kind === kind &&
  typeof report?.generatedAt === "string" &&
  Number.isFinite(Date.parse(report.generatedAt)) &&
  sourceBound(report) &&
  imageBound(report);
const semanticStatus = (report, kind, schemaVersion, predicate = () => true) => {
  if (!baseReport(report, kind, schemaVersion)) return "unverified";
  if (report.status === "failed") return "failed";
  if (report.status !== "verified") return "unverified";
  return predicate(report) ? "verified" : "failed";
};
const claimStatus = (report, kind, id) => {
  if (!baseReport(report, kind, 2)) return "unverified";
  if (report.command?.status === "failed") return "failed";
  const claim = report.claims?.find((entry) => entry.id === id);
  return ["verified", "failed", "unverified"].includes(claim?.status)
    ? claim.status
    : "unverified";
};
const combine = (...statuses) =>
  statuses.includes("failed") ? "failed" : statuses.every((status) => status === "verified") ? "verified" : "unverified";

const protocolStatus = semanticStatus(
  reports.protocol,
  "commitgate-protocol-evaluation",
  2,
  (report) => report.command?.exitCode === 0 && report.tests?.total > 0 && report.tests?.failed === 0,
);
const adversarialStatus = semanticStatus(
  reports.adversarial,
  "commitgate-adversarial-evaluation",
  2,
  (report) => report.command?.exitCode === 0 && report.tests?.total > 0 && report.tests?.failed === 0,
);
const recoveryStatus = semanticStatus(
  reports.recovery,
  "commitgate-recovery-evaluation",
  2,
  (report) => report.command?.exitCode === 0 && report.tests?.total > 0 && report.tests?.failed === 0,
);
const authorityStatus = semanticStatus(
  reports.authority,
  "persistent-authority-static-audit",
  2,
  (report) =>
    report.unauthorizedPersistentWriteCount === 0 &&
    report.authoritySurface?.length >= 9 &&
    report.authoritySurface.every((entry) => entry.status === "verified"),
);
const containerStatus = semanticStatus(
  reports.container,
  "container-verifier-evaluation",
  2,
  (report) =>
    report.provenance?.realContainerExecution === true &&
    shaIdentity(report.provenance?.imageId) &&
    Object.values(report.structural ?? {}).length >= 12 &&
    Object.values(report.structural ?? {}).every(Boolean) &&
    report.positive?.status === "PASS" &&
    report.positive?.exitCode === 0 &&
    report.negative?.status === "FAIL" &&
    Number.isInteger(report.negative?.exitCode) &&
    report.negative.exitCode !== 0,
);
const checkStatus = semanticStatus(
  reports.check,
  "baseline-regression-check",
  1,
  (report) => {
    const requiredCommands = [
      "npm run typecheck",
      "npm run test",
      "npm run test:evaluator-cleanup",
      "npm run build",
    ];
    return (
      requiredCommands.every((command) =>
        report.results?.some(
          (entry) =>
            entry.command === command &&
            entry.status === "verified" &&
            entry.exitCode === 0,
        ),
      ) &&
      report.results?.every(
        (entry) => entry.status === "verified" && entry.exitCode === 0,
      )
    );
  },
);
const secretNames = ["MODEL_API_KEY", "MODEL_RELAY_TOKEN", "OPENROUTER_API_KEY", "ARK_API_KEY"];
const secretStatus = semanticStatus(
  reports.secrets,
  "secret-scan",
  1,
  (report) =>
    report.scannedWorkingTree === true &&
    report.scannedEvidenceArtifacts === true &&
    report.scannedGitHistory === true &&
    report.exactCredentialNormalizationSelfCheck === "verified" &&
    secretNames.every((name) => ["scanned", "not-present"].includes(report.exactCredentialScan?.[name])) &&
    (secretNames.every((name) => report.exactCredentialScan?.[name] === "not-present") ||
      report.gitObjectExactScan === "verified") &&
    Array.isArray(report.findings) &&
    report.findings.length === 0,
);

function providerStatus(provider) {
  const report = reports[provider];
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
    const committed = ["real-positive-commit", "fresh-session-follow-up"].map(
      (id) => byId.get(id),
    );
    const quarantined = byId.get("real-protected-quarantine");
    return (
      candidate.provider?.providerId === provider &&
      candidate.provider?.credentialsRecorded === false &&
      typeof candidate.provider?.resolvedModel === "string" &&
      candidate.provider.resolvedModel.length > 0 &&
      candidate.provenance?.realProviderRequest === true &&
      candidate.provenance?.realCodexContainer === true &&
      required.every((id) => byId.get(id)?.status === "verified") &&
      committed.every(
        (entry) =>
          entry?.decision === "COMMITTED" &&
          entry.runId &&
          entry.baseViewId &&
          entry.proposalId &&
          entry.evaluationContextHash &&
          entry.evidenceDigest &&
          entry.permitId &&
          entry.permitState === "CONSUMED",
      ) &&
      quarantined?.decision === "QUARANTINED" &&
      quarantined.runId &&
      quarantined.baseViewId &&
      quarantined.proposalId &&
      quarantined.artifactRetention === "destroyed"
    );
  });
}
const arkStatus = providerStatus("ark");
const openrouterStatus = providerStatus("openrouter");

async function browserStatus() {
  const status = semanticStatus(
    reports.browser,
    "browser-clean-clone-evaluation",
    2,
    (report) => {
      const required = [
        "clean-clone-npm-ci-and-image-build",
        "browser-create-agent",
        "browser-positive-committed",
        "browser-protected-quarantined",
        "browser-provider-or-verifier-aborted",
        "browser-fresh-follow-up",
        "stale-permit-replay-rejected",
        "browser-manual-rollback",
      ];
      return (
        report.provider?.providerId === "ark" &&
        report.provider?.credentialsRecorded === false &&
        report.preconditions?.every((entry) => entry.status === "verified") &&
        required.every((id) => report.steps?.find((entry) => entry.id === id)?.status === "verified") &&
        Array.isArray(report.artifacts) &&
        report.artifacts.length >= 3
      );
    },
  );
  if (status !== "verified") return status;
  for (const entry of reports.browser.artifacts) {
    if (!entry.path?.startsWith("eval/artifacts/") || !/^[a-f0-9]{64}$/.test(entry.sha256 ?? "")) {
      return "failed";
    }
    const actual = await artifact(entry.path);
    if (!actual || actual.sha256 !== entry.sha256) return "failed";
  }
  return "verified";
}
const cleanBrowserStatus = await browserStatus();
const independentStatus = semanticStatus(
  reports.independent,
  "independent-clean-worktree-audit",
  2,
  (report) => {
    const required = [
      "clean-local-clone",
      "checkout-source-revision",
      "clone-identity",
      "npm-ci",
      "baseline-check",
      "read-only-source-files",
      "protocol",
      "adversarial",
      "recovery",
      "authority",
      "container",
      "secrets",
      "source-unchanged-after-audit",
    ];
    return (
      report.independent === true &&
      report.cleanClone === true &&
      report.readOnlySource === true &&
      required.every((id) => report.results?.find((entry) => entry.id === id)?.status === "verified")
    );
  },
);
const documentationStatus = semanticStatus(
  reports.documentation,
  "independent-documentation-review",
  2,
  (report) =>
    report.reviewerIndependent === true &&
    ["README", "architecture", "three-minute-script", "limitations"].every(
      (id) => report.items?.find((entry) => entry.id === id)?.status === "verified",
    ),
);

const protocolClaim = (id) => claimStatus(reports.protocol, "commitgate-protocol-evaluation", id);
const adversarialClaim = (id) => claimStatus(reports.adversarial, "commitgate-adversarial-evaluation", id);
const recoveryClaim = (id) => claimStatus(reports.recovery, "commitgate-recovery-evaluation", id);
const verified = (status) => status === "verified";
function item(id, label, points, status, evidence) {
  return { id, label, points, status, awarded: verified(status) ? points : 0, evidence };
}

const categories = [
  {
    id: "end-to-end",
    label: "End-to-end middleware behavior",
    maximum: 40,
    provisionalCap: 24,
    items: [
      item("real-browser-codex", "Official browser to Codex container", 10, combine(arkStatus, cleanBrowserStatus), ["eval/provider-ark-report.json", "eval/browser-clean-clone-report.json"]),
      item("commit", "Sealed proposal and one-shot commit", 8, combine(protocolClaim("sealed-proposal-single-source"), protocolClaim("one-shot-promotion-permit"), protocolClaim("sealed-commit")), ["eval/protocol-report.json"]),
      item("quarantine", "Protected-path rejection", 8, combine(protocolClaim("terminal-decision-semantics"), adversarialClaim("path-budget-canary-platform")), ["eval/protocol-report.json", "eval/adversarial-report.json"]),
      item("reconciliation", "View/session continuation fence", 5, combine(protocolClaim("message-authority-fence"), adversarialClaim("session-home-isolation")), ["eval/protocol-report.json", "eval/adversarial-report.json"]),
      item("rollback", "Append-only rollback and recovery", 5, combine(protocolClaim("append-only-rollback"), recoveryClaim("rollback-crash-recovery")), ["eval/protocol-report.json", "eval/recovery-report.json"]),
      item("regression", "Starter CRUD/build regression", 4, checkStatus, ["eval/evidence/check-report.json"]),
    ],
  },
  {
    id: "design",
    label: "Technical design and integration",
    maximum: 25,
    provisionalCap: 25,
    items: [
      item("boundary", "State-view/proposal/permit boundary", 5, combine(protocolClaim("view-generation-aba-fence"), protocolClaim("sealed-proposal-single-source"), protocolClaim("one-shot-promotion-permit")), ["eval/protocol-report.json"]),
      item("integration", "Runner, API and terminal projection", 5, combine(protocolClaim("sealed-commit"), protocolClaim("terminal-decision-semantics"), protocolClaim("database-v3-migration")), ["eval/protocol-report.json"]),
      item("isolation", "Credential-free verifier isolation", 6, combine(containerStatus, adversarialClaim("verifier-clean-environment"), adversarialClaim("relay-only-network")), ["eval/container-report.json", "eval/adversarial-report.json"]),
      item("schema", "View CAS, message authority and migration", 5, combine(protocolClaim("view-generation-aba-fence"), protocolClaim("database-v3-migration"), protocolClaim("message-authority-fence")), ["eval/protocol-report.json"]),
      item("contracts", "Trusted checks, resource limits and writer authority", 4, combine(authorityStatus, adversarialClaim("cumulative-verifier-budget"), adversarialClaim("trusted-bundle-link-rejection")), ["eval/authority-report.json", "eval/adversarial-report.json"]),
    ],
  },
  {
    id: "robustness",
    label: "Verification and robustness",
    maximum: 20,
    provisionalCap: 20,
    items: [
      item("automated", "Protocol/adversarial/recovery suites", 6, combine(protocolStatus, adversarialStatus, recoveryStatus), ["eval/protocol-report.json", "eval/adversarial-report.json", "eval/recovery-report.json"]),
      item("bypass", "Candidate and environment bypass protection", 5, combine(adversarialClaim("candidate-test-runner-bypass"), adversarialClaim("candidate-mutation-detected"), adversarialClaim("trusted-bundle-link-rejection")), ["eval/adversarial-report.json"]),
      item("failures", "Conflict and malformed-evidence handling", 4, combine(protocolClaim("view-cas-conflict"), adversarialClaim("malformed-evidence-fail-closed"), recoveryClaim("database-projection-rollback")), ["eval/protocol-report.json", "eval/adversarial-report.json", "eval/recovery-report.json"]),
      item("recovery", "Crash recovery, event chain and repair CAS", 3, combine(recoveryClaim("rename-swap-rollback"), recoveryClaim("pending-promotion-recovery"), recoveryClaim("immutable-transition-chain"), recoveryClaim("repair-expected-state-cas")), ["eval/recovery-report.json"]),
      item("redaction", "Secret scanning and metadata-only evidence", 2, combine(secretStatus, adversarialClaim("receipt-redaction")), ["eval/evidence/secret-report.json", "eval/adversarial-report.json"]),
    ],
  },
  {
    id: "demo",
    label: "Demo and reproducibility",
    maximum: 15,
    provisionalCap: 8,
    items: [
      item("three-minute", "Three-minute official browser demo", 4, cleanBrowserStatus, ["eval/browser-clean-clone-report.json"]),
      item("provider", "Real official provider startup/E2E", 4, arkStatus, ["eval/provider-ark-report.json"]),
      item("docs", "Independent README/architecture/demo review", 3, documentationStatus, ["eval/evidence/documentation-review.json"]),
      item("reports", "Independent machine-readable evidence replay", 2, independentStatus, ["eval/independent-audit-report.json"]),
      item("clean-clone", "Read-only clean-clone reproduction", 2, independentStatus, ["eval/independent-audit-report.json"]),
    ],
  },
];

const competitionVerified =
  arkStatus === "verified" &&
  cleanBrowserStatus === "verified" &&
  independentStatus === "verified" &&
  secretStatus === "verified";
for (const category of categories) {
  category.raw = category.items.reduce((sum, entry) => sum + entry.awarded, 0);
  category.cap = competitionVerified ? category.maximum : category.provisionalCap;
  category.score = Math.min(category.raw, category.cap);
}
const rawTotal = categories.reduce((sum, category) => sum + category.raw, 0);
const cappedTotal = categories.reduce((sum, category) => sum + category.score, 0);
const overallCap = competitionVerified ? 100 : 77;
const score = Math.min(cappedTotal, overallCap);
const evidenceFailed = categories.some((category) => category.items.some((entry) => entry.status === "failed"));
const status = competitionVerified
  ? "competition-verified"
  : evidenceFailed
    ? "provisional-with-failures"
    : "provisional";
const alternateProviderVerified = openrouterStatus === "verified";
const report = {
  schemaVersion: 2,
  kind: "evidence-bound-rubric-projection",
  generatedAt: new Date().toISOString(),
  status,
  score,
  maximum: 100,
  rawBeforeCaps: rawTotal,
  appliedOverallCap: overallCap,
  competitionVerified,
  officialProviderE2E: arkStatus,
  alternateProviderVerified,
  browserCleanClone: cleanBrowserStatus,
  independentAudit: independentStatus,
  source: currentProvenance,
  executionIdentity: currentIdentity,
  claimBoundary: competitionVerified
    ? "Official Ark, clean-clone browser, independent replay and secret evidence are verified for one source/image identity."
    : "Official provider/browser/independent evidence is incomplete; provisional caps apply. OpenRouter evidence never sets officialProviderE2E.",
  categories,
};
await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");

const lines = [
  "# CommitGate evidence-bound rubric projection",
  "",
  `- Status: **${status}**`,
  `- Score: **${score}/100**`,
  `- Applied cap: **${overallCap}/100**`,
  `- Competition verified: **${competitionVerified ? "yes" : "no"}**`,
  `- Official provider E2E: **${arkStatus}**`,
  `- Alternate provider verified: **${alternateProviderVerified ? "yes" : "no"}**`,
  "",
  "| Category | Raw | Cap | Score |",
  "| --- | ---: | ---: | ---: |",
  ...categories.map((category) => `| ${category.label} | ${category.raw}/${category.maximum} | ${category.cap} | ${category.score} |`),
  "",
  "## Evidence items",
  "",
  ...categories.flatMap((category) => [
    `### ${category.label}`,
    "",
    ...category.items.map((entry) => `- \`${entry.status}\` ${entry.awarded}/${entry.points} — ${entry.label}; evidence: ${entry.evidence.join(", ")}`),
    "",
  ]),
  "## Claim boundary",
  "",
  report.claimBoundary,
  "",
];
await writeFile(markdownPath, lines.join("\n"), "utf8");
for (const category of categories) {
  console.log(`${category.label}: ${category.score}/${category.maximum} (raw ${category.raw}, cap ${category.cap})`);
  for (const entry of category.items) {
    console.log(`  ${entry.status.padEnd(10)} ${entry.awarded}/${entry.points} ${entry.label}`);
  }
}
console.log(`TOTAL: ${score}/100 [${status}; cap ${overallCap}]`);
console.log(`score report: ${reportPath}`);
