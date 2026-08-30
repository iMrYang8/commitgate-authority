#!/usr/bin/env node
import { access, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { evidenceProvenance, executionIdentity } from "./evidence-utils.mjs";
import {
  activeEvidenceReportInventory,
  resolveActiveProviderReport,
} from "./evidence-inventory.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const reportPath = path.join(root, "eval", "evidence", "documentation-review.json");
const checkOnly = process.argv.includes("--check");
const source = await evidenceProvenance(root);
const readOnlyCleanSource = source.workingTreeCleanAtCapture === true;

const documents = {
  README: await readFile(path.join(root, "README.md"), "utf8"),
  architecture: await readFile(path.join(root, "docs", "ARCHITECTURE.md"), "utf8"),
  "three-minute-script": await readFile(
    path.join(root, "docs", "DEMO_3_MINUTES.md"),
    "utf8",
  ),
  limitations: await readFile(path.join(root, "docs", "LIMITATIONS.md"), "utf8"),
  deployment: await readFile(path.join(root, "docs", "DEPLOYMENT.md"), "utf8"),
};

const requirements = {
  README: [
    /Verified Workspace Transactions for AI Agents/i,
    /No evidence, no effect/i,
    /pre-effect admission transaction for\s+filesystem state/i,
    /Responses-compatible Provider/i,
    /providerE2EVerified/i,
    /assigns no numeric score/i,
    /release browser report[\s\S]{0,180}\*\*12\/12\*\*/i,
    /Editable source:[\s\S]{0,120}commitgate-architecture\.drawio/i,
    /Worker-derived View/i,
    /pre-run TOFU/i,
    /30 seconds by[\s\S]{0,260}CANDIDATE_SCAN_TIME_BUDGET_EXCEEDED/i,
    /shared tmpfs[\s\S]{0,180}kernel byte and inode ceilings/i,
    /RUNTIME_BROKER_PROCESS_SIGKILL_ORPHAN_RECONCILIATION[\s\S]{0,420}exact-label reconciliation/i,
    /demo:verify-video[\s\S]{0,900}officialSubmissionReady[\s\S]{0,420}externalReviewVerified/i,
    /manual-secret-review[\s\S]{0,260}official submission/i,
    /audit:source-delivery[\s\S]{0,520}does not prove anonymous clone access/i,
    /fixed registry of ten effect-capable negative[\s\S]{0,420}assertion-backed[\s\S]{0,260}raw-hash fields `null`/i,
    /Transition Worker local-filesystem protocol[\s\S]{0,420}deterministicProbeMs[\s\S]{0,360}not be presented as Verifier latency/i,
  ],
  architecture: [
    /No Evidence, No Effect/i,
    /Editable one-page diagram/i,
    /interface StateViewRef/,
    /interface SealedProposal/,
    /EvaluationContextHash/,
    /one-shot `PromotionPermit`/,
    /providerE2EVerified/,
    /Worker-derived StateView/i,
    /pre-run TOFU/i,
    /wall-clock budget of 30 seconds/i,
    /shared\s+tmpfs[\s\S]{0,220}kernel-enforced aggregate exchange budget/i,
    /RUNTIME_BROKER_PROCESS_SIGKILL_ORPHAN_RECONCILIATION[\s\S]{0,420}broker-reconciliation/i,
    /exact ten-item effect-capable negative-fixture[\s\S]{0,420}raw-hash fields remain `null`/i,
    /Transition Worker local-filesystem microbenchmark[\s\S]{0,360}not Verifier-container or end-to-end latency/i,
  ],
  "three-minute-script": [
    /## 0:00–0:20/,
    /## 0:20–1:05/,
    /## 1:05–1:45/,
    /## 1:45–2:10/,
    /## 2:10–2:30/,
    /## 2:30–3:00/,
    /npm run demo:verify-video/,
    /POST \/api\/runs\/:id\/commitgate\/promotion-attempts/i,
    /Candidate world:[\s\S]{0,100}Persistent world:/i,
    /No evidence, no effect/i,
    /Responses-compatible Provider/i,
    /process kill\/restart/i,
    /officialSubmissionReady=true[\s\S]{0,220}externalReviewVerified/i,
  ],
  limitations: [
    /filesystem effects under the authoritative Agent workspace/i,
    /process kill\/restart recovery/i,
    /not power-loss durability/i,
    /Responses-compatible Provider/i,
    /providerE2EVerified/i,
    /checklist does not calculate an organizer or predicted score/i,
    /recorded Ark clean-clone report verified 12\/12 product scenarios/i,
    /Worker[\s\S]{0,140}derives every next\s+StateView/i,
    /pre-run TOFU anchor/i,
    /wall-clock limit \(30[\s\S]{0,180}CANDIDATE_SCAN_TIME_BUDGET_EXCEEDED/i,
    /byte- and inode-bounded tmpfs/i,
    /RUNTIME_BROKER_PROCESS_SIGKILL_ORPHAN_RECONCILIATION[\s\S]{0,360}exact-label negative-query/i,
    /exact[\s\S]{0,80}ten-item effect-capable negative registry[\s\S]{0,360}seven CAS\/cancellation observations[\s\S]{0,160}`null` raw-hash fields/i,
    /Worker-local[\s\S]{0,120}deterministic probe[\s\S]{0,340}not evidence for product[\s\S]{0,80}latency/i,
  ],
  deployment: [
    /MODEL_PROVIDER=ark[\s\S]{0,200}MODEL_WIRE_API=responses/i,
    /Responses-compatible Provider/i,
    /RUNTIME_PROVIDER=broker[\s\S]{0,160}TRANSITION_AUTHORITY=worker/i,
    /signingKeyId=<24-hex public-key fingerprint>/i,
    /pre-run TOFU/i,
    /(?:default 30 seconds|\u9ed8\u8ba4 30 \u79d2)[\s\S]{0,180}CANDIDATE_SCAN_TIME_BUDGET_EXCEEDED/i,
    /byte\/inode[\s\S]{0,100}tmpfs[\s\S]{0,180}aggregate kernel cap/i,
    /caller-authored next View/i,
    /RUNTIME_BROKER_PROCESS_SIGKILL_ORPHAN_RECONCILIATION[\s\S]{0,420}精确 label/i,
    /evidence:checklist/i,
    /audit:source-delivery[\s\S]{0,620}(?:anonymous|匿名读取)/i,
    /Ed25519[\s\S]{0,260}可选/i,
    /officialSubmissionReady=true/i,
    /固定的 10 项 effect-capable[\s\S]{0,420}raw[\s\S]{0,20}hash 字段保持 `null`/i,
    /Transition Worker 本地文件系统协议[\s\S]{0,500}deterministicProbeMs[\s\S]{0,260}不得[\s\S]{0,120}Verifier latency/i,
  ],
};

const items = Object.entries(requirements).map(([id, patterns]) => {
  const text = documents[id];
  const checks = patterns.map((pattern) => ({
    pattern: pattern.source,
    matched: pattern.test(text),
  }));
  return {
    id,
    status: checks.every((check) => check.matched) ? "verified" : "failed",
    checks,
  };
});

const allCurrentDocumentation = Object.values(documents).join("\n");
const coreEvidenceContracts = [
  {
    id: "broker-hmac-evidence",
    pattern:
      /Runtime Broker[\s\S]{0,360}HMAC-SHA256[\s\S]{0,360}(?:Runtime teardown|Verifier)[\s\S]{0,240}(?:attestation|evidence)/i,
  },
  {
    id: "effect-disposition-proof",
    pattern:
      /sealedProposalHash\s*==\s*verifierInputHash\s*==\s*promotionSourceHash\s*==\s*finalAuthoritativeHash[\s\S]{0,520}(?:authoritativeBeforeHash\s*==\s*authoritativeAfterHash|authoritativeAfterHash\s*==\s*authoritativeBeforeHash)/i,
  },
  {
    id: "opaque-ref-write-once-tombstone",
    pattern: /opaque[\s\S]{0,260}write-?once[\s\S]{0,260}tombstone/i,
  },
  {
    id: "broker-durable-lifecycle-ledger",
    pattern:
      /durable monotonic lifecycle ledger[\s\S]{0,360}AGENT_STARTED[\s\S]{0,120}AGENT_CLOSED[\s\S]{0,120}VERIFIER_STARTED[\s\S]{0,120}ALL_CLOSED[\s\S]{0,360}tombstone/i,
  },
  {
    id: "unique-demo-entrypoint",
    pattern: /唯一启动命令\s+`npm run demo`/i,
  },
];
const forbiddenAlternativeEntrypoints = [
  /(?:primary|official|one-command|唯一|正式|默认)[^\n]{0,100}(?:npm run dev|npm run start|docker(?:-compose| compose) up)/i,
];
items.push({
  id: "core-evidence-contracts",
  status:
    coreEvidenceContracts.every(({ pattern }) => pattern.test(allCurrentDocumentation)) &&
    forbiddenAlternativeEntrypoints.every(
      (pattern) => !pattern.test(allCurrentDocumentation),
    )
      ? "verified"
      : "failed",
  checks: [
    ...coreEvidenceContracts.map(({ id, pattern }) => ({
      pattern: `${id}:${pattern.source}`,
      matched: pattern.test(allCurrentDocumentation),
    })),
    ...forbiddenAlternativeEntrypoints.map((pattern) => ({
      pattern: `forbidden-alternative-demo-entrypoint:${pattern.source}`,
      matched: !pattern.test(allCurrentDocumentation),
    })),
  ],
});

let browserProviderId = null;
try {
  const browserReport = JSON.parse(
    await readFile(path.join(root, "eval", "browser-clean-clone-report.json"), "utf8"),
  );
  if (
    /^[a-z0-9_-]+$/i.test(browserReport?.provider?.providerId ?? "") &&
    browserReport?.source?.sourceRevision === source.sourceRevision &&
    browserReport?.source?.sourceTreeHash === source.sourceTreeHash &&
    browserReport?.source?.sourceFileCount === source.sourceFileCount &&
    browserReport?.source?.workingTreeCleanAtCapture === true
  ) {
    browserProviderId = browserReport.provider.providerId;
  }
} catch {
  // The release gate still requires browser evidence.  Documentation review
  // may select one current-source Provider compatibility report before then.
}
const activeProviderReport = await resolveActiveProviderReport(root, {
  browserProviderId,
  source,
});
const activeReportInventory = await activeEvidenceReportInventory(root, [
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
  activeProviderReport,
]);
items.push({
  id: "active-evidence-report-isolation",
  status: activeReportInventory.unexpected.length === 0 ? "verified" : "failed",
  checks: [{
    pattern: "active report paths are an exact allowlist; historical reports live under eval/history/<revision>/",
    matched: activeReportInventory.unexpected.length === 0,
    unexpected: activeReportInventory.unexpected,
  }],
});

const forbiddenProviderClaims = [
  /Ark\s+(?:is|as)\s+the\s+official/i,
  /official\s+(?:competition\s+)?(?:Provider|path)[^\n]{0,80}Ark/i,
  /realModelArk/i,
];
items.push({
  id: "provider-neutral-language",
  status: forbiddenProviderClaims.some((pattern) => pattern.test(allCurrentDocumentation))
    ? "failed"
    : "verified",
  checks: forbiddenProviderClaims.map((pattern) => ({
    pattern: `forbidden:${pattern.source}`,
    matched: !pattern.test(allCurrentDocumentation),
  })),
});

const forbiddenCurrentScores = [
  /\b76\/100\b/,
  /\b82\/100\b/,
  /\b91\/100\b/,
  /\b94\/100\b/,
  /\b94\+(?![\w/])/,
];
items.push({
  id: "no-current-numeric-score",
  status: forbiddenCurrentScores.some((pattern) => pattern.test(allCurrentDocumentation))
    ? "failed"
    : "verified",
  checks: forbiddenCurrentScores.map((pattern) => ({
    pattern: `forbidden:${pattern.source}`,
    matched: !pattern.test(allCurrentDocumentation),
  })),
});

const activeLegacyScorePaths = [
  path.join(root, "eval", "score-report.json"),
  path.join(root, "eval", "score-report.md"),
];
const activeLegacyScoreAbsent = await Promise.all(
  activeLegacyScorePaths.map(async (candidate) => {
    try {
      await access(candidate);
      return false;
    } catch {
      return true;
    }
  }),
);
let archivedScorePaths = [];
try {
  archivedScorePaths = (await readdir(path.join(root, "eval", "history"), {
    recursive: true,
  })).filter((entry) => /(?:^|\/)score-report\.(?:json|md)$/.test(entry));
} catch {
  archivedScorePaths = [];
}
const archivedUnderRevision = archivedScorePaths.length >= 2 &&
  archivedScorePaths.every((entry) => /^[a-f0-9]{40}\//.test(entry));
items.push({
  id: "historical-score-isolation",
  status: activeLegacyScoreAbsent.every(Boolean) && archivedUnderRevision
    ? "verified"
    : "failed",
  checks: [
    {
      pattern: "active eval/score-report.{json,md} absent",
      matched: activeLegacyScoreAbsent.every(Boolean),
    },
    {
      pattern: "legacy score reports archived below eval/history/<40-hex-revision>/",
      matched: archivedUnderRevision,
    },
  ],
});

const contentStatus = items.some((item) => item.status === "failed")
  ? "failed"
  : "verified";
const status = checkOnly
  ? contentStatus
  : readOnlyCleanSource && contentStatus === "verified"
    ? "verified"
    : contentStatus === "failed"
      ? "failed"
      : "unverified";
const report = {
  schemaVersion: 3,
  kind: "documentation-contract-audit",
  generatedAt: new Date().toISOString(),
  status,
  source,
  executionIdentity: executionIdentity(root),
  auditOrigin: "project-defined",
  externallyIndependent: false,
  readOnlyCleanSource,
  method:
    "Project-defined semantic contract audit over a clean source checkout; checks protocol claim, timed demo, Provider-neutral evidence semantics and non-goal boundaries rather than file presence alone. It is not an external third-party review.",
  items,
};
if (!checkOnly) {
  await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");
}
for (const item of items) {
  console.log(`${item.status.padEnd(10)} ${item.id}`);
  if (checkOnly) {
    for (const check of item.checks.filter((entry) => !entry.matched)) {
      console.log(`  missing    /${check.pattern}/`);
    }
  }
}
console.log(
  checkOnly
    ? `${status}: documentation static check; report not written`
    : `${status}: documentation review: ${reportPath}`,
);
process.exitCode = status === "verified" ? 0 : status === "unverified" ? 2 : 1;
