#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { evidenceProvenance, executionIdentity } from "./evidence-utils.mjs";
import { assertEvaluationRecord, evaluationRecord } from "./evaluation-record.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const suiteId = process.argv[2];

const suites = {
  protocol: {
    kind: "commitgate-protocol-evaluation",
    files: [
      "src/state-view.test.ts",
      "src/store.test.ts",
      "src/agent-service.test.ts",
      "src/app.test.ts",
      "src/commitgate/protocol.test.ts",
      "src/commitgate/effect-proof.test.ts",
      "src/commitgate/rollback-permit-store.test.ts",
      "src/commitgate/manifest.test.ts",
      "src/commitgate/coordinator.test.ts",
      "src/commitgate/verifier-runner.test.ts",
      "src/commitgate/version-store.test.ts",
      "src/commitgate/workspace-transaction.test.ts",
      "src/worker-commitgate-runner.test.ts",
      "src/transition-worker/worker.test.ts",
    ],
    claims: [
      ["view-generation-aba-fence", [/fences an ABA/i]],
      ["sealed-proposal-single-source", [/(sealed proposal|immutable proposal|after sealing|sealed bytes)/i]],
      ["one-shot-promotion-permit", [/(one-shot.*permit|permit.*replay|replay.*permit|consumed permit)/i]],
      ["permit-evidence-completeness", [/refuses to mint a permit for partial, failing, or wrong-input evidence/i]],
      ["transaction-capability-replay", [/same consumed capability for a no-op promotion/i]],
      ["one-shot-rollback-permit", [/dedicated rollback permit.*rejects permit replay/i]],
      ["rollback-import-toctou", [/rollback snapshot changed during import before any swap/i]],
      ["evaluation-context-binding", [/binds actual image identity, verifier config, resources and check content/i]],
      ["manifest-v2-link-rejection", [/(rejects?.*symlink|symlink.*reject)/i, /(hardlink.*reject|rejects?.*hardlink)/i]],
      ["manifest-v2-path-collision", [/(casefold|case-fold|case collision)/i, /(unicode|NFC|NFD)/i]],
      ["database-v3-migration", [/migrates a version 1 database/i]],
      ["sealed-commit", [/promotes a valid candidate/i]],
      ["view-cas-conflict", [/persistent-state conflict/i]],
      ["terminal-decision-semantics", [/quarantines protected changes/i, /ABORTED receipt|wrapped runner fails/i]],
      ["append-only-rollback", [/(new ROLLBACK event|append-only events)/i]],
      ["message-authority-fence", [/persists a playground conversation/i]],
      ["worker-product-commit", [/commits through proposal, evidence, permit and Worker generation CAS/i]],
      ["worker-product-noncommit", [/quarantines a protected-path change without advancing workspace generation/i]],
      [
        "worker-cas-conflict-decision",
        [
          /durably conflicts an H0 proposal after H1 wins without changing workspace, generation, or versions/i,
          /durably classifies a stale promotion workspace hash as CONFLICTED/i,
          /maps a stale Worker View CAS to one durable CONFLICTED disposition before finalize/i,
        ],
      ],
      ["worker-cancellation-fence", [/makes cancellation authoritative before (verifier|permit|promotion)/i]],
      ["explicit-non-effect-proof", [/proves no persistent effect for/i]],
    ],
  },
  adversarial: {
    kind: "commitgate-adversarial-evaluation",
    files: [
      "src/commitgate/robustness.test.ts",
      "src/commitgate/coordinator.test.ts",
      "src/commitgate/manifest.test.ts",
      "src/commitgate/verifier-runner.test.ts",
      "src/commitgate/receipt-store.test.ts",
      "src/commitgate/protocol.test.ts",
      "src/container-codex-runner.test.ts",
      "src/config.test.ts",
      "src/model-relay-server.test.ts",
      "src/transition-worker/worker-policy.test.ts",
      "src/runtime-broker/attestation.test.ts",
      "src/transition-worker/broker-attestation.test.ts",
      "src/transition-worker/opaque-ref-binding.test.ts",
    ],
    claims: [
      ["path-budget-canary-platform", [/rejects file budgets, canaries, and platform-managed edits/i]],
      ["malformed-evidence-fail-closed", [/missing verifier exit evidence/i, /PASS without exit zero and duplicate results/i]],
      ["candidate-mutation-detected", [/(candidate.*mutation|context drifts after checks)/i]],
      ["candidate-test-runner-bypass", [/trusted check exit evidence/i, /candidate-controlled and shell-wrapped check entrypoints/i]],
      ["trusted-bundle-link-rejection", [/rejects symlinks and hardlinks transitively/i]],
      ["verifier-clean-environment", [/immutable proposal and checks bundle with an isolated scratch/i]],
      ["cumulative-verifier-budget", [/accounts timeout and output across the whole verifier run/i]],
      ["relay-only-network", [/relay-only internal network/i]],
      ["relay-capability-forwarding", [/minimal Model Relay.*Provider key.*scope.*revoked run capability/i]],
      ["session-home-isolation", [/isolates session homes by Agent and epoch/i]],
      ["late-write-after-runtime", [/(late write|background.*write|runtime teardown)/i]],
      ["sealed-source-tamper", [/(seal.*original candidate|original candidate.*seal|sealed.*tamper|promotes sealed bytes.*obsolete candidate)/i]],
      ["ignored-path-dos", [/(ignored path.*DoS|scratch.*quota|file count.*quota)/i]],
      ["receipt-redaction", [/(redacts credential-shaped verifier output|redacts per-run Model Relay capabilities)/i]],
      [
        "worker-owned-permit-policy",
        [
          /protected proposal even when the caller submits self-consistent PASS evidence/i,
          /rejects a (missing|extra|wrong) trusted-check set/i,
          /rejects a caller-selected (policy|check specification)/i,
          /rejects an unpinned (trusted-check bundle|Verifier image|Verifier config|resource policy)/i,
        ],
      ],
      [
        "broker-authenticated-runtime-evidence",
        [
          /rejects caller-forged all-true teardown and PASS evidence/i,
          /rejects payload tampering and the wrong key/i,
        ],
      ],
      [
        "worker-owned-opaque-exchange-refs",
        [
          /derives candidate-\$\{runId\}.*tombstones cross-Agent reuse/i,
          /seals only the transition's durable candidate/i,
          /exports only verify-\$\{runId\}.*another run's export/i,
        ],
      ],
    ],
  },
  recovery: {
    kind: "commitgate-recovery-evaluation",
    files: [
      "src/commitgate-service.test.ts",
      "src/commitgate/robustness.test.ts",
      "src/commitgate/workspace-transaction.test.ts",
      "src/commitgate/version-store.test.ts",
      "src/transition-log.test.ts",
      "src/transition-worker/filesystem.test.ts",
      "src/transition-worker/rpc.test.ts",
      "src/transition-worker/worker.test.ts",
      "src/transition-worker/worker-terminal-recovery.test.ts",
      "src/transition-worker/authority-intent-recovery.test.ts",
      "src/transition-worker/evidence-blob-store.test.ts",
      "src/transition-worker/signing-key-store.test.ts",
      "src/transition-worker/runtime-teardown-handshake.test.ts",
      "src/research/receipt-proof.test.ts",
      "src/agent-service-worker-admission-recovery.test.ts",
      "src/runtime-broker/rpc.test.ts",
      "src/runtime-broker/lifecycle-ledger.test.ts",
      "src/transition-worker/receipt-proof-projection-size.test.ts",
      "src/worker-commitgate-runner.test.ts",
    ],
    claims: [
      ["rename-swap-rollback", [/restores the backup when the staging rename fails/i]],
      ["ambiguous-recovery-lock", [/raises recovery-required when both staging rename and backup restore fail/i]],
      ["pending-promotion-recovery", [/recovers forward after product DB commit/i, /pending journal write fails after swap/i]],
      ["database-projection-rollback", [/product database commit fails/i, /version projection fails/i]],
      ["rollback-crash-recovery", [/rollback acknowledgement failure/i, /database-committed rollback/i]],
      ["immutable-transition-chain", [/immutable events into a verified digest chain/i]],
      ["transition-tamper-detection", [/detects an edited historical event/i]],
      ["repair-expected-state-cas", [/repair expected-view and workspace-hash CAS/i]],
      ["stale-callback-fence", [/(stale callback|active lease|late callback)/i]],
      ["terminal-callback-fence", [/does not acknowledge or project a promotion whose terminal callback lease is stale/i]],
      ["recovery-message-disposition", [/rejects an authoritative assistant message when startup recovery rolls its view back/i]],
      ["queued-follow-up-view-rebind", [/(queued follow-up|submittedViewId|follow-up.*view)/i]],
      ["rollback-full-crash-matrix", [/(rollback.*crash point|permit.*CONSUMING|rollback.*acknowledgement stage)/i]],
      ["worker-one-shot-promotion", [/promotes only a sealed proposal with a one-shot permit/i]],
      ["worker-noop-rollback-generation", [/new generation for a no-op rollback snapshot/i]],
      ["worker-rollback-target-binding", [/binds the rollback target version to its snapshot/i]],
      [
        "worker-rpc-wire-path-confinement",
        [/rejects raw host paths and repair force flags/i],
      ],
      ["worker-filesystem-closure", [/fails closed for symlinks and hardlinks/i]],
      [
        "worker-cancellation-race",
        [/fences an accepted run cancellation before permit consumption/i, /returns TOO_LATE after the permit enters CONSUMING/i],
      ],
      [
        "receipt-proof-cryptographic-integrity",
        [
          /(signs and verifies a self-contained authority receipt proof bundle|binds a canonical authority receipt to its terminal event)/i,
          /verifies a conflicted receipt against disposition-time HEAD and the full event chain/i,
        ],
      ],
      [
        "worker-atomic-noncommit-terminal",
        [/derives the fresh non-commit View, revokes the permit, and records one atomic terminal fact/i],
      ],
      [
        "worker-preterminal-abort-recovery",
        [/recovers PREPARED into an ABORTED fresh-session receipt and destroys the candidate/i,
          /surfaces RECOVERY_REQUIRED and never appends a fake rollback/i],
      ],
      [
        "worker-durable-intent-recovery",
        [/forwards initialization after its intent/i,
          /adopts an already-renamed legacy tree/i,
          /forwards platform regeneration from backup\+staging and archives exactly once/i,
          /recovers a sealed proposal and verifier export intent/i],
      ],
      [
        "worker-evidence-blob-integrity",
        [/stores canonical JSON bytes under their SHA-256 ID/i,
          /recomputes the digest on get and rejects post-write tampering/i],
      ],
      [
        "worker-signing-key-confinement",
        [/persists a Worker-only key and produces portable proofs/i,
          /fails closed when persisted private-key permissions are widened/i],
      ],
      [
        "worker-product-admission-gap-recovery",
        [/terminalizes the DB-admitted\/Worker-unprepared run through Worker cancellation/i,
          /releases a rollback busy marker when the API died before Worker prepare/i],
      ],
      [
        "worker-broker-mount-release-handshake",
        [/keeps candidate and verifier bytes intact across restart until ALL teardown is recorded/i,
          /quiesces a Broker orphan before restart recovery destroys candidate bytes/i],
      ],
      [
        "broker-orphan-reconciliation-fail-closed",
        [/rediscovers and force-removes a labeled orphan before attesting mount release/i,
          /fails closed when a bound orphan survives force removal/i],
      ],
      [
        "broker-durable-lifecycle-tombstone",
        [
          /rejects closure for a binding that never launched/i,
          /permits only the monotonic Agent -> Verifier -> closed sequence/i,
          /persists tombstones across Broker instances and rejects cross-binding reuse/i,
        ],
      ],
      [
        "receipt-proof-projection-bounded",
        [/keeps 21 compact receipts below the RPC cap and rebuilds one full v3 chain/i],
      ],
    ],
  },
};

if (!Object.hasOwn(suites, suiteId)) {
  console.error("Usage: node scripts/eval-suite.mjs protocol|adversarial|recovery");
  process.exit(2);
}

const suite = suites[suiteId];
const evidenceDirectory = path.join(root, "eval", "evidence");
const rawPath = path.join(evidenceDirectory, `${suiteId}-vitest.json`);
const reportPath = path.join(root, "eval", `${suiteId}-report.json`);
await mkdir(evidenceDirectory, { recursive: true });

const args = [
  "run",
  "test",
  "-w",
  "@launchpad/server",
  "--",
  ...suite.files,
  "--reporter=json",
  `--outputFile=${rawPath}`,
];
const started = Date.now();
const result = spawnSync("npm", args, {
  cwd: root,
  env: process.env,
  encoding: "utf8",
  maxBuffer: 32 * 1024 * 1024,
});
if (result.stdout) process.stdout.write(result.stdout);
if (result.stderr) process.stderr.write(result.stderr);

let raw = null;
let parseError = null;
try {
  raw = JSON.parse(await readFile(rawPath, "utf8"));
} catch (error) {
  parseError = error instanceof Error ? error.message : String(error);
}
const assertions = (raw?.testResults ?? []).flatMap((testFile) =>
  (testFile.assertionResults ?? []).map((assertion) => ({
    name: assertion.fullName || assertion.title || "",
    status:
      assertion.status === "failed" &&
      (assertion.failureMessages ?? []).some((message) =>
        /listen EPERM: operation not permitted .*worker\.sock/i.test(message),
      )
        ? "unverified"
        : assertion.status,
    file: testFile.name ?? null,
    failureMessages: assertion.failureMessages ?? [],
  })),
);

function evaluateClaim([id, patterns]) {
  const groups = patterns.map((pattern) => assertions.filter((item) => pattern.test(item.name)));
  const matching = [...new Map(groups.flat().map((item) => [`${item.file}:${item.name}`, item])).values()];
  const failedGroup = groups.find((group) => group.some((item) => item.status === "failed"));
  const missingGroup = groups.find((group) => !group.some((item) => item.status === "passed"));
  return {
    id,
    status: failedGroup ? "failed" : missingGroup ? "unverified" : "verified",
    evidence: matching.map((item) => ({ test: item.name, status: item.status, file: item.file })),
  };
}

const claims = suite.claims.map(evaluateClaim);
const failedAssertions = assertions.filter((item) => item.status === "failed");
const environmentBlockedAssertions = assertions.filter((item) => item.status === "unverified");
const commandStatus = result.status === 0 && raw?.success !== false && !parseError
  ? "verified"
  : !parseError && failedAssertions.length === 0 && environmentBlockedAssertions.length > 0
    ? "unverified"
    : "failed";
const status = commandStatus === "failed" || claims.some((claim) => claim.status === "failed")
  ? "failed"
  : claims.some((claim) => claim.status === "unverified")
    ? "unverified"
    : "verified";
const source = await evidenceProvenance(root);
const identity = executionIdentity(root);
const evaluationRecords = claims.map((claim) => assertEvaluationRecord(evaluationRecord({
  source,
  provider: identity.provider,
  executionIdentity: identity,
  surface: suiteId,
  scenario: { id: claim.id, status: claim.status },
})));
const report = {
  schemaVersion: 2,
  kind: suite.kind,
  generatedAt: new Date().toISOString(),
  status,
  source,
  executionIdentity: identity,
  durationMs: Date.now() - started,
  command: {
    executable: "npm",
    arguments: args,
    exitCode: result.status,
    status: commandStatus,
  },
  tests: {
    files: raw?.testResults?.length ?? null,
    total: raw?.numTotalTests ?? assertions.length,
    passed: raw?.numPassedTests ?? assertions.filter((item) => item.status === "passed").length,
    failed: raw?.numFailedTests ?? assertions.filter((item) => item.status === "failed").length,
  },
  claims,
  evaluationRecords,
  parseError,
  evidenceFiles: [path.relative(root, rawPath)],
  claimBoundary:
    "Only named passing tests count as verified. Missing mechanical evidence is unverified; a matching failing test or failed command is failed.",
};
await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");
for (const claim of claims) {
  console.log(`${claim.status.padEnd(10)} ${claim.id}`);
}
console.log(`${status}: ${suiteId} report: ${reportPath}`);
process.exitCode = status === "verified" ? 0 : status === "unverified" ? 2 : 1;
