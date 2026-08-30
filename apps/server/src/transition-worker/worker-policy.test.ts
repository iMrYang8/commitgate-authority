import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { computeEvaluationContextHash, sha256Canonical } from "../commitgate/protocol.js";
import type { EvaluationContext } from "../commitgate/types.js";
import {
  WORKER_MANIFEST_SCHEMA_VERSION,
  resolveWorkerGateContract,
} from "../worker-gate-policy.js";
import { buildWorkerManifest, makeTreeWritable } from "./filesystem.js";
import { TransitionWorker, type TransitionWorkerConfig } from "./worker.js";

const roots: string[] = [];
const SOURCE_REVISION = "a".repeat(40);
const DEPLOYMENT_CONTRACT = resolveWorkerGateContract("deployment-protected");

afterEach(async () => {
  await Promise.all(roots.splice(0).map(async (root) => {
    await makeTreeWritable(root).catch(() => undefined);
    await rm(root, { recursive: true, force: true });
  }));
});

type RecordedCheck = {
  id: string;
  status: "PASS" | "FAIL" | "ERROR" | "SKIPPED";
  exitCode: number | null;
  durationMs: number;
  outputHash: string;
  timedOut: boolean;
};

async function productEvidenceFixture(input: {
  protectedMutation?: boolean;
  context?: Partial<EvaluationContext>;
  checks?: RecordedCheck[];
  requireVerifiedSourceRevision?: boolean;
}) {
  const root = await mkdtemp(path.join(tmpdir(), "commitgate-worker-policy-"));
  roots.push(root);
  const config: TransitionWorkerConfig = {
    workspaceRoot: path.join(root, "workspaces"),
    controlRoot: path.join(root, "control"),
    inboxRoot: path.join(root, "exchange"),
    socketPath: path.join(root, "run", "worker.sock"),
    sourceRevision: SOURCE_REVISION,
    requireVerifiedSourceRevision: input.requireVerifiedSourceRevision ?? true,
    expectedCheckBundleHash: "b".repeat(64),
    expectedVerifierImageDigest: `sha256:${"c".repeat(64)}`,
    expectedVerifierConfigHash: "d".repeat(64),
    expectedResourcePolicyHash: "e".repeat(64),
    policyProfile: "deployment-protected",
  };
  const worker = new TransitionWorker(config);
  await worker.initialize();
  const initialized = await worker.initializeAgent({
    agentId: "agent-policy",
    operationId: "init-policy",
    headVersionId: "initial-policy",
    generation: 1,
    sessionEpoch: 0,
    agentConfigVersion: 1,
    policyVersion: 1,
    name: "Policy Agent",
    instructions: "# trusted\n",
  });
  const prepared = await worker.prepareRun({
    agentId: "agent-policy",
    transitionId: "run-policy",
    runId: "run-policy",
    runLeaseId: "lease-policy",
    candidateVolumeId: "candidate-run-policy",
    expectedViewId: initialized.head!.view.viewId,
    expectedWorkspaceHash: initialized.head!.workspaceHash,
    baseGeneration: 1,
  });
  const candidate = path.join(config.inboxRoot, prepared.relativeSubpath);
  if (input.protectedMutation) {
    await mkdir(path.join(candidate, "infra"), { recursive: true });
    await writeFile(path.join(candidate, "infra", "production.yaml"), "replicas: 0\n");
  } else {
    await writeFile(path.join(candidate, "feature.ts"), "export const ok = true;\n");
  }
  const artifactHash = (await buildWorkerManifest(candidate)).hash;
  await worker.sealProposal({
    agentId: "agent-policy",
    transitionId: "run-policy",
    proposalId: "proposal-policy",
    sourceVolumeId: "candidate-run-policy",
    baseViewId: initialized.head!.view.viewId,
    expectedArtifactHash: artifactHash,
    runtimeTeardownDigest: "9".repeat(64),
  });
  const context: EvaluationContext = {
    schemaVersion: 1,
    runId: "run-policy",
    agentId: "agent-policy",
    proposalId: "proposal-policy",
    baseView: initialized.head!.view,
    manifestSchemaVersion: WORKER_MANIFEST_SCHEMA_VERSION,
    policyHash: DEPLOYMENT_CONTRACT.policyHash,
    checkBundleHash: "b".repeat(64),
    checkSpecHash: DEPLOYMENT_CONTRACT.checkSpecHash,
    verifierImageDigest: `sha256:${"c".repeat(64)}`,
    verifierConfigHash: "d".repeat(64),
    resourcePolicyHash: "e".repeat(64),
    sourceRevision: SOURCE_REVISION,
    ...input.context,
  };
  const checks = input.checks ?? [{
    id: "workspace-sanity",
    status: "PASS" as const,
    exitCode: 0,
    durationMs: 1,
    outputHash: createHash("sha256").update("pass").digest("hex"),
    timedOut: false,
  }];
  const evaluationContextHash = computeEvaluationContextHash(context);
  const checkResultsHash = sha256Canonical(checks);
  const evidenceDigest = sha256Canonical({
    schemaVersion: 1,
    proposalId: "proposal-policy",
    artifactHash,
    evaluationContextHash,
    checkResultsHash,
  });
  const independentlyPassed = checks.length > 0 && checks.every(
    (check) => check.status === "PASS" && check.exitCode === 0 && !check.timedOut,
  );
  await worker.recordEvidence({
    agentId: "agent-policy",
    transitionId: "run-policy",
    proposalId: "proposal-policy",
    evaluationContextHash,
    evidenceDigest,
    evaluationContext: context,
    verifierInputHash: artifactHash,
    checkResultsHash,
    coverage: "complete",
    requiredChecksPassed: independentlyPassed,
    checks,
  });
  return {
    worker,
    permit: {
      agentId: "agent-policy",
      transitionId: "run-policy",
      permitId: "permit-policy",
      proposalId: "proposal-policy",
      baseViewId: initialized.head!.view.viewId,
      targetArtifactHash: artifactHash,
      evaluationContextHash,
      evidenceDigest,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    },
  };
}

describe("TransitionWorker-owned authorization contract", () => {
  it("disables the legacy unleased Agent-commit admission method in production", async () => {
    const { worker } = await productEvidenceFixture({});
    const projection = await worker.projection("agent-policy");
    await expect(worker.prepare({
      agentId: "agent-policy",
      transitionId: "legacy-bypass",
      kind: "AGENT_COMMIT",
      expectedViewId: projection.head!.view.viewId,
      expectedWorkspaceHash: projection.head!.workspaceHash,
      baseGeneration: projection.head!.view.generation,
    })).rejects.toMatchObject({ code: "PRODUCT_PREPARE_RUN_REQUIRED" });
  });

  it("rejects a protected proposal even when the caller submits self-consistent PASS evidence", async () => {
    const { worker, permit } = await productEvidenceFixture({ protectedMutation: true });
    await expect(worker.issuePermit(permit)).rejects.toMatchObject({
      code: "PROPOSAL_POLICY_VIOLATION",
    });
    expect((await worker.projection("agent-policy")).permits).toEqual({});
  });

  it.each([
    ["missing", [], "EVIDENCE_INCOMPLETE"],
    ["extra", ["workspace-sanity", "caller-added"], "TRUSTED_CHECK_SET_MISMATCH"],
    ["wrong", ["caller-selected"], "TRUSTED_CHECK_SET_MISMATCH"],
  ] as const)("rejects a %s trusted-check set", async (_label, ids, code) => {
    const checks = ids.map((id) => ({
      id,
      status: "PASS" as const,
      exitCode: 0,
      durationMs: 1,
      outputHash: createHash("sha256").update(id).digest("hex"),
      timedOut: false,
    }));
    const { worker, permit } = await productEvidenceFixture({ checks });
    await expect(worker.issuePermit(permit)).rejects.toMatchObject({ code });
  });

  it.each([
    ["policy", { policyHash: "f".repeat(64) }, "POLICY_HASH_MISMATCH"],
    ["check specification", { checkSpecHash: "f".repeat(64) }, "CHECK_SPEC_HASH_MISMATCH"],
    ["manifest schema", { manifestSchemaVersion: 1 }, "MANIFEST_SCHEMA_MISMATCH"],
  ] as const)("rejects a caller-selected %s", async (_label, context, code) => {
    const { worker, permit } = await productEvidenceFixture({ context });
    await expect(worker.issuePermit(permit)).rejects.toMatchObject({ code });
  });

  it("rechecks source revision at permit issuance even without the production record-time fence", async () => {
    const { worker, permit } = await productEvidenceFixture({
      context: { sourceRevision: "b".repeat(40) },
      requireVerifiedSourceRevision: false,
    });
    await expect(worker.issuePermit(permit)).rejects.toMatchObject({
      code: "SOURCE_REVISION_MISMATCH",
    });
  });

  it.each([
    ["trusted-check bundle", { checkBundleHash: "f".repeat(64) }, "CHECK_BUNDLE_HASH_MISMATCH"],
    ["Verifier image", { verifierImageDigest: `sha256:${"f".repeat(64)}` }, "VERIFIER_IMAGE_DIGEST_MISMATCH"],
    ["Verifier config", { verifierConfigHash: "f".repeat(64) }, "VERIFIER_CONFIG_HASH_MISMATCH"],
    ["resource policy", { resourcePolicyHash: "f".repeat(64) }, "RESOURCE_POLICY_HASH_MISMATCH"],
  ] as const)("rejects an unpinned %s", async (_label, context, code) => {
    const { worker, permit } = await productEvidenceFixture({ context });
    await expect(worker.issuePermit(permit)).rejects.toMatchObject({ code });
  });
});
