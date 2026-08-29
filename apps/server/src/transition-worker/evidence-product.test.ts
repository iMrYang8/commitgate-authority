import { chmod, mkdir, rm, writeFile } from "node:fs/promises";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  computeEvaluationContextHash,
  sha256Canonical,
} from "../commitgate/protocol.js";
import type { EvaluationContext } from "../commitgate/types.js";
import { buildWorkerManifest, makeTreeWritable } from "./filesystem.js";
import { TransitionWorker, type TransitionWorkerConfig } from "./worker.js";
import {
  WORKER_CHECK_SPEC_HASH,
  WORKER_GATE_POLICY_HASH,
  WORKER_MANIFEST_SCHEMA_VERSION,
} from "../worker-gate-policy.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map(async (root) => {
      await makeTreeWritable(root).catch(() => undefined);
      await rm(root, { recursive: true, force: true });
    }),
  );
});

async function recordedProductEvidence() {
  const root = await mkdtemp(path.join(tmpdir(), "commitgate-worker-evidence-product-"));
  roots.push(root);
  const config: TransitionWorkerConfig = {
    workspaceRoot: path.join(root, "workspaces"),
    controlRoot: path.join(root, "control"),
    inboxRoot: path.join(root, "exchange"),
    socketPath: path.join(root, "run", "worker.sock"),
    sourceRevision: "evidence-product-test",
  };
  const worker = new TransitionWorker(config);
  await worker.initialize();
  const initialized = await worker.initializeAgent({
    agentId: "agent-evidence",
    operationId: "init-evidence",
    headVersionId: "initial-evidence",
    generation: 1,
    sessionEpoch: 0,
    agentConfigVersion: 1,
    policyVersion: 1,
    name: "Evidence Agent",
    instructions: "# trusted\n",
  });
  const prepared = await worker.prepareRun({
    agentId: "agent-evidence",
    transitionId: "run-evidence",
    runId: "run-evidence",
    runLeaseId: "lease-evidence",
    candidateVolumeId: "candidate-run-evidence",
    expectedViewId: initialized.head!.view.viewId,
    expectedWorkspaceHash: initialized.head!.workspaceHash,
    baseGeneration: 1,
  });
  const candidate = path.join(config.inboxRoot, prepared.relativeSubpath);
  await writeFile(path.join(candidate, "feature.ts"), "export const evidence = true;\n");
  const artifactHash = (await buildWorkerManifest(candidate)).hash;
  await worker.sealProposal({
    agentId: "agent-evidence",
    transitionId: "run-evidence",
    proposalId: "proposal-evidence",
    sourceVolumeId: "candidate-run-evidence",
    baseViewId: initialized.head!.view.viewId,
    expectedArtifactHash: artifactHash,
    runtimeTeardownDigest: "8".repeat(64),
  });
  const evaluationContext: EvaluationContext = {
    schemaVersion: 1,
    runId: "run-evidence",
    agentId: "agent-evidence",
    proposalId: "proposal-evidence",
    baseView: initialized.head!.view,
    manifestSchemaVersion: WORKER_MANIFEST_SCHEMA_VERSION,
    policyHash: WORKER_GATE_POLICY_HASH,
    checkBundleHash: "2".repeat(64),
    checkSpecHash: WORKER_CHECK_SPEC_HASH,
    verifierImageDigest: `sha256:${"4".repeat(64)}`,
    verifierConfigHash: "5".repeat(64),
    resourcePolicyHash: "6".repeat(64),
    sourceRevision: "evidence-product-test",
  };
  const checks = [{
    id: "workspace-sanity",
    status: "PASS" as const,
    exitCode: 0,
    durationMs: 4,
    outputHash: "7".repeat(64),
    timedOut: false,
  }];
  const evaluationContextHash = computeEvaluationContextHash(evaluationContext);
  const checkResultsHash = sha256Canonical(checks);
  const evidenceDigest = sha256Canonical({
    schemaVersion: 1,
    proposalId: "proposal-evidence",
    artifactHash,
    evaluationContextHash,
    checkResultsHash,
  });
  await worker.recordEvidence({
    agentId: "agent-evidence",
    transitionId: "run-evidence",
    proposalId: "proposal-evidence",
    evaluationContextHash,
    evidenceDigest,
    evaluationContext,
    verifierInputHash: artifactHash,
    checkResultsHash,
    coverage: "complete",
    requiredChecksPassed: true,
    checks,
  });
  const permitInput = {
    agentId: "agent-evidence",
    transitionId: "run-evidence",
    permitId: "permit-evidence",
    proposalId: "proposal-evidence",
    baseViewId: initialized.head!.view.viewId,
    targetArtifactHash: artifactHash,
    evaluationContextHash,
    evidenceDigest,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  } as const;
  return {
    config,
    worker,
    initialized,
    evaluationContext,
    checks,
    permitInput,
  };
}

describe("TransitionWorker evidence blob product integration", () => {
  it("keeps complete evidence out of the event log and rebuilds its blob reference", async () => {
    const {
      config,
      worker,
      evaluationContext,
      checks,
      permitInput,
    } = await recordedProductEvidence();
    const evidenceEvent = (await worker.log.transition("agent-evidence", "run-evidence"))
      .find((event) => event.type === "EVIDENCE_RECORDED")!;
    expect(evidenceEvent.payload).toMatchObject({
      schemaVersion: 2,
      proposalId: "proposal-evidence",
      checkCount: 1,
      sourceRevision: "evidence-product-test",
      policyHash: evaluationContext.policyHash,
    });
    expect(evidenceEvent.payload).not.toHaveProperty("evaluationContext");
    expect(evidenceEvent.payload).not.toHaveProperty("checks");

    const projection = await worker.projection("agent-evidence");
    const projected = projection.evidence["proposal-evidence"]!;
    expect(projected.evidenceBlob).toMatchObject({ schemaVersion: 1 });
    expect(projected.checkCount).toBe(1);
    expect(projected.checks).toEqual(checks);
    const stored = await worker.evidenceBlobs.get<Record<string, unknown>>(
      projected.evidenceBlob!.blobId,
    );
    expect(stored).toMatchObject({
      schemaVersion: 2,
      evaluationContext,
      checks,
      requiredChecksPassed: true,
    });

    await rm(path.join(config.controlRoot, "heads", "agent-evidence.json"));
    // Rebuild the disposable projection marker while the run lease remains
    // live. A real process restart intentionally aborts an orphaned EVIDENCED
    // transition, so it must not be used as a shortcut to resume issuance.
    const rebuilt = await worker.rebuildProjection("agent-evidence");
    expect(rebuilt.evidence["proposal-evidence"]?.evidenceBlob).toEqual(
      projected.evidenceBlob,
    );
    expect(rebuilt.evidence["proposal-evidence"]?.checks).toEqual(checks);
    expect(rebuilt.evidence["proposal-evidence"]?.sourceRevision)
      .toBe("evidence-product-test");
    expect(rebuilt.evidence["proposal-evidence"]?.policyHash)
      .toBe(evaluationContext.policyHash);
    await expect(worker.issuePermit(permitInput)).resolves.toMatchObject({
      permits: { "permit-evidence": { state: "ISSUED" } },
    });
  });

  it("fails permit issuance closed when the evidence blob is missing", async () => {
    const { worker, permitInput } = await recordedProductEvidence();
    const projected = (await worker.projection("agent-evidence"))
      .evidence["proposal-evidence"]!;
    await rm(path.join(
      worker.evidenceBlobs.directory,
      `${projected.evidenceBlob!.blobId}.json`,
    ));
    await expect(worker.issuePermit(permitInput)).rejects.toMatchObject({
      code: "EVIDENCE_BLOB_INVALID",
    });
    expect(
      (await worker.log.transition("agent-evidence", "run-evidence"))
        .some((event) => event.type === "PERMIT_ISSUED"),
    ).toBe(false);
  });

  it("fails permit issuance closed when the evidence blob is modified", async () => {
    const { worker, permitInput } = await recordedProductEvidence();
    const projected = (await worker.projection("agent-evidence"))
      .evidence["proposal-evidence"]!;
    const blobPath = path.join(
      worker.evidenceBlobs.directory,
      `${projected.evidenceBlob!.blobId}.json`,
    );
    await chmod(blobPath, 0o600);
    await writeFile(blobPath, '{"tampered":true}', { mode: 0o600 });
    await expect(worker.issuePermit(permitInput)).rejects.toMatchObject({
      code: "EVIDENCE_BLOB_INVALID",
    });
    expect(
      (await worker.log.transition("agent-evidence", "run-evidence"))
        .some((event) => event.type === "PERMIT_ISSUED"),
    ).toBe(false);
  });

  it("continues to rebuild legacy V1 inline evidence without treating it as a blob", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-worker-evidence-v1-"));
    roots.push(root);
    const config: TransitionWorkerConfig = {
      workspaceRoot: path.join(root, "workspaces"),
      controlRoot: path.join(root, "control"),
      inboxRoot: path.join(root, "exchange"),
      socketPath: path.join(root, "run", "worker.sock"),
    };
    const worker = new TransitionWorker(config);
    await worker.initialize();
    const legacyWorkspace = path.join(config.workspaceRoot, "legacy-agent");
    await mkdir(legacyWorkspace);
    const legacyWorkspaceHash = (await buildWorkerManifest(legacyWorkspace)).hash;
    await worker.prepare({
      agentId: "legacy-agent",
      transitionId: "legacy-transition",
      kind: "AGENT_COMMIT",
      expectedViewId: null,
      expectedWorkspaceHash: legacyWorkspaceHash,
      baseGeneration: 0,
    });
    await worker.log.append({
      agentId: "legacy-agent",
      transitionId: "legacy-transition",
      type: "PROPOSAL_SEALED",
      payload: {
        proposalId: "legacy-proposal",
        baseViewId: "8".repeat(64),
        artifactHash: "9".repeat(64),
      },
    });
    const inlineCheck = {
      id: "legacy-check",
      status: "PASS",
      exitCode: 0,
      durationMs: 1,
      outputHash: "a".repeat(64),
      timedOut: false,
    };
    await worker.log.append({
      agentId: "legacy-agent",
      transitionId: "legacy-transition",
      type: "EVIDENCE_RECORDED",
      payload: {
        proposalId: "legacy-proposal",
        evaluationContextHash: "b".repeat(64),
        evidenceDigest: "c".repeat(64),
        verifierInputHash: "9".repeat(64),
        checkResultsHash: "d".repeat(64),
        coverage: "complete",
        requiredChecksPassed: true,
        checks: [inlineCheck],
        evaluationContext: {
          sourceRevision: "legacy-revision",
          policyHash: "e".repeat(64),
        },
      },
    });
    const rebuilt = await worker.rebuildProjection("legacy-agent");
    expect(rebuilt.evidence["legacy-proposal"]).toMatchObject({
      evidenceBlob: null,
      checkCount: 1,
      checks: [inlineCheck],
      sourceRevision: "legacy-revision",
      policyHash: "e".repeat(64),
    });
  });
});
