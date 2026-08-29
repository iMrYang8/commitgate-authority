import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { mkdtemp } from "node:fs/promises";
import { afterEach, describe, expect, it } from "vitest";
import { makeStateView } from "../state-view.js";
import { computeEvaluationContextHash, sha256Canonical } from "../commitgate/protocol.js";
import type { EvaluationContext } from "../commitgate/types.js";
import { verifyAuthorityReceiptProof } from "../research/receipt-proof.js";
import {
  buildWorkerManifest,
  copyClosedTree,
  makeTreeReadonly,
  makeTreeWritable,
} from "./filesystem.js";
import {
  deriveWorkerStateHashes,
  inspectProposalDiff,
  loadTransitionWorkerConfig,
  TransitionWorker,
  type TransitionWorkerConfig,
} from "./worker.js";
import { WorkerSigningKeyStore } from "./signing-key-store.js";
import {
  WORKER_CHECK_SPEC_HASH,
  WORKER_GATE_POLICY_HASH,
  WORKER_MANIFEST_SCHEMA_VERSION,
} from "../worker-gate-policy.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map(async (root) => {
    await makeTreeWritable(root).catch(() => undefined);
    await rm(root, { recursive: true, force: true });
  }));
});

async function fixture() {
  const root = await mkdtemp(path.join(tmpdir(), "commitgate-worker-"));
  roots.push(root);
  const config: TransitionWorkerConfig = {
    workspaceRoot: path.join(root, "workspaces"),
    controlRoot: path.join(root, "control"),
    inboxRoot: path.join(root, "inbox"),
    socketPath: path.join(root, "run", "worker.sock"),
  };
  const worker = new TransitionWorker(config);
  await worker.initialize();
  const workspace = path.join(config.workspaceRoot, "agent-a");
  await mkdir(workspace);
  await writeFile(path.join(workspace, "value.txt"), "base\n");
  const baseManifest = await buildWorkerManifest(workspace);
  const baseHash = baseManifest.hash;
  const baseView = makeStateView({
    agentId: "agent-a",
    headVersionId: "initial",
    generation: 0,
    ...deriveWorkerStateHashes(baseManifest),
    sessionEpoch: 0,
    agentConfigVersion: 1,
    policyVersion: 1,
  });
  await worker.log.append({
    agentId: "agent-a",
    transitionId: "fixture-head",
    type: "PLATFORM_STATE_REGENERATED",
    payload: { view: baseView, workspaceHash: baseHash },
  });
  return { root, config, worker, workspace, baseHash, baseView };
}

function passingEvidence(input: {
  runId: string;
  agentId: string;
  proposalId: string;
  baseView: EvaluationContext["baseView"];
  artifactHash: string;
  sourceRevision: string;
}) {
  const evaluationContext: EvaluationContext = {
    schemaVersion: 1,
    runId: input.runId,
    agentId: input.agentId,
    proposalId: input.proposalId,
    baseView: input.baseView,
    manifestSchemaVersion: WORKER_MANIFEST_SCHEMA_VERSION,
    policyHash: WORKER_GATE_POLICY_HASH,
    checkBundleHash: "1".repeat(64),
    checkSpecHash: WORKER_CHECK_SPEC_HASH,
    verifierImageDigest: `sha256:${"2".repeat(64)}`,
    verifierConfigHash: "3".repeat(64),
    resourcePolicyHash: "4".repeat(64),
    sourceRevision: input.sourceRevision,
  };
  const checks = [{
    id: "workspace-sanity",
    status: "PASS" as const,
    exitCode: 0,
    durationMs: 1,
    outputHash: "5".repeat(64),
    timedOut: false,
  }];
  const evaluationContextHash = computeEvaluationContextHash(evaluationContext);
  const checkResultsHash = sha256Canonical(checks);
  const evidenceDigest = sha256Canonical({
    schemaVersion: 1,
    proposalId: input.proposalId,
    artifactHash: input.artifactHash,
    evaluationContextHash,
    checkResultsHash,
  });
  return {
    evaluationContext,
    evaluationContextHash,
    verifierInputHash: input.artifactHash,
    checkResultsHash,
    coverage: "complete" as const,
    requiredChecksPassed: true,
    checks,
    evidenceDigest,
  };
}

describe("TransitionWorker", () => {
  it("charges add, modify and delete budgets by affected files and max(before, after) bytes", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-worker-diff-budget-"));
    roots.push(root);
    const base = path.join(root, "base");
    const candidate = path.join(root, "candidate");
    const empty = path.join(root, "empty");
    await mkdir(base);
    await mkdir(candidate);
    await mkdir(empty);
    const oversized = Buffer.alloc(1_048_577, 0x61);
    await writeFile(path.join(base, "large.bin"), oversized);

    const deleted = inspectProposalDiff(
      await buildWorkerManifest(base),
      await buildWorkerManifest(candidate),
    );
    expect(deleted.changedPaths).toEqual(["large.bin"]);
    expect(deleted.staticFailures).toContain("SINGLE_FILE_BUDGET_EXCEEDED:large.bin");
    expect(deleted.staticFailures).toContain("CHANGED_BYTE_BUDGET_EXCEEDED");

    await writeFile(path.join(candidate, "large.bin"), "x");
    const shrunk = inspectProposalDiff(
      await buildWorkerManifest(base),
      await buildWorkerManifest(candidate),
    );
    expect(shrunk.staticFailures).toContain("SINGLE_FILE_BUDGET_EXCEEDED:large.bin");
    expect(shrunk.staticFailures).toContain("CHANGED_BYTE_BUDGET_EXCEEDED");

    await rm(path.join(candidate, "large.bin"));
    for (let index = 0; index < 101; index += 1) {
      await mkdir(path.join(candidate, `dir-${index}`));
    }
    const directoriesOnly = inspectProposalDiff(
      await buildWorkerManifest(empty),
      await buildWorkerManifest(candidate),
    );
    expect(directoriesOnly.staticFailures).not.toContain("CHANGED_FILE_BUDGET_EXCEEDED");
    for (let index = 0; index < 101; index += 1) {
      await writeFile(path.join(candidate, `file-${index}`), "");
    }
    const addedFiles = inspectProposalDiff(
      await buildWorkerManifest(empty),
      await buildWorkerManifest(candidate),
    );
    expect(addedFiles.staticFailures).toContain("CHANGED_FILE_BUDGET_EXCEEDED");
  });
  it("uses fixed roots and rejects nested authority mounts", () => {
    const configured = loadTransitionWorkerConfig({});
    expect(configured).toMatchObject({
      workspaceRoot: "/var/lib/commitgate/workspaces",
      controlRoot: "/var/lib/commitgate/control",
      inboxRoot: "/var/lib/commitgate/inbox",
      socketPath: "/run/commitgate/transition-worker.sock",
    });
    expect(() => loadTransitionWorkerConfig({
      TRANSITION_WORKER_WORKSPACE_ROOT: "/authority",
      TRANSITION_WORKER_CONTROL_ROOT: "/authority/control",
      TRANSITION_WORKER_INBOX_ROOT: "/inbox",
    })).toThrow("must not contain");
    expect(() => loadTransitionWorkerConfig({
      NODE_ENV: "production",
      COMMITGATE_SOURCE_REVISION: "unverified",
    })).toThrow(/40-hex COMMITGATE_SOURCE_REVISION/);
    expect(() => loadTransitionWorkerConfig({
      NODE_ENV: "production",
      COMMITGATE_SOURCE_REVISION: "a".repeat(40),
      BROKER_ATTESTATION_KEY: "k".repeat(32),
    })).toThrow(/pinned trusted bundle/);
    expect(loadTransitionWorkerConfig({
      NODE_ENV: "production",
      COMMITGATE_SOURCE_REVISION: "a".repeat(40),
      BROKER_ATTESTATION_KEY: "k".repeat(32),
      COMMITGATE_EXPECTED_CHECK_BUNDLE_HASH: "b".repeat(64),
      COMMITGATE_EXPECTED_VERIFIER_IMAGE_DIGEST: "sha256:" + "c".repeat(64),
      COMMITGATE_EXPECTED_VERIFIER_CONFIG_HASH: "d".repeat(64),
      COMMITGATE_EXPECTED_RESOURCE_POLICY_HASH: "e".repeat(64),
    })).toMatchObject({
      sourceRevision: "a".repeat(40),
      requireVerifiedSourceRevision: true,
      requireRuntimeTeardownHandshake: true,
    });
  });

  it("initializes, materializes and disposes an Agent through opaque volume IDs", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-worker-product-"));
    roots.push(root);
    const config: TransitionWorkerConfig = {
      workspaceRoot: path.join(root, "workspaces"),
      controlRoot: path.join(root, "control"),
      inboxRoot: path.join(root, "inbox"),
      socketPath: path.join(root, "run", "worker.sock"),
    };
    const worker = new TransitionWorker(config);
    await worker.initialize();
    expect(worker.health().signingKeyId).toMatch(/^[a-f0-9]{24}$/);
    const initialized = await worker.initializeAgent({
      agentId: "agent-product",
      operationId: "init-1",
      headVersionId: "initial-1",
      generation: 1,
      sessionEpoch: 0,
      agentConfigVersion: 1,
      policyVersion: 1,
      name: "Product Agent",
      instructions: "# Trusted instructions\n",
    });
    expect(initialized.head?.view.generation).toBe(1);
    expect(initialized.versions[0]?.kind).toBe("INITIAL");
    const initializedManifest = await buildWorkerManifest(
      path.join(config.workspaceRoot, "agent-product"),
    );
    expect(initialized.head?.view).toMatchObject(
      deriveWorkerStateHashes(initializedManifest),
    );
    for (const [operationId, metadata] of [
      ["forged-session", { sessionEpoch: 0, agentConfigVersion: 2, policyVersion: 1 }],
      ["forged-config", { sessionEpoch: 1, agentConfigVersion: 3, policyVersion: 1 }],
      ["forged-policy", { sessionEpoch: 1, agentConfigVersion: 2, policyVersion: 2 }],
    ] as const) {
      await expect(worker.regeneratePlatformState({
        agentId: "agent-product",
        operationId,
        expectedViewId: initialized.head!.view.viewId,
        expectedWorkspaceHash: initialized.head!.workspaceHash,
        instructions: "# forged metadata must not apply\n",
        ...metadata,
      })).rejects.toMatchObject({ code: "PLATFORM_STATE_METADATA_INVALID" });
      expect((await worker.projection("agent-product")).head).toEqual(initialized.head);
    }
    const prepared = await worker.prepareRun({
      agentId: "agent-product",
      transitionId: "run-1",
      runId: "run-1",
      runLeaseId: "lease-run-1",
      candidateVolumeId: "candidate-run-1",
      expectedViewId: initialized.head!.view.viewId,
      expectedWorkspaceHash: initialized.head!.workspaceHash,
      baseGeneration: 1,
    });
    expect(prepared.relativeSubpath).toBe("candidate-run-1");
    expect(
      (await buildWorkerManifest(path.join(config.inboxRoot, prepared.relativeSubpath))).hash,
    ).toBe(initialized.head?.workspaceHash);

    const { schemaVersion: _schemaVersion, viewId: _viewId, ...baseViewInput } =
      initialized.head!.view;
    const rejectedView = makeStateView({
      ...baseViewInput,
      sessionEpoch: 1,
    });
    const disposed = await worker.disposeRun({
      agentId: "agent-product",
      transitionId: "run-1",
      receiptId: "receipt-rejected-1",
      decision: "QUARANTINED",
      finalView: rejectedView,
      reasonCodes: ["PROTECTED_PATH_CHANGED"],
    });
    expect(disposed.head?.view.sessionEpoch).toBe(1);
    expect(disposed.head?.view.generation).toBe(1);
    expect(disposed.terminalReceipts.at(-1)?.decision).toBe("QUARANTINED");
    expect(disposed.transitions["run-1"]?.artifactsDestroyed).toBe(true);
    await expect(
      readFile(path.join(config.inboxRoot, "candidate-run-1", "AGENTS.md"), "utf8"),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("recovers a durable cancellation into one ABORTED receipt and an idempotent fresh View", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-worker-cancel-recovery-"));
    roots.push(root);
    const config: TransitionWorkerConfig = {
      workspaceRoot: path.join(root, "workspaces"),
      controlRoot: path.join(root, "control"),
      inboxRoot: path.join(root, "inbox"),
      socketPath: path.join(root, "run", "worker.sock"),
      sourceRevision: "cancel-recovery-revision",
    };
    const worker = new TransitionWorker(config);
    await worker.initialize();
    const initialized = await worker.initializeAgent({
      agentId: "agent-cancel",
      operationId: "init-cancel",
      headVersionId: "initial-cancel",
      generation: 4,
      sessionEpoch: 2,
      agentConfigVersion: 1,
      policyVersion: 1,
      name: "Cancelled Agent",
      instructions: "# trusted\n",
    });
    const prepared = await worker.prepareRun({
      agentId: "agent-cancel",
      transitionId: "run-cancel",
      runId: "run-cancel",
      runLeaseId: "lease-cancel",
      candidateVolumeId: "candidate-run-cancel",
      expectedViewId: initialized.head!.view.viewId,
      expectedWorkspaceHash: initialized.head!.workspaceHash,
      baseGeneration: 4,
    });
    await writeFile(
      path.join(config.inboxRoot, prepared.relativeSubpath, "late.txt"),
      "must never persist\n",
    );
    await worker.cancelRun({
      agentId: "agent-cancel",
      transitionId: "run-cancel",
      runId: "run-cancel",
      runLeaseId: "lease-cancel",
      expectedViewId: initialized.head!.view.viewId,
    });
    expect((await worker.projection("agent-cancel")).terminalReceipts).toHaveLength(0);

    // Simulate an API/Worker process boundary after RUN_CANCELLED but before
    // AgentService can call finalizeDisposition.
    const restarted = new TransitionWorker(config);
    await restarted.initialize();
    const recovered = await restarted.projection("agent-cancel");
    const receipt = recovered.terminalReceipts.find(
      (entry) => entry.receiptId === "run-cancel",
    );
    expect(receipt).toMatchObject({ decision: "ABORTED" });
    expect(receipt?.reasonCodes).toContain("RUN_CANCELLED_RECOVERED");
    expect(receipt?.view.generation).toBe(4);
    expect(receipt?.view.sessionEpoch).toBe(3);
    expect(receipt?.workspaceHash).toBe(initialized.head?.workspaceHash);
    expect(recovered.head?.workspaceHash).toBe(initialized.head?.workspaceHash);
    expect(recovered.versions).toHaveLength(1);
    expect(recovered.receiptProofs["run-cancel"]).toBeDefined();
    expect(recovered.receiptProofs["run-cancel"]!.bundle).toMatchObject({
      schemaVersion: 2,
    });
    expect(recovered.receiptProofs["run-cancel"]!.bundle).not.toHaveProperty("eventChain");
    expect(
      verifyAuthorityReceiptProof(await restarted.getReceiptProof("agent-cancel", "run-cancel")),
    ).toEqual({ valid: true, reason: null });
    expect(
      await buildWorkerManifest(path.join(config.workspaceRoot, "agent-cancel")),
    ).toMatchObject({ hash: initialized.head?.workspaceHash });
    await expect(
      readFile(path.join(config.inboxRoot, "candidate-run-cancel", "late.txt"), "utf8"),
    ).rejects.toMatchObject({ code: "ENOENT" });

    const beforeEvents = await restarted.log.transition("agent-cancel", "run-cancel");
    const finalized = await restarted.disposeRun({
      agentId: "agent-cancel",
      transitionId: "run-cancel",
      receiptId: "run-cancel",
      decision: "ABORTED",
      finalView: receipt!.view,
      reasonCodes: ["RUN_CANCELLED"],
    });
    const afterEvents = await restarted.log.transition("agent-cancel", "run-cancel");
    expect(afterEvents).toHaveLength(beforeEvents.length);
    expect(finalized.terminalReceipts.filter((entry) => entry.receiptId === "run-cancel"))
      .toHaveLength(1);
    expect(finalized.head?.view.viewId).toBe(receipt?.viewId);
  });

  it("adopts legacy state once and fails closed on conflicting replay", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-worker-legacy-"));
    roots.push(root);
    const config: TransitionWorkerConfig = {
      workspaceRoot: path.join(root, "workspaces"),
      controlRoot: path.join(root, "control"),
      inboxRoot: path.join(root, "inbox"),
      socketPath: path.join(root, "run", "worker.sock"),
    };
    const worker = new TransitionWorker(config);
    await worker.initialize();
    const legacy = path.join(config.inboxRoot, "legacy-agent");
    await mkdir(legacy);
    await writeFile(path.join(legacy, "value.txt"), "legacy\n");
    const manifest = await buildWorkerManifest(legacy);
    const view = makeStateView({
      agentId: "agent-legacy",
      headVersionId: "legacy-head",
      generation: 7,
      ...deriveWorkerStateHashes(manifest),
      sessionEpoch: 2,
      agentConfigVersion: 3,
      policyVersion: 1,
    });
    const adopted = await worker.adoptLegacyState({
      agentId: "agent-legacy",
      operationId: "adopt-1",
      sourceVolumeId: "legacy-agent",
      expectedWorkspaceHash: manifest.hash,
      adoptedView: view,
      versionId: "legacy-head",
    });
    expect(adopted.head?.view.viewId).toBe(view.viewId);
    expect((await worker.adoptLegacyState({
      agentId: "agent-legacy",
      operationId: "adopt-2",
      sourceVolumeId: "legacy-agent",
      expectedWorkspaceHash: manifest.hash,
      adoptedView: view,
      versionId: "legacy-head",
    })).digest).toBe(adopted.digest);
    await expect(worker.adoptLegacyState({
      agentId: "agent-legacy",
      operationId: "adopt-conflict",
      sourceVolumeId: "legacy-agent",
      expectedWorkspaceHash: "f".repeat(64),
      adoptedView: view,
      versionId: "legacy-head",
    })).rejects.toMatchObject({ code: "LEGACY_STATE_CONFLICT" });
  });

  it("imports a legacy Agent only from the configured read-only legacy root", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-worker-legacy-root-"));
    roots.push(root);
    const legacyRoot = path.join(root, "legacy");
    const legacy = path.join(legacyRoot, "agent-preserved");
    await mkdir(legacy, { recursive: true });
    await writeFile(path.join(legacy, "value.txt"), "preserved\n");
    const manifest = await buildWorkerManifest(legacy);
    const config: TransitionWorkerConfig = {
      workspaceRoot: path.join(root, "workspaces"),
      controlRoot: path.join(root, "control"),
      inboxRoot: path.join(root, "inbox"),
      socketPath: path.join(root, "run", "worker.sock"),
      legacyWorkspaceRoot: legacyRoot,
    };
    const worker = new TransitionWorker(config);
    await worker.initialize();
    const view = makeStateView({
      agentId: "agent-preserved",
      headVersionId: "legacy-head",
      generation: 7,
      ...deriveWorkerStateHashes(manifest),
      sessionEpoch: 2,
      agentConfigVersion: 3,
      policyVersion: 4,
    });
    const adopted = await worker.adoptLegacyState({
      agentId: "agent-preserved",
      operationId: "legacy-adopt",
      legacyAgentId: "agent-preserved",
      expectedWorkspaceHash: manifest.hash,
      adoptedView: view,
      versionId: "legacy-head",
    });
    expect(adopted.head?.view).toEqual(view);
    expect(await readFile(path.join(config.workspaceRoot, "agent-preserved", "value.txt"), "utf8"))
      .toBe("preserved\n");
    expect((await worker.log.read("agent-preserved")).at(-1)?.type)
      .toBe("LEGACY_STATE_ADOPTED");
  });

  it("promotes only a sealed proposal with a one-shot permit and rebuilds HEAD", async () => {
    const { config, worker, workspace, baseHash, baseView } = await fixture();
    const source = path.join(config.inboxRoot, "candidate-tx-1");
    await worker.prepareRun({
      agentId: "agent-a",
      transitionId: "tx-1",
      runId: "tx-1",
      runLeaseId: "lease-tx-1",
      candidateVolumeId: "candidate-tx-1",
      expectedViewId: baseView.viewId,
      expectedWorkspaceHash: baseHash,
      baseGeneration: 0,
    });
    await writeFile(path.join(source, "value.txt"), "committed\n");
    const artifactManifest = await buildWorkerManifest(source);
    const artifactHash = artifactManifest.hash;
    const evidence = passingEvidence({
      runId: "tx-1",
      agentId: "agent-a",
      proposalId: "proposal-1",
      baseView,
      artifactHash,
      sourceRevision: "unverified",
    });
    await worker.sealProposal({
      agentId: "agent-a",
      transitionId: "tx-1",
      proposalId: "proposal-1",
      sourceVolumeId: "candidate-tx-1",
      baseViewId: baseView.viewId,
      expectedArtifactHash: artifactHash,
      runtimeTeardownDigest: "6".repeat(64),
    });
    await expect(readFile(path.join(source, "value.txt"), "utf8")).rejects.toMatchObject({ code: "ENOENT" });
    await worker.exportProposal({
      agentId: "agent-a",
      transitionId: "tx-1",
      proposalId: "proposal-1",
      exportVolumeId: "verify-tx-1",
    });
    await worker.recordEvidence({
      agentId: "agent-a",
      transitionId: "tx-1",
      proposalId: "proposal-1",
      ...evidence,
    });
    await worker.issuePermit({
      agentId: "agent-a",
      transitionId: "tx-1",
      permitId: "permit-1",
      proposalId: "proposal-1",
      baseViewId: baseView.viewId,
      targetArtifactHash: artifactHash,
      evaluationContextHash: evidence.evaluationContextHash,
      evidenceDigest: evidence.evidenceDigest,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    const promotion = {
      agentId: "agent-a",
      transitionId: "tx-1",
      permitId: "permit-1",
      proposalId: "proposal-1",
      expectedViewId: baseView.viewId,
      expectedWorkspaceHash: baseHash,
      versionId: "version-1",
      receiptId: "receipt-1",
    } as const;
    const workerDerivedView = makeStateView({
      agentId: "agent-a",
      headVersionId: "version-1",
      generation: 1,
      ...deriveWorkerStateHashes(artifactManifest),
      sessionEpoch: baseView.sessionEpoch,
      agentConfigVersion: baseView.agentConfigVersion,
      policyVersion: baseView.policyVersion,
    });
    const {
      schemaVersion: _derivedSchemaVersion,
      viewId: _derivedViewId,
      ...workerDerivedInput
    } = workerDerivedView;
    const forgedViews = [
      makeStateView({ ...workerDerivedInput, versionedHash: "a".repeat(64) }),
      makeStateView({ ...workerDerivedInput, platformManagedHash: "b".repeat(64) }),
      makeStateView({ ...workerDerivedInput, liveStateHash: "c".repeat(64) }),
      makeStateView({ ...workerDerivedInput, sessionEpoch: workerDerivedInput.sessionEpoch + 1 }),
      makeStateView({
        ...workerDerivedInput,
        agentConfigVersion: workerDerivedInput.agentConfigVersion + 1,
      }),
      makeStateView({ ...workerDerivedInput, policyVersion: workerDerivedInput.policyVersion + 1 }),
    ];
    for (const forgedView of forgedViews) {
      await expect(worker.applyPromotion({ ...promotion, nextView: forgedView }))
        .rejects.toMatchObject({ code: "NEXT_VIEW_INVALID" });
      const unchanged = await worker.projection("agent-a");
      expect(unchanged.head?.view.viewId).toBe(baseView.viewId);
      expect(unchanged.permits["permit-1"]?.state).toBe("ISSUED");
    }
    const projected = await worker.applyPromotion(promotion);
    const nextView = projected.head!.view;
    expect(nextView).toEqual(workerDerivedView);

    expect(await readFile(path.join(workspace, "value.txt"), "utf8")).toBe("committed\n");
    expect(projected.head?.view.viewId).toBe(nextView.viewId);
    expect(projected.permits["permit-1"]?.state).toBe("CONSUMED");
    expect(projected.proposals["proposal-1"]?.state).toBe("DESTROYED");
    expect(projected.transitions["tx-1"]?.artifactsDestroyed).toBe(true);
    expect(projected.versions).toHaveLength(1);
    expect(projected.terminalReceipts[0]?.decision).toBe("COMMITTED");
    const compactProof = projected.receiptProofs["receipt-1"]?.bundle;
    expect(compactProof).toBeDefined();
    expect(compactProof?.schemaVersion).toBe(2);
    expect(compactProof).not.toHaveProperty("eventChain");
    expect(verifyAuthorityReceiptProof(compactProof!)).toEqual({ valid: true, reason: null });
    const proof = await worker.getReceiptProof("agent-a", "receipt-1");
    expect(proof.schemaVersion).toBe(3);
    expect(proof?.eventChain?.[0]?.sequence).toBe(1);
    expect(proof?.eventChain?.at(-1)?.eventId).toBe(proof?.terminalEvent.eventId);
    expect(verifyAuthorityReceiptProof(proof!)).toEqual({ valid: true, reason: null });
    expect(verifyAuthorityReceiptProof(JSON.parse(JSON.stringify(proof!)))).toEqual({
      valid: true,
      reason: null,
    });
    expect(proof?.receipt).toMatchObject({
      receiptId: "receipt-1",
      runId: "tx-1",
      agentId: "agent-a",
      transitionId: "tx-1",
      decision: "COMMITTED",
      baseViewId: baseView.viewId,
      finalViewId: nextView.viewId,
      baseGeneration: 0,
      nextGeneration: 1,
      baseWorkspaceHash: baseHash,
      dispositionBaseViewId: baseView.viewId,
      dispositionBaseGeneration: 0,
      dispositionBaseWorkspaceHash: baseHash,
      finalWorkspaceHash: artifactHash,
      proposalId: "proposal-1",
      proposalArtifactHash: artifactHash,
      verifierInputHash: artifactHash,
      promotionSourceHash: artifactHash,
      evaluationContextHash: evidence.evaluationContextHash,
      evidenceDigest: evidence.evidenceDigest,
      permitId: "permit-1",
      permitState: "CONSUMED",
    });
    const terminalEvent = (await worker.log.read("agent-a")).find(
      (event) => event.eventId === projected.terminalReceipts[0]?.eventId,
    );
    expect(proof?.proof).toMatchObject({
      logSequence: terminalEvent?.sequence,
      previousDigest: terminalEvent?.previousDigest,
      eventDigest: terminalEvent?.digest,
    });
    const proofEvent = (await worker.log.read("agent-a")).find(
      (event) => event.type === "RECEIPT_PROOF_RECORDED",
    );
    expect(proofEvent?.payload).toMatchObject({
      schemaVersion: 2,
      receiptId: "receipt-1",
      terminalEventId: terminalEvent?.eventId,
    });
    expect(proofEvent?.payload).not.toHaveProperty("bundle");
    expect(proofEvent?.payload).not.toHaveProperty("eventChain");
    await expect(
      readFile(path.join(config.controlRoot, "proposals", "agent-a", "proposal-1", "value.txt"), "utf8"),
    ).rejects.toMatchObject({ code: "ENOENT" });
    await expect(
      readFile(path.join(config.inboxRoot, "export-1", "value.txt"), "utf8"),
    ).rejects.toMatchObject({ code: "ENOENT" });
    await expect(worker.applyPromotion(promotion)).rejects.toMatchObject({ code: "PERMIT_REPLAY" });
    await expect(worker.attemptPermitConsumption({
      agentId: "agent-a",
      transitionId: "tx-1",
      permitId: "permit-1",
      expectedViewId: nextView.viewId,
    })).rejects.toMatchObject({ code: "PERMIT_REPLAY" });

    await rm(path.join(config.controlRoot, "heads", "agent-a.json"));
    const rebuilt = await worker.rebuildProjection("agent-a");
    expect(rebuilt.digest).toBe(projected.digest);
    expect((await worker.projections.readHead("agent-a"))?.viewId).toBe(nextView.viewId);
  });

  it("never rolls back an acknowledged workspace when signing fails and repairs proof on restart", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-worker-proof-recovery-"));
    roots.push(root);
    const config: TransitionWorkerConfig = {
      workspaceRoot: path.join(root, "workspaces"),
      controlRoot: path.join(root, "control"),
      inboxRoot: path.join(root, "inbox"),
      socketPath: path.join(root, "run", "worker.sock"),
      sourceRevision: "proof-test-revision",
    };
    const backing = new WorkerSigningKeyStore(config.controlRoot);
    let signingAvailable = false;
    const worker = new TransitionWorker(config, {
      signingKeyStore: {
        get keyId() {
          return backing.keyId;
        },
        initialize: () => backing.initialize(),
        sign: (receipt, event, predecessorEvent) => {
          if (!signingAvailable) throw new Error("SIGNING_BACKEND_UNAVAILABLE");
          return backing.sign(receipt, event, predecessorEvent);
        },
      },
    });
    await worker.initialize();
    const initialized = await worker.initializeAgent({
      agentId: "agent-proof",
      operationId: "init-proof",
      headVersionId: "initial-proof",
      generation: 1,
      sessionEpoch: 0,
      agentConfigVersion: 1,
      policyVersion: 1,
      name: "Proof Agent",
      instructions: "# Proof test\n",
    });
    const source = path.join(config.inboxRoot, "candidate-tx-proof");
    await worker.prepareRun({
      agentId: "agent-proof",
      transitionId: "tx-proof",
      runId: "tx-proof",
      runLeaseId: "lease-tx-proof",
      candidateVolumeId: "candidate-tx-proof",
      expectedViewId: initialized.head!.view.viewId,
      expectedWorkspaceHash: initialized.head!.workspaceHash,
      baseGeneration: initialized.head!.view.generation,
    });
    await writeFile(path.join(source, "value.txt"), "committed despite signer outage\n");
    const artifactHash = (await buildWorkerManifest(source)).hash;
    const evidence = passingEvidence({
      runId: "tx-proof",
      agentId: "agent-proof",
      proposalId: "proposal-proof",
      baseView: initialized.head!.view,
      artifactHash,
      sourceRevision: "proof-test-revision",
    });
    await worker.sealProposal({
      agentId: "agent-proof",
      transitionId: "tx-proof",
      proposalId: "proposal-proof",
      sourceVolumeId: "candidate-tx-proof",
      baseViewId: initialized.head!.view.viewId,
      expectedArtifactHash: artifactHash,
      runtimeTeardownDigest: "b".repeat(64),
    });
    await worker.recordEvidence({
      agentId: "agent-proof",
      transitionId: "tx-proof",
      proposalId: "proposal-proof",
      ...evidence,
    });
    await worker.issuePermit({
      agentId: "agent-proof",
      transitionId: "tx-proof",
      permitId: "permit-proof",
      proposalId: "proposal-proof",
      baseViewId: initialized.head!.view.viewId,
      targetArtifactHash: artifactHash,
      evaluationContextHash: evidence.evaluationContextHash,
      evidenceDigest: evidence.evidenceDigest,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    const committed = await worker.applyPromotion({
      agentId: "agent-proof",
      transitionId: "tx-proof",
      permitId: "permit-proof",
      proposalId: "proposal-proof",
      expectedViewId: initialized.head!.view.viewId,
      expectedWorkspaceHash: initialized.head!.workspaceHash,
      versionId: "version-proof",
      receiptId: "run-proof",
    });
    const nextView = committed.head!.view;
    expect(committed.transitions["tx-proof"]?.state).toBe("ACKNOWLEDGED");
    expect(committed.head?.view.viewId).toBe(nextView.viewId);
    expect(committed.receiptProofs["run-proof"]).toBeUndefined();
    expect(
      await readFile(path.join(config.workspaceRoot, "agent-proof", "value.txt"), "utf8"),
    ).toBe("committed despite signer outage\n");
    expect(
      (await worker.log.transition("agent-proof", "tx-proof")).map((event) => event.type),
    ).not.toContain("TRANSITION_ROLLED_BACK");

    signingAvailable = true;
    const restarted = new TransitionWorker(config);
    await restarted.initialize();
    const recovered = await restarted.projection("agent-proof");
    const recoveredCompactProof = recovered.receiptProofs["run-proof"]?.bundle;
    expect(recoveredCompactProof).toBeDefined();
    expect(recoveredCompactProof).not.toHaveProperty("eventChain");
    const recoveredProof = await restarted.getReceiptProof("agent-proof", "run-proof");
    expect(recoveredProof.receipt.sourceRevision).toBe("proof-test-revision");
    expect(verifyAuthorityReceiptProof(recoveredProof)).toEqual({ valid: true, reason: null });
    expect(recovered.head?.view.viewId).toBe(nextView.viewId);
    expect(recovered.versions.at(-1)?.versionId).toBe("version-proof");
  });

  it("durably conflicts an H0 proposal after H1 wins without changing workspace, generation, or versions", async () => {
    const { config, worker, baseHash, baseView } = await fixture();
    const prepareProposal = async (
      transitionId: string,
      proposalId: string,
      permitId: string,
      volumeId: string,
      value: string,
    ) => {
      const source = path.join(config.inboxRoot, volumeId);
      await mkdir(source);
      await writeFile(path.join(source, "value.txt"), value);
      const artifactHash = (await buildWorkerManifest(source)).hash;
      const evaluationContextHash = `${transitionId === "tx-winning" ? "1" : "3"}`.repeat(64);
      const evidenceDigest = `${transitionId === "tx-winning" ? "2" : "4"}`.repeat(64);
      await worker.prepare({
        agentId: "agent-a",
        transitionId,
        kind: "AGENT_COMMIT",
        expectedViewId: baseView.viewId,
        expectedWorkspaceHash: baseHash,
        baseGeneration: 0,
      });
      await worker.sealProposal({
        agentId: "agent-a",
        transitionId,
        proposalId,
        sourceVolumeId: volumeId,
        baseViewId: baseView.viewId,
        expectedArtifactHash: artifactHash,
      });
      await worker.recordEvidence({
        agentId: "agent-a",
        transitionId,
        proposalId,
        evaluationContextHash,
        evidenceDigest,
      });
      await worker.issuePermit({
        agentId: "agent-a",
        transitionId,
        permitId,
        proposalId,
        baseViewId: baseView.viewId,
        targetArtifactHash: artifactHash,
        evaluationContextHash,
        evidenceDigest,
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      });
      return artifactHash;
    };

    const winningHash = await prepareProposal(
      "tx-winning",
      "proposal-winning",
      "permit-winning",
      "volume-winning",
      "winning\n",
    );
    await prepareProposal(
      "tx-stale",
      "proposal-stale",
      "permit-stale",
      "volume-stale",
      "stale\n",
    );
    const winningProjection = await worker.applyPromotion({
      agentId: "agent-a",
      transitionId: "tx-winning",
      permitId: "permit-winning",
      proposalId: "proposal-winning",
      expectedViewId: baseView.viewId,
      expectedWorkspaceHash: baseHash,
      versionId: "version-winning",
      receiptId: "receipt-winning",
    });
    const winningView = winningProjection.head!.view;
    const beforeReplay = await worker.projection("agent-a");

    await expect(worker.applyPromotion({
      agentId: "agent-a",
      transitionId: "tx-stale",
      permitId: "permit-stale",
      proposalId: "proposal-stale",
      expectedViewId: baseView.viewId,
      expectedWorkspaceHash: baseHash,
      versionId: "version-stale",
      receiptId: "receipt-stale",
    })).rejects.toMatchObject({ code: "VIEW_CAS_MISMATCH" });

    const afterReplay = await worker.projection("agent-a");
    expect(afterReplay.versions).toEqual(beforeReplay.versions);
    expect(afterReplay.head).toMatchObject({
      workspaceHash: beforeReplay.head?.workspaceHash,
      view: {
        generation: winningView.generation,
        headVersionId: winningView.headVersionId,
        liveStateHash: winningView.liveStateHash,
        sessionEpoch: winningView.sessionEpoch + 1,
      },
    });
    expect(afterReplay.head?.view.viewId).not.toBe(winningView.viewId);
    expect(afterReplay.head?.view.generation).toBe(1);
    expect(afterReplay.transitions["tx-stale"]).toMatchObject({
      state: "ROLLED_BACK",
      artifactsDestroyed: true,
    });
    expect(afterReplay.permits["permit-stale"]?.state).toBe("REVOKED");
    expect(afterReplay.terminalReceipts).toContainEqual(expect.objectContaining({
      receiptId: "receipt-stale",
      transitionId: "tx-stale",
      decision: "CONFLICTED",
      workspaceHash: beforeReplay.head?.workspaceHash,
      dispositionBaseViewId: winningView.viewId,
      dispositionBaseGeneration: winningView.generation,
      dispositionBaseWorkspaceHash: beforeReplay.head?.workspaceHash,
      reasonCodes: ["VIEW_CAS_MISMATCH"],
    }));
    // Simulate the Runner/API disappearing after the typed CAS fault. Startup
    // recovery must preserve the already-durable conflict instead of deriving
    // an ABORTED receipt from the old PERMITTED state.
    const restarted = new TransitionWorker(config);
    await restarted.initialize();
    const recovered = await restarted.projection("agent-a");
    expect(recovered.terminalReceipts.filter(
      (receipt) => receipt.transitionId === "tx-stale",
    )).toEqual([expect.objectContaining({ decision: "CONFLICTED" })]);
    expect(recovered.head).toEqual(afterReplay.head);
    expect(recovered.versions).toEqual(afterReplay.versions);
  });

  it("durably classifies a stale promotion workspace hash as CONFLICTED", async () => {
    const { worker, baseHash, baseView } = await fixture();
    const sourceVolumeId = "volume-workspace-cas";
    const source = path.join(worker.config.inboxRoot, sourceVolumeId);
    await mkdir(source);
    await writeFile(path.join(source, "value.txt"), "candidate\n");
    const artifactHash = (await buildWorkerManifest(source)).hash;
    await worker.prepare({
      agentId: "agent-a",
      transitionId: "tx-workspace-cas",
      kind: "AGENT_COMMIT",
      expectedViewId: baseView.viewId,
      expectedWorkspaceHash: baseHash,
      baseGeneration: baseView.generation,
    });
    await worker.sealProposal({
      agentId: "agent-a",
      transitionId: "tx-workspace-cas",
      proposalId: "proposal-workspace-cas",
      sourceVolumeId,
      baseViewId: baseView.viewId,
      expectedArtifactHash: artifactHash,
    });
    await worker.recordEvidence({
      agentId: "agent-a",
      transitionId: "tx-workspace-cas",
      proposalId: "proposal-workspace-cas",
      evaluationContextHash: "a".repeat(64),
      evidenceDigest: "b".repeat(64),
    });
    await worker.issuePermit({
      agentId: "agent-a",
      transitionId: "tx-workspace-cas",
      permitId: "permit-workspace-cas",
      proposalId: "proposal-workspace-cas",
      baseViewId: baseView.viewId,
      targetArtifactHash: artifactHash,
      evaluationContextHash: "a".repeat(64),
      evidenceDigest: "b".repeat(64),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });

    await expect(worker.applyPromotion({
      agentId: "agent-a",
      transitionId: "tx-workspace-cas",
      permitId: "permit-workspace-cas",
      proposalId: "proposal-workspace-cas",
      expectedViewId: baseView.viewId,
      expectedWorkspaceHash: "f".repeat(64),
      versionId: "version-workspace-cas",
      receiptId: "receipt-workspace-cas",
    })).rejects.toMatchObject({ code: "WORKSPACE_CAS_MISMATCH" });

    const projection = await worker.projection("agent-a");
    expect(projection.head).toMatchObject({
      workspaceHash: baseHash,
      view: {
        generation: baseView.generation,
        sessionEpoch: baseView.sessionEpoch + 1,
        liveStateHash: baseHash,
      },
    });
    expect(projection.versions).toHaveLength(0);
    expect(projection.terminalReceipts).toContainEqual(expect.objectContaining({
      receiptId: "receipt-workspace-cas",
      decision: "CONFLICTED",
      workspaceHash: baseHash,
      dispositionBaseViewId: baseView.viewId,
      dispositionBaseWorkspaceHash: baseHash,
      reasonCodes: ["WORKSPACE_CAS_MISMATCH"],
    }));
  });

  it("fences an accepted run cancellation before permit consumption", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-worker-cancel-"));
    roots.push(root);
    const config: TransitionWorkerConfig = {
      workspaceRoot: path.join(root, "workspaces"),
      controlRoot: path.join(root, "control"),
      inboxRoot: path.join(root, "exchange"),
      socketPath: path.join(root, "run", "worker.sock"),
    };
    const worker = new TransitionWorker(config);
    await worker.initialize();
    const initialized = await worker.initializeAgent({
      agentId: "agent-cancel",
      operationId: "init-cancel",
      headVersionId: "initial-cancel",
      generation: 1,
      sessionEpoch: 0,
      agentConfigVersion: 1,
      policyVersion: 1,
      name: "Cancel Agent",
      instructions: "# trusted\n",
    });
    await worker.prepareRun({
      agentId: "agent-cancel",
      transitionId: "run-cancel",
      runId: "run-cancel",
      runLeaseId: "lease-cancel",
      candidateVolumeId: "candidate-run-cancel",
      expectedViewId: initialized.head!.view.viewId,
      expectedWorkspaceHash: initialized.head!.workspaceHash,
      baseGeneration: 1,
    });

    await expect(worker.cancelRun({
      agentId: "agent-cancel",
      transitionId: "run-cancel",
      runId: "run-cancel",
      runLeaseId: "wrong-lease",
      expectedViewId: initialized.head!.view.viewId,
    })).rejects.toMatchObject({ code: "RUN_CANCELLATION_BINDING_MISMATCH" });
    await expect(worker.cancelRun({
      agentId: "agent-cancel",
      transitionId: "run-cancel",
      runId: "run-cancel",
      runLeaseId: "lease-cancel",
      expectedViewId: initialized.head!.view.viewId,
    })).resolves.toEqual({ state: "CANCELLED" });
    await expect(worker.sealProposal({
      agentId: "agent-cancel",
      transitionId: "run-cancel",
      proposalId: "proposal-cancel",
      sourceVolumeId: "candidate-run-cancel",
      baseViewId: initialized.head!.view.viewId,
    })).rejects.toMatchObject({ code: "RUN_CANCELLED" });

    const base = initialized.head!.view;
    const { schemaVersion: _schemaVersion, viewId: _viewId, ...baseInput } = base;
    await worker.disposeRun({
      agentId: "agent-cancel",
      transitionId: "run-cancel",
      receiptId: "run-cancel",
      decision: "ABORTED",
      finalView: makeStateView({ ...baseInput, sessionEpoch: 1 }),
      reasonCodes: ["RUN_CANCELLED"],
    });
    const terminal = await worker.projection("agent-cancel");
    expect(terminal.head?.view.generation).toBe(1);
    expect(terminal.head?.workspaceHash).toBe(initialized.head?.workspaceHash);
    expect(terminal.versions).toHaveLength(1);
    expect(terminal.terminalReceipts.at(-1)?.decision).toBe("ABORTED");
    await expect(worker.cancelRun({
      agentId: "agent-cancel",
      transitionId: "run-cancel",
      runId: "run-cancel",
      runLeaseId: "lease-cancel",
      expectedViewId: initialized.head!.view.viewId,
    })).resolves.toEqual({ state: "ALREADY_TERMINAL" });
  });

  it("returns TOO_LATE after the permit enters CONSUMING", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-worker-cancel-late-"));
    roots.push(root);
    const config: TransitionWorkerConfig = {
      workspaceRoot: path.join(root, "workspaces"),
      controlRoot: path.join(root, "control"),
      inboxRoot: path.join(root, "exchange"),
      socketPath: path.join(root, "run", "worker.sock"),
      sourceRevision: "test-revision",
    };
    const worker = new TransitionWorker(config);
    await worker.initialize();
    const initialized = await worker.initializeAgent({
      agentId: "agent-late",
      operationId: "init-late",
      headVersionId: "initial-late",
      generation: 1,
      sessionEpoch: 0,
      agentConfigVersion: 1,
      policyVersion: 1,
      name: "Late Agent",
      instructions: "# trusted\n",
    });
    const source = path.join(config.inboxRoot, "candidate-run-late");
    await worker.prepareRun({
      agentId: "agent-late",
      transitionId: "run-late",
      runId: "run-late",
      runLeaseId: "lease-late",
      candidateVolumeId: "candidate-run-late",
      expectedViewId: initialized.head!.view.viewId,
      expectedWorkspaceHash: initialized.head!.workspaceHash,
      baseGeneration: 1,
    });
    await writeFile(path.join(source, "feature.ts"), "export const late = true;\n");
    const artifactHash = (await buildWorkerManifest(source)).hash;
    const sealInput = {
      agentId: "agent-late",
      transitionId: "run-late",
      proposalId: "proposal-late",
      sourceVolumeId: "candidate-run-late",
      baseViewId: initialized.head!.view.viewId,
      expectedArtifactHash: artifactHash,
    } as const;
    await expect(worker.sealProposal(sealInput)).rejects.toMatchObject({
      code: "RUNTIME_TEARDOWN_EVIDENCE_INVALID",
    });
    await expect(worker.sealProposal({
      ...sealInput,
      runtimeTeardownDigest: "not-a-digest",
    })).rejects.toMatchObject({ code: "RUNTIME_TEARDOWN_EVIDENCE_INVALID" });
    await worker.sealProposal({
      ...sealInput,
      runtimeTeardownDigest: "8".repeat(64),
    });
    const context: EvaluationContext = {
      schemaVersion: 1,
      runId: "run-late",
      agentId: "agent-late",
      proposalId: "proposal-late",
      baseView: initialized.head!.view,
      manifestSchemaVersion: WORKER_MANIFEST_SCHEMA_VERSION,
      policyHash: WORKER_GATE_POLICY_HASH,
      checkBundleHash: "2".repeat(64),
      checkSpecHash: WORKER_CHECK_SPEC_HASH,
      verifierImageDigest: "sha256:" + "4".repeat(64),
      verifierConfigHash: "5".repeat(64),
      resourcePolicyHash: "6".repeat(64),
      sourceRevision: "test-revision",
    };
    const checks = [{
      id: "workspace-sanity",
      status: "PASS" as const,
      exitCode: 0,
      durationMs: 1,
      outputHash: "7".repeat(64),
      timedOut: false,
    }];
    const evaluationContextHash = computeEvaluationContextHash(context);
    const checkResultsHash = sha256Canonical(checks);
    const evidenceDigest = sha256Canonical({
      schemaVersion: 1,
      proposalId: "proposal-late",
      artifactHash,
      evaluationContextHash,
      checkResultsHash,
    });
    await worker.recordEvidence({
      agentId: "agent-late",
      transitionId: "run-late",
      proposalId: "proposal-late",
      evaluationContextHash,
      evidenceDigest,
      evaluationContext: context,
      verifierInputHash: artifactHash,
      checkResultsHash,
      coverage: "complete",
      requiredChecksPassed: true,
      checks,
    });
    await worker.issuePermit({
      agentId: "agent-late",
      transitionId: "run-late",
      permitId: "permit-late",
      proposalId: "proposal-late",
      baseViewId: initialized.head!.view.viewId,
      targetArtifactHash: artifactHash,
      evaluationContextHash,
      evidenceDigest,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    const nextView = makeStateView({
      agentId: "agent-late",
      headVersionId: "version-late",
      generation: 2,
      versionedHash: artifactHash,
      platformManagedHash: artifactHash,
      liveStateHash: artifactHash,
      sessionEpoch: 0,
      agentConfigVersion: 1,
      policyVersion: 1,
    });
    await worker.log.append({
      agentId: "agent-late",
      transitionId: "run-late",
      type: "PERMIT_CONSUMING",
      payload: {
        permitId: "permit-late",
        proposalId: "proposal-late",
        nextView,
        versionId: "version-late",
        receiptId: "receipt-late",
        targetArtifactHash: artifactHash,
      },
    });

    await expect(worker.cancelRun({
      agentId: "agent-late",
      transitionId: "run-late",
      runId: "run-late",
      runLeaseId: "lease-late",
      expectedViewId: initialized.head!.view.viewId,
    })).resolves.toEqual({ state: "TOO_LATE" });
  });

  it("binds the rollback target version to its snapshot and creates a new generation for a no-op rollback snapshot", async () => {
    const { config, worker, baseHash, baseView } = await fixture();
    const source = path.join(config.inboxRoot, "volume-1");
    await mkdir(source);
    await writeFile(path.join(source, "value.txt"), "one\n");
    const artifactHash = (await buildWorkerManifest(source)).hash;
    await worker.prepare({
      agentId: "agent-a", transitionId: "tx-1", kind: "AGENT_COMMIT",
      expectedViewId: baseView.viewId, expectedWorkspaceHash: baseHash, baseGeneration: 0,
    });
    await worker.sealProposal({
      agentId: "agent-a", transitionId: "tx-1", proposalId: "proposal-1",
      sourceVolumeId: "volume-1", baseViewId: baseView.viewId, expectedArtifactHash: artifactHash,
    });
    await worker.recordEvidence({
      agentId: "agent-a", transitionId: "tx-1", proposalId: "proposal-1",
      evaluationContextHash: "3".repeat(64), evidenceDigest: "4".repeat(64),
    });
    await worker.issuePermit({
      agentId: "agent-a", transitionId: "tx-1", permitId: "permit-1",
      proposalId: "proposal-1", baseViewId: baseView.viewId,
      targetArtifactHash: artifactHash, evaluationContextHash: "3".repeat(64),
      evidenceDigest: "4".repeat(64), expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    const committed = await worker.applyPromotion({
      agentId: "agent-a", transitionId: "tx-1", permitId: "permit-1",
      proposalId: "proposal-1", expectedViewId: baseView.viewId,
      expectedWorkspaceHash: baseHash,
      versionId: "version-1", receiptId: "receipt-1",
    });
    const committedView = committed.head!.view;

    await worker.prepare({
      agentId: "agent-a", transitionId: "tx-rb", kind: "ROLLBACK",
      expectedViewId: committedView.viewId, expectedWorkspaceHash: artifactHash, baseGeneration: 1,
    });
    await expect(worker.applyRollback({
      agentId: "agent-a", transitionId: "tx-rb", rollbackPermitId: "rollback-permit-missing",
      targetSnapshotId: artifactHash, expectedViewId: committedView.viewId,
      targetVersionId: "NONEXISTENT_TARGET",
      expectedWorkspaceHash: artifactHash,
      versionId: "version-rb-missing", receiptId: "receipt-rb-missing",
    })).rejects.toMatchObject({ code: "ROLLBACK_TARGET_VERSION_NOT_FOUND" });
    await expect(worker.applyRollback({
      agentId: "agent-a", transitionId: "tx-rb", rollbackPermitId: "rollback-permit-mismatch",
      targetSnapshotId: "c".repeat(64), expectedViewId: committedView.viewId,
      targetVersionId: "version-1",
      expectedWorkspaceHash: artifactHash,
      versionId: "version-rb-mismatch", receiptId: "receipt-rb-mismatch",
    })).rejects.toMatchObject({ code: "ROLLBACK_TARGET_BINDING_MISMATCH" });
    const projection = await worker.applyRollback({
      agentId: "agent-a", transitionId: "tx-rb", rollbackPermitId: "rollback-permit-1",
      targetSnapshotId: artifactHash, expectedViewId: committedView.viewId,
      targetVersionId: "version-1",
      expectedWorkspaceHash: artifactHash,
      versionId: "version-rb", receiptId: "receipt-rb",
    });
    expect(projection.head?.view.generation).toBe(2);
    expect(projection.head?.view).toMatchObject({
      versionedHash: committedView.versionedHash,
      platformManagedHash: committedView.platformManagedHash,
      liveStateHash: artifactHash,
      sessionEpoch: committedView.sessionEpoch + 1,
      agentConfigVersion: committedView.agentConfigVersion,
      policyVersion: committedView.policyVersion,
    });
    expect(projection.versions.at(-1)?.kind).toBe("ROLLBACK");
    expect(projection.versions.at(-1)?.rollbackTargetVersionId).toBe("version-1");
    expect(projection.permits["rollback-permit-1"]?.state).toBe("CONSUMED");
    expect(projection.receiptProofs["receipt-rb"]?.bundle).not.toHaveProperty("eventChain");
    const rollbackProof = await worker.getReceiptProof("agent-a", "receipt-rb");
    expect(verifyAuthorityReceiptProof(rollbackProof)).toEqual({
      valid: true,
      reason: null,
    });
  });

  it("requires expected view and workspace hash for repair and exposes no force flag", async () => {
    const { worker } = await fixture();
    await expect(worker.repair({
      agentId: "agent-a",
      transitionId: "missing",
      action: "forward",
      expectedViewId: "a".repeat(64),
      expectedWorkspaceHash: "b".repeat(64),
    })).rejects.toMatchObject({ code: "REPAIR_NOT_REQUIRED" });
  });

  it("forwards a kill after rename from the durable consuming intent on restart", async () => {
    const { config, worker, workspace, baseHash, baseView } = await fixture();
    const source = path.join(config.inboxRoot, "volume-recovery");
    await mkdir(source);
    await writeFile(path.join(source, "value.txt"), "after-kill\n");
    const targetManifest = await buildWorkerManifest(source);
    const targetHash = targetManifest.hash;
    await worker.prepare({
      agentId: "agent-a", transitionId: "tx-kill", kind: "AGENT_COMMIT",
      expectedViewId: baseView.viewId, expectedWorkspaceHash: baseHash, baseGeneration: 0,
    });
    await worker.sealProposal({
      agentId: "agent-a", transitionId: "tx-kill", proposalId: "proposal-kill",
      sourceVolumeId: "volume-recovery", baseViewId: baseView.viewId,
      expectedArtifactHash: targetHash,
    });
    await worker.recordEvidence({
      agentId: "agent-a", transitionId: "tx-kill", proposalId: "proposal-kill",
      evaluationContextHash: "5".repeat(64), evidenceDigest: "6".repeat(64),
    });
    await worker.issuePermit({
      agentId: "agent-a", transitionId: "tx-kill", permitId: "permit-kill",
      proposalId: "proposal-kill", baseViewId: baseView.viewId,
      targetArtifactHash: targetHash, evaluationContextHash: "5".repeat(64),
      evidenceDigest: "6".repeat(64), expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    const nextView = makeStateView({
      agentId: "agent-a", headVersionId: "version-kill", generation: 1,
      ...deriveWorkerStateHashes(targetManifest),
      sessionEpoch: 0, agentConfigVersion: 1, policyVersion: 1,
    });
    await worker.log.append({
      agentId: "agent-a",
      transitionId: "tx-kill",
      type: "PERMIT_CONSUMING",
      payload: {
        permitId: "permit-kill",
        proposalId: "proposal-kill",
        nextView,
        versionId: "version-kill",
        receiptId: "receipt-kill",
        targetArtifactHash: targetHash,
      },
    });
    await rm(workspace, { recursive: true });
    await copyClosedTree(
      path.join(config.controlRoot, "proposals", "agent-a", "proposal-kill"),
      workspace,
    );

    const restarted = new TransitionWorker(config);
    await restarted.initialize();
    const recovered = await restarted.projection("agent-a");
    expect(recovered.transitions["tx-kill"]?.state).toBe("ACKNOWLEDGED");
    expect(recovered.head?.view.viewId).toBe(nextView.viewId);
    expect(recovered.terminalReceipts.at(-1)?.receiptId).toBe("receipt-kill");
    expect(await readFile(path.join(workspace, "value.txt"), "utf8")).toBe("after-kill\n");
  });

  it("recovers a rollback crash point from PERMIT_CONSUMING through the rollback acknowledgement stage", async () => {
    const { config, worker, workspace, baseHash, baseView } = await fixture();
    const baseSnapshot = path.join(
      config.controlRoot,
      "snapshots",
      "agent-a",
      baseHash,
    );
    await mkdir(path.dirname(baseSnapshot), { recursive: true });
    await copyClosedTree(workspace, baseSnapshot);
    await makeTreeReadonly(baseSnapshot);

    const source = path.join(config.inboxRoot, "volume-before-rollback");
    await mkdir(source);
    await writeFile(path.join(source, "value.txt"), "committed-before-rollback\n");
    const committedManifest = await buildWorkerManifest(source);
    const committedHash = committedManifest.hash;
    await worker.prepare({
      agentId: "agent-a", transitionId: "tx-commit", kind: "AGENT_COMMIT",
      expectedViewId: baseView.viewId, expectedWorkspaceHash: baseHash, baseGeneration: 0,
    });
    await worker.sealProposal({
      agentId: "agent-a", transitionId: "tx-commit", proposalId: "proposal-commit",
      sourceVolumeId: "volume-before-rollback", baseViewId: baseView.viewId,
      expectedArtifactHash: committedHash,
    });
    await worker.recordEvidence({
      agentId: "agent-a", transitionId: "tx-commit", proposalId: "proposal-commit",
      evaluationContextHash: "7".repeat(64), evidenceDigest: "8".repeat(64),
    });
    await worker.issuePermit({
      agentId: "agent-a", transitionId: "tx-commit", permitId: "permit-commit",
      proposalId: "proposal-commit", baseViewId: baseView.viewId,
      targetArtifactHash: committedHash, evaluationContextHash: "7".repeat(64),
      evidenceDigest: "8".repeat(64), expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    const committedView = makeStateView({
      agentId: "agent-a", headVersionId: "version-commit", generation: 1,
      ...deriveWorkerStateHashes(committedManifest), sessionEpoch: 0,
      agentConfigVersion: 1, policyVersion: 1,
    });
    await worker.applyPromotion({
      agentId: "agent-a", transitionId: "tx-commit", permitId: "permit-commit",
      proposalId: "proposal-commit", expectedViewId: baseView.viewId,
      expectedWorkspaceHash: baseHash,
      versionId: "version-commit", receiptId: "receipt-commit",
    });

    const transitionId = "tx-rollback-crash";
    const rollbackPermitId = "rollback-permit-crash";
    const proposalId = `snapshot-${baseHash}`;
    const evaluationContextHash = "9".repeat(64);
    const evidenceDigest = "a".repeat(64);
    const rollbackView = makeStateView({
      agentId: "agent-a", headVersionId: "version-rollback", generation: 2,
      versionedHash: baseView.versionedHash,
      platformManagedHash: baseView.platformManagedHash,
      liveStateHash: baseHash,
      sessionEpoch: 1, agentConfigVersion: 1, policyVersion: 1,
    });
    await worker.prepare({
      agentId: "agent-a", transitionId, kind: "ROLLBACK",
      expectedViewId: committedView.viewId, expectedWorkspaceHash: committedHash,
      baseGeneration: 1,
    });
    await worker.log.append({
      agentId: "agent-a", transitionId, type: "PROPOSAL_SEALED",
      payload: {
        proposalId,
        baseViewId: committedView.viewId,
        artifactHash: baseHash,
        source: "version_snapshot",
      },
    });
    await worker.log.append({
      agentId: "agent-a", transitionId, type: "EVIDENCE_RECORDED",
      payload: {
        proposalId,
        evaluationContextHash,
        evidenceDigest,
        verifierInputHash: baseHash,
      },
    });
    await worker.log.append({
      agentId: "agent-a", transitionId, type: "PERMIT_ISSUED",
      payload: {
        permitId: rollbackPermitId,
        proposalId,
        baseViewId: committedView.viewId,
        targetArtifactHash: baseHash,
        evaluationContextHash,
        evidenceDigest,
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      },
    });
    await worker.log.append({
      agentId: "agent-a", transitionId, type: "PERMIT_CONSUMING",
      payload: {
        permitId: rollbackPermitId,
        proposalId,
        nextView: rollbackView,
        versionId: "version-rollback",
        receiptId: "receipt-rollback",
        targetArtifactHash: baseHash,
        rollbackTargetVersionId: "initial",
      },
    });
    const consuming = await worker.projection("agent-a");
    expect(consuming.transitions[transitionId]?.state).toBe("CONSUMING");
    expect(consuming.permits[rollbackPermitId]?.state).toBe("CONSUMING");

    // Reproduce a process kill after the rename-swap but before
    // WORKSPACE_APPLIED/TRANSITION_ACKNOWLEDGED reached the event log.
    const backup = path.join(config.workspaceRoot, `.cg-backup-agent-a-${transitionId}`);
    await rename(workspace, backup);
    await copyClosedTree(baseSnapshot, workspace);

    const restarted = new TransitionWorker(config);
    await restarted.initialize();
    const recovered = await restarted.projection("agent-a");
    expect(recovered.transitions[transitionId]?.state).toBe("ACKNOWLEDGED");
    expect(recovered.permits[rollbackPermitId]?.state).toBe("CONSUMED");
    expect(recovered.head?.view.viewId).toBe(rollbackView.viewId);
    expect(recovered.versions.at(-1)).toMatchObject({
      kind: "ROLLBACK",
      versionId: "version-rollback",
      generation: 2,
      workspaceHash: baseHash,
      rollbackTargetVersionId: "initial",
    });
    expect(recovered.terminalReceipts.at(-1)).toMatchObject({
      receiptId: "receipt-rollback",
      decision: "COMMITTED",
    });
    expect(
      (await restarted.log.transition("agent-a", transitionId)).map((event) => event.type),
    ).toEqual([
      "TRANSITION_PREPARED",
      "PROPOSAL_SEALED",
      "EVIDENCE_RECORDED",
      "PERMIT_ISSUED",
      "PERMIT_CONSUMING",
      "WORKSPACE_APPLIED",
      "TRANSITION_ACKNOWLEDGED",
      "RUN_ARTIFACTS_DESTROYED",
      "RECEIPT_PROOF_RECORDED",
    ]);
    expect(await readFile(path.join(workspace, "value.txt"), "utf8")).toBe("base\n");
    await expect(readFile(path.join(backup, "value.txt"), "utf8")).rejects.toMatchObject({
      code: "ENOENT",
    });
  });
});
