import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { mkdtemp } from "node:fs/promises";
import { afterEach, describe, expect, it } from "vitest";
import { makeStateView } from "../state-view.js";
import {
  buildWorkerManifest,
  copyClosedTree,
  makeTreeReadonly,
  makeTreeWritable,
} from "./filesystem.js";
import {
  loadTransitionWorkerConfig,
  TransitionWorker,
  type TransitionWorkerConfig,
} from "./worker.js";

const roots: string[] = [];
const zeros = "0".repeat(64);

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
  const baseHash = (await buildWorkerManifest(workspace)).hash;
  const baseView = makeStateView({
    agentId: "agent-a",
    headVersionId: "initial",
    generation: 0,
    versionedHash: baseHash,
    platformManagedHash: zeros,
    liveStateHash: baseHash,
    sessionEpoch: 0,
    agentConfigVersion: 1,
    policyVersion: 1,
  });
  return { root, config, worker, workspace, baseHash, baseView };
}

describe("TransitionWorker", () => {
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
    const prepared = await worker.prepareRun({
      agentId: "agent-product",
      transitionId: "run-1",
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
      versionedHash: manifest.hash,
      platformManagedHash: zeros,
      liveStateHash: manifest.hash,
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
      versionedHash: manifest.hash,
      platformManagedHash: manifest.hash,
      liveStateHash: manifest.hash,
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
    const source = path.join(config.inboxRoot, "volume-1");
    await mkdir(source);
    await writeFile(path.join(source, "value.txt"), "committed\n");
    const artifactHash = (await buildWorkerManifest(source)).hash;
    const contextHash = "1".repeat(64);
    const evidenceDigest = "2".repeat(64);

    await worker.prepare({
      agentId: "agent-a",
      transitionId: "tx-1",
      kind: "AGENT_COMMIT",
      expectedViewId: baseView.viewId,
      expectedWorkspaceHash: baseHash,
      baseGeneration: 0,
    });
    await worker.sealProposal({
      agentId: "agent-a",
      transitionId: "tx-1",
      proposalId: "proposal-1",
      sourceVolumeId: "volume-1",
      baseViewId: baseView.viewId,
      expectedArtifactHash: artifactHash,
    });
    await expect(readFile(path.join(source, "value.txt"), "utf8")).rejects.toMatchObject({ code: "ENOENT" });
    await worker.recordEvidence({
      agentId: "agent-a",
      transitionId: "tx-1",
      proposalId: "proposal-1",
      evaluationContextHash: contextHash,
      evidenceDigest,
    });
    await worker.issuePermit({
      agentId: "agent-a",
      transitionId: "tx-1",
      permitId: "permit-1",
      proposalId: "proposal-1",
      baseViewId: baseView.viewId,
      targetArtifactHash: artifactHash,
      evaluationContextHash: contextHash,
      evidenceDigest,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    const nextView = makeStateView({
      agentId: "agent-a",
      headVersionId: "version-1",
      generation: 1,
      versionedHash: artifactHash,
      platformManagedHash: zeros,
      liveStateHash: artifactHash,
      sessionEpoch: 0,
      agentConfigVersion: 1,
      policyVersion: 1,
    });
    const promotion = {
      agentId: "agent-a",
      transitionId: "tx-1",
      permitId: "permit-1",
      proposalId: "proposal-1",
      expectedViewId: baseView.viewId,
      expectedWorkspaceHash: baseHash,
      nextView,
      versionId: "version-1",
      receiptId: "receipt-1",
    } as const;
    const projected = await worker.applyPromotion(promotion);

    expect(await readFile(path.join(workspace, "value.txt"), "utf8")).toBe("committed\n");
    expect(projected.head?.view.viewId).toBe(nextView.viewId);
    expect(projected.permits["permit-1"]?.state).toBe("CONSUMED");
    expect(projected.versions).toHaveLength(1);
    expect(projected.terminalReceipts[0]?.decision).toBe("COMMITTED");
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

  it("creates a new generation for a no-op rollback snapshot", async () => {
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
    const committedView = makeStateView({
      agentId: "agent-a", headVersionId: "version-1", generation: 1,
      versionedHash: artifactHash, platformManagedHash: zeros, liveStateHash: artifactHash,
      sessionEpoch: 0, agentConfigVersion: 1, policyVersion: 1,
    });
    await worker.applyPromotion({
      agentId: "agent-a", transitionId: "tx-1", permitId: "permit-1",
      proposalId: "proposal-1", expectedViewId: baseView.viewId,
      expectedWorkspaceHash: baseHash, nextView: committedView,
      versionId: "version-1", receiptId: "receipt-1",
    });

    await worker.prepare({
      agentId: "agent-a", transitionId: "tx-rb", kind: "ROLLBACK",
      expectedViewId: committedView.viewId, expectedWorkspaceHash: artifactHash, baseGeneration: 1,
    });
    const rollbackView = makeStateView({
      agentId: "agent-a", headVersionId: "version-rb", generation: 2,
      versionedHash: artifactHash, platformManagedHash: zeros, liveStateHash: artifactHash,
      sessionEpoch: 1, agentConfigVersion: 1, policyVersion: 1,
    });
    const projection = await worker.applyRollback({
      agentId: "agent-a", transitionId: "tx-rb", rollbackPermitId: "rollback-permit-1",
      targetSnapshotId: artifactHash, expectedViewId: committedView.viewId,
      targetVersionId: "version-1",
      expectedWorkspaceHash: artifactHash, nextView: rollbackView,
      versionId: "version-rb", receiptId: "receipt-rb",
    });
    expect(projection.head?.view.generation).toBe(2);
    expect(projection.versions.at(-1)?.kind).toBe("ROLLBACK");
    expect(projection.versions.at(-1)?.rollbackTargetVersionId).toBe("version-1");
    expect(projection.permits["rollback-permit-1"]?.state).toBe("CONSUMED");
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
    const targetHash = (await buildWorkerManifest(source)).hash;
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
      versionedHash: targetHash, platformManagedHash: zeros, liveStateHash: targetHash,
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
    const committedHash = (await buildWorkerManifest(source)).hash;
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
      versionedHash: committedHash, platformManagedHash: zeros,
      liveStateHash: committedHash, sessionEpoch: 0,
      agentConfigVersion: 1, policyVersion: 1,
    });
    await worker.applyPromotion({
      agentId: "agent-a", transitionId: "tx-commit", permitId: "permit-commit",
      proposalId: "proposal-commit", expectedViewId: baseView.viewId,
      expectedWorkspaceHash: baseHash, nextView: committedView,
      versionId: "version-commit", receiptId: "receipt-commit",
    });

    const transitionId = "tx-rollback-crash";
    const rollbackPermitId = "rollback-permit-crash";
    const proposalId = `snapshot-${baseHash}`;
    const evaluationContextHash = "9".repeat(64);
    const evidenceDigest = "a".repeat(64);
    const rollbackView = makeStateView({
      agentId: "agent-a", headVersionId: "version-rollback", generation: 2,
      versionedHash: baseHash, platformManagedHash: zeros, liveStateHash: baseHash,
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
      payload: { proposalId, evaluationContextHash, evidenceDigest },
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
    ]);
    expect(await readFile(path.join(workspace, "value.txt"), "utf8")).toBe("base\n");
    await expect(readFile(path.join(backup, "value.txt"), "utf8")).rejects.toMatchObject({
      code: "ENOENT",
    });
  });
});
