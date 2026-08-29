import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { mkdtemp } from "node:fs/promises";
import { afterEach, describe, expect, it } from "vitest";
import { makeStateView } from "../state-view.js";
import {
  buildWorkerManifest,
  copyClosedTree,
  makeTreeWritable,
} from "./filesystem.js";
import {
  TransitionWorker,
  type TransitionWorkerConfig,
} from "./worker.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map(async (root) => {
    await makeTreeWritable(root).catch(() => undefined);
    await rm(root, { recursive: true, force: true });
  }));
});

async function initialized(agentId = "agent-proof") {
  const root = await mkdtemp(path.join(tmpdir(), "commitgate-terminal-recovery-"));
  roots.push(root);
  const config: TransitionWorkerConfig = {
    workspaceRoot: path.join(root, "workspaces"),
    controlRoot: path.join(root, "control"),
    inboxRoot: path.join(root, "exchange"),
    socketPath: path.join(root, "run", "worker.sock"),
    sourceRevision: "terminal-recovery-test",
  };
  const worker = new TransitionWorker(config);
  await worker.initialize();
  const projection = await worker.initializeAgent({
    agentId,
    operationId: `init-${agentId}`,
    headVersionId: `initial-${agentId}`,
    generation: 3,
    sessionEpoch: 4,
    agentConfigVersion: 2,
    policyVersion: 5,
    name: "Proof closure fixture",
    instructions: "# trusted\n",
  });
  return { root, config, worker, projection, agentId };
}

async function seedCandidateBinding(
  config: TransitionWorkerConfig,
  agentId: string,
  runId: string,
): Promise<void> {
  const volumeId = `candidate-${runId}`;
  const root = path.join(config.controlRoot, "exchange-ref-bindings");
  await mkdir(root, { recursive: true });
  await writeFile(path.join(root, `${volumeId}.json`), JSON.stringify({
    schemaVersion: 1,
    purpose: "candidate",
    volumeId,
    agentId,
    transitionId: runId,
    runId,
    proposalId: null,
  }) + "\n");
}

async function genericPermitted() {
  const state = await initialized("agent-permit");
  const head = state.projection.head!;
  const transitionId = "transition-permit";
  await state.worker.prepare({
    agentId: state.agentId,
    transitionId,
    kind: "AGENT_COMMIT",
    expectedViewId: head.view.viewId,
    expectedWorkspaceHash: head.workspaceHash,
    baseGeneration: head.view.generation,
  });
  const sourceVolumeId = "candidate-permit";
  const source = path.join(state.config.inboxRoot, sourceVolumeId);
  await copyClosedTree(path.join(state.config.workspaceRoot, state.agentId), source);
  await writeFile(path.join(source, "feature.txt"), "candidate-only\n");
  const artifactHash = (await buildWorkerManifest(source)).hash;
  await state.worker.sealProposal({
    agentId: state.agentId,
    transitionId,
    proposalId: "proposal-permit",
    sourceVolumeId,
    baseViewId: head.view.viewId,
    expectedArtifactHash: artifactHash,
  });
  await state.worker.recordEvidence({
    agentId: state.agentId,
    transitionId,
    proposalId: "proposal-permit",
    evaluationContextHash: "a".repeat(64),
    evidenceDigest: "b".repeat(64),
  });
  await state.worker.issuePermit({
    agentId: state.agentId,
    transitionId,
    permitId: "permit-1",
    proposalId: "proposal-permit",
    baseViewId: head.view.viewId,
    targetArtifactHash: artifactHash,
    evaluationContextHash: "a".repeat(64),
    evidenceDigest: "b".repeat(64),
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  });
  return { ...state, head, transitionId, artifactHash };
}

describe("TransitionWorker terminal and recovery closure", () => {
  it("replays prepareRun idempotently only while every durable binding and candidate byte matches", async () => {
    const { config, worker, projection, agentId } = await initialized("agent-prepare");
    const head = projection.head!;
    const request = {
      agentId,
      transitionId: "run-prepare",
      runId: "run-prepare",
      runLeaseId: "lease-prepare",
      candidateVolumeId: "candidate-run-prepare",
      expectedViewId: head.view.viewId,
      expectedWorkspaceHash: head.workspaceHash,
      baseGeneration: head.view.generation,
    };
    const first = await worker.prepareRun(request);
    const replay = await worker.prepareRun(request);
    expect(replay).toEqual(first);
    expect(first.runId).toBe(request.runId);
    expect(
      (await worker.log.transition(agentId, request.transitionId))
        .filter((event) => event.type === "TRANSITION_PREPARED"),
    ).toHaveLength(1);

    await expect(worker.prepareRun({ ...request, runLeaseId: "other-lease" }))
      .rejects.toMatchObject({ code: "TRANSITION_REPLAY_CONFLICT" });
    await writeFile(
      path.join(config.inboxRoot, request.candidateVolumeId, "mutated.txt"),
      "late mutation\n",
    );
    await expect(worker.prepareRun(request))
      .rejects.toMatchObject({ code: "CANDIDATE_STATE_MISMATCH" });
  });

  it("adopts only an exactly bound copy-before-event orphan and rejects divergent bytes", async () => {
    const { config, worker, projection, agentId } = await initialized("agent-prepare-orphan");
    const head = projection.head!;
    await seedCandidateBinding(config, agentId, "run-exact-orphan");
    await copyClosedTree(
      path.join(config.workspaceRoot, agentId),
      path.join(config.inboxRoot, "candidate-run-exact-orphan"),
    );
    const recovered = await worker.prepareRun({
      agentId,
      transitionId: "run-exact-orphan",
      runId: "run-exact-orphan",
      runLeaseId: "lease-exact-orphan",
      candidateVolumeId: "candidate-run-exact-orphan",
      expectedViewId: head.view.viewId,
      expectedWorkspaceHash: head.workspaceHash,
      baseGeneration: head.view.generation,
    });
    expect(recovered.candidateHash).toBe(head.workspaceHash);
    expect(
      (await worker.log.transition(agentId, "run-exact-orphan"))
        .filter((event) => event.type === "TRANSITION_PREPARED"),
    ).toHaveLength(1);

    await seedCandidateBinding(config, agentId, "run-divergent-orphan");
    await copyClosedTree(
      path.join(config.workspaceRoot, agentId),
      path.join(config.inboxRoot, "candidate-run-divergent-orphan"),
    );
    await writeFile(
      path.join(config.inboxRoot, "candidate-run-divergent-orphan", "untrusted.txt"),
      "not the admitted base\n",
    );
    await expect(worker.prepareRun({
      agentId,
      transitionId: "run-divergent-orphan",
      runId: "run-divergent-orphan",
      runLeaseId: "lease-divergent-orphan",
      candidateVolumeId: "candidate-run-divergent-orphan",
      expectedViewId: head.view.viewId,
      expectedWorkspaceHash: head.workspaceHash,
      baseGeneration: head.view.generation,
    })).rejects.toMatchObject({ code: "CANDIDATE_STATE_MISMATCH" });
    expect((await worker.projection(agentId)).transitions["run-divergent-orphan"])
      .toBeUndefined();
  });

  it("derives the fresh non-commit View, revokes the permit, and records one atomic terminal fact", async () => {
    const state = await genericPermitted();
    const before = await buildWorkerManifest(
      path.join(state.config.workspaceRoot, state.agentId),
    );
    const disposed = await state.worker.disposeRun({
      agentId: state.agentId,
      transitionId: state.transitionId,
      receiptId: "receipt-noncommit",
      decision: "QUARANTINED",
      expectedViewId: state.head.view.viewId,
      nextSessionEpoch: state.head.view.sessionEpoch + 1,
      reasonCodes: ["TRUSTED_CHECK_FAILED"],
    });
    const receipt = disposed.terminalReceipts.find(
      (entry) => entry.receiptId === "receipt-noncommit",
    );
    expect(receipt?.view).toMatchObject({
      generation: state.head.view.generation,
      sessionEpoch: state.head.view.sessionEpoch + 1,
      headVersionId: state.head.view.headVersionId,
      liveStateHash: state.head.workspaceHash,
    });
    expect(disposed.transitions[state.transitionId]?.state).toBe("ROLLED_BACK");
    expect(disposed.transitions[state.transitionId]?.artifactsDestroyed).toBe(true);
    expect(disposed.permits["permit-1"]?.state).toBe("REVOKED");
    expect(disposed.proposals["proposal-permit"]?.state).toBe("DESTROYED");
    expect((await buildWorkerManifest(
      path.join(state.config.workspaceRoot, state.agentId),
    )).hash).toBe(before.hash);
    const eventTypes = (await state.worker.log.transition(state.agentId, state.transitionId))
      .map((event) => event.type);
    expect(eventTypes).toContain("NON_COMMIT_DISPOSITIONED");
    expect(eventTypes).not.toContain("VIEW_DISPOSITIONED");
    expect(eventTypes).not.toContain("TRANSITION_ROLLED_BACK");
    const replayed = await state.worker.disposeRun({
      agentId: state.agentId,
      transitionId: state.transitionId,
      receiptId: "receipt-noncommit",
      decision: "QUARANTINED",
      expectedViewId: state.head.view.viewId,
      nextSessionEpoch: state.head.view.sessionEpoch + 1,
      reasonCodes: ["TRUSTED_CHECK_FAILED"],
    });
    expect(replayed.terminalReceipts.filter(
      (entry) => entry.receiptId === "receipt-noncommit",
    )).toHaveLength(1);
    await expect(state.worker.disposeRun({
      agentId: state.agentId,
      transitionId: state.transitionId,
      receiptId: "receipt-noncommit",
      decision: "QUARANTINED",
      expectedViewId: state.head.view.viewId,
      nextSessionEpoch: state.head.view.sessionEpoch + 2,
      reasonCodes: ["TRUSTED_CHECK_FAILED"],
    })).rejects.toMatchObject({ code: "NEXT_VIEW_INVALID" });
    await expect(state.worker.disposeRun({
      agentId: state.agentId,
      transitionId: state.transitionId,
      receiptId: "receipt-noncommit",
      decision: "QUARANTINED",
      expectedViewId: "f".repeat(64),
      nextSessionEpoch: state.head.view.sessionEpoch + 1,
      reasonCodes: ["TRUSTED_CHECK_FAILED"],
    })).rejects.toMatchObject({ code: "VIEW_CAS_MISMATCH" });
  });

  it("strictly rejects a client-authored finalView before destroying run artifacts", async () => {
    const { config, worker, projection, agentId } = await initialized("agent-final-view");
    const head = projection.head!;
    await worker.prepareRun({
      agentId,
      transitionId: "run-final-view",
      runId: "run-final-view",
      runLeaseId: "lease-final-view",
      candidateVolumeId: "candidate-run-final-view",
      expectedViewId: head.view.viewId,
      expectedWorkspaceHash: head.workspaceHash,
      baseGeneration: head.view.generation,
    });
    const forged = makeStateView({
      agentId,
      headVersionId: head.view.headVersionId,
      generation: head.view.generation,
      versionedHash: "f".repeat(64),
      platformManagedHash: head.view.platformManagedHash,
      liveStateHash: head.workspaceHash,
      sessionEpoch: head.view.sessionEpoch + 1,
      agentConfigVersion: head.view.agentConfigVersion,
      policyVersion: head.view.policyVersion,
    });
    await expect(worker.disposeRun({
      agentId,
      transitionId: "run-final-view",
      receiptId: "receipt-final-view",
      decision: "ABORTED",
      finalView: forged,
      reasonCodes: ["FORGED_VIEW"],
    })).rejects.toMatchObject({ code: "NEXT_VIEW_INVALID" });
    expect(await readFile(
      path.join(config.inboxRoot, "candidate-run-final-view", "AGENTS.md"),
      "utf8",
    )).toContain("trusted");
    expect((await worker.projection(agentId)).terminalReceipts).toHaveLength(0);
  });

  it("recovers PREPARED into an ABORTED fresh-session receipt and destroys the candidate", async () => {
    const { config, worker, projection, agentId } = await initialized("agent-early");
    const head = projection.head!;
    await worker.prepareRun({
      agentId,
      transitionId: "run-early",
      runId: "run-early",
      runLeaseId: "lease-early",
      candidateVolumeId: "candidate-run-early",
      expectedViewId: head.view.viewId,
      expectedWorkspaceHash: head.workspaceHash,
      baseGeneration: head.view.generation,
    });
    await writeFile(
      path.join(config.inboxRoot, "candidate-run-early", "untrusted.txt"),
      "never persist\n",
    );

    const restarted = new TransitionWorker(config);
    await restarted.initialize();
    const recovered = await restarted.projection(agentId);
    expect(recovered.transitions["run-early"]).toMatchObject({
      state: "ROLLED_BACK",
      artifactsDestroyed: true,
    });
    expect(recovered.terminalReceipts.find((receipt) => receipt.receiptId === "run-early"))
      .toMatchObject({
        decision: "ABORTED",
        reasonCodes: ["INCOMPLETE_PREPARED_RECOVERED"],
      });
    expect(recovered.head?.view.sessionEpoch).toBe(head.view.sessionEpoch + 1);
    expect(recovered.head?.view.generation).toBe(head.view.generation);
    await expect(readFile(
      path.join(config.inboxRoot, "candidate-run-early", "untrusted.txt"),
      "utf8",
    )).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("reads and closes the legacy VIEW_DISPOSITIONED to ROLLED_BACK kill gap", async () => {
    const { config, worker, projection, agentId } = await initialized("agent-legacy-gap");
    const head = projection.head!;
    await worker.prepareRun({
      agentId,
      transitionId: "run-legacy-gap",
      runId: "run-legacy-gap",
      runLeaseId: "lease-legacy-gap",
      candidateVolumeId: "candidate-run-legacy-gap",
      expectedViewId: head.view.viewId,
      expectedWorkspaceHash: head.workspaceHash,
      baseGeneration: head.view.generation,
    });
    const legacyView = makeStateView({
      agentId,
      headVersionId: head.view.headVersionId,
      generation: head.view.generation,
      versionedHash: head.view.versionedHash,
      platformManagedHash: head.view.platformManagedHash,
      liveStateHash: head.workspaceHash,
      sessionEpoch: head.view.sessionEpoch + 1,
      agentConfigVersion: head.view.agentConfigVersion,
      policyVersion: head.view.policyVersion,
    });
    await worker.log.append({
      agentId,
      transitionId: "run-legacy-gap",
      type: "VIEW_DISPOSITIONED",
      payload: {
        receiptId: "run-legacy-gap",
        decision: "ABORTED",
        viewId: legacyView.viewId,
        view: legacyView,
        workspaceHash: head.workspaceHash,
        reasonCodes: ["LEGACY_FIXTURE"],
      },
    });

    const restarted = new TransitionWorker(config);
    await restarted.initialize();
    const recovered = await restarted.projection(agentId);
    expect(recovered.transitions["run-legacy-gap"]).toMatchObject({
      state: "ROLLED_BACK",
      artifactsDestroyed: true,
    });
    expect(recovered.terminalReceipts.filter(
      (receipt) => receipt.receiptId === "run-legacy-gap",
    )).toHaveLength(1);
    expect(
      (await restarted.log.transition(agentId, "run-legacy-gap"))
        .map((event) => event.type),
    ).toContain("TRANSITION_ROLLED_BACK");
    await expect(readFile(
      path.join(config.inboxRoot, "candidate-run-legacy-gap", "AGENTS.md"),
      "utf8",
    )).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("surfaces RECOVERY_REQUIRED and never appends a fake rollback when exact restore fails", async () => {
    const state = await genericPermitted();
    const corruptSnapshot = path.join(
      state.config.controlRoot,
      "snapshots",
      state.agentId,
      state.artifactHash,
    );
    await mkdir(corruptSnapshot, { recursive: true });
    await writeFile(path.join(corruptSnapshot, "corrupt.txt"), "wrong snapshot\n");
    Object.defineProperty(state.worker, "restoreBackup", {
      configurable: true,
      value: async () => {
        throw new Error("injected exact-restore failure");
      },
    });
    await expect(state.worker.applyPromotion({
      agentId: state.agentId,
      transitionId: state.transitionId,
      permitId: "permit-1",
      proposalId: "proposal-permit",
      expectedViewId: state.head.view.viewId,
      expectedWorkspaceHash: state.head.workspaceHash,
      versionId: "version-failed-restore",
      receiptId: "receipt-failed-restore",
    })).rejects.toMatchObject({ code: "RECOVERY_REQUIRED" });
    const eventTypes = (await state.worker.log.transition(state.agentId, state.transitionId))
      .map((event) => event.type);
    expect(eventTypes).not.toContain("NON_COMMIT_DISPOSITIONED");
    expect(eventTypes).not.toContain("TRANSITION_ROLLED_BACK");
    const unresolved = await state.worker.projection(state.agentId);
    expect(unresolved.terminalReceipts).toHaveLength(0);
    expect(unresolved.head?.view.viewId).toBe(state.head.view.viewId);
    // The Worker reports an explicit repair state: the complete target tree
    // remains at the authoritative name and the exact base remains in backup.
    // It never labels this unresolved pair as a successful non-effect.
    expect((await buildWorkerManifest(
      path.join(state.config.workspaceRoot, state.agentId),
    )).hash).toBe(state.artifactHash);
    expect((await buildWorkerManifest(
      path.join(
        state.config.workspaceRoot,
        `.cg-backup-${state.agentId}-${state.transitionId}`,
      ),
    )).hash).toBe(state.head.workspaceHash);
  });
});
