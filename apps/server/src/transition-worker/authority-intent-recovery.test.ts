import { createHash } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { mkdtemp } from "node:fs/promises";
import { afterEach, describe, expect, it } from "vitest";
import { sha256Canonical } from "../commitgate/protocol.js";
import { makeStateView } from "../state-view.js";
import {
  buildWorkerManifest,
  copyClosedTree,
  makeTreeReadonly,
  makeTreeWritable,
} from "./filesystem.js";
import {
  deriveWorkerStateHashes,
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

const token = (...parts: string[]): string =>
  createHash("sha256").update(JSON.stringify(parts)).digest("hex");

async function fixture() {
  const root = await mkdtemp(path.join(tmpdir(), "commitgate-authority-intent-"));
  roots.push(root);
  const config: TransitionWorkerConfig = {
    workspaceRoot: path.join(root, "workspaces"),
    controlRoot: path.join(root, "control"),
    inboxRoot: path.join(root, "exchange"),
    socketPath: path.join(root, "run", "worker.sock"),
  };
  const worker = new TransitionWorker(config);
  await worker.initialize();
  return { root, config, worker };
}

async function initialized(agentId: string) {
  const state = await fixture();
  const projection = await state.worker.initializeAgent({
    agentId,
    operationId: `init-${agentId}`,
    headVersionId: `initial-${agentId}`,
    generation: 2,
    sessionEpoch: 3,
    agentConfigVersion: 4,
    policyVersion: 5,
    name: "Authority intent fixture",
    instructions: "# trusted v1\n",
  });
  return { ...state, projection, agentId };
}

describe("TransitionWorker durable non-core intents", () => {
  it("forwards initialization after its intent but before the authority rename", async () => {
    const { config, worker } = await fixture();
    const agentId = "agent-init-crash";
    const operationId = "init-crash";
    const staging = path.join(
      config.workspaceRoot,
      `.cg-authority-initialize-stage-${token(agentId, operationId, "initialize")}`,
    );
    await mkdir(staging);
    await writeFile(path.join(staging, "AGENTS.md"), "# trusted\n", { mode: 0o600 });
    await writeFile(path.join(staging, "protected.txt"), "TRUSTED_BASELINE\n", { mode: 0o600 });
    const manifest = await buildWorkerManifest(staging);
    const view = makeStateView({
      agentId,
      headVersionId: "initial-crash",
      generation: 1,
      ...deriveWorkerStateHashes(manifest),
      sessionEpoch: 0,
      agentConfigVersion: 1,
      policyVersion: 1,
    });
    await worker.log.append({
      agentId,
      transitionId: operationId,
      type: "AGENT_INITIALIZATION_PREPARED",
      payload: { view, workspaceHash: manifest.hash, versionId: "initial-crash" },
    });

    const restarted = new TransitionWorker(config);
    await restarted.initialize();
    const projection = await restarted.projection(agentId);
    expect(projection.head?.view).toEqual(view);
    expect(projection.versions).toHaveLength(1);
    expect((await restarted.log.transition(agentId, operationId)).map((event) => event.type))
      .toEqual(["AGENT_INITIALIZATION_PREPARED", "AGENT_INITIALIZED"]);
    expect((await buildWorkerManifest(path.join(config.workspaceRoot, agentId))).hash)
      .toBe(manifest.hash);
    await expect(readFile(path.join(staging, "AGENTS.md"), "utf8"))
      .rejects.toMatchObject({ code: "ENOENT" });
  });

  it("fails closed when an initialization intent would overwrite unrelated authority", async () => {
    const { config, worker } = await fixture();
    const agentId = "agent-init-conflict";
    const operationId = "init-conflict";
    const staging = path.join(
      config.workspaceRoot,
      `.cg-authority-initialize-stage-${token(agentId, operationId, "initialize")}`,
    );
    await mkdir(staging);
    await writeFile(path.join(staging, "AGENTS.md"), "# intended\n", { mode: 0o600 });
    const intended = await buildWorkerManifest(staging);
    const view = makeStateView({
      agentId,
      headVersionId: "initial-conflict",
      generation: 1,
      ...deriveWorkerStateHashes(intended),
      sessionEpoch: 0,
      agentConfigVersion: 1,
      policyVersion: 1,
    });
    await worker.log.append({
      agentId,
      transitionId: operationId,
      type: "AGENT_INITIALIZATION_PREPARED",
      payload: { view, workspaceHash: intended.hash, versionId: "initial-conflict" },
    });
    const workspace = path.join(config.workspaceRoot, agentId);
    await mkdir(workspace);
    await writeFile(path.join(workspace, "intruder.txt"), "must survive fail-closed\n");

    await expect(new TransitionWorker(config).initialize())
      .rejects.toMatchObject({ code: "RECOVERY_REQUIRED" });
    expect(await readFile(path.join(workspace, "intruder.txt"), "utf8"))
      .toBe("must survive fail-closed\n");
    expect((await worker.log.transition(agentId, operationId))
      .filter((event) => event.type === "AGENT_INITIALIZED")).toHaveLength(0);
  });

  it("adopts an already-renamed legacy tree without inventing a second copy", async () => {
    const { config, worker } = await fixture();
    const agentId = "agent-adopt-crash";
    const operationId = "adopt-crash";
    const workspace = path.join(config.workspaceRoot, agentId);
    await mkdir(workspace);
    await writeFile(path.join(workspace, "legacy.txt"), "preserved\n", { mode: 0o600 });
    const manifest = await buildWorkerManifest(workspace);
    const view = makeStateView({
      agentId,
      headVersionId: "legacy-version",
      generation: 9,
      ...deriveWorkerStateHashes(manifest),
      sessionEpoch: 2,
      agentConfigVersion: 3,
      policyVersion: 4,
    });
    await worker.log.append({
      agentId,
      transitionId: operationId,
      type: "LEGACY_ADOPTION_PREPARED",
      payload: {
        view,
        workspaceHash: manifest.hash,
        versionId: "legacy-version",
        sourceVolumeId: "legacy-source",
        legacyAgentId: null,
      },
    });

    const restarted = new TransitionWorker(config);
    await restarted.initialize();
    const projection = await restarted.projection(agentId);
    expect(projection.head?.view).toEqual(view);
    expect(projection.versions[0]).toMatchObject({
      kind: "INITIAL",
      versionId: "legacy-version",
      workspaceHash: manifest.hash,
    });
    expect((await restarted.log.transition(agentId, operationId)).map((event) => event.type))
      .toEqual(["LEGACY_ADOPTION_PREPARED", "LEGACY_STATE_ADOPTED"]);
    expect(await readFile(path.join(workspace, "legacy.txt"), "utf8")).toBe("preserved\n");
  });

  it("forwards platform regeneration from backup+staging and archives exactly once", async () => {
    const state = await initialized("agent-platform-crash");
    const base = state.projection.head!;
    const operationId = "platform-crash";
    const staging = path.join(
      state.config.workspaceRoot,
      `.cg-authority-platform-stage-${token(state.agentId, operationId, "platform")}`,
    );
    const backup = path.join(
      state.config.workspaceRoot,
      `.cg-authority-platform-backup-${token(state.agentId, operationId, "platform-backup")}`,
    );
    const workspace = path.join(state.config.workspaceRoot, state.agentId);
    await copyClosedTree(workspace, staging);
    await writeFile(path.join(staging, "AGENTS.md"), "# trusted v2\n", { mode: 0o600 });
    const target = await buildWorkerManifest(staging);
    const nextView = makeStateView({
      agentId: state.agentId,
      headVersionId: base.view.headVersionId,
      generation: base.view.generation + 1,
      ...deriveWorkerStateHashes(target),
      sessionEpoch: base.view.sessionEpoch + 1,
      agentConfigVersion: base.view.agentConfigVersion + 1,
      policyVersion: base.view.policyVersion,
    });
    await state.worker.log.append({
      agentId: state.agentId,
      transitionId: operationId,
      type: "PLATFORM_STATE_REGENERATION_PREPARED",
      payload: {
        baseViewId: base.view.viewId,
        baseWorkspaceHash: base.workspaceHash,
        view: nextView,
        workspaceHash: target.hash,
      },
    });
    // Exact SIGKILL shape after the first rename of the swap.
    await rename(workspace, backup);

    const restarted = new TransitionWorker(state.config);
    await restarted.initialize();
    const regenerated = await restarted.projection(state.agentId);
    expect(regenerated.head?.view).toEqual(nextView);
    expect(await readFile(path.join(workspace, "AGENTS.md"), "utf8")).toBe("# trusted v2\n");
    await expect(readFile(path.join(backup, "AGENTS.md"), "utf8"))
      .rejects.toMatchObject({ code: "ENOENT" });

    const archiveId = "archive-crash";
    const archive = path.join(
      state.config.workspaceRoot,
      ".deleted",
      `${state.agentId}-${token(state.agentId, archiveId, "archive").slice(0, 32)}`,
    );
    await restarted.log.append({
      agentId: state.agentId,
      transitionId: archiveId,
      type: "AGENT_ARCHIVE_PREPARED",
      payload: { viewId: nextView.viewId, workspaceHash: target.hash },
    });
    await mkdir(path.dirname(archive), { recursive: true });
    await rename(workspace, archive);

    const restartedAgain = new TransitionWorker(state.config);
    await restartedAgain.initialize();
    const archived = await restartedAgain.projection(state.agentId);
    expect(archived.archived).toBe(true);
    expect((await restartedAgain.log.transition(state.agentId, archiveId))
      .filter((event) => event.type === "AGENT_ARCHIVED")).toHaveLength(1);
    expect((await buildWorkerManifest(archive)).hash).toBe(target.hash);
    await expect(readFile(path.join(workspace, "AGENTS.md"), "utf8"))
      .rejects.toMatchObject({ code: "ENOENT" });
  });

  it("recovers a sealed proposal and verifier export intent before abort cleanup", async () => {
    const state = await initialized("agent-artifact-crash");
    const head = state.projection.head!;
    const transitionId = "run-artifact-crash";
    const candidateVolumeId = "candidate-run-artifact-crash";
    await state.worker.prepareRun({
      agentId: state.agentId,
      transitionId,
      runId: transitionId,
      runLeaseId: "lease-artifact-crash",
      candidateVolumeId,
      expectedViewId: head.view.viewId,
      expectedWorkspaceHash: head.workspaceHash,
      baseGeneration: head.view.generation,
    });
    const candidate = path.join(state.config.inboxRoot, candidateVolumeId);
    await writeFile(path.join(candidate, "feature.txt"), "candidate only\n");
    const artifactHash = (await buildWorkerManifest(candidate)).hash;
    await state.worker.sealProposal({
      agentId: state.agentId,
      transitionId,
      proposalId: "proposal-artifact-crash",
      sourceVolumeId: candidateVolumeId,
      baseViewId: head.view.viewId,
      expectedArtifactHash: artifactHash,
      runtimeTeardownDigest: "a".repeat(64),
    });
    const exportVolumeId = "verify-run-artifact-crash";
    const exportStaging = path.join(
      state.config.inboxRoot,
      `.cg-export-${token(state.agentId, transitionId, exportVolumeId, "export")}`,
    );
    await copyClosedTree(
      path.join(state.config.controlRoot, "proposals", state.agentId, "proposal-artifact-crash"),
      exportStaging,
    );
    await makeTreeReadonly(exportStaging);
    await state.worker.log.append({
      agentId: state.agentId,
      transitionId,
      type: "PROPOSAL_EXPORT_PREPARED",
      payload: {
        proposalId: "proposal-artifact-crash",
        exportVolumeId,
        artifactHash,
      },
    });

    const restarted = new TransitionWorker(state.config);
    await restarted.initialize();
    const types = (await restarted.log.transition(state.agentId, transitionId))
      .map((event) => event.type);
    expect(types).toContain("PROPOSAL_EXPORT_PREPARED");
    expect(types).toContain("PROPOSAL_EXPORTED");
    expect(types).toContain("RUN_ARTIFACTS_DESTROYED");
    expect((await restarted.projection(state.agentId)).terminalReceipts.at(-1)?.decision)
      .toBe("ABORTED");
    await expect(readFile(path.join(state.config.inboxRoot, exportVolumeId, "feature.txt"), "utf8"))
      .rejects.toMatchObject({ code: "ENOENT" });
  });

  it("finishes a seal intent from immutable Worker bytes and destroys the old candidate", async () => {
    const state = await initialized("agent-seal-crash");
    const head = state.projection.head!;
    const transitionId = "run-seal-crash";
    const candidateVolumeId = "candidate-run-seal-crash";
    await state.worker.prepareRun({
      agentId: state.agentId,
      transitionId,
      runId: transitionId,
      runLeaseId: "lease-seal-crash",
      candidateVolumeId,
      expectedViewId: head.view.viewId,
      expectedWorkspaceHash: head.workspaceHash,
      baseGeneration: head.view.generation,
    });
    const candidate = path.join(state.config.inboxRoot, candidateVolumeId);
    await writeFile(path.join(candidate, "feature.txt"), "candidate only\n");
    const artifactHash = (await buildWorkerManifest(candidate)).hash;
    const proposalId = "proposal-seal-crash";
    const proposal = path.join(
      state.config.controlRoot,
      "proposals",
      state.agentId,
      proposalId,
    );
    await mkdir(path.dirname(proposal), { recursive: true });
    await copyClosedTree(candidate, proposal);
    await makeTreeReadonly(proposal);
    await state.worker.log.append({
      agentId: state.agentId,
      transitionId,
      type: "PROPOSAL_SEAL_PREPARED",
      payload: {
        proposalId,
        baseViewId: head.view.viewId,
        artifactHash,
        manifestHash: artifactHash,
        changedPathsDigest: sha256Canonical(["feature.txt"]),
        runtimeTeardownDigest: "b".repeat(64),
        changedPaths: ["feature.txt"],
        staticFailures: [],
        sourceVolumeId: candidateVolumeId,
      },
    });

    const restarted = new TransitionWorker(state.config);
    await restarted.initialize();
    const types = (await restarted.log.transition(state.agentId, transitionId))
      .map((event) => event.type);
    expect(types).toContain("PROPOSAL_SEALED");
    expect(types).toContain("RUN_ARTIFACTS_DESTROYED");
    await expect(readFile(path.join(candidate, "feature.txt"), "utf8"))
      .rejects.toMatchObject({ code: "ENOENT" });
    await expect(readFile(path.join(proposal, "feature.txt"), "utf8"))
      .rejects.toMatchObject({ code: "ENOENT" });
    expect((await restarted.projection(state.agentId)).terminalReceipts.at(-1)?.decision)
      .toBe("ABORTED");
  });

  it("sweeps pre-intent staging, proposal and evidence blobs at startup", async () => {
    const state = await fixture();
    const orphanBlob = await state.worker.evidenceBlobs.put({ orphan: true });
    const authorityOrphan = path.join(state.config.workspaceRoot, ".cg-authority-orphan");
    const exportOrphan = path.join(state.config.inboxRoot, ".cg-export-orphan");
    const proposalOrphan = path.join(state.config.controlRoot, "proposals", "ghost", "proposal");
    for (const target of [authorityOrphan, exportOrphan, proposalOrphan]) {
      await mkdir(target, { recursive: true });
      await writeFile(path.join(target, "orphan.txt"), "orphan\n");
    }

    const restarted = new TransitionWorker(state.config);
    await restarted.initialize();
    for (const target of [authorityOrphan, exportOrphan, proposalOrphan]) {
      await expect(readFile(path.join(target, "orphan.txt"), "utf8"))
        .rejects.toMatchObject({ code: "ENOENT" });
    }
    await expect(restarted.evidenceBlobs.get(orphanBlob.blobId))
      .rejects.toMatchObject({ code: "EVIDENCE_BLOB_NOT_FOUND" });
  });
});
