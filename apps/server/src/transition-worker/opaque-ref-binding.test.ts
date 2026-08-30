import { lstat, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { mkdtemp } from "node:fs/promises";
import { afterEach, describe, expect, it } from "vitest";
import { DEFAULT_IGNORED_EPHEMERAL_NAMES } from "../commitgate/policy.js";
import { buildWorkerManifest, makeTreeWritable } from "./filesystem.js";
import { TransitionWorker, type TransitionWorkerConfig } from "./worker.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map(async (root) => {
    await makeTreeWritable(root).catch(() => undefined);
    await rm(root, { recursive: true, force: true });
  }));
});

async function fixture() {
  const root = await mkdtemp(path.join(tmpdir(), "commitgate-opaque-ref-"));
  roots.push(root);
  const config: TransitionWorkerConfig = {
    workspaceRoot: path.join(root, "workspaces"),
    controlRoot: path.join(root, "control"),
    inboxRoot: path.join(root, "exchange"),
    socketPath: path.join(root, "run", "worker.sock"),
    sourceRevision: "opaque-ref-test",
  };
  const worker = new TransitionWorker(config);
  await worker.initialize();
  return { config, worker };
}

async function initializeAgent(worker: TransitionWorker, agentId: string) {
  return worker.initializeAgent({
    agentId,
    operationId: `init-${agentId}`,
    headVersionId: `initial-${agentId}`,
    generation: 1,
    sessionEpoch: 0,
    agentConfigVersion: 1,
    policyVersion: 1,
    name: "Opaque ref fixture",
    instructions: "# trusted\n",
  });
}

describe("TransitionWorker opaque exchange-ref binding", () => {
  it("derives candidate-${runId}, rejects caller-selected refs, and tombstones cross-Agent reuse", async () => {
    const { config, worker } = await fixture();
    const first = await initializeAgent(worker, "agent-a");
    const second = await initializeAgent(worker, "agent-b");

    const base = {
      agentId: "agent-a",
      transitionId: "run-a",
      runId: "run-a",
      runLeaseId: "lease-a",
      expectedViewId: first.head!.view.viewId,
      expectedWorkspaceHash: first.head!.workspaceHash,
      baseGeneration: first.head!.view.generation,
    };
    await expect(worker.prepareRun({
      ...base,
      candidateVolumeId: "candidate-caller-selected",
    })).rejects.toMatchObject({ code: "CANDIDATE_REF_BINDING_MISMATCH" });
    await expect(worker.prepareRun({
      ...base,
      transitionId: "other-transition",
      candidateVolumeId: "candidate-run-a",
    })).rejects.toMatchObject({ code: "RUN_BINDING_INVALID" });
    expect((await worker.projection("agent-a")).transitions).toEqual({});

    const unowned = path.join(config.inboxRoot, "candidate-run-poisoned");
    await mkdir(unowned, { recursive: true });
    await writeFile(path.join(unowned, "foreign.txt"), "foreign bytes\n");
    const poisoned = {
      ...base,
      transitionId: "run-poisoned",
      runId: "run-poisoned",
      runLeaseId: "lease-poisoned",
      candidateVolumeId: "candidate-run-poisoned",
    };
    await expect(worker.prepareRun(poisoned))
      .rejects.toMatchObject({ code: "EXCHANGE_REF_OCCUPIED" });
    await expect(worker.prepareRun(poisoned))
      .rejects.toMatchObject({ code: "EXCHANGE_REF_OCCUPIED" });
    expect(await readFile(path.join(unowned, "foreign.txt"), "utf8"))
      .toBe("foreign bytes\n");

    const prepared = await worker.prepareRun({
      ...base,
      transitionId: "run-shared",
      runId: "run-shared",
      runLeaseId: "lease-shared-a",
      candidateVolumeId: "candidate-run-shared",
    });
    expect(prepared).toMatchObject({
      candidateVolumeId: "candidate-run-shared",
      relativeSubpath: "candidate-run-shared",
    });
    const candidate = path.join(config.inboxRoot, prepared.relativeSubpath);
    const candidateMetadata = await lstat(candidate, { bigint: true });
    for (const relative of DEFAULT_IGNORED_EPHEMERAL_NAMES) {
      const target = path.join(candidate, relative);
      const metadata = await lstat(target, { bigint: true });
      expect(metadata.isDirectory()).toBe(true);
      expect(metadata.isSymbolicLink()).toBe(false);
      expect(metadata.uid).toBe(candidateMetadata.uid);
      expect(metadata.gid).toBe(candidateMetadata.gid);
      expect(Number(metadata.mode & 0o777n)).toBe(0o700);
      expect(await readdir(target)).toEqual([]);
    }
    const preparedManifest = await buildWorkerManifest(candidate);
    expect(preparedManifest.hash).toBe(prepared.candidateHash);
    expect(preparedManifest.resourceUsage.ignoredEntries)
      .toBe(DEFAULT_IGNORED_EPHEMERAL_NAMES.length);
    expect(preparedManifest.entries.some((entry) =>
      DEFAULT_IGNORED_EPHEMERAL_NAMES.includes(
        entry.path as (typeof DEFAULT_IGNORED_EPHEMERAL_NAMES)[number],
      )
    )).toBe(false);

    await expect(worker.prepareRun({
      agentId: "agent-b",
      transitionId: "run-shared",
      runId: "run-shared",
      runLeaseId: "lease-shared-b",
      candidateVolumeId: "candidate-run-shared",
      expectedViewId: second.head!.view.viewId,
      expectedWorkspaceHash: second.head!.workspaceHash,
      baseGeneration: second.head!.view.generation,
    })).rejects.toMatchObject({ code: "EXCHANGE_REF_OCCUPIED" });
    expect((await worker.projection("agent-b")).transitions).toEqual({});
  });

  it("seals only the transition's durable candidate and never adopts an unbound export", async () => {
    const { config, worker } = await fixture();
    const initialized = await initializeAgent(worker, "agent-seal");
    const prepared = await worker.prepareRun({
      agentId: "agent-seal",
      transitionId: "run-seal",
      runId: "run-seal",
      runLeaseId: "lease-seal",
      candidateVolumeId: "candidate-run-seal",
      expectedViewId: initialized.head!.view.viewId,
      expectedWorkspaceHash: initialized.head!.workspaceHash,
      baseGeneration: initialized.head!.view.generation,
    });
    const candidate = path.join(config.inboxRoot, prepared.relativeSubpath);
    await writeFile(path.join(candidate, "feature.ts"), "export const sealed = true;\n");
    const artifactHash = (await buildWorkerManifest(candidate)).hash;
    const foreignCandidate = path.join(config.inboxRoot, "candidate-foreign");
    await mkdir(foreignCandidate);
    await writeFile(path.join(foreignCandidate, "foreign.txt"), "do not consume\n");

    await expect(worker.sealProposal({
      agentId: "agent-seal",
      transitionId: "run-seal",
      proposalId: "proposal-seal",
      sourceVolumeId: "candidate-foreign",
      baseViewId: initialized.head!.view.viewId,
      expectedArtifactHash: artifactHash,
      runtimeTeardownDigest: "a".repeat(64),
    })).rejects.toMatchObject({ code: "CANDIDATE_REF_BINDING_MISMATCH" });
    expect(await readFile(path.join(foreignCandidate, "foreign.txt"), "utf8"))
      .toBe("do not consume\n");

    await worker.sealProposal({
      agentId: "agent-seal",
      transitionId: "run-seal",
      proposalId: "proposal-seal",
      sourceVolumeId: "candidate-run-seal",
      baseViewId: initialized.head!.view.viewId,
      expectedArtifactHash: artifactHash,
      runtimeTeardownDigest: "a".repeat(64),
    });
    await expect(worker.sealProposal({
      agentId: "agent-seal",
      transitionId: "run-seal",
      proposalId: "proposal-seal",
      sourceVolumeId: "candidate-foreign",
      baseViewId: initialized.head!.view.viewId,
      expectedArtifactHash: artifactHash,
      runtimeTeardownDigest: "a".repeat(64),
    })).rejects.toMatchObject({ code: "CANDIDATE_REF_BINDING_MISMATCH" });

    const wrongExport = path.join(config.inboxRoot, "verify-other-run");
    await mkdir(wrongExport);
    await writeFile(path.join(wrongExport, "foreign.txt"), "other run\n");
    await expect(worker.exportProposal({
      agentId: "agent-seal",
      transitionId: "run-seal",
      proposalId: "proposal-seal",
      exportVolumeId: "verify-other-run",
    })).rejects.toMatchObject({ code: "VERIFIER_REF_BINDING_MISMATCH" });
    expect(await readFile(path.join(wrongExport, "foreign.txt"), "utf8"))
      .toBe("other run\n");

    const exactButUnowned = path.join(config.inboxRoot, "verify-run-seal");
    await mkdir(exactButUnowned);
    await writeFile(path.join(exactButUnowned, "foreign.txt"), "unbound exact path\n");
    const exportRequest = {
      agentId: "agent-seal",
      transitionId: "run-seal",
      proposalId: "proposal-seal",
      exportVolumeId: "verify-run-seal",
    };
    await expect(worker.exportProposal(exportRequest))
      .rejects.toMatchObject({ code: "EXCHANGE_REF_OCCUPIED" });
    await expect(worker.exportProposal(exportRequest))
      .rejects.toMatchObject({ code: "EXCHANGE_REF_OCCUPIED" });
    expect(await readFile(path.join(exactButUnowned, "foreign.txt"), "utf8"))
      .toBe("unbound exact path\n");
    expect((await worker.projection("agent-seal")).proposals["proposal-seal"]?.exportVolumeIds)
      .toEqual([]);
  });

  it("exports only verify-${runId} and cannot overwrite another run's export", async () => {
    const { config, worker } = await fixture();
    const first = await initializeAgent(worker, "agent-export-a");
    const second = await initializeAgent(worker, "agent-export-b");

    const seal = async (agentId: string, runId: string, head: typeof first.head) => {
      const candidateVolumeId = `candidate-${runId}`;
      const proposalId = `proposal-${runId}`;
      const prepared = await worker.prepareRun({
        agentId,
        transitionId: runId,
        runId,
        runLeaseId: `lease-${runId}`,
        candidateVolumeId,
        expectedViewId: head!.view.viewId,
        expectedWorkspaceHash: head!.workspaceHash,
        baseGeneration: head!.view.generation,
      });
      const candidate = path.join(config.inboxRoot, prepared.relativeSubpath);
      await writeFile(path.join(candidate, "feature.txt"), `${agentId}\n`);
      const artifactHash = (await buildWorkerManifest(candidate)).hash;
      await worker.sealProposal({
        agentId,
        transitionId: runId,
        proposalId,
        sourceVolumeId: candidateVolumeId,
        baseViewId: head!.view.viewId,
        expectedArtifactHash: artifactHash,
        runtimeTeardownDigest: "b".repeat(64),
      });
      return { proposalId, artifactHash };
    };

    const proposalA = await seal("agent-export-a", "run-export-a", first.head);
    const exportedA = await worker.exportProposal({
      agentId: "agent-export-a",
      transitionId: "run-export-a",
      proposalId: proposalA.proposalId,
      exportVolumeId: "verify-run-export-a",
    });
    expect(exportedA).toMatchObject({
      exportVolumeId: "verify-run-export-a",
      relativeSubpath: "verify-run-export-a",
      artifactHash: proposalA.artifactHash,
    });

    const proposalB = await seal("agent-export-b", "run-export-b", second.head);
    await expect(worker.exportProposal({
      agentId: "agent-export-b",
      transitionId: "run-export-b",
      proposalId: proposalB.proposalId,
      exportVolumeId: "verify-run-export-a",
    })).rejects.toMatchObject({ code: "VERIFIER_REF_BINDING_MISMATCH" });
    expect((await buildWorkerManifest(path.join(config.inboxRoot, "verify-run-export-a"))).hash)
      .toBe(proposalA.artifactHash);

    const exportedB = await worker.exportProposal({
      agentId: "agent-export-b",
      transitionId: "run-export-b",
      proposalId: proposalB.proposalId,
      exportVolumeId: "verify-run-export-b",
    });
    expect(exportedB.artifactHash).toBe(proposalB.artifactHash);
  });
});
