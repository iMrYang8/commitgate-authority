import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { rpcRequestSchema, type RuntimeTeardownRecord } from "./contracts.js";
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
  const root = await mkdtemp(path.join(tmpdir(), "commitgate-runtime-handshake-"));
  roots.push(root);
  const config: TransitionWorkerConfig = {
    workspaceRoot: path.join(root, "workspaces"),
    controlRoot: path.join(root, "control"),
    inboxRoot: path.join(root, "exchange"),
    socketPath: path.join(root, "run", "worker.sock"),
    requireRuntimeTeardownHandshake: true,
  };
  const worker = new TransitionWorker(config);
  await worker.initialize();
  const initialized = await worker.initializeAgent({
    agentId: "agent-handshake",
    operationId: "init-handshake",
    headVersionId: "initial-handshake",
    generation: 1,
    sessionEpoch: 4,
    agentConfigVersion: 1,
    policyVersion: 1,
    name: "Runtime handshake fixture",
    instructions: "# trusted\n",
  });
  const prepared = await worker.prepareRun({
    agentId: "agent-handshake",
    transitionId: "run-handshake",
    runId: "run-handshake",
    runLeaseId: "lease-handshake",
    candidateVolumeId: "candidate-run-handshake",
    expectedViewId: initialized.head!.view.viewId,
    expectedWorkspaceHash: initialized.head!.workspaceHash,
    baseGeneration: initialized.head!.view.generation,
    sessionEpoch: initialized.head!.view.sessionEpoch,
  });
  const candidate = path.join(config.inboxRoot, prepared.relativeSubpath);
  await writeFile(path.join(candidate, "feature.ts"), "export const safe = true;\n");
  const artifactHash = (await buildWorkerManifest(candidate)).hash;
  const attestation = (scope: "AGENT" | "ALL"): RuntimeTeardownRecord => ({
    schemaVersion: 1,
    runId: "run-handshake",
    agentId: "agent-handshake",
    runLeaseId: "lease-handshake",
    sessionEpoch: 4,
    scope,
    containerExited: true,
    containerRemoved: true,
    mountsReleased: true,
    source: "broker-reconciliation",
  });
  return { root, config, worker, initialized, candidate, artifactHash, attestation };
}

describe("Transition Worker / Runtime Broker mount-release handshake", () => {
  it("keeps candidate and verifier bytes intact across restart until ALL teardown is recorded", async () => {
    const state = await fixture();
    const seal = {
      agentId: "agent-handshake",
      transitionId: "run-handshake",
      proposalId: "proposal-run-handshake",
      sourceVolumeId: "candidate-run-handshake",
      baseViewId: state.initialized.head!.view.viewId,
      expectedArtifactHash: state.artifactHash,
    };

    await expect(state.worker.sealProposal({
      ...seal,
      runtimeTeardownDigest: "a".repeat(64),
    })).rejects.toMatchObject({ code: "RUNTIME_TEARDOWN_REQUIRED" });
    expect(await readFile(path.join(state.candidate, "feature.ts"), "utf8"))
      .toContain("safe");
    await expect(state.worker.recoverAgent("agent-handshake"))
      .rejects.toMatchObject({ code: "RUNTIME_TEARDOWN_REQUIRED" });

    let projection = await state.worker.recordRuntimeTeardown({
      agentId: "agent-handshake",
      transitionId: "run-handshake",
      attestation: state.attestation("AGENT"),
    });
    const agentDigest = projection.transitions["run-handshake"]!
      .runtimeTeardownAgent!.digest;
    projection = await state.worker.sealProposal({
      ...seal,
      runtimeTeardownDigest: agentDigest,
    });
    expect(projection.proposals[seal.proposalId]?.state).toBe("SEALED");
    await state.worker.exportProposal({
      agentId: "agent-handshake",
      transitionId: "run-handshake",
      proposalId: seal.proposalId,
      exportVolumeId: "verify-run-handshake",
    });

    // Worker startup must remain available but must not remove a path that a
    // Broker-owned verifier could still have mounted.
    const restarted = new TransitionWorker(state.config);
    await expect(restarted.initialize()).resolves.toBeUndefined();
    projection = await restarted.projection("agent-handshake");
    expect(projection.transitions["run-handshake"]?.artifactsDestroyed).toBe(false);
    expect(projection.terminalReceipts).toHaveLength(0);
    expect(await readFile(path.join(
      state.config.inboxRoot,
      "verify-run-handshake",
      "feature.ts",
    ), "utf8")).toContain("safe");
    await expect(restarted.recoverAgent("agent-handshake"))
      .rejects.toMatchObject({ code: "RUNTIME_TEARDOWN_REQUIRED" });

    await restarted.recordRuntimeTeardown({
      agentId: "agent-handshake",
      transitionId: "run-handshake",
      attestation: state.attestation("ALL"),
    });
    projection = await restarted.recoverAgent("agent-handshake");
    expect(projection.terminalReceipts.at(-1)?.decision).toBe("ABORTED");
    expect(projection.transitions["run-handshake"]?.artifactsDestroyed).toBe(true);
    await expect(readFile(path.join(
      state.config.inboxRoot,
      "verify-run-handshake",
      "feature.ts",
    ), "utf8")).rejects.toMatchObject({ code: "ENOENT" });
    expect((await restarted.log.transition("agent-handshake", "run-handshake"))
      .filter((event) => event.type === "RUN_ARTIFACTS_DESTROYED"))
      .toHaveLength(1);
  });

  it("rejects incomplete or stale Broker attestations before they enter the event log", async () => {
    const state = await fixture();
    expect(rpcRequestSchema.safeParse({
      id: "rpc-handshake",
      method: "recordRuntimeTeardown",
      params: {
        agentId: "agent-handshake",
        transitionId: "run-handshake",
        attestation: {
          ...state.attestation("ALL"),
          mountsReleased: false,
        },
      },
    }).success).toBe(false);

    await expect(state.worker.recordRuntimeTeardown({
      agentId: "agent-handshake",
      transitionId: "run-handshake",
      attestation: {
        ...state.attestation("ALL"),
        runLeaseId: "stale-lease",
      },
    })).rejects.toMatchObject({ code: "RUNTIME_TEARDOWN_BINDING_INVALID" });
    expect((await state.worker.log.transition("agent-handshake", "run-handshake"))
      .some((event) => event.type === "RUNTIME_TEARDOWN_RECORDED"))
      .toBe(false);
  });
});
