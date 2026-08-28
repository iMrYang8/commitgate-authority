import { chmod, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { AgentRunner, RunnerRequest, RunnerResult } from "../types.js";
import { CommitGateRunner } from "./commitgate-runner.js";
import { CommitGateCoordinator, type CommitGateCoordinatorOptions } from "./coordinator.js";
import { defaultCommitGatePolicy } from "./policy.js";
import { buildManifest } from "./manifest.js";
import { createStateViewRef } from "./protocol.js";
import { recoverCommitGate } from "./recovery.js";
import type { CheckResult, GateReceipt, VerifierInput } from "./types.js";
import { FunctionVerifierRunner } from "./verifier-runner.js";
import { WorkspaceTransaction } from "./workspace-transaction.js";

const roots: string[] = [];
async function makeWritable(root: string): Promise<void> {
  await chmod(root, 0o700);
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const item = path.join(root, entry.name);
    if (entry.isDirectory()) await makeWritable(item);
    else await chmod(item, 0o600);
  }
}
afterEach(async () => {
  await Promise.all(roots.splice(0).map(async (root) => {
    await makeWritable(root).catch(() => undefined);
    await rm(root, { recursive: true, force: true });
  }));
});

async function setup(
  mutate: (request: RunnerRequest) => Promise<void>,
  verifier: (input: VerifierInput) => Promise<CheckResult[]> | CheckResult[] = () => [],
  overrides: Partial<CommitGateCoordinatorOptions> = {},
) {
  const root = await mkdtemp(path.join(tmpdir(), "commitgate-coordinator-"));
  roots.push(root);
  const workspaceRoot = path.join(root, "workspaces");
  const workspace = path.join(workspaceRoot, "agent-1");
  await import("node:fs/promises").then(({ mkdir }) => mkdir(workspace, { recursive: true }));
  await writeFile(path.join(workspace, "README.md"), "base\n");
  await writeFile(path.join(workspace, "AGENTS.md"), "managed\n");
  await writeFile(path.join(workspace, "protected.txt"), "do not change\n");
  const inner: AgentRunner = {
    run: async (request): Promise<RunnerResult> => {
      await mutate(request);
      return { output: "done", threadId: "thread-new", usage: null };
    },
    cancel: async () => false,
    isAvailable: async () => true,
  };
  const coordinator = new CommitGateCoordinator({
    ...overrides,
    workspaceRoot,
    verifier: new FunctionVerifierRunner(verifier),
  });
  const runner = new CommitGateRunner(inner, coordinator, { autoAcknowledge: true });
  return { root, workspaceRoot, workspace, coordinator, runner };
}

function request(workspacePath: string, runId = "run-1"): RunnerRequest {
  return { runId, agentId: "agent-1", workspacePath, prompt: "edit", threadId: "thread-old" };
}

describe("CommitGateRunner", () => {
  it("promotes a valid candidate and records INITIAL plus AGENT_COMMIT", async () => {
    const { workspace, coordinator, runner } = await setup(async (input) => {
      await writeFile(path.join(input.workspacePath, "README.md"), "candidate\n");
    });
    const provider = {
      providerId: "openrouter" as const,
      gateway: "https://openrouter.example/api/v1",
      requestedModel: "deepseek/deepseek-v4-flash",
      // The Responses gateway did not report a resolved model in this fixture.
      resolvedModel: null,
    };
    const result = await runner.run({ ...request(workspace), provider });
    expect(result.commitGate.decision).toBe("COMMITTED");
    expect(result.threadId).toBe("thread-new");
    expect(await readFile(path.join(workspace, "README.md"), "utf8")).toBe("candidate\n");
    expect((await coordinator.versionStore.list("agent-1")).map((version) => version.kind)).toEqual([
      "AGENT_COMMIT",
      "INITIAL",
    ]);
    const receipt = await coordinator.receiptStore.get("agent-1", "run-1");
    expect(receipt).toMatchObject({
      schemaVersion: 2,
      phase: "TERMINAL",
      transactionStatus: "TERMINAL",
      decision: "COMMITTED",
      promotionPendingDatabaseAck: false,
      provider,
    });
    expect(receipt?.baseGeneration).toBe(1);
    expect(receipt?.nextGeneration).toBe(2);
    expect(receipt?.generation).toBe(2);
    expect(receipt?.baseView?.generation).toBe(1);
    expect(receipt?.nextView?.generation).toBe(2);
    expect(result.commitGate).toMatchObject({
      baseGeneration: 1,
      nextGeneration: 2,
    });
    await expect(
      coordinator.attemptConsumedPermitReplay({
        agentId: "agent-1",
        runId: "run-1",
        permitId: receipt!.permitId!,
        expectedCurrentViewId: receipt!.finalViewId!,
      }),
    ).resolves.toEqual({ code: "PERMIT_REPLAY", permitState: "CONSUMED" });
    expect(result.commitGate.provider).toEqual(provider);
    await expect(
      coordinator.receiptStore.put({
        ...receipt!,
        reasonCodes: ["attempted rewrite"],
      }),
    ).rejects.toThrow("TERMINAL_RECEIPT_IMMUTABLE");
  });

  it("quarantines protected changes, preserves persistent state, and resets thread", async () => {
    const { workspace, coordinator, runner } = await setup(async (input) => {
      await writeFile(path.join(input.workspacePath, "protected.txt"), "tampered\n");
    });
    const result = await runner.run(request(workspace));
    expect(result.commitGate).toMatchObject({ decision: "QUARANTINED", failureClass: "agent_wrong" });
    expect(result.commitGate).toMatchObject({ baseGeneration: 1, nextGeneration: 1 });
    expect(result.threadId).toBeNull();
    expect(await readFile(path.join(workspace, "protected.txt"), "utf8")).toBe("do not change\n");
    expect(await coordinator.versionStore.list("agent-1")).toHaveLength(1);
  });

  it("uses trusted check exit evidence rather than candidate-authored scripts", async () => {
    const failure: CheckResult = {
      id: "contract",
      status: "FAIL",
      exitCode: 1,
      durationMs: 4,
      output: "contract mismatch",
      timedOut: false,
    };
    const { workspace, coordinator } = await setup(async () => undefined, () => [failure]);
    const prepared = await coordinator.prepare({
      runId: "run-check",
      agentId: "agent-1",
      persistentPath: workspace,
      policy: {
        ...defaultCommitGatePolicy,
        requiredChecks: [{
          id: "contract",
          runner: "node",
          entrypoint: "contract.mjs",
          args: [],
          timeoutMs: 10_000,
          scratchBytes: 1_048_576,
        }],
      },
    });
    await writeFile(path.join(prepared.candidatePath, "package.json"), '{"scripts":{"test":"exit 0"}}\n');
    const result = await coordinator.verifyAndFinalize(prepared);
    expect(result.receipt).toMatchObject({ decision: "QUARANTINED", failureClass: "agent_wrong" });
    expect(result.receipt.reasonCodes).toContain("TRUSTED_CHECK_FAILED:contract");
  });

  it("detects a persistent-state conflict during independent verification", async () => {
    let persistent = "";
    const fixture = await setup(
      async (input) => writeFile(path.join(input.workspacePath, "README.md"), "candidate\n"),
      async () => {
        await writeFile(path.join(persistent, "README.md"), "external writer\n");
        return [];
      },
    );
    persistent = fixture.workspace;
    const result = await fixture.runner.run(request(fixture.workspace));
    expect(result.commitGate).toMatchObject({ decision: "CONFLICTED", failureClass: "state_conflict" });
    expect(await readFile(path.join(fixture.workspace, "README.md"), "utf8")).toBe("external writer\n");
  });

  it("fails closed on ignored ephemeral file-count and byte DoS before sealing", async () => {
    const fileCount = await setup(
      async (input) => {
        const ignored = path.join(input.workspacePath, "node_modules", "attack");
        await mkdir(ignored, { recursive: true });
        await Promise.all(
          ["a", "b", "c"].map((name) =>
            writeFile(path.join(ignored, name), name),
          ),
        );
      },
      undefined,
      {
        candidateResourceLimits: {
          maxIgnoredEntries: 3,
          maxIgnoredBytes: 100,
          maxIgnoredSingleFileBytes: 100,
        },
      },
    );
    const fileResult = await fileCount.runner.run(
      request(fileCount.workspace, "ignored-file-dos"),
    );
    expect(fileResult.commitGate).toMatchObject({
      decision: "QUARANTINED",
      failureClass: "agent_wrong",
    });
    expect(
      (await fileCount.coordinator.receiptStore.get("agent-1", "ignored-file-dos"))
        ?.reasonCodes,
    ).toEqual(
      expect.arrayContaining([
        expect.stringContaining("IGNORED_EPHEMERAL_FILE_BUDGET_EXCEEDED"),
      ]),
    );
    expect(await readFile(path.join(fileCount.workspace, "README.md"), "utf8")).toBe(
      "base\n",
    );

    const bytes = await setup(
      async (input) => {
        const ignored = path.join(input.workspacePath, "coverage");
        await mkdir(ignored, { recursive: true });
        await writeFile(path.join(ignored, "blob"), "0123456789abcdef");
      },
      undefined,
      {
        candidateResourceLimits: {
          maxIgnoredEntries: 10,
          maxIgnoredBytes: 8,
          maxIgnoredSingleFileBytes: 32,
        },
      },
    );
    const byteResult = await bytes.runner.run(
      request(bytes.workspace, "ignored-byte-dos"),
    );
    expect(byteResult.commitGate).toMatchObject({
      decision: "QUARANTINED",
      failureClass: "agent_wrong",
    });
    expect(
      (await bytes.coordinator.receiptStore.get("agent-1", "ignored-byte-dos"))
        ?.reasonCodes,
    ).toEqual(
      expect.arrayContaining([
        expect.stringContaining("IGNORED_EPHEMERAL_BYTE_BUDGET_EXCEEDED"),
      ]),
    );
  });

  it("detects H0 to H1 to H0 ABA through the authoritative generation", async () => {
    let generation = 10;
    const fixture = await setup(
      async (input) => writeFile(path.join(input.workspacePath, "README.md"), "candidate\n"),
      async () => {
        // Bytes remain H0, but another authoritative transition advanced the
        // product generation twice before our permit was minted.
        generation = 12;
        return [];
      },
      {
        stateViewProvider: {
          capture: (input) =>
            createStateViewRef({
              schemaVersion: 1,
              agentId: input.agentId,
              headVersionId: `external-v${generation}`,
              generation,
              versionedHash: input.versionedHash,
              platformManagedHash: input.platformManagedHash,
              liveStateHash: input.liveStateHash,
              sessionEpoch: input.sessionEpoch,
              agentConfigVersion: input.agentConfigVersion,
              policyVersion: input.policyVersion,
            }),
        },
      },
    );
    const result = await fixture.runner.run(request(fixture.workspace, "aba-run"));
    expect(result.commitGate).toMatchObject({
      decision: "CONFLICTED",
      failureClass: "state_conflict",
    });
    expect(await readFile(path.join(fixture.workspace, "README.md"), "utf8")).toBe("base\n");
  });

  it("stores an ABORTED receipt when the wrapped runner fails", async () => {
    const { workspace, coordinator } = await setup(async () => undefined);
    const failing: AgentRunner = {
      run: async () => { throw new Error("runner exploded"); },
      cancel: async () => false,
      isAvailable: async () => true,
    };
    const runner = new CommitGateRunner(failing, coordinator);
    await expect(runner.run(request(workspace, "run-fail"))).rejects.toThrow("runner exploded");
    expect(await coordinator.receiptStore.get("agent-1", "run-fail")).toMatchObject({ decision: "ABORTED" });
  });

  it("writes a minimum CONFLICTED receipt when StateView admission fails", async () => {
    const { workspace, coordinator, runner } = await setup(async () => {
      throw new Error("Agent runtime must not execute after admission conflict");
    });
    const baseLiveStateHash = (await buildManifest(workspace, defaultCommitGatePolicy)).hash;
    const result = await runner.run({
      ...request(workspace, "admission-view-conflict"),
      baseViewId: "f".repeat(64),
      baseLiveStateHash,
      stateGeneration: 1,
      sessionEpoch: 0,
    });
    expect(result.commitGate).toMatchObject({
      decision: "CONFLICTED",
      failureClass: "state_conflict",
      candidateHash: null,
    });
    expect(
      await coordinator.receiptStore.get("agent-1", "admission-view-conflict"),
    ).toMatchObject({
      phase: "PENDING_DISPOSITION",
      decision: "CONFLICTED",
      artifactRetention: "destroyed",
    });
  });

  it("writes a minimum ABORTED receipt when prepare infrastructure fails", async () => {
    const { workspace, coordinator, runner } = await setup(async () => undefined);
    const baseLiveStateHash = (await buildManifest(workspace, defaultCommitGatePolicy)).hash;
    const missing = path.join(path.dirname(workspace), "missing-agent-workspace");
    const provider = {
      providerId: "ark" as const,
      gateway: "https://ark.example/api/v3",
      requestedModel: "ep-requested",
      resolvedModel: null,
    };
    await expect(
      runner.run({
        ...request(missing, "admission-prepare-aborted"),
        baseViewId: "e".repeat(64),
        baseLiveStateHash,
        stateGeneration: 1,
        sessionEpoch: 0,
        provider,
      }),
    ).rejects.toThrow();
    expect(
      await coordinator.receiptStore.get("agent-1", "admission-prepare-aborted"),
    ).toMatchObject({
      phase: "PENDING_DISPOSITION",
      decision: "ABORTED",
      candidateCleanup: "deleted",
      provider,
    });
  });

  it("dispositions a pre-swap pending receipt that has no journal", async () => {
    const { workspace, workspaceRoot, coordinator } = await setup(
      async () => undefined,
    );
    await coordinator.initializeAgent("agent-1", workspace);
    const baseHash = (await buildManifest(workspace, defaultCommitGatePolicy)).hash;
    const pending: GateReceipt = {
      schemaVersion: 1,
      runId: "pre-swap-crash",
      agentId: "agent-1",
      phase: "PENDING_PROMOTION",
      decision: "COMMITTED",
      failureClass: null,
      reasonCodes: [],
      baseSnapshotHash: baseHash,
      candidateSnapshotHash: "b".repeat(64),
      patchHash: "c".repeat(64),
      finalSnapshotHash: "b".repeat(64),
      policyHash: "d".repeat(64),
      evidence: { static: "complete", trustedChecks: "complete" },
      checks: [],
      changedPaths: ["README.md"],
      threadDisposition: "resumed",
      candidateCleanup: "deleted",
      sessionEpoch: 0,
      versionId: null,
      promotionPendingDatabaseAck: true,
      transactionStatus: "PENDING_PROMOTION",
      artifactRetention: "sealed",
      provider: null,
      startedAt: new Date(0).toISOString(),
      completedAt: new Date(1).toISOString(),
    };
    await coordinator.receiptStore.put(pending);

    const report = await recoverCommitGate({
      workspaceRoot,
      transaction: new WorkspaceTransaction(),
    });

    expect(report.actions).toContainEqual(
      expect.objectContaining({
        runId: pending.runId,
        action: "rolled_back",
      }),
    );
    expect(await coordinator.receiptStore.get("agent-1", pending.runId)).toMatchObject({
      phase: "TERMINAL",
      decision: "ABORTED",
      transactionStatus: "TERMINAL",
      finalSnapshotHash: baseHash,
      threadDisposition: "reset",
    });
  });

  it("fails closed after a crash before database acknowledgement", async () => {
    const { workspace, workspaceRoot, coordinator } = await setup(async () => undefined);
    const prepared = await coordinator.prepare({
      runId: "run-crash",
      agentId: "agent-1",
      persistentPath: workspace,
    });
    await writeFile(path.join(prepared.candidatePath, "README.md"), "unacknowledged\n");
    const finalization = await coordinator.verifyAndFinalize(prepared);
    expect(finalization.receipt).toMatchObject({
      phase: "PENDING_PROMOTION",
      decision: "COMMITTED",
      promotionPendingDatabaseAck: true,
    });
    expect(await readFile(path.join(workspace, "README.md"), "utf8")).toBe("unacknowledged\n");

    const report = await recoverCommitGate({
      workspaceRoot,
      transaction: new WorkspaceTransaction(),
    });
    expect(report.healthy).toBe(true);
    expect(report.actions).toEqual(
      expect.arrayContaining([expect.objectContaining({ runId: "run-crash", action: "rolled_back" })]),
    );
    expect(await readFile(path.join(workspace, "README.md"), "utf8")).toBe("base\n");
    expect(await coordinator.receiptStore.get("agent-1", "run-crash")).toMatchObject({
      decision: "ABORTED",
      promotionPendingDatabaseAck: false,
      threadDisposition: "reset",
    });
  });

  it("preserves a legacy terminal receipt and appends recovery disposition", async () => {
    const { workspace, workspaceRoot, coordinator } = await setup(
      async () => undefined,
    );
    const prepared = await coordinator.prepare({
      runId: "legacy-terminal-crash",
      agentId: "agent-1",
      persistentPath: workspace,
    });
    await writeFile(path.join(prepared.candidatePath, "README.md"), "legacy promoted\n");
    await coordinator.verifyAndFinalize(prepared);
    const pending = (await coordinator.receiptStore.get(
      "agent-1",
      prepared.runId,
    ))!;
    const legacy = { ...pending, phase: "TERMINAL" as const };
    delete legacy.transactionStatus;
    await coordinator.receiptStore.put(legacy);

    const report = await recoverCommitGate({
      workspaceRoot,
      transaction: new WorkspaceTransaction(),
    });

    expect(report.actions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          runId: prepared.runId,
          action: "rolled_back",
        }),
      ]),
    );
    expect(await coordinator.receiptStore.get("agent-1", prepared.runId)).toEqual(
      legacy,
    );
    expect(
      await coordinator.receiptStore.listRecoveryEvents(
        "agent-1",
        prepared.runId,
      ),
    ).toEqual([
      expect.objectContaining({
        type: "RECOVERY_ROLLED_BACK",
        originalDecision: "COMMITTED",
        effectiveDecision: "ABORTED",
      }),
    ]);
  });
});
