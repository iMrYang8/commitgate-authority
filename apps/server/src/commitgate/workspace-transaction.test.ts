import {
  chmod,
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CommitGateRecoveryRequiredError } from "../errors.js";
import { writeJsonAtomic } from "./atomic-json.js";
import { copyWorkspace } from "./file-ops.js";
import { buildManifest } from "./manifest.js";
import { defaultCommitGatePolicy } from "./policy.js";
import { PromotionPermitStore } from "./promotion-permit-store.js";
import { createEvidenceBundle, createStateViewRef, sha256Canonical } from "./protocol.js";
import { recoverCommitGate } from "./recovery.js";
import { RollbackPermitStore } from "./rollback-permit-store.js";
import { SealedProposalStore, runtimeTeardownDigest } from "./sealed-proposal-store.js";
import { WorkspaceTransaction } from "./workspace-transaction.js";

const roots: string[] = [];

async function makeWritable(root: string): Promise<void> {
  await chmod(root, 0o700);
  const entries = await readdir(root, { withFileTypes: true });
  await Promise.all(
    entries.map(async (entry) => {
      const item = path.join(root, entry.name);
      if (entry.isDirectory()) {
        await makeWritable(item);
      } else {
        await chmod(item, 0o600);
      }
    }),
  );
}

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map(async (root) => {
      await makeWritable(root).catch(() => undefined);
      await rm(root, { recursive: true, force: true });
    }),
  );
});

async function fixture() {
  const root = await mkdtemp(path.join(tmpdir(), "commitgate-transaction-"));
  roots.push(root);
  const workspaceRoot = path.join(root, "workspaces");
  const persistentPath = path.join(workspaceRoot, "agent");
  const controlPath = path.join(workspaceRoot, ".commitgate", "agent");
  const sourcePath = path.join(controlPath, "candidates", "source");
  await mkdir(persistentPath, { recursive: true });
  await mkdir(controlPath, { recursive: true });
  await mkdir(sourcePath, { recursive: true });
  await writeFile(path.join(persistentPath, "README.md"), "base\n");
  await writeFile(path.join(persistentPath, "AGENTS.md"), "managed\n");
  await writeFile(path.join(sourcePath, "README.md"), "candidate\n");
  await writeFile(path.join(sourcePath, "AGENTS.md"), "managed\n");
  await writeFile(
    path.join(controlPath, "policy.json"),
    JSON.stringify(defaultCommitGatePolicy),
    "utf8",
  );
  const baseHash = (await buildManifest(persistentPath, defaultCommitGatePolicy)).hash;
  return { workspaceRoot, persistentPath, controlPath, sourcePath, baseHash };
}

async function authorizedPromotion(
  input: Awaited<ReturnType<typeof fixture>>,
  runId: string,
) {
  const baseManifest = await buildManifest(input.persistentPath, defaultCommitGatePolicy);
  const baseVersioned = await buildManifest(input.persistentPath, defaultCommitGatePolicy, {
    include: new Set(["versioned"]),
  });
  const basePlatform = await buildManifest(input.persistentPath, defaultCommitGatePolicy, {
    include: new Set(["platformManaged"]),
  });
  const baseView = createStateViewRef({
    schemaVersion: 1,
    agentId: "agent",
    headVersionId: "version-base",
    generation: 1,
    versionedHash: baseVersioned.hash,
    platformManagedHash: basePlatform.hash,
    liveStateHash: baseManifest.hash,
    sessionEpoch: 0,
    agentConfigVersion: 1,
    policyVersion: 1,
  });
  const candidateManifest = await buildManifest(input.sourcePath, defaultCommitGatePolicy);
  const proposals = new SealedProposalStore();
  const sealed = await proposals.seal({
    runId,
    agentId: "agent",
    controlPath: input.controlPath,
    candidatePath: input.sourcePath,
    baseViewId: baseView.viewId,
    policy: defaultCommitGatePolicy,
    changedPathsDigest: sha256Canonical([]),
    runtimeTeardownDigest: runtimeTeardownDigest({ removed: true }),
    expectedCandidateHash: candidateManifest.hash,
  });
  const evaluationContextHash = sha256Canonical({ runId, context: "test" });
  const evidence = createEvidenceBundle({
    proposalId: sealed.proposal.proposalId,
    evaluationContextHash,
    verifierInputHash: sealed.proposal.manifestHash,
    checkResultsHash: sha256Canonical([{ id: "trusted", status: "PASS" }]),
    coverage: "complete",
    requiredChecksPassed: true,
    issuedAt: new Date(0).toISOString(),
  });
  const permits = new PromotionPermitStore(() => new Date("2099-01-01T00:00:00Z"));
  const permit = await permits.issue({
    runId,
    agentId: "agent",
    controlPath: input.controlPath,
    proposal: sealed.proposal,
    baseView,
    evaluationContextHash,
    evidence,
  });
  const capability = await permits.claim({
    agentId: "agent",
    controlPath: input.controlPath,
    permitId: permit.permitId,
    proposal: sealed.proposal,
    proposalPath: sealed.payloadPath,
    proposalManifest: sealed.manifest,
    baseView,
    evaluationContextHash,
    evidenceDigest: evidence.digest,
  });
  return {
    runId,
    agentId: "agent",
    persistentPath: input.persistentPath,
    controlPath: input.controlPath,
    policy: defaultCommitGatePolicy,
    capability,
    assertCurrentView: () => true,
  };
}

describe("WorkspaceTransaction rename-swap recovery", () => {
  it("cannot reuse the same consumed capability for a no-op promotion", async () => {
    const input = await fixture();
    await writeFile(path.join(input.sourcePath, "README.md"), "base\n");
    const authorized = await authorizedPromotion(input, "noop-capability-replay");
    const transaction = new WorkspaceTransaction();
    const first = await transaction.promoteAuthorized(authorized);
    await first.acknowledge();

    await expect(transaction.promoteAuthorized(authorized)).rejects.toMatchObject({
      code: "PERMIT_REPLAY",
    });
    expect(await readFile(path.join(input.persistentPath, "README.md"), "utf8")).toBe(
      "base\n",
    );
  });

  it("rejects a rollback snapshot changed during import before any swap", async () => {
    const input = await fixture();
    const snapshotPath = path.join(input.controlPath, "snapshots", "snapshot-v1");
    await mkdir(snapshotPath, { recursive: true });
    await writeFile(path.join(snapshotPath, "README.md"), "snapshot-v1\n");
    const snapshotHash = (
      await buildManifest(snapshotPath, defaultCommitGatePolicy, {
        include: new Set(["versioned"]),
      })
    ).hash;
    const permits = new RollbackPermitStore(() => new Date("2099-01-01T00:00:00Z"));
    const permit = await permits.issue({
      runId: "rollback-toctou",
      agentId: "agent",
      controlPath: input.controlPath,
      targetVersionId: "version-v1",
      targetSnapshotHash: snapshotHash,
      expectedHeadVersionId: "version-v2",
      baseHash: input.baseHash,
    });
    const capability = await permits.claim({
      controlPath: input.controlPath,
      rollbackPermitId: permit.rollbackPermitId,
      snapshotPath,
      targetVersionId: permit.targetVersionId,
      targetSnapshotHash: permit.targetSnapshotHash,
      expectedHeadVersionId: permit.expectedHeadVersionId,
      baseHash: permit.baseHash,
    });
    const transaction = new WorkspaceTransaction({
      copyWorkspace: async (source, destination, policy, options) => {
        await copyWorkspace(source, destination, policy, options);
        if (source === snapshotPath) {
          await writeFile(path.join(destination, "README.md"), "switched bytes\n");
        }
      },
    });

    await expect(
      transaction.rollbackAuthorized({
        persistentPath: input.persistentPath,
        controlPath: input.controlPath,
        policy: defaultCommitGatePolicy,
        capability,
      }),
    ).rejects.toThrow("Rollback staging bytes do not match the permitted snapshot");
    expect(await readFile(path.join(input.persistentPath, "README.md"), "utf8")).toBe(
      "base\n",
    );
    expect((await permits.get(input.controlPath, permit.rollbackPermitId)).state).toBe(
      "CONSUMING",
    );
  });

  it("restores the backup when the staging rename fails", async () => {
    const input = await fixture();
    let calls = 0;
    const transaction = new WorkspaceTransaction({
      rename: async (source, destination) => {
        calls += 1;
        if (calls === 2) throw new Error("injected second rename failure");
        await rename(source, destination);
      },
    });

    await expect(
      transaction.promoteAuthorized(await authorizedPromotion(input, "rename-failure")),
    ).rejects.toThrow("injected second rename failure");
    expect(await readFile(path.join(input.persistentPath, "README.md"), "utf8")).toBe(
      "base\n",
    );
    const journal = JSON.parse(
      await readFile(
        path.join(input.controlPath, "journals", "rename-failure.json"),
        "utf8",
      ),
    );
    expect(journal.state).toBe("ROLLED_BACK");
  });

  it("raises recovery-required when both staging rename and backup restore fail", async () => {
    const input = await fixture();
    let calls = 0;
    const transaction = new WorkspaceTransaction({
      rename: async (source, destination) => {
        calls += 1;
        if (calls === 2 || calls === 3) {
          throw new Error(`injected rename failure ${calls}`);
        }
        await rename(source, destination);
      },
    });

    await expect(
      transaction.promoteAuthorized(await authorizedPromotion(input, "restore-failure")),
    ).rejects.toBeInstanceOf(CommitGateRecoveryRequiredError);

    const report = await recoverCommitGate({
      workspaceRoot: input.workspaceRoot,
      transaction: new WorkspaceTransaction(),
    });
    expect(report.actions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ runId: "restore-failure", action: "rolled_back" }),
      ]),
    );
    expect(await readFile(path.join(input.persistentPath, "README.md"), "utf8")).toBe(
      "base\n",
    );
  });

  it("leaves startup recovery evidence when the pending journal write fails after swap", async () => {
    const input = await fixture();
    const transaction = new WorkspaceTransaction({
      writeJournal: async (filePath, journal) => {
        if (journal.state === "PROMOTED_PENDING_DB") {
          throw new Error("injected pending journal write failure");
        }
        await writeJsonAtomic(filePath, journal);
      },
    });

    await expect(
      transaction.promoteAuthorized(
        await authorizedPromotion(input, "pending-journal-failure"),
      ),
    ).rejects.toBeInstanceOf(CommitGateRecoveryRequiredError);
    expect(await readFile(path.join(input.persistentPath, "README.md"), "utf8")).toBe(
      "candidate\n",
    );
    const unresolved = JSON.parse(
      await readFile(
        path.join(input.controlPath, "journals", "pending-journal-failure.json"),
        "utf8",
      ),
    );
    expect(unresolved.state).toBe("PROMOTING");

    const report = await recoverCommitGate({
      workspaceRoot: input.workspaceRoot,
      transaction: new WorkspaceTransaction(),
    });
    expect(report.actions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          runId: "pending-journal-failure",
          action: "rolled_back",
        }),
      ]),
    );
    expect(await readFile(path.join(input.persistentPath, "README.md"), "utf8")).toBe(
      "base\n",
    );
  });
});
