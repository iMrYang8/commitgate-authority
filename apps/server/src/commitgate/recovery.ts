import { mkdir, readdir, rename, rm } from "node:fs/promises";
import path from "node:path";
import { readJson, writeJsonAtomic } from "./atomic-json.js";
import { buildManifest } from "./manifest.js";
import { loadPolicy } from "./policy.js";
import { assertContained, assertSafeIdentifier, pathExists } from "./file-ops.js";
import { ReceiptStore } from "./receipt-store.js";
import type { CommitGatePolicy, GateReceipt, PromotionJournal } from "./types.js";
import { VersionStore } from "./version-store.js";
import { WorkspaceTransaction } from "./workspace-transaction.js";

export interface RecoveryOptions {
  workspaceRoot: string;
  controlRoot?: string;
  getDatabaseHead?: (
    agentId: string,
  ) => Promise<RecoveryDatabaseHead | null> | RecoveryDatabaseHead | null;
  /** Supplied only by WorkspaceTransitionWriter in production. */
  transaction: WorkspaceTransaction;
}

export interface RecoveryDatabaseHead {
  versionId: string;
  liveStateHash: string;
  runId: string | null;
  kind: "INITIAL" | "AGENT_COMMIT" | "ROLLBACK";
}

export interface RecoveryAction {
  agentId: string;
  runId: string;
  action: "acknowledged" | "rolled_back" | "cleaned" | "manual_intervention";
  detail: string;
}

export interface RecoveryReport {
  actions: RecoveryAction[];
  healthy: boolean;
}

export async function recoverCommitGate(options: RecoveryOptions): Promise<RecoveryReport> {
  const controlRoot = path.resolve(options.controlRoot ?? path.join(path.resolve(options.workspaceRoot), ".commitgate"));
  const transaction = options.transaction;
  const receiptStore = new ReceiptStore(controlRoot);
  const versionStore = new VersionStore(controlRoot, {}, transaction);
  const actions: RecoveryAction[] = [];
  await mkdir(controlRoot, { recursive: true, mode: 0o700 });
  const agentIds = (await readdir(controlRoot, { withFileTypes: true }))
    .filter(
      (entry) =>
        entry.isDirectory() &&
        entry.name !== "trusted-checks" &&
        !entry.name.startsWith("."),
    )
    .map((entry) => entry.name);
  for (const agentId of agentIds) {
    const agentRoot = path.join(controlRoot, agentId);
    let policy: CommitGatePolicy;
    try {
      policy = await loadPolicy(path.join(agentRoot, "policy.json"));
    } catch (error) {
      actions.push({
        agentId,
        runId: "unknown",
        action: "manual_intervention",
        detail: "Invalid recovery policy: " + (error instanceof Error ? error.message : String(error)),
      });
      continue;
    }
    const journalsPath = path.join(agentRoot, "journals");
    let journals: string[] = [];
    try {
      journals = (await readdir(journalsPath)).filter((name) => name.endsWith(".json"));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    const journalRunIds = new Set(
      journals.map((name) => name.replace(/\.json$/, "")),
    );
    for (const file of journals) {
      const journalPath = path.join(journalsPath, file);
      let journal: PromotionJournal;
      try {
        journal = await readJson<PromotionJournal>(journalPath);
        validateJournal(journal, agentId, agentRoot, options.workspaceRoot, controlRoot);
      } catch (error) {
        actions.push({
          agentId,
          runId: file.replace(/\.json$/, ""),
          action: "manual_intervention",
          detail:
            "Invalid promotion journal: " +
            (error instanceof Error ? error.message : String(error)),
        });
        continue;
      }
      if (journal.state === "ACKNOWLEDGED") {
        try {
          if (journal.kind === "PROMOTION") {
            await updateRecoveredReceipt(receiptStore, agentId, journal.runId, {
              phase: "TERMINAL",
              transactionStatus: "TERMINAL",
              artifactRetention: "version_snapshot",
              promotionPendingDatabaseAck: false,
              finalSnapshotHash: journal.targetHash,
            });
          }
          await versionStore.releaseRetention(agentId);
          actions.push({
            agentId,
            runId: journal.runId,
            action: "acknowledged",
            detail: "Journal was already acknowledged; terminal cleanup is complete",
          });
        } catch (error) {
          actions.push({
            agentId,
            runId: journal.runId,
            action: "manual_intervention",
            detail: error instanceof Error ? error.message : String(error),
          });
        }
        continue;
      }
      if (journal.state === "ROLLED_BACK") {
        try {
          await versionStore.revertRunVersion(agentId, journal.runId);
          await markReceiptRolledBack(receiptStore, journal);
          await versionStore.releaseRetention(agentId);
          actions.push({
            agentId,
            runId: journal.runId,
            action: "rolled_back",
            detail: "Journal was already rolled back; terminal cleanup is complete",
          });
        } catch (error) {
          actions.push({
            agentId,
            runId: journal.runId,
            action: "manual_intervention",
            detail: error instanceof Error ? error.message : String(error),
          });
        }
        continue;
      }
      try {
        if (journal.state === "PREPARING") {
          await rm(journal.stagingPath, { recursive: true, force: true });
          await markJournal(journalPath, journal, "ROLLED_BACK");
          actions.push({ agentId, runId: journal.runId, action: "cleaned", detail: "Removed unpromoted staging workspace" });
          continue;
        }
        const persistentHash = await manifestHashOrNull(journal.persistentPath, policy);
        const databaseHead = (await options.getDatabaseHead?.(agentId)) ?? null;
        const index = await versionStore.getIndex(agentId);
        const stagedVersion = index.versions.find(
          (item) => item.id === index.headVersionId && item.runId === journal.runId,
        );
        const expectedKind = journal.kind === "ROLLBACK" ? "ROLLBACK" : "AGENT_COMMIT";
        const databaseCommitted = Boolean(
          stagedVersion &&
            stagedVersion.kind === expectedKind &&
            databaseHead?.versionId === stagedVersion.id &&
            databaseHead.liveStateHash === journal.targetHash &&
            databaseHead.runId === journal.runId &&
            databaseHead.kind === expectedKind,
        );
        if (
          journal.state === "PROMOTED_PENDING_DB" &&
          databaseCommitted &&
          persistentHash === journal.targetHash
        ) {
          const versionId = stagedVersion!.id;
          if (journal.kind === "ROLLBACK") {
            const target = index.versions.find((item) => item.id === journal.targetVersionId);
            if (
              stagedVersion!.rollbackTargetVersionId !== journal.targetVersionId ||
              !target ||
              stagedVersion!.snapshotHash !== target.snapshotHash
            ) {
              throw new Error(
                "Rollback journal matches the database hash, but its append-only version event is missing or inconsistent",
              );
            }
          }
          await rm(journal.backupPath, { recursive: true, force: true });
          await markJournal(journalPath, journal, "ACKNOWLEDGED");
          await versionStore.releaseRetention(agentId);
          if (journal.kind === "PROMOTION") {
            await updateRecoveredReceipt(receiptStore, agentId, journal.runId, {
              versionId,
              phase: "TERMINAL",
              transactionStatus: "TERMINAL",
              artifactRetention: "version_snapshot",
              promotionPendingDatabaseAck: false,
            });
          }
          actions.push({ agentId, runId: journal.runId, action: "acknowledged", detail: "Database and promoted workspace agree" });
        } else if (await pathExists(journal.backupPath)) {
          await transaction.rollbackJournal(journal, policy, journalPath);
          await versionStore.revertRunVersion(agentId, journal.runId);
          await markReceiptRolledBack(receiptStore, journal);
          actions.push({ agentId, runId: journal.runId, action: "rolled_back", detail: "Fail-closed recovery restored backup" });
        } else if (persistentHash === journal.baseHash) {
          await markJournal(journalPath, journal, "ROLLED_BACK");
          await versionStore.revertRunVersion(agentId, journal.runId);
          await markReceiptRolledBack(receiptStore, journal);
          actions.push({ agentId, runId: journal.runId, action: "rolled_back", detail: "Persistent workspace already matches base" });
        } else if (persistentHash === null && (await pathExists(journal.backupPath))) {
          await rename(journal.backupPath, journal.persistentPath);
          await markJournal(journalPath, journal, "ROLLED_BACK");
          actions.push({ agentId, runId: journal.runId, action: "rolled_back", detail: "Restored missing persistent workspace" });
        } else {
          actions.push({ agentId, runId: journal.runId, action: "manual_intervention", detail: "Journal, database and workspace hashes cannot be reconciled uniquely" });
        }
      } catch (error) {
        actions.push({
          agentId,
          runId: journal.runId,
          action: "manual_intervention",
          detail: error instanceof Error ? error.message : String(error),
        });
      }
    }
    // A protocol-complete receipt is persisted before rename-swap. If startup
    // sees such a transaction without a journal, the process stopped before
    // the transition began. It is safe to disposition only when authoritative
    // bytes still match the admitted base; any other state is external damage
    // and remains fail-closed for manual repair.
    for (const receipt of await receiptStore.list(agentId)) {
      if (
        receipt.phase !== "PENDING_PROMOTION" ||
        journalRunIds.has(receipt.runId)
      ) {
        continue;
      }
      const persistentPath = path.join(
        path.resolve(options.workspaceRoot),
        agentId,
      );
      const persistentHash = await manifestHashOrNull(persistentPath, policy);
      if (persistentHash === receipt.baseSnapshotHash) {
        await markReceiptRolledBack(receiptStore, {
          agentId,
          runId: receipt.runId,
          baseHash: receipt.baseSnapshotHash,
        });
        actions.push({
          agentId,
          runId: receipt.runId,
          action: "rolled_back",
          detail:
            "Disposed a pre-swap promotion transaction with no transition journal",
        });
      } else {
        actions.push({
          agentId,
          runId: receipt.runId,
          action: "manual_intervention",
          detail:
            "Pending promotion has no journal and authoritative bytes do not match its base",
        });
      }
    }
    for (const name of ["candidates", "verify", "staging"]) {
      const directory = path.join(agentRoot, name);
      try {
        for (const entry of await readdir(directory)) {
          await rm(path.join(directory, entry), { recursive: true, force: true });
          actions.push({ agentId, runId: entry, action: "cleaned", detail: "Removed orphaned " + name + " directory" });
        }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
  }
  return { actions, healthy: actions.every((action) => action.action !== "manual_intervention") };
}

function validateJournal(
  journal: PromotionJournal,
  agentId: string,
  agentRoot: string,
  workspaceRoot: string,
  controlRoot: string,
): void {
  if (!journal || journal.schemaVersion !== 1 || journal.agentId !== agentId) {
    throw new Error("Journal schema or agent identity is invalid");
  }
  assertSafeIdentifier(journal.runId, "journal runId");
  if (!['PROMOTION', 'ROLLBACK'].includes(journal.kind)) {
    throw new Error("Journal kind is invalid");
  }
  if (
    !['PREPARING', 'PROMOTING', 'PROMOTED_PENDING_DB', 'ACKNOWLEDGED', 'ROLLED_BACK'].includes(
      journal.state,
    )
  ) {
    throw new Error("Journal state is invalid");
  }
  if (!/^[a-f0-9]{64}$/.test(journal.baseHash) || !/^[a-f0-9]{64}$/.test(journal.targetHash)) {
    throw new Error("Journal hashes are invalid");
  }
  assertContained(workspaceRoot, journal.persistentPath, "journal persistent path");
  const persistent = path.resolve(journal.persistentPath);
  const trustedControl = path.resolve(controlRoot);
  if (persistent === trustedControl || persistent.startsWith(trustedControl + path.sep)) {
    throw new Error("Journal persistent path points into the control plane");
  }
  for (const [label, value] of [
    ["staging", journal.stagingPath],
    ["backup", journal.backupPath],
    ["source", journal.sourcePath],
  ] as const) {
    assertContained(agentRoot, value, `journal ${label} path`);
  }
}

async function manifestHashOrNull(workspacePath: string, policy: CommitGatePolicy): Promise<string | null> {
  if (!(await pathExists(workspacePath))) return null;
  return (await buildManifest(workspacePath, policy)).hash;
}

async function markJournal(
  filePath: string,
  journal: PromotionJournal,
  state: PromotionJournal["state"],
): Promise<void> {
  await writeJsonAtomic(filePath, { ...journal, state, updatedAt: new Date().toISOString() });
}

async function updateRecoveredReceipt(
  store: ReceiptStore,
  agentId: string,
  runId: string,
  patch: Partial<GateReceipt>,
): Promise<void> {
  const receipt = await store.get(agentId, runId);
  await store.appendRecoveryEvent({
    agentId,
    runId,
    type: "RECOVERY_ACKNOWLEDGED",
    originalDecision: receipt?.decision ?? null,
    effectiveDecision: "COMMITTED",
    reasonCode: "STARTUP_RECOVERY_ACKNOWLEDGED",
    finalSnapshotHash:
      patch.finalSnapshotHash ?? receipt?.finalSnapshotHash ?? "unavailable",
    threadDisposition: "resumed",
  });
  if (receipt && receipt.phase !== "TERMINAL") {
    await store.put({ ...receipt, ...patch });
  }
}

async function markReceiptRolledBack(
  store: ReceiptStore,
  journal: Pick<PromotionJournal, "agentId" | "runId" | "baseHash">,
): Promise<void> {
  const receipt = await store.get(journal.agentId, journal.runId);
  await store.appendRecoveryEvent({
    agentId: journal.agentId,
    runId: journal.runId,
    type: "RECOVERY_ROLLED_BACK",
    originalDecision: receipt?.decision ?? null,
    effectiveDecision: "ABORTED",
    reasonCode: "STARTUP_RECOVERY_ROLLBACK",
    finalSnapshotHash: journal.baseHash,
    threadDisposition: "reset",
  });
  if (!receipt || receipt.phase === "TERMINAL") return;
  await store.put({
    ...receipt,
    phase: "TERMINAL",
    decision: "ABORTED",
    failureClass: "infra_errored",
    reasonCodes: [...receipt.reasonCodes, "STARTUP_RECOVERY_ROLLBACK"],
    finalSnapshotHash: journal.baseHash,
    threadDisposition: "reset",
    sessionEpoch:
      receipt.threadDisposition === "resumed" ? receipt.sessionEpoch + 1 : receipt.sessionEpoch,
    versionId: null,
    promotionPendingDatabaseAck: false,
    transactionStatus: "TERMINAL",
    artifactRetention: "destroyed",
    completedAt: new Date().toISOString(),
  });
}
