import { mkdir, rename as fsRename, rm, stat } from "node:fs/promises";
import path from "node:path";
import { CommitGateRecoveryRequiredError } from "../errors.js";
import { readJson, writeJsonAtomic } from "./atomic-json.js";
import {
  applyManifestModes,
  assertSafeIdentifier,
  copyWorkspace,
  pathExists,
} from "./file-ops.js";
import { buildManifest } from "./manifest.js";
import type { PromotionCapability } from "./promotion-permit-store.js";
import type { RollbackCapability } from "./rollback-permit-store.js";
import { assertReadonlySealedPayload } from "./sealed-proposal-store.js";
import { sha256Canonical } from "./protocol.js";
import type {
  CommitGatePolicy,
  PromotionHandle,
  PromotionJournal,
  SnapshotManifest,
} from "./types.js";

export class StateConflictError extends Error {
  readonly code = "STATE_CONFLICT";
  constructor(message = "Persistent workspace changed after candidate preparation") {
    super(message);
    this.name = "StateConflictError";
  }
}

interface InternalPromoteInput {
  runId: string;
  agentId: string;
  persistentPath: string;
  controlPath: string;
  sourcePath: string;
  policy: CommitGatePolicy;
  baseHash: string;
  expectedTargetHash?: string;
  expectedSourceVersionedHash?: string;
  kind?: "PROMOTION" | "ROLLBACK";
  targetVersionId?: string | null;
  proposalId?: string | null;
  permitId?: string | null;
  baseViewId?: string | null;
  evaluationContextHash?: string | null;
  proposalManifest?: SnapshotManifest;
  assertCurrentView?: () => Promise<boolean> | boolean;
  /** One-shot durable authorization transition, invoked after CAS and immediately before swap. */
  consumeAuthorization?: () => Promise<unknown>;
}

export interface AuthorizedPromoteInput {
  runId: string;
  agentId: string;
  persistentPath: string;
  controlPath: string;
  policy: CommitGatePolicy;
  capability: PromotionCapability;
  assertCurrentView: () => Promise<boolean> | boolean;
}

export interface AuthorizedRollbackInput {
  persistentPath: string;
  controlPath: string;
  policy: CommitGatePolicy;
  capability: RollbackCapability;
}

export interface WorkspaceTransactionOptions {
  rename?: (source: string, destination: string) => Promise<void>;
  writeJournal?: (filePath: string, journal: PromotionJournal) => Promise<void>;
  copyWorkspace?: typeof copyWorkspace;
}

export async function assertSameFilesystem(
  persistentPath: string,
  controlPath: string,
): Promise<void> {
  const [persistent, control] = await Promise.all([
    stat(persistentPath),
    stat(controlPath),
  ]);
  if (persistent.dev !== control.dev) {
    throw new Error("EXDEV_UNSUPPORTED_FILESYSTEM");
  }
}

export class WorkspaceTransaction {
  private readonly renamePath: (source: string, destination: string) => Promise<void>;
  private readonly writeJournal: (
    filePath: string,
    journal: PromotionJournal,
  ) => Promise<void>;
  private readonly copyTree: typeof copyWorkspace;

  constructor(options: WorkspaceTransactionOptions = {}) {
    this.renamePath = options.rename ?? fsRename;
    this.writeJournal = options.writeJournal ?? writeJsonAtomic;
    this.copyTree = options.copyWorkspace ?? copyWorkspace;
  }

  /**
   * Promotion entry point used by CommitGateCoordinator.  Raw paths are not an
   * authorization: callers must present a durable, one-shot permit capability
   * that is already in CONSUMING state and is bound to the sealed proposal.
   */
  async promoteAuthorized(input: AuthorizedPromoteInput): Promise<PromotionHandle> {
    const { capability } = input;
    if (
      capability.permit.state !== "CONSUMING" ||
      capability.permit.runId !== input.runId ||
      capability.permit.agentId !== input.agentId ||
      capability.permit.proposalId !== capability.proposal.proposalId ||
      capability.permit.baseViewId !== capability.baseView.viewId ||
      capability.permit.targetArtifactHash !== capability.proposal.artifactHash ||
      capability.proposal.baseViewId !== capability.baseView.viewId ||
      capability.proposal.state !== "SEALED"
    ) {
      throw new Error("PROMOTION_CAPABILITY_BINDING_MISMATCH");
    }
    if (Date.parse(capability.permit.expiresAt) <= Date.now()) {
      throw new Error("PROMOTION_PERMIT_EXPIRED_BEFORE_SWAP");
    }
    await assertReadonlySealedPayload(
      capability.proposalPath,
      input.policy,
      capability.proposalManifest,
    );
    const source = capability.proposalManifest;
    const artifactHash = sha256Canonical({
      manifestSchemaVersion: source.schemaVersion,
      manifestHash: source.hash,
      entries: source.entries,
    });
    if (
      source.hash !== capability.proposal.manifestHash ||
      artifactHash !== capability.proposal.artifactHash
    ) {
      throw new Error("PROMOTION_SOURCE_IS_NOT_SEALED_PROPOSAL");
    }
    return this.promote({
      runId: input.runId,
      agentId: input.agentId,
      persistentPath: input.persistentPath,
      controlPath: input.controlPath,
      sourcePath: capability.proposalPath,
      policy: input.policy,
      baseHash: capability.baseView.liveStateHash,
      expectedTargetHash: capability.proposal.manifestHash,
      proposalId: capability.proposal.proposalId,
      permitId: capability.permit.permitId,
      baseViewId: capability.baseView.viewId,
      evaluationContextHash: capability.permit.evaluationContextHash,
      proposalManifest: capability.proposalManifest,
      assertCurrentView: input.assertCurrentView,
      consumeAuthorization: capability.consume,
    });
  }

  /** Rollback entry point. The snapshot path and expected head are sealed into a one-shot permit. */
  async rollbackAuthorized(input: AuthorizedRollbackInput): Promise<PromotionHandle> {
    const { permit } = input.capability;
    if (permit.state !== "CONSUMING") {
      throw new Error("ROLLBACK_PERMIT_NOT_CONSUMING");
    }
    if (Date.parse(permit.expiresAt) <= Date.now()) {
      throw new Error("ROLLBACK_PERMIT_EXPIRED_BEFORE_SWAP");
    }
    return this.promote({
      runId: permit.runId,
      agentId: permit.agentId,
      persistentPath: input.persistentPath,
      controlPath: input.controlPath,
      sourcePath: input.capability.snapshotPath,
      policy: input.policy,
      baseHash: permit.baseHash,
      expectedSourceVersionedHash: permit.targetSnapshotHash,
      kind: "ROLLBACK",
      targetVersionId: permit.targetVersionId,
      permitId: permit.rollbackPermitId,
      consumeAuthorization: input.capability.consume,
    });
  }

  private async promote(input: InternalPromoteInput): Promise<PromotionHandle> {
    assertSafeIdentifier(input.runId, "runId");
    assertSafeIdentifier(input.agentId, "agentId");
    await assertSameFilesystem(input.persistentPath, input.controlPath);
    const stagingPath = path.join(input.controlPath, "staging", input.runId);
    const backupPath = path.join(input.controlPath, "backups", input.runId);
    const journalPath = path.join(input.controlPath, "journals", input.runId + ".json");
    await mkdir(path.dirname(stagingPath), { recursive: true, mode: 0o700 });
    await mkdir(path.dirname(backupPath), { recursive: true, mode: 0o700 });
    await rm(stagingPath, { recursive: true, force: true });
    await rm(backupPath, { recursive: true, force: true });

    if (input.expectedSourceVersionedHash) {
      const sourceVersioned = await buildManifest(input.sourcePath, input.policy, {
        include: new Set(["versioned"]),
      });
      if (sourceVersioned.hash !== input.expectedSourceVersionedHash) {
        throw new Error("Rollback snapshot hash does not match version metadata");
      }
    }

    await this.copyTree(input.sourcePath, stagingPath, input.policy, {
      include: new Set(["versioned"]),
    });
    await this.copyTree(input.persistentPath, stagingPath, input.policy, {
      include: new Set(["platformManaged"]),
      cleanDestination: false,
    });
    if (input.kind !== "ROLLBACK" && input.proposalManifest) {
      await applyManifestModes(stagingPath, input.proposalManifest);
    }
    if (input.expectedSourceVersionedHash) {
      const stagedVersioned = await buildManifest(stagingPath, input.policy, {
        include: new Set(["versioned"]),
      });
      if (stagedVersioned.hash !== input.expectedSourceVersionedHash) {
        throw new Error("Rollback staging bytes do not match the permitted snapshot");
      }
    }
    const staged = await buildManifest(stagingPath, input.policy);
    if (input.expectedTargetHash && staged.hash !== input.expectedTargetHash) {
      throw new Error("Staging workspace does not match verified candidate hash");
    }

    const now = new Date().toISOString();
    let journal: PromotionJournal = {
      schemaVersion: 1,
      runId: input.runId,
      agentId: input.agentId,
      kind: input.kind ?? "PROMOTION",
      state: "PREPARING",
      persistentPath: input.persistentPath,
      stagingPath,
      backupPath,
      sourcePath: input.sourcePath,
      baseHash: input.baseHash,
      targetHash: staged.hash,
      targetVersionId: input.targetVersionId ?? null,
      proposalId: input.proposalId ?? null,
      permitId: input.permitId ?? null,
      baseViewId: input.baseViewId ?? null,
      evaluationContextHash: input.evaluationContextHash ?? null,
      createdAt: now,
      updatedAt: now,
    };
    await this.writeJournal(journalPath, journal);

    const current = await buildManifest(input.persistentPath, input.policy);
    const currentViewMatches = input.assertCurrentView
      ? await input.assertCurrentView()
      : true;
    if (current.hash !== input.baseHash || !currentViewMatches) {
      await rm(stagingPath, { recursive: true, force: true });
      await this.updateJournal(journalPath, journal, "ROLLED_BACK");
      throw new StateConflictError();
    }

    if (input.consumeAuthorization) {
      try {
        await input.consumeAuthorization();
      } catch (error) {
        await rm(stagingPath, { recursive: true, force: true });
        await this.updateJournal(journalPath, journal, "ROLLED_BACK");
        throw error;
      }
    }

    journal = await this.updateJournal(journalPath, journal, "PROMOTING");
    let backupCreated = false;
    try {
      await this.renamePath(input.persistentPath, backupPath);
      backupCreated = true;
      await this.renamePath(stagingPath, input.persistentPath);
      const finalManifest = await buildManifest(input.persistentPath, input.policy);
      if (finalManifest.hash !== staged.hash) {
        throw new Error("Promoted workspace hash does not match staging hash");
      }
    } catch (error) {
      try {
        if (backupCreated) {
          if (await pathExists(input.persistentPath)) {
            const failedPath = path.join(input.controlPath, "failed", input.runId + "-" + Date.now());
            await mkdir(path.dirname(failedPath), { recursive: true, mode: 0o700 });
            await this.renamePath(input.persistentPath, failedPath);
          }
          if (await pathExists(backupPath)) {
            await this.renamePath(backupPath, input.persistentPath);
          }
          const restored = await buildManifest(input.persistentPath, input.policy);
          if (restored.hash !== input.baseHash) {
            throw new Error("Promotion failure recovery restored an unexpected workspace hash");
          }
        }
        await this.updateJournal(journalPath, journal, "ROLLED_BACK");
      } catch (recoveryError) {
        throw new CommitGateRecoveryRequiredError(
          "Promotion failed after swap began and automatic restoration did not complete",
          new AggregateError([error, recoveryError]),
        );
      }
      throw error;
    }
    try {
      journal = await this.updateJournal(journalPath, journal, "PROMOTED_PENDING_DB");
    } catch (error) {
      // The rename-swap and final hash check already succeeded.  At this point
      // the backup plus PROMOTING journal are the only durable recovery
      // evidence, so do not guess whether to keep or roll back inside the live
      // request.  Lock the Agent and let startup recovery decide from the
      // journal, DB head, and workspace hashes.
      throw new CommitGateRecoveryRequiredError(
        "Promotion completed but the pending database journal state was not persisted",
        error,
      );
    }

    let settled = false;
    return {
      journal,
      acknowledge: async () => {
        if (settled) return;
        const currentJournal = await readJson<PromotionJournal>(journalPath);
        if (currentJournal.state === "ACKNOWLEDGED") return;
        if (currentJournal.state !== "PROMOTED_PENDING_DB") {
          throw new Error("Cannot acknowledge transaction in state " + currentJournal.state);
        }
        await rm(backupPath, { recursive: true, force: true });
        await this.updateJournal(journalPath, currentJournal, "ACKNOWLEDGED");
        settled = true;
      },
      rollback: async () => {
        if (settled) return;
        const currentJournal = await readJson<PromotionJournal>(journalPath);
        await this.rollbackJournal(currentJournal, input.policy, journalPath);
        settled = true;
      },
    };
  }

  async rollbackJournal(
    journal: PromotionJournal,
    policy: CommitGatePolicy,
    journalPath: string,
  ): Promise<void> {
    if (journal.state === "ROLLED_BACK") return;
    if (journal.state === "ACKNOWLEDGED") throw new Error("Acknowledged transaction cannot be rolled back");
    if (await pathExists(journal.backupPath)) {
      if (await pathExists(journal.persistentPath)) {
        const failedPath = path.join(path.dirname(path.dirname(journal.backupPath)), "failed", journal.runId + "-" + Date.now());
        await mkdir(path.dirname(failedPath), { recursive: true, mode: 0o700 });
        await this.renamePath(journal.persistentPath, failedPath);
      }
      await this.renamePath(journal.backupPath, journal.persistentPath);
    }
    const restored = await buildManifest(journal.persistentPath, policy);
    if (restored.hash !== journal.baseHash) {
      throw new Error("Recovery restored a workspace with an unexpected hash");
    }
    await rm(journal.stagingPath, { recursive: true, force: true });
    await this.updateJournal(journalPath, journal, "ROLLED_BACK");
  }

  private async updateJournal(
    filePath: string,
    journal: PromotionJournal,
    state: PromotionJournal["state"],
  ): Promise<PromotionJournal> {
    const next = { ...journal, state, updatedAt: new Date().toISOString() };
    await this.writeJournal(filePath, next);
    return next;
  }
}
