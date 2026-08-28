import { randomUUID } from "node:crypto";
import { mkdir, rm } from "node:fs/promises";
import path from "node:path";
import { CommitGateRecoveryRequiredError } from "../errors.js";
import { readJson, writeJsonAtomic } from "./atomic-json.js";
import {
  applyManifestModes,
  assertSafeIdentifier,
  copyWorkspace,
  pathExists,
} from "./file-ops.js";
import { buildManifest, hashManifestEntries } from "./manifest.js";
import { policyHash as calculatePolicyHash } from "./policy.js";
import { RollbackPermitStore } from "./rollback-permit-store.js";
import type {
  CommitGatePolicy,
  PromotionHandle,
  SnapshotMetadataRecord,
  SnapshotManifest,
  VersionIndex,
  VersionKind,
  WorkspaceVersionRecord,
} from "./types.js";
import {
  WorkspaceTransaction,
  type AuthorizedRollbackInput,
} from "./workspace-transaction.js";

export interface VersionStoreOptions {
  maxUniqueSnapshots?: number;
  maxPayloadBytes?: number;
}

export interface RollbackTransitionAuthority {
  applyRollback(input: AuthorizedRollbackInput): Promise<PromotionHandle>;
}

export interface RecordVersionInput {
  agentId: string;
  workspacePath: string;
  policy: CommitGatePolicy;
  kind: Exclude<VersionKind, "ROLLBACK">;
  runId?: string | null;
  manifestOverride?: SnapshotManifest;
}

export interface RecordCommitOptions {
  /** Keep every snapshot payload while a promotion journal is awaiting DB acknowledgement. */
  deferPrune?: boolean;
  /** Gate-owned sealed proposal path; avoids re-reading mutable live state. */
  sourcePath?: string;
  /** Intended manifest for a read-only sealed source whose physical write bits were removed. */
  sourceManifest?: SnapshotManifest;
}

export interface RollbackVersionInput {
  agentId: string;
  workspacePath: string;
  policy: CommitGatePolicy;
  targetVersionId: string;
  expectedHeadVersionId: string;
  runId: string;
}

export class VersionStoreError extends Error {
  constructor(
    readonly code: "VERSION_NOT_FOUND" | "HEAD_MISMATCH" | "SNAPSHOT_PRUNED",
    message: string,
  ) {
    super(message);
    this.name = "VersionStoreError";
  }
}

export class VersionStore {
  private readonly maxUniqueSnapshots: number;
  private readonly maxPayloadBytes: number;
  private readonly queues = new Map<string, Promise<void>>();
  private readonly pendingRollbacks = new Map<
    string,
    { agentId: string; handle: PromotionHandle }
  >();
  private readonly transaction: WorkspaceTransaction | null;
  private readonly transitionAuthority: RollbackTransitionAuthority | null;
  private readonly rollbackPermits = new RollbackPermitStore();

  constructor(
    private readonly controlRoot: string,
    options: VersionStoreOptions = {},
    authority: WorkspaceTransaction | RollbackTransitionAuthority,
  ) {
    this.maxUniqueSnapshots = options.maxUniqueSnapshots ?? 20;
    this.maxPayloadBytes = options.maxPayloadBytes ?? 512 * 1024 * 1024;
    if (authority instanceof WorkspaceTransaction) {
      this.transaction = authority;
      this.transitionAuthority = null;
    } else {
      this.transaction = null;
      this.transitionAuthority = authority;
    }
  }

  async initializeAgent(
    agentId: string,
    workspacePath: string,
    policy: CommitGatePolicy,
  ): Promise<WorkspaceVersionRecord> {
    return this.enqueue(agentId, async () => {
      const index = await this.load(agentId);
      if (index.versions.length > 0) return index.versions[0]!;
      return this.recordUnlocked(index, { agentId, workspacePath, policy, kind: "INITIAL" });
    });
  }

  async recordCommit(
    agentId: string,
    workspacePath: string,
    policy: CommitGatePolicy,
    runId: string,
    options: RecordCommitOptions = {},
  ): Promise<WorkspaceVersionRecord> {
    return this.enqueue(agentId, async () => {
      const index = await this.load(agentId);
      const existing = index.versions.find(
        (version) => version.kind === "AGENT_COMMIT" && version.runId === runId,
      );
      if (existing) return existing;
      if (index.versions.length === 0) {
        await this.recordUnlocked(index, { agentId, workspacePath, policy, kind: "INITIAL" });
      }
      return this.recordUnlocked(
        index,
        {
          agentId,
          workspacePath: options.sourcePath ?? workspacePath,
          policy,
          kind: "AGENT_COMMIT",
          runId,
          ...(options.sourceManifest
            ? { manifestOverride: options.sourceManifest }
            : {}),
        },
        undefined,
        null,
        options.deferPrune ?? false,
      );
    });
  }

  async rollback(input: RollbackVersionInput): Promise<WorkspaceVersionRecord> {
    const version = await this.stageRollback(input);
    try {
      await this.acknowledgeRollback(input.runId);
      return version;
    } catch (error) {
      await this.rollbackPendingRollback(input.runId).catch(() => undefined);
      throw error;
    }
  }

  async stageRollback(input: RollbackVersionInput): Promise<WorkspaceVersionRecord> {
    return this.enqueue(input.agentId, async () => {
      if (this.pendingRollbacks.has(input.runId)) {
        throw new Error("Rollback run already has a pending transaction");
      }
      const index = await this.load(input.agentId);
      if (index.headVersionId !== input.expectedHeadVersionId) {
        throw new VersionStoreError("HEAD_MISMATCH", "Workspace version head changed");
      }
      const target = index.versions.find((version) => version.id === input.targetVersionId);
      if (!target) throw new VersionStoreError("VERSION_NOT_FOUND", "Target version does not exist");
      const snapshot = index.snapshots.find((item) => item.hash === target.snapshotHash);
      if (!snapshot || snapshot.prunedAt || !target.snapshotAvailable) {
        throw new VersionStoreError("SNAPSHOT_PRUNED", "Target snapshot payload has been pruned");
      }
      const sourcePath = path.join(this.agentRoot(input.agentId), snapshot.relativePath);
      if (!(await pathExists(sourcePath))) throw new VersionStoreError("SNAPSHOT_PRUNED", "Target snapshot payload is missing");
      const base = await buildManifest(input.workspacePath, input.policy);
      const controlPath = this.agentRoot(input.agentId);
      const issuedPermit = await this.rollbackPermits.issue({
        runId: input.runId,
        agentId: input.agentId,
        controlPath,
        targetVersionId: target.id,
        targetSnapshotHash: target.snapshotHash,
        expectedHeadVersionId: input.expectedHeadVersionId,
        baseHash: base.hash,
      });
      const capability = await this.rollbackPermits.claim({
        controlPath,
        rollbackPermitId: issuedPermit.rollbackPermitId,
        snapshotPath: sourcePath,
        targetVersionId: target.id,
        targetSnapshotHash: target.snapshotHash,
        expectedHeadVersionId: input.expectedHeadVersionId,
        baseHash: base.hash,
      });
      const rollbackInput: AuthorizedRollbackInput = {
        persistentPath: input.workspacePath,
        controlPath,
        policy: input.policy,
        capability,
      };
      let handle: PromotionHandle;
      try {
        handle = this.transitionAuthority
          ? await this.transitionAuthority.applyRollback(rollbackInput)
          : await this.transaction!.rollbackAuthorized(rollbackInput);
      } catch (error) {
        await this.rollbackPermits
          .revoke(controlPath, issuedPermit.rollbackPermitId)
          .catch(() => undefined);
        throw error;
      }
      await this.rollbackPermits.markConsumed(controlPath, capability);
      try {
        const version = await this.recordUnlocked(index, {
          agentId: input.agentId,
          workspacePath: input.workspacePath,
          policy: input.policy,
          kind: "AGENT_COMMIT",
          runId: input.runId,
        }, "ROLLBACK", target.id, true);
        this.pendingRollbacks.set(input.runId, { agentId: input.agentId, handle });
        return version;
      } catch (error) {
        try {
          await handle.rollback();
        } catch (rollbackError) {
          throw new CommitGateRecoveryRequiredError(
            "CommitGate rollback staging failed and the promoted workspace could not be restored",
            new AggregateError([error, rollbackError]),
          );
        }
        throw error;
      }
    });
  }

  async acknowledgeRollback(runId: string): Promise<void> {
    const pending = this.pendingRollbacks.get(runId);
    if (!pending) throw new Error("No pending rollback transaction for run " + runId);
    await pending.handle.acknowledge();
    this.pendingRollbacks.delete(runId);
    await this.releaseRetention(pending.agentId);
  }

  async rollbackPendingRollback(runId: string): Promise<void> {
    const pending = this.pendingRollbacks.get(runId);
    if (!pending) return;
    await pending.handle.rollback();
    await this.revertRunVersion(pending.agentId, runId);
    this.pendingRollbacks.delete(runId);
  }

  async list(agentId: string, limit = 20, beforeSequence?: number): Promise<WorkspaceVersionRecord[]> {
    const index = await this.load(agentId);
    return index.versions
      .filter((version) => beforeSequence === undefined || version.sequence < beforeSequence)
      .sort((a, b) => b.sequence - a.sequence)
      .slice(0, Math.max(1, Math.min(100, limit)));
  }

  async head(agentId: string): Promise<WorkspaceVersionRecord | null> {
    const index = await this.load(agentId);
    return index.versions.find((version) => version.id === index.headVersionId) ?? null;
  }

  async getIndex(agentId: string): Promise<VersionIndex> {
    return structuredClone(await this.load(agentId));
  }

  async revertRunVersion(agentId: string, runId: string): Promise<boolean> {
    return this.enqueue(agentId, async () => {
      const index = await this.load(agentId);
      const head = index.versions.find((version) => version.id === index.headVersionId);
      if (!head || head.runId !== runId || head.kind === "INITIAL") return false;
      index.versions = index.versions.filter((version) => version.id !== head.id);
      index.headVersionId = head.parentVersionId;
      const snapshot = index.snapshots.find((item) => item.hash === head.snapshotHash);
      if (snapshot) snapshot.refCount = Math.max(0, snapshot.refCount - 1);
      await this.prune(index);
      await this.persist(index);
      return true;
    });
  }

  /** Apply the configured retention limits after an active journal is terminal. */
  async releaseRetention(agentId: string): Promise<void> {
    return this.enqueue(agentId, async () => {
      const index = await this.load(agentId);
      await this.prune(index);
      await this.persist(index);
    });
  }

  private async recordUnlocked(
    index: VersionIndex,
    input: RecordVersionInput,
    kindOverride?: VersionKind,
    rollbackTargetVersionId: string | null = null,
    deferPrune = false,
  ): Promise<WorkspaceVersionRecord> {
    const manifest = input.manifestOverride
      ? {
          schemaVersion: 2 as const,
          entries: input.manifestOverride.entries.filter(
            (entry) => entry.pathClass === "versioned",
          ),
          hash: "",
        }
      : await buildManifest(input.workspacePath, input.policy, {
          include: new Set(["versioned"]),
        });
    if (input.manifestOverride) manifest.hash = hashManifestEntries(manifest.entries);
    let snapshot = index.snapshots.find((item) => item.hash === manifest.hash);
    const relativePath = path.posix.join("snapshots", manifest.hash);
    const snapshotPath = path.join(this.agentRoot(input.agentId), ...relativePath.split("/"));
    if (!snapshot || snapshot.prunedAt || !(await pathExists(snapshotPath))) {
      await copyWorkspace(input.workspacePath, snapshotPath, input.policy, { include: new Set(["versioned"]) });
      if (input.manifestOverride) {
        await applyManifestModes(snapshotPath, input.manifestOverride, new Set(["versioned"]));
      }
      const copiedManifest = await buildManifest(snapshotPath, input.policy, {
        include: new Set(["versioned"]),
      });
      if (copiedManifest.hash !== manifest.hash) {
        await rm(snapshotPath, { recursive: true, force: true });
        throw new Error("VERSION_SNAPSHOT_CHANGED_DURING_IMPORT");
      }
      const sizeBytes = manifest.entries.reduce((sum, entry) => sum + (entry.type === "file" ? entry.size : 0), 0);
      const existingReferences = index.versions.filter(
        (version) => version.snapshotHash === manifest.hash,
      ).length;
      snapshot = {
        hash: manifest.hash,
        relativePath,
        sizeBytes,
        refCount: existingReferences,
        createdAt: new Date().toISOString(),
        prunedAt: null,
      };
      index.snapshots = index.snapshots.filter((item) => item.hash !== manifest.hash);
      index.snapshots.push(snapshot);
      for (const version of index.versions) {
        if (version.snapshotHash === manifest.hash) version.snapshotAvailable = true;
      }
    }
    snapshot.refCount += 1;
    const parentVersionId = index.headVersionId;
    const sequence = (index.versions.at(-1)?.sequence ?? 0) + 1;
    const version: WorkspaceVersionRecord = {
      id: `v${sequence}-${manifest.hash.slice(0, 10)}-${randomUUID().slice(0, 8)}`,
      agentId: input.agentId,
      sequence,
      kind: kindOverride ?? input.kind,
      snapshotHash: manifest.hash,
      policyHash: calculatePolicyHash(input.policy),
      parentVersionId,
      rollbackTargetVersionId,
      runId: input.runId ?? null,
      createdAt: new Date().toISOString(),
      snapshotAvailable: true,
    };
    index.versions.push(version);
    index.headVersionId = version.id;
    if (!deferPrune) await this.prune(index);
    await this.persist(index);
    return version;
  }

  private async prune(index: VersionIndex): Promise<void> {
    // A prior crash may leave a payload whose metadata was already committed as
    // pruned.  It is safe to retry those deletions because rollback consults the
    // metadata before touching a payload.
    for (const snapshot of index.snapshots.filter((item) => item.prunedAt)) {
      await rm(path.join(this.agentRoot(index.agentId), snapshot.relativePath), {
        recursive: true,
        force: true,
      }).catch(() => undefined);
    }
    let available = index.snapshots.filter((item) => !item.prunedAt);
    let bytes = available.reduce((sum, item) => sum + item.sizeBytes, 0);
    if (available.length <= this.maxUniqueSnapshots && bytes <= this.maxPayloadBytes) return;
    const initialHash = index.versions.find((version) => version.kind === "INITIAL")?.snapshotHash;
    const headHash = index.versions.find((version) => version.id === index.headVersionId)?.snapshotHash;
    const protectedHashes = new Set([initialHash, headHash].filter((value): value is string => Boolean(value)));
    const payloadsToDelete: string[] = [];
    for (const snapshot of [...available].sort((a, b) => a.createdAt.localeCompare(b.createdAt))) {
      if (available.length <= this.maxUniqueSnapshots && bytes <= this.maxPayloadBytes) break;
      if (protectedHashes.has(snapshot.hash)) continue;
      snapshot.prunedAt = new Date().toISOString();
      payloadsToDelete.push(snapshot.relativePath);
      bytes -= snapshot.sizeBytes;
      available = available.filter((item) => item.hash !== snapshot.hash);
      for (const version of index.versions) {
        if (version.snapshotHash === snapshot.hash) version.snapshotAvailable = false;
      }
    }
    if (payloadsToDelete.length === 0) return;
    // Commit the rollback-disable metadata before deleting bytes.  A crash can
    // therefore leave only a harmless orphan payload, never metadata that
    // falsely advertises a missing snapshot as available.
    await this.persist(index);
    for (const relativePath of payloadsToDelete) {
      await rm(path.join(this.agentRoot(index.agentId), relativePath), {
        recursive: true,
        force: true,
      }).catch(() => undefined);
    }
  }

  private agentRoot(agentId: string): string {
    assertSafeIdentifier(agentId, "agentId");
    return path.join(this.controlRoot, agentId);
  }

  private indexPath(agentId: string): string {
    return path.join(this.agentRoot(agentId), "versions", "index.json");
  }

  private async load(agentId: string): Promise<VersionIndex> {
    try {
      return await readJson<VersionIndex>(this.indexPath(agentId));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      return { schemaVersion: 1, agentId, headVersionId: null, versions: [], snapshots: [] };
    }
  }

  private async persist(index: VersionIndex): Promise<void> {
    await mkdir(path.dirname(this.indexPath(index.agentId)), { recursive: true, mode: 0o700 });
    await writeJsonAtomic(this.indexPath(index.agentId), index);
  }

  private async enqueue<T>(agentId: string, operation: () => Promise<T>): Promise<T> {
    const previous = this.queues.get(agentId) ?? Promise.resolve();
    let result!: T;
    const current = previous.then(async () => {
      result = await operation();
    });
    this.queues.set(agentId, current.catch(() => undefined));
    await current;
    return result;
  }
}
