import { mkdir, rename } from "node:fs/promises";
import path from "node:path";
import type { Agent } from "./types.js";
import type { RecoveryOptions, RecoveryReport } from "./commitgate/recovery.js";
import { copyWorkspace } from "./commitgate/file-ops.js";
import { buildManifest } from "./commitgate/manifest.js";
import {
  SealedProposalStore,
  type ResolvedSealedProposal,
  type SealProposalInput,
} from "./commitgate/sealed-proposal-store.js";
import type {
  AuthorizedPromoteInput,
  AuthorizedRollbackInput,
} from "./commitgate/workspace-transaction.js";
import { WorkspaceTransaction } from "./commitgate/workspace-transaction.js";
import type {
  CommitGatePolicy,
  PromotionHandle,
  SnapshotManifest,
} from "./commitgate/types.js";
import { WorkspaceManager } from "./workspace.js";
import type { TransitionAuthority } from "./transition-authority.js";

/**
 * The only product-layer facade allowed to mutate an authoritative workspace.
 * CommitGate's promotion/rollback mechanism has its own capability-gated
 * writer; all CRUD/configuration transitions pass through this class.
 *
 * P0 enforces one writer structurally and serializes per Agent. P1 can replace
 * this facade with the same RPC surface backed by a separate UID/container.
 */
export class WorkspaceTransitionWriter implements TransitionAuthority {
  readonly mode = "in-process" as const;
  private readonly tails = new Map<string, Promise<void>>();
  private readonly transaction: WorkspaceTransaction;
  private readonly proposalStore = new SealedProposalStore();

  constructor(
    private readonly workspaces: WorkspaceManager,
    private readonly commitGateControlRoot?: string,
    transaction?: WorkspaceTransaction,
  ) {
    // This is deliberately the single production construction site for the
    // low-level rename-swap primitive. Tests may inject a fault-enabled
    // transaction, but product code receives only this typed authority.
    this.transaction = transaction ?? new WorkspaceTransaction();
  }

  workspacePath(agentId: string): string {
    return this.workspaces.workspacePath(agentId);
  }

  initialize(): Promise<void> {
    return this.workspaces.initialize();
  }

  createAgentWorkspace(agent: Agent): Promise<void> {
    return this.enqueue(agent.id, () => this.workspaces.create(agent));
  }

  /** Serialize admission-time candidate materialization with other state transitions. */
  materializeCandidate(input: {
    agentId: string;
    persistentPath: string;
    candidatePath: string;
    policy: CommitGatePolicy;
  }): Promise<{
    baseBefore: SnapshotManifest;
    candidateBase: SnapshotManifest;
    baseAfter: SnapshotManifest;
  }> {
    return this.enqueue(input.agentId, async () => {
      const baseBefore = await buildManifest(input.persistentPath, input.policy);
      await copyWorkspace(input.persistentPath, input.candidatePath, input.policy, {
        include: new Set(["versioned", "platformManaged"]),
      });
      const candidateBase = await buildManifest(input.candidatePath, input.policy);
      const baseAfter = await buildManifest(input.persistentPath, input.policy);
      return { baseBefore, candidateBase, baseAfter };
    });
  }

  /** Serialize the immutable import boundary after the Agent runtime is torn down. */
  sealProposal(input: SealProposalInput): Promise<ResolvedSealedProposal> {
    return this.enqueue(input.agentId, () => this.proposalStore.seal(input));
  }

  regeneratePlatformState(agent: Agent): Promise<void> {
    return this.enqueue(agent.id, () => this.workspaces.writeInstructions(agent));
  }

  archiveAgent(agent: Agent): Promise<string> {
    return this.enqueue(agent.id, () => this.workspaces.archive(agent));
  }

  applyPromotion(input: AuthorizedPromoteInput): Promise<PromotionHandle> {
    return this.enqueue(input.agentId, () => this.transaction.promoteAuthorized(input));
  }

  applyRollback(input: AuthorizedRollbackInput): Promise<PromotionHandle> {
    return this.enqueue(input.capability.permit.agentId, () =>
      this.transaction.rollbackAuthorized(input),
    );
  }

  recoverTransition(
    options: Omit<RecoveryOptions, "transaction">,
  ): Promise<RecoveryReport> {
    // Dynamic import avoids a runtime cycle: recovery projects VersionStore,
    // while VersionStore itself accepts this writer as its mutation authority.
    return import("./commitgate/recovery.js").then(({ recoverCommitGate }) =>
      recoverCommitGate({ ...options, transaction: this.transaction }),
    );
  }

  /** P1 repair is exposed only by the expected-state checked transition-worker RPC/CLI. */
  async applyRepair(_agentId: string): Promise<never> {
    throw new Error("REPAIR_REQUIRES_TRANSITION_WORKER_RPC");
  }

  archiveControlPlane(agentId: string): Promise<void> {
    if (!this.commitGateControlRoot) return Promise.resolve();
    return this.enqueue(agentId, async () => {
      const source = path.join(this.commitGateControlRoot!, agentId);
      const destinationRoot = path.join(this.commitGateControlRoot!, ".deleted");
      await mkdir(destinationRoot, { recursive: true, mode: 0o700 });
      try {
        await rename(source, path.join(destinationRoot, agentId + "-" + Date.now()));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    });
  }

  private async enqueue<T>(agentId: string, operation: () => Promise<T>): Promise<T> {
    const previous = this.tails.get(agentId) ?? Promise.resolve();
    let result!: T;
    const current = previous.then(async () => {
      result = await operation();
    });
    this.tails.set(agentId, current.catch(() => undefined));
    await current;
    return result;
  }
}
