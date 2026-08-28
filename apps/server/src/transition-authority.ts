import type { Agent } from "./types.js";
import type { RecoveryOptions, RecoveryReport } from "./commitgate/recovery.js";
import type {
  ResolvedSealedProposal,
  SealProposalInput,
} from "./commitgate/sealed-proposal-store.js";
import type {
  AuthorizedPromoteInput,
  AuthorizedRollbackInput,
} from "./commitgate/workspace-transaction.js";
import type {
  CommitGatePolicy,
  PromotionHandle,
  SnapshotManifest,
} from "./commitgate/types.js";

/**
 * The product's complete authoritative-workspace mutation surface.
 * Production may implement it over a private worker RPC; tests and local
 * development may use the in-process implementation explicitly.
 */
export interface TransitionAuthority {
  readonly mode: "in-process" | "worker";
  workspacePath(agentId: string): string;
  initialize(): Promise<void>;
  createAgentWorkspace(agent: Agent): Promise<void>;
  materializeCandidate(input: {
    agentId: string;
    persistentPath: string;
    candidatePath: string;
    policy: CommitGatePolicy;
  }): Promise<{
    baseBefore: SnapshotManifest;
    candidateBase: SnapshotManifest;
    baseAfter: SnapshotManifest;
  }>;
  sealProposal(input: SealProposalInput): Promise<ResolvedSealedProposal>;
  regeneratePlatformState(agent: Agent): Promise<void>;
  archiveAgent(agent: Agent): Promise<string>;
  archiveControlPlane(agentId: string): Promise<void>;
  applyPromotion(input: AuthorizedPromoteInput): Promise<PromotionHandle>;
  applyRollback(input: AuthorizedRollbackInput): Promise<PromotionHandle>;
  recoverTransition(
    options: Omit<RecoveryOptions, "transaction">,
  ): Promise<RecoveryReport>;
  applyRepair(agentId: string): Promise<never>;
}
