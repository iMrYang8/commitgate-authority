export type AgentStatus = "ready" | "busy" | "stopped" | "error";
export type RunStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export type MessageRole = "user" | "assistant";
export type GateDecision = "COMMITTED" | "QUARANTINED" | "CONFLICTED" | "ABORTED";
export type GateFailureClass =
  | "agent_wrong"
  | "evidence_broken"
  | "infra_errored"
  | "state_conflict"
  | null;
export type GateCheckStatus = "PASS" | "FAIL" | "ERROR" | "SKIPPED";
export type GateLifecycleEventName =
  | "RUN_STARTED"
  | "PROPOSAL_SEALED"
  | "VERIFICATION_COMPLETED"
  | "PERMIT_ISSUED"
  | "VIEW_COMMITTED"
  | "SESSION_RESET"
  | "RUN_ABORTED";
export type GateTransactionStatus =
  | "PREPARING"
  | "EXECUTING"
  | "SEALED"
  | "VERIFYING"
  | "PENDING_DISPOSITION"
  | "PENDING_PROMOTION"
  | "TERMINAL";
export type MessageAuthority =
  | "INPUT"
  | "PROVISIONAL"
  | "AUTHORITATIVE"
  | "REJECTED"
  | "SUPERSEDED";

export interface StateViewRef {
  schemaVersion: 1;
  viewId: string;
  agentId: string;
  headVersionId: string;
  generation: number;
  versionedHash: string;
  platformManagedHash: string;
  liveStateHash: string;
  sessionEpoch: number;
  agentConfigVersion: number;
  policyVersion: number;
}

export interface ModelProviderIdentity {
  providerId: "ark" | "openrouter" | "custom";
  gateway: string;
  requestedModel: string;
  resolvedModel: string | null;
}

export interface EffectDispositionProof {
  candidateChanged: boolean;
  candidateObservation: "changed" | "unchanged" | "unobserved";
  admissionBaseHash: string;
  authoritativeBeforeHash: string;
  authoritativeAfterHash: string;
  authoritativeChanged: boolean;
  sealedProposalHash: string | null;
  verifierInputHash: string | null;
  promotionSourceHash: string | null;
  finalAuthoritativeHash: string;
  invariant: "PROMOTED_EXACT_PROPOSAL" | "NO_PERSISTENT_EFFECT";
  invariantSatisfied: boolean;
}

export interface CommitGateSummary {
  transactionStatus?: GateTransactionStatus;
  decision: GateDecision;
  failureClass: GateFailureClass;
  receiptId: string;
  baseHash: string;
  candidateHash: string | null;
  finalHash: string;
  policyHash: string;
  checks: Array<{
    id: string;
    status: GateCheckStatus;
    reasonCode: string | null;
  }>;
  changedPaths: string[];
  threadDisposition: "resumed" | "reset";
  candidateCleanup: "deleted" | "deferred";
  baseViewId?: string | null;
  nextViewId?: string | null;
  baseGeneration?: number | null;
  nextGeneration?: number | null;
  proposalId?: string | null;
  proposalHash?: string | null;
  evaluationContextHash?: string | null;
  evidenceDigest?: string | null;
  permitId?: string | null;
  permitState?: "ISSUED" | "CONSUMING" | "CONSUMED" | "REVOKED" | null;
  artifactRetention?: "destroyed" | "version_snapshot" | "deferred";
  provider?: ModelProviderIdentity | null;
  lifecycle?: Array<{ sequence: number; name: GateLifecycleEventName }>;
  /** Present for Worker-authority results so the product DB can project, never derive, HEAD. */
  finalView?: StateViewRef;
  /** Derived from authoritative hashes; never accepted as an authorization input. */
  effectProof?: EffectDispositionProof;
}

export type WorkspaceVersionKind = "INITIAL" | "AGENT_COMMIT" | "ROLLBACK";

export interface WorkspaceVersion {
  id: string;
  agentId: string;
  sequence: number;
  parentVersionId: string | null;
  kind: WorkspaceVersionKind;
  snapshotHash: string;
  liveStateHash: string;
  pathPolicyHash: string;
  sourceRunId: string | null;
  sourceReceiptId: string | null;
  rollbackTargetVersionId: string | null;
  changedPaths: string[];
  snapshotAvailable: boolean;
  generation: number;
  viewId: string | null;
  transitionEventId: string | null;
  createdAt: string;
}

export interface SnapshotMetadata {
  agentId: string;
  hash: string;
  sizeBytes: number;
  state: "available" | "pruned";
  createdAt: string;
}

export interface Agent {
  id: string;
  name: string;
  description: string;
  instructions: string;
  status: AgentStatus;
  /** Logical compatibility field; production filesystem authority is workspaceRef. */
  workspacePath: string;
  workspaceRef?: {
    authority: "transition-worker";
    agentId: string;
  };
  codexThreadId: string | null;
  sessionEpoch: number;
  needsReconciliation: boolean;
  headVersionId: string | null;
  stateGeneration: number;
  currentViewId: string;
  currentVersionedHash: string;
  currentPlatformManagedHash: string;
  currentLiveStateHash: string;
  agentConfigVersion: number;
  policyVersion: number;
  activeRunLeaseId: string | null;
  recoveryRequired: boolean;
  lastError: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface Message {
  id: string;
  agentId: string;
  runId: string;
  role: MessageRole;
  content: string;
  authority: MessageAuthority;
  viewId: string | null;
  proposalId: string | null;
  createdAt: string;
}

export interface RunUsage {
  inputTokens?: number;
  cachedInputTokens?: number;
  outputTokens?: number;
}

export interface AgentRun {
  id: string;
  agentId: string;
  status: RunStatus;
  prompt: string;
  output: string | null;
  error: string | null;
  usage: RunUsage | null;
  commitGate: CommitGateSummary | null;
  /** Read-only pre-v3 summary; never eligible for permit issuance or replay. */
  legacyReceipt: CommitGateSummary | null;
  transactionStatus: GateTransactionStatus;
  runLeaseId: string;
  submittedViewId: string;
  baseViewId: string;
  proposalId: string | null;
  evaluationContextHash: string | null;
  permitId: string | null;
  retryOfRunId: string | null;
  staleCallback: boolean;
  provider: ModelProviderIdentity | null;
  startedAt: string | null;
  completedAt: string | null;
  createdAt: string;
}

export interface Database {
  version: 3;
  agents: Agent[];
  messages: Message[];
  runs: AgentRun[];
  versions: WorkspaceVersion[];
  snapshots: SnapshotMetadata[];
}

export interface CreateAgentInput {
  name: string;
  description?: string | undefined;
  instructions?: string | undefined;
}

export interface UpdateAgentInput {
  name?: string | undefined;
  description?: string | undefined;
  instructions?: string | undefined;
}

export interface RunnerResult {
  output: string;
  threadId: string | null;
  usage: RunUsage | null;
  commitGate?: CommitGateSummary;
}

export interface RunnerRequest {
  runId: string;
  agentId: string;
  workspacePath: string;
  /** Opaque Worker-issued exchange reference; production Broker ignores workspacePath. */
  workspaceRef?: {
    volumeId: string;
    relativeSubpath: string;
    runId: string;
    agentId: string;
  };
  prompt: string;
  threadId: string | null;
  sessionEpoch?: number;
  runLeaseId?: string;
  baseViewId?: string;
  stateGeneration?: number;
  expectedHeadVersionId?: string | null;
  agentConfigVersion?: number;
  policyVersion?: number;
  baseVersionedHash?: string;
  basePlatformManagedHash?: string;
  baseLiveStateHash?: string;
  provider?: ModelProviderIdentity | null;
}

export interface RunnerCancellation {
  runId: string;
  runLeaseId: string;
  sessionEpoch: number;
}

export interface AgentRunner {
  run(request: RunnerRequest): Promise<RunnerResult>;
  cancel(agentId: string, cancellation?: RunnerCancellation): Promise<boolean>;
  isAvailable(): Promise<boolean>;
}
