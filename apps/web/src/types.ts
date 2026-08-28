export type AgentStatus = "ready" | "busy" | "stopped" | "error";
export type RunStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export type GateDecision = "COMMITTED" | "QUARANTINED" | "CONFLICTED" | "ABORTED";
export type MessageAuthority =
  | "INPUT"
  | "PROVISIONAL"
  | "AUTHORITATIVE"
  | "REJECTED"
  | "SUPERSEDED";

export interface StateViewRef {
  schemaVersion: number;
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

export interface ProviderIdentity {
  providerId?: string;
  gateway?: string;
  requestedModel?: string;
  /** Null means the gateway did not report the routed model; never infer it. */
  resolvedModel?: string | null;
  wireApi?: string;
  retryOfRunId?: string | null;
}

export interface CommitGateSummary {
  decision: GateDecision;
  failureClass:
    | "agent_wrong"
    | "evidence_broken"
    | "infra_errored"
    | "state_conflict"
    | null;
  receiptId: string;
  baseHash: string;
  candidateHash: string | null;
  finalHash: string;
  policyHash: string;
  checks: Array<{
    id: string;
    status: "PASS" | "FAIL" | "ERROR" | "SKIPPED";
    reasonCode: string | null;
  }>;
  changedPaths: string[];
  threadDisposition: "resumed" | "reset";
  candidateCleanup: "deleted" | "deferred";
  baseViewId?: string;
  nextViewId?: string | null;
  baseGeneration?: number;
  nextGeneration?: number | null;
  proposalId?: string | null;
  proposalHash?: string | null;
  /** Legacy UI alias used by early v3 drafts. */
  proposalArtifactHash?: string | null;
  evaluationContextHash?: string | null;
  evidenceDigest?: string | null;
  permitId?: string | null;
  permitState?: "ISSUED" | "CONSUMING" | "CONSUMED" | "REVOKED" | null;
  artifactRetention?: "destroyed" | "version_snapshot" | "deferred" | "pending" | "sealed";
  evidenceRetention?: "metadata-only" | "full";
  provider?: ProviderIdentity | null;
  lifecycle?: Array<{
    sequence: number;
    name:
      | "RUN_STARTED"
      | "PROPOSAL_SEALED"
      | "VERIFICATION_COMPLETED"
      | "PERMIT_ISSUED"
      | "VIEW_COMMITTED"
      | "SESSION_RESET"
      | "RUN_ABORTED";
  }>;
}

export interface GateReceipt {
  schemaVersion: number;
  runId: string;
  agentId: string;
  phase: "TERMINAL";
  decision: GateDecision;
  failureClass: CommitGateSummary["failureClass"];
  reasonCodes: string[];
  baseSnapshotHash: string;
  candidateSnapshotHash: string | null;
  patchHash: string | null;
  finalSnapshotHash: string;
  policyHash: string;
  checks: Array<{
    id: string;
    status: "PASS" | "FAIL" | "ERROR" | "SKIPPED";
    exitCode: number | null;
    durationMs: number;
    output: string;
    timedOut: boolean;
  }>;
  changedPaths: string[];
  threadDisposition: "resumed" | "reset";
  candidateCleanup: "deleted" | "deferred";
  sessionEpoch: number;
  versionId: string | null;
  promotionPendingDatabaseAck: boolean;
  startedAt: string;
  completedAt: string;
  evidence: Record<string, unknown>;
  baseView?: StateViewRef | null;
  nextView?: StateViewRef | null;
  baseViewId?: string;
  finalViewId?: string | null;
  baseGeneration?: number;
  nextGeneration?: number;
  /** Legacy alias retained for v1 receipt compatibility. */
  generation?: number;
  nextViewId?: string | null;
  proposalId?: string | null;
  proposalArtifactHash?: string | null;
  evaluationContextHash?: string | null;
  evidenceDigest?: string | null;
  permitId?: string | null;
  permitState?: "ISSUED" | "CONSUMING" | "CONSUMED" | "REVOKED" | null;
  artifactRetention?: "destroyed" | "pending" | "sealed";
  evidenceRetention?: "metadata-only" | "full";
  provider?: ProviderIdentity | null;
  transactionStatus?: "PENDING_PROMOTION" | "PENDING_DISPOSITION" | "TERMINAL";
}

export interface WorkspaceVersion {
  id: string;
  agentId: string;
  sequence: number;
  parentVersionId: string | null;
  kind: "INITIAL" | "AGENT_COMMIT" | "ROLLBACK";
  snapshotHash: string;
  liveStateHash: string;
  pathPolicyHash: string;
  sourceRunId: string | null;
  sourceReceiptId: string | null;
  rollbackTargetVersionId: string | null;
  changedPaths: string[];
  createdAt: string;
  snapshotAvailable: boolean;
  generation?: number;
  viewId?: string | null;
  transitionEventId?: string | null;
}

export interface Agent {
  id: string;
  name: string;
  description: string;
  instructions: string;
  status: AgentStatus;
  workspacePath: string;
  codexThreadId: string | null;
  sessionEpoch: number;
  needsReconciliation: boolean;
  headVersionId: string | null;
  stateGeneration?: number;
  currentViewId?: string | null;
  currentLiveStateHash?: string | null;
  /** Legacy compatibility alias; v3 uses currentLiveStateHash. */
  liveStateHash?: string | null;
  agentConfigVersion?: number;
  policyVersion?: number;
  activeRunLeaseId?: string | null;
  recoveryRequired: boolean;
  lastError: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface Message {
  id: string;
  agentId: string;
  runId: string;
  role: "user" | "assistant";
  content: string;
  authority?: MessageAuthority;
  viewId?: string | null;
  proposalId?: string | null;
  createdAt: string;
}

export interface AgentRun {
  id: string;
  agentId: string;
  status: RunStatus;
  prompt: string;
  output: string | null;
  error: string | null;
  usage: {
    inputTokens?: number;
    cachedInputTokens?: number;
    outputTokens?: number;
  } | null;
  commitGate: CommitGateSummary | null;
  legacyReceipt: CommitGateSummary | null;
  transactionStatus?:
    | "PREPARING"
    | "EXECUTING"
    | "SEALED"
    | "VERIFYING"
    | "PENDING_DISPOSITION"
    | "PENDING_PROMOTION"
    | "TERMINAL";
  runLeaseId?: string;
  submittedViewId?: string;
  baseViewId?: string;
  proposalId?: string | null;
  evaluationContextHash?: string | null;
  permitId?: string | null;
  retryOfRunId?: string | null;
  staleCallback?: boolean;
  provider?: ProviderIdentity | null;
  startedAt: string | null;
  completedAt: string | null;
  createdAt: string;
}

export interface SystemInfo {
  arkConfigured: boolean;
  arkBaseUrl: string;
  arkModel: string | null;
  codexAvailable: boolean;
  codexSandboxMode: string;
  runtimeProvider: "local-process" | "container";
  containerEngine: string | null;
  runtime: string;
  commitGateEnabled: boolean;
  commitGateReady: boolean;
  verifierAvailable: boolean;
  modelConfigured?: boolean;
  providerConfigured?: boolean;
  modelProvider?: "ark" | "openrouter" | string;
  modelBaseUrl?: string;
  modelGateway?: string;
  modelId?: string | null;
  modelWireApi?: string;
  modelAccessMode?: string;
  alternateProviderVerified?: boolean;
  officialProviderE2E?: "verified" | "failed" | "unverified" | string;
}
