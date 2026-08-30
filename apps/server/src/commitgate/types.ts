import type {
  CommitGateSummary,
  EffectDispositionProof,
  ModelProviderIdentity,
  RunnerResult,
} from "../types.js";

export type PathClass = "versioned" | "platformManaged" | "ignoredEphemeral";

export type GatePhase =
  | "PREPARING"
  | "EXECUTING"
  | "VERIFYING"
  | "PROMOTING"
  | "TERMINAL";

export type GateDecision = "COMMITTED" | "QUARANTINED" | "CONFLICTED" | "ABORTED";
export type FailureClass =
  | "agent_wrong"
  | "evidence_broken"
  | "infra_errored"
  | "state_conflict";
export type CheckStatus = "PASS" | "FAIL" | "ERROR" | "SKIPPED";
export type EvidenceCoverage = "complete" | "partial" | "unavailable";

export interface RequiredCheckPolicy {
  id: string;
  runner: "node" | "python" | "binary";
  entrypoint: string;
  args: string[];
  timeoutMs: number;
  scratchBytes: number;
}

export interface CommitGatePolicy {
  schemaVersion: 1;
  protectedPaths: string[];
  platformManagedPaths: string[];
  ignoredEphemeralNames: string[];
  maxChangedFiles: number;
  maxChangedBytes: number;
  maxSingleFileBytes: number;
  verifierTimeoutMs: number;
  verifierMaxOutputBytes: number;
  canaryPatterns: string[];
  requiredChecks: RequiredCheckPolicy[];
}

export interface ManifestEntry {
  path: string;
  type: "file" | "dir" | "symlink";
  mode: number;
  size: number;
  contentHash?: string;
  linkTarget?: string;
  pathClass: PathClass;
}

export interface SnapshotManifest {
  schemaVersion: 2;
  entries: ManifestEntry[];
  hash: string;
}

/**
 * A complete reference to the authoritative state that admitted a run.  The
 * view id is a digest of every other field; a matching workspace hash alone is
 * deliberately insufficient because it cannot distinguish an ABA transition.
 */
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

export type StateViewInput = Omit<StateViewRef, "viewId">;

export interface StateViewCaptureInput {
  agentId: string;
  persistentPath: string;
  headVersionId: string;
  generation: number;
  versionedHash: string;
  platformManagedHash: string;
  liveStateHash: string;
  sessionEpoch: number;
  agentConfigVersion: number;
  policyVersion: number;
}

/** Product integrations may supply their database generation through this hook. */
export interface StateViewProvider {
  capture(input: StateViewCaptureInput): Promise<StateViewRef> | StateViewRef;
}

export interface SealedProposal {
  schemaVersion: 1;
  proposalId: string;
  runId: string;
  agentId: string;
  baseViewId: string;
  artifactHash: string;
  manifestHash: string;
  changedPathsDigest: string;
  runtimeTeardownDigest: string;
  state: "SEALED" | "DESTROYED";
  sealedAt: string;
}

export interface EvaluationContext {
  schemaVersion: 1;
  runId: string;
  agentId: string;
  proposalId: string;
  baseView: StateViewRef;
  manifestSchemaVersion: number;
  policyHash: string;
  checkBundleHash: string;
  checkSpecHash: string;
  verifierImageDigest: string;
  verifierConfigHash: string;
  resourcePolicyHash: string;
  sourceRevision: string;
}

export interface EvidenceBundle {
  schemaVersion: 1;
  proposalId: string;
  evaluationContextHash: string;
  verifierInputHash: string;
  checkResultsHash: string;
  coverage: EvidenceCoverage;
  /** Signed verdict over the required trusted-check set, not a caller-side boolean. */
  requiredChecksPassed: boolean;
  issuedAt: string;
  digest: string;
}

export type PromotionPermitState =
  | "ISSUED"
  | "CONSUMING"
  | "CONSUMED"
  | "REVOKED";

export interface PromotionPermit {
  schemaVersion: 1;
  permitId: string;
  runId: string;
  agentId: string;
  proposalId: string;
  baseViewId: string;
  targetArtifactHash: string;
  evaluationContextHash: string;
  evidenceDigest: string;
  nonce: string;
  expiresAt: string;
  state: PromotionPermitState;
  issuedAt: string;
  updatedAt: string;
}

export interface RollbackPermit {
  schemaVersion: 1;
  rollbackPermitId: string;
  runId: string;
  agentId: string;
  targetVersionId: string;
  targetSnapshotHash: string;
  expectedHeadVersionId: string;
  baseHash: string;
  nonce: string;
  expiresAt: string;
  state: PromotionPermitState;
  issuedAt: string;
  updatedAt: string;
}

export interface VerifierExecutionEnvironment {
  imageReference: string;
  imageId: string;
  imageDigest: string;
  configHash: string;
  checkBundleHash: string;
  resourcePolicyHash?: string;
  sourceRevision?: string;
}

export type ManifestChangeKind = "added" | "modified" | "deleted";
export interface ManifestChange {
  path: string;
  kind: ManifestChangeKind;
  before: ManifestEntry | null;
  after: ManifestEntry | null;
}

export interface CheckResult {
  id: string;
  status: CheckStatus;
  exitCode: number | null;
  durationMs: number;
  output: string;
  timedOut: boolean;
}

export interface VerificationResult {
  coverage: EvidenceCoverage;
  checks: CheckResult[];
  changes: ManifestChange[];
  candidateManifest: SnapshotManifest;
  candidateHashBefore: string;
  candidateHashAfter: string;
  staticFailures: string[];
  policyHash: string;
}

export interface PreparedCandidate {
  runId: string;
  agentId: string;
  persistentPath: string;
  controlPath: string;
  candidatePath: string;
  verifyPath: string;
  baseManifest: SnapshotManifest;
  baseSnapshotHash: string;
  baseView: StateViewRef;
  policy: CommitGatePolicy;
  policyHash: string;
  policyPath: string | null;
  runLeaseId: string;
  runtimeTeardownDigest: string;
  runtimeTeardownVerified: boolean;
  sessionEpoch: number;
  /** Admission-time identity. resolvedModel remains null unless the gateway reports it. */
  provider: ModelProviderIdentity | null;
  startedAt: string;
}

export interface GateReceipt {
  /** v3 additionally binds the deployment-selected Worker policy profile. */
  schemaVersion: 1 | 2 | 3;
  runId: string;
  agentId: string;
  phase: "PENDING_PROMOTION" | "PENDING_DISPOSITION" | "TERMINAL";
  decision: GateDecision;
  failureClass: FailureClass | null;
  reasonCodes: string[];
  baseSnapshotHash: string;
  candidateSnapshotHash: string | null;
  patchHash: string | null;
  finalSnapshotHash: string;
  policyHash: string;
  policyProfile?: "workspace-default" | "deployment-protected";
  policyVersion?: number;
  checkSpecHash?: string;
  evidence: Record<string, EvidenceCoverage>;
  checks: CheckResult[];
  changedPaths: string[];
  threadDisposition: "resumed" | "reset";
  candidateCleanup: "deleted" | "deferred";
  sessionEpoch: number;
  versionId: string | null;
  promotionPendingDatabaseAck: boolean;
  /** Protocol-v2 bindings. Optional only while reading legacy receipts. */
  baseView?: StateViewRef | null;
  nextView?: StateViewRef | null;
  baseViewId?: string;
  finalViewId?: string | null;
  /** Authoritative workspace generation at run admission. */
  baseGeneration?: number;
  /** Authoritative workspace generation after terminal disposition. */
  nextGeneration?: number;
  /** @deprecated Legacy alias. New v2 receipts set this to nextGeneration. */
  generation?: number;
  proposalId?: string | null;
  evaluationContextHash?: string | null;
  evidenceDigest?: string | null;
  permitId?: string | null;
  permitState?: PromotionPermitState | null;
  transactionStatus?: "PENDING_PROMOTION" | "PENDING_DISPOSITION" | "TERMINAL";
  artifactRetention?: "destroyed" | "sealed" | "version_snapshot" | "deferred";
  /** Optional only for legacy receipts written before provider evidence existed. */
  provider?: ModelProviderIdentity | null;
  /** Read/API projection only. Promotion never trusts this derived value. */
  effectProof?: EffectDispositionProof;
  startedAt: string;
  completedAt: string;
}

export type CommitGateSummaryData = CommitGateSummary;

export interface CommitGateRunnerResult extends RunnerResult {
  commitGate: CommitGateSummaryData;
}

export interface VerifierInput {
  runId: string;
  agentId: string;
  runLeaseId?: string;
  sessionEpoch?: number;
  verifyPath: string;
  workspaceRef?: {
    volumeId: string;
    relativeSubpath: string;
    runId: string;
    agentId: string;
  };
  trustedChecksPath: string;
  checks: RequiredCheckPolicy[];
  timeoutMs: number;
  maxOutputBytes: number;
  proposalId?: string;
  evaluationContextHash?: string;
  checkBundleHash?: string;
  signal?: AbortSignal;
}

export interface VerifierRunner {
  run(input: VerifierInput): Promise<CheckResult[]>;
  describeExecutionEnvironment?(runId?: string):
    | Promise<VerifierExecutionEnvironment>
    | VerifierExecutionEnvironment;
}

export type VersionKind = "INITIAL" | "AGENT_COMMIT" | "ROLLBACK";
export interface WorkspaceVersionRecord {
  id: string;
  agentId: string;
  sequence: number;
  kind: VersionKind;
  snapshotHash: string;
  /** Hash of the normalized policy at event creation; absent only on legacy indexes. */
  policyHash?: string;
  parentVersionId: string | null;
  rollbackTargetVersionId: string | null;
  runId: string | null;
  createdAt: string;
  snapshotAvailable: boolean;
}

export interface SnapshotMetadataRecord {
  hash: string;
  relativePath: string;
  sizeBytes: number;
  refCount: number;
  createdAt: string;
  prunedAt: string | null;
}

export interface VersionIndex {
  schemaVersion: 1;
  agentId: string;
  headVersionId: string | null;
  versions: WorkspaceVersionRecord[];
  snapshots: SnapshotMetadataRecord[];
}

export interface PromotionJournal {
  schemaVersion: 1;
  runId: string;
  agentId: string;
  kind: "PROMOTION" | "ROLLBACK";
  state:
    | "PREPARING"
    | "PROMOTING"
    | "PROMOTED_PENDING_DB"
    | "ACKNOWLEDGED"
    | "ROLLED_BACK";
  persistentPath: string;
  stagingPath: string;
  backupPath: string;
  sourcePath: string;
  baseHash: string;
  targetHash: string;
  targetVersionId: string | null;
  proposalId?: string | null;
  permitId?: string | null;
  baseViewId?: string | null;
  evaluationContextHash?: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface PromotionHandle {
  journal: PromotionJournal;
  acknowledge(): Promise<void>;
  rollback(): Promise<void>;
}

export interface GateFinalization {
  receipt: GateReceipt;
  summary: CommitGateSummaryData;
}
