import type { StateViewRef } from "./types.js";
import type {
  AdoptLegacyStateParams,
  AttemptPermitConsumptionParams,
  ApplyPromotionParams,
  ApplyRollbackParams,
  ArchiveAgentParams,
  DisposeRunParams,
  ExportProposalParams,
  InitializeAgentParams,
  IssuePermitParams,
  PlatformStateParams,
  PrepareParams,
  PrepareRunParams,
  RecordEvidenceParams,
  SealProposalParams,
  WorkerRpcRequestInput,
} from "./transition-worker/contracts.js";
import type { WorkerProjection } from "./transition-worker/projection.js";
import { TransitionWorkerRpcClient } from "./transition-worker/rpc.js";
import type {
  PreparedRunRef,
  VerifierWorkspaceRef,
  WorkerHealth,
} from "./transition-worker/worker.js";

export interface AuthorityHealth extends WorkerHealth {
  authority: "transition-worker";
}

export interface CandidateWorkspaceRef {
  volumeId: string;
  relativeSubpath: string;
  runId: string;
  agentId: string;
}

export interface AuthorityDisposition {
  decision: "COMMITTED" | "QUARANTINED" | "CONFLICTED" | "ABORTED";
  baseView: StateViewRef;
  finalView: StateViewRef;
  projection: WorkerProjection;
  eventSequence: number;
  eventDigest: string;
}

/**
 * Serializable authority boundary used by the production API. Every method is
 * expressible with IDs, digests and typed metadata; no method accepts a host
 * path, callback, shell command or client-authored receipt.
 */
export interface TransitionAuthorityClient {
  readonly mode: "worker";
  initialize(): Promise<AuthorityHealth>;
  initializeAgent(input: InitializeAgentParams): Promise<WorkerProjection>;
  adoptLegacyState(input: AdoptLegacyStateParams): Promise<WorkerProjection>;
  prepareRun(input: PrepareRunParams): Promise<PreparedRunRef>;
  prepare(input: PrepareParams): Promise<WorkerProjection>;
  sealProposal(input: SealProposalParams): Promise<WorkerProjection>;
  exportProposal(input: ExportProposalParams): Promise<VerifierWorkspaceRef>;
  recordEvidence(input: RecordEvidenceParams): Promise<WorkerProjection>;
  issuePermit(input: IssuePermitParams): Promise<WorkerProjection>;
  attemptPermitConsumption(input: AttemptPermitConsumptionParams): Promise<never>;
  applyPromotion(input: ApplyPromotionParams): Promise<WorkerProjection>;
  applyRollback(input: ApplyRollbackParams): Promise<WorkerProjection>;
  disposeRun(input: DisposeRunParams): Promise<WorkerProjection>;
  regeneratePlatformState(input: PlatformStateParams): Promise<WorkerProjection>;
  archiveAgent(input: ArchiveAgentParams): Promise<WorkerProjection>;
  getProjection(agentId: string): Promise<WorkerProjection>;
  recover(agentId: string): Promise<WorkerProjection>;
}

export class WorkerTransitionAuthorityClient implements TransitionAuthorityClient {
  readonly mode = "worker" as const;
  private readonly rpc: TransitionWorkerRpcClient;

  constructor(socketPath: string, private readonly timeoutMs = 30_000) {
    this.rpc = new TransitionWorkerRpcClient(socketPath);
  }

  async initialize(): Promise<AuthorityHealth> {
    const health = await this.rpc.request<WorkerHealth>(
      { method: "health", params: {} },
      this.timeoutMs,
    );
    if (health.status !== "ok") throw new Error("AUTHORITY_UNAVAILABLE");
    return { ...health, authority: "transition-worker" };
  }

  initializeAgent(input: InitializeAgentParams) {
    return this.request<WorkerProjection>({ method: "initializeAgent", params: input });
  }

  adoptLegacyState(input: AdoptLegacyStateParams) {
    return this.request<WorkerProjection>({ method: "adoptLegacyState", params: input });
  }

  prepareRun(input: PrepareRunParams) {
    return this.request<PreparedRunRef>({ method: "prepareRun", params: input });
  }

  prepare(input: PrepareParams) {
    return this.request<WorkerProjection>({ method: "prepare", params: input });
  }

  sealProposal(input: SealProposalParams) {
    return this.request<WorkerProjection>({ method: "sealProposal", params: input });
  }

  exportProposal(input: ExportProposalParams) {
    return this.request<VerifierWorkspaceRef>({ method: "exportProposal", params: input });
  }

  recordEvidence(input: RecordEvidenceParams) {
    return this.request<WorkerProjection>({ method: "recordEvidence", params: input });
  }

  issuePermit(input: IssuePermitParams) {
    return this.request<WorkerProjection>({ method: "issuePermit", params: input });
  }

  attemptPermitConsumption(input: AttemptPermitConsumptionParams): Promise<never> {
    return this.request<never>({ method: "attemptPermitConsumption", params: input });
  }

  applyPromotion(input: ApplyPromotionParams) {
    return this.request<WorkerProjection>({ method: "applyPromotion", params: input });
  }

  applyRollback(input: ApplyRollbackParams) {
    return this.request<WorkerProjection>({ method: "applyRollback", params: input });
  }

  disposeRun(input: DisposeRunParams) {
    return this.request<WorkerProjection>({ method: "disposeRun", params: input });
  }

  regeneratePlatformState(input: PlatformStateParams) {
    return this.request<WorkerProjection>({ method: "regeneratePlatformState", params: input });
  }

  archiveAgent(input: ArchiveAgentParams) {
    return this.request<WorkerProjection>({ method: "archiveAgent", params: input });
  }

  getProjection(agentId: string) {
    return this.rpc.request<WorkerProjection>(
      { method: "getProjection", params: { agentId } },
      this.timeoutMs,
    );
  }

  recover(agentId: string) {
    return this.rpc.request<WorkerProjection>(
      { method: "recoverAgent", params: { agentId } },
      this.timeoutMs,
    );
  }

  private request<T>(request: WorkerRpcRequestInput): Promise<T> {
    return this.rpc.request(request, this.timeoutMs);
  }
}
