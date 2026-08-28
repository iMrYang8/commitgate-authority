import { z } from "zod";

const identifier = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9_.-]+$/);
const digest = z.string().regex(/^[a-f0-9]{64}$/);
const decision = z.enum(["COMMITTED", "QUARANTINED", "CONFLICTED", "ABORTED"]);

export const stateViewSchema = z
  .object({
    schemaVersion: z.literal(1),
    viewId: digest,
    agentId: identifier,
    headVersionId: z.string().min(1).max(256),
    generation: z.number().int().nonnegative(),
    versionedHash: digest,
    platformManagedHash: digest,
    liveStateHash: digest,
    sessionEpoch: z.number().int().nonnegative(),
    agentConfigVersion: z.number().int().nonnegative(),
    policyVersion: z.number().int().nonnegative(),
  })
  .strict();

const prepareParams = z
  .object({
    agentId: identifier,
    transitionId: identifier,
    kind: z.enum(["AGENT_COMMIT", "ROLLBACK"]),
    expectedViewId: digest.nullable(),
    expectedWorkspaceHash: digest,
    baseGeneration: z.number().int().nonnegative(),
  })
  .strict();

const initializeAgentParams = z
  .object({
    agentId: identifier,
    operationId: identifier,
    headVersionId: identifier,
    generation: z.number().int().nonnegative(),
    sessionEpoch: z.number().int().nonnegative(),
    agentConfigVersion: z.number().int().nonnegative(),
    policyVersion: z.number().int().nonnegative(),
    name: z.string().min(1).max(200),
    instructions: z.string().max(50_000),
  })
  .strict();

const adoptLegacyStateParams = z
  .object({
    agentId: identifier,
    operationId: identifier,
    sourceVolumeId: identifier.optional(),
    legacyAgentId: identifier.optional(),
    expectedWorkspaceHash: digest,
    adoptedView: stateViewSchema,
    versionId: identifier,
  })
  .strict()
  .refine(
    (value) => Number(value.sourceVolumeId !== undefined) + Number(value.legacyAgentId !== undefined) === 1,
    "Exactly one legacy source reference is required",
  );

const prepareRunParams = z
  .object({
    agentId: identifier,
    transitionId: identifier,
    candidateVolumeId: identifier,
    expectedViewId: digest,
    expectedWorkspaceHash: digest,
    baseGeneration: z.number().int().nonnegative(),
  })
  .strict();

const exportProposalParams = z
  .object({
    agentId: identifier,
    transitionId: identifier,
    proposalId: identifier,
    exportVolumeId: identifier,
  })
  .strict();

const disposeRunParams = z
  .object({
    agentId: identifier,
    transitionId: identifier,
    receiptId: identifier,
    decision: decision.exclude(["COMMITTED"]),
    finalView: stateViewSchema,
    reasonCodes: z.array(z.string().min(1).max(128)).max(64),
  })
  .strict();

const platformStateParams = z
  .object({
    agentId: identifier,
    operationId: identifier,
    expectedViewId: digest,
    expectedWorkspaceHash: digest,
    instructions: z.string().max(50_000),
    sessionEpoch: z.number().int().nonnegative(),
    agentConfigVersion: z.number().int().nonnegative(),
    policyVersion: z.number().int().nonnegative(),
  })
  .strict();

const archiveAgentParams = z
  .object({
    agentId: identifier,
    operationId: identifier,
    expectedViewId: digest,
    expectedWorkspaceHash: digest,
  })
  .strict();

const sealProposalParams = z
  .object({
    agentId: identifier,
    transitionId: identifier,
    proposalId: identifier,
    sourceVolumeId: identifier,
    baseViewId: digest,
    expectedArtifactHash: digest.optional(),
  })
  .strict();

const recordEvidenceParams = z
  .object({
    agentId: identifier,
    transitionId: identifier,
    proposalId: identifier,
    evaluationContextHash: digest,
    evidenceDigest: digest,
  })
  .strict();

const issuePermitParams = z
  .object({
    agentId: identifier,
    transitionId: identifier,
    permitId: identifier,
    proposalId: identifier,
    baseViewId: digest,
    targetArtifactHash: digest,
    evaluationContextHash: digest,
    evidenceDigest: digest,
    expiresAt: z.string().datetime(),
  })
  .strict();

const attemptPermitConsumptionParams = z
  .object({
    agentId: identifier,
    transitionId: identifier,
    permitId: identifier,
    expectedViewId: digest,
  })
  .strict();

const promotionParams = z
  .object({
    agentId: identifier,
    transitionId: identifier,
    permitId: identifier,
    proposalId: identifier,
    expectedViewId: digest,
    expectedWorkspaceHash: digest,
    nextView: stateViewSchema,
    versionId: identifier,
    receiptId: identifier,
  })
  .strict();

const rollbackParams = z
  .object({
    agentId: identifier,
    transitionId: identifier,
    rollbackPermitId: identifier,
    targetSnapshotId: digest,
    targetVersionId: identifier,
    expectedViewId: digest,
    expectedWorkspaceHash: digest,
    nextView: stateViewSchema,
    versionId: identifier,
    receiptId: identifier,
  })
  .strict();

const repairParams = z
  .object({
    agentId: identifier,
    transitionId: identifier,
    action: z.enum(["forward", "rollback"]),
    expectedViewId: digest,
    expectedWorkspaceHash: digest,
  })
  .strict();

export const rpcRequestSchema = z.discriminatedUnion("method", [
  z.object({ id: identifier, method: z.literal("health"), params: z.object({}).strict() }).strict(),
  z
    .object({
      id: identifier,
      method: z.literal("getProjection"),
      params: z.object({ agentId: identifier }).strict(),
    })
    .strict(),
  z
    .object({
      id: identifier,
      method: z.literal("rebuildProjection"),
      params: z.object({ agentId: identifier }).strict(),
    })
    .strict(),
  z
    .object({
      id: identifier,
      method: z.literal("recoverAgent"),
      params: z.object({ agentId: identifier }).strict(),
    })
    .strict(),
  z
    .object({ id: identifier, method: z.literal("initializeAgent"), params: initializeAgentParams })
    .strict(),
  z
    .object({ id: identifier, method: z.literal("adoptLegacyState"), params: adoptLegacyStateParams })
    .strict(),
  z
    .object({ id: identifier, method: z.literal("prepareRun"), params: prepareRunParams })
    .strict(),
  z
    .object({ id: identifier, method: z.literal("exportProposal"), params: exportProposalParams })
    .strict(),
  z
    .object({ id: identifier, method: z.literal("disposeRun"), params: disposeRunParams })
    .strict(),
  z
    .object({ id: identifier, method: z.literal("regeneratePlatformState"), params: platformStateParams })
    .strict(),
  z
    .object({ id: identifier, method: z.literal("archiveAgent"), params: archiveAgentParams })
    .strict(),
  z.object({ id: identifier, method: z.literal("prepare"), params: prepareParams }).strict(),
  z
    .object({ id: identifier, method: z.literal("sealProposal"), params: sealProposalParams })
    .strict(),
  z
    .object({ id: identifier, method: z.literal("recordEvidence"), params: recordEvidenceParams })
    .strict(),
  z.object({ id: identifier, method: z.literal("issuePermit"), params: issuePermitParams }).strict(),
  z
    .object({
      id: identifier,
      method: z.literal("attemptPermitConsumption"),
      params: attemptPermitConsumptionParams,
    })
    .strict(),
  z.object({ id: identifier, method: z.literal("applyPromotion"), params: promotionParams }).strict(),
  z.object({ id: identifier, method: z.literal("applyRollback"), params: rollbackParams }).strict(),
  z.object({ id: identifier, method: z.literal("repair"), params: repairParams }).strict(),
]);

export type WorkerRpcRequest = z.infer<typeof rpcRequestSchema>;
export type WorkerRpcRequestInput = WorkerRpcRequest extends infer TRequest
  ? TRequest extends { id: string }
    ? Omit<TRequest, "id"> & { id?: string }
    : never
  : never;
export type PrepareParams = z.infer<typeof prepareParams>;
export type InitializeAgentParams = z.infer<typeof initializeAgentParams>;
export type AdoptLegacyStateParams = z.infer<typeof adoptLegacyStateParams>;
export type PrepareRunParams = z.infer<typeof prepareRunParams>;
export type ExportProposalParams = z.infer<typeof exportProposalParams>;
export type DisposeRunParams = z.infer<typeof disposeRunParams>;
export type PlatformStateParams = z.infer<typeof platformStateParams>;
export type ArchiveAgentParams = z.infer<typeof archiveAgentParams>;
export type SealProposalParams = z.infer<typeof sealProposalParams>;
export type RecordEvidenceParams = z.infer<typeof recordEvidenceParams>;
export type IssuePermitParams = z.infer<typeof issuePermitParams>;
export type AttemptPermitConsumptionParams = z.infer<typeof attemptPermitConsumptionParams>;
export type ApplyPromotionParams = z.infer<typeof promotionParams>;
export type ApplyRollbackParams = z.infer<typeof rollbackParams>;
export type RepairParams = z.infer<typeof repairParams>;

export interface WorkerRpcSuccess {
  id: string;
  ok: true;
  result: unknown;
}

export interface WorkerRpcFailure {
  id: string;
  ok: false;
  error: {
    code: string;
    message: string;
  };
}

export type WorkerRpcResponse = WorkerRpcSuccess | WorkerRpcFailure;
