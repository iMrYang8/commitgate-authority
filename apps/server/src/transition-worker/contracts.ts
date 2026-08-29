import { z } from "zod";
import {
  signedBrokerRuntimeTeardownSchema,
  signedBrokerVerifierAttestationSchema,
} from "../runtime-broker/contracts.js";

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
    runId: identifier,
    runLeaseId: identifier,
    candidateVolumeId: identifier,
    expectedViewId: digest,
    expectedWorkspaceHash: digest,
    baseGeneration: z.number().int().nonnegative(),
    /**
     * Runtime binding used by the Broker restart handshake. Production
     * callers always supply it; optionality is retained only for reading the
     * pre-handshake development/test contract.
     */
    sessionEpoch: z.number().int().nonnegative().optional(),
  })
  .strict()
  .refine((value) => value.transitionId === value.runId, {
    message: "The Agent run must own its transition",
    path: ["runId"],
  });

const cancelRunParams = z
  .object({
    agentId: identifier,
    transitionId: identifier,
    runId: identifier,
    runLeaseId: identifier,
    expectedViewId: digest,
  })
  .strict()
  .refine((value) => value.transitionId === value.runId, {
    message: "The cancellation must bind the owning transition",
    path: ["runId"],
  });

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
    /**
     * New callers fence the current authoritative HEAD and request exactly one
     * fresh session epoch.  The Worker, not the caller, constructs the final
     * non-commit StateView.
     */
    expectedViewId: digest.optional(),
    nextSessionEpoch: z.number().int().nonnegative().optional(),
    /**
     * Read-only migration bridge for pre-proof-closure clients.  When present
     * it must equal the StateView independently derived by the Worker.
     */
    finalView: stateViewSchema.optional(),
    reasonCodes: z.array(z.string().min(1).max(128)).max(64),
  })
  .strict()
  .superRefine((value, context) => {
    const hasExpectedView = value.expectedViewId !== undefined;
    const hasNextEpoch = value.nextSessionEpoch !== undefined;
    if (hasExpectedView !== hasNextEpoch) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "expectedViewId and nextSessionEpoch must be supplied together",
      });
    }
    if (!hasExpectedView && value.finalView === undefined) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message: "A fenced session request or legacy finalView is required",
      });
    }
  });

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
    runtimeTeardownDigest: digest.optional(),
  })
  .strict();

const runtimeTeardownAttestationSchema = z
  .object({
    schemaVersion: z.literal(1),
    runId: identifier,
    agentId: identifier,
    runLeaseId: identifier,
    sessionEpoch: z.number().int().nonnegative(),
    scope: z.enum(["AGENT", "ALL"]),
    containerExited: z.literal(true),
    containerRemoved: z.literal(true),
    mountsReleased: z.literal(true),
    source: z.enum(["runtime-attestation", "broker-reconciliation"]),
  })
  .strict();

const recordRuntimeTeardownParams = z
  .object({
    agentId: identifier,
    transitionId: identifier,
    attestation: z.union([
      runtimeTeardownAttestationSchema,
      signedBrokerRuntimeTeardownSchema,
    ]),
  })
  .strict()
  .superRefine((value, context) => {
    if (
      value.transitionId !== value.attestation.runId ||
      value.agentId !== value.attestation.agentId
    ) {
      context.addIssue({
        code: "custom",
        message: "Runtime teardown attestation must bind the owning transition and Agent",
        path: ["attestation"],
      });
    }
  });

const evaluationContextSchema = z.object({
  schemaVersion: z.literal(1),
  runId: identifier,
  agentId: identifier,
  proposalId: identifier,
  baseView: stateViewSchema,
  manifestSchemaVersion: z.number().int().positive(),
  policyHash: digest,
  checkBundleHash: digest,
  checkSpecHash: digest,
  verifierImageDigest: z.string().min(1).max(512),
  verifierConfigHash: digest,
  resourcePolicyHash: z.string().min(1).max(512),
  sourceRevision: z.string().min(1).max(256),
}).strict();

const recordedCheckSchema = z.object({
  id: identifier,
  status: z.enum(["PASS", "FAIL", "ERROR", "SKIPPED"]),
  exitCode: z.number().int().nullable(),
  durationMs: z.number().int().nonnegative(),
  outputHash: digest,
  timedOut: z.boolean(),
}).strict();

const recordEvidenceParams = z
  .object({
    agentId: identifier,
    transitionId: identifier,
    proposalId: identifier,
    evaluationContextHash: digest,
    evidenceDigest: digest,
    evaluationContext: evaluationContextSchema.optional(),
    verifierInputHash: digest.optional(),
    checkResultsHash: digest.optional(),
    coverage: z.enum(["complete", "partial", "unavailable"]).optional(),
    requiredChecksPassed: z.boolean().optional(),
    checks: z.array(recordedCheckSchema).min(1).max(32).optional(),
    brokerAttestation: signedBrokerVerifierAttestationSchema.optional(),
  })
  .strict()
  .superRefine((value, context) => {
    const completeFields = [
      value.evaluationContext,
      value.verifierInputHash,
      value.checkResultsHash,
      value.coverage,
      value.requiredChecksPassed,
      value.checks,
    ];
    const supplied = completeFields.filter((item) => item !== undefined).length;
    if (supplied !== 0 && supplied !== completeFields.length) {
      context.addIssue({
        code: "custom",
        message: "Complete typed evidence fields must be supplied together",
      });
    }
  });

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
    // Compatibility-only assertion. The Worker derives the authoritative
    // next View from its current HEAD and the sealed proposal bytes.
    nextView: stateViewSchema.optional(),
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
    // Compatibility-only assertion. The Worker derives rollback state from
    // the Worker-owned snapshot and advances the session epoch itself.
    nextView: stateViewSchema.optional(),
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

const getReceiptProofParams = z
  .object({
    agentId: identifier,
    receiptId: identifier,
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
      method: z.literal("getReceiptProof"),
      params: getReceiptProofParams,
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
    .object({
      id: identifier,
      method: z.literal("recordRuntimeTeardown"),
      params: recordRuntimeTeardownParams,
    })
    .strict(),
  z
    .object({ id: identifier, method: z.literal("cancelRun"), params: cancelRunParams })
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
export type RecordRuntimeTeardownParams = z.infer<typeof recordRuntimeTeardownParams>;
export type RuntimeTeardownRecord = z.infer<typeof runtimeTeardownAttestationSchema>;
export type CancelRunParams = z.infer<typeof cancelRunParams>;
export interface CancelRunResult {
  state: "CANCELLED" | "TOO_LATE" | "ALREADY_TERMINAL";
}
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
export type GetReceiptProofParams = z.infer<typeof getReceiptProofParams>;

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
