import { z } from "zod";
import type {
  CheckResult,
  RequiredCheckPolicy,
  VerifierExecutionEnvironment,
} from "../commitgate/types.js";
import type { RunnerRequest, RunnerResult } from "../types.js";
import type { SignedBrokerAttestation } from "./attestation.js";

const identifier = z.string().min(1).max(160).regex(/^[A-Za-z0-9_.-]+$/);
const digest = z.string().regex(/^[a-f0-9]{64}$/);
const providerIdentitySchema = z.object({
  providerId: z.enum(["ark", "openrouter", "custom"]),
  gateway: z.string().url().max(2_048),
  requestedModel: z.string().min(1).max(512),
  resolvedModel: z.string().min(1).max(512).nullable(),
}).strict();

const workspaceRefSchema = z.object({
  volumeId: identifier,
  relativeSubpath: identifier,
  runId: identifier,
  agentId: identifier,
}).strict();

export const brokerRunRequestSchema = z.object({
  runId: identifier,
  agentId: identifier,
  workspacePath: z.string().min(1).max(4_096).optional(),
  workspaceRef: workspaceRefSchema.optional(),
  prompt: z.string().min(1).max(50_000),
  threadId: z.string().min(1).max(512).nullable(),
  sessionEpoch: z.number().int().nonnegative().optional(),
  runLeaseId: identifier.optional(),
  baseViewId: digest.optional(),
  stateGeneration: z.number().int().nonnegative().optional(),
  expectedHeadVersionId: z.string().min(1).max(256).nullable().optional(),
  agentConfigVersion: z.number().int().nonnegative().optional(),
  policyVersion: z.number().int().nonnegative().optional(),
  baseVersionedHash: digest.optional(),
  basePlatformManagedHash: digest.optional(),
  baseLiveStateHash: digest.optional(),
  provider: providerIdentitySchema.nullable().optional(),
}).strict().superRefine((request, context) => {
  if ((request.workspacePath ? 1 : 0) + (request.workspaceRef ? 1 : 0) !== 1) {
    context.addIssue({
      code: "custom",
      message: "Exactly one of workspacePath or workspaceRef is required",
      path: ["workspaceRef"],
    });
  }
  if (
    request.workspaceRef &&
    (request.workspaceRef.runId !== request.runId || request.workspaceRef.agentId !== request.agentId)
  ) {
    context.addIssue({ code: "custom", message: "Workspace ref binding mismatch", path: ["workspaceRef"] });
  }
});

const cancellationSchema = z.object({
  runId: identifier,
  runLeaseId: identifier,
  sessionEpoch: z.number().int().nonnegative(),
}).strict();

export const brokerReconcileRequestSchema = z.object({
  runId: identifier,
  agentId: identifier,
  runLeaseId: identifier,
  sessionEpoch: z.number().int().nonnegative(),
  scope: z.enum(["AGENT", "ALL"]),
}).strict();

export const brokerTeardownRequestSchema = brokerReconcileRequestSchema;

const trustedCheckSchema = z.object({
  id: identifier,
  runner: z.enum(["node", "python", "binary"]),
  entrypoint: z.string().min(1).max(512),
  args: z.array(z.string().max(4_096)).max(64),
  timeoutMs: z.number().int().min(1_000).max(120_000),
  scratchBytes: z.number().int().min(1_048_576).max(536_870_912),
}).strict();

export const brokerVerifierRequestSchema = z.object({
  runId: identifier,
  agentId: identifier,
  runLeaseId: identifier,
  sessionEpoch: z.number().int().nonnegative(),
  proposalId: identifier,
  verifierInputHash: digest,
  checkSpecHash: digest,
  workspaceRef: workspaceRefSchema,
  checks: z.array(trustedCheckSchema).min(1).max(32),
  timeoutMs: z.number().int().min(1_000).max(300_000),
  maxOutputBytes: z.number().int().min(1_024).max(4_194_304),
}).strict().superRefine((request, context) => {
  if (
    request.workspaceRef.runId !== request.runId ||
    request.workspaceRef.agentId !== request.agentId ||
    request.workspaceRef.volumeId !== `verify-${request.runId}` ||
    request.workspaceRef.relativeSubpath !== `verify-${request.runId}`
  ) {
    context.addIssue({ code: "custom", message: "Verifier workspace ref binding mismatch", path: ["workspaceRef"] });
  }
});

const brokerAttestationProofSchema = z.object({
  schemaVersion: z.literal(1),
  algorithm: z.literal("HMAC-SHA256"),
  keyId: z.string().regex(/^[a-f0-9]{24}$/),
  mac: digest,
}).strict();

const brokerRecordedCheckSchema = z.object({
  id: identifier,
  status: z.enum(["PASS", "FAIL", "ERROR", "SKIPPED"]),
  exitCode: z.number().int().nullable(),
  durationMs: z.number().int().nonnegative(),
  outputHash: digest,
  timedOut: z.boolean(),
}).strict();

const brokerVerifierEnvironmentPinsSchema = z.object({
  checkBundleHash: digest,
  verifierImageDigest: z.string().min(1).max(512),
  verifierConfigHash: digest,
  resourcePolicyHash: digest,
  sourceRevision: z.string().min(1).max(256),
}).strict();

const brokerRuntimeTeardownPayloadSchema = z.object({
  schemaVersion: z.literal(1),
  kind: z.literal("runtime-teardown"),
  runId: identifier,
  agentId: identifier,
  runLeaseId: identifier,
  sessionEpoch: z.number().int().nonnegative(),
  scope: z.enum(["AGENT", "ALL"]),
  containerExited: z.literal(true),
  containerRemoved: z.literal(true),
  mountsReleased: z.literal(true),
  source: z.enum(["runtime-attestation", "broker-reconciliation"]),
  resolvedModel: z.string().min(1).max(512).nullable().optional(),
}).strict();

const brokerVerifierPayloadSchema = z.object({
  schemaVersion: z.literal(1),
  kind: z.literal("verifier-result"),
  scope: z.literal("VERIFIER"),
  runId: identifier,
  agentId: identifier,
  runLeaseId: identifier,
  sessionEpoch: z.number().int().nonnegative(),
  proposalId: identifier,
  verifierInputHash: digest,
  checkSpecHash: digest,
  checkResultsHash: digest,
  coverage: z.enum(["complete", "partial", "unavailable"]),
  checks: z.array(brokerRecordedCheckSchema).min(1).max(32),
  environment: brokerVerifierEnvironmentPinsSchema,
}).strict();

export const signedBrokerRuntimeTeardownSchema = brokerRuntimeTeardownPayloadSchema.extend({
  brokerAttestation: brokerAttestationProofSchema,
}).strict();

export const signedBrokerVerifierAttestationSchema = brokerVerifierPayloadSchema.extend({
  brokerAttestation: brokerAttestationProofSchema,
}).strict();

export const brokerRpcRequestSchema = z.discriminatedUnion("method", [
  z.object({ id: z.string(), method: z.literal("health") }),
  z.object({ id: z.string(), method: z.literal("runAgent"), request: brokerRunRequestSchema }).strict(),
  z.object({ id: z.string(), method: z.literal("runVerifier"), request: brokerVerifierRequestSchema }).strict(),
  z.object({ id: z.string(), method: z.literal("cancel"), agentId: identifier, cancellation: cancellationSchema }).strict(),
  z.object({ id: z.string(), method: z.literal("teardown"), request: brokerTeardownRequestSchema }).strict(),
  z.object({ id: z.string(), method: z.literal("reconcile"), request: brokerReconcileRequestSchema }).strict(),
]);

export type BrokerRpcRequest = z.infer<typeof brokerRpcRequestSchema>;
export type BrokerRunWireRequest = Omit<RunnerRequest, "workspacePath"> & {
  workspacePath?: string;
};
export interface BrokerVerifierRequest {
  runId: string;
  agentId: string;
  runLeaseId: string;
  sessionEpoch: number;
  proposalId: string;
  verifierInputHash: string;
  checkSpecHash: string;
  workspaceRef: NonNullable<RunnerRequest["workspaceRef"]>;
  checks: RequiredCheckPolicy[];
  timeoutMs: number;
  maxOutputBytes: number;
}
export interface BrokerVerifierResult {
  checks: CheckResult[];
  environment: VerifierExecutionEnvironment;
  attestation: SignedBrokerVerifierAttestation;
}
export type BrokerReconcileRequest = z.infer<typeof brokerReconcileRequestSchema>;
export type BrokerTeardownRequest = z.infer<typeof brokerTeardownRequestSchema>;
export type BrokerRuntimeTeardownPayload = z.infer<typeof brokerRuntimeTeardownPayloadSchema>;
export type SignedBrokerRuntimeTeardownAttestation = SignedBrokerAttestation<
  BrokerRuntimeTeardownPayload
>;
export type RuntimeReconciliationAttestation = SignedBrokerRuntimeTeardownAttestation;
export type BrokerRecordedCheck = z.infer<typeof brokerRecordedCheckSchema>;
export type BrokerVerifierEnvironmentPins = z.infer<
  typeof brokerVerifierEnvironmentPinsSchema
>;
export type BrokerVerifierAttestationPayload = z.infer<typeof brokerVerifierPayloadSchema>;
export type SignedBrokerVerifierAttestation = SignedBrokerAttestation<
  BrokerVerifierAttestationPayload
>;
export type BrokerRpcRequestInput =
  | { id?: string; method: "health" }
  | { id?: string; method: "runAgent"; request: BrokerRunWireRequest }
  | { id?: string; method: "runVerifier"; request: BrokerVerifierRequest }
  | { id?: string; method: "cancel"; agentId: string; cancellation: z.infer<typeof cancellationSchema> }
  | { id?: string; method: "teardown"; request: BrokerTeardownRequest }
  | { id?: string; method: "reconcile"; request: BrokerReconcileRequest };

export type BrokerRpcResponse =
  | { id: string; ok: true; result: unknown }
  | { id: string; ok: false; error: { code: string; message: string } };

export interface RuntimeBrokerHealth {
  ready: boolean;
  runtimeAvailable: boolean;
  activeRuns: number;
}

export interface RuntimeBrokerDispatch {
  runAgent(request: BrokerRunWireRequest): Promise<RunnerResult>;
  runVerifier(request: BrokerVerifierRequest): Promise<BrokerVerifierResult>;
  cancel(agentId: string, cancellation: z.infer<typeof cancellationSchema>): Promise<boolean>;
  teardown(request: BrokerTeardownRequest): Promise<SignedBrokerRuntimeTeardownAttestation>;
  reconcile(request: BrokerReconcileRequest): Promise<RuntimeReconciliationAttestation>;
  health(): Promise<RuntimeBrokerHealth>;
}
