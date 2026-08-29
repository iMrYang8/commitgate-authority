import { defaultCommitGatePolicy, policyHash } from "./commitgate/policy.js";
import { computeCheckSpecHash } from "./commitgate/trusted-check-bundle.js";
import type {
  CommitGatePolicy,
  EvaluationContext,
  RequiredCheckPolicy,
} from "./commitgate/types.js";

/**
 * The product Worker, rather than an API caller, owns this authorization
 * contract.  Callers may submit verifier evidence, but they cannot select the
 * policy or the trusted checks which authorize a persistent effect.
 */
const WORKSPACE_SANITY_CHECK: RequiredCheckPolicy = Object.freeze({
  id: "workspace-sanity",
  runner: "node",
  entrypoint: "workspace-sanity.mjs",
  args: Object.freeze([]) as unknown as string[],
  timeoutMs: 15_000,
  scratchBytes: 64 * 1024 * 1024,
});

const FROZEN_WORKER_GATE_POLICY: CommitGatePolicy = Object.freeze({
  ...defaultCommitGatePolicy,
  protectedPaths: Object.freeze([...defaultCommitGatePolicy.protectedPaths]) as unknown as string[],
  platformManagedPaths: Object.freeze([...defaultCommitGatePolicy.platformManagedPaths]) as unknown as string[],
  ignoredEphemeralNames: Object.freeze([...defaultCommitGatePolicy.ignoredEphemeralNames]) as unknown as string[],
  canaryPatterns: Object.freeze([...defaultCommitGatePolicy.canaryPatterns]) as unknown as string[],
  requiredChecks: Object.freeze([WORKSPACE_SANITY_CHECK]) as unknown as RequiredCheckPolicy[],
});

export const WORKER_MANIFEST_SCHEMA_VERSION = 2 as const;
export const WORKER_GATE_POLICY_HASH = policyHash(FROZEN_WORKER_GATE_POLICY);
export const WORKER_CHECK_SPEC_HASH = computeCheckSpecHash(
  FROZEN_WORKER_GATE_POLICY.requiredChecks,
);
export const WORKER_REQUIRED_CHECK_IDS = Object.freeze(
  FROZEN_WORKER_GATE_POLICY.requiredChecks.map((check) => check.id),
);

export function workerGatePolicy(): CommitGatePolicy {
  return structuredClone(FROZEN_WORKER_GATE_POLICY);
}

export interface WorkerRecordedCheckContract {
  id: string;
  status: "PASS" | "FAIL" | "ERROR" | "SKIPPED";
  exitCode: number | null;
  timedOut: boolean;
}

export interface WorkerEvidenceContractInput {
  context: EvaluationContext;
  checks: readonly WorkerRecordedCheckContract[];
  coverage: "complete" | "partial" | "unavailable";
  requiredChecksPassed: boolean;
  sourceRevision: string;
  requireEnvironmentPins: boolean;
  expectedCheckBundleHash?: string;
  expectedVerifierImageDigest?: string;
  expectedVerifierConfigHash?: string;
  expectedResourcePolicyHash?: string;
}

export interface WorkerEvidenceContractFailure {
  code:
    | "MANIFEST_SCHEMA_MISMATCH"
    | "POLICY_HASH_MISMATCH"
    | "CHECK_SPEC_HASH_MISMATCH"
    | "SOURCE_REVISION_MISMATCH"
    | "WORKER_GATE_CONFIG_INCOMPLETE"
    | "CHECK_BUNDLE_HASH_MISMATCH"
    | "VERIFIER_IMAGE_DIGEST_MISMATCH"
    | "VERIFIER_CONFIG_HASH_MISMATCH"
    | "RESOURCE_POLICY_HASH_MISMATCH"
    | "TRUSTED_CHECK_COVERAGE_INCOMPLETE"
    | "TRUSTED_CHECK_SET_MISMATCH"
    | "TRUSTED_CHECK_FAILED";
  message: string;
}

/**
 * Recomputes the authorization decision from Worker-owned constants.  In
 * particular, `requiredChecksPassed` is only cross-checked; it is never used as
 * an authority-bearing boolean.
 */
export function validateWorkerEvidenceContract(
  input: WorkerEvidenceContractInput,
): WorkerEvidenceContractFailure | null {
  if (input.context.manifestSchemaVersion !== WORKER_MANIFEST_SCHEMA_VERSION) {
    return {
      code: "MANIFEST_SCHEMA_MISMATCH",
      message: `Evidence manifest schema ${input.context.manifestSchemaVersion} is not Worker schema ${WORKER_MANIFEST_SCHEMA_VERSION}`,
    };
  }
  if (input.context.policyHash !== WORKER_GATE_POLICY_HASH) {
    return {
      code: "POLICY_HASH_MISMATCH",
      message: "Evidence policy hash is not the Worker-owned policy",
    };
  }
  if (input.context.checkSpecHash !== WORKER_CHECK_SPEC_HASH) {
    return {
      code: "CHECK_SPEC_HASH_MISMATCH",
      message: "Evidence check specification is not the Worker-owned trusted-check contract",
    };
  }
  if (input.context.sourceRevision !== input.sourceRevision) {
    return {
      code: "SOURCE_REVISION_MISMATCH",
      message: "Evidence source revision does not match the Transition Worker",
    };
  }
  const expectedPins = [
    input.expectedCheckBundleHash,
    input.expectedVerifierImageDigest,
    input.expectedVerifierConfigHash,
    input.expectedResourcePolicyHash,
  ];
  if (input.requireEnvironmentPins && expectedPins.some((value) => !value)) {
    return {
      code: "WORKER_GATE_CONFIG_INCOMPLETE",
      message: "Production Worker is missing a frozen Verifier environment pin",
    };
  }
  if (
    input.expectedCheckBundleHash !== undefined &&
    input.context.checkBundleHash !== input.expectedCheckBundleHash
  ) {
    return {
      code: "CHECK_BUNDLE_HASH_MISMATCH",
      message: "Evidence trusted-check bundle hash is not the Worker-pinned bundle",
    };
  }
  if (
    input.expectedVerifierImageDigest !== undefined &&
    input.context.verifierImageDigest !== input.expectedVerifierImageDigest
  ) {
    return {
      code: "VERIFIER_IMAGE_DIGEST_MISMATCH",
      message: "Evidence Verifier image digest is not the Worker-pinned image",
    };
  }
  if (
    input.expectedVerifierConfigHash !== undefined &&
    input.context.verifierConfigHash !== input.expectedVerifierConfigHash
  ) {
    return {
      code: "VERIFIER_CONFIG_HASH_MISMATCH",
      message: "Evidence Verifier config hash is not the Worker-pinned config",
    };
  }
  if (
    input.expectedResourcePolicyHash !== undefined &&
    input.context.resourcePolicyHash !== input.expectedResourcePolicyHash
  ) {
    return {
      code: "RESOURCE_POLICY_HASH_MISMATCH",
      message: "Evidence resource-policy hash is not the Worker-pinned policy",
    };
  }
  if (input.coverage !== "complete") {
    return {
      code: "TRUSTED_CHECK_COVERAGE_INCOMPLETE",
      message: "Trusted-check coverage is not complete",
    };
  }

  const observedIds = input.checks.map((check) => check.id);
  const observedUnique = new Set(observedIds);
  if (
    observedIds.length !== WORKER_REQUIRED_CHECK_IDS.length ||
    observedUnique.size !== observedIds.length ||
    !WORKER_REQUIRED_CHECK_IDS.every((id) => observedUnique.has(id))
  ) {
    return {
      code: "TRUSTED_CHECK_SET_MISMATCH",
      message: "Evidence check IDs do not exactly match the Worker-owned trusted-check set",
    };
  }

  const independentlyPassed = input.checks.every(
    (check) => check.status === "PASS" && check.exitCode === 0 && !check.timedOut,
  );
  if (!independentlyPassed || input.requiredChecksPassed !== independentlyPassed) {
    return {
      code: "TRUSTED_CHECK_FAILED",
      message: "Every Worker-required trusted check must independently PASS",
    };
  }
  return null;
}
