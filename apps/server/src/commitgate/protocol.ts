import { createHash } from "node:crypto";
import type {
  CheckResult,
  EvaluationContext,
  EvidenceBundle,
  StateViewInput,
  StateViewRef,
} from "./types.js";

export function canonicalJson(value: unknown): string {
  const visit = (item: unknown): unknown => {
    if (Array.isArray(item)) return item.map(visit);
    if (item && typeof item === "object") {
      return Object.fromEntries(
        Object.entries(item as Record<string, unknown>)
          .filter(([, child]) => child !== undefined)
          .sort(([left], [right]) => left.localeCompare(right, "en"))
          .map(([key, child]) => [key, visit(child)]),
      );
    }
    if (typeof item === "number" && !Number.isFinite(item)) {
      throw new Error("Canonical JSON does not support non-finite numbers");
    }
    return item;
  };
  return JSON.stringify(visit(value));
}

export function sha256Canonical(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function assertDigest(value: string, field: string): void {
  if (!/^[a-f0-9]{64}$/.test(value)) throw new Error(field + " must be a SHA-256 digest");
}

export function computeStateViewId(input: StateViewInput): string {
  if (input.schemaVersion !== 1) throw new Error("Unsupported StateView schema");
  if (!Number.isSafeInteger(input.generation) || input.generation < 0) {
    throw new Error("StateView generation must be a non-negative safe integer");
  }
  for (const [field, value] of [
    ["versionedHash", input.versionedHash],
    ["platformManagedHash", input.platformManagedHash],
    ["liveStateHash", input.liveStateHash],
  ] as const) assertDigest(value, field);
  // ViewId is the digest of the complete canonical StateViewRef except viewId.
  // Including schemaVersion prevents a future schema from accidentally
  // reusing a v1 identifier for the same visible fields.
  return createHash("sha256")
    .update(
      JSON.stringify({
        schemaVersion: input.schemaVersion,
        agentId: input.agentId,
        headVersionId: input.headVersionId,
        generation: input.generation,
        versionedHash: input.versionedHash,
        platformManagedHash: input.platformManagedHash,
        liveStateHash: input.liveStateHash,
        sessionEpoch: input.sessionEpoch,
        agentConfigVersion: input.agentConfigVersion,
        policyVersion: input.policyVersion,
      }),
    )
    .digest("hex");
}

export function createStateViewRef(input: StateViewInput): StateViewRef {
  return { ...input, viewId: computeStateViewId(input) };
}

export function assertStateViewRef(view: StateViewRef): void {
  const { viewId, ...input } = view;
  if (computeStateViewId(input) !== viewId) throw new Error("STATE_VIEW_DIGEST_MISMATCH");
}

export function computeEvaluationContextHash(context: EvaluationContext): string {
  assertStateViewRef(context.baseView);
  return sha256Canonical(context);
}

export function computeCheckResultsHash(checks: readonly CheckResult[]): string {
  return sha256Canonical(
    checks.map((check) => ({
      id: check.id,
      status: check.status,
      exitCode: check.exitCode,
      durationMs: check.durationMs,
      outputHash: createHash("sha256").update(check.output).digest("hex"),
      timedOut: check.timedOut,
    })),
  );
}

export function createEvidenceBundle(
  input: Omit<EvidenceBundle, "digest" | "schemaVersion">,
): EvidenceBundle {
  const unsigned = { schemaVersion: 1 as const, ...input };
  return { ...unsigned, digest: sha256Canonical(unsigned) };
}

export function assertEvidenceBundle(bundle: EvidenceBundle): void {
  const { digest, ...unsigned } = bundle;
  if (sha256Canonical(unsigned) !== digest) throw new Error("EVIDENCE_DIGEST_MISMATCH");
}
