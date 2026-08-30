export interface TerminalReceiptProofContractRecord {
  label: string | null;
  expectedDecision: "COMMITTED" | "QUARANTINED" | "ABORTED" | null;
  declaredExpectedDecision: string | null;
  observedDecision: string | null;
  receiptId: string | null;
  runId: string | null;
  transitionId: string | null;
  eventDigest: string | null;
  bundleSchemaVersion: number | null;
  eventChainLength: number;
  fullEventChainValid: boolean;
  rollbackTargetVersionId: string | null;
  valid: boolean;
}

export const TERMINAL_RECEIPT_PROOF_CONTRACT: Readonly<
  Record<string, Readonly<{ decision: "COMMITTED" | "QUARANTINED" | "ABORTED"; rollback: boolean }>>
>;

export const BROWSER_CLEAN_CLONE_STEP_IDS: readonly string[];
export const BROWSER_CLEAN_CLONE_PRECONDITION_IDS: readonly string[];
export const BROWSER_CLEAN_CLONE_ARTIFACT_KINDS: readonly string[];
export const REAL_PROVIDER_E2E_SCENARIO_IDS: readonly string[];

export function declaredCurrentProviderE2EStatus(
  report: unknown,
): "verified" | "failed" | "unverified";

export function validateRealProviderE2EContract(
  report: unknown,
  expected?: { providerId?: string | null },
): { valid: boolean; reason: string | null };

export function validateTerminalReceiptProofSetContract(
  proofSet: unknown,
  expected?: { sourceRevision?: string | null; signingKeyId?: string | null },
): {
  valid: boolean;
  reason: string | null;
  requiredLabels: string[];
  labels: unknown[];
  identityUnique: boolean;
  records: TerminalReceiptProofContractRecord[];
};

export function validateBrowserReceiptArtifactBinding(
  artifacts: unknown,
  expected: { proofSetSha256: string | null; keyIdSha256: string | null },
): { valid: boolean; reason: string | null };

export function validateBrowserCleanCloneContract(
  report: unknown,
  expected?: {
    providerId?: string | null;
    proofSetSha256?: string | null;
    keyIdSha256?: string | null;
  },
): {
  valid: boolean;
  reason: string | null;
  checks: Record<string, boolean>;
  failedChecks: string[];
};
