import type { GateDecision } from "../types.js";

/**
 * Small, mechanically checkable proof of the only two persistence outcomes
 * CommitGate claims.  It is deliberately derived from authoritative hashes
 * instead of trusting a caller-supplied success boolean.
 */
export interface EffectDispositionProof {
  /** Boolean compatibility projection; consult candidateObservation for unknown. */
  candidateChanged: boolean;
  candidateObservation: "changed" | "unchanged" | "unobserved";
  /** Admission base is kept separate when a conflict observes a newer HEAD. */
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

export function deriveEffectDispositionProof(input: {
  decision: GateDecision;
  baseHash: string;
  candidateHash: string | null;
  finalHash: string;
  sealedProposalHash?: string | null;
  verifierInputHash?: string | null;
  promotionSourceHash?: string | null;
  finalAuthoritativeHash?: string;
  /** Authoritative state immediately before this disposition, after any drift. */
  authoritativeBeforeHash?: string;
}): EffectDispositionProof {
  const committed = input.decision === "COMMITTED";
  const sealedProposalHash = input.sealedProposalHash ?? null;
  const verifierInputHash = input.verifierInputHash ?? null;
  const promotionSourceHash = input.promotionSourceHash ?? null;
  const finalAuthoritativeHash = input.finalAuthoritativeHash ?? input.finalHash;
  const authoritativeBeforeHash = input.authoritativeBeforeHash ?? input.baseHash;
  const candidateObservation = input.candidateHash === null
    ? "unobserved" as const
    : input.candidateHash === input.baseHash
      ? "unchanged" as const
      : "changed" as const;
  const exactPromotionBinding =
    sealedProposalHash !== null &&
    verifierInputHash !== null &&
    promotionSourceHash !== null &&
    sealedProposalHash === verifierInputHash &&
    sealedProposalHash === promotionSourceHash &&
    sealedProposalHash === finalAuthoritativeHash;
  return {
    candidateChanged: candidateObservation === "changed",
    candidateObservation,
    admissionBaseHash: input.baseHash,
    authoritativeBeforeHash,
    authoritativeAfterHash: input.finalHash,
    authoritativeChanged: input.finalHash !== authoritativeBeforeHash,
    sealedProposalHash,
    verifierInputHash,
    promotionSourceHash,
    finalAuthoritativeHash,
    invariant: committed ? "PROMOTED_EXACT_PROPOSAL" : "NO_PERSISTENT_EFFECT",
    invariantSatisfied: committed
      ? exactPromotionBinding
      : authoritativeBeforeHash === input.finalHash,
  };
}
