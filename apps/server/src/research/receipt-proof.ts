import { createHash, createPublicKey, sign, verify } from "node:crypto";

export interface ReceiptProofBody {
  schemaVersion: 1;
  runId: string;
  proposalId: string;
  logSequence: number;
  previousDigest: string | null;
  eventDigest: string;
  evaluationContextHash: string;
  evidenceDigest: string;
  permitId: string;
  decision: "COMMITTED" | "QUARANTINED" | "CONFLICTED" | "ABORTED";
}

export interface SignedReceiptProof extends ReceiptProofBody {
  signingKeyId: string;
  signatureAlgorithm: "Ed25519";
  signature: string;
}

const canonicalBytes = (body: ReceiptProofBody): Buffer =>
  Buffer.from(
    JSON.stringify({
      schemaVersion: body.schemaVersion,
      runId: body.runId,
      proposalId: body.proposalId,
      logSequence: body.logSequence,
      previousDigest: body.previousDigest,
      eventDigest: body.eventDigest,
      evaluationContextHash: body.evaluationContextHash,
      evidenceDigest: body.evidenceDigest,
      permitId: body.permitId,
      decision: body.decision,
    }),
    "utf8",
  );

export function receiptSigningKeyId(publicKeyPem: string): string {
  const der = createPublicKey(publicKeyPem).export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex").slice(0, 24);
}

export function signReceiptProof(
  body: ReceiptProofBody,
  privateKeyPem: string,
  publicKeyPem: string,
): SignedReceiptProof {
  const signature = sign(null, canonicalBytes(body), privateKeyPem).toString("base64url");
  return {
    ...body,
    signingKeyId: receiptSigningKeyId(publicKeyPem),
    signatureAlgorithm: "Ed25519",
    signature,
  };
}

export function verifyReceiptProof(
  proof: SignedReceiptProof,
  publicKeyPem: string,
): { valid: boolean; reason: string | null } {
  if (!proof || proof.schemaVersion !== 1 || proof.signatureAlgorithm !== "Ed25519") {
    return { valid: false, reason: "unsupported proof schema or algorithm" };
  }
  try {
    if (proof.signingKeyId !== receiptSigningKeyId(publicKeyPem)) {
      return { valid: false, reason: "signing key id mismatch" };
    }
    const { signingKeyId: _keyId, signatureAlgorithm: _algorithm, signature, ...body } = proof;
    const valid = verify(
      null,
      canonicalBytes(body),
      publicKeyPem,
      Buffer.from(signature, "base64url"),
    );
    return { valid, reason: valid ? null : "signature mismatch" };
  } catch {
    return { valid: false, reason: "malformed signature" };
  }
}

/**
 * Product proof envelope.  The signed body binds a canonical authority-owned
 * terminal receipt to the immutable transition event that produced it.  The
 * public key may travel with the bundle; its fingerprint is the stable key id.
 */
interface AuthorityReceiptRecordCommon {
  receiptId: string;
  runId: string;
  agentId: string;
  /** Worker-owned transition that produced the terminal receipt. */
  transitionId: string;
  decision: "COMMITTED" | "QUARANTINED" | "CONFLICTED" | "ABORTED";
  baseViewId: string;
  finalViewId: string;
  baseGeneration: number;
  nextGeneration: number;
  baseWorkspaceHash: string;
  finalWorkspaceHash: string;
  proposalId: string | null;
  proposalArtifactHash: string | null;
  verifierInputHash: string | null;
  promotionSourceHash: string | null;
  evaluationContextHash: string | null;
  evidenceDigest: string | null;
  permitId: string | null;
  permitState: "CONSUMED" | "REVOKED" | null;
  sourceRevision: string;
}

/**
 * Legacy product receipt.  In v1 `base*` was overloaded as both the proposal's
 * admission base and the authoritative state immediately before disposition.
 * That is only true when the HEAD did not drift, so a genuine CONFLICTED run
 * cannot be represented by this schema.
 */
export interface AuthorityReceiptRecordV1 extends AuthorityReceiptRecordCommon {
  schemaVersion: 1;
}

/**
 * Receipt v2 keeps the immutable Proposal base in the compatibility `base*`
 * fields and records the independently observed disposition-time HEAD.  A
 * rejected proposal proves no effect relative to the latter, not relative to
 * a stale admission snapshot.
 */
export interface AuthorityReceiptRecordV2 extends AuthorityReceiptRecordCommon {
  schemaVersion: 2;
  dispositionBaseViewId: string;
  dispositionBaseGeneration: number;
  dispositionBaseWorkspaceHash: string;
}

/** Receipt v3 binds the deployment-selected, Worker-owned policy pack. */
export interface AuthorityReceiptRecordV3 extends AuthorityReceiptRecordCommon {
  schemaVersion: 3;
  dispositionBaseViewId: string;
  dispositionBaseGeneration: number;
  dispositionBaseWorkspaceHash: string;
  policyProfile: "workspace-default" | "deployment-protected";
  policyVersion: number;
  policyHash: string;
  checkSpecHash: string;
}

export type AuthorityReceiptRecord =
  | AuthorityReceiptRecordV1
  | AuthorityReceiptRecordV2
  | AuthorityReceiptRecordV3;

export interface AuthorityReceiptProofBody {
  schemaVersion: 2;
  receiptHash: string;
  runId: string;
  agentId: string;
  decision: AuthorityReceiptRecord["decision"];
  logSequence: number;
  previousDigest: string | null;
  eventDigest: string;
  sourceRevision: string;
}

export interface SignedAuthorityReceiptProof extends AuthorityReceiptProofBody {
  signingKeyId: string;
  signatureAlgorithm: "Ed25519";
  signature: string;
}

export interface AuthorityReceiptProofBundle {
  /** v2 is retained for offline verification of already-issued bundles. */
  schemaVersion: 2 | 3;
  receipt: AuthorityReceiptRecord;
  proof: SignedAuthorityReceiptProof;
  /** Canonical event envelope allows an offline verifier to recompute digest. */
  terminalEvent: AuthorityTerminalEventEnvelope;
  /** One-event predecessor checkpoint proves the terminal previousDigest link. */
  predecessorEvent: AuthorityTerminalEventEnvelope | null;
  /** v3 carries the complete authority event prefix from genesis to terminal. */
  eventChain?: AuthorityTerminalEventEnvelope[];
  publicKeyPem: string;
}

export interface AuthorityTerminalEventEnvelope {
  schemaVersion: 1;
  eventId: string;
  agentId: string;
  transitionId: string;
  sequence: number;
  type: string;
  previousDigest: string | null;
  payload: Record<string, unknown>;
  createdAt: string;
  digest: string;
}

function authorityEventDigest(event: AuthorityTerminalEventEnvelope): string {
  const { digest: _digest, ...unsigned } = event;
  return createHash("sha256").update(JSON.stringify(unsigned)).digest("hex");
}

const authorityIdPattern = /^[A-Za-z0-9_.-]{1,128}$/;
const sha256Pattern = /^[a-f0-9]{64}$/;

function dispositionBase(receipt: AuthorityReceiptRecord): {
  viewId: string;
  generation: number;
  workspaceHash: string;
} | null {
  if (receipt.schemaVersion === 1) {
    return {
      viewId: receipt.baseViewId,
      generation: receipt.baseGeneration,
      workspaceHash: receipt.baseWorkspaceHash,
    };
  }
  if (
    !sha256Pattern.test(receipt.dispositionBaseViewId) ||
    !Number.isSafeInteger(receipt.dispositionBaseGeneration) ||
    receipt.dispositionBaseGeneration < 0 ||
    !sha256Pattern.test(receipt.dispositionBaseWorkspaceHash)
  ) return null;
  return {
    viewId: receipt.dispositionBaseViewId,
    generation: receipt.dispositionBaseGeneration,
    workspaceHash: receipt.dispositionBaseWorkspaceHash,
  };
}

function authorityReceiptSemanticError(receipt: AuthorityReceiptRecord): string | null {
  if (![1, 2, 3].includes(receipt.schemaVersion)) {
    return "authority receipt schema invalid";
  }
  if (receipt.schemaVersion === 1 && receipt.decision === "CONFLICTED") {
    return "legacy receipt cannot prove conflict disposition base";
  }
  const beforeDisposition = dispositionBase(receipt);
  if (!beforeDisposition) return "authority receipt disposition base invalid";
  const requiredIds = [
    receipt.receiptId,
    receipt.runId,
    receipt.agentId,
    receipt.transitionId,
  ];
  const optionalIds = [receipt.proposalId, receipt.permitId];
  const requiredDigests = [
    receipt.baseViewId,
    receipt.finalViewId,
    receipt.baseWorkspaceHash,
    receipt.finalWorkspaceHash,
  ];
  const optionalDigests = [
    receipt.proposalArtifactHash,
    receipt.verifierInputHash,
    receipt.promotionSourceHash,
    receipt.evaluationContextHash,
    receipt.evidenceDigest,
  ];
  if (
    !requiredIds.every((value) => authorityIdPattern.test(value)) ||
    !optionalIds.every((value) => value === null || authorityIdPattern.test(value)) ||
    !requiredDigests.every((value) => sha256Pattern.test(value)) ||
    !optionalDigests.every((value) => value === null || sha256Pattern.test(value)) ||
    !Number.isSafeInteger(receipt.baseGeneration) ||
    receipt.baseGeneration < 0 ||
    !Number.isSafeInteger(receipt.nextGeneration) ||
    receipt.nextGeneration < 0 ||
    typeof receipt.sourceRevision !== "string" ||
    receipt.sourceRevision.length < 1 ||
    receipt.sourceRevision.length > 256 ||
    !["COMMITTED", "QUARANTINED", "CONFLICTED", "ABORTED"].includes(receipt.decision) ||
    ![null, "CONSUMED", "REVOKED"].includes(receipt.permitState)
  ) {
    return "authority receipt field format invalid";
  }
  if (
    receipt.schemaVersion === 3 &&
    (!["workspace-default", "deployment-protected"].includes(receipt.policyProfile) ||
      !Number.isSafeInteger(receipt.policyVersion) ||
      receipt.policyVersion < 1 ||
      !sha256Pattern.test(receipt.policyHash) ||
      !sha256Pattern.test(receipt.checkSpecHash))
  ) {
    return "authority receipt policy binding invalid";
  }
  if ((receipt.permitId === null) !== (receipt.permitState === null)) {
    return "authority receipt permit binding invalid";
  }
  if (receipt.decision === "COMMITTED") {
    if (
      beforeDisposition.viewId !== receipt.baseViewId ||
      beforeDisposition.generation !== receipt.baseGeneration ||
      beforeDisposition.workspaceHash !== receipt.baseWorkspaceHash ||
      receipt.nextGeneration !== beforeDisposition.generation + 1 ||
      receipt.permitState !== "CONSUMED" ||
      receipt.proposalId === null ||
      receipt.permitId === null ||
      receipt.evaluationContextHash === null ||
      receipt.evidenceDigest === null ||
      typeof receipt.proposalArtifactHash !== "string" ||
      typeof receipt.verifierInputHash !== "string" ||
      typeof receipt.promotionSourceHash !== "string" ||
      receipt.proposalArtifactHash !== receipt.verifierInputHash ||
      receipt.proposalArtifactHash !== receipt.promotionSourceHash ||
      receipt.proposalArtifactHash !== receipt.finalWorkspaceHash
    ) {
      return "committed receipt semantic invariant mismatch";
    }
    return null;
  }
  if (
    receipt.nextGeneration !== beforeDisposition.generation ||
    receipt.finalWorkspaceHash !== beforeDisposition.workspaceHash ||
    receipt.permitState === "CONSUMED"
  ) {
    return "non-commit receipt semantic invariant mismatch";
  }
  const proposalBaseMatchesDisposition =
    receipt.baseViewId === beforeDisposition.viewId &&
    receipt.baseGeneration === beforeDisposition.generation &&
    receipt.baseWorkspaceHash === beforeDisposition.workspaceHash;
  if (
    receipt.schemaVersion >= 2 &&
    receipt.decision === "CONFLICTED" &&
    proposalBaseMatchesDisposition
  ) {
    return "conflicted receipt has no base drift";
  }
  if (
    receipt.schemaVersion >= 2 &&
    receipt.decision !== "CONFLICTED" &&
    !proposalBaseMatchesDisposition
  ) {
    return "non-conflict receipt disposition base mismatch";
  }
  return null;
}

function terminalReceiptBindingError(
  receipt: AuthorityReceiptRecord,
  terminal: AuthorityTerminalEventEnvelope,
): string | null {
  if (terminal.payload.receiptId !== receipt.receiptId) {
    return "terminal event receipt id mismatch";
  }
  if (receipt.decision === "COMMITTED") {
    return terminal.type === "TRANSITION_ACKNOWLEDGED"
      ? null
      : "committed receipt terminal event type mismatch";
  }
  if (!["NON_COMMIT_DISPOSITIONED", "VIEW_DISPOSITIONED"].includes(terminal.type)) {
    return "non-commit receipt terminal event type mismatch";
  }
  if (
    terminal.payload.decision !== receipt.decision ||
    terminal.payload.workspaceHash !== receipt.finalWorkspaceHash ||
    terminal.payload.viewId !== receipt.finalViewId
  ) {
    return "non-commit terminal event payload mismatch";
  }
  const beforeDisposition = dispositionBase(receipt);
  if (
    receipt.schemaVersion >= 2 &&
    (!beforeDisposition || terminal.payload.previousViewId !== beforeDisposition.viewId)
  ) {
    return "non-commit disposition base event mismatch";
  }
  return null;
}

const canonicalAuthorityReceipt = (receipt: AuthorityReceiptRecord): Buffer => {
  const canonical = {
    schemaVersion: receipt.schemaVersion,
    receiptId: receipt.receiptId,
    runId: receipt.runId,
    agentId: receipt.agentId,
    transitionId: receipt.transitionId,
    decision: receipt.decision,
    baseViewId: receipt.baseViewId,
    finalViewId: receipt.finalViewId,
    baseGeneration: receipt.baseGeneration,
    nextGeneration: receipt.nextGeneration,
    baseWorkspaceHash: receipt.baseWorkspaceHash,
    ...(receipt.schemaVersion !== 1
      ? {
          dispositionBaseViewId: receipt.dispositionBaseViewId,
          dispositionBaseGeneration: receipt.dispositionBaseGeneration,
          dispositionBaseWorkspaceHash: receipt.dispositionBaseWorkspaceHash,
        }
      : {}),
    ...(receipt.schemaVersion === 3
      ? {
          policyProfile: receipt.policyProfile,
          policyVersion: receipt.policyVersion,
          policyHash: receipt.policyHash,
          checkSpecHash: receipt.checkSpecHash,
        }
      : {}),
    finalWorkspaceHash: receipt.finalWorkspaceHash,
    proposalId: receipt.proposalId,
    proposalArtifactHash: receipt.proposalArtifactHash,
    verifierInputHash: receipt.verifierInputHash,
    promotionSourceHash: receipt.promotionSourceHash,
    evaluationContextHash: receipt.evaluationContextHash,
    evidenceDigest: receipt.evidenceDigest,
    permitId: receipt.permitId,
    permitState: receipt.permitState,
    sourceRevision: receipt.sourceRevision,
  };
  return Buffer.from(JSON.stringify(canonical), "utf8");
};

const canonicalAuthorityProofBody = (body: AuthorityReceiptProofBody): Buffer =>
  Buffer.from(JSON.stringify({
    schemaVersion: body.schemaVersion,
    receiptHash: body.receiptHash,
    runId: body.runId,
    agentId: body.agentId,
    decision: body.decision,
    logSequence: body.logSequence,
    previousDigest: body.previousDigest,
    eventDigest: body.eventDigest,
    sourceRevision: body.sourceRevision,
  }), "utf8");

export function authorityReceiptHash(receipt: AuthorityReceiptRecord): string {
  return createHash("sha256").update(canonicalAuthorityReceipt(receipt)).digest("hex");
}

export function signAuthorityReceiptProof(
  receipt: AuthorityReceiptRecord,
  event: AuthorityTerminalEventEnvelope,
  eventChainOrPredecessor:
    | readonly AuthorityTerminalEventEnvelope[]
    | AuthorityTerminalEventEnvelope
    | null,
  privateKeyPem: string,
  publicKeyPem: string,
): AuthorityReceiptProofBundle {
  const eventChain = Array.isArray(eventChainOrPredecessor)
    ? eventChainOrPredecessor.map((entry) => structuredClone(entry))
    : undefined;
  const predecessorEvent = eventChain
    ? eventChain.length > 1
      ? eventChain[eventChain.length - 2]!
      : null
    : eventChainOrPredecessor as AuthorityTerminalEventEnvelope | null;
  const body: AuthorityReceiptProofBody = {
    schemaVersion: 2,
    receiptHash: authorityReceiptHash(receipt),
    runId: receipt.runId,
    agentId: receipt.agentId,
    decision: receipt.decision,
    logSequence: event.sequence,
    previousDigest: event.previousDigest,
    eventDigest: event.digest,
    sourceRevision: receipt.sourceRevision,
  };
  return {
    schemaVersion: eventChain ? 3 : 2,
    receipt,
    proof: {
      ...body,
      signingKeyId: receiptSigningKeyId(publicKeyPem),
      signatureAlgorithm: "Ed25519",
      signature: sign(null, canonicalAuthorityProofBody(body), privateKeyPem).toString("base64url"),
    },
    terminalEvent: structuredClone(event),
    predecessorEvent: predecessorEvent ? structuredClone(predecessorEvent) : null,
    ...(eventChain ? { eventChain } : {}),
    publicKeyPem,
  };
}

function authorityEventChainError(
  chain: readonly AuthorityTerminalEventEnvelope[],
  terminal: AuthorityTerminalEventEnvelope,
  agentId: string,
): string | null {
  if (chain.length === 0) return "authority event chain is empty";
  let previous: AuthorityTerminalEventEnvelope | null = null;
  for (const event of chain) {
    if (
      !event ||
      typeof event !== "object" ||
      event.schemaVersion !== 1 ||
      event.agentId !== agentId ||
      event.sequence !== (previous?.sequence ?? 0) + 1 ||
      event.previousDigest !== (previous?.digest ?? null) ||
      authorityEventDigest(event) !== event.digest
    ) {
      return "authority event chain binding mismatch";
    }
    previous = event;
  }
  if (
    !previous ||
    previous.eventId !== terminal.eventId ||
    previous.sequence !== terminal.sequence ||
    previous.digest !== terminal.digest
  ) {
    return "authority event chain terminal mismatch";
  }
  return null;
}

/**
 * Prove that the Proposal/Evidence/Permit named by a terminal receipt are not
 * merely self-consistent signed fields: they must be the unique facts emitted
 * by this transition in the same append-only authority chain.
 */
function authorityTransitionFactsError(
  receipt: AuthorityReceiptRecord,
  chain: readonly AuthorityTerminalEventEnvelope[],
  terminal: AuthorityTerminalEventEnvelope,
): string | null {
  const transitionEvents = chain.filter(
    (event) => event.transitionId === receipt.transitionId,
  );
  const eventsOfType = (type: string) =>
    transitionEvents.filter((event) => event.type === type);
  const unique = (type: string): AuthorityTerminalEventEnvelope | null => {
    const matches = eventsOfType(type);
    return matches.length === 1 ? matches[0]! : null;
  };
  const beforeTerminal = (event: AuthorityTerminalEventEnvelope) =>
    event.sequence < terminal.sequence;

  const proposalEvents = eventsOfType("PROPOSAL_SEALED");
  if (receipt.proposalId === null) {
    if (proposalEvents.length !== 0) {
      return "receipt omits proposal recorded by authority chain";
    }
  } else {
    const proposal = unique("PROPOSAL_SEALED");
    if (
      !proposal ||
      !beforeTerminal(proposal) ||
      proposal.payload.proposalId !== receipt.proposalId ||
      proposal.payload.baseViewId !== receipt.baseViewId ||
      proposal.payload.artifactHash !== receipt.proposalArtifactHash
    ) {
      return "proposal event receipt binding mismatch";
    }
  }

  const evidenceFields = [
    receipt.verifierInputHash,
    receipt.evaluationContextHash,
    receipt.evidenceDigest,
  ];
  const evidencePresent = evidenceFields.some((value) => value !== null);
  if (evidencePresent && !evidenceFields.every((value) => value !== null)) {
    return "receipt evidence fields are incomplete";
  }
  const evidenceEvents = eventsOfType("EVIDENCE_RECORDED");
  if (!evidencePresent) {
    if (evidenceEvents.length !== 0) {
      return "receipt omits evidence recorded by authority chain";
    }
  } else {
    const evidence = unique("EVIDENCE_RECORDED");
    if (
      !evidence ||
      !beforeTerminal(evidence) ||
      evidence.payload.proposalId !== receipt.proposalId ||
      evidence.payload.verifierInputHash !== receipt.verifierInputHash ||
      evidence.payload.evaluationContextHash !== receipt.evaluationContextHash ||
      evidence.payload.evidenceDigest !== receipt.evidenceDigest
    ) {
      return "evidence event receipt binding mismatch";
    }
  }

  const issuedEvents = eventsOfType("PERMIT_ISSUED");
  const consumingEvents = eventsOfType("PERMIT_CONSUMING");
  if (receipt.permitId === null) {
    if (issuedEvents.length !== 0 || consumingEvents.length !== 0) {
      return "receipt omits permit recorded by authority chain";
    }
  } else {
    const issued = unique("PERMIT_ISSUED");
    if (
      !issued ||
      !beforeTerminal(issued) ||
      issued.payload.permitId !== receipt.permitId ||
      issued.payload.proposalId !== receipt.proposalId ||
      issued.payload.baseViewId !== receipt.baseViewId ||
      issued.payload.targetArtifactHash !== receipt.promotionSourceHash ||
      issued.payload.evaluationContextHash !== receipt.evaluationContextHash ||
      issued.payload.evidenceDigest !== receipt.evidenceDigest
    ) {
      return "permit issue event receipt binding mismatch";
    }
    if (receipt.permitState === "CONSUMED" && consumingEvents.length !== 1) {
      return "consumed permit event is missing or duplicated";
    }
    if (consumingEvents.length > 1) {
      return "permit consuming event is duplicated";
    }
    const consuming = consumingEvents[0];
    if (
      consuming &&
      (!beforeTerminal(consuming) ||
        consuming.payload.permitId !== receipt.permitId ||
        consuming.payload.proposalId !== receipt.proposalId ||
        consuming.payload.targetArtifactHash !== receipt.promotionSourceHash)
    ) {
      return "permit consuming event receipt binding mismatch";
    }
  }

  const appliedEvents = eventsOfType("WORKSPACE_APPLIED");
  if (receipt.decision === "COMMITTED") {
    const applied = unique("WORKSPACE_APPLIED");
    const appliedView = applied?.payload.view;
    if (
      !applied ||
      !beforeTerminal(applied) ||
      applied.payload.workspaceHash !== receipt.finalWorkspaceHash ||
      !appliedView ||
      typeof appliedView !== "object" ||
      (appliedView as Record<string, unknown>).viewId !== receipt.finalViewId
    ) {
      return "workspace-applied event receipt binding mismatch";
    }
  } else if (appliedEvents.length !== 0) {
    return "non-commit receipt contains workspace-applied event";
  }
  return null;
}

export function verifyAuthorityReceiptProof(
  bundle: AuthorityReceiptProofBundle,
): { valid: boolean; reason: string | null } {
  if (
    !bundle ||
    typeof bundle !== "object" ||
    !bundle.receipt ||
    typeof bundle.receipt !== "object" ||
    !bundle.proof ||
    typeof bundle.proof !== "object" ||
    typeof bundle.publicKeyPem !== "string"
  ) {
    return { valid: false, reason: "malformed authority proof bundle" };
  }
  const { receipt, proof, publicKeyPem } = bundle;
  if (
    ![2, 3].includes(bundle.schemaVersion) ||
    ![1, 2, 3].includes(receipt.schemaVersion) ||
    proof.schemaVersion !== 2 ||
    proof.signatureAlgorithm !== "Ed25519"
  ) {
    return { valid: false, reason: "unsupported proof schema or algorithm" };
  }
  try {
    if (proof.signingKeyId !== receiptSigningKeyId(publicKeyPem)) {
      return { valid: false, reason: "signing key id mismatch" };
    }
    if (proof.receiptHash !== authorityReceiptHash(receipt)) {
      return { valid: false, reason: "receipt hash mismatch" };
    }
  } catch {
    return { valid: false, reason: "malformed public key or receipt" };
  }
  if (
    proof.runId !== receipt.runId ||
    proof.agentId !== receipt.agentId ||
    proof.decision !== receipt.decision ||
    proof.sourceRevision !== receipt.sourceRevision
  ) {
    return { valid: false, reason: "receipt proof binding mismatch" };
  }
  const terminal = bundle.terminalEvent;
  const predecessor = bundle.predecessorEvent;
  if (
    !terminal ||
    typeof terminal !== "object" ||
    terminal.schemaVersion !== 1 ||
    terminal.agentId !== receipt.agentId ||
    terminal.transitionId !== receipt.transitionId ||
    terminal.sequence !== proof.logSequence ||
    terminal.previousDigest !== proof.previousDigest ||
    terminal.digest !== proof.eventDigest ||
    authorityEventDigest(terminal) !== terminal.digest
  ) {
    return { valid: false, reason: "terminal event digest binding mismatch" };
  }
  const terminalBindingError = terminalReceiptBindingError(receipt, terminal);
  if (terminalBindingError) return { valid: false, reason: terminalBindingError };
  if (bundle.schemaVersion === 3) {
    if (!Array.isArray(bundle.eventChain)) {
      return { valid: false, reason: "authority event chain is missing" };
    }
    const chainError = authorityEventChainError(bundle.eventChain, terminal, receipt.agentId);
    if (chainError) return { valid: false, reason: chainError };
    const expectedPredecessor = bundle.eventChain.length > 1
      ? bundle.eventChain[bundle.eventChain.length - 2]!
      : null;
    if (
      (expectedPredecessor === null) !== (predecessor === null) ||
      (expectedPredecessor !== null &&
        (predecessor?.eventId !== expectedPredecessor.eventId ||
          predecessor.digest !== expectedPredecessor.digest))
    ) {
      return { valid: false, reason: "terminal event predecessor binding mismatch" };
    }
    const transitionFactsError = authorityTransitionFactsError(
      receipt,
      bundle.eventChain,
      terminal,
    );
    if (transitionFactsError) {
      return { valid: false, reason: transitionFactsError };
    }
  } else {
    if (terminal.sequence === 1) {
      if (terminal.previousDigest !== null || predecessor !== null) {
        return { valid: false, reason: "terminal event predecessor binding mismatch" };
      }
    } else if (
      !predecessor ||
      predecessor.schemaVersion !== 1 ||
      predecessor.agentId !== terminal.agentId ||
      predecessor.sequence !== terminal.sequence - 1 ||
      authorityEventDigest(predecessor) !== predecessor.digest ||
      terminal.previousDigest !== predecessor.digest
    ) {
      return { valid: false, reason: "terminal event predecessor binding mismatch" };
    }
  }
  const {
    signingKeyId: _keyId,
    signatureAlgorithm: _algorithm,
    signature,
    ...body
  } = proof;
  try {
    const valid = verify(
      null,
      canonicalAuthorityProofBody(body),
      publicKeyPem,
      Buffer.from(signature, "base64url"),
    );
    if (!valid) return { valid: false, reason: "signature mismatch" };
    const semanticError = authorityReceiptSemanticError(receipt);
    if (semanticError) return { valid: false, reason: semanticError };
    return { valid: true, reason: null };
  } catch {
    return { valid: false, reason: "malformed signature" };
  }
}
