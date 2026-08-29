import { createHash, generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  signAuthorityReceiptProof,
  signReceiptProof,
  verifyAuthorityReceiptProof,
  verifyReceiptProof,
  type AuthorityReceiptRecord,
  type AuthorityTerminalEventEnvelope,
  type ReceiptProofBody,
} from "./receipt-proof.js";

describe("signed receipt proof", () => {
  it("detects terminal proof tampering", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const body: ReceiptProofBody = {
      schemaVersion: 1,
      runId: "run-1",
      proposalId: "proposal-1",
      logSequence: 9,
      previousDigest: "a".repeat(64),
      eventDigest: "b".repeat(64),
      evaluationContextHash: "c".repeat(64),
      evidenceDigest: "d".repeat(64),
      permitId: "permit-1",
      decision: "COMMITTED",
    };
    const proof = signReceiptProof(body, privatePem, publicPem);
    expect(verifyReceiptProof(proof, publicPem)).toEqual({ valid: true, reason: null });
    expect(
      verifyReceiptProof({ ...proof, decision: "ABORTED" }, publicPem),
    ).toEqual({ valid: false, reason: "signature mismatch" });
  });

  it("binds a canonical authority receipt to its terminal event", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const receipt: AuthorityReceiptRecord = {
      schemaVersion: 1,
      receiptId: "receipt-1",
      runId: "run-1",
      agentId: "agent-1",
      transitionId: "run-1",
      decision: "COMMITTED",
      baseViewId: "a".repeat(64),
      finalViewId: "b".repeat(64),
      baseGeneration: 1,
      nextGeneration: 2,
      baseWorkspaceHash: "c".repeat(64),
      finalWorkspaceHash: "d".repeat(64),
      proposalId: "proposal-1",
      proposalArtifactHash: "d".repeat(64),
      verifierInputHash: "d".repeat(64),
      promotionSourceHash: "d".repeat(64),
      evaluationContextHash: "e".repeat(64),
      evidenceDigest: "f".repeat(64),
      permitId: "permit-1",
      permitState: "CONSUMED",
      sourceRevision: "revision-1",
    };
    const predecessorUnsigned = {
      schemaVersion: 1 as const,
      eventId: "event-7",
      agentId: "agent-1",
      transitionId: "run-1",
      sequence: 7,
      type: "WORKSPACE_APPLIED",
      previousDigest: "1".repeat(64),
      payload: { workspaceHash: "d".repeat(64) },
      createdAt: "2026-08-29T00:00:00.000Z",
    };
    const predecessor = {
      ...predecessorUnsigned,
      digest: createHash("sha256").update(JSON.stringify(predecessorUnsigned)).digest("hex"),
    };
    const terminalUnsigned = {
      schemaVersion: 1 as const,
      eventId: "event-8",
      agentId: "agent-1",
      transitionId: "run-1",
      sequence: 8,
      type: "TRANSITION_ACKNOWLEDGED",
      previousDigest: predecessor.digest,
      payload: { receiptId: "receipt-1" },
      createdAt: "2026-08-29T00:00:01.000Z",
    };
    const terminal = {
      ...terminalUnsigned,
      digest: createHash("sha256").update(JSON.stringify(terminalUnsigned)).digest("hex"),
    };
    const bundle = signAuthorityReceiptProof(
      receipt,
      terminal,
      predecessor,
      privatePem,
      publicPem,
    );
    expect(verifyAuthorityReceiptProof(bundle)).toEqual({ valid: true, reason: null });
    expect(
      verifyAuthorityReceiptProof({
        ...bundle,
        receipt: { ...bundle.receipt, finalWorkspaceHash: "0".repeat(64) },
      }),
    ).toEqual({ valid: false, reason: "receipt hash mismatch" });
    expect(
      verifyAuthorityReceiptProof({
        ...bundle,
        proof: { ...bundle.proof, sourceRevision: "other-revision" },
      }),
    ).toEqual({ valid: false, reason: "receipt proof binding mismatch" });
    expect(
      verifyAuthorityReceiptProof({
        ...bundle,
        terminalEvent: { ...bundle.terminalEvent, payload: { receiptId: "tampered" } },
      }),
    ).toEqual({ valid: false, reason: "terminal event digest binding mismatch" });
    const wrongTransitionReceipt = {
      ...receipt,
      transitionId: "different-transition",
    };
    expect(verifyAuthorityReceiptProof(signAuthorityReceiptProof(
      wrongTransitionReceipt,
      terminal,
      predecessor,
      privatePem,
      publicPem,
    ))).toEqual({ valid: false, reason: "terminal event digest binding mismatch" });
    const wrongProposalChain = {
      ...receipt,
      promotionSourceHash: "0".repeat(64),
    };
    expect(verifyAuthorityReceiptProof(signAuthorityReceiptProof(
      wrongProposalChain,
      terminal,
      predecessor,
      privatePem,
      publicPem,
    ))).toEqual({ valid: false, reason: "committed receipt semantic invariant mismatch" });
    expect(verifyAuthorityReceiptProof(signAuthorityReceiptProof(
      { ...receipt, nextGeneration: receipt.baseGeneration },
      terminal,
      predecessor,
      privatePem,
      publicPem,
    ))).toEqual({ valid: false, reason: "committed receipt semantic invariant mismatch" });
    expect(verifyAuthorityReceiptProof(signAuthorityReceiptProof(
      {
        ...receipt,
        decision: "ABORTED",
        nextGeneration: receipt.baseGeneration,
        finalWorkspaceHash: "0".repeat(64),
        permitState: "REVOKED",
      },
      {
        ...terminal,
        type: "NON_COMMIT_DISPOSITIONED",
        payload: {
          receiptId: receipt.receiptId,
          decision: "ABORTED",
          workspaceHash: "0".repeat(64),
          viewId: receipt.finalViewId,
        },
        digest: createHash("sha256").update(JSON.stringify({
          ...terminalUnsigned,
          type: "NON_COMMIT_DISPOSITIONED",
          payload: {
            receiptId: receipt.receiptId,
            decision: "ABORTED",
            workspaceHash: "0".repeat(64),
            viewId: receipt.finalViewId,
          },
        })).digest("hex"),
      },
      predecessor,
      privatePem,
      publicPem,
    ))).toEqual({ valid: false, reason: "non-commit receipt semantic invariant mismatch" });
    expect(
      verifyAuthorityReceiptProof({} as never),
    ).toEqual({ valid: false, reason: "malformed authority proof bundle" });
  });

  it("verifies a conflicted receipt against disposition-time HEAD and the full event chain", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const event = (
      sequence: number,
      previous: AuthorityTerminalEventEnvelope | null,
      transitionId: string,
      type: string,
      payload: Record<string, unknown>,
    ): AuthorityTerminalEventEnvelope => {
      const unsigned = {
        schemaVersion: 1 as const,
        eventId: `event-${sequence}`,
        agentId: "agent-conflict",
        transitionId,
        sequence,
        type,
        previousDigest: previous?.digest ?? null,
        payload,
        createdAt: `2026-08-29T00:00:0${sequence}.000Z`,
      };
      return {
        ...unsigned,
        digest: createHash("sha256").update(JSON.stringify(unsigned)).digest("hex"),
      };
    };
    const genesis = event(1, null, "initialize", "AGENT_INITIALIZED", { generation: 0 });
    const sealed = event(2, genesis, "stale-run", "PROPOSAL_SEALED", {
      proposalId: "proposal-stale",
      baseViewId: "a".repeat(64),
      artifactHash: "f".repeat(64),
    });
    const winning = event(3, sealed, "winning-run", "TRANSITION_ACKNOWLEDGED", {
      receiptId: "winning-receipt",
    });
    const proposalBaseViewId = "a".repeat(64);
    const dispositionBaseViewId = "b".repeat(64);
    const finalViewId = "c".repeat(64);
    const proposalBaseHash = "d".repeat(64);
    const winningHash = "e".repeat(64);
    const terminal = event(4, winning, "stale-run", "NON_COMMIT_DISPOSITIONED", {
      receiptId: "receipt-conflict",
      decision: "CONFLICTED",
      previousViewId: dispositionBaseViewId,
      viewId: finalViewId,
      workspaceHash: winningHash,
    });
    const receipt: AuthorityReceiptRecord = {
      schemaVersion: 2,
      receiptId: "receipt-conflict",
      runId: "stale-run",
      agentId: "agent-conflict",
      transitionId: "stale-run",
      decision: "CONFLICTED",
      baseViewId: proposalBaseViewId,
      finalViewId,
      baseGeneration: 0,
      nextGeneration: 1,
      baseWorkspaceHash: proposalBaseHash,
      finalWorkspaceHash: winningHash,
      dispositionBaseViewId,
      dispositionBaseGeneration: 1,
      dispositionBaseWorkspaceHash: winningHash,
      proposalId: "proposal-stale",
      proposalArtifactHash: "f".repeat(64),
      verifierInputHash: null,
      promotionSourceHash: null,
      evaluationContextHash: null,
      evidenceDigest: null,
      permitId: null,
      permitState: null,
      sourceRevision: "revision-conflict",
    };
    const bundle = signAuthorityReceiptProof(
      receipt,
      terminal,
      [genesis, sealed, winning, terminal],
      privatePem,
      publicPem,
    );
    expect(bundle.schemaVersion).toBe(3);
    expect(verifyAuthorityReceiptProof(bundle)).toEqual({ valid: true, reason: null });

    const legacyConflictReceipt: AuthorityReceiptRecord = {
      schemaVersion: 1,
      receiptId: receipt.receiptId,
      runId: receipt.runId,
      agentId: receipt.agentId,
      transitionId: receipt.transitionId,
      decision: "CONFLICTED",
      baseViewId: receipt.baseViewId,
      finalViewId: receipt.finalViewId,
      baseGeneration: receipt.baseGeneration,
      nextGeneration: receipt.nextGeneration,
      baseWorkspaceHash: receipt.baseWorkspaceHash,
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
    expect(verifyAuthorityReceiptProof(signAuthorityReceiptProof(
      legacyConflictReceipt,
      terminal,
      [genesis, sealed, winning, terminal],
      privatePem,
      publicPem,
    ))).toEqual({
      valid: false,
      reason: "legacy receipt cannot prove conflict disposition base",
    });

    expect(verifyAuthorityReceiptProof({
      ...bundle,
      eventChain: [genesis, sealed, terminal],
    })).toEqual({ valid: false, reason: "authority event chain binding mismatch" });
    expect(verifyAuthorityReceiptProof({
      ...bundle,
      eventChain: [
        genesis,
        sealed,
        { ...winning, payload: { receiptId: "tampered" } },
        terminal,
      ],
    })).toEqual({ valid: false, reason: "authority event chain binding mismatch" });

    const noDriftReceipt: AuthorityReceiptRecord = {
      ...receipt,
      dispositionBaseViewId: proposalBaseViewId,
      dispositionBaseGeneration: 0,
      dispositionBaseWorkspaceHash: proposalBaseHash,
      nextGeneration: 0,
      finalWorkspaceHash: proposalBaseHash,
    };
    const noDriftTerminal = event(4, winning, "stale-run", "NON_COMMIT_DISPOSITIONED", {
      receiptId: "receipt-conflict",
      decision: "CONFLICTED",
      previousViewId: proposalBaseViewId,
      viewId: finalViewId,
      workspaceHash: proposalBaseHash,
    });
    expect(verifyAuthorityReceiptProof(signAuthorityReceiptProof(
      noDriftReceipt,
      noDriftTerminal,
      [genesis, sealed, winning, noDriftTerminal],
      privatePem,
      publicPem,
    ))).toEqual({ valid: false, reason: "conflicted receipt has no base drift" });

    const wrongProposalReceipt: AuthorityReceiptRecord = {
      ...receipt,
      proposalId: "proposal-from-another-transition",
    };
    expect(verifyAuthorityReceiptProof(signAuthorityReceiptProof(
      wrongProposalReceipt,
      terminal,
      [genesis, sealed, winning, terminal],
      privatePem,
      publicPem,
    ))).toEqual({ valid: false, reason: "proposal event receipt binding mismatch" });
  });
});
