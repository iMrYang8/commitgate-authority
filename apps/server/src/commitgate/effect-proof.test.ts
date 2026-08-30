import { describe, expect, it } from "vitest";
import { deriveEffectDispositionProof } from "./effect-proof.js";
import { AgentService } from "../agent-service.js";
import type { GateReceipt } from "./types.js";
import type { WorkerProjection } from "../transition-worker/projection.js";
import { makeStateView } from "../state-view.js";

describe("effect disposition proof", () => {
  it("proves exact proposal promotion for a commit", () => {
    expect(
      deriveEffectDispositionProof({
        decision: "COMMITTED",
        baseHash: "base",
        candidateHash: "next",
        finalHash: "next",
        sealedProposalHash: "next",
        verifierInputHash: "next",
        promotionSourceHash: "next",
        finalAuthoritativeHash: "next",
      }),
    ).toMatchObject({
      candidateChanged: true,
      authoritativeChanged: true,
      invariant: "PROMOTED_EXACT_PROPOSAL",
      invariantSatisfied: true,
      sealedProposalHash: "next",
      verifierInputHash: "next",
      promotionSourceHash: "next",
      finalAuthoritativeHash: "next",
    });
  });

  it.each(["QUARANTINED", "CONFLICTED", "ABORTED"] as const)(
    "proves no persistent effect for %s",
    (decision) => {
      expect(
        deriveEffectDispositionProof({
          decision,
          baseHash: "base",
          candidateHash: "candidate",
          finalHash: "base",
        }),
      ).toMatchObject({
        candidateChanged: true,
        authoritativeChanged: false,
        invariant: "NO_PERSISTENT_EFFECT",
        invariantSatisfied: true,
      });
    },
  );

  it("fails closed when a rejected run changed the authoritative hash", () => {
    expect(
      deriveEffectDispositionProof({
        decision: "QUARANTINED",
        baseHash: "base",
        candidateHash: "candidate",
        finalHash: "unexpected",
      }).invariantSatisfied,
    ).toBe(false);
  });

  it("distinguishes an unobserved candidate and proves a conflict against disposition-time HEAD", () => {
    expect(
      deriveEffectDispositionProof({
        decision: "ABORTED",
        baseHash: "admission",
        candidateHash: null,
        finalHash: "admission",
      }),
    ).toMatchObject({
      candidateChanged: false,
      candidateObservation: "unobserved",
      admissionBaseHash: "admission",
    });
    expect(
      deriveEffectDispositionProof({
        decision: "CONFLICTED",
        baseHash: "stale-admission",
        authoritativeBeforeHash: "winning-head",
        candidateHash: "proposal",
        finalHash: "winning-head",
      }),
    ).toMatchObject({
      admissionBaseHash: "stale-admission",
      authoritativeBeforeHash: "winning-head",
      authoritativeAfterHash: "winning-head",
      invariantSatisfied: true,
    });
  });

  it("fails closed when any committed exact-promotion binding is absent or differs", () => {
    const common = {
      decision: "COMMITTED" as const,
      baseHash: "base",
      candidateHash: "next",
      finalHash: "next",
      sealedProposalHash: "next",
      verifierInputHash: "next",
      promotionSourceHash: "next",
      finalAuthoritativeHash: "next",
    };
    expect(deriveEffectDispositionProof({ ...common, verifierInputHash: null }).invariantSatisfied)
      .toBe(false);
    expect(deriveEffectDispositionProof({ ...common, promotionSourceHash: "other" }).invariantSatisfied)
      .toBe(false);
    expect(deriveEffectDispositionProof({ ...common, finalAuthoritativeHash: "other" }).invariantSatisfied)
      .toBe(false);
  });

  it("derives the GET receipt proof from Worker projection facts", async () => {
    const runId = "run-proof";
    const agentId = "agent-proof";
    const baseHash = "a".repeat(64);
    const artifactHash = "b".repeat(64);
    const baseView = makeStateView({
      agentId,
      headVersionId: "initial-version",
      generation: 1,
      versionedHash: baseHash,
      platformManagedHash: baseHash,
      liveStateHash: baseHash,
      sessionEpoch: 0,
      agentConfigVersion: 1,
      policyVersion: 1,
    });
    const finalView = makeStateView({
      agentId,
      headVersionId: "commit-version",
      generation: 2,
      versionedHash: artifactHash,
      platformManagedHash: artifactHash,
      liveStateHash: artifactHash,
      sessionEpoch: 0,
      agentConfigVersion: 1,
      policyVersion: 1,
    });
    const receipt = {
      runId,
      agentId,
      decision: "COMMITTED",
      baseSnapshotHash: "client-base-is-ignored",
      candidateSnapshotHash: "client-candidate-is-ignored",
      finalSnapshotHash: "client-final-is-ignored",
    } as GateReceipt;
    const projection = {
      transitions: {
        [runId]: {
          transitionId: runId,
          kind: "AGENT_COMMIT",
          runId,
          runLeaseId: "lease",
          baseViewId: baseView.viewId,
          baseGeneration: 1,
          proposalId: "proposal-1",
          permitId: "permit-1",
          baseWorkspaceHash: baseHash,
        },
      },
      proposals: {
        "proposal-1": {
          proposalId: "proposal-1",
          artifactHash,
          changedPaths: ["feature.ts"],
        },
      },
      evidence: {
        "proposal-1": {
          verifierInputHash: artifactHash,
          evaluationContextHash: "context",
          evidenceDigest: "evidence",
          policyHash: "policy",
          coverage: "complete",
          checks: [],
        },
      },
      permits: {
        "permit-1": {
          permitId: "permit-1",
          targetArtifactHash: artifactHash,
          state: "CONSUMED",
        },
      },
      terminalReceipts: [{
        receiptId: runId,
        transitionId: runId,
        decision: "COMMITTED",
        viewId: finalView.viewId,
        view: finalView,
        workspaceHash: artifactHash,
        reasonCodes: [],
      }],
    } as unknown as WorkerProjection;
    const service = Object.create(AgentService.prototype) as AgentService;
    Object.assign(service as unknown as Record<string, unknown>, {
      store: { snapshot: () => ({ runs: [{ id: runId, agentId }] }) },
      commitGate: {
        mode: "worker",
        runner: { getReceipt: () => receipt },
        authority: { getProjection: async () => projection },
      },
      workerAuthorityHealth: {
        policyProfile: "workspace-default",
        policyVersion: 1,
        policyHash: "c".repeat(64),
        checkSpecHash: "d".repeat(64),
      },
    });

    const projected = await service.getCommitGateReceipt(runId);
    expect(projected.effectProof).toMatchObject({
      authoritativeBeforeHash: baseHash,
      authoritativeAfterHash: artifactHash,
      sealedProposalHash: artifactHash,
      verifierInputHash: artifactHash,
      promotionSourceHash: artifactHash,
      finalAuthoritativeHash: artifactHash,
      invariantSatisfied: true,
    });

    projection.evidence["proposal-1"]!.verifierInputHash = null;
    expect((await service.getCommitGateReceipt(runId)).effectProof?.invariantSatisfied).toBe(false);
  });
});
