import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  computeEvaluationContextHash,
  sha256Canonical,
} from "../commitgate/protocol.js";
import type { EvaluationContext } from "../commitgate/types.js";
import { signBrokerAttestation } from "../runtime-broker/attestation.js";
import {
  WORKER_CHECK_SPEC_HASH,
  WORKER_GATE_POLICY_HASH,
  WORKER_MANIFEST_SCHEMA_VERSION,
} from "../worker-gate-policy.js";
import { buildWorkerManifest, makeTreeWritable } from "./filesystem.js";
import { rpcRequestSchema } from "./contracts.js";
import { TransitionWorker, type TransitionWorkerConfig } from "./worker.js";

const roots: string[] = [];
const key = "test-only-broker-attestation-key-with-more-than-32-bytes";

afterEach(async () => {
  await Promise.all(roots.splice(0).map(async (root) => {
    await makeTreeWritable(root).catch(() => undefined);
    await rm(root, { recursive: true, force: true });
  }));
});

describe("Broker-authenticated Runtime and Verifier facts", () => {
  it("rejects caller-forged all-true teardown and PASS evidence", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-broker-attestation-"));
    roots.push(root);
    const config: TransitionWorkerConfig = {
      workspaceRoot: path.join(root, "workspaces"),
      controlRoot: path.join(root, "control"),
      inboxRoot: path.join(root, "exchange"),
      socketPath: path.join(root, "run", "worker.sock"),
      sourceRevision: "attestation-test",
      requireRuntimeTeardownHandshake: true,
      requireBrokerAttestations: true,
      brokerAttestationKey: key,
    };
    const worker = new TransitionWorker(config);
    await worker.initialize();
    const initialized = await worker.initializeAgent({
      agentId: "agent-attested",
      operationId: "init-attested",
      headVersionId: "initial-attested",
      generation: 1,
      sessionEpoch: 4,
      agentConfigVersion: 1,
      policyVersion: 1,
      name: "Attestation fixture",
      instructions: "# trusted\n",
    });
    const prepared = await worker.prepareRun({
      agentId: "agent-attested",
      transitionId: "run-attested",
      runId: "run-attested",
      runLeaseId: "lease-attested",
      candidateVolumeId: "candidate-run-attested",
      expectedViewId: initialized.head!.view.viewId,
      expectedWorkspaceHash: initialized.head!.workspaceHash,
      baseGeneration: initialized.head!.view.generation,
      sessionEpoch: initialized.head!.view.sessionEpoch,
    });
    const candidate = path.join(config.inboxRoot, prepared.relativeSubpath);
    await writeFile(path.join(candidate, "feature.ts"), "export const safe = true;\n");

    const rawAllTrue = {
      schemaVersion: 1 as const,
      runId: "run-attested",
      agentId: "agent-attested",
      runLeaseId: "lease-attested",
      sessionEpoch: 4,
      scope: "AGENT" as const,
      containerExited: true as const,
      containerRemoved: true as const,
      mountsReleased: true as const,
      source: "runtime-attestation" as const,
    };
    await expect(worker.dispatch(rpcRequestSchema.parse({
      id: "raw-teardown",
      method: "recordRuntimeTeardown",
      params: {
        agentId: "agent-attested",
        transitionId: "run-attested",
        attestation: rawAllTrue,
      },
    }))).rejects.toMatchObject({ code: "BROKER_ATTESTATION_REQUIRED" });

    let projection = await worker.recordRuntimeTeardown({
      agentId: "agent-attested",
      transitionId: "run-attested",
      attestation: signBrokerAttestation({
        ...rawAllTrue,
        kind: "runtime-teardown" as const,
      }, key),
    });
    const teardownDigest = projection.transitions["run-attested"]!
      .runtimeTeardownAgent!.digest;
    const artifactHash = (await buildWorkerManifest(candidate)).hash;
    await worker.sealProposal({
      agentId: "agent-attested",
      transitionId: "run-attested",
      proposalId: "proposal-attested",
      sourceVolumeId: "candidate-run-attested",
      baseViewId: initialized.head!.view.viewId,
      expectedArtifactHash: artifactHash,
      runtimeTeardownDigest: teardownDigest,
    });
    projection = await worker.recordRuntimeTeardown({
      agentId: "agent-attested",
      transitionId: "run-attested",
      attestation: signBrokerAttestation({
        ...rawAllTrue,
        kind: "runtime-teardown" as const,
        scope: "ALL" as const,
      }, key),
    });
    expect(projection.transitions["run-attested"]?.runtimeTeardownAll)
      .not.toBeNull();

    const context: EvaluationContext = {
      schemaVersion: 1,
      runId: "run-attested",
      agentId: "agent-attested",
      proposalId: "proposal-attested",
      baseView: initialized.head!.view,
      manifestSchemaVersion: WORKER_MANIFEST_SCHEMA_VERSION,
      policyHash: WORKER_GATE_POLICY_HASH,
      checkBundleHash: "2".repeat(64),
      checkSpecHash: WORKER_CHECK_SPEC_HASH,
      verifierImageDigest: `sha256:${"4".repeat(64)}`,
      verifierConfigHash: "5".repeat(64),
      resourcePolicyHash: "6".repeat(64),
      sourceRevision: "attestation-test",
    };
    const checks = [{
      id: "workspace-sanity",
      status: "PASS" as const,
      exitCode: 0,
      durationMs: 4,
      outputHash: "7".repeat(64),
      timedOut: false,
    }];
    const checkResultsHash = sha256Canonical(checks);
    const evaluationContextHash = computeEvaluationContextHash(context);
    const evidenceDigest = sha256Canonical({
      schemaVersion: 1,
      proposalId: "proposal-attested",
      artifactHash,
      evaluationContextHash,
      checkResultsHash,
    });
    const evidenceInput = {
      agentId: "agent-attested",
      transitionId: "run-attested",
      proposalId: "proposal-attested",
      evaluationContextHash,
      evidenceDigest,
      evaluationContext: context,
      verifierInputHash: artifactHash,
      checkResultsHash,
      coverage: "complete" as const,
      requiredChecksPassed: true,
      checks,
    };
    await expect(worker.dispatch(rpcRequestSchema.parse({
      id: "unsigned-pass-evidence",
      method: "recordEvidence",
      params: evidenceInput,
    }))).rejects.toMatchObject({
      code: "BROKER_ATTESTATION_REQUIRED",
    });

    const failedChecks = [{ ...checks[0]!, status: "FAIL" as const, exitCode: 1 }];
    const forgedPass = {
      ...signBrokerAttestation({
        schemaVersion: 1 as const,
        kind: "verifier-result" as const,
        scope: "VERIFIER" as const,
        runId: "run-attested",
        agentId: "agent-attested",
        runLeaseId: "lease-attested",
        sessionEpoch: 4,
        proposalId: "proposal-attested",
        verifierInputHash: artifactHash,
        checkSpecHash: WORKER_CHECK_SPEC_HASH,
        checkResultsHash: sha256Canonical(failedChecks),
        coverage: "complete" as const,
        checks: failedChecks,
        environment: {
          checkBundleHash: context.checkBundleHash,
          verifierImageDigest: context.verifierImageDigest,
          verifierConfigHash: context.verifierConfigHash,
          resourcePolicyHash: context.resourcePolicyHash,
          sourceRevision: context.sourceRevision,
        },
      }, key),
      // A caller changes the signed FAIL result to an all-PASS result while
      // retaining the Broker MAC. The Worker must reject before recording it.
      checks,
      checkResultsHash,
    };
    await expect(worker.dispatch(rpcRequestSchema.parse({
      id: "forged-pass-evidence",
      method: "recordEvidence",
      params: {
        ...evidenceInput,
        brokerAttestation: forgedPass,
      },
    }))).rejects.toMatchObject({ code: "BROKER_ATTESTATION_INVALID" });

    const signedPass = signBrokerAttestation({
      schemaVersion: 1 as const,
      kind: "verifier-result" as const,
      scope: "VERIFIER" as const,
      runId: "run-attested",
      agentId: "agent-attested",
      runLeaseId: "lease-attested",
      sessionEpoch: 4,
      proposalId: "proposal-attested",
      verifierInputHash: artifactHash,
      checkSpecHash: WORKER_CHECK_SPEC_HASH,
      checkResultsHash,
      coverage: "complete" as const,
      checks,
      environment: {
        checkBundleHash: context.checkBundleHash,
        verifierImageDigest: context.verifierImageDigest,
        verifierConfigHash: context.verifierConfigHash,
        resourcePolicyHash: context.resourcePolicyHash,
        sourceRevision: context.sourceRevision,
      },
    }, key);
    await expect(worker.recordEvidence({
      ...evidenceInput,
      brokerAttestation: signedPass,
    })).resolves.toMatchObject({
      evidence: { "proposal-attested": { requiredChecksPassed: true } },
    });
  });
});
