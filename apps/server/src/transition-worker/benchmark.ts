import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { computeEvaluationContextHash, sha256Canonical } from "../commitgate/protocol.js";
import type { EvaluationContext } from "../commitgate/types.js";
import {
  WORKER_CHECK_SPEC_HASH,
  WORKER_GATE_POLICY_HASH,
  WORKER_MANIFEST_SCHEMA_VERSION,
} from "../worker-gate-policy.js";
import { buildWorkerManifest, makeTreeWritable } from "./filesystem.js";
import { linuxStrongWorkerManifestOptions } from "./linux-extended-metadata.js";
import { TransitionWorker, type TransitionWorkerConfig } from "./worker.js";

const iterations = Math.max(1, Number(process.env.COMMITGATE_BENCH_ITERATIONS ?? 30));
const sizes = (process.env.COMMITGATE_BENCH_SIZES ?? "4096,262144,1048576")
  .split(",")
  .map(Number)
  .filter((value) => Number.isSafeInteger(value) && value > 0);
const root = process.env.COMMITGATE_BENCH_ROOT ?? "/tmp/commitgate-benchmark";
const elapsed = (start: number) => performance.now() - start;
const percentile = (values: number[], fraction: number) => {
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * fraction) - 1)] ?? 0;
};

await makeTreeWritable(root).catch(() => undefined);
await rm(root, { recursive: true, force: true });
const config: TransitionWorkerConfig = {
  workspaceRoot: path.join(root, "workspaces"),
  controlRoot: path.join(root, "control"),
  inboxRoot: path.join(root, "exchange"),
  socketPath: path.join(root, "run", "worker.sock"),
  sourceRevision: "benchmark-build",
};
if (process.platform !== "linux") {
  throw new Error("BENCHMARK_REQUIRES_LINUX_STRONG_MANIFEST_PROFILE");
}
const manifestOptions = linuxStrongWorkerManifestOptions();
const worker = new TransitionWorker(config, { manifestOptions });
await worker.initialize();
const rows: Array<Record<string, number>> = [];

for (const sizeBytes of sizes) {
  for (let iteration = 0; iteration < iterations; iteration += 1) {
    const suffix = `${sizeBytes}-${iteration}-${randomUUID().slice(0, 8)}`;
    const agentId = `bench-agent-${suffix}`;
    const transitionId = `bench-run-${suffix}`;
    const proposalId = `bench-proposal-${suffix}`;
    const permitId = `bench-permit-${suffix}`;
    const candidateVolumeId = `candidate-${transitionId}`;
    const exportVolumeId = `verify-${transitionId}`;
    const initial = await worker.initializeAgent({
      agentId,
      operationId: `bench-init-${suffix}`,
      headVersionId: `bench-v1-${suffix}`,
      generation: 1,
      sessionEpoch: 0,
      agentConfigVersion: 1,
      policyVersion: 1,
      name: "Benchmark Agent",
      instructions: "# Platform-managed Agent instructions\n",
    });
    const prepared = await worker.prepareRun({
      agentId,
      transitionId,
      runId: transitionId,
      runLeaseId: `bench-lease-${suffix}`,
      candidateVolumeId,
      expectedViewId: initial.head!.view.viewId,
      expectedWorkspaceHash: initial.head!.workspaceHash,
      baseGeneration: 1,
    });
    const candidate = path.join(config.inboxRoot, prepared.relativeSubpath);
    const marker = Buffer.from("COMMITGATE_OK\n", "utf8");
    await writeFile(path.join(candidate, "result.txt"), marker);
    let remainingBytes = Math.max(0, sizeBytes - marker.byteLength);
    let chunkIndex = 0;
    while (remainingBytes > 0) {
      const chunkBytes = Math.min(262_144, remainingBytes);
      await writeFile(
        path.join(candidate, `payload-${String(chunkIndex).padStart(2, "0")}.bin`),
        Buffer.alloc(chunkBytes, iteration % 251),
      );
      remainingBytes -= chunkBytes;
      chunkIndex += 1;
    }
    const artifactHash = (await buildWorkerManifest(candidate, manifestOptions)).hash;

    let started = performance.now();
    await worker.sealProposal({
      agentId,
      transitionId,
      proposalId,
      sourceVolumeId: candidateVolumeId,
      baseViewId: initial.head!.view.viewId,
      expectedArtifactHash: artifactHash,
      runtimeTeardownDigest: createHash("sha256")
        .update(`benchmark-teardown:${transitionId}`)
        .digest("hex"),
    });
    const sealMs = elapsed(started);

    started = performance.now();
    const exported = await worker.exportProposal({
      agentId,
      transitionId,
      proposalId,
      exportVolumeId,
    });
    const exportMs = elapsed(started);

    started = performance.now();
    const exportedRoot = path.join(config.inboxRoot, exported.relativeSubpath);
    const verifierManifest = await buildWorkerManifest(exportedRoot, manifestOptions);
    const result = await readFile(path.join(exportedRoot, "result.txt"), "utf8");
    const checkoutConfig = await readFile(
      path.join(exportedRoot, "services", "checkout", "config.json"),
      "utf8",
    );
    if (
      verifierManifest.hash !== artifactHash ||
      result !== "COMMITGATE_OK\n" ||
      !checkoutConfig.includes('"retryLimit":3')
    ) {
      throw new Error("BENCHMARK_DETERMINISTIC_PROBE_FAILED");
    }
    const deterministicProbeMs = elapsed(started);

    const checks = [{
      id: "workspace-sanity",
      status: "PASS" as const,
      exitCode: 0,
      durationMs: Math.max(0, Math.round(deterministicProbeMs)),
      outputHash: createHash("sha256").update("benchmark-pass").digest("hex"),
      timedOut: false,
    }];
    const context: EvaluationContext = {
      schemaVersion: 1,
      runId: transitionId,
      agentId,
      proposalId,
      baseView: initial.head!.view,
      manifestSchemaVersion: WORKER_MANIFEST_SCHEMA_VERSION,
      policyHash: WORKER_GATE_POLICY_HASH,
      checkBundleHash: sha256Canonical({ bundle: "benchmark-v1" }),
      checkSpecHash: WORKER_CHECK_SPEC_HASH,
      verifierImageDigest: "sha256:" + "b".repeat(64),
      verifierConfigHash: sha256Canonical({ network: "none", scratch: "isolated" }),
      resourcePolicyHash: sha256Canonical({ sizeBytes }),
      sourceRevision: "benchmark-build",
    };
    const contextHash = computeEvaluationContextHash(context);
    const checkResultsHash = sha256Canonical(checks);
    const evidenceDigest = sha256Canonical({
      schemaVersion: 1,
      proposalId,
      artifactHash,
      evaluationContextHash: contextHash,
      checkResultsHash,
    });
    started = performance.now();
    await worker.recordEvidence({
      agentId,
      transitionId,
      proposalId,
      evaluationContextHash: contextHash,
      evidenceDigest,
      evaluationContext: context,
      verifierInputHash: verifierManifest.hash,
      checkResultsHash,
      coverage: "complete",
      requiredChecksPassed: true,
      checks,
    });
    await worker.issuePermit({
      agentId,
      transitionId,
      permitId,
      proposalId,
      baseViewId: initial.head!.view.viewId,
      targetArtifactHash: artifactHash,
      evaluationContextHash: contextHash,
      evidenceDigest,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    const permitMs = elapsed(started);

    const versionId = `bench-v2-${suffix}`;
    started = performance.now();
    await worker.applyPromotion({
      agentId,
      transitionId,
      permitId,
      proposalId,
      expectedViewId: initial.head!.view.viewId,
      expectedWorkspaceHash: initial.head!.workspaceHash,
      versionId,
      receiptId: `bench-receipt-${suffix}`,
    });
    const promotionMs = elapsed(started);
    rows.push({
      sizeBytes,
      sealMs,
      exportMs,
      deterministicProbeMs,
      permitMs,
      promotionMs,
      totalGateMs: sealMs + exportMs + deterministicProbeMs + permitMs + promotionMs,
    });
  }
}

const phases = [
  "sealMs",
  "exportMs",
  "deterministicProbeMs",
  "permitMs",
  "promotionMs",
  "totalGateMs",
] as const;
const results = sizes.map((sizeBytes) => {
  const selected = rows.filter((row) => row.sizeBytes === sizeBytes);
  return {
    sizeBytes,
    iterations: selected.length,
    phases: Object.fromEntries(
      phases.map((phase) => {
        const values = selected.map((row) => {
          const value = row[phase];
          if (typeof value !== "number") throw new Error(`BENCHMARK_PHASE_MISSING:${phase}`);
          return value;
        });
        return [phase, {
          p50Ms: Number(percentile(values, 0.5).toFixed(3)),
          p95Ms: Number(percentile(values, 0.95).toFixed(3)),
        }];
      }),
    ),
  };
});
console.log(JSON.stringify({
  schemaVersion: 1,
  filesystemProfile: "linux-strong",
  manifestSchemaVersion: 2,
  measurementProfile: "worker-local-filesystem-protocol",
  verificationMeasurement: {
    mode: "manifest-and-fixed-file-deterministic-probe",
    brokerRpcIncluded: false,
    verifierContainerIncluded: false,
    trustedCheckBundleProcessIncluded: false,
    modelInferenceIncluded: false,
  },
  iterations,
  sizes,
  results,
}));
