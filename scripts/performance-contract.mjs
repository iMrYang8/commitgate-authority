export const WORKER_MICROBENCHMARK_ITERATIONS = 30;
export const WORKER_MICROBENCHMARK_SIZES = Object.freeze([
  4_096,
  262_144,
  1_048_576,
]);
export const WORKER_MICROBENCHMARK_PHASES = Object.freeze([
  "sealMs",
  "exportMs",
  "deterministicProbeMs",
  "permitMs",
  "promotionMs",
  "totalGateMs",
]);
export const WORKER_MICROBENCHMARK_PROFILE =
  "worker-local-filesystem-protocol";
export const WORKER_MICROBENCHMARK_PROBE_MODE =
  "manifest-and-fixed-file-deterministic-probe";

export function validateWorkerMicrobenchmark(benchmark) {
  const rows = Array.isArray(benchmark?.results) ? benchmark.results : [];
  const verification = benchmark?.verificationMeasurement;
  const valid =
    benchmark?.schemaVersion === 1 &&
    benchmark?.filesystemProfile === "linux-strong" &&
    benchmark?.manifestSchemaVersion === 2 &&
    benchmark?.measurementProfile === WORKER_MICROBENCHMARK_PROFILE &&
    verification?.mode === WORKER_MICROBENCHMARK_PROBE_MODE &&
    verification?.brokerRpcIncluded === false &&
    verification?.verifierContainerIncluded === false &&
    verification?.trustedCheckBundleProcessIncluded === false &&
    verification?.modelInferenceIncluded === false &&
    benchmark?.iterations === WORKER_MICROBENCHMARK_ITERATIONS &&
    Array.isArray(benchmark?.sizes) &&
    benchmark.sizes.length === WORKER_MICROBENCHMARK_SIZES.length &&
    WORKER_MICROBENCHMARK_SIZES.every(
      (size, index) => benchmark.sizes[index] === size,
    ) &&
    rows.length === WORKER_MICROBENCHMARK_SIZES.length &&
    WORKER_MICROBENCHMARK_SIZES.every((size, index) => {
      const row = rows[index];
      return row?.sizeBytes === size &&
        row?.iterations === WORKER_MICROBENCHMARK_ITERATIONS &&
        WORKER_MICROBENCHMARK_PHASES.every((phase) => {
          const p50 = row?.phases?.[phase]?.p50Ms;
          const p95 = row?.phases?.[phase]?.p95Ms;
          return Number.isFinite(p50) && p50 >= 0 &&
            Number.isFinite(p95) && p95 >= p50;
        });
    });
  return {
    valid,
    reason: valid
      ? null
      : "Worker microbenchmark is missing the exact Linux 30-run deterministic-probe matrix",
  };
}

export function validatePerformanceReportContract(report) {
  const benchmark = validateWorkerMicrobenchmark(report?.benchmark);
  const valid =
    report?.schemaVersion === 1 &&
    report?.kind === "commitgate-linux-gate-overhead" &&
    report?.status === "verified" &&
    report?.command?.exitCode === 0 &&
    report?.command?.timedOut === false &&
    report?.validation?.schemaAndOrder === true &&
    report?.validation?.workerImageDigest === true &&
    report?.validation?.productVerifierContainerMeasured === false &&
    benchmark.valid;
  return {
    valid,
    reason: valid
      ? null
      : benchmark.reason ?? "Worker microbenchmark report contract mismatch",
  };
}
