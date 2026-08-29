#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { evidenceProvenance, executionIdentity } from "./evidence-utils.mjs";
import {
  WORKER_MICROBENCHMARK_ITERATIONS,
  validateWorkerMicrobenchmark,
} from "./performance-contract.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const reportPath = path.join(root, "eval", "evidence", "performance-report.json");
const explicitImage = process.env.COMMITGATE_TRANSITION_WORKER_IMAGE;
const image = explicitImage ?? "commitgate-transition-worker:local";
const engine = process.env.CONTAINER_ENGINE ?? "docker";
const iterations = Number(
  process.env.COMMITGATE_BENCH_ITERATIONS ??
    String(WORKER_MICROBENCHMARK_ITERATIONS),
);
const sizes = process.env.COMMITGATE_BENCH_SIZES ?? "4096,262144,1048576";
const timeoutMs = Number(process.env.COMMITGATE_BENCH_TIMEOUT_MS ?? "1200000");
// The canonical command must not silently benchmark a stale local tag. When
// the caller did not pin an externally built image, rebuild the product Worker
// image from the current source tree before collecting timings. A caller that
// supplies COMMITGATE_TRANSITION_WORKER_IMAGE remains responsible for that
// immutable image and the digest is still captured below.
const buildArgs = ["build", "-f", "Dockerfile.transition-worker", "-t", image, "."];
const buildStarted = Date.now();
const buildResult = explicitImage
  ? null
  : spawnSync(engine, buildArgs, {
      cwd: root,
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
      timeout: Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : 1_200_000,
    });
const buildTimedOut =
  buildResult?.error?.code === "ETIMEDOUT" || buildResult?.signal === "SIGTERM";
const args = [
  "run", "--rm", "--network", "none",
  "--read-only",
  "--tmpfs", "/tmp:rw,size=768m,nosuid,nodev",
  "--env", `COMMITGATE_BENCH_ITERATIONS=${iterations}`,
  "--env", `COMMITGATE_BENCH_SIZES=${sizes}`,
  "--entrypoint", "node",
  image,
  "apps/server/dist/transition-worker/benchmark.js",
];
const started = Date.now();
const result = buildResult && (buildResult.status !== 0 || buildTimedOut)
  ? {
      status: null,
      signal: null,
      stdout: "",
      stderr: "benchmark skipped because the Worker image build failed",
      error: buildResult.error,
    }
  : spawnSync(engine, args, {
      cwd: root,
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
      timeout: Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : 1_200_000,
    });
let benchmark = null;
let parseError = null;
try {
  benchmark = JSON.parse((result.stdout ?? "").trim().split("\n").at(-1) ?? "");
} catch (error) {
  parseError = error instanceof Error ? error.message : String(error);
}
const statisticsValid = validateWorkerMicrobenchmark(benchmark).valid;
const timedOut = result.error?.code === "ETIMEDOUT" || result.signal === "SIGTERM";
const identity = executionIdentity(root, {
  environment: {
    ...process.env,
    COMMITGATE_TRANSITION_WORKER_IMAGE: image,
  },
});
const workerIdentityValid =
  identity.workerImage?.reference === image &&
  identity.workerImage?.status === "verified" &&
  /^sha256:[a-f0-9]{64}$/.test(identity.workerImage?.imageDigest ?? "");
const status =
  (!buildResult || (buildResult.status === 0 && !buildTimedOut)) &&
  result.status === 0 && !timedOut && benchmark && !parseError && statisticsValid && workerIdentityValid
    ? "verified"
    : result.error?.code === "ENOENT" || /No such image|Cannot connect/i.test(result.stderr ?? "")
      ? "unverified"
      : "failed";
const report = {
  schemaVersion: 1,
  kind: "commitgate-linux-gate-overhead",
  generatedAt: new Date().toISOString(),
  status,
  source: await evidenceProvenance(root),
  executionIdentity: identity,
  image,
  imageBuild: {
    performed: buildResult !== null,
    executable: buildResult ? engine : null,
    arguments: buildResult ? buildArgs : [],
    exitCode: buildResult?.status ?? null,
    signal: buildResult?.signal ?? null,
    timedOut: buildTimedOut,
    durationMs: buildResult ? started - buildStarted : 0,
    stderr: buildResult && buildResult.status !== 0
      ? (buildResult.stderr ?? "").slice(-4_096)
      : "",
  },
  command: {
    executable: engine,
    arguments: args,
    exitCode: result.status,
    signal: result.signal ?? null,
    timedOut,
    timeoutMs: Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : 1_200_000,
  },
  durationMs: Date.now() - started,
  benchmark,
  parseError,
  validation: {
    schemaAndOrder: statisticsValid,
    workerImageDigest: workerIdentityValid,
    productVerifierContainerMeasured: false,
  },
  stderr: status === "verified" ? "" : (result.stderr ?? "").slice(-4_096),
  claimBoundary:
    "Worker-local filesystem protocol microbenchmark only: seal, export, a manifest plus fixed-file deterministic probe, permit, and promotion under Linux-strong Manifest v2. It does not execute Runtime Broker RPC, launch the product Verifier container, or run the trusted-check bundle process. Model inference and network latency are also excluded. Therefore these numbers are not full end-to-end product gate latency; no arbitrary latency pass threshold is applied.",
};
await mkdir(path.dirname(reportPath), { recursive: true });
await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");
console.log(JSON.stringify(report, null, 2));
if (status !== "verified") process.exitCode = 2;
