import { startTransitionWorkerRpc } from "./rpc.js";
import { resolveWorkerFaultInjection } from "./fault-injection.js";
import { linuxStrongWorkerManifestOptions } from "./linux-extended-metadata.js";
import { loadTransitionWorkerConfig, TransitionWorker } from "./worker.js";
import { loadRuntimeSecretFiles } from "../load-runtime-secrets.js";

await loadRuntimeSecretFiles();

if (
  process.env.COMMITGATE_TRANSITION_WORKER !== "enabled" &&
  process.env.COMMITGATE_P1_TRANSITION_WORKER !== "experimental"
) {
  throw new Error(
    "Set COMMITGATE_TRANSITION_WORKER=enabled to start the Authority V2 worker",
  );
}

// Fail startup if the dangerous test-only switch is malformed or appears in
// a non-test process. The actual hook runs only after a durable event append.
resolveWorkerFaultInjection();

if (process.env.NODE_ENV === "production" && process.platform !== "linux") {
  throw new Error("PRODUCTION_TRANSITION_WORKER_REQUIRES_LINUX");
}
const worker = new TransitionWorker(loadTransitionWorkerConfig(), {
  // The supported product image is Linux and includes fixed attr/acl tools.
  // Portable unit tests instantiate TransitionWorker directly without this
  // profile and must not be used as filesystem-closure evidence.
  ...(process.platform === "linux"
    ? { manifestOptions: linuxStrongWorkerManifestOptions() }
    : {}),
});
const server = await startTransitionWorkerRpc(worker);

const shutdown = () => {
  server.close(() => process.exit(0));
};
process.once("SIGTERM", shutdown);
process.once("SIGINT", shutdown);
