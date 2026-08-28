import { startTransitionWorkerRpc } from "./rpc.js";
import { loadTransitionWorkerConfig, TransitionWorker } from "./worker.js";

if (
  process.env.COMMITGATE_TRANSITION_WORKER !== "enabled" &&
  process.env.COMMITGATE_P1_TRANSITION_WORKER !== "experimental"
) {
  throw new Error(
    "Set COMMITGATE_TRANSITION_WORKER=enabled to start the Authority V2 worker",
  );
}

const worker = new TransitionWorker(loadTransitionWorkerConfig());
const server = await startTransitionWorkerRpc(worker);

const shutdown = () => {
  server.close(() => process.exit(0));
};
process.once("SIGTERM", shutdown);
process.once("SIGINT", shutdown);
