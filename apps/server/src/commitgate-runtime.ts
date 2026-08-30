import type { AppConfig } from "./config.js";
import type { CommitGateComponents } from "./commitgate/factory.js";
import { RuntimeBrokerRunner } from "./runtime-broker/client.js";
import { WorkerTransitionAuthorityClient } from "./transition-authority-client.js";
import { WorkerCommitGateRunner } from "./worker-commitgate-runner.js";

export interface WorkerCommitGateComponents {
  mode: "worker";
  runner: WorkerCommitGateRunner;
  authority: WorkerTransitionAuthorityClient;
}

export type CommitGateRuntimeComponents =
  | CommitGateComponents
  | WorkerCommitGateComponents;

export function createWorkerCommitGateComponents(
  config: AppConfig,
  broker: RuntimeBrokerRunner,
): WorkerCommitGateComponents {
  const authority = new WorkerTransitionAuthorityClient(
    config.transitionWorkerSocket,
    config.codexTimeoutMs + 30_000,
  );
  const runner = new WorkerCommitGateRunner(
    broker,
    authority,
    config.commitGateExchangeRoot,
    config.commitGateSourceRevision,
    config.nodeEnv === "production",
    config.commitGatePolicyProfile,
  );
  return { mode: "worker", runner, authority };
}
