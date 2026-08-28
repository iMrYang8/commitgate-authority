import type { AppConfig } from "./config.js";
import {
  createCommitGateComponents,
} from "./commitgate/index.js";
import { ContainerCodexRunner } from "./container-codex-runner.js";
import { CodexRunner } from "./codex-runner.js";
import { RuntimeBrokerRunner } from "./runtime-broker/client.js";
import type { AgentRunner } from "./types.js";
import {
  createWorkerCommitGateComponents,
  type CommitGateRuntimeComponents,
} from "./commitgate-runtime.js";

export interface RunnerRuntime {
  runner: AgentRunner;
  commitGate: CommitGateRuntimeComponents | null;
}

export function createRunner(config: AppConfig): RunnerRuntime {
  const baseRunner = config.runtimeProvider === "container"
    ? new ContainerCodexRunner(config)
    : config.runtimeProvider === "broker"
      ? new RuntimeBrokerRunner(config.runtimeBrokerSocket, config.codexTimeoutMs + 30_000)
      : new CodexRunner(config);
  if (!config.commitGateEnabled || !["container", "broker"].includes(config.runtimeProvider)) {
    return { runner: baseRunner, commitGate: null };
  }
  const commitGate = config.transitionAuthority === "worker"
    ? createWorkerCommitGateComponents(config, baseRunner as RuntimeBrokerRunner)
    : createCommitGateComponents(config, baseRunner);
  return { runner: commitGate.runner, commitGate };
}
