import path from "node:path";
import type { AppConfig } from "../config.js";
import type { AgentRunner } from "../types.js";
import type { TransitionAuthority } from "../transition-authority.js";
import { createInProcessTransitionAuthority } from "../transition-authority-factory.js";
import { WorkspaceManager } from "../workspace.js";
import { CommitGateRunner } from "./commitgate-runner.js";
import { CommitGateCoordinator } from "./coordinator.js";
import { defaultCommitGatePolicy, validatePolicy } from "./policy.js";
import { ReceiptStore } from "./receipt-store.js";
import { VersionStore } from "./version-store.js";
import { DockerVerifierRunner } from "./verifier-runner.js";

export interface CommitGateComponents {
  // Optional for compatibility with existing test fixtures and embedders.
  // Worker authority is always selected explicitly; an omitted mode therefore
  // means the legacy in-process implementation.
  mode?: "in-process";
  runner: CommitGateRunner;
  coordinator: CommitGateCoordinator;
  receiptStore: ReceiptStore;
  versionStore: VersionStore;
  transitionWriter?: TransitionAuthority;
}

export function createCommitGateComponents(
  config: AppConfig,
  inner: AgentRunner,
): CommitGateComponents {
  if (!["container", "broker"].includes(config.runtimeProvider)) {
    throw new Error("CommitGate strong isolation requires RUNTIME_PROVIDER=container or broker");
  }
  const transitionWriter = createInProcessTransitionAuthority(
    new WorkspaceManager(config.workspaceRoot),
    config.commitGateControlRoot,
  );
  const sensitiveValues = [
    ...new Set([
      config.modelApiKey,
      config.modelRuntimeApiKey,
      config.modelRelayToken,
    ]),
  ].filter((value) => value.length > 0);
  const receiptStore = new ReceiptStore(config.commitGateControlRoot, sensitiveValues);
  const versionStore = new VersionStore(
    config.commitGateControlRoot,
    {
      maxUniqueSnapshots: config.commitGateMaxUniqueSnapshots,
      maxPayloadBytes: config.commitGateMaxSnapshotBytes,
    },
    transitionWriter,
  );
  const policy = validatePolicy({
    ...defaultCommitGatePolicy,
    maxChangedFiles: config.commitGateMaxChangedFiles,
    maxChangedBytes: config.commitGateMaxChangedBytes,
    maxSingleFileBytes: config.commitGateMaxSingleFileBytes,
    verifierTimeoutMs: config.commitGateVerifierTimeoutMs,
    verifierMaxOutputBytes: config.commitGateVerifierMaxOutputBytes,
    requiredChecks: [
      {
        id: "workspace-sanity",
        runner: "node",
        entrypoint: "workspace-sanity.mjs",
        args: [],
        timeoutMs: Math.min(15_000, config.commitGateVerifierTimeoutMs),
        scratchBytes: 64 * 1024 * 1024,
      },
    ],
  });
  const coordinator = new CommitGateCoordinator({
    workspaceRoot: config.workspaceRoot,
    controlRoot: config.commitGateControlRoot,
    trustedChecksRoot: config.commitGateTrustedChecksDirectory,
    verifier: new DockerVerifierRunner({
      engine: config.containerEngine,
      image: config.containerRuntimeImage,
      cpuLimit: config.containerCpuLimit,
      memoryLimit: config.containerMemoryLimit,
      pidsLimit: config.containerPidsLimit,
      user: config.containerUser,
      instanceId: config.runtimeInstanceId,
      trustedChecksPath: config.commitGateTrustedChecksDirectory,
      trustedCheckStorePath: path.join(
        config.commitGateControlRoot,
        "_trusted-check-bundles",
      ),
      runTimeoutMs: config.commitGateVerifierTimeoutMs,
      maxOutputBytes: config.commitGateVerifierMaxOutputBytes,
      sourceRevision: config.commitGateSourceRevision,
    }),
    receiptStore,
    versionStore,
    transitionWriter,
    defaultPolicy: policy,
    sensitiveValues,
    requireTrustedChecks: true,
    requireRuntimeTeardownEvidence: true,
    sourceRevision: config.commitGateSourceRevision,
  });
  const runner = new CommitGateRunner(inner, coordinator);
  return { mode: "in-process", runner, coordinator, receiptStore, versionStore, transitionWriter };
}
