import { chmod, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import type { ModelProviderIdentity } from "./types.js";
import { parseWorkerPolicyProfile } from "./worker-gate-policy.js";

const DEFAULT_ARK_BASE_URL = "https://ark.cn-beijing.volces.com/api/v3";
const DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1";

const envSchema = z.object({
  PROCESS_ROLE: z
    .enum(["api", "runtime-broker", "transition-worker", "relay"])
    .default("api"),
  HOST: z.string().default("0.0.0.0"),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  LOG_LEVEL: z.string().default("info"),
  APP_DATA_DIR: z.string().default(path.resolve(".data")),
  AGENT_WORKSPACE_ROOT: z.string().default(path.resolve("workspaces")),
  CODEX_HOME: z.string().default(path.resolve("codex-home")),
  CODEX_BIN: z.string().default("codex"),
  CODEX_SANDBOX_MODE: z
    .enum(["read-only", "workspace-write", "danger-full-access"])
    .default("workspace-write"),
  CODEX_TIMEOUT_MS: z.coerce.number().int().min(1_000).default(600_000),
  CODEX_MAX_OUTPUT_BYTES: z.coerce.number().int().min(65_536).default(2_097_152),
  RUNTIME_PROVIDER: z.enum(["local-process", "container", "broker"]).default("local-process"),
  RUNTIME_BROKER_SOCKET: z.string().optional(),
  BROKER_ATTESTATION_KEY: z.string().optional(),
  CONTAINER_ENGINE: z.string().min(1).default("docker"),
  CONTAINER_RUNTIME_IMAGE: z.string().min(1).default("volc-agent-runtime:local"),
  CONTAINER_CPU_LIMIT: z.coerce.number().positive().default(2),
  CONTAINER_MEMORY_LIMIT: z
    .string()
    .regex(/^\d+(?:\.\d+)?[bkmg]$/i)
    .default("2g"),
  CONTAINER_PIDS_LIMIT: z.coerce.number().int().positive().default(256),
  CONTAINER_USER: z.string().optional(),
  CONTAINER_AGENT_NETWORK: z.string().trim().min(1).default("bridge"),
  CONTAINER_AGENT_SCRATCH_BYTES: z.coerce
    .number()
    .int()
    .min(1_048_576)
    .default(268_435_456),
  CONTAINER_AGENT_SCRATCH_FILES: z.coerce
    .number()
    .int()
    .min(128)
    .default(8_192),
  CONTAINER_AGENT_IGNORED_BYTES: z.coerce
    .number()
    .int()
    .min(1_048_576)
    .default(67_108_864),
  CONTAINER_AGENT_IGNORED_FILES: z.coerce
    .number()
    .int()
    .min(128)
    .default(4_096),
  COMMITGATE_ENABLED: z.enum(["true", "false"]).default("true"),
  COMMITGATE_POLICY_PROFILE: z
    .enum(["workspace-default", "deployment-protected"])
    .default("workspace-default"),
  TRANSITION_AUTHORITY: z.enum(["in-process", "worker"]).default("in-process"),
  TRANSITION_WORKER_SOCKET: z.string().optional(),
  COMMITGATE_EXCHANGE_ROOT: z.string().optional(),
  COMMITGATE_EXCHANGE_VOLUME: z
    .string()
    .trim()
    .min(1)
    .max(128)
    .regex(/^[A-Za-z0-9_.-]+$/)
    .default("commitgate-exchange"),
  COMMITGATE_SESSION_VOLUME: z
    .string()
    .trim()
    .min(1)
    .max(128)
    .regex(/^[A-Za-z0-9_.-]+$/)
    .default("commitgate-sessions"),
  COMMITGATE_SESSION_VOLUME_ROOT: z.string().optional(),
  COMMITGATE_TRUSTED_CHECKS_VOLUME: z
    .string()
    .trim()
    .min(1)
    .max(128)
    .regex(/^[A-Za-z0-9_.-]+$/)
    .default("commitgate-trusted-checks"),
  COMMITGATE_TRUSTED_CHECKS_VOLUME_ROOT: z.string().optional(),
  COMMITGATE_CONTROL_ROOT: z.string().optional(),
  COMMITGATE_TRUSTED_CHECKS_DIR: z.string().default(path.resolve("eval/trusted-checks")),
  COMMITGATE_MAX_CHANGED_FILES: z.coerce.number().int().positive().default(100),
  COMMITGATE_MAX_CHANGED_BYTES: z.coerce.number().int().positive().default(1_048_576),
  COMMITGATE_MAX_SINGLE_FILE_BYTES: z.coerce.number().int().positive().default(262_144),
  COMMITGATE_VERIFIER_TIMEOUT_MS: z.coerce.number().int().min(1_000).default(30_000),
  COMMITGATE_VERIFIER_MAX_OUTPUT_BYTES: z.coerce
    .number()
    .int()
    .min(1_024)
    .default(65_536),
  COMMITGATE_MAX_UNIQUE_SNAPSHOTS: z.coerce.number().int().min(2).default(20),
  COMMITGATE_MAX_SNAPSHOT_BYTES: z.coerce
    .number()
    .int()
    .min(1_048_576)
    .default(536_870_912),
  COMMITGATE_SOURCE_REVISION: z.string().trim().min(1).max(128).optional(),
  RUNTIME_INSTANCE_ID: z
    .string()
    .trim()
    .min(1)
    .max(48)
    .regex(/^[a-zA-Z0-9_.-]+$/)
    .default("default"),
  APP_AUTH_TOKEN: z
    .string()
    .trim()
    .max(128)
    .regex(/^[A-Za-z0-9._~-]*$/, "APP_AUTH_TOKEN must use URL-safe characters")
    .optional(),
  ARK_API_KEY: z.string().optional(),
  ARK_MODEL: z.string().optional(),
  ARK_BASE_URL: z.string().url().default(DEFAULT_ARK_BASE_URL),
  MODEL_PROVIDER: z.enum(["ark", "openrouter"]).optional(),
  MODEL_BASE_URL: z.string().url().optional(),
  MODEL_ID: z.string().optional(),
  MODEL_API_KEY: z.string().optional(),
  MODEL_WIRE_API: z.literal("responses").default("responses"),
  MODEL_ACCESS_MODE: z.enum(["direct", "relay"]).default("direct"),
  MODEL_RELAY_URL: z.string().url().optional(),
  /** Host/API-side relay endpoint for revocation; Runtime still receives MODEL_RELAY_URL. */
  MODEL_RELAY_ADMIN_URL: z.string().url().optional(),
  MODEL_RELAY_TOKEN: z.string().optional(),
  MODEL_RELAY_CAPABILITY_TTL_SECONDS: z.coerce
    .number()
    .int()
    .min(30)
    .max(3_600)
    .optional(),
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
});

export type AppConfig = ReturnType<typeof loadConfig>;

function isDedicatedAgentNetwork(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  return (
    normalized.length > 0 &&
    !["bridge", "host", "default", "none"].includes(normalized) &&
    !normalized.startsWith("container:") &&
    !normalized.startsWith("slirp4netns")
  );
}

export function loadConfig(environment: NodeJS.ProcessEnv = process.env) {
  const env = envSchema.parse(environment);
  const sourceRevision = env.COMMITGATE_SOURCE_REVISION ?? "unverified";
  const productionProofParticipant =
    env.NODE_ENV === "production" &&
    (env.PROCESS_ROLE === "runtime-broker" ||
      (env.PROCESS_ROLE === "api" && env.COMMITGATE_ENABLED === "true"));
  if (productionProofParticipant && !/^[a-f0-9]{40}$/.test(sourceRevision)) {
    throw new Error(
      "Production CommitGate API/Runtime Broker requires a full 40-hex COMMITGATE_SOURCE_REVISION",
    );
  }
  if (
    env.NODE_ENV === "production" &&
    env.PROCESS_ROLE === "api" &&
    [
      "COMMITGATE_FAULT_INJECTION",
      "COMMITGATE_API_FAULT_POINT",
      "COMMITGATE_API_FAULT_AGENT_ID",
      "COMMITGATE_API_FAULT_RUN_ID",
    ].some((name) => environment[name] !== undefined)
  ) {
    throw new Error("Production API must not expose CommitGate fault-injection switches");
  }
  const authToken = env.APP_AUTH_TOKEN?.trim() ?? "";
  const loopbackHosts = new Set(["127.0.0.1", "::1", "localhost"]);
  if (
    env.NODE_ENV === "production" &&
    env.PROCESS_ROLE === "api" &&
    !loopbackHosts.has(env.HOST)
  ) {
    if (authToken.length < 24 || authToken.startsWith("replace-")) {
      throw new Error(
        "APP_AUTH_TOKEN must contain at least 24 characters for a non-loopback production server",
      );
    }
  }
  const defaultContainerUser =
    typeof process.getuid === "function" && typeof process.getgid === "function"
      ? process.getuid() + ":" + process.getgid()
      : "1000:1000";
  const workspaceRoot = path.resolve(env.AGENT_WORKSPACE_ROOT);
  const modelProvider = env.MODEL_PROVIDER ?? "ark";
  const legacyArkBaseUrl = env.ARK_BASE_URL.replace(/\/+$/, "");
  const modelBaseUrl = (
    env.MODEL_BASE_URL ??
    (modelProvider === "openrouter" ? DEFAULT_OPENROUTER_BASE_URL : legacyArkBaseUrl)
  ).replace(/\/+$/, "");
  const modelId = (env.MODEL_ID ?? env.ARK_MODEL ?? "").trim();
  const upstreamModelApiKey = (env.MODEL_API_KEY ?? env.ARK_API_KEY ?? "").trim();
  const modelRelayUrl = env.MODEL_RELAY_URL?.replace(/\/+$/, "") ?? "";
  const modelRelayAdminUrl = (
    env.MODEL_RELAY_ADMIN_URL ?? modelRelayUrl
  ).replace(/\/+$/, "");
  const modelRelayToken = env.MODEL_RELAY_TOKEN?.trim() ?? "";
  if (env.MODEL_ACCESS_MODE === "relay") {
    if (!modelRelayUrl || !modelRelayToken) {
      throw new Error(
        "MODEL_ACCESS_MODE=relay requires MODEL_RELAY_URL and MODEL_RELAY_TOKEN",
      );
    }
    if (Buffer.byteLength(modelRelayToken, "utf8") < 32) {
      throw new Error("MODEL_RELAY_TOKEN must contain at least 32 bytes");
    }
    if (
      ["container", "broker"].includes(env.RUNTIME_PROVIDER) &&
      !isDedicatedAgentNetwork(env.CONTAINER_AGENT_NETWORK)
    ) {
      throw new Error(
        "MODEL_ACCESS_MODE=relay requires CONTAINER_AGENT_NETWORK to name a dedicated internal network",
      );
    }
  }
  if (
    env.NODE_ENV === "production" &&
    env.PROCESS_ROLE === "api" &&
    env.COMMITGATE_ENABLED === "true"
  ) {
    if (env.RUNTIME_PROVIDER !== "broker") {
      throw new Error(
        "Production CommitGate requires RUNTIME_PROVIDER=broker",
      );
    }
    if (env.MODEL_ACCESS_MODE !== "relay") {
      throw new Error(
        "Production CommitGate requires MODEL_ACCESS_MODE=relay; direct Provider credentials are development/test compatibility only",
      );
    }
    if (!isDedicatedAgentNetwork(env.CONTAINER_AGENT_NETWORK)) {
      throw new Error(
        "Production CommitGate requires a dedicated internal CONTAINER_AGENT_NETWORK",
      );
    }
    if (!env.MODEL_RELAY_ADMIN_URL) {
      throw new Error(
        "Production CommitGate requires MODEL_RELAY_ADMIN_URL for fail-closed capability activation and revocation",
      );
    }
    if (upstreamModelApiKey.length > 0) {
      throw new Error(
        "Production CommitGate API must not receive MODEL_API_KEY/ARK_API_KEY; configure the upstream key only in Model Relay",
      );
    }
    if (env.TRANSITION_AUTHORITY !== "worker") {
      throw new Error(
        "Production CommitGate requires TRANSITION_AUTHORITY=worker; in-process authority is development/test only",
      );
    }
    if (!env.TRANSITION_WORKER_SOCKET) {
      throw new Error("Production CommitGate requires TRANSITION_WORKER_SOCKET");
    }
    if (
      env.BROKER_ATTESTATION_KEY?.trim() ||
      environment.BROKER_ATTESTATION_KEY_FILE?.trim()
    ) {
      throw new Error("Production API must not receive the Broker attestation key");
    }
  }
  if (env.NODE_ENV === "production" && env.PROCESS_ROLE === "runtime-broker") {
    if (env.RUNTIME_PROVIDER !== "container") {
      throw new Error("Production Runtime Broker requires RUNTIME_PROVIDER=container");
    }
    if (env.MODEL_ACCESS_MODE !== "relay") {
      throw new Error("Production Runtime Broker requires MODEL_ACCESS_MODE=relay");
    }
    if (!isDedicatedAgentNetwork(env.CONTAINER_AGENT_NETWORK)) {
      throw new Error(
        "Production Runtime Broker requires a dedicated internal CONTAINER_AGENT_NETWORK",
      );
    }
    if (!env.MODEL_RELAY_ADMIN_URL) {
      throw new Error("Production Runtime Broker requires MODEL_RELAY_ADMIN_URL");
    }
    if (upstreamModelApiKey.length > 0) {
      throw new Error("Production Runtime Broker must not receive a Provider API key");
    }
    if (Buffer.byteLength(env.BROKER_ATTESTATION_KEY?.trim() ?? "", "utf8") < 32) {
      throw new Error("Production Runtime Broker requires a 32-byte Broker attestation key");
    }
  }
  const modelRuntimeBaseUrl =
    env.MODEL_ACCESS_MODE === "relay" ? modelRelayUrl : modelBaseUrl;
  const modelRuntimeApiKey =
    env.MODEL_ACCESS_MODE === "relay" ? "" : upstreamModelApiKey;
  const modelRelayCapabilityTtlSeconds =
    env.MODEL_RELAY_CAPABILITY_TTL_SECONDS ??
    Math.min(3_600, Math.ceil(env.CODEX_TIMEOUT_MS / 1_000) + 120);
  return {
    processRole: env.PROCESS_ROLE,
    host: env.HOST,
    port: env.PORT,
    logLevel: env.LOG_LEVEL,
    dataDirectory: path.resolve(env.APP_DATA_DIR),
    workspaceRoot,
    codexHome: path.resolve(env.CODEX_HOME),
    codexBin: env.CODEX_BIN,
    codexSandboxMode: env.CODEX_SANDBOX_MODE,
    codexTimeoutMs: env.CODEX_TIMEOUT_MS,
    codexMaxOutputBytes: env.CODEX_MAX_OUTPUT_BYTES,
    runtimeProvider: env.RUNTIME_PROVIDER,
    runtimeBrokerSocket: path.resolve(
      env.RUNTIME_BROKER_SOCKET || path.join(env.APP_DATA_DIR, "run", "runtime-broker.sock"),
    ),
    brokerAttestationKey:
      env.BROKER_ATTESTATION_KEY?.trim() ||
      (env.NODE_ENV === "production"
        ? ""
        : "commitgate-development-broker-attestation-key-do-not-use-in-production"),
    containerEngine: env.CONTAINER_ENGINE,
    containerRuntimeImage: env.CONTAINER_RUNTIME_IMAGE,
    containerCpuLimit: env.CONTAINER_CPU_LIMIT,
    containerMemoryLimit: env.CONTAINER_MEMORY_LIMIT,
    containerPidsLimit: env.CONTAINER_PIDS_LIMIT,
    containerUser: env.CONTAINER_USER?.trim() || defaultContainerUser,
    containerAgentNetwork: env.CONTAINER_AGENT_NETWORK,
    containerAgentScratchBytes: env.CONTAINER_AGENT_SCRATCH_BYTES,
    containerAgentScratchFiles: env.CONTAINER_AGENT_SCRATCH_FILES,
    containerAgentIgnoredBytes: env.CONTAINER_AGENT_IGNORED_BYTES,
    containerAgentIgnoredFiles: env.CONTAINER_AGENT_IGNORED_FILES,
    commitGateEnabled: env.COMMITGATE_ENABLED === "true",
    commitGatePolicyProfile: parseWorkerPolicyProfile(env.COMMITGATE_POLICY_PROFILE),
    transitionAuthority: env.TRANSITION_AUTHORITY,
    transitionWorkerSocket: path.resolve(
      env.TRANSITION_WORKER_SOCKET || path.join(env.APP_DATA_DIR, "run", "transition-worker.sock"),
    ),
    commitGateExchangeRoot: path.resolve(
      env.COMMITGATE_EXCHANGE_ROOT || path.join(env.APP_DATA_DIR, "exchange"),
    ),
    commitGateExchangeVolume: env.COMMITGATE_EXCHANGE_VOLUME,
    commitGateSessionVolume: env.COMMITGATE_SESSION_VOLUME,
    commitGateSessionVolumeRoot: path.resolve(
      env.COMMITGATE_SESSION_VOLUME_ROOT || env.CODEX_HOME,
    ),
    commitGateTrustedChecksVolume: env.COMMITGATE_TRUSTED_CHECKS_VOLUME,
    commitGateTrustedChecksVolumeRoot: path.resolve(
      env.COMMITGATE_TRUSTED_CHECKS_VOLUME_ROOT || path.join(env.APP_DATA_DIR, "trusted-checks"),
    ),
    commitGateControlRoot: path.resolve(
      env.COMMITGATE_CONTROL_ROOT || path.join(workspaceRoot, ".commitgate"),
    ),
    commitGateTrustedChecksDirectory: path.resolve(env.COMMITGATE_TRUSTED_CHECKS_DIR),
    commitGateMaxChangedFiles: env.COMMITGATE_MAX_CHANGED_FILES,
    commitGateMaxChangedBytes: env.COMMITGATE_MAX_CHANGED_BYTES,
    commitGateMaxSingleFileBytes: env.COMMITGATE_MAX_SINGLE_FILE_BYTES,
    commitGateVerifierTimeoutMs: env.COMMITGATE_VERIFIER_TIMEOUT_MS,
    commitGateVerifierMaxOutputBytes: env.COMMITGATE_VERIFIER_MAX_OUTPUT_BYTES,
    commitGateMaxUniqueSnapshots: env.COMMITGATE_MAX_UNIQUE_SNAPSHOTS,
    commitGateMaxSnapshotBytes: env.COMMITGATE_MAX_SNAPSHOT_BYTES,
    commitGateSourceRevision: sourceRevision,
    runtimeInstanceId: env.RUNTIME_INSTANCE_ID,
    authToken,
    modelProvider,
    modelBaseUrl,
    modelId,
    modelApiKey: upstreamModelApiKey,
    modelWireApi: env.MODEL_WIRE_API,
    modelAccessMode: env.MODEL_ACCESS_MODE,
    modelRelayUrl,
    modelRelayAdminUrl,
    modelRelayToken,
    modelRelayCapabilityTtlSeconds,
    modelRuntimeBaseUrl,
    modelRuntimeApiKey,
    // Legacy aliases keep the existing API/UI operational while callers migrate to MODEL_*.
    arkApiKey: upstreamModelApiKey,
    arkModel: modelId,
    arkBaseUrl: modelBaseUrl,
    nodeEnv: env.NODE_ENV,
  };
}

export function isArkConfigured(config: AppConfig): boolean {
  return isModelConfigured(config);
}

export function isModelConfigured(config: AppConfig): boolean {
  const credential =
    config.modelAccessMode === "relay"
      ? config.modelRelayToken
      : config.modelRuntimeApiKey;
  return (
    credential.length > 0 &&
    !credential.startsWith("replace-") &&
    config.modelId.length > 0 &&
    !config.modelId.includes("replace-")
  );
}

export function modelProviderIdentity(config: AppConfig): ModelProviderIdentity {
  return {
    providerId: config.modelProvider,
    gateway: config.modelRuntimeBaseUrl,
    requestedModel: config.modelId,
    resolvedModel: null,
  };
}

export async function writeCodexConfig(config: AppConfig): Promise<void> {
  await mkdir(config.codexHome, { recursive: true });
  const toml = [
    "# Generated by Volc Agent Launchpad. Edit environment variables, not this file.",
    "model = " + JSON.stringify(config.modelId || "model-not-configured"),
    'model_provider = "commitgate_model"',
    "",
    "[model_providers.commitgate_model]",
    "name = " + JSON.stringify(
      config.modelAccessMode === "relay"
        ? "CommitGate Model Relay"
        : config.modelProvider === "openrouter"
          ? "OpenRouter"
          : "Volcengine Ark",
    ),
    "base_url = " + JSON.stringify(config.modelRuntimeBaseUrl),
    'env_key = "MODEL_API_KEY"',
    "wire_api = " + JSON.stringify(config.modelWireApi),
    "requires_openai_auth = false",
    "",
  ].join("\n");
  const configPath = path.join(config.codexHome, "config.toml");
  const configMode = config.processRole === "runtime-broker" ? 0o640 : 0o600;
  await writeFile(configPath, toml, {
    encoding: "utf8",
    mode: configMode,
  });
  await chmod(configPath, configMode);
}
