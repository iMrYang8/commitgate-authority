import { execFileSync } from "node:child_process";
import path from "node:path";
import { loadConfig } from "../apps/server/src/config.js";
import {
  verifierConfigHash,
  verifierResourcePolicyHash,
  type DockerVerifierConfig,
} from "../apps/server/src/commitgate/verifier-runner.js";
import { hashSealedTrustedCheckBundleSource } from "../apps/server/src/commitgate/trusted-check-bundle.js";

const repositoryRoot = path.resolve(import.meta.dirname, "..");
const sourceRevision = process.env.COMMITGATE_SOURCE_REVISION ?? "";
const stackId = process.env.COMMITGATE_STACK_ID ?? "commitgate";
const runtimeImage = process.env.CONTAINER_RUNTIME_IMAGE ?? "volc-agent-runtime:local";
const syntheticRelayToken = "x".repeat(32);
// Pin derivation happens before demo runtime secrets are materialized. The
// attestation value is needed only to satisfy production Broker config
// validation; none of the derived hashes depends on it and it is never output
// or passed to a container.
const syntheticBrokerAttestationKey = "pin-derivation-only-".padEnd(48, "x");

const config = loadConfig({
  ...process.env,
  NODE_ENV: "production",
  PROCESS_ROLE: "runtime-broker",
  RUNTIME_PROVIDER: "container",
  TRANSITION_AUTHORITY: "worker",
  COMMITGATE_ENABLED: "false",
  COMMITGATE_SOURCE_REVISION: sourceRevision,
  COMMITGATE_TRUSTED_CHECKS_DIR: path.join(repositoryRoot, "eval", "trusted-checks"),
  COMMITGATE_TRUSTED_CHECKS_VOLUME_ROOT: "/var/lib/commitgate/trusted-checks",
  COMMITGATE_TRUSTED_CHECKS_VOLUME: `${stackId}-trusted-checks`,
  COMMITGATE_EXCHANGE_ROOT: "/var/lib/commitgate/exchange",
  COMMITGATE_EXCHANGE_VOLUME: `${stackId}-exchange`,
  CODEX_HOME: "/var/lib/commitgate/sessions",
  CONTAINER_RUNTIME_IMAGE: runtimeImage,
  CONTAINER_USER: "10001:20000",
  CONTAINER_AGENT_NETWORK: `${stackId}-agent-relay`,
  MODEL_ACCESS_MODE: "relay",
  MODEL_RELAY_URL: "http://model-relay:3100/v1",
  MODEL_RELAY_ADMIN_URL: "http://model-relay:3100/v1",
  MODEL_API_KEY: "",
  ARK_API_KEY: "",
  BROKER_ATTESTATION_KEY: syntheticBrokerAttestationKey,
  // Only configuration validation reads this synthetic launcher-local value.
  // It is not a Provider credential and is never passed into a container.
  MODEL_RELAY_TOKEN: syntheticRelayToken,
});

const verifierConfig: DockerVerifierConfig = {
  engine: config.containerEngine,
  image: config.containerRuntimeImage,
  cpuLimit: config.containerCpuLimit,
  memoryLimit: config.containerMemoryLimit,
  pidsLimit: config.containerPidsLimit,
  user: config.containerUser,
  instanceId: config.runtimeInstanceId,
  trustedChecksPath: config.commitGateTrustedChecksDirectory,
  trustedCheckStorePath: path.join(config.commitGateTrustedChecksVolumeRoot, "store"),
  trustedChecksVolume: config.commitGateTrustedChecksVolume,
  trustedChecksVolumeRoot: config.commitGateTrustedChecksVolumeRoot,
  proposalVolume: config.commitGateExchangeVolume,
  runTimeoutMs: config.commitGateVerifierTimeoutMs,
  maxOutputBytes: config.commitGateVerifierMaxOutputBytes,
  sourceRevision: config.commitGateSourceRevision,
};

const inspected = JSON.parse(
  execFileSync(config.containerEngine, ["image", "inspect", runtimeImage], {
    encoding: "utf8",
    maxBuffer: 2 * 1024 * 1024,
  }),
) as Array<{ Id?: unknown; RepoDigests?: unknown }>;
const image = inspected[0];
if (!image || typeof image.Id !== "string" || !/^sha256:[a-f0-9]{64}$/.test(image.Id)) {
  throw new Error("VERIFIER_IMAGE_ID_UNAVAILABLE");
}
const repositoryDigests = Array.isArray(image.RepoDigests)
  ? image.RepoDigests.filter((value): value is string => typeof value === "string").sort()
  : [];
const repositoryDigest = repositoryDigests[0]?.split("@").at(-1);
const imageDigest = repositoryDigest && /^sha256:[a-f0-9]{64}$/.test(repositoryDigest)
  ? repositoryDigest
  : image.Id;

const pins = {
  COMMITGATE_EXPECTED_CHECK_BUNDLE_HASH: await hashSealedTrustedCheckBundleSource(
    config.commitGateTrustedChecksDirectory,
  ),
  COMMITGATE_EXPECTED_VERIFIER_IMAGE_DIGEST: imageDigest,
  COMMITGATE_EXPECTED_VERIFIER_CONFIG_HASH: verifierConfigHash(verifierConfig),
  COMMITGATE_EXPECTED_RESOURCE_POLICY_HASH: verifierResourcePolicyHash(verifierConfig),
};

if (process.argv.includes("--shell")) {
  for (const [name, value] of Object.entries(pins)) {
    process.stdout.write(`export ${name}=${value}\n`);
  }
} else {
  process.stdout.write(JSON.stringify(pins, null, 2) + "\n");
}
