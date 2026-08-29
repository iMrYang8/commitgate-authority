import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  isModelConfigured,
  loadConfig,
  modelProviderIdentity,
  writeCodexConfig,
} from "./config.js";
import {
  activateModelRelayCapability,
  codexConfigPath,
  codexSessionHome,
  createModelRelayCapability,
  modelCredentialForRun,
  prepareCodexSessionHome,
  redactModelCredential,
  revokeModelRelayCapability,
  retireCodexSessionHome,
  verifyModelRelayCapability,
} from "./model-provider.js";

const roots: string[] = [];
const sourceRevision = "a".repeat(40);

afterEach(async () => {
  const { rm } = await import("node:fs/promises");
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function tempRoot(): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), "commitgate-config-"));
  roots.push(root);
  return root;
}

describe("model provider configuration", () => {
  it("requires a frozen 40-hex source revision for production proof participants", () => {
    expect(() => loadConfig({
      NODE_ENV: "production",
      PROCESS_ROLE: "api",
      COMMITGATE_ENABLED: "true",
    })).toThrow(/40-hex COMMITGATE_SOURCE_REVISION/);
    expect(() => loadConfig({
      NODE_ENV: "production",
      PROCESS_ROLE: "runtime-broker",
      COMMITGATE_ENABLED: "false",
      COMMITGATE_SOURCE_REVISION: "unverified",
    })).toThrow(/40-hex COMMITGATE_SOURCE_REVISION/);
  });

  it("fails closed when a production API carries any fault-injection switch", () => {
    expect(() => loadConfig({
      NODE_ENV: "production",
      COMMITGATE_SOURCE_REVISION: sourceRevision,
      PROCESS_ROLE: "api",
      HOST: "127.0.0.1",
      COMMITGATE_FAULT_INJECTION: "false",
    })).toThrow(/must not expose CommitGate fault-injection switches/);
    expect(() => loadConfig({
      NODE_ENV: "production",
      COMMITGATE_SOURCE_REVISION: sourceRevision,
      PROCESS_ROLE: "api",
      HOST: "127.0.0.1",
      COMMITGATE_API_FAULT_POINT: "API_PROJECTION_PENDING",
    })).toThrow(/must not expose CommitGate fault-injection switches/);
  });

  it("keeps ARK_* compatible while emitting the generic Responses provider", async () => {
    const root = await tempRoot();
    const config = loadConfig({
      NODE_ENV: "test",
      CODEX_HOME: path.join(root, "codex"),
      ARK_API_KEY: "ark-secret",
      ARK_MODEL: "ep-legacy",
      ARK_BASE_URL: "https://ark.example/v3/",
    });

    expect(config.modelProvider).toBe("ark");
    expect(config.modelApiKey).toBe("ark-secret");
    expect(config.modelId).toBe("ep-legacy");
    expect(config.modelBaseUrl).toBe("https://ark.example/v3");
    expect(config.arkApiKey).toBe(config.modelApiKey);
    expect(isModelConfigured(config)).toBe(true);

    await writeCodexConfig(config);
    const generated = await readFile(codexConfigPath(config), "utf8");
    expect(generated).toContain('model_provider = "commitgate_model"');
    expect(generated).toContain('env_key = "MODEL_API_KEY"');
    expect(generated).toContain('wire_api = "responses"');
    expect(generated).toContain('base_url = "https://ark.example/v3"');
    expect(generated).not.toContain("ark-secret");
  });

  it("gives MODEL_* precedence and reports the real OpenRouter identity", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      MODEL_PROVIDER: "openrouter",
      MODEL_BASE_URL: "https://openrouter.example/api/v1/",
      MODEL_ID: "deepseek/deepseek-v4-flash",
      MODEL_API_KEY: "or-secret",
      ARK_MODEL: "legacy-model",
      ARK_API_KEY: "legacy-secret",
    });

    expect(config.modelProvider).toBe("openrouter");
    expect(config.modelId).toBe("deepseek/deepseek-v4-flash");
    expect(config.modelApiKey).toBe("or-secret");
    expect(modelProviderIdentity(config)).toEqual({
      providerId: "openrouter",
      gateway: "https://openrouter.example/api/v1",
      requestedModel: "deepseek/deepseek-v4-flash",
      resolvedModel: null,
    });
  });

  it("requires relay credentials and a dedicated internal network", () => {
    expect(() =>
      loadConfig({
        NODE_ENV: "test",
        MODEL_ACCESS_MODE: "relay",
        MODEL_RELAY_URL: "http://relay:8080/v1",
        MODEL_RELAY_TOKEN: "relay-signing-secret-that-is-at-least-32-bytes",
        RUNTIME_PROVIDER: "broker",
      }),
    ).toThrow(/dedicated internal network/);
    expect(() =>
      loadConfig({
        NODE_ENV: "test",
        MODEL_ACCESS_MODE: "relay",
        CONTAINER_AGENT_NETWORK: "commitgate-model-internal",
      }),
    ).toThrow(/MODEL_RELAY_URL and MODEL_RELAY_TOKEN/);
  });

  it("fails closed on direct Provider access in production CommitGate", () => {
    expect(() =>
      loadConfig({
        NODE_ENV: "production",
        COMMITGATE_SOURCE_REVISION: sourceRevision,
        HOST: "127.0.0.1",
        RUNTIME_PROVIDER: "broker",
        COMMITGATE_ENABLED: "true",
        MODEL_ACCESS_MODE: "direct",
        MODEL_ID: "model",
        MODEL_API_KEY: "upstream-secret",
      }),
    ).toThrow(/requires MODEL_ACCESS_MODE=relay/);
    expect(() =>
      loadConfig({
        NODE_ENV: "production",
        COMMITGATE_SOURCE_REVISION: sourceRevision,
        HOST: "127.0.0.1",
        RUNTIME_PROVIDER: "local-process",
        COMMITGATE_ENABLED: "true",
      }),
    ).toThrow(/requires RUNTIME_PROVIDER=broker/);
  });

  it("permits production CommitGate only with relay capability and a dedicated network", () => {
    const config = loadConfig({
      NODE_ENV: "production",
      COMMITGATE_SOURCE_REVISION: sourceRevision,
      HOST: "127.0.0.1",
      RUNTIME_PROVIDER: "broker",
      COMMITGATE_ENABLED: "true",
      TRANSITION_AUTHORITY: "worker",
      TRANSITION_WORKER_SOCKET: "/run/commitgate/transition-worker.sock",
      MODEL_PROVIDER: "openrouter",
      MODEL_ID: "deepseek/deepseek-v4-flash",
      MODEL_ACCESS_MODE: "relay",
      MODEL_RELAY_URL: "http://model-relay:8080/v1",
      MODEL_RELAY_ADMIN_URL: "http://127.0.0.1:3100",
      MODEL_RELAY_TOKEN: "relay-signing-secret-that-is-at-least-32-bytes",
      CONTAINER_AGENT_NETWORK: "commitgate-model-internal",
    });

    expect(config.modelRuntimeApiKey).toBe("");
    expect(config.modelApiKey).toBe("");
    expect(config.modelAccessMode).toBe("relay");
    expect(config.containerAgentNetwork).toBe("commitgate-model-internal");
    expect(config.transitionAuthority).toBe("worker");
    expect(config.brokerAttestationKey).toBe("");

    expect(() =>
      loadConfig({
        NODE_ENV: "production",
        COMMITGATE_SOURCE_REVISION: sourceRevision,
        PROCESS_ROLE: "api",
        HOST: "127.0.0.1",
        RUNTIME_PROVIDER: "broker",
        COMMITGATE_ENABLED: "true",
        TRANSITION_AUTHORITY: "worker",
        TRANSITION_WORKER_SOCKET: "/run/commitgate/transition-worker.sock",
        MODEL_ID: "model",
        MODEL_ACCESS_MODE: "relay",
        MODEL_RELAY_URL: "http://model-relay:8080/v1",
        MODEL_RELAY_ADMIN_URL: "http://127.0.0.1:3100",
        MODEL_RELAY_TOKEN: "relay-signing-secret-that-is-at-least-32-bytes",
        CONTAINER_AGENT_NETWORK: "commitgate-model-internal",
        BROKER_ATTESTATION_KEY: "api-must-not-receive-this-attestation-key-value",
      }),
    ).toThrow(/must not receive the Broker attestation key/);

    expect(() =>
      loadConfig({
        NODE_ENV: "production",
        COMMITGATE_SOURCE_REVISION: sourceRevision,
        HOST: "127.0.0.1",
        RUNTIME_PROVIDER: "broker",
        COMMITGATE_ENABLED: "true",
        MODEL_ID: "model",
        MODEL_API_KEY: "must-live-only-in-relay",
        MODEL_ACCESS_MODE: "relay",
        MODEL_RELAY_URL: "http://model-relay:8080/v1",
        MODEL_RELAY_ADMIN_URL: "http://127.0.0.1:3100",
        MODEL_RELAY_TOKEN: "relay-signing-secret-that-is-at-least-32-bytes",
        CONTAINER_AGENT_NETWORK: "commitgate-model-internal",
      }),
    ).toThrow(/upstream key only in Model Relay/);

    expect(() =>
      loadConfig({
        NODE_ENV: "production",
        COMMITGATE_SOURCE_REVISION: sourceRevision,
        HOST: "127.0.0.1",
        RUNTIME_PROVIDER: "broker",
        COMMITGATE_ENABLED: "true",
        MODEL_ID: "model",
        MODEL_ACCESS_MODE: "relay",
        MODEL_RELAY_URL: "http://model-relay:8080/v1",
        MODEL_RELAY_TOKEN: "relay-signing-secret-that-is-at-least-32-bytes",
        CONTAINER_AGENT_NETWORK: "commitgate-model-internal",
      }),
    ).toThrow(/requires MODEL_RELAY_ADMIN_URL/);
  });

  it("requires the transition worker as production CommitGate authority", () => {
    const base = {
      NODE_ENV: "production",
      COMMITGATE_SOURCE_REVISION: sourceRevision,
      HOST: "127.0.0.1",
      RUNTIME_PROVIDER: "broker",
      COMMITGATE_ENABLED: "true",
      MODEL_ID: "model",
      MODEL_ACCESS_MODE: "relay",
      MODEL_RELAY_URL: "http://model-relay:8080/v1",
      MODEL_RELAY_ADMIN_URL: "http://127.0.0.1:3100",
      MODEL_RELAY_TOKEN: "relay-signing-secret-that-is-at-least-32-bytes",
      CONTAINER_AGENT_NETWORK: "commitgate-model-internal",
    } as const;
    expect(() => loadConfig(base)).toThrow(/TRANSITION_AUTHORITY=worker/);
    expect(() => loadConfig({ ...base, TRANSITION_AUTHORITY: "worker" })).toThrow(
      /TRANSITION_WORKER_SOCKET/,
    );
  });

  it("enforces the dedicated relay-only boundary for the production Runtime Broker role", () => {
    const base = {
      NODE_ENV: "production",
      COMMITGATE_SOURCE_REVISION: sourceRevision,
      PROCESS_ROLE: "runtime-broker",
      HOST: "127.0.0.1",
      RUNTIME_PROVIDER: "container",
      COMMITGATE_ENABLED: "false",
      MODEL_ID: "model",
      MODEL_ACCESS_MODE: "relay",
      MODEL_RELAY_URL: "http://model-relay:3100/v1",
      MODEL_RELAY_ADMIN_URL: "http://127.0.0.1:3100/v1",
      MODEL_RELAY_TOKEN: "relay-signing-secret-that-is-at-least-32-bytes",
      BROKER_ATTESTATION_KEY: "broker-attestation-secret-that-is-at-least-32-bytes",
      CONTAINER_AGENT_NETWORK: "commitgate-model-internal",
    } as const;
    expect(loadConfig(base).processRole).toBe("runtime-broker");
    const { BROKER_ATTESTATION_KEY: _key, ...withoutAttestationKey } = base;
    expect(() => loadConfig(withoutAttestationKey)).toThrow(
      /requires a 32-byte Broker attestation key/,
    );
    expect(() => loadConfig({ ...base, CONTAINER_AGENT_NETWORK: "bridge" })).toThrow(
      /dedicated internal/,
    );
    expect(() => loadConfig({ ...base, MODEL_API_KEY: "provider-key" })).toThrow(
      /must not receive a Provider API key/,
    );
  });

  it("retains explicit direct-provider compatibility outside production CommitGate", () => {
    expect(
      loadConfig({
        NODE_ENV: "development",
        RUNTIME_PROVIDER: "container",
        COMMITGATE_ENABLED: "true",
        MODEL_ACCESS_MODE: "direct",
        MODEL_ID: "dev-model",
        MODEL_API_KEY: "dev-key",
      }).modelRuntimeApiKey,
    ).toBe("dev-key");
    expect(
      loadConfig({
        NODE_ENV: "production",
        COMMITGATE_SOURCE_REVISION: sourceRevision,
        HOST: "127.0.0.1",
        COMMITGATE_ENABLED: "false",
        MODEL_ACCESS_MODE: "direct",
      }).modelAccessMode,
    ).toBe("direct");
  });

  it("issues a short-lived HMAC capability scoped to one Agent run", () => {
    const secret = "relay-signing-secret-that-is-at-least-32-bytes";
    const scope = { runId: "run-1", agentId: "agent-1", sessionEpoch: 3 };
    const token = createModelRelayCapability(scope, secret, {
      nowMs: 1_000_000,
      ttlSeconds: 60,
      nonce: "fixed_nonce_123456789",
    });

    expect(token).toMatch(/^cg1\./);
    expect(token).not.toContain(secret);
    expect(
      verifyModelRelayCapability(token, secret, scope, 1_030_000),
    ).toMatchObject({
      runId: "run-1",
      agentId: "agent-1",
      sessionEpoch: 3,
      expiresAt: 1_060,
    });
    expect(() =>
      verifyModelRelayCapability(
        token,
        secret,
        { ...scope, runId: "run-2" },
        1_030_000,
      ),
    ).toThrow(/scope/);
    expect(() =>
      verifyModelRelayCapability(token, secret, scope, 1_060_000),
    ).toThrow(/expired/);
    expect(() =>
      verifyModelRelayCapability(token.slice(0, -1) + "A", secret, scope, 1_030_000),
    ).toThrow(/signature/);

    const relayConfig = loadConfig({
      NODE_ENV: "test",
      MODEL_PROVIDER: "openrouter",
      MODEL_ID: "deepseek/deepseek-v4-flash",
      MODEL_ACCESS_MODE: "relay",
      MODEL_RELAY_URL: "http://relay:8080/v1",
      MODEL_RELAY_TOKEN: secret,
    });
    const runtimeCredential = modelCredentialForRun(relayConfig, scope);
    expect(runtimeCredential).toMatch(/^cg1\./);
    expect(runtimeCredential).not.toBe(secret);
    expect(relayConfig.modelRuntimeApiKey).toBe("");
    expect(redactModelCredential(`token=${runtimeCredential}`, runtimeCredential)).toBe(
      "token=[REDACTED_MODEL_CREDENTIAL]",
    );
  });

  it("uses the host-side authenticated relay control endpoint for activation and revocation", async () => {
    const secret = "relay-signing-secret-that-is-at-least-32-bytes";
    const config = loadConfig({
      NODE_ENV: "test",
      MODEL_ID: "model",
      MODEL_ACCESS_MODE: "relay",
      MODEL_RELAY_URL: "http://model-relay:8080/v1",
      MODEL_RELAY_ADMIN_URL: "http://127.0.0.1:3100",
      MODEL_RELAY_TOKEN: secret,
    });
    const token = createModelRelayCapability(
      { runId: "run", agentId: "agent", sessionEpoch: 1 },
      secret,
      { ttlSeconds: 60, nowMs: 1_000_000, nonce: "fixed_nonce_123456789" },
    );
    const paths: string[] = [];
    const fakeFetch = (async (input: string | URL | Request, init?: RequestInit) => {
      paths.push(String(input));
      expect(new Headers(init?.headers).get("authorization")).toBe(
        "Bearer " + secret,
      );
      expect(String(init?.body)).toContain(token);
      if (String(input).endsWith("/activate")) {
        return Response.json({ activated: true });
      }
      return Response.json({ revoked: true, resolvedModel: "resolved-model" });
    }) as typeof fetch;

    await expect(
      activateModelRelayCapability(config, token, fakeFetch),
    ).resolves.toBe(true);
    await expect(
      revokeModelRelayCapability(config, token, fakeFetch),
    ).resolves.toEqual({ revoked: true, resolvedModel: "resolved-model" });
    expect(paths).toEqual([
      "http://127.0.0.1:3100/internal/capabilities/activate",
      "http://127.0.0.1:3100/internal/capabilities/revoke",
    ]);
  });

  it("isolates session homes by Agent and epoch and retires the previous epoch", async () => {
    const root = await tempRoot();
    const config = loadConfig({
      NODE_ENV: "test",
      CODEX_HOME: path.join(root, "codex"),
      ARK_MODEL: "ep-test",
    });
    await writeCodexConfig(config);
    const epoch0 = await prepareCodexSessionHome(
      config,
      { agentId: "agent/one", sessionEpoch: 0 },
      true,
    );
    await writeFile(path.join(epoch0, "thread-cache"), "old");
    const epoch1 = await prepareCodexSessionHome(
      config,
      { agentId: "agent/one", sessionEpoch: 1 },
      true,
    );

    expect(epoch1).toBe(codexSessionHome(config, "agent/one", 1));
    expect(epoch1).not.toBe(codexSessionHome(config, "agent/two", 1));
    await expect(stat(epoch0)).rejects.toMatchObject({ code: "ENOENT" });
    expect((await stat(path.join(epoch1, "config.toml"))).mode & 0o777).toBe(0o400);
    expect(await readFile(path.join(epoch1, "config.toml"), "utf8")).toContain(
      'model = "ep-test"',
    );
    await expect(
      prepareCodexSessionHome(
        config,
        { agentId: "agent/one", sessionEpoch: 0 },
        true,
      ),
    ).rejects.toThrow(/Stale Codex session epoch/);

    await retireCodexSessionHome(config, "agent/one", 2);
    await expect(stat(epoch1)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(
      prepareCodexSessionHome(
        config,
        { agentId: "agent/one", sessionEpoch: 1 },
        true,
      ),
    ).rejects.toThrow(/Stale Codex session epoch/);
  });
});
