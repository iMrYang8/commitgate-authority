import { describe, expect, it } from "vitest";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { HttpError } from "./errors.js";
import type { AgentService } from "./agent-service.js";

const service = {
  listAgents: () => [],
  systemInfo: async () => ({}),
} as unknown as AgentService;

describe("HTTP boundary", () => {
  it("protects API routes with the configured shared token", async () => {
    const app = await createApp(
      loadConfig({ NODE_ENV: "test", APP_AUTH_TOKEN: "a-strong-test-token" }),
      service,
    );
    const denied = await app.inject({ method: "GET", url: "/api/agents" });
    expect(denied.statusCode).toBe(401);

    const allowed = await app.inject({
      method: "GET",
      url: "/api/agents",
      headers: { authorization: "Bearer a-strong-test-token" },
    });
    expect(allowed.statusCode).toBe(200);
    await app.close();
  });

  it("exposes an Agent-scoped rollback receipt proof only with APP_AUTH_TOKEN", async () => {
    const agentId = "11111111-1111-4111-8111-111111111111";
    const receiptId = "rollback-22222222-2222-4222-8222-222222222222";
    const boundary = {
      listAgents: () => [],
      systemInfo: async () => ({}),
      getCommitGateProofByReceipt: async (
        requestedAgentId: string,
        requestedReceiptId: string,
      ) => ({
        schemaVersion: 2,
        receipt: {
          receiptId: requestedReceiptId,
          agentId: requestedAgentId,
          decision: "COMMITTED",
        },
        proof: { signingKeyId: "worker-key", signatureAlgorithm: "Ed25519" },
        terminalEvent: { eventId: "rollback-terminal-event" },
        predecessorEvent: null,
        publicKeyPem: "PUBLIC KEY",
      }),
    } as unknown as AgentService;
    const app = await createApp(
      loadConfig({ NODE_ENV: "test", APP_AUTH_TOKEN: "a-strong-test-token" }),
      boundary,
    );
    const url = `/api/agents/${agentId}/commitgate/proofs/${receiptId}`;

    const denied = await app.inject({ method: "GET", url });
    expect(denied.statusCode).toBe(401);

    const allowed = await app.inject({
      method: "GET",
      url,
      headers: { authorization: "Bearer a-strong-test-token" },
    });
    expect(allowed.statusCode).toBe(200);
    expect(allowed.json().proof).toMatchObject({
      receipt: { receiptId, agentId, decision: "COMMITTED" },
      proof: { signingKeyId: "worker-key", signatureAlgorithm: "Ed25519" },
    });

    const pathLikeReceipt = await app.inject({
      method: "GET",
      url: `/api/agents/${agentId}/commitgate/proofs/..%2Fcontrol%2Flog`,
      headers: { authorization: "Bearer a-strong-test-token" },
    });
    expect(pathLikeReceipt.statusCode).toBe(400);
    await app.close();
  });

  it("preserves Fastify client error status codes", async () => {
    const app = await createApp(
      loadConfig({ NODE_ENV: "test", COMMITGATE_ENABLED: "false" }),
      service,
    );
    const malformed = await app.inject({
      method: "POST",
      url: "/api/agents",
      headers: { "content-type": "application/json" },
      payload: "{not-json",
    });
    expect(malformed.statusCode).toBe(400);

    const oversized = await app.inject({
      method: "POST",
      url: "/api/agents",
      headers: { "content-type": "application/json" },
      payload: JSON.stringify({ name: "x".repeat(1_100_000) }),
    });
    expect(oversized.statusCode).toBe(413);
    await app.close();
  });

  it("exposes receipt, version history and coded rollback conflicts", async () => {
    const agentId = "11111111-1111-4111-8111-111111111111";
    const runId = "22222222-2222-4222-8222-222222222222";
    const boundary = {
      listAgents: () => [],
      systemInfo: async () => ({}),
      getVersions: () => [{ id: "v1", sequence: 1 }],
      getCommitGateReceipt: async () => ({ runId, decision: "COMMITTED" }),
      getCommitGateProof: async () => ({
        schemaVersion: 2,
        receipt: { receiptId: runId, decision: "COMMITTED" },
        proof: { signingKeyId: "worker-key", signatureAlgorithm: "Ed25519" },
        terminalEvent: { eventId: "terminal-event" },
        predecessorEvent: null,
        publicKeyPem: "PUBLIC KEY",
      }),
      attemptPromotionReplay: async () => ({
        code: "PERMIT_REPLAY" as const,
        permitState: "CONSUMED" as const,
        headUnchanged: true as const,
        currentViewId: "b".repeat(64),
        currentGeneration: 3,
      }),
      rollback: async () => {
        throw new HttpError(409, "Expected head does not match", "HEAD_MISMATCH");
      },
    } as unknown as AgentService;
    const app = await createApp(
      loadConfig({ NODE_ENV: "test", COMMITGATE_ENABLED: "false" }),
      boundary,
    );

    const versions = await app.inject({
      method: "GET",
      url: `/api/agents/${agentId}/versions?limit=20`,
    });
    expect(versions.statusCode).toBe(200);
    expect(versions.json().versions).toEqual([{ id: "v1", sequence: 1 }]);

    const receipt = await app.inject({ method: "GET", url: `/api/runs/${runId}/commitgate` });
    expect(receipt.statusCode).toBe(200);
    expect(receipt.json().receipt.decision).toBe("COMMITTED");

    const proof = await app.inject({
      method: "GET",
      url: `/api/runs/${runId}/commitgate/proof`,
    });
    expect(proof.statusCode).toBe(200);
    expect(proof.json().proof).toMatchObject({
      schemaVersion: 2,
      receipt: { receiptId: runId, decision: "COMMITTED" },
      proof: { signingKeyId: "worker-key", signatureAlgorithm: "Ed25519" },
    });

    const replay = await app.inject({
      method: "POST",
      url: `/api/runs/${runId}/commitgate/promotion-attempts`,
      payload: {
        permitId: "k-consumed",
        expectedViewId: "b".repeat(64),
      },
    });
    expect(replay.statusCode).toBe(409);
    expect(replay.json()).toMatchObject({
      code: "PERMIT_REPLAY",
      permitState: "CONSUMED",
      headUnchanged: true,
      currentGeneration: 3,
    });

    const rollback = await app.inject({
      method: "POST",
      url: `/api/agents/${agentId}/rollbacks`,
      payload: {
        targetVersionId: "v1",
        expectedHeadVersionId: "stale",
        expectedViewId: "a".repeat(64),
        expectedGeneration: 1,
      },
    });
    expect(rollback.statusCode).toBe(409);
    expect(rollback.json()).toMatchObject({ code: "HEAD_MISMATCH" });
    await app.close();
  });

  it("fail-closes CommitGate mutation APIs when APP_AUTH_TOKEN is absent", async () => {
    const app = await createApp(loadConfig({ NODE_ENV: "test" }), service);
    const response = await app.inject({
      method: "POST",
      url: "/api/agents",
      payload: { name: "blocked" },
    });
    expect(response.statusCode).toBe(503);
    expect(response.json()).toMatchObject({ code: "APP_AUTH_TOKEN_REQUIRED" });
    const auth = await app.inject({ method: "GET", url: "/api/auth" });
    expect(auth.json()).toEqual({ required: true, configured: false });
    await app.close();
  });
});
