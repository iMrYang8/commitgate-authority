import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { createModelRelayCapability } from "./model-provider.js";
import {
  ModelRelayCapabilityRegistry,
  forwardModelRelayRequest,
} from "./model-relay-server.js";

const secret = "relay-secret-material-that-is-at-least-32-bytes";
const token = createModelRelayCapability(
  { runId: "run-1", agentId: "agent-1", sessionEpoch: 2 },
  secret,
  { ttlSeconds: 60, nowMs: 1_000_000, nonce: "abcdefghijklmnop" },
);

describe("minimal Model Relay", () => {
  it("keeps the Provider key at the relay, enforces scope, and rejects a revoked run capability", async () => {
    const fetchImpl = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      expect(new Headers(init?.headers).get("authorization")).toBe("Bearer provider-secret");
      expect(Buffer.from(init?.body as Uint8Array).toString("utf8")).not.toContain(
        "provider-secret",
      );
      return Response.json({ id: "resp-1", model: "MODEL_ID" });
    }) as unknown as typeof fetch;
    const capabilityRegistry = new ModelRelayCapabilityRegistry();
    const base = {
      providerId: "openrouter" as const,
      signingSecret: secret,
      upstreamApiKey: "provider-secret",
      upstreamBaseUrl: "https://provider.invalid/v1",
      modelId: "MODEL_ID",
      fetchImpl,
      nowMs: () => 1_001_000,
      capabilityRegistry,
    };
    const inactive = await forwardModelRelayRequest(
      {
        authorization: "Bearer " + token,
        contentType: "application/json",
        accept: "application/json",
        body: Buffer.from(JSON.stringify({ model: "MODEL_ID", input: "hello" })),
      },
      base,
    );
    expect(inactive.status).toBe(401);
    await expect(inactive.json()).resolves.toMatchObject({
      error: { code: "RELAY_CAPABILITY_INACTIVE" },
    });
    capabilityRegistry.activate(
      "abcdefghijklmnop",
      1_060,
      createHash("sha256").update(token).digest("hex"),
      1_001,
    );
    const accepted = await forwardModelRelayRequest(
      {
        authorization: "Bearer " + token,
        contentType: "application/json",
        accept: "application/json",
        body: Buffer.from(JSON.stringify({ model: "MODEL_ID", input: "hello" })),
      },
      base,
    );
    expect(accepted.status).toBe(200);
    expect(fetchImpl).toHaveBeenCalledOnce();
    await vi.waitFor(() => expect(capabilityRegistry.resolvedModel("abcdefghijklmnop")).toBe("MODEL_ID"));

    const wrongModel = await forwardModelRelayRequest(
      {
        authorization: "Bearer " + token,
        contentType: "application/json",
        accept: "application/json",
        body: Buffer.from(JSON.stringify({ model: "OTHER_MODEL", input: "hello" })),
      },
      base,
    );
    expect(wrongModel.status).toBe(403);
    expect(fetchImpl).toHaveBeenCalledOnce();

    capabilityRegistry.revoke("abcdefghijklmnop", 1_060);
    const revoked = await forwardModelRelayRequest(
      {
        authorization: "Bearer " + token,
        contentType: "application/json",
        accept: "application/json",
        body: Buffer.from(JSON.stringify({ model: "MODEL_ID", input: "replay" })),
      },
      base,
    );
    expect(revoked.status).toBe(401);
    await expect(revoked.json()).resolves.toMatchObject({
      error: { code: "RELAY_CAPABILITY_REVOKED" },
    });
    expect(fetchImpl).toHaveBeenCalledOnce();

    const unsigned = await forwardModelRelayRequest(
      {
        authorization: "Bearer invalid",
        contentType: "application/json",
        accept: "application/json",
        body: Buffer.from(JSON.stringify({ model: "MODEL_ID" })),
      },
      base,
    );
    expect(unsigned.status).toBe(401);
  });

  it("reports resolved-model ambiguity instead of fabricating one model", () => {
    const registry = new ModelRelayCapabilityRegistry();
    registry.recordResolvedModel("nonce", "model-a", 9_999_999_999);
    expect(registry.resolvedModel("nonce")).toBe("model-a");
    registry.recordResolvedModel("nonce", "model-b", 9_999_999_999);
    expect(registry.resolvedModel("nonce")).toBeNull();
  });

  it("does not treat generated nested model text as Provider identity", async () => {
    const capabilityRegistry = new ModelRelayCapabilityRegistry();
    capabilityRegistry.activate(
      "abcdefghijklmnop",
      1_060,
      createHash("sha256").update(token).digest("hex"),
      1_001,
    );
    const accepted = await forwardModelRelayRequest(
      {
        authorization: "Bearer " + token,
        contentType: "application/json",
        accept: "application/json",
        body: Buffer.from(JSON.stringify({ model: "MODEL_ID", input: "hello" })),
      },
      {
        providerId: "openrouter",
        signingSecret: secret,
        upstreamApiKey: "provider-secret",
        upstreamBaseUrl: "https://provider.invalid/v1",
        modelId: "MODEL_ID",
        nowMs: () => 1_001_000,
        capabilityRegistry,
        fetchImpl: (async () =>
          Response.json({
            id: "resp-1",
            output: [{ content: [{ text: '{"model":"forged-by-output"}' }] }],
          })) as typeof fetch,
      },
    );
    expect(accepted.status).toBe(200);
    await accepted.arrayBuffer();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(capabilityRegistry.resolvedModel("abcdefghijklmnop")).toBeNull();
  });

  it("removes Codex's disabled web-search tool only for Ark without mutating the input", async () => {
    const capabilityRegistry = activeRegistry();
    const originalPayload = {
      model: "MODEL_ID",
      input: "hello",
      tools: [
        { type: "web_search", external_web_access: false },
        { type: "function", name: "read_file", parameters: { type: "object" } },
      ],
      tool_choice: "auto",
    };
    const body = Buffer.from(JSON.stringify(originalPayload));
    const fetchImpl = vi.fn(
      async (_url: string | URL | Request, init?: RequestInit) => {
        const forwarded = JSON.parse(
          Buffer.from(init?.body as Uint8Array).toString("utf8"),
        ) as typeof originalPayload;
        expect(forwarded.tools).toEqual([
          {
            type: "function",
            name: "read_file",
            parameters: { type: "object" },
          },
        ]);
        expect(forwarded.tool_choice).toBe("auto");
        return Response.json({ id: "resp-ark", model: "MODEL_ID" });
      },
    ) as unknown as typeof fetch;

    const response = await forwardModelRelayRequest(
      relayRequest(body),
      {
        providerId: "ark",
        signingSecret: secret,
        upstreamApiKey: "provider-secret",
        upstreamBaseUrl: "https://provider.invalid/v1",
        modelId: "MODEL_ID",
        fetchImpl,
        nowMs: () => 1_001_000,
        capabilityRegistry,
      },
    );

    expect(response.status).toBe(200);
    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(JSON.parse(body.toString("utf8"))).toEqual(originalPayload);
    expect(originalPayload.tools).toHaveLength(2);
  });

  it("forwards the same request bytes to OpenRouter", async () => {
    const capabilityRegistry = activeRegistry();
    const body = Buffer.from(
      JSON.stringify({
        model: "MODEL_ID",
        input: [
          { type: "function_call_output", call_id: "call-1", output: "ok" },
          { type: "message", role: "assistant", content: [] },
        ],
        tools: [{ type: "web_search", external_web_access: false }],
      }),
    );
    const fetchImpl = vi.fn(
      async (_url: string | URL | Request, init?: RequestInit) => {
        expect(init?.body).toBe(body);
        return Response.json({ id: "resp-openrouter", model: "MODEL_ID" });
      },
    ) as unknown as typeof fetch;

    const response = await forwardModelRelayRequest(
      relayRequest(body),
      {
        providerId: "openrouter",
        signingSecret: secret,
        upstreamApiKey: "provider-secret",
        upstreamBaseUrl: "https://provider.invalid/v1",
        modelId: "MODEL_ID",
        fetchImpl,
        nowMs: () => 1_001_000,
        capabilityRegistry,
      },
    );

    expect(response.status).toBe(200);
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it("adds Ark's required status only to function_call_output items that omit it", async () => {
    const originalPayload = {
      model: "MODEL_ID",
      input: [
        {
          type: "function_call",
          call_id: "call-1",
          name: "read_file",
          arguments: "{}",
        },
        { type: "function_call_output", call_id: "call-1", output: "first" },
        {
          type: "function_call_output",
          call_id: "call-2",
          output: "second",
          status: "in_progress",
        },
      ],
    };
    const body = Buffer.from(JSON.stringify(originalPayload));
    const fetchImpl = vi.fn(
      async (_url: string | URL | Request, init?: RequestInit) => {
        const forwarded = JSON.parse(
          Buffer.from(init?.body as Uint8Array).toString("utf8"),
        ) as typeof originalPayload;
        expect(forwarded.input).toEqual([
          originalPayload.input[0],
          { ...originalPayload.input[1], status: "completed" },
          originalPayload.input[2],
        ]);
        return Response.json({ id: "resp-ark", model: "MODEL_ID" });
      },
    ) as unknown as typeof fetch;

    const response = await forwardModelRelayRequest(
      relayRequest(body),
      {
        providerId: "ark",
        signingSecret: secret,
        upstreamApiKey: "provider-secret",
        upstreamBaseUrl: "https://provider.invalid/v1",
        modelId: "MODEL_ID",
        fetchImpl,
        nowMs: () => 1_001_000,
        capabilityRegistry: activeRegistry(),
      },
    );

    expect(response.status).toBe(200);
    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(JSON.parse(body.toString("utf8"))).toEqual(originalPayload);
    expect(originalPayload.input[1]).not.toHaveProperty("status");
    expect(originalPayload.input[2]).toHaveProperty("status", "in_progress");
  });

  it("adds Ark's required status only to assistant input messages that omit it", async () => {
    const originalPayload = {
      model: "MODEL_ID",
      input: [
        { type: "message", role: "developer", content: "instructions" },
        { type: "message", role: "user", content: "request" },
        {
          type: "message",
          role: "assistant",
          content: [{ type: "output_text", text: "answer" }],
        },
        {
          type: "message",
          role: "assistant",
          content: [{ type: "output_text", text: "partial" }],
          status: "incomplete",
        },
      ],
    };
    const body = Buffer.from(JSON.stringify(originalPayload));
    const fetchImpl = vi.fn(
      async (_url: string | URL | Request, init?: RequestInit) => {
        const forwarded = JSON.parse(
          Buffer.from(init?.body as Uint8Array).toString("utf8"),
        ) as typeof originalPayload;
        expect(forwarded.input).toEqual([
          originalPayload.input[0],
          originalPayload.input[1],
          { ...originalPayload.input[2], status: "completed" },
          originalPayload.input[3],
        ]);
        return Response.json({ id: "resp-ark", model: "MODEL_ID" });
      },
    ) as unknown as typeof fetch;

    const response = await forwardModelRelayRequest(
      relayRequest(body),
      {
        providerId: "ark",
        signingSecret: secret,
        upstreamApiKey: "provider-secret",
        upstreamBaseUrl: "https://provider.invalid/v1",
        modelId: "MODEL_ID",
        fetchImpl,
        nowMs: () => 1_001_000,
        capabilityRegistry: activeRegistry(),
      },
    );

    expect(response.status).toBe(200);
    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(JSON.parse(body.toString("utf8"))).toEqual(originalPayload);
    expect(originalPayload.input[0]).not.toHaveProperty("status");
    expect(originalPayload.input[1]).not.toHaveProperty("status");
    expect(originalPayload.input[2]).not.toHaveProperty("status");
    expect(originalPayload.input[3]).toHaveProperty("status", "incomplete");
  });

  it("fails closed when Ark tool_choice selects a removed web-search tool", async () => {
    const fetchImpl = vi.fn() as unknown as typeof fetch;
    const response = await forwardModelRelayRequest(
      relayRequest(
        Buffer.from(
          JSON.stringify({
            model: "MODEL_ID",
            tools: [{ type: "web_search", external_web_access: false }],
            tool_choice: { type: "web_search" },
          }),
        ),
      ),
      {
        providerId: "ark",
        signingSecret: secret,
        upstreamApiKey: "provider-secret",
        upstreamBaseUrl: "https://provider.invalid/v1",
        modelId: "MODEL_ID",
        fetchImpl,
        nowMs: () => 1_001_000,
        capabilityRegistry: activeRegistry(),
      },
    );

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: "RELAY_ARK_WEB_SEARCH_TOOL_CHOICE_UNSUPPORTED" },
    });
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

function activeRegistry(): ModelRelayCapabilityRegistry {
  const registry = new ModelRelayCapabilityRegistry();
  registry.activate(
    "abcdefghijklmnop",
    1_060,
    createHash("sha256").update(token).digest("hex"),
    1_001,
  );
  return registry;
}

function relayRequest(body: Uint8Array) {
  return {
    authorization: "Bearer " + token,
    contentType: "application/json",
    accept: "application/json",
    body,
  };
}
