import { Readable } from "node:stream";
import { createHash, timingSafeEqual } from "node:crypto";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { verifyModelRelayCapability } from "./model-provider.js";
import type { ModelProviderIdentity } from "./types.js";

const MAX_REQUEST_BYTES = 8 * 1024 * 1024;
const MAX_IDENTITY_CAPTURE_BYTES = 1024 * 1024;
const IDENTITY_CAPTURE_TIMEOUT_MS = 2_000;
const RESPONSE_HEADERS = new Set([
  "content-type",
  "cache-control",
  "x-request-id",
  "openai-processing-ms",
]);

export interface ModelRelayOptions {
  providerId: ModelProviderIdentity["providerId"];
  signingSecret: string;
  upstreamApiKey: string;
  upstreamBaseUrl: string;
  modelId: string;
  fetchImpl?: typeof fetch;
  nowMs?: () => number;
  capabilityRegistry?: ModelRelayCapabilityRegistry;
}

/** Run-scoped relay capabilities may serve an Agent loop's multiple model calls,
 * but become unusable as soon as Runtime teardown revokes their nonce. */
export class ModelRelayCapabilityRegistry {
  private readonly active = new Map<
    string,
    { expiresAt: number; tokenDigest: string }
  >();
  private readonly revoked = new Map<string, number>();
  private readonly resolvedModels = new Map<
    string,
    { model: string; expiresAt: number; conflicted: boolean }
  >();
  private readonly pendingResolution = new Map<string, Promise<void>>();

  activate(
    nonce: string,
    expiresAt: number,
    tokenDigest: string,
    nowSeconds = Math.floor(Date.now() / 1_000),
  ): void {
    this.prune(nowSeconds);
    if (expiresAt <= nowSeconds) throw new Error("RELAY_CAPABILITY_EXPIRED");
    if (this.revoked.has(nonce)) throw new Error("RELAY_CAPABILITY_ALREADY_REVOKED");
    const existing = this.active.get(nonce);
    if (existing && existing.tokenDigest !== tokenDigest) {
      throw new Error("RELAY_CAPABILITY_NONCE_COLLISION");
    }
    this.active.set(nonce, { expiresAt, tokenDigest });
  }

  isActive(
    nonce: string,
    tokenDigest: string,
    nowSeconds = Math.floor(Date.now() / 1_000),
  ): boolean {
    this.prune(nowSeconds);
    const active = this.active.get(nonce);
    return Boolean(active && active.tokenDigest === tokenDigest);
  }

  revoke(
    nonce: string,
    expiresAt: number,
    nowSeconds = Math.floor(Date.now() / 1_000),
  ): void {
    this.prune(nowSeconds);
    this.active.delete(nonce);
    this.revoked.set(nonce, expiresAt);
  }

  recordResolvedModel(nonce: string, model: string, expiresAt = Number.MAX_SAFE_INTEGER): void {
    const normalized = model.trim();
    if (!normalized) return;
    const existing = this.resolvedModels.get(nonce);
    if (existing && existing.model !== normalized) {
      this.resolvedModels.set(nonce, {
        model: existing.model,
        expiresAt: Math.max(existing.expiresAt, expiresAt),
        conflicted: true,
      });
      return;
    }
    this.resolvedModels.set(nonce, {
      model: normalized,
      expiresAt,
      conflicted: existing?.conflicted ?? false,
    });
  }

  resolvedModel(nonce: string): string | null {
    const record = this.resolvedModels.get(nonce);
    return record && !record.conflicted ? record.model : null;
  }

  trackResolvedModel(
    nonce: string,
    expiresAt: number,
    operation: Promise<string | null>,
  ): void {
    const resolution = operation
      .then((model) => {
        if (model) this.recordResolvedModel(nonce, model, expiresAt);
      })
      .catch(() => undefined);
    const previous = this.pendingResolution.get(nonce) ?? Promise.resolve();
    const pending = Promise.all([previous, resolution]).then(() => undefined);
    this.pendingResolution.set(nonce, pending);
    void pending.finally(() => {
      if (this.pendingResolution.get(nonce) === pending) {
        this.pendingResolution.delete(nonce);
      }
    });
  }

  async awaitResolvedModel(nonce: string, timeoutMs = 1_000): Promise<string | null> {
    const pending = this.pendingResolution.get(nonce);
    if (pending) {
      await Promise.race([
        pending,
        new Promise<void>((resolve) => setTimeout(resolve, timeoutMs)),
      ]);
    }
    return this.resolvedModel(nonce);
  }

  isRevoked(nonce: string, nowSeconds = Math.floor(Date.now() / 1_000)): boolean {
    this.prune(nowSeconds);
    return this.revoked.has(nonce);
  }

  private prune(nowSeconds = Math.floor(Date.now() / 1_000)): void {
    for (const [nonce, active] of this.active) {
      if (active.expiresAt <= nowSeconds) this.active.delete(nonce);
    }
    for (const [nonce, expiresAt] of this.revoked) {
      if (expiresAt <= nowSeconds) this.revoked.delete(nonce);
    }
    for (const [nonce, identity] of this.resolvedModels) {
      if (identity.expiresAt <= nowSeconds) this.resolvedModels.delete(nonce);
    }
  }
}

function tokenDigest(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

export interface RelayRequest {
  authorization: string | undefined;
  contentType: string | undefined;
  accept: string | undefined;
  body: Uint8Array;
}

export async function forwardModelRelayRequest(
  request: RelayRequest,
  options: ModelRelayOptions,
): Promise<Response> {
  const token = request.authorization?.match(/^Bearer\s+(.+)$/i)?.[1];
  if (!token) return jsonError(401, "RELAY_CAPABILITY_REQUIRED");
  const nowMs = options.nowMs?.() ?? Date.now();
  let capability: ReturnType<typeof verifyModelRelayCapability>;
  try {
    capability = verifyModelRelayCapability(
      token,
      options.signingSecret,
      {},
      nowMs,
    );
    if (
      options.capabilityRegistry?.isRevoked(
        capability.nonce,
        Math.floor(nowMs / 1_000),
      )
    ) {
      return jsonError(401, "RELAY_CAPABILITY_REVOKED");
    }
    if (
      options.capabilityRegistry &&
      !options.capabilityRegistry.isActive(
        capability.nonce,
        tokenDigest(token),
        Math.floor(nowMs / 1_000),
      )
    ) {
      return jsonError(401, "RELAY_CAPABILITY_INACTIVE");
    }
  } catch {
    return jsonError(401, "RELAY_CAPABILITY_INVALID");
  }
  if (!options.upstreamApiKey || options.upstreamApiKey.startsWith("replace-")) {
    return jsonError(503, "UPSTREAM_PROVIDER_NOT_CONFIGURED");
  }
  if (request.body.byteLength === 0 || request.body.byteLength > MAX_REQUEST_BYTES) {
    return jsonError(413, "RELAY_REQUEST_SIZE_INVALID");
  }
  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(Buffer.from(request.body).toString("utf8")) as Record<
      string,
      unknown
    >;
  } catch {
    return jsonError(400, "RELAY_REQUEST_JSON_INVALID");
  }
  if (payload.model !== options.modelId) {
    return jsonError(403, "RELAY_MODEL_SCOPE_MISMATCH");
  }
  const preparedPayload = prepareUpstreamPayload(
    payload,
    request.body,
    options.providerId,
  );
  if (preparedPayload.errorCode) {
    return jsonError(400, preparedPayload.errorCode);
  }
  const upstream = options.upstreamBaseUrl.replace(/\/+$/, "") + "/responses";
  try {
    const response = await (options.fetchImpl ?? fetch)(upstream, {
      method: "POST",
      headers: {
        authorization: "Bearer " + options.upstreamApiKey,
        "content-type": request.contentType || "application/json",
        accept: request.accept || "text/event-stream, application/json",
      },
      body: preparedPayload.body,
      redirect: "error",
    });
    if (options.capabilityRegistry) {
      options.capabilityRegistry.trackResolvedModel(
        capability.nonce,
        capability.expiresAt,
        captureResolvedModel(response.clone()),
      );
    }
    return response;
  } catch {
    return jsonError(502, "UPSTREAM_PROVIDER_UNAVAILABLE");
  }
}

interface PreparedUpstreamPayload {
  body: Uint8Array;
  errorCode?: string;
}

function prepareUpstreamPayload(
  payload: Readonly<Record<string, unknown>>,
  originalBody: Uint8Array,
  providerId: ModelProviderIdentity["providerId"],
): PreparedUpstreamPayload {
  if (providerId !== "ark") {
    return { body: originalBody };
  }

  let upstreamPayload: Readonly<Record<string, unknown>> = payload;
  let changed = false;

  if (Array.isArray(payload.tools)) {
    const tools = payload.tools.filter(
      (tool) => !isDisabledExternalWebSearchTool(tool),
    );
    if (tools.length !== payload.tools.length) {
      if (explicitlySelectsWebSearch(payload.tool_choice)) {
        return {
          body: originalBody,
          errorCode: "RELAY_ARK_WEB_SEARCH_TOOL_CHOICE_UNSUPPORTED",
        };
      }
      upstreamPayload = { ...upstreamPayload, tools };
      changed = true;
    }
  }

  if (Array.isArray(payload.input)) {
    let inputChanged = false;
    const input = payload.input.map((item) => {
      if (!requiresArkCompletedStatus(item)) return item;
      inputChanged = true;
      return { ...item, status: "completed" };
    });
    if (inputChanged) {
      upstreamPayload = { ...upstreamPayload, input };
      changed = true;
    }
  }

  if (!changed) return { body: originalBody };

  // Build new objects instead of mutating the parsed request. OpenRouter and
  // Ark requests that need no compatibility normalization continue upstream
  // byte-for-byte unchanged.
  return { body: Buffer.from(JSON.stringify(upstreamPayload), "utf8") };
}

function isDisabledExternalWebSearchTool(value: unknown): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const tool = value as Record<string, unknown>;
  return tool.type === "web_search" && tool.external_web_access === false;
}

function requiresArkCompletedStatus(
  value: unknown,
): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const item = value as Record<string, unknown>;
  if (Object.hasOwn(item, "status")) return false;
  return (
    item.type === "function_call_output" ||
    (item.type === "message" && item.role === "assistant")
  );
}

function explicitlySelectsWebSearch(value: unknown): boolean {
  if (value === "web_search") return true;
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const choice = value as Record<string, unknown>;
  return (
    choice.type === "web_search" ||
    (choice.type === "tool" && choice.name === "web_search") ||
    (choice.type === "allowed_tools" &&
      Array.isArray(choice.tools) &&
      choice.tools.some(explicitlySelectsWebSearch))
  );
}

export function createModelRelayServer(options: ModelRelayOptions): Server {
  const capabilityRegistry =
    options.capabilityRegistry ?? new ModelRelayCapabilityRegistry();
  const serverOptions = { ...options, capabilityRegistry };
  return createServer(async (request, response) => {
    if (request.method === "GET" && request.url === "/health") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end('{"status":"ok","service":"commitgate-model-relay"}\n');
      return;
    }
    if (
      request.method === "POST" &&
      [
        "/internal/capabilities/activate",
        "/internal/capabilities/revoke",
      ].includes(request.url ?? "")
    ) {
      if (!constantTimeBearerMatches(request.headers.authorization, options.signingSecret)) {
        response.writeHead(401, { "content-type": "application/json" });
        response.end('{"error":{"code":"RELAY_ADMIN_AUTH_INVALID"}}\n');
        return;
      }
      try {
        const body = JSON.parse(
          Buffer.from(await readBoundedBody(request)).toString("utf8"),
        ) as { token?: unknown };
        if (typeof body.token !== "string") throw new Error("missing token");
        const capability = verifyModelRelayCapability(
          body.token,
          options.signingSecret,
          {},
          options.nowMs?.() ?? Date.now(),
        );
        if (request.url === "/internal/capabilities/activate") {
          capabilityRegistry.activate(
            capability.nonce,
            capability.expiresAt,
            tokenDigest(body.token),
            Math.floor((options.nowMs?.() ?? Date.now()) / 1_000),
          );
          response.writeHead(200, { "content-type": "application/json" });
          response.end('{"activated":true}\n');
          return;
        }
        capabilityRegistry.revoke(
          capability.nonce,
          capability.expiresAt,
          Math.floor((options.nowMs?.() ?? Date.now()) / 1_000),
        );
        const resolvedModel = await capabilityRegistry.awaitResolvedModel(
          capability.nonce,
        );
        response.writeHead(200, { "content-type": "application/json" });
        response.end(
          JSON.stringify({
            revoked: true,
            resolvedModel,
          }) + "\n",
        );
      } catch {
        response.writeHead(400, { "content-type": "application/json" });
        response.end(
          JSON.stringify({
            error: {
              code:
                request.url === "/internal/capabilities/activate"
                  ? "RELAY_ACTIVATE_INVALID"
                  : "RELAY_REVOKE_INVALID",
            },
          }) + "\n",
        );
      }
      return;
    }
    if (
      request.method !== "POST" ||
      !["/responses", "/v1/responses"].includes(request.url ?? "")
    ) {
      response.writeHead(404, { "content-type": "application/json" });
      response.end('{"error":{"code":"RELAY_ROUTE_NOT_FOUND"}}\n');
      return;
    }
    let body: Uint8Array;
    try {
      body = await readBoundedBody(request);
    } catch {
      response.writeHead(413, { "content-type": "application/json" });
      response.end('{"error":{"code":"RELAY_REQUEST_TOO_LARGE"}}\n');
      return;
    }
    const upstream = await forwardModelRelayRequest(
      {
        authorization: request.headers.authorization,
        contentType: request.headers["content-type"],
        accept: request.headers.accept,
        body,
      },
      serverOptions,
    );
    pipeResponse(upstream, response);
  });
}

async function captureResolvedModel(response: Response): Promise<string | null> {
  try {
    if (!response.body) return null;
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    const decoder = new TextDecoder();
    let pendingLine = "";
    let bytes = 0;
    const deadline = Date.now() + IDENTITY_CAPTURE_TIMEOUT_MS;
    try {
      while (bytes <= MAX_IDENTITY_CAPTURE_BYTES) {
        const remainingMs = deadline - Date.now();
        if (remainingMs <= 0) break;
        const result = await readBeforeDeadline(reader, remainingMs);
        if (!result) break;
        const { done, value } = result;
        if (done) break;
        if (!value) continue;
        const remaining = MAX_IDENTITY_CAPTURE_BYTES - bytes;
        if (remaining <= 0) break;
        const accepted = value.subarray(0, remaining);
        chunks.push(accepted);
        bytes += accepted.byteLength;

        // SSE events are complete at a line boundary. Parse each line once so
        // long streams do not repeatedly concatenate/reparse the whole prefix.
        pendingLine += decoder.decode(accepted, { stream: true });
        const lines = pendingLine.split(/\r?\n/);
        pendingLine = lines.pop() ?? "";
        for (const line of lines) {
          const model = findModelInResponseText(line);
          if (model) return model;
        }
        if (value.byteLength > remaining) break;
      }
    } finally {
      // A cloned/tee'd stream may keep cancel() pending until the client-side
      // branch drains. Identity capture must never delay revocation evidence.
      void reader.cancel().catch(() => undefined);
    }
    const completeText = Buffer.concat(
      chunks.map((chunk) => Buffer.from(chunk)),
      bytes,
    ).toString("utf8");
    return findModelInResponseText(completeText);
  } catch {
    // Resolved identity remains null when the gateway does not expose it.
  }
  return null;
}

async function readBeforeDeadline(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  timeoutMs: number,
): Promise<{ done: boolean; value: Uint8Array | undefined } | null> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      reader.read(),
      new Promise<null>((resolve) => {
        timer = setTimeout(() => resolve(null), timeoutMs);
        timer.unref();
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function findModelInResponseText(text: string): string | null {
  try {
    const parsed = findModel(JSON.parse(text));
    if (parsed) return parsed;
  } catch {
    // Streaming responses are parsed line-by-line below.
  }
  try {
    for (const line of text.split(/\r?\n/)) {
      const candidate = line.startsWith("data:") ? line.slice(5).trim() : line.trim();
      if (!candidate || candidate === "[DONE]") continue;
      try {
        const model = findModel(JSON.parse(candidate));
        if (model) return model;
      } catch {
        // Ignore non-JSON SSE fields.
      }
    }
  } catch {
    return null;
  }
  return null;
}

function findModel(value: unknown): string | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  if (typeof record.model === "string" && record.model.trim()) return record.model.trim();
  // Responses streaming events place the authoritative identity on the
  // top-level response object. Do not recursively trust arbitrary generated
  // output containing a user-controlled `model` field.
  const nestedResponse = record.response;
  if (
    nestedResponse &&
    typeof nestedResponse === "object" &&
    !Array.isArray(nestedResponse)
  ) {
    const model = (nestedResponse as Record<string, unknown>).model;
    if (typeof model === "string" && model.trim()) return model.trim();
  }
  return null;
}

function constantTimeBearerMatches(
  authorization: string | undefined,
  expectedSecret: string,
): boolean {
  const candidate = authorization?.match(/^Bearer\s+(.+)$/i)?.[1] ?? "";
  const left = Buffer.from(candidate, "utf8");
  const right = Buffer.from(expectedSecret, "utf8");
  return left.length === right.length && timingSafeEqual(left, right);
}

function readBoundedBody(request: IncomingMessage): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let bytes = 0;
    request.on("data", (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > MAX_REQUEST_BYTES) {
        reject(new Error("RELAY_REQUEST_TOO_LARGE"));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.once("end", () => resolve(Buffer.concat(chunks)));
    request.once("error", reject);
  });
}

function pipeResponse(upstream: Response, response: ServerResponse): void {
  const headers: Record<string, string> = {};
  for (const [name, value] of upstream.headers.entries()) {
    if (RESPONSE_HEADERS.has(name.toLowerCase())) headers[name] = value;
  }
  response.writeHead(upstream.status, headers);
  if (!upstream.body) {
    response.end();
    return;
  }
  Readable.fromWeb(upstream.body as never).pipe(response);
}

function jsonError(status: number, code: string): Response {
  return Response.json({ error: { code } }, { status });
}
