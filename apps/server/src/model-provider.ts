import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import type { AppConfig } from "./config.js";
import type { RunnerRequest } from "./types.js";

export interface ModelRelayCapability {
  version: 1;
  audience: "commitgate-model-relay";
  runId: string;
  agentId: string;
  sessionEpoch: number;
  issuedAt: number;
  expiresAt: number;
  nonce: string;
}

export interface ExpectedRelayScope {
  runId?: string;
  agentId?: string;
  sessionEpoch?: number;
}

function assertRelaySecret(secret: string): void {
  if (Buffer.byteLength(secret, "utf8") < 32) {
    throw new Error("Model Relay signing secret must contain at least 32 bytes");
  }
}

function signCapability(encodedPayload: string, secret: string): Buffer {
  return createHmac("sha256", secret).update("cg1." + encodedPayload).digest();
}

export function createModelRelayCapability(
  scope: Pick<RunnerRequest, "runId" | "agentId" | "sessionEpoch">,
  secret: string,
  options: { nowMs?: number; ttlSeconds: number; nonce?: string },
): string {
  assertRelaySecret(secret);
  if (!Number.isSafeInteger(options.ttlSeconds) || options.ttlSeconds < 1) {
    throw new Error("Model Relay capability TTL must be a positive integer");
  }
  const sessionEpoch = scope.sessionEpoch ?? 0;
  if (
    !scope.runId ||
    !scope.agentId ||
    !Number.isSafeInteger(sessionEpoch) ||
    sessionEpoch < 0
  ) {
    throw new Error("Model Relay capability scope is invalid");
  }
  const nonce = options.nonce ?? randomBytes(18).toString("base64url");
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(nonce)) {
    throw new Error("Model Relay capability nonce is invalid");
  }
  const issuedAt = Math.floor((options.nowMs ?? Date.now()) / 1_000);
  const payload: ModelRelayCapability = {
    version: 1,
    audience: "commitgate-model-relay",
    runId: scope.runId,
    agentId: scope.agentId,
    sessionEpoch,
    issuedAt,
    expiresAt: issuedAt + options.ttlSeconds,
    nonce,
  };
  const encodedPayload = Buffer.from(JSON.stringify(payload), "utf8").toString(
    "base64url",
  );
  return (
    "cg1." +
    encodedPayload +
    "." +
    signCapability(encodedPayload, secret).toString("base64url")
  );
}

export function verifyModelRelayCapability(
  token: string,
  secret: string,
  expected: ExpectedRelayScope,
  nowMs = Date.now(),
): ModelRelayCapability {
  assertRelaySecret(secret);
  if (token.length > 4_096) throw new Error("Model Relay capability is too large");
  const [prefix, encodedPayload, encodedSignature, extra] = token.split(".");
  if (prefix !== "cg1" || !encodedPayload || !encodedSignature || extra !== undefined) {
    throw new Error("Model Relay capability format is invalid");
  }
  const providedSignature = Buffer.from(encodedSignature, "base64url");
  const expectedSignature = signCapability(encodedPayload, secret);
  if (
    providedSignature.length !== expectedSignature.length ||
    !timingSafeEqual(providedSignature, expectedSignature)
  ) {
    throw new Error("Model Relay capability signature is invalid");
  }
  let payload: ModelRelayCapability;
  try {
    payload = JSON.parse(
      Buffer.from(encodedPayload, "base64url").toString("utf8"),
    ) as ModelRelayCapability;
  } catch {
    throw new Error("Model Relay capability payload is invalid");
  }
  const now = Math.floor(nowMs / 1_000);
  if (
    payload.version !== 1 ||
    payload.audience !== "commitgate-model-relay" ||
    typeof payload.runId !== "string" ||
    typeof payload.agentId !== "string" ||
    !Number.isSafeInteger(payload.sessionEpoch) ||
    payload.sessionEpoch < 0 ||
    typeof payload.issuedAt !== "number" ||
    !Number.isSafeInteger(payload.issuedAt) ||
    typeof payload.expiresAt !== "number" ||
    !Number.isSafeInteger(payload.expiresAt) ||
    typeof payload.nonce !== "string" ||
    !/^[A-Za-z0-9_-]{16,128}$/.test(payload.nonce)
  ) {
    throw new Error("Model Relay capability payload is invalid");
  }
  if (payload.issuedAt > now + 30) {
    throw new Error("Model Relay capability was issued in the future");
  }
  if (payload.expiresAt <= now || payload.expiresAt <= payload.issuedAt) {
    throw new Error("Model Relay capability has expired");
  }
  if (
    (expected.runId !== undefined && payload.runId !== expected.runId) ||
    (expected.agentId !== undefined && payload.agentId !== expected.agentId) ||
    (expected.sessionEpoch !== undefined &&
      payload.sessionEpoch !== expected.sessionEpoch)
  ) {
    throw new Error("Model Relay capability scope does not match the request");
  }
  return payload;
}

export function modelCredentialForRun(
  config: AppConfig,
  request: Pick<RunnerRequest, "runId" | "agentId" | "sessionEpoch">,
): string {
  if (config.modelAccessMode === "direct") return config.modelRuntimeApiKey;
  return createModelRelayCapability(request, config.modelRelayToken, {
    ttlSeconds: config.modelRelayCapabilityTtlSeconds,
  });
}

/** Revoke a run-scoped bearer capability after the Runtime container is gone. */
export async function revokeModelRelayCapability(
  config: AppConfig,
  capabilityToken: string,
  fetchImpl: typeof fetch = fetch,
): Promise<{ revoked: boolean; resolvedModel: string | null }> {
  if (config.modelAccessMode !== "relay") {
    return { revoked: true, resolvedModel: null };
  }
  const endpoint = new URL(
    "/internal/capabilities/revoke",
    config.modelRelayAdminUrl,
  ).toString();
  try {
    const response = await fetchImpl(endpoint, {
      method: "POST",
      headers: {
        authorization: "Bearer " + config.modelRelayToken,
        "content-type": "application/json",
      },
      body: JSON.stringify({ token: capabilityToken }),
      redirect: "error",
    });
    if (!response.ok) return { revoked: false, resolvedModel: null };
    const payload = (await response.json().catch(() => null)) as {
      revoked?: unknown;
      resolvedModel?: unknown;
    } | null;
    return {
      revoked: payload?.revoked === true,
      resolvedModel:
        typeof payload?.resolvedModel === "string" && payload.resolvedModel.trim()
          ? payload.resolvedModel.trim()
          : null,
    };
  } catch {
    return { revoked: false, resolvedModel: null };
  }
}

/**
 * Register a freshly minted run capability before the Runtime is spawned.
 * The relay denies signed-but-unregistered tokens, so relay restart and stale
 * token replay fail closed instead of silently clearing the revocation set.
 */
export async function activateModelRelayCapability(
  config: AppConfig,
  capabilityToken: string,
  fetchImpl: typeof fetch = fetch,
): Promise<boolean> {
  if (config.modelAccessMode !== "relay") return true;
  const endpoint = new URL(
    "/internal/capabilities/activate",
    config.modelRelayAdminUrl,
  ).toString();
  try {
    const response = await fetchImpl(endpoint, {
      method: "POST",
      headers: {
        authorization: "Bearer " + config.modelRelayToken,
        "content-type": "application/json",
      },
      body: JSON.stringify({ token: capabilityToken }),
      redirect: "error",
    });
    if (!response.ok) return false;
    const payload = (await response.json().catch(() => null)) as {
      activated?: unknown;
    } | null;
    return payload?.activated === true;
  } catch {
    return false;
  }
}

export function redactModelCredential(value: string, credential: string): string {
  if (!credential || !value.includes(credential)) return value;
  return value.split(credential).join("[REDACTED_MODEL_CREDENTIAL]");
}

function stableAgentDirectory(agentId: string): string {
  const prefix = agentId.replace(/[^a-zA-Z0-9_.-]/g, "-").slice(0, 32) || "agent";
  const digest = createHash("sha256").update(agentId).digest("hex").slice(0, 16);
  return prefix + "-" + digest;
}

export function codexConfigPath(config: AppConfig): string {
  return path.join(config.codexHome, "config.toml");
}

export function codexSessionHome(
  config: Pick<AppConfig, "codexHome">,
  agentId: string,
  sessionEpoch = 0,
): string {
  if (!Number.isSafeInteger(sessionEpoch) || sessionEpoch < 0) {
    throw new Error("sessionEpoch must be a non-negative safe integer");
  }
  return path.join(
    config.codexHome,
    "sessions",
    stableAgentDirectory(agentId),
    "epoch-" + sessionEpoch,
  );
}

async function readEpochMarker(agentRoot: string): Promise<number | null> {
  try {
    const value = Number.parseInt(
      (await readFile(path.join(agentRoot, "current-epoch"), "utf8")).trim(),
      10,
    );
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error("Codex session epoch marker is invalid");
    }
    return value;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
}

async function writeEpochMarker(agentRoot: string, epoch: number): Promise<void> {
  const marker = path.join(agentRoot, "current-epoch");
  const temporary = marker + ".tmp-" + process.pid + "-" + Date.now();
  await writeFile(temporary, epoch + "\n", { encoding: "utf8", mode: 0o600 });
  await rename(temporary, marker);
}

/**
 * Materialize a per-Agent, per-epoch session directory. Old epochs for the same
 * Agent are removed before a new turn starts, so a reset cannot silently reuse
 * a previous Codex thread/cache. The container path receives config.toml through
 * a separate readonly nested mount; local-process mode gets a readonly copy but
 * is intentionally not part of CommitGate's strong isolation boundary.
 */
export async function prepareCodexSessionHome(
  config: AppConfig,
  request: Pick<RunnerRequest, "agentId" | "sessionEpoch">,
  localProcess: boolean,
): Promise<string> {
  const epoch = request.sessionEpoch ?? 0;
  const sessionHome = codexSessionHome(config, request.agentId, epoch);
  const agentRoot = path.dirname(sessionHome);
  const directoryMode = config.transitionAuthority === "worker" ? 0o770 : 0o700;
  await mkdir(agentRoot, { recursive: true, mode: directoryMode });
  if (config.transitionAuthority === "worker") await chmod(agentRoot, directoryMode);

  const currentEpoch = await readEpochMarker(agentRoot);
  if (currentEpoch !== null && epoch < currentEpoch) {
    throw new Error(
      `Stale Codex session epoch ${epoch}; current epoch is ${currentEpoch}`,
    );
  }

  for (const entry of await readdir(agentRoot, { withFileTypes: true })) {
    if (entry.name.startsWith("epoch-") && entry.name !== path.basename(sessionHome)) {
      await rm(path.join(agentRoot, entry.name), { recursive: true, force: true });
    }
  }
  if (currentEpoch !== epoch) await writeEpochMarker(agentRoot, epoch);
  await mkdir(sessionHome, { recursive: true, mode: directoryMode });
  if (config.transitionAuthority === "worker") await chmod(sessionHome, directoryMode);

  const sourceConfig = codexConfigPath(config);
  const stat = await lstat(sourceConfig);
  if (!stat.isFile()) throw new Error("Generated Codex config.toml is not a regular file");

  if (localProcess) {
    const target = path.join(sessionHome, "config.toml");
    const temporary = target + ".tmp-" + process.pid + "-" + Date.now();
    await copyFile(sourceConfig, temporary);
    await chmod(temporary, 0o400);
    await rename(temporary, target);
  }
  return sessionHome;
}

/** Advance the filesystem fence immediately after a non-commit/reset decision. */
export async function retireCodexSessionHome(
  config: AppConfig,
  agentId: string,
  nextSessionEpoch: number,
): Promise<void> {
  const nextHome = codexSessionHome(config, agentId, nextSessionEpoch);
  const agentRoot = path.dirname(nextHome);
  await mkdir(agentRoot, { recursive: true, mode: 0o700 });
  const currentEpoch = await readEpochMarker(agentRoot);
  if (currentEpoch !== null && nextSessionEpoch < currentEpoch) {
    throw new Error(
      `Cannot retire Codex session to stale epoch ${nextSessionEpoch}; current epoch is ${currentEpoch}`,
    );
  }
  for (const entry of await readdir(agentRoot, { withFileTypes: true })) {
    if (entry.name.startsWith("epoch-")) {
      await rm(path.join(agentRoot, entry.name), { recursive: true, force: true });
    }
  }
  await writeEpochMarker(agentRoot, nextSessionEpoch);
}
