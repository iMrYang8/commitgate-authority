#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import {
  evidenceProvenance,
  executionIdentity,
  parseFlag,
} from "./evidence-utils.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const provider = parseFlag(process.argv.slice(2), "provider") ?? process.env.MODEL_PROVIDER ?? "ark";
if (!new Set(["ark", "openrouter"]).has(provider)) {
  console.error("Usage: npm run eval:provider -- --provider ark|openrouter");
  process.exit(2);
}

const genericKey = (process.env.MODEL_API_KEY ?? "").trim();
const legacyArkKey = provider === "ark" ? (process.env.ARK_API_KEY ?? "").trim() : "";
const key = genericKey || legacyArkKey;
const model = (process.env.MODEL_ID ?? (provider === "ark" ? process.env.ARK_MODEL : "") ?? "").trim();
const baseUrl = (
  process.env.MODEL_BASE_URL ??
  (provider === "openrouter"
    ? "https://openrouter.ai/api/v1"
    : process.env.ARK_BASE_URL ?? "https://ark.cn-beijing.volces.com/api/v3")
).replace(/\/+$/, "");
const configured =
  key.length > 0 &&
  !key.startsWith("replace-") &&
  model.length > 0 &&
  !model.includes("replace-");
const reportPath = path.join(root, "eval", `provider-${provider}-report.json`);

if (!configured) {
  const report = {
    schemaVersion: 2,
    kind: "real-provider-evaluation",
    generatedAt: new Date().toISOString(),
    status: "unverified",
    source: await evidenceProvenance(root),
    executionIdentity: executionIdentity(root, { providerId: provider }),
    provider: {
      providerId: provider,
      gateway: baseUrl,
      requestedModel: model || null,
      resolvedModel: null,
      credentialsRecorded: false,
    },
    reason:
      provider === "ark"
        ? "MODEL_API_KEY/MODEL_ID or compatible ARK_API_KEY/ARK_MODEL are not configured"
        : "MODEL_API_KEY and MODEL_ID are not configured for OpenRouter",
    officialProviderE2E: "unverified",
    alternateProviderVerified: false,
    competitionVerified: false,
  };
  await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");
  console.log(`unverified: ${provider} provider credentials are not configured; report: ${reportPath}`);
  process.exit(2);
}

const childEnvironment = {
  ...process.env,
  MODEL_PROVIDER: provider,
  MODEL_BASE_URL: baseUrl,
  MODEL_ID: model,
  MODEL_API_KEY: key,
  MODEL_WIRE_API: "responses",
  COMMITGATE_PROVIDER_REPORT: reportPath,
};
const result = spawnSync(
  process.execPath,
  ["--import", "tsx", path.join(root, "scripts", "eval-real.ts"), "--provider", provider],
  { cwd: root, env: childEnvironment, stdio: "inherit" },
);
process.exit(result.status ?? 1);
