#!/usr/bin/env node
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { evidenceProvenance, executionIdentity } from "./evidence-utils.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const reportPath = path.join(root, "eval", "evidence", "demo-start-report.json");
const baseUrl = `http://127.0.0.1:${process.env.PORT || "3000"}`;
const deadline = Date.now() + 15 * 60_000;
const headers = process.env.APP_AUTH_TOKEN
  ? { authorization: `Bearer ${process.env.APP_AUTH_TOKEN}` }
  : {};
let system = null;
let error = null;

while (Date.now() < deadline) {
  try {
    const health = await fetch(baseUrl + "/api/health", { headers });
    if (health.ok) {
      const response = await fetch(baseUrl + "/api/system", { headers });
      if (response.ok) {
        system = await response.json();
        if (
          (system.modelConfigured === true || system.providerConfigured === true || system.arkConfigured === true) &&
          system.codexAvailable === true &&
          system.commitGateReady === true &&
          system.verifierAvailable === true
        ) {
          break;
        }
      }
    }
  } catch (reason) {
    error = reason instanceof Error ? reason.message : String(reason);
  }
  await new Promise((resolve) => setTimeout(resolve, 1_000));
}

const verified = Boolean(
  (system?.modelConfigured || system?.providerConfigured || system?.arkConfigured) &&
  system?.codexAvailable &&
  system?.commitGateReady &&
  system?.verifierAvailable,
);
const report = {
  schemaVersion: 2,
  kind: "one-command-demo-start",
  generatedAt: new Date().toISOString(),
  status: verified ? "verified" : "failed",
  source: await evidenceProvenance(root),
  executionIdentity: executionIdentity(root),
  baseUrl,
  system: system
    ? {
        modelConfigured:
          system.modelConfigured ?? system.providerConfigured ?? system.arkConfigured ?? false,
        modelProvider: system.modelProvider ?? (system.arkConfigured ? "ark" : null),
        modelId: system.modelId ?? system.arkModel ?? null,
        codexAvailable: system.codexAvailable,
        commitGateReady: system.commitGateReady,
        verifierAvailable: system.verifierAvailable,
        runtimeProvider: system.runtimeProvider,
      }
    : null,
  credentialsRecorded: false,
  error: verified ? null : error || "Demo did not become fully ready before timeout",
};
await mkdir(path.dirname(reportPath), { recursive: true });
await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");
console.log(`${report.status}: demo startup report: ${reportPath}`);
process.exitCode = verified ? 0 : 1;
