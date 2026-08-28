import { readFile } from "node:fs/promises";
import { loadConfig } from "./config.js";
import { createModelRelayServer } from "./model-relay-server.js";

for (const [fileVariable, valueVariable] of [
  ["MODEL_API_KEY_FILE", "MODEL_API_KEY"],
  ["MODEL_RELAY_TOKEN_FILE", "MODEL_RELAY_TOKEN"],
] as const) {
  const file = process.env[fileVariable]?.trim();
  if (file) process.env[valueVariable] = (await readFile(file, "utf8")).trim();
}

const config = loadConfig();
if (config.modelAccessMode !== "relay") {
  throw new Error("Model Relay requires MODEL_ACCESS_MODE=relay");
}
const port = Number.parseInt(process.env.MODEL_RELAY_PORT ?? "3100", 10);
if (!Number.isInteger(port) || port < 1 || port > 65_535) {
  throw new Error("MODEL_RELAY_PORT must be a valid TCP port");
}
const server = createModelRelayServer({
  providerId: config.modelProvider,
  signingSecret: config.modelRelayToken,
  upstreamApiKey: config.modelApiKey,
  upstreamBaseUrl: config.modelBaseUrl,
  modelId: config.modelId,
});
server.listen(port, "0.0.0.0");

const shutdown = () => server.close(() => process.exit(0));
process.once("SIGTERM", shutdown);
process.once("SIGINT", shutdown);
