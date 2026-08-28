import { mkdir } from "node:fs/promises";
import path from "node:path";
import { loadConfig } from "../config.js";
import { writeCodexConfig } from "../config.js";
import { RuntimeBroker, startRuntimeBrokerRpc } from "./server.js";
import { loadRuntimeSecretFiles } from "../load-runtime-secrets.js";

await loadRuntimeSecretFiles();
const config = loadConfig({
  ...process.env,
  PROCESS_ROLE: "runtime-broker",
  HOST: "127.0.0.1",
  RUNTIME_PROVIDER: "container",
  COMMITGATE_ENABLED: "false",
});
await writeCodexConfig(config);
await mkdir(path.dirname(config.runtimeBrokerSocket), { recursive: true, mode: 0o750 });
const server = await startRuntimeBrokerRpc(new RuntimeBroker(config), config.runtimeBrokerSocket);
process.stdout.write(JSON.stringify({ ready: true, socket: config.runtimeBrokerSocket }) + "\n");

const shutdown = () => server.close(() => process.exit(0));
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
