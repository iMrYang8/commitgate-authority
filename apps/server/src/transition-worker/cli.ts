#!/usr/bin/env node
import { pathToFileURL } from "node:url";
import { TransitionWorkerRpcClient } from "./rpc.js";

export type WorkerCliCommand =
  | { command: "health" }
  | { command: "state" | "rebuild"; agentId: string }
  | {
      command: "repair";
      agentId: string;
      transitionId: string;
      action: "forward" | "rollback";
      expectedViewId: string;
      expectedWorkspaceHash: string;
    };

const digest = /^[a-f0-9]{64}$/;
const identifier = /^[A-Za-z0-9_.-]{1,128}$/;

export function parseWorkerCli(argv: string[]): WorkerCliCommand {
  const [command, ...tokens] = argv;
  if (command === "health" && tokens.length === 0) return { command };
  if (!command || !["state", "rebuild", "repair"].includes(command)) {
    throw new Error("Usage: transition-worker <health|state|rebuild|repair> [options]");
  }
  const options = new Map<string, string>();
  for (let index = 0; index < tokens.length; index += 2) {
    const key = tokens[index];
    const value = tokens[index + 1];
    if (!key?.startsWith("--") || !value || options.has(key)) {
      throw new Error("Invalid or duplicate CLI option");
    }
    options.set(key, value);
  }
  const allowed = command === "repair"
    ? new Set(["--agent", "--transition", "--action", "--expected-view", "--expected-workspace-hash"])
    : new Set(["--agent"]);
  for (const key of options.keys()) {
    if (!allowed.has(key)) throw new Error(`Unsupported CLI option: ${key}`);
  }
  const agentId = options.get("--agent") ?? "";
  if (!identifier.test(agentId)) throw new Error("--agent must be a safe identifier");
  if (command === "state" || command === "rebuild") return { command, agentId };

  const transitionId = options.get("--transition") ?? "";
  const action = options.get("--action") ?? "";
  const expectedViewId = options.get("--expected-view") ?? "";
  const expectedWorkspaceHash = options.get("--expected-workspace-hash") ?? "";
  if (!identifier.test(transitionId)) throw new Error("--transition must be a safe identifier");
  if (action !== "forward" && action !== "rollback") {
    throw new Error("--action must be forward or rollback");
  }
  if (!digest.test(expectedViewId)) throw new Error("--expected-view must be a SHA-256 digest");
  if (!digest.test(expectedWorkspaceHash)) {
    throw new Error("--expected-workspace-hash must be a SHA-256 digest");
  }
  return {
    command: "repair",
    agentId,
    transitionId,
    action,
    expectedViewId,
    expectedWorkspaceHash,
  };
}

export async function runWorkerCli(argv: string[], environment = process.env): Promise<unknown> {
  const command = parseWorkerCli(argv);
  const socketPath = environment.TRANSITION_WORKER_SOCKET ?? "/run/commitgate/transition-worker.sock";
  const client = new TransitionWorkerRpcClient(socketPath);
  switch (command.command) {
    case "health":
      return client.request({ method: "health", params: {} });
    case "state":
      return client.request({ method: "getProjection", params: { agentId: command.agentId } });
    case "rebuild":
      return client.request({ method: "rebuildProjection", params: { agentId: command.agentId } });
    case "repair":
      return client.request({
        method: "repair",
        params: {
          agentId: command.agentId,
          transitionId: command.transitionId,
          action: command.action,
          expectedViewId: command.expectedViewId,
          expectedWorkspaceHash: command.expectedWorkspaceHash,
        },
      });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runWorkerCli(process.argv.slice(2))
    .then((result) => process.stdout.write(JSON.stringify(result, null, 2) + "\n"))
    .catch((error: unknown) => {
      process.stderr.write((error instanceof Error ? error.message : String(error)) + "\n");
      process.exitCode = 1;
    });
}
