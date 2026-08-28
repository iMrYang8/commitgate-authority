import { mkdtemp, mkdir, stat, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { Server } from "node:net";
import { loadConfig } from "../config.js";
import type { RunnerRequest } from "../types.js";
import { RuntimeBrokerRunner } from "./client.js";
import type { RuntimeBrokerDispatch } from "./contracts.js";
import {
  startRuntimeBrokerRpc,
  validateBrokerRunRequest,
  validateBrokerWorkspaceIdentity,
} from "./server.js";
import { brokerRunRequestSchema } from "./contracts.js";

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

describe("runtime broker Unix RPC", () => {
  it("accepts only the server-derived candidate path for the bound run", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      COMMITGATE_CONTROL_ROOT: "/control",
      RUNTIME_PROVIDER: "broker",
    });
    const base = {
      runId: "run",
      agentId: "agent",
      prompt: "change file",
      threadId: null,
    };
    expect(() => validateBrokerRunRequest(config, {
      ...base,
      workspacePath: "/control/agent/candidates/run",
    })).not.toThrow();
    expect(() => validateBrokerRunRequest(config, {
      ...base,
      workspacePath: "/control/agent/candidates/other",
    })).toThrow(/BROKER_WORKSPACE_NOT_RUN_CANDIDATE/);
    expect(() => validateBrokerRunRequest(config, {
      ...base,
      workspacePath: "/control/../workspaces/agent",
    })).toThrow(/BROKER_WORKSPACE_NOT_RUN_CANDIDATE/);
  });

  it("uses a strict wire schema and rejects unknown Runtime controls", () => {
    expect(() => brokerRunRequestSchema.parse({
      runId: "run",
      agentId: "agent",
      workspacePath: "/control/agent/candidates/run",
      prompt: "change file",
      threadId: null,
      privileged: true,
    })).toThrow();
    expect(() => brokerRunRequestSchema.parse({
      runId: "run",
      agentId: "agent",
      workspacePath: "/control/agent/candidates/run",
      workspaceRef: {
        volumeId: "candidate-run",
        relativeSubpath: "candidate-run",
        runId: "run",
        agentId: "agent",
      },
      prompt: "change file",
      threadId: null,
    })).toThrow(/Exactly one/);
  });

  it("requires a Worker-bound opaque candidate reference in worker mode", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      TRANSITION_AUTHORITY: "worker",
      COMMITGATE_EXCHANGE_ROOT: "/exchange",
      RUNTIME_PROVIDER: "broker",
    });
    const opaque = {
      runId: "run",
      agentId: "agent",
      workspaceRef: {
        volumeId: "candidate-run",
        relativeSubpath: "candidate-run",
        runId: "run",
        agentId: "agent",
      },
      prompt: "change file",
      threadId: null,
    };
    expect(() => validateBrokerRunRequest(config, opaque)).not.toThrow();
    expect(() => validateBrokerRunRequest(config, {
      ...opaque,
      workspacePath: "/exchange/candidate-run",
    })).toThrow(/OPAQUE_WORKSPACE_REF_REQUIRED/);
    expect(() => validateBrokerRunRequest(config, {
      ...opaque,
      workspaceRef: { ...opaque.workspaceRef, volumeId: "candidate-other" },
    })).toThrow(/WORKSPACE_REF_BINDING_MISMATCH/);
  });

  it("rejects a candidate root that resolves through a symlink", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-broker-identity-"));
    const controlRoot = path.join(root, "control");
    const outside = path.join(root, "outside");
    await mkdir(path.join(controlRoot, "agent", "candidates"), { recursive: true });
    await mkdir(outside);
    await symlink(outside, path.join(controlRoot, "agent", "candidates", "run"));
    const config = loadConfig({
      NODE_ENV: "test",
      COMMITGATE_CONTROL_ROOT: controlRoot,
      RUNTIME_PROVIDER: "broker",
    });
    await expect(validateBrokerWorkspaceIdentity(config, {
      runId: "run",
      agentId: "agent",
      workspacePath: path.join(controlRoot, "agent", "candidates", "run"),
      prompt: "change file",
      threadId: null,
    })).rejects.toThrow(/BROKER_WORKSPACE_NOT_DIRECTORY/);
  });

  it("runs, cancels and returns teardown evidence through a mode-0660 socket", async (context) => {
    const socketTempRoot = process.platform === "darwin" ? "/private/tmp" : tmpdir();
    const root = await mkdtemp(path.join(socketTempRoot, "commitgate-broker-"));
    const socketPath = path.join(root, "run", "broker.sock");
    await mkdir(path.dirname(socketPath), { recursive: true });
    let observed: RunnerRequest | null = null;
    const dispatch: RuntimeBrokerDispatch = {
      async health() {
        return { ready: true, runtimeAvailable: true, activeRuns: 0 };
      },
      async runAgent(request) {
        observed = request;
        return { output: "done", threadId: "thread", usage: null };
      },
      async runVerifier() {
        return {
          checks: [],
          environment: {
            imageReference: "runtime",
            imageId: "sha256:image",
            imageDigest: "sha256:image",
            configHash: "a".repeat(64),
            checkBundleHash: "b".repeat(64),
          },
        };
      },
      async cancel(agentId, cancellation) {
        return agentId === "agent" && cancellation.runId === "run";
      },
      async teardown(runId) {
        return {
          containerExited: runId === "run",
          containerRemoved: true,
          mountsReleased: true,
        };
      },
    };
    let server: Server;
    try {
      server = await startRuntimeBrokerRpc(dispatch, socketPath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EPERM") {
        context.skip();
        return;
      }
      throw error;
    }
    servers.push(server);
    const client = new RuntimeBrokerRunner(socketPath);
    const request: RunnerRequest = {
      runId: "run",
      agentId: "agent",
      workspacePath: "/control/agent/candidates/run",
      prompt: "change file",
      threadId: null,
    };

    await expect(client.isAvailable()).resolves.toBe(true);
    await expect(client.run(request)).resolves.toMatchObject({ output: "done" });
    expect(observed).toEqual(request);
    await expect(client.cancel("agent", {
      runId: "run",
      runLeaseId: "lease",
      sessionEpoch: 0,
    })).resolves.toBe(true);
    await expect(client.attestCommitGateTeardown("run")).resolves.toMatchObject({
      containerExited: true,
      mountsReleased: true,
    });
    expect((await stat(socketPath)).mode & 0o777).toBe(0o660);
  });
});
