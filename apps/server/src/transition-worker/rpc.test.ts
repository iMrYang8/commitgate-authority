import { lstat, mkdir, rm } from "node:fs/promises";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { TransitionWorkerRpcClient, startTransitionWorkerRpc } from "./rpc.js";
import { TransitionWorker, type TransitionWorkerConfig } from "./worker.js";
import { createServer, type Server, type Socket } from "node:net";
import { rpcRequestSchema } from "./contracts.js";

const roots: string[] = [];
const servers: Server[] = [];
const acceptedSockets: Socket[] = [];

afterEach(async () => {
  // A deliberately silent peer is part of the timeout fixture. Destroy its
  // accepted connection before closing the listener so delayed FIN handling
  // cannot turn a client timeout assertion into an afterEach timeout.
  for (const socket of acceptedSockets.splice(0)) socket.destroy();
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("transition-worker Unix RPC", () => {
  it("uses a private mode-0660 Unix socket", async (context) => {
    const socketTempRoot = process.platform === "darwin" ? "/private/tmp" : tmpdir();
    const root = await mkdtemp(path.join(socketTempRoot, "commitgate-rpc-"));
    roots.push(root);
    const config: TransitionWorkerConfig = {
      workspaceRoot: path.join(root, "workspaces"),
      controlRoot: path.join(root, "control"),
      inboxRoot: path.join(root, "inbox"),
      socketPath: path.join(root, "run", "worker.sock"),
    };
    await Promise.all([
      mkdir(config.workspaceRoot),
      mkdir(config.controlRoot),
      mkdir(config.inboxRoot),
    ]);
    let server: Server;
    try {
      server = await startTransitionWorkerRpc(new TransitionWorker(config));
    } catch (error) {
      // Codex's restricted sandbox denies Unix listen(2). Keep that evidence
      // explicitly skipped/unverified here; the same test runs mechanically in
      // normal local/CI Docker rather than substituting a TCP transport.
      if ((error as NodeJS.ErrnoException).code === "EPERM") {
        context.skip();
        return;
      }
      throw error;
    }
    servers.push(server);
    const client = new TransitionWorkerRpcClient(config.socketPath);
    const health = await client.request<{ status: string; mode: string }>({
      method: "health",
      params: {},
    });
    expect(health).toMatchObject({ status: "ok", mode: "authority-v2", protocolVersion: 2 });
    expect((await lstat(config.socketPath)).mode & 0o777).toBe(0o660);
  });

  it("rejects raw host paths and repair force flags at the strict wire schema", () => {
    expect(rpcRequestSchema.safeParse({
      id: "request-1",
      method: "repair",
      params: {
        agentId: "agent",
        transitionId: "tx",
        action: "forward",
        expectedViewId: "a".repeat(64),
        expectedWorkspaceHash: "b".repeat(64),
        force: true,
      },
    }).success).toBe(false);

    expect(rpcRequestSchema.safeParse({
      id: "request-2",
      method: "getProjection",
      params: { agentId: "agent", path: "/host/workspace" },
    }).success).toBe(false);
  });

  it("fails closed when a worker accepts a request but never responds", async (context) => {
    const socketTempRoot = process.platform === "darwin" ? "/private/tmp" : tmpdir();
    const root = await mkdtemp(path.join(socketTempRoot, "commitgate-rpc-timeout-"));
    roots.push(root);
    const socketPath = path.join(root, "worker.sock");
    const server = createServer((socket) => acceptedSockets.push(socket));
    try {
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(socketPath, () => resolve());
      });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EPERM") {
        context.skip();
        return;
      }
      throw error;
    }
    servers.push(server);
    const client = new TransitionWorkerRpcClient(socketPath);
    await expect(client.request({ method: "health", params: {} }, 25)).rejects.toMatchObject({
      code: "WORKER_RPC_TIMEOUT",
    });
  });
});
