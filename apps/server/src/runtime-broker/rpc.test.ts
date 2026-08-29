import { chmod, mkdtemp, mkdir, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { Server } from "node:net";
import { loadConfig } from "../config.js";
import { computeCheckSpecHash } from "../commitgate/trusted-check-bundle.js";
import { buildWorkerManifest } from "../transition-worker/filesystem.js";
import type { RunnerRequest } from "../types.js";
import {
  RuntimeBrokerRunner,
  VERIFIER_RPC_TEARDOWN_GRACE_MS,
  verifierRpcTimeoutMs,
} from "./client.js";
import type { RuntimeBrokerDispatch } from "./contracts.js";
import {
  RuntimeBroker,
  startRuntimeBrokerRpc,
  validateBrokerRunRequest,
  validateBrokerWorkspaceIdentity,
} from "./server.js";
import { brokerRunRequestSchema } from "./contracts.js";
import { signBrokerAttestation } from "./attestation.js";
import { BrokerLifecycleLedger } from "./lifecycle-ledger.js";

const attestationKey =
  "broker-attestation-secret-that-is-at-least-32-bytes";

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

describe("runtime broker Unix RPC", () => {
  it("keeps verifier RPC alive for the global budget plus teardown grace", async () => {
    expect(verifierRpcTimeoutMs(30_000)).toBe(
      30_000 + VERIFIER_RPC_TEARDOWN_GRACE_MS,
    );
    expect(() => verifierRpcTimeoutMs(999)).toThrow(
      expect.objectContaining({ code: "BROKER_VERIFIER_TIMEOUT_INVALID" }),
    );

    const client = new RuntimeBrokerRunner("/unused");
    let observedTimeout: number | undefined;
    (client as unknown as {
      rpc: { request(request: unknown, timeoutMs?: number): Promise<unknown> };
    }).rpc = {
      async request(_request, timeoutMs) {
        observedTimeout = timeoutMs;
        return { checks: [], environment: {} };
      },
    };
    await client.runVerifier({
      runId: "run",
      agentId: "agent",
      runLeaseId: "lease",
      sessionEpoch: 0,
      proposalId: "proposal",
      verifierInputHash: "a".repeat(64),
      checkSpecHash: "b".repeat(64),
      workspaceRef: {
        volumeId: "verify-run",
        relativeSubpath: "verify-run",
        runId: "run",
        agentId: "agent",
      },
      checks: [{
        id: "check",
        runner: "node",
        entrypoint: "check.mjs",
        args: [],
        timeoutMs: 30_000,
        scratchBytes: 1_048_576,
      }],
      timeoutMs: 30_000,
      maxOutputBytes: 65_536,
    });
    expect(observedTimeout).toBe(60_000);
  });

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
      runLeaseId: "lease",
      sessionEpoch: 0,
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
          attestation: signBrokerAttestation({
            schemaVersion: 1 as const,
            kind: "verifier-result" as const,
            scope: "VERIFIER" as const,
            runId: "run",
            agentId: "agent",
            runLeaseId: "lease",
            sessionEpoch: 0,
            proposalId: "proposal",
            verifierInputHash: "a".repeat(64),
            checkSpecHash: "b".repeat(64),
            checkResultsHash: "c".repeat(64),
            coverage: "unavailable" as const,
            checks: [],
            environment: {
              checkBundleHash: "b".repeat(64),
              verifierImageDigest: "sha256:image",
              verifierConfigHash: "a".repeat(64),
              resourcePolicyHash: "d".repeat(64),
              sourceRevision: "revision",
            },
          }, attestationKey),
        };
      },
      async cancel(agentId, cancellation) {
        return agentId === "agent" && cancellation.runId === "run";
      },
      async teardown(request) {
        return signBrokerAttestation({
          schemaVersion: 1 as const,
          kind: "runtime-teardown" as const,
          ...request,
          containerExited: true as const,
          containerRemoved: true as const,
          mountsReleased: true as const,
          source: "runtime-attestation" as const,
        }, attestationKey);
      },
      async reconcile(request) {
        return signBrokerAttestation({
          schemaVersion: 1 as const,
          kind: "runtime-teardown" as const,
          ...request,
          containerExited: true as const,
          containerRemoved: true as const,
          mountsReleased: true as const,
          source: "broker-reconciliation" as const,
        }, attestationKey);
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
    await expect(client.attestCommitGateTeardown({
      runId: "run",
      agentId: "agent",
      runLeaseId: "lease",
      sessionEpoch: 0,
      scope: "ALL",
    })).resolves.toMatchObject({
      containerExited: true,
      mountsReleased: true,
    });
    await expect(client.reconcileCommitGateRuntime({
      runId: "run",
      agentId: "agent",
      runLeaseId: "lease",
      sessionEpoch: 0,
      scope: "ALL",
    })).resolves.toMatchObject({ source: "broker-reconciliation", mountsReleased: true });
    expect((await stat(socketPath)).mode & 0o777).toBe(0o660);
  });

  it("cancels the verifier container by the same bound runId", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-broker-verifier-cancel-"));
    const exchangeRoot = path.join(root, "exchange");
    await mkdir(path.join(exchangeRoot, "verify-run"), { recursive: true });
    const config = loadConfig({
      NODE_ENV: "test",
      COMMITGATE_ENABLED: "true",
      TRANSITION_AUTHORITY: "worker",
      RUNTIME_PROVIDER: "broker",
      COMMITGATE_EXCHANGE_ROOT: exchangeRoot,
      CODEX_HOME: path.join(root, "sessions"),
    });
    const broker = new RuntimeBroker(config);
    const binding = {
      runId: "run",
      agentId: "agent",
      runLeaseId: "lease",
      sessionEpoch: 0,
    };
    const lifecycle = new BrokerLifecycleLedger(
      path.join(config.commitGateSessionVolumeRoot, ".runtime-broker-ledger"),
    );
    await lifecycle.beginAgent(binding);
    await lifecycle.markAgentClosed(binding);
    let verifierStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      verifierStarted = resolve;
    });
    const internals = broker as unknown as {
      runner: {
        cancel(agentId: string, cancellation: unknown): Promise<boolean>;
        isAvailable(): Promise<boolean>;
      };
      verifier: {
        describeExecutionEnvironment(runId: string): Promise<Record<string, string>>;
        run(input: { signal?: AbortSignal }): Promise<never>;
      };
    };
    internals.runner = {
      async cancel() { return false; },
      async isAvailable() { return true; },
    };
    internals.verifier = {
      async describeExecutionEnvironment() {
        return {
          imageReference: "runtime",
          imageId: "sha256:image",
          imageDigest: "a".repeat(64),
          configHash: "b".repeat(64),
          checkBundleHash: "c".repeat(64),
          resourcePolicyHash: "d".repeat(64),
          sourceRevision: "revision",
        };
      },
      async run(input) {
        verifierStarted();
        return await new Promise<never>((_resolve, reject) => {
          input.signal?.addEventListener(
            "abort",
            () => reject(input.signal?.reason ?? new Error("aborted")),
            { once: true },
          );
        });
      },
    };
    const verifierChecks = [{
      id: "contract",
      runner: "node" as const,
      entrypoint: "check.mjs",
      args: [],
      timeoutMs: 10_000,
      scratchBytes: 1_048_576,
    }];
    const verifying = broker.runVerifier({
      runId: "run",
      agentId: "agent",
      runLeaseId: "lease",
      sessionEpoch: 0,
      proposalId: "proposal-run",
      verifierInputHash: (await buildWorkerManifest(
        path.join(exchangeRoot, "verify-run"),
      )).hash,
      checkSpecHash: computeCheckSpecHash(verifierChecks),
      workspaceRef: {
        volumeId: "verify-run",
        relativeSubpath: "verify-run",
        runId: "run",
        agentId: "agent",
      },
      checks: verifierChecks,
      timeoutMs: 30_000,
      maxOutputBytes: 65_536,
    });
    await started;
    await expect(broker.cancel("agent", {
      runId: "run",
      runLeaseId: "lease",
      sessionEpoch: 0,
    })).resolves.toBe(true);
    await expect(verifying).rejects.toMatchObject({ name: "RunCancelledError" });
    expect((await broker.health()).activeRuns).toBe(0);
  });

  it("returns formal verifier teardown and closes all known run containers", async () => {
    const config = loadConfig({ NODE_ENV: "test", RUNTIME_PROVIDER: "broker" });
    const broker = new RuntimeBroker(config);
    const internals = broker as unknown as {
      runner: {
        hasCommitGateTeardown(runId: string): boolean;
        attestCommitGateTeardown(runId: string): Promise<{
          containerExited: boolean;
          containerRemoved: boolean;
          mountsReleased: boolean;
        }>;
      };
      verifier: {
        attestCommitGateTeardown(runId: string): Promise<{
          containerExited: boolean;
          containerRemoved: boolean;
          mountsReleased: boolean;
        } | null>;
      };
    };
    internals.runner = {
      hasCommitGateTeardown: (runId) => runId === "combined",
      async attestCommitGateTeardown(_runId) {
        return {
          containerExited: true,
          containerRemoved: true,
          mountsReleased: true,
        };
      },
    };
    internals.verifier = {
      async attestCommitGateTeardown(runId) {
        if (runId === "unknown") return null;
        return {
          containerExited: true,
          containerRemoved: runId !== "combined",
          mountsReleased: true,
        };
      },
    };

    await expect(broker.teardown({
      runId: "verifier-only",
      agentId: "agent",
      runLeaseId: "lease",
      sessionEpoch: 0,
      scope: "ALL",
    })).resolves.toMatchObject({
      schemaVersion: 1,
      kind: "runtime-teardown",
      containerExited: true,
      containerRemoved: true,
      mountsReleased: true,
      brokerAttestation: {
        algorithm: "HMAC-SHA256",
        mac: expect.stringMatching(/^[a-f0-9]{64}$/),
      },
    });
    await expect(broker.teardown({
      runId: "combined",
      agentId: "agent",
      runLeaseId: "lease",
      sessionEpoch: 0,
      scope: "ALL",
    })).rejects.toThrow(/BROKER_RUNTIME_TEARDOWN_INCOMPLETE/);
  });

  it("rediscovers and force-removes a labeled orphan before attesting mount release", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-broker-orphan-"));
    const engine = path.join(root, "fake-engine.mjs");
    const state = path.join(root, "orphan-present");
    const log = path.join(root, "engine-args.log");
    await writeFile(state, "present\n");
    await writeFile(engine, [
      "#!/usr/bin/env node",
      'import { appendFile, readFile, rm } from "node:fs/promises";',
      `const state = ${JSON.stringify(state)};`,
      `const log = ${JSON.stringify(log)};`,
      "await appendFile(log, JSON.stringify(process.argv.slice(2)) + '\\n');",
      "const args = process.argv.slice(2);",
      "if (args[0] === 'container' && args[1] === 'ls') {",
      "  const verifier = args.includes('label=io.commitgate.runtime=verifier');",
      "  if (verifier) { try { await readFile(state); process.stdout.write('a'.repeat(64) + '\\n'); } catch {} }",
      "  process.exit(0);",
      "}",
      "if (args[0] === 'rm' && args[1] === '--force') { await rm(state, { force: true }); process.exit(0); }",
      "process.exit(1);",
      "",
    ].join("\n"));
    await chmod(engine, 0o700);
    try {
      const broker = new RuntimeBroker(loadConfig({
        NODE_ENV: "test",
        PROCESS_ROLE: "runtime-broker",
        RUNTIME_PROVIDER: "container",
        CONTAINER_ENGINE: engine,
        RUNTIME_INSTANCE_ID: "restart-fixture",
      }));
      await expect(broker.reconcile({
        runId: "run-orphan",
        agentId: "agent-orphan",
        runLeaseId: "lease-orphan",
        sessionEpoch: 7,
        scope: "ALL",
      })).resolves.toMatchObject({
        schemaVersion: 1,
        kind: "runtime-teardown",
        runId: "run-orphan",
        agentId: "agent-orphan",
        runLeaseId: "lease-orphan",
        sessionEpoch: 7,
        scope: "ALL",
        containerExited: true,
        containerRemoved: true,
        mountsReleased: true,
        source: "broker-reconciliation",
        brokerAttestation: {
          algorithm: "HMAC-SHA256",
          mac: expect.stringMatching(/^[a-f0-9]{64}$/),
        },
      });
      const calls = await readFile(log, "utf8");
      expect(calls).toContain("label=io.commitgate.run-id=run-orphan");
      expect(calls).toContain("label=io.commitgate.run-lease-id=lease-orphan");
      expect(calls).toContain("label=io.commitgate.session-epoch=7");
      await expect(readFile(state, "utf8")).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("fails closed when a bound orphan survives force removal", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-broker-stuck-orphan-"));
    const engine = path.join(root, "fake-engine.mjs");
    await writeFile(engine, [
      "#!/usr/bin/env node",
      "const args = process.argv.slice(2);",
      "if (args[0] === 'container' && args[1] === 'ls') { process.stdout.write('b'.repeat(64) + '\\n'); process.exit(0); }",
      "if (args[0] === 'rm' && args[1] === '--force') process.exit(0);",
      "process.exit(1);",
      "",
    ].join("\n"));
    await chmod(engine, 0o700);
    try {
      const broker = new RuntimeBroker(loadConfig({
        NODE_ENV: "test",
        PROCESS_ROLE: "runtime-broker",
        RUNTIME_PROVIDER: "container",
        CONTAINER_ENGINE: engine,
        RUNTIME_INSTANCE_ID: "restart-fixture",
      }));
      await expect(broker.reconcile({
        runId: "run-stuck",
        agentId: "agent-stuck",
        runLeaseId: "lease-stuck",
        sessionEpoch: 3,
        scope: "ALL",
      })).rejects.toThrow("BROKER_RECONCILIATION_INCOMPLETE");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 15_000);

  it("rejects reconciliation for a binding with no durable launch record", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-broker-unseen-binding-"));
    try {
      const broker = new RuntimeBroker(loadConfig({
        NODE_ENV: "test",
        PROCESS_ROLE: "runtime-broker",
        RUNTIME_PROVIDER: "container",
        TRANSITION_AUTHORITY: "worker",
        COMMITGATE_EXCHANGE_ROOT: path.join(root, "exchange"),
        CODEX_HOME: path.join(root, "sessions"),
      }));
      await expect(broker.reconcile({
        runId: "never-launched",
        agentId: "agent",
        runLeaseId: "lease",
        sessionEpoch: 0,
        scope: "ALL",
      })).rejects.toThrow("BROKER_RUNTIME_BINDING_UNKNOWN");
      await expect(broker.teardown({
        runId: "never-launched",
        agentId: "agent",
        runLeaseId: "lease",
        sessionEpoch: 0,
        scope: "AGENT",
      })).rejects.toThrow("BROKER_RUNTIME_BINDING_UNKNOWN");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
