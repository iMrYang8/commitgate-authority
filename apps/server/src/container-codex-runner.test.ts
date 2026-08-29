import { describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";
import {
  assertInternalAgentNetworkInspection,
  BOUNDED_ROOT_IGNORED_PATHS,
  buildContainerRunArgs,
  buildWorkerSessionCleanupArgs,
  containerProcessCwd,
  ContainerCodexRunner,
  containerName,
} from "./container-codex-runner.js";
import { codexConfigPath, codexSessionHome } from "./model-provider.js";

describe("Container Codex runner", () => {
  it("builds an isolated Docker/Podman-compatible invocation", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      ARK_API_KEY: "secret-that-must-not-appear-in-argv",
      ARK_MODEL: "ep-test",
      CODEX_HOME: "/tmp/codex-home",
      RUNTIME_PROVIDER: "container",
      CONTAINER_ENGINE: "podman",
      CONTAINER_RUNTIME_IMAGE: "runtime:test",
      CONTAINER_USER: "501:20",
      RUNTIME_INSTANCE_ID: "test-instance",
    });
    const args = buildContainerRunArgs(
      {
        runId: "run-1",
        agentId: "agent/unsafe",
        workspacePath: "/tmp/agent-workspace",
        prompt: "write a small program",
        threadId: null,
        sessionEpoch: 4,
      },
      config,
    );

    expect(containerName("agent/unsafe", "test-instance")).toBe(
      "launchpad-test-instance-agent-unsafe",
    );
    expect(args).toContain("runtime:test");
    expect(args).toContain("type=bind,src=/tmp/agent-workspace,dst=/workspace");
    expect(args).toContain(
      "type=bind,src=" + codexSessionHome(config, "agent/unsafe", 4) + ",dst=/codex-home",
    );
    expect(args).toContain(
      "type=bind,src=" + codexConfigPath(config) + ",dst=/codex-home/config.toml,readonly",
    );
    expect(args).not.toContain("type=bind,src=/tmp/codex-home,dst=/codex-home");
    expect(args).toContain("501:20");
    expect(args).toContain("workspace-write");
    expect(args).toContain("--read-only");
    expect(args).toContain(
      "/scratch:rw,nosuid,nodev,size=268435456,nr_inodes=8192",
    );
    expect(args).toContain("/tmp:rw,nosuid,nodev,size=67108864,nr_inodes=2048");
    expect(args.join(" ")).toContain("/workspace/node_modules:rw,nosuid,nodev");
    expect(args.join(" ")).toContain("/workspace/.git:rw,nosuid,nodev");
    expect(args.join(" ")).toContain("/workspace/.codex:rw,nosuid,nodev");
    expect(args.join(" ")).toContain("/workspace/dist:rw,nosuid,nodev");
    expect(args.join(" ")).toContain("/workspace/coverage:rw,nosuid,nodev");
    expect(args).toContain("HOME=/scratch");
    expect(args).toContain("TMPDIR=/scratch");
    expect(args).toContain("NPM_CONFIG_CACHE=/scratch/cache/npm");
    expect(args).toContain("PIP_CACHE_DIR=/scratch/cache/pip");
    expect(args).toContain("/workspace");
    expect(args).toContain("io.commitgate.instance-id=test-instance");
    expect(args).toContain("keep-id");
    expect(args).toContain("MODEL_API_KEY");
    expect(args).not.toContain("ARK_API_KEY");
    expect(args).not.toContain("APP_AUTH_TOKEN");
    expect(args.join(" ")).not.toMatch(/docker\.sock|dst=\/workspace-root|dst=\/control/);
    expect(args).not.toContain("secret-that-must-not-appear-in-argv");

    const withAttestation = buildContainerRunArgs(
      {
        runId: "run-1",
        agentId: "agent/unsafe",
        workspacePath: "/tmp/agent-workspace",
        prompt: "write a small program",
        threadId: null,
        sessionEpoch: 4,
      },
      config,
      { cidFile: "/tmp/private-attest/run.cid" },
    );
    expect(withAttestation).toContain("--cidfile");
    expect(withAttestation).toContain("/tmp/private-attest/run.cid");
    expect(withAttestation.join(" ")).not.toContain("dst=/tmp/private-attest");
  });

  it("fails closed against scratch byte and file-count DoS with kernel tmpfs quotas", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      RUNTIME_PROVIDER: "container",
      CONTAINER_AGENT_SCRATCH_BYTES: "1048576",
      CONTAINER_AGENT_SCRATCH_FILES: "128",
      CONTAINER_AGENT_IGNORED_BYTES: "5242880",
      CONTAINER_AGENT_IGNORED_FILES: "640",
    });
    const args = buildContainerRunArgs(
      {
        runId: "scratch-dos",
        agentId: "agent",
        workspacePath: "/tmp/workspace",
        prompt: "run",
        threadId: null,
      },
      config,
    );
    expect(args).toContain(
      "/scratch:rw,nosuid,nodev,size=1048576,nr_inodes=128",
    );
    expect(BOUNDED_ROOT_IGNORED_PATHS).toEqual([
      ".git",
      ".codex",
      "node_modules",
      "dist",
      "coverage",
    ]);
    for (const relative of BOUNDED_ROOT_IGNORED_PATHS) {
      expect(args).toContain(
        `/workspace/${relative}:rw,nosuid,nodev,size=1048576,nr_inodes=128`,
      );
    }
    expect(args).toContain("--read-only");
  });

  it("requires the configured production relay network to be engine-reported internal", () => {
    expect(() =>
      assertInternalAgentNetworkInspection(
        JSON.stringify([{ Name: "commitgate-model-internal", Internal: true }]),
        "commitgate-model-internal",
      ),
    ).not.toThrow();
    expect(() =>
      assertInternalAgentNetworkInspection(
        JSON.stringify([{ Name: "commitgate-model-internal", Internal: false }]),
        "commitgate-model-internal",
      ),
    ).toThrow(/must be the configured.*internal network/i);
    expect(() =>
      assertInternalAgentNetworkInspection(
        JSON.stringify([{ Name: "other", Internal: true }]),
        "commitgate-model-internal",
      ),
    ).toThrow(/must be the configured.*internal network/i);
  });

  it("does not claim teardown evidence for an unknown run", async () => {
    const config = loadConfig({ NODE_ENV: "test", RUNTIME_PROVIDER: "container" });
    await expect(
      new ContainerCodexRunner(config).attestCommitGateTeardown("missing"),
    ).resolves.toEqual({
      containerExited: false,
      containerRemoved: false,
      mountsReleased: false,
    });
  });

  it("rejects a caller binding that differs from the completed Runtime run", async () => {
    const config = loadConfig({ NODE_ENV: "test", RUNTIME_PROVIDER: "container" });
    const runner = new ContainerCodexRunner(config);
    const internals = runner as unknown as {
      completedTeardowns: Map<string, unknown>;
    };
    internals.completedTeardowns.set("bound-run", {
      containerName: "bound-container",
      binding: {
        runId: "bound-run",
        agentId: "agent-a",
        runLeaseId: "lease-a",
        sessionEpoch: 3,
      },
      containerExited: true,
      containerRemoved: true,
      mountsReleased: true,
    });

    await expect(runner.attestCommitGateTeardown("bound-run", {
      runId: "bound-run",
      agentId: "agent-a",
      runLeaseId: "forged-lease",
      sessionEpoch: 3,
    })).rejects.toThrow("BROKER_RUNTIME_TEARDOWN_BINDING_MISMATCH");
  });

  it("resumes a thread inside the mounted Runtime workspace", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      CODEX_HOME: "/tmp/codex-home",
      RUNTIME_PROVIDER: "container",
    });
    const args = buildContainerRunArgs(
      {
        runId: "run-2",
        agentId: "agent",
        workspacePath: "/tmp/workspace",
        prompt: "continue",
        threadId: "thread-123",
      },
      config,
    );
    expect(args.slice(-3)).toEqual(["resume", "thread-123", "continue"]);
    expect(args).not.toContain("keep-id");
  });

  it("supports a relay-only internal network without passing upstream credentials", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      CODEX_HOME: "/tmp/codex-home",
      RUNTIME_PROVIDER: "container",
      MODEL_PROVIDER: "openrouter",
      MODEL_ID: "deepseek/deepseek-v4-flash",
      MODEL_API_KEY: "upstream-secret",
      MODEL_ACCESS_MODE: "relay",
      MODEL_RELAY_URL: "http://model-relay:8080/v1",
      MODEL_RELAY_TOKEN: "relay-signing-secret-that-is-at-least-32-bytes",
      CONTAINER_AGENT_NETWORK: "commitgate-model-internal",
    });
    const args = buildContainerRunArgs(
      {
        runId: "run-relay",
        agentId: "agent",
        workspacePath: "/tmp/workspace",
        prompt: "continue",
        threadId: null,
        sessionEpoch: 2,
      },
      config,
    );

    expect(args).toContain("commitgate-model-internal");
    expect(args).toContain("HTTP_PROXY=");
    expect(args).toContain("HTTPS_PROXY=");
    expect(args).toContain("ALL_PROXY=");
    expect(args).toContain("NO_PROXY=*");
    expect(args).not.toContain("upstream-secret");
    expect(args).not.toContain("relay-signing-secret-that-is-at-least-32-bytes");
    expect(args).not.toContain("host");
  });

  it("mounts only fixed Worker-owned volume subpaths for opaque workspaces and sessions", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      CODEX_HOME: "/var/lib/commitgate/sessions",
      COMMITGATE_EXCHANGE_ROOT: "/var/lib/commitgate/exchange",
      COMMITGATE_SESSION_VOLUME_ROOT: "/var/lib/commitgate/sessions",
      COMMITGATE_SESSION_VOLUME: "commitgate-sessions",
      COMMITGATE_EXCHANGE_VOLUME: "commitgate-exchange",
      RUNTIME_PROVIDER: "container",
      TRANSITION_AUTHORITY: "worker",
    });
    const args = buildContainerRunArgs({
      runId: "run-opaque",
      agentId: "agent-a",
      workspacePath: "/var/lib/commitgate/exchange/candidate-run-opaque",
      workspaceRef: {
        volumeId: "candidate-run-opaque",
        relativeSubpath: "candidate-run-opaque",
        runId: "run-opaque",
        agentId: "agent-a",
      },
      prompt: "continue",
      threadId: null,
      sessionEpoch: 3,
    }, config);
    const joined = args.join("\n");
    expect(joined).toContain(
      "type=volume,src=commitgate-exchange,dst=/workspace,volume-subpath=candidate-run-opaque",
    );
    expect(joined).toContain("type=volume,src=commitgate-sessions,dst=/codex-home,volume-subpath=sessions/");
    expect(joined).toContain(
      "type=volume,src=commitgate-sessions,dst=/codex-home/config.toml,readonly,volume-subpath=config.toml",
    );
    expect(joined).not.toContain("type=bind,src=/var/lib/commitgate");
    expect(containerProcessCwd({
      workspacePath: "/var/lib/commitgate/exchange/candidate-run-opaque",
      workspaceRef: {
        volumeId: "candidate-run-opaque",
        relativeSubpath: "candidate-run-opaque",
        runId: "run-opaque",
        agentId: "agent-a",
      },
    }, config)).toBe("/var/lib/commitgate/exchange");
    expect(containerProcessCwd({
      workspacePath: "/tmp/legacy-candidate",
    }, config)).toBe("/tmp/legacy-candidate");
    const cleanup = buildWorkerSessionCleanupArgs({
      agentId: "agent-a",
      sessionEpoch: 3,
      workspaceRef: {
        volumeId: "candidate-run-opaque",
        relativeSubpath: "candidate-run-opaque",
        runId: "run-opaque",
        agentId: "agent-a",
      },
    }, config, "epoch-2", "10001:20000");
    expect(cleanup.join("\n")).toContain(
      "type=volume,src=commitgate-sessions,dst=/session-agent,volume-subpath=sessions/",
    );
    expect(cleanup.slice(-4)).toEqual(["rm", "-rf", "--", "/session-agent/epoch-2"]);
    expect(cleanup.join("\n")).not.toMatch(/authority|control|docker\.sock/);
  });
});
