import { spawn } from "node:child_process";
import { EventEmitter } from "node:events";
import {
  link,
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { PassThrough } from "node:stream";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  buildVerifierContainerArgs,
  DockerVerifierRunner,
  hashTrustedCheckBundle,
  VerifierRunBudget,
  verifierConfigHash,
  verifierResourcePolicyHash,
} from "./verifier-runner.js";
import {
  describeTrustedCheckBundle,
  hashSealedTrustedCheckBundleSource,
  TrustedCheckBundleStore,
} from "./trusted-check-bundle.js";
import type { VerifierInput } from "./types.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map(async (root) => {
      await makeWritable(root).catch(() => undefined);
      await rm(root, { recursive: true, force: true });
    }),
  );
});

async function makeWritable(root: string): Promise<void> {
  await chmod(root, 0o700);
  const entries = await readdir(root, { withFileTypes: true });
  for (const entry of entries) {
    const item = path.join(root, entry.name);
    if (entry.isDirectory()) await makeWritable(item);
    else await chmod(item, 0o600);
  }
}

async function tempRoot(): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), "commitgate-verifier-"));
  roots.push(root);
  return root;
}

function input(overrides: Partial<VerifierInput> = {}): VerifierInput {
  return {
    runId: "run",
    agentId: "agent",
    verifyPath: "/tmp/verify",
    trustedChecksPath: "/tmp/checks",
    checks: [],
    timeoutMs: 30_000,
    maxOutputBytes: 65_536,
    ...overrides,
  };
}

const verifierConfig = {
  engine: "docker",
  image: "runtime:test",
  cpuLimit: 1,
  memoryLimit: "512m",
  pidsLimit: 64,
  user: "1000:1000",
};

describe("Docker verifier isolation", () => {
  it("mounts an immutable proposal and checks bundle with an isolated scratch", () => {
    const args = buildVerifierContainerArgs(
      input(),
      {
        id: "contract",
        runner: "node",
        entrypoint: "test.mjs",
        args: [],
        timeoutMs: 10_000,
        scratchBytes: 1_048_576,
      },
      verifierConfig,
    );
    expect(args).toContain("none");
    expect(args).toContain("--read-only");
    expect(args).toContain("no-new-privileges");
    expect(args).toContain("ALL");
    expect(args.join(" ")).toContain("dst=/proposal,readonly");
    expect(args.join(" ")).toContain("dst=/checks,readonly");
    expect(args.join(" ")).toContain(
      "/scratch:rw,nosuid,nodev,size=1048576,nr_inodes=4096",
    );
    expect(args).toContain("/proposal");
    expect(args).toContain("/usr/bin/env");
    expect(args).toContain("-i");
    expect(args).toContain("HOME=/scratch");
    expect(args.join(" ")).not.toMatch(
      /ARK_API_KEY|MODEL_API_KEY|OPENAI_API_KEY|CODEX_HOME|dst=\/workspace|--network bridge/,
    );
    expect(args.slice(-2)).toEqual(["node", "/checks/test.mjs"]);
  });

  it("uses fixed named-volume subpaths for Broker-owned verifier inputs", () => {
    const args = buildVerifierContainerArgs(
      input({
        runId: "run",
        agentId: "agent",
        verifyPath: "/exchange/verify-run",
        trustedChecksPath: "/trusted/store/payloads/bundle-hash",
        workspaceRef: {
          volumeId: "verify-run",
          relativeSubpath: "verify-run",
          runId: "run",
          agentId: "agent",
        },
      }),
      {
        id: "contract",
        runner: "node",
        entrypoint: "test.mjs",
        args: [],
        timeoutMs: 10_000,
        scratchBytes: 1_048_576,
      },
      {
        ...verifierConfig,
        proposalVolume: "commitgate-exchange",
        trustedChecksVolume: "commitgate-trusted-checks",
        trustedChecksVolumeRoot: "/trusted",
      },
    );
    expect(args).toContain(
      "type=volume,src=commitgate-exchange,dst=/proposal,readonly,volume-subpath=verify-run",
    );
    expect(args).toContain(
      "type=volume,src=commitgate-trusted-checks,dst=/checks,readonly,volume-subpath=store/payloads/bundle-hash",
    );
    expect(args.join(" ")).not.toContain("type=bind,src=/exchange");
  });

  it("keeps bundled trusted-check defaults aligned with the proposal mount", async () => {
    const args = buildVerifierContainerArgs(
      input(),
      {
        id: "contract",
        runner: "node",
        entrypoint: "test.mjs",
        args: [],
        timeoutMs: 10_000,
        scratchBytes: 1_048_576,
      },
      verifierConfig,
    );
    const proposalMount = args.find((argument) =>
      argument.includes("dst=/proposal,readonly"),
    );
    expect(proposalMount).toBeDefined();
    expect(args[args.indexOf("--workdir") + 1]).toBe("/proposal");

    for (const fixture of ["workspace-contract.mjs", "workspace-sanity.mjs"]) {
      const source = await readFile(
        new URL(`../../../../eval/trusted-checks/${fixture}`, import.meta.url),
        "utf8",
      );
      expect(source).toContain(
        'process.env.COMMITGATE_CANDIDATE_ROOT || "/proposal"',
      );
      expect(source).not.toContain(
        'process.env.COMMITGATE_CANDIDATE_ROOT || "/candidate"',
      );
    }
  });

  it("fails closed before spawning when a protected run has no trusted check", async () => {
    const runner = new DockerVerifierRunner(verifierConfig);
    await expect(runner.run(input())).rejects.toThrow(/at least one trusted check/);
  });

  it("rejects candidate-controlled and shell-wrapped check entrypoints", () => {
    expect(() =>
      buildVerifierContainerArgs(
        input(),
        {
          id: "candidate",
          runner: "node",
          entrypoint: "../proposal/test.mjs",
          args: [],
          timeoutMs: 10_000,
          scratchBytes: 1_048_576,
        },
        verifierConfig,
      ),
    ).toThrow(/invalid entrypoint/);
    expect(() =>
      buildVerifierContainerArgs(
        input(),
        {
          id: "shell",
          runner: "shell" as "node",
          entrypoint: "test.mjs",
          args: ["-c"],
          timeoutMs: 10_000,
          scratchBytes: 1_048_576,
        },
        verifierConfig,
      ),
    ).toThrow(/unsupported runner/);
  });

  it("accounts timeout and output across the whole verifier run", () => {
    const budget = new VerifierRunBudget(1_000, 10, 5_000);
    expect(budget.remainingTimeMs(5_400)).toBe(600);
    expect(budget.consumeOutput(7)).toBe(7);
    expect(budget.remainingOutputBytes()).toBe(3);
    expect(budget.consumeOutput(8)).toBe(3);
    expect(budget.outputExceeded()).toBe(true);
    expect(budget.remainingOutputBytes()).toBe(0);
  });

  it("binds actual image identity, verifier config, resources and check content", async () => {
    const root = await tempRoot();
    const source = path.join(root, "source");
    const store = path.join(root, "store");
    await mkdir(source);
    await writeFile(path.join(source, "check.mjs"), "console.log('trusted');\n");
    const config = {
      ...verifierConfig,
      trustedChecksPath: source,
      trustedCheckStorePath: store,
      scratchBytes: 1_048_576,
      runTimeoutMs: 8_000,
      maxOutputBytes: 4_096,
      sourceRevision: "revision-test",
    };
    const runner = new DockerVerifierRunner(config, {
      inspectImage: async () => ({
        imageId: "sha256:image-id",
        imageDigest: "sha256:repo-digest",
      }),
    });
    const sealed = await new TrustedCheckBundleStore(source, store).seal();

    await expect(runner.describeExecutionEnvironment()).resolves.toEqual({
      imageReference: "runtime:test",
      imageId: "sha256:image-id",
      imageDigest: "sha256:repo-digest",
      configHash: verifierConfigHash(config),
      checkBundleHash: sealed.hash,
      resourcePolicyHash: verifierResourcePolicyHash(config),
      sourceRevision: "revision-test",
    });
  });

  it("mounts the exact sealed bundle bound to the run after the live source changes", async () => {
    const root = await tempRoot();
    const source = path.join(root, "source");
    const store = path.join(root, "sealed-store");
    await mkdir(source);
    await writeFile(path.join(source, "check.mjs"), "original trusted check\n");
    const invocations: string[][] = [];
    const fakeSpawn = ((_command: string, args: readonly string[]) => {
      invocations.push([...args]);
      const child = new EventEmitter() as EventEmitter & {
        stdout: PassThrough;
        stderr: PassThrough;
        kill: () => boolean;
      };
      child.stdout = new PassThrough();
      child.stderr = new PassThrough();
      child.kill = () => true;
      queueMicrotask(() => child.emit("close", 0));
      return child;
    }) as unknown as typeof spawn;
    const runner = new DockerVerifierRunner(
      {
        ...verifierConfig,
        trustedChecksPath: source,
        trustedCheckStorePath: store,
      },
      {
        inspectImage: async () => ({
          imageId: "sha256:image-id",
          imageDigest: "sha256:image-digest",
        }),
        spawnProcess: fakeSpawn,
        inspectContainerRemoved: async () => true,
      },
    );
    const environment = await runner.describeExecutionEnvironment("bound-run");
    const sealedPath = path.join(store, "payloads", environment.checkBundleHash);

    await writeFile(path.join(source, "check.mjs"), "mutated live source\n");
    await expect(
      runner.run(
        input({
          runId: "bound-run",
          trustedChecksPath: source,
          checkBundleHash: environment.checkBundleHash,
          checks: [
            {
              id: "contract",
              runner: "node",
              entrypoint: "check.mjs",
              args: [],
              timeoutMs: 10_000,
              scratchBytes: 1_048_576,
            },
          ],
        }),
      ),
    ).resolves.toMatchObject([{ id: "contract", status: "PASS" }]);
    await expect(runner.attestCommitGateTeardown("bound-run")).resolves.toEqual({
      containerExited: true,
      containerRemoved: true,
      mountsReleased: true,
    });
    await expect(runner.attestCommitGateTeardown("bound-run", {
      runId: "bound-run",
      agentId: "agent",
      runLeaseId: "forged-lease",
      sessionEpoch: 0,
    })).rejects.toThrow("BROKER_VERIFIER_TEARDOWN_BINDING_MISMATCH");

    expect(invocations).toHaveLength(1);
    expect(invocations[0]?.join(" ")).toContain(
      `type=bind,src=${sealedPath},dst=/checks,readonly`,
    );
    expect(await readFile(path.join(sealedPath, "check.mjs"), "utf8")).toBe(
      "original trusted check\n",
    );
    expect((await stat(path.join(sealedPath, "check.mjs"))).mode & 0o222).toBe(0);
    await expect(runner.describeExecutionEnvironment("bound-run")).resolves.toEqual(
      environment,
    );
    const laterEnvironment = await runner.describeExecutionEnvironment("later-run");
    expect(laterEnvironment.checkBundleHash).not.toBe(environment.checkBundleHash);
  });

  it("classifies a signal-range container exit as infrastructure ERROR, not policy FAIL", async () => {
    const root = await tempRoot();
    const source = path.join(root, "source");
    const store = path.join(root, "sealed-store");
    await mkdir(source);
    await writeFile(path.join(source, "check.mjs"), "setInterval(() => undefined, 1000);\n");
    const fakeSpawn = (() => {
      const child = new EventEmitter() as EventEmitter & {
        stdout: PassThrough;
        stderr: PassThrough;
        kill: () => boolean;
      };
      child.stdout = new PassThrough();
      child.stderr = new PassThrough();
      child.kill = () => true;
      queueMicrotask(() => child.emit("close", 137));
      return child;
    }) as unknown as typeof spawn;
    const runner = new DockerVerifierRunner(
      {
        ...verifierConfig,
        trustedChecksPath: source,
        trustedCheckStorePath: store,
      },
      {
        inspectImage: async () => ({
          imageId: "sha256:image-id",
          imageDigest: "sha256:image-digest",
        }),
        spawnProcess: fakeSpawn,
        inspectContainerRemoved: async () => true,
      },
    );

    await expect(
      runner.run(
        input({
          runId: "externally-killed-verifier",
          trustedChecksPath: source,
          checks: [{
            id: "contract",
            runner: "node",
            entrypoint: "check.mjs",
            args: [],
            timeoutMs: 10_000,
            scratchBytes: 1_048_576,
          }],
        }),
      ),
    ).resolves.toMatchObject([{
      id: "contract",
      status: "ERROR",
      exitCode: 137,
      timedOut: false,
      output: expect.stringContaining("[VERIFIER_CONTAINER_UNEXPECTED_EXIT:137]"),
    }]);
    await expect(
      runner.attestCommitGateTeardown("externally-killed-verifier"),
    ).resolves.toEqual({
      containerExited: true,
      containerRemoved: true,
      mountsReleased: true,
    });
  });

  it("rejects a context hash that does not name the run's sealed bundle", async () => {
    const root = await tempRoot();
    const source = path.join(root, "source");
    const store = path.join(root, "store");
    await mkdir(source);
    await writeFile(path.join(source, "check.mjs"), "trusted\n");
    const runner = new DockerVerifierRunner(
      {
        ...verifierConfig,
        trustedChecksPath: source,
        trustedCheckStorePath: store,
      },
      {
        inspectImage: async () => ({
          imageId: "sha256:image-id",
          imageDigest: "sha256:image-digest",
        }),
      },
    );
    await runner.describeExecutionEnvironment("hash-mismatch");
    await expect(
      runner.run(
        input({
          runId: "hash-mismatch",
          trustedChecksPath: source,
          checkBundleHash: "wrong-hash",
          checks: [
            {
              id: "contract",
              runner: "node",
              entrypoint: "check.mjs",
              args: [],
              timeoutMs: 10_000,
              scratchBytes: 1_048_576,
            },
          ],
        }),
      ),
    ).rejects.toThrow(/does not match the sealed bundle/);
  });
});

describe("trusted check bundle", () => {
  it("imports a readonly content-addressed payload separate from the mutable source", async () => {
    const root = await tempRoot();
    const source = path.join(root, "source");
    const store = path.join(root, "store");
    await mkdir(source);
    await writeFile(path.join(source, "check.mjs"), "first\n");
    const bundleStore = new TrustedCheckBundleStore(source, store);
    const expectedSealedHash = await hashSealedTrustedCheckBundleSource(source);
    const first = await bundleStore.seal();

    expect(first.hash).toBe(expectedSealedHash);
    expect(first.hash).not.toBe(await hashTrustedCheckBundle(source));
    expect(first.payloadPath).toBe(path.join(store, "payloads", first.hash));
    expect((await stat(first.payloadPath)).mode & 0o222).toBe(0);
    expect((await stat(path.join(first.payloadPath, "check.mjs"))).mode & 0o222).toBe(0);
    await writeFile(path.join(source, "check.mjs"), "second\n");
    expect(await readFile(path.join(first.payloadPath, "check.mjs"), "utf8")).toBe(
      "first\n",
    );
    const second = await bundleStore.seal();
    expect(second.hash).not.toBe(first.hash);
    expect(second.payloadPath).not.toBe(first.payloadPath);
  });

  it("rejects a sealed bundle whose payload root regains write permission", async () => {
    const root = await tempRoot();
    const source = path.join(root, "source");
    const store = path.join(root, "store");
    await mkdir(source);
    await writeFile(path.join(source, "check.mjs"), "first\n");
    const bundleStore = new TrustedCheckBundleStore(source, store);
    const sealed = await bundleStore.seal();

    await chmod(sealed.payloadPath, 0o755);
    await expect(bundleStore.resolve(sealed.hash)).rejects.toThrow(
      /ROOT_NOT_READONLY/,
    );
  });

  it("is deterministic and changes with trusted check content", async () => {
    const root = await tempRoot();
    await writeFile(path.join(root, "b.mjs"), "b\n");
    await writeFile(path.join(root, "a.mjs"), "a\n");
    const first = await hashTrustedCheckBundle(root);
    expect(await hashTrustedCheckBundle(root)).toBe(first);
    expect((await describeTrustedCheckBundle(root)).hash).toBe(first);
    await writeFile(path.join(root, "a.mjs"), "changed\n");
    expect(await hashTrustedCheckBundle(root)).not.toBe(first);
  });

  it("rejects symlinks and hardlinks transitively", async () => {
    const symlinkRoot = await tempRoot();
    await writeFile(path.join(symlinkRoot, "check.mjs"), "ok\n");
    await symlink("check.mjs", path.join(symlinkRoot, "alias.mjs"));
    await expect(hashTrustedCheckBundle(symlinkRoot)).rejects.toThrow(/symlink/i);

    const hardlinkRoot = await tempRoot();
    await writeFile(path.join(hardlinkRoot, "check.mjs"), "ok\n");
    await link(path.join(hardlinkRoot, "check.mjs"), path.join(hardlinkRoot, "alias.mjs"));
    await expect(hashTrustedCheckBundle(hardlinkRoot)).rejects.toThrow(/hardlink/i);
  });
});
