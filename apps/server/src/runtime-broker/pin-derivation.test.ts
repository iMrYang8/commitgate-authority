import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { hashSealedTrustedCheckBundleSource } from "../commitgate/trusted-check-bundle.js";

const repositoryRoot = path.resolve(import.meta.dirname, "../../../..");

describe("Worker evidence pin derivation bootstrap", () => {
  it("derives pins before runtime secrets exist and does not print a synthetic key", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "commitgate-pin-derivation-"));
    const engine = path.join(root, "fake-engine.mjs");
    await writeFile(engine, [
      "#!/usr/bin/env node",
      "const args = process.argv.slice(2);",
      "if (args[0] === 'image' && args[1] === 'inspect') {",
      `  process.stdout.write(JSON.stringify([{Id:'sha256:${"a".repeat(64)}',RepoDigests:[]}]))`,
      "  process.exit(0)",
      "}",
      "process.exit(2)",
      "",
    ].join("\n"), "utf8");
    await chmod(engine, 0o700);
    try {
      const environment: NodeJS.ProcessEnv = {
        ...process.env,
        COMMITGATE_SOURCE_REVISION: "b".repeat(40),
        COMMITGATE_STACK_ID: "pin-test",
        CONTAINER_ENGINE: engine,
        MODEL_ID: "pin-test-model",
      };
      delete environment.BROKER_ATTESTATION_KEY;
      delete environment.BROKER_ATTESTATION_KEY_FILE;
      const result = spawnSync(
        process.execPath,
        ["--import", "tsx", "scripts/derive-worker-evidence-pins.ts"],
        {
          cwd: repositoryRoot,
          env: environment,
          encoding: "utf8",
          maxBuffer: 2 * 1024 * 1024,
        },
      );
      expect(result.status, result.stderr).toBe(0);
      const pins = JSON.parse(result.stdout) as Record<string, unknown>;
      const expectedBundleHash = await hashSealedTrustedCheckBundleSource(
        path.join(repositoryRoot, "eval", "trusted-checks"),
      );
      expect(pins).toEqual({
        COMMITGATE_EXPECTED_CHECK_BUNDLE_HASH: expectedBundleHash,
        COMMITGATE_EXPECTED_VERIFIER_IMAGE_DIGEST: `sha256:${"a".repeat(64)}`,
        COMMITGATE_EXPECTED_VERIFIER_CONFIG_HASH: expect.stringMatching(/^[a-f0-9]{64}$/),
        COMMITGATE_EXPECTED_RESOURCE_POLICY_HASH: expect.stringMatching(/^[a-f0-9]{64}$/),
      });
      expect(result.stdout).not.toContain("pin-derivation-only");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
