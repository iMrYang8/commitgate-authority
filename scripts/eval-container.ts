import { execFile } from "node:child_process";
import { mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  buildVerifierContainerArgs,
  DockerVerifierRunner,
} from "../apps/server/src/commitgate/verifier-runner.js";
import type { VerifierInput } from "../apps/server/src/commitgate/types.js";
import { makeTreeWritable } from "../apps/server/src/transition-worker/filesystem.js";
import { evidenceProvenance, executionIdentity } from "./evidence-utils.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const evidenceDir = path.join(root, "eval", "evidence");
const tempRoot = path.join(root, "eval", `.container-${process.pid}`);
const candidate = path.join(tempRoot, "candidate");
const checks = path.join(tempRoot, "checks");
const reportPath = path.join(root, "eval", "container-report.json");
const engine = process.env.CONTAINER_ENGINE || "docker";
const image = process.env.CONTAINER_RUNTIME_IMAGE || "volc-agent-runtime:local";
const execFileAsync = promisify(execFile);
const user =
  typeof process.getuid === "function" && typeof process.getgid === "function"
    ? `${process.getuid()}:${process.getgid()}`
    : undefined;
await mkdir(candidate, { recursive: true });
await mkdir(checks, { recursive: true });
await mkdir(evidenceDir, { recursive: true });

const checkSource = `
import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { lookup } from "node:dns/promises";

assert.equal(process.env.ARK_API_KEY, undefined, "Ark key leaked into verifier");
assert.equal(process.env.MODEL_API_KEY, undefined, "Generic provider key leaked into verifier");
assert.equal(process.env.MODEL_RELAY_TOKEN, undefined, "Relay token leaked into verifier");
assert.equal(process.env.OPENAI_API_KEY, undefined, "OpenAI-compatible key leaked into verifier");
assert.equal(process.env.CODEX_HOME, undefined, "Codex home leaked into verifier");
assert.equal(process.env.NODE_OPTIONS, undefined, "NODE_OPTIONS leaked into verifier");
assert.equal(process.env.PYTHONPATH, undefined, "PYTHONPATH leaked into verifier");
assert.equal(await readFile("/proposal/value.txt", "utf8"), "ok\\n");
let networkResolved = false;
try { await lookup("example.com"); networkResolved = true; } catch {}
assert.equal(networkResolved, false, "Verifier unexpectedly resolved the public network");
let checksWritable = true;
try { await writeFile("/checks/write-probe", "bad"); } catch { checksWritable = false; }
assert.equal(checksWritable, false, "Trusted checks mount is writable");
let proposalWritable = true;
try { await writeFile("/proposal/write-probe", "bad"); } catch { proposalWritable = false; }
assert.equal(proposalWritable, false, "Proposal mount is writable");
console.log("isolated-contract: PASS");
`;
await writeFile(path.join(checks, "isolated-contract.mjs"), checkSource, "utf8");
await writeFile(path.join(candidate, "value.txt"), "ok\n", "utf8");

const config = {
  engine,
  image,
  cpuLimit: 1,
  memoryLimit: "512m",
  pidsLimit: 64,
  ...(user ? { user } : {}),
  instanceId: "eval",
  trustedChecksPath: checks,
  runTimeoutMs: 20_000,
  maxOutputBytes: 65_536,
  sourceRevision: "container-eval",
};
const policyCheck = {
  id: "isolated-contract",
  runner: "node" as const,
  entrypoint: "isolated-contract.mjs",
  args: [],
  timeoutMs: 20_000,
  scratchBytes: 64 * 1024 * 1024,
};
const input: VerifierInput = {
  runId: "container-eval",
  agentId: "fixture-agent",
  verifyPath: candidate,
  trustedChecksPath: checks,
  checks: [policyCheck],
  timeoutMs: 20_000,
  maxOutputBytes: 65_536,
};
const args = buildVerifierContainerArgs(input, policyCheck, config);
const imageIndex = args.indexOf(image);
const commandTail = imageIndex >= 0 ? args.slice(imageIndex + 1) : [];
const joinedArguments = args.join(" ");
const structural = {
  networkNone: args.includes("none") && args[args.indexOf("--network") + 1] === "none",
  readOnlyRoot: args.includes("--read-only"),
  capsDropped: args.includes("ALL") && args.includes("--cap-drop"),
  noNewPrivileges: args.includes("no-new-privileges"),
  proposalReadOnly: args.some((arg) => arg.includes("dst=/proposal,readonly")),
  trustedChecksReadOnly: args.some((arg) => arg.includes("dst=/checks,readonly")),
  scratchOnlyWritableMount: args.some((arg) => arg.startsWith("/scratch:rw")),
  isolatedEnvironment:
    args[args.indexOf("--entrypoint") + 1] === "/usr/bin/env" && commandTail[0] === "-i",
  noProviderCredentialArgument:
    !/ARK_API_KEY|MODEL_API_KEY|MODEL_RELAY_TOKEN|OPENAI_API_KEY|OPENROUTER_API_KEY/.test(joinedArguments),
  noCodexHome: !args.some((arg) => arg.includes("dst=/codex-home")),
  noPersistentMount: !args.some((arg) => arg.includes("dst=/workspace")),
  noShellWrapper:
    commandTail.includes("node") &&
    commandTail.includes("/checks/isolated-contract.mjs") &&
    !commandTail.some((arg) => /^(?:sh|bash|zsh|-c)$/.test(arg)),
};

let positive = null;
let negative = null;
let error: string | null = null;
let imageId: string | null = null;
try {
  imageId = (
    await execFileAsync(engine, ["image", "inspect", image, "--format", "{{.Id}}"], {
      timeout: 10_000,
    })
  ).stdout.trim();
  const runner = new DockerVerifierRunner(config);
  positive = (await runner.run(input))[0] ?? null;
  await writeFile(path.join(candidate, "value.txt"), "tampered\n", "utf8");
  negative = (await runner.run({ ...input, runId: "container-eval-negative" }))[0] ?? null;
} catch (reason) {
  error = reason instanceof Error ? reason.message : String(reason);
}

const environmentUnavailable = Boolean(
  error &&
    /permission denied|cannot connect|is the docker daemon running|not found|no such image|ENOENT/i.test(
      error,
    ),
);
const status =
  !error &&
  Object.values(structural).every(Boolean) &&
  positive?.status === "PASS" &&
  negative?.status === "FAIL"
    ? "verified"
    : environmentUnavailable
      ? "unverified"
      : "failed";
const report = {
  schemaVersion: 2,
  kind: "container-verifier-evaluation",
  generatedAt: new Date().toISOString(),
  status,
  source: await evidenceProvenance(root),
  executionIdentity: executionIdentity(root),
  provenance: {
    realContainerExecution: Boolean(imageId && positive && negative),
    realModelArk: false,
    image,
    imageId,
    engine,
  },
  structural,
  positive,
  negative,
  error,
  command: {
    executable: engine,
    arguments: args.map((argument) => argument.replaceAll(root, "<REPO>")),
    note: "Temporary mount fixtures are recreated by npm run eval:container.",
  },
};
await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");
await makeTreeWritable(tempRoot).catch(() => undefined);
await rm(tempRoot, { recursive: true, force: true });
console.log(`container report: ${reportPath}`);
if (positive) console.log(`positive trusted check: ${positive.status}`);
if (negative) console.log(`negative trusted check: ${negative.status}`);
process.exitCode = status === "verified" ? 0 : status === "unverified" ? 2 : 1;
