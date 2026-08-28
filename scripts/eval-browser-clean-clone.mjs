#!/usr/bin/env node
import { execFile, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import {
  assertEvaluationRecord,
  evaluationRecord,
} from "./evaluation-record.mjs";
import { evidenceProvenance, executionIdentity, parseFlag } from "./evidence-utils.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const execFileAsync = promisify(execFile);
const args = process.argv.slice(2);
const provider = parseFlag(args, "provider") ?? process.env.MODEL_PROVIDER ?? "ark";
const selfTest = args.includes("--self-test");
const reportPath = path.join(root, "eval", "browser-clean-clone-report.json");
const driverPath = path.join(root, "scripts", "eval-browser-driver.ts");
const packagePath = path.join(root, "package.json");
const packageLockPath = path.join(root, "package-lock.json");
const requiredScenarioIds = [
  "browser-create-agent",
  "browser-positive-committed",
  "browser-candidate-runner-cannot-self-verify",
  "browser-protected-quarantined",
  "browser-provider-or-verifier-aborted",
  "browser-fresh-follow-up",
  "provider-identity-bound",
  "stale-permit-replay-rejected",
  "browser-manual-rollback",
];

if (!new Set(["ark", "openrouter"]).has(provider)) {
  console.error("Usage: npm run eval:browser:clean-clone -- --provider ark|openrouter");
  process.exit(2);
}

async function staticContractCheck() {
  const [driver, packageJson, packageLock] = await Promise.all([
    readFile(driverPath, "utf8"),
    readFile(packagePath, "utf8").then(JSON.parse),
    readFile(packageLockPath, "utf8").then(JSON.parse),
  ]);
  const declaredPlaywright = packageJson.devDependencies?.["@playwright/test"];
  const lockedPlaywright =
    packageLock.packages?.["node_modules/@playwright/test"]?.version;
  return [
    {
      id: "driver-contract:playwright-dependency-lock",
      ok:
        typeof declaredPlaywright === "string" &&
        /^[~^]?1\.62\.1$/.test(declaredPlaywright) &&
        lockedPlaywright === "1.62.1",
    },
    {
      id: "driver-contract:chromium-launch-call",
      ok: /chromium\.launch\(/.test(driver),
    },
    {
      id: "driver-contract:trace-capture-call",
      ok: /context\.tracing\.start/.test(driver) && /trace\.zip/.test(driver),
    },
    {
      id: "driver-contract:trace-secret-redaction",
      ok:
        /sanitizePlaywrightTrace/.test(driver) &&
        /\[key, relaySecret, authToken\]/.test(driver),
    },
    {
      id: "driver-contract:video-capture-call",
      ok: /recordVideo/.test(driver) && /video\?\.path/.test(driver),
    },
    {
      id: "driver-contract:public-permit-replay-call",
      ok:
        !/PromotionPermitStore/.test(driver) &&
        /\/api\/runs\/\$\{receipt\.runId\}\/commitgate\/promotion-attempts/.test(driver) &&
        /PERMIT_REPLAY/.test(driver) &&
        /Public promotion-attempt API rejected the consumed permit/.test(driver),
    },
    ...requiredScenarioIds.map((id) => ({
      id: `driver-contract:scenario-id:${id}`,
      ok: driver.includes(`id: "${id}"`),
    })),
  ];
}

if (selfTest) {
  const checks = await staticContractCheck();
  for (const check of checks) {
    console.log(`${check.ok ? "verified" : "failed"} ${check.id}`);
  }
  process.exit(checks.every((check) => check.ok) ? 0 : 1);
}

const source = await evidenceProvenance(root);
const key = (
  process.env.MODEL_API_KEY ??
  (provider === "ark" ? process.env.ARK_API_KEY : "") ??
  ""
).trim();
const model = (
  process.env.MODEL_ID ??
  (provider === "ark" ? process.env.ARK_MODEL : "") ??
  ""
).trim();
const baseUrl = (
  process.env.MODEL_BASE_URL ??
  (provider === "openrouter"
    ? "https://openrouter.ai/api/v1"
    : process.env.ARK_BASE_URL ?? "https://ark.cn-beijing.volces.com/api/v3")
).replace(/\/+$/, "");
const engine = process.env.CONTAINER_ENGINE || "docker";
const dependencyChecks = await staticContractCheck();
const nonSecretEnvironment = { ...process.env };
for (const name of ["MODEL_API_KEY", "ARK_API_KEY"]) {
  delete nonSecretEnvironment[name];
}
const git = spawnSync("git", ["--version"], {
  encoding: "utf8",
  env: nonSecretEnvironment,
});
const docker = spawnSync(engine, ["info", "--format", "{{.ServerVersion}}"], {
  encoding: "utf8",
  env: nonSecretEnvironment,
});
const preconditions = [
  {
    id: "committed-clean-source",
    status: source.workingTreeCleanAtCapture ? "verified" : "unverified",
    detail: source.workingTreeCleanAtCapture
      ? `${source.sourceRevision} / ${source.sourceTreeHash}`
      : "Commit the intended source revision before clean-clone replay",
  },
  {
    id: "provider-credentials",
    status:
      key && !key.startsWith("replace-") && model && !model.includes("replace-")
        ? "verified"
        : "unverified",
    detail:
      key && model
        ? `${provider} / ${model}; credential value not recorded`
        : "Configure MODEL_API_KEY and MODEL_ID (Ark compatibility variables are accepted)",
  },
  {
    id: "git-client",
    status: git.status === 0 ? "verified" : "unverified",
    detail: (
      (git.status === 0 ? git.stdout : git.stderr) ||
      git.error?.message ||
      "git unavailable"
    ).trim(),
  },
  {
    id: "container-engine",
    status: docker.status === 0 ? "verified" : "unverified",
    detail: (
      (docker.status === 0 ? docker.stdout : docker.stderr) ||
      docker.error?.message ||
      `${engine} unavailable`
    ).trim(),
  },
  {
    id: "checked-in-playwright-driver",
    status: dependencyChecks.every((check) => check.ok) ? "verified" : "unverified",
    detail: dependencyChecks.every((check) => check.ok)
      ? "Playwright dependency, browser actions, live permit replay, trace and video contracts are checked in"
      : dependencyChecks.filter((check) => !check.ok).map((check) => check.id).join(", "),
  },
];

function baseReport(status, reason) {
  return {
    schemaVersion: 2,
    kind: "browser-clean-clone-evaluation",
    generatedAt: new Date().toISOString(),
    status,
    source,
    executionIdentity: executionIdentity(root, { providerId: provider }),
    provider: {
      providerId: provider,
      gateway: baseUrl,
      requestedModel: model || null,
      resolvedModel: null,
      credentialsRecorded: false,
    },
    preconditions,
    steps: [
      { id: "clean-clone-npm-ci-and-image-build", status: "unverified" },
      ...requiredScenarioIds.map((id) => ({ id, status: "unverified" })),
    ],
    artifacts: [],
    officialProviderE2E: "unverified",
    alternateProviderVerified: false,
    competitionVerified: false,
    reason,
    launcher: {
      cleanClone: true,
      npmCi: true,
      playwrightChromium: true,
      browserInstallCommand: "npx playwright install chromium",
      manualConfirmationAccepted: false,
    },
  };
}

await mkdir(path.dirname(reportPath), { recursive: true });
if (preconditions.some((item) => item.status !== "verified")) {
  const report = baseReport(
    "unverified",
    "One or more mechanical clean-clone/browser prerequisites are missing",
  );
  await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");
  for (const item of preconditions) {
    console.log(`${item.status.padEnd(10)} ${item.id}: ${item.detail}`);
  }
  console.log(`unverified: clean-clone browser report: ${reportPath}`);
  process.exit(2);
}

// Docker Desktop/Colima may not expose macOS's private per-user tmpdir to the
// daemon. Keep the clean clone in an ignored project-local directory so every
// bind mount resolves to the same host path while remaining a distinct clone.
const scratchParent = path.join(root, ".local");
await mkdir(scratchParent, { recursive: true });
const scratch = await mkdtemp(
  path.join(scratchParent, "commitgate-browser-clone-"),
);
const clone = path.join(scratch, "repo");
const revisionTag = source.sourceRevision.slice(0, 12);
const artifactDirectory = path.join(
  root,
  "eval",
  "artifacts",
  "browser-clean-clone",
  `${revisionTag}-${provider}`,
);
const rawReportPath = path.join(artifactDirectory, "driver-report.json");
const runtimeImage = `volc-agent-runtime:browser-${revisionTag}-${process.pid}`;
const relayImage = `commitgate-model-relay:browser-${revisionTag}-${process.pid}`;
const stackId = `cgb-${process.pid}-${revisionTag.slice(0, 6)}`;
const composeProject = stackId;
const publicPort = 37_000 + (process.pid % 1_000);
const subnetSlot = process.pid % 200;
const stackEnvironment = {
  ...process.env,
  MODEL_PROVIDER: provider,
  MODEL_BASE_URL: baseUrl,
  MODEL_ID: model,
  MODEL_API_KEY: key,
  MODEL_WIRE_API: "responses",
  PUBLIC_PORT: String(publicPort),
  COMMITGATE_COMPOSE_PROJECT: composeProject,
  COMMITGATE_STACK_ID: stackId,
  COMMITGATE_DEFAULT_NETWORK: `${stackId}-default`,
  COMMITGATE_DEFAULT_SUBNET: `10.252.${subnetSlot}.0/24`,
  COMMITGATE_AGENT_SUBNET: `10.253.${subnetSlot}.0/24`,
};
const commandEvidence = [];
let childFailure = null;
let stackStarted = false;

const redact = (value) => {
  let output = String(value ?? "");
  for (const secret of [key, process.env.ARK_API_KEY ?? ""]) {
    if (secret) output = output.split(secret).join("[REDACTED]");
  }
  return output;
};

async function runStep(id, executable, commandArgs, options = {}) {
  const startedAt = new Date().toISOString();
  try {
    const result = await execFileAsync(executable, commandArgs, {
      cwd: options.cwd ?? clone,
      env: options.env ?? nonSecretEnvironment,
      timeout: options.timeout ?? 15 * 60_000,
      maxBuffer: 64 * 1024 * 1024,
    });
    commandEvidence.push({
      id,
      status: "verified",
      startedAt,
      completedAt: new Date().toISOString(),
      exitCode: 0,
      outputTail: redact((result.stdout + result.stderr).slice(-4_096)),
    });
  } catch (error) {
    const acceptedExit =
      Array.isArray(options.acceptExitCodes) &&
      options.acceptExitCodes.includes(error?.code);
    commandEvidence.push({
      id,
      status: acceptedExit ? "unverified" : "failed",
      startedAt,
      completedAt: new Date().toISOString(),
      exitCode: error?.code ?? 1,
      outputTail: redact(
        `${error?.stdout ?? ""}\n${error?.stderr ?? ""}\n${error?.message ?? error}`.slice(
          -16_384,
        ),
      ),
    });
    if (acceptedExit) return;
    throw error;
  }
}

try {
  await mkdir(artifactDirectory, { recursive: true });
  await runStep(
    "git-clean-clone",
    "git",
    ["clone", "--no-hardlinks", "--local", "--no-checkout", root, clone],
    { cwd: scratch, timeout: 2 * 60_000 },
  );
  await runStep("git-checkout-revision", "git", ["checkout", "--detach", source.sourceRevision]);
  await runStep("npm-ci", "npm", ["ci"], { timeout: 10 * 60_000 });
  await runStep("application-build", "npm", ["run", "build"], {
    timeout: 10 * 60_000,
  });
  if (process.env.COMMITGATE_SKIP_PLAYWRIGHT_INSTALL !== "true") {
    const playwrightCli = path.join(clone, "node_modules", ".bin", "playwright");
    await runStep("playwright-install-chromium", playwrightCli, ["install", "chromium"], {
      timeout: 15 * 60_000,
    });
  } else {
    commandEvidence.push({
      id: "playwright-install-chromium",
      status: "verified",
      detail: "Skipped by COMMITGATE_SKIP_PLAYWRIGHT_INSTALL=true; cached Chromium must launch",
    });
  }
  stackStarted = true;
  await runStep("authority-v2-stack-start", "./scripts/demo-stack.sh", ["start"], {
    env: stackEnvironment,
    timeout: 30 * 60_000,
  });
  const stackAuthToken = (
    await readFile(path.join(clone, ".demo-state", "secrets", "app_auth_token"), "utf8")
  ).trim();
  const driverEnvironment = {
    ...nonSecretEnvironment,
    MODEL_PROVIDER: provider,
    MODEL_BASE_URL: baseUrl,
    MODEL_ID: model,
    MODEL_API_KEY: key,
    MODEL_WIRE_API: "responses",
    CONTAINER_ENGINE: engine,
    CONTAINER_RUNTIME_IMAGE: "volc-agent-runtime:local",
    COMMITGATE_MODEL_RELAY_IMAGE: "commitgate-model-relay:local",
    COMMITGATE_BROWSER_RAW_REPORT: rawReportPath,
    COMMITGATE_BROWSER_ARTIFACT_DIR: artifactDirectory,
    COMMITGATE_CLEAN_CLONE_EXPECTED_REVISION: source.sourceRevision,
    COMMITGATE_BROWSER_EXTERNAL_STACK: "true",
    COMMITGATE_BROWSER_BASE_URL: `http://127.0.0.1:${publicPort}`,
    COMMITGATE_BROWSER_AUTH_TOKEN: stackAuthToken,
    COMMITGATE_BROWSER_RELAY_CONTAINER: `${composeProject}-model-relay-1`,
    COMMITGATE_BROWSER_RELAY_EGRESS_NETWORK: `${stackId}-default`,
  };
  await runStep(
    "playwright-browser-driver",
    process.execPath,
    ["--import", "tsx", "scripts/eval-browser-driver.ts", "--provider", provider],
    { env: driverEnvironment, timeout: 45 * 60_000, acceptExitCodes: [2] },
  );
} catch (error) {
  childFailure = redact(error instanceof Error ? error.message : String(error));
}

if (stackStarted) {
  await runStep("authority-v2-stack-cleanup", "./scripts/demo-stack.sh", ["reset"], {
    env: stackEnvironment,
    timeout: 5 * 60_000,
  }).catch(() => undefined);
}

let driverReport = null;
try {
  driverReport = JSON.parse(await readFile(rawReportPath, "utf8"));
} catch {
  // Command evidence below preserves the exact failed stage.
}

async function artifactRecord(filePath, kind) {
  const bytes = await readFile(filePath);
  return {
    kind,
    path: path.relative(root, filePath),
    sha256: createHash("sha256").update(bytes).digest("hex"),
    sizeBytes: bytes.byteLength,
  };
}

const artifacts = [];
if (driverReport) {
  for (const artifact of driverReport.artifacts ?? []) {
    try {
      const filePath = path.resolve(artifact.path);
      if ((await stat(filePath)).isFile()) {
        const measured = await artifactRecord(filePath, artifact.kind);
        artifacts.push({
          ...measured,
          driverSha256: artifact.sha256,
          hashMatchesDriver: measured.sha256 === artifact.sha256,
        });
      }
    } catch {
      // Missing artifacts keep the final status failed.
    }
  }
  artifacts.push(await artifactRecord(rawReportPath, "driver-report"));
}

const driverSteps = new Map((driverReport?.scenario ?? []).map((item) => [item.id, item]));
const buildVerified = [
  "git-clean-clone",
  "git-checkout-revision",
  "npm-ci",
  "application-build",
  "playwright-install-chromium",
  "authority-v2-stack-start",
].every((id) => commandEvidence.find((item) => item.id === id)?.status === "verified");
const steps = [
  {
    id: "clean-clone-npm-ci-and-image-build",
    status: buildVerified ? "verified" : "failed",
  },
  ...requiredScenarioIds.map((id) => ({
    id,
    status: driverSteps.get(id)?.status ?? "unverified",
    evidence: driverSteps.get(id) ?? null,
  })),
];
const requiredArtifactKinds = new Set([
  "playwright-trace",
  "playwright-video",
  "final-screenshot",
  "driver-report",
]);
const artifactsVerified =
  [...requiredArtifactKinds].every((kind) => artifacts.some((item) => item.kind === kind)) &&
  artifacts.every((item) => item.hashMatchesDriver !== false);
const revisionVerified =
  driverReport?.source?.sourceRevision === source.sourceRevision &&
  driverReport?.source?.sourceTreeHash === source.sourceTreeHash &&
  driverReport?.source?.workingTreeCleanAtCapture === true;
const providerIdentityVerified =
  driverReport?.provider?.providerId === provider &&
  driverReport?.provider?.requestedModel === model &&
  typeof driverReport?.provider?.resolvedModel === "string" &&
  driverReport.provider.resolvedModel.trim().length > 0;
const hardFailure = Boolean(
  childFailure ||
    !driverReport ||
    driverReport.status === "failed" ||
    steps.some((step) => step.status === "failed") ||
    !artifactsVerified ||
    !revisionVerified ||
    !providerIdentityVerified,
);
const status = hardFailure
  ? "failed"
  : driverReport.status === "verified" &&
      steps.every((step) => step.status === "verified")
    ? "verified"
    : "unverified";
const evaluationRecords = (driverReport?.scenario ?? []).map((scenario) =>
  assertEvaluationRecord(evaluationRecord({
    source,
    provider: driverReport?.provider ?? { providerId: provider, requestedModel: model },
    scenario,
  })),
);
const report = {
  schemaVersion: 2,
  kind: "browser-clean-clone-evaluation",
  generatedAt: new Date().toISOString(),
  status,
  source,
  cleanCloneSource: driverReport?.source ?? null,
  executionIdentity:
    driverReport?.executionIdentity ?? executionIdentity(root, { providerId: provider }),
  provider: driverReport?.provider ?? {
    providerId: provider,
    gateway: baseUrl,
    requestedModel: model,
    resolvedModel: null,
    credentialsRecorded: false,
  },
  preconditions,
  steps,
  artifacts,
  commandEvidence,
  evaluationRecords,
  provenance: {
    realCleanClone: true,
    realNpmCi: buildVerified,
    browserAutomation: driverReport?.provenance?.browserAutomation === true,
    traceVideoReportHashesVerified: artifactsVerified,
    sourceRevisionMatches: revisionVerified,
    providerIdentityBound: providerIdentityVerified,
    credentialsRecorded: false,
  },
  officialProviderE2E:
    provider === "ark" && status === "verified" ? "verified" : "unverified",
  alternateProviderVerified: provider === "openrouter" && status === "verified",
  competitionVerified: provider === "ark" && status === "verified",
  reason:
    status === "verified"
      ? null
      : childFailure ??
        driverReport?.error ??
        (status === "unverified"
          ? "One or more required clean-clone steps is unverified; permit replay remains protocol-store evidence rather than a public browser mutation surface"
          : "One or more mechanical browser claims failed"),
};
await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", "utf8");

await execFileAsync(engine, ["image", "rm", "--force", runtimeImage, relayImage], {
  timeout: 60_000,
}).catch(() => undefined);
await rm(scratch, { recursive: true, force: true });

for (const step of steps) console.log(`${step.status.padEnd(10)} ${step.id}`);
console.log(`${status}: clean-clone browser report: ${reportPath}`);
process.exit(status === "verified" ? 0 : status === "unverified" ? 2 : 1);
