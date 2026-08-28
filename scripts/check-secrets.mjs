#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { evidenceProvenance, executionIdentity } from "./evidence-utils.mjs";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const evidenceDir = path.join(root, "eval", "evidence");
const excludedAtAnyDepth = new Set([
  ".git",
  "node_modules",
  "dist",
  "coverage",
]);
const excludedRuntimeRoots = new Set([
  ".data",
  ".local",
  "data",
  "workspaces",
  "codex-home",
]);
const findings = [];

const credentialNames = [
  "MODEL_API_KEY",
  "MODEL_RELAY_TOKEN",
  "OPENROUTER_API_KEY",
  "ARK_API_KEY",
];

function exactCredentialsFromEnvironment(environment, names = credentialNames) {
  return names
    // AppConfig and eval:real both trim the runtime value. Scan the exact same
    // bytes that can reach the Agent, receipts and redaction boundary.
    .map((name) => ({ name, value: (environment[name] ?? "").trim() }))
    .filter((entry) => entry.value.length > 0);
}

function exactMatchRecords(data, source, credentials) {
  const matches = [];
  for (const credential of credentials) {
    const needle = Buffer.from(credential.value);
    let offset = data.indexOf(needle);
    while (offset >= 0) {
      matches.push({ source, rule: `${credential.name.toLowerCase()}-exact`, offset });
      offset = data.indexOf(needle, offset + Math.max(1, needle.length));
    }
  }
  return matches;
}

const exactCredentials = exactCredentialsFromEnvironment(process.env);
const normalizationFixture = exactCredentialsFromEnvironment({
  MODEL_API_KEY: "  fixture-exact-key  ",
});
const exactCredentialNormalizationSelfCheck =
  normalizationFixture[0]?.value === "fixture-exact-key" &&
  exactMatchRecords(
    Buffer.from("prefix:fixture-exact-key:suffix"),
    "normalization-self-check",
    normalizationFixture,
  ).length === 1;
if (!exactCredentialNormalizationSelfCheck) {
  findings.push({
    source: "secret-scanner",
    rule: "exact-credential-normalization-self-check-failed",
  });
}
const assignmentNames = [
  "MODEL_API_KEY",
  "MODEL_RELAY_TOKEN",
  "OPENROUTER_API_KEY",
  "ARK_API_KEY",
  "APP_AUTH_TOKEN",
  "VOLCENGINE_ACCESS_KEY",
  "VOLCENGINE_SECRET_KEY",
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "GITHUB_TOKEN",
];

function inspectExact(data, source) {
  findings.push(...exactMatchRecords(data, source, exactCredentials));
}

function inspect(data, source) {
  inspectExact(data, source);
  const text = data.toString("utf8");
  const patterns = [
    { id: "openai-style-key", regex: /\b(?:sk|ak)-[A-Za-z0-9_-]{20,}\b/g },
    { id: "volc-access-key", regex: /\bAKLT[A-Za-z0-9]{16,}\b/g },
    { id: "bearer-token", regex: /\bBearer\s+[A-Za-z0-9._~+/-]{24,}=*\b/g },
    { id: "github-token", regex: /\bgh[opsu]_[A-Za-z0-9]{30,}\b/g },
    { id: "private-key", regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  ];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern.regex)) {
      findings.push({ source, rule: pattern.id, offset: match.index ?? -1 });
    }
  }
  for (const [index, line] of text.split(/\r?\n/).entries()) {
    const match = line.match(
      new RegExp(
        `^\\s*(?:export\\s+)?(${assignmentNames.join("|")})\\s*[:=]\\s*(.*?)\\s*$`,
      ),
    );
    if (!match) continue;
    const name = match[1] ?? "credential";
    const rawValue = (match[2] ?? "").replace(/[,\\]\s*$/, "").trim();
    const value = rawValue
      .replace(/,$/, "")
      .replace(/^['"]|['"]$/g, "")
      .trim();
    const testFixtureSource = /(?:^|\/)\w[^/]*\.test\.[cm]?[jt]s$/.test(source);
    const codeIdentifier =
      /\.[cm]?[jt]s$/.test(source) &&
      !/^['"]/.test(rawValue) &&
      /^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*$/.test(value);
    const placeholder =
      value === "" ||
      value === "key" ||
      testFixtureSource ||
      codeIdentifier ||
      /^[A-Z][A-Z0-9_]*$/.test(value) ||
      /replace|your[-_ ]|scoped-demo|test-|fixture|must-not|generated-above|redacted|local[-_ ]?secret|^\$[A-Za-z_][A-Za-z0-9_]*$|\$\{|^z\b|^this\.|^process\.|^config\.|^key$|^token$/i.test(
        value,
      );
    if (!placeholder) {
      findings.push({ source, rule: `${name.toLowerCase()}-assignment`, line: index + 1 });
    }
  }
}

async function walk(directory, relative = "") {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (
      excludedAtAnyDepth.has(entry.name) ||
      (relative === "" && excludedRuntimeRoots.has(entry.name))
    ) continue;
    const nextRelative = relative ? `${relative}/${entry.name}` : entry.name;
    if (nextRelative === ".env.local") continue;
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      await walk(absolute, nextRelative);
    } else if (entry.isFile()) {
      const data = await readFile(absolute);
      if (data.byteLength <= 4 * 1024 * 1024) {
        inspect(data, `working-tree:${nextRelative}`);
      } else {
        for (const credential of exactCredentials) {
          if (data.includes(Buffer.from(credential.value))) {
            findings.push({
              source: `working-tree:${nextRelative}`,
              rule: `${credential.name.toLowerCase()}-exact`,
            });
          }
        }
      }
    }
  }
}

await walk(root);
const history = spawnSync("git", ["log", "--all", "-p", "--", "."], {
  cwd: root,
  encoding: "utf8",
  maxBuffer: 32 * 1024 * 1024,
});
if (history.status === 0) {
  // Diff context may contain unchanged test fixtures next to a real code edit.
  // Scan only added/removed payload lines and retain the file identity so the
  // same explicit test-fixture allowance used for the working tree applies.
  let currentPath = "unknown";
  const changedByPath = new Map();
  for (const line of history.stdout.split(/\r?\n/)) {
    const header = line.match(/^diff --git a\/(.+) b\/(.+)$/);
    if (header) {
      currentPath = header[2] ?? header[1] ?? "unknown";
      continue;
    }
    if (!/^[+-]/.test(line) || /^(?:\+\+\+|---) /.test(line)) continue;
    const payload = line.slice(1);
    changedByPath.set(currentPath, `${changedByPath.get(currentPath) ?? ""}${payload}\n`);
  }
  for (const [relative, payload] of changedByPath) {
    inspect(Buffer.from(payload), `git-history:${relative}`);
  }
} else findings.push({ source: "git-history", rule: "scan-error", detail: history.stderr.trim() });

let gitObjectExactScan = exactCredentials.length === 0 ? "not-required" : "verified";
if (exactCredentials.length > 0) {
  const listedObjects = spawnSync("git", ["rev-list", "--objects", "--all"], {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
  });
  if (listedObjects.status !== 0) {
    gitObjectExactScan = "failed";
    findings.push({
      source: "git-object-history",
      rule: "scan-error",
      detail: listedObjects.stderr.trim(),
    });
  } else {
    const objectIds = [
      ...new Set(
        listedObjects.stdout
          .split(/\r?\n/)
          .filter(Boolean)
          .map((line) => line.split(/\s+/, 1)[0]),
      ),
    ];
    let scannedBytes = 0;
    const maxHistoryBytes = 512 * 1024 * 1024;
    for (const objectId of objectIds) {
      const type = spawnSync("git", ["cat-file", "-t", objectId], {
        cwd: root,
        encoding: "utf8",
      });
      if (type.status !== 0) {
        gitObjectExactScan = "failed";
        findings.push({ source: `git-object:${objectId}`, rule: "scan-error" });
        break;
      }
      if (type.stdout.trim() !== "blob") continue;
      const sizeResult = spawnSync("git", ["cat-file", "-s", objectId], {
        cwd: root,
        encoding: "utf8",
      });
      const size = Number(sizeResult.stdout.trim());
      if (sizeResult.status !== 0 || !Number.isSafeInteger(size) || size < 0) {
        gitObjectExactScan = "failed";
        findings.push({ source: `git-object:${objectId}`, rule: "scan-error" });
        break;
      }
      scannedBytes += size;
      if (scannedBytes > maxHistoryBytes) {
        gitObjectExactScan = "failed";
        findings.push({
          source: "git-object-history",
          rule: "scan-budget-exceeded",
          limitBytes: maxHistoryBytes,
        });
        break;
      }
      const blob = spawnSync("git", ["cat-file", "blob", objectId], {
        cwd: root,
        encoding: null,
        maxBuffer: Math.max(1024 * 1024, size + 1024),
      });
      if (blob.status !== 0 || !Buffer.isBuffer(blob.stdout)) {
        gitObjectExactScan = "failed";
        findings.push({ source: `git-object:${objectId}`, rule: "scan-error" });
        break;
      }
      inspectExact(blob.stdout, `git-object:${objectId}`);
    }
  }
}

await mkdir(evidenceDir, { recursive: true });
const report = {
  schemaVersion: 1,
  kind: "secret-scan",
  generatedAt: new Date().toISOString(),
  status: findings.length === 0 ? "verified" : "failed",
  source: await evidenceProvenance(root),
  executionIdentity: executionIdentity(root),
  scannedWorkingTree: true,
  scannedEvidenceArtifacts: true,
  scannedGitHistory: history.status === 0,
  gitObjectExactScan,
  exactCredentialNormalizationSelfCheck:
    exactCredentialNormalizationSelfCheck ? "verified" : "failed",
  ignoredLocalCredentialFile: ".env.local",
  scope:
    "Repository working tree (including eval evidence) and Git history; runtime data roots are excluded and covered by deterministic receipt-redaction tests",
  exactCredentialScan: Object.fromEntries(
    credentialNames.map((name) => [
      name,
      exactCredentials.some((entry) => entry.name === name) ? "scanned" : "not-present",
    ]),
  ),
  rules: [
    "OpenAI-style keys",
    "Volc access keys",
    "Bearer tokens",
    "GitHub tokens",
    "private-key PEM headers",
    ...assignmentNames.map((name) => `${name} assignments`),
    "exact trimmed in-memory provider and relay credential bytes when configured",
  ],
  findings,
};
await writeFile(
  path.join(evidenceDir, "secret-report.json"),
  JSON.stringify(report, null, 2) + "\n",
  "utf8",
);
console.log(`${report.status}: ${findings.length} secret finding(s)`);
console.log(`secret report: ${path.join(evidenceDir, "secret-report.json")}`);
process.exitCode = report.status === "verified" ? 0 : 1;
