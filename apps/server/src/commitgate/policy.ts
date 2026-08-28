import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import type { CommitGatePolicy, PathClass, RequiredCheckPolicy } from "./types.js";

export const DEFAULT_IGNORED_EPHEMERAL_NAMES = [
  ".git",
  ".codex",
  "node_modules",
  "dist",
  "coverage",
] as const;

export const defaultCommitGatePolicy: CommitGatePolicy = Object.freeze({
  schemaVersion: 1,
  protectedPaths: ["protected.txt"],
  platformManagedPaths: ["AGENTS.md"],
  ignoredEphemeralNames: [...DEFAULT_IGNORED_EPHEMERAL_NAMES],
  maxChangedFiles: 100,
  maxChangedBytes: 1_048_576,
  maxSingleFileBytes: 262_144,
  verifierTimeoutMs: 30_000,
  verifierMaxOutputBytes: 65_536,
  canaryPatterns: [],
  requiredChecks: [],
});

function assertPositiveInteger(value: unknown, field: string): asserts value is number {
  if (!Number.isInteger(value) || (value as number) <= 0) {
    throw new Error(field + " must be a positive integer");
  }
}

export function normalizePolicyPath(value: string, field = "path"): string {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) {
    throw new Error(field + " must be a non-empty path");
  }
  const slash = value.replaceAll("\\", "/");
  if (path.posix.isAbsolute(slash) || /^[A-Za-z]:\//.test(slash)) {
    throw new Error(field + " must be relative");
  }
  const normalized = path.posix.normalize(slash).replace(/^\.\//, "");
  if (normalized === ".." || normalized.startsWith("../") || normalized === ".") {
    throw new Error(field + " escapes the workspace");
  }
  return normalized.replace(/\/$/, "");
}

function validateCheck(value: unknown, index: number): RequiredCheckPolicy {
  if (!value || typeof value !== "object") throw new Error(`requiredChecks[${index}] is invalid`);
  const check = value as Partial<RequiredCheckPolicy>;
  if (!check.id || !/^[a-zA-Z0-9_.-]{1,64}$/.test(check.id)) {
    throw new Error(`requiredChecks[${index}].id is invalid`);
  }
  if (!check.runner || !["node", "python", "binary"].includes(check.runner)) {
    throw new Error(`requiredChecks[${index}].runner is invalid`);
  }
  if (
    !check.entrypoint ||
    typeof check.entrypoint !== "string" ||
    check.entrypoint !== normalizePolicyPath(check.entrypoint, `requiredChecks[${index}].entrypoint`) ||
    check.entrypoint.startsWith("../")
  ) {
    throw new Error(`requiredChecks[${index}].entrypoint is invalid`);
  }
  if (!Array.isArray(check.args) || check.args.some((arg) => typeof arg !== "string" || arg.includes("\0"))) {
    throw new Error(`requiredChecks[${index}].args is invalid`);
  }
  assertPositiveInteger(check.timeoutMs, `requiredChecks[${index}].timeoutMs`);
  assertPositiveInteger(check.scratchBytes, `requiredChecks[${index}].scratchBytes`);
  return {
    id: check.id,
    runner: check.runner,
    entrypoint: check.entrypoint,
    args: [...check.args],
    timeoutMs: check.timeoutMs,
    scratchBytes: check.scratchBytes,
  };
}

export function validatePolicy(value: unknown): CommitGatePolicy {
  if (!value || typeof value !== "object") throw new Error("CommitGate policy must be an object");
  const input = value as Partial<CommitGatePolicy>;
  if (input.schemaVersion !== 1) throw new Error("Unsupported CommitGate policy schema");
  const pathArray = (items: unknown, field: string): string[] => {
    if (!Array.isArray(items)) throw new Error(field + " must be an array");
    return [...new Set(items.map((item, index) => normalizePolicyPath(String(item), `${field}[${index}]`)))].sort();
  };
  const protectedPaths = pathArray(input.protectedPaths, "protectedPaths");
  const platformManagedPaths = pathArray(input.platformManagedPaths, "platformManagedPaths");
  const ignoredEphemeralNames = pathArray(input.ignoredEphemeralNames, "ignoredEphemeralNames");
  if (ignoredEphemeralNames.some((name) => name.includes("/"))) {
    throw new Error("ignoredEphemeralNames entries must be path-segment names");
  }
  assertPositiveInteger(input.maxChangedFiles, "maxChangedFiles");
  assertPositiveInteger(input.maxChangedBytes, "maxChangedBytes");
  assertPositiveInteger(input.maxSingleFileBytes, "maxSingleFileBytes");
  assertPositiveInteger(input.verifierTimeoutMs, "verifierTimeoutMs");
  assertPositiveInteger(input.verifierMaxOutputBytes, "verifierMaxOutputBytes");
  if (!Array.isArray(input.canaryPatterns) || input.canaryPatterns.some((item) => typeof item !== "string" || item.length === 0)) {
    throw new Error("canaryPatterns must contain non-empty strings");
  }
  if (!Array.isArray(input.requiredChecks)) throw new Error("requiredChecks must be an array");
  const requiredChecks = input.requiredChecks.map(validateCheck);
  if (new Set(requiredChecks.map((check) => check.id)).size !== requiredChecks.length) {
    throw new Error("requiredChecks ids must be unique");
  }
  return {
    schemaVersion: 1,
    protectedPaths,
    platformManagedPaths,
    ignoredEphemeralNames,
    maxChangedFiles: input.maxChangedFiles,
    maxChangedBytes: input.maxChangedBytes,
    maxSingleFileBytes: input.maxSingleFileBytes,
    verifierTimeoutMs: input.verifierTimeoutMs,
    verifierMaxOutputBytes: input.verifierMaxOutputBytes,
    canaryPatterns: [...input.canaryPatterns],
    requiredChecks,
  };
}

export async function loadPolicy(filePath?: string): Promise<CommitGatePolicy> {
  if (!filePath) return structuredClone(defaultCommitGatePolicy);
  try {
    return validatePolicy(JSON.parse(await readFile(filePath, "utf8")));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return structuredClone(defaultCommitGatePolicy);
    }
    throw error;
  }
}

export function policyHash(policy: CommitGatePolicy): string {
  return createHash("sha256").update(JSON.stringify(validatePolicy(policy))).digest("hex");
}

export function classifyPath(relativePath: string, policy: CommitGatePolicy): PathClass {
  const normalized = normalizePolicyPath(relativePath, "workspace path");
  const segments = normalized.split("/");
  if (segments.some((segment) => policy.ignoredEphemeralNames.includes(segment))) {
    return "ignoredEphemeral";
  }
  if (policy.platformManagedPaths.some((managed) => normalized === managed || normalized.startsWith(managed + "/"))) {
    return "platformManaged";
  }
  return "versioned";
}

function globToRegExp(pattern: string): RegExp {
  let result = "^";
  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index];
    if (char === "*" && pattern[index + 1] === "*") {
      result += ".*";
      index += 1;
    } else if (char === "*") {
      result += "[^/]*";
    } else if (char === "?") {
      result += "[^/]";
    } else {
      result += char?.replace(/[|\\{}()[\]^$+?.]/g, "\\$&") ?? "";
    }
  }
  return new RegExp(result + "$");
}

export function pathMatches(relativePath: string, patterns: string[]): boolean {
  const normalized = normalizePolicyPath(relativePath, "workspace path");
  return patterns.some((raw) => {
    const pattern = normalizePolicyPath(raw, "policy pattern");
    if (pattern.includes("*") || pattern.includes("?")) return globToRegExp(pattern).test(normalized);
    return normalized === pattern || normalized.startsWith(pattern + "/");
  });
}
