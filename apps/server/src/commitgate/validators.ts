import { changedByteCount, diffManifests } from "./manifest.js";
import { pathMatches } from "./policy.js";
import { readChangedFileBuffers } from "./file-ops.js";
import type {
  CommitGatePolicy,
  ManifestChange,
  SnapshotManifest,
} from "./types.js";

export interface StaticValidationResult {
  changes: ManifestChange[];
  failures: string[];
}

export async function validateCandidate(
  policy: CommitGatePolicy,
  base: SnapshotManifest,
  candidate: SnapshotManifest,
  candidateRoot: string,
  sensitiveValues: readonly string[] = [],
): Promise<StaticValidationResult> {
  const changes = diffManifests(base, candidate);
  const failures: string[] = [];
  const changedFiles = changes.filter(
    (change) =>
      (change.before !== null && change.before.type !== "dir") ||
      (change.after !== null && change.after.type !== "dir"),
  ).length;
  if (changedFiles > policy.maxChangedFiles) failures.push("DIFF_FILE_BUDGET_EXCEEDED");
  if (changedByteCount(changes) > policy.maxChangedBytes) failures.push("DIFF_BYTE_BUDGET_EXCEEDED");
  for (const change of changes) {
    if (
      sensitiveValues.some(
        (value) => value.length > 0 && change.path.includes(value),
      )
    ) {
      failures.push("SENSITIVE_VALUE_DETECTED:" + change.path.replaceAll(/[^/]/g, "*"));
    }
    if (change.before?.pathClass === "platformManaged" || change.after?.pathClass === "platformManaged") {
      failures.push("PLATFORM_MANAGED_PATH_CHANGED:" + change.path);
    }
    if (pathMatches(change.path, policy.protectedPaths)) {
      failures.push("PROTECTED_PATH_CHANGED:" + change.path);
    }
    if (change.before?.type === "symlink" || change.after?.type === "symlink") {
      failures.push("SYMLINK_CHANGED:" + change.path);
    }
    if (change.after?.type === "file" && change.after.size > policy.maxSingleFileBytes) {
      failures.push("SINGLE_FILE_BUDGET_EXCEEDED:" + change.path);
    }
  }
  if (policy.canaryPatterns.length > 0 || sensitiveValues.length > 0) {
    const files = await readChangedFileBuffers(
      candidateRoot,
      changes.slice(0, policy.maxChangedFiles + 1).map((change) => change.path),
      policy.maxSingleFileBytes,
    );
    for (const file of files) {
      if (
        policy.canaryPatterns.some((canary) =>
          file.content.includes(Buffer.from(canary, "utf8")),
        )
      ) {
        failures.push("CANARY_DETECTED:" + file.path);
      }
      if (
        sensitiveValues.some(
          (value) => value.length > 0 && file.content.includes(Buffer.from(value, "utf8")),
        )
      ) {
        failures.push("SENSITIVE_VALUE_DETECTED:" + file.path);
      }
    }
  }
  return { changes, failures: [...new Set(failures)] };
}
