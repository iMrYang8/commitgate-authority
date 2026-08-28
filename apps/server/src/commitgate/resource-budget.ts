import { lstat, opendir } from "node:fs/promises";
import path from "node:path";
import { classifyPath } from "./policy.js";
import type { CommitGatePolicy } from "./types.js";

export interface CandidateResourceLimits {
  maxIgnoredEntries: number;
  maxIgnoredBytes: number;
  maxIgnoredSingleFileBytes: number;
}

export const DEFAULT_CANDIDATE_RESOURCE_LIMITS: CandidateResourceLimits =
  Object.freeze({
    maxIgnoredEntries: 4_096,
    maxIgnoredBytes: 64 * 1024 * 1024,
    maxIgnoredSingleFileBytes: 16 * 1024 * 1024,
  });

export interface CandidateResourceUsage {
  ignoredEntries: number;
  ignoredBytes: number;
}

export function normalizeCandidateResourceLimits(
  overrides: Partial<CandidateResourceLimits> = {},
): CandidateResourceLimits {
  const result = { ...DEFAULT_CANDIDATE_RESOURCE_LIMITS, ...overrides };
  for (const [name, value] of Object.entries(result)) {
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new Error(`${name} must be a positive safe integer`);
    }
  }
  return result;
}

/**
 * Streams directory entries and stops at the first over-budget ignored inode.
 * This runs before manifest hashing/sealing, so ignored trees cannot force an
 * unbounded recursive copy or remain hidden from the gate's resource policy.
 */
export async function auditCandidateResourceUsage(
  root: string,
  policy: CommitGatePolicy,
  limits: CandidateResourceLimits = DEFAULT_CANDIDATE_RESOURCE_LIMITS,
): Promise<CandidateResourceUsage> {
  const normalizedLimits = normalizeCandidateResourceLimits(limits);
  const rootPath = path.resolve(root);
  const rootStats = await lstat(rootPath);
  if (!rootStats.isDirectory() || rootStats.isSymbolicLink()) {
    throw new Error("CANDIDATE_RESOURCE_ROOT_INVALID");
  }

  let ignoredEntries = 0;
  let ignoredBytes = 0;
  const count = (relative: string, size: number): void => {
    ignoredEntries += 1;
    if (ignoredEntries > normalizedLimits.maxIgnoredEntries) {
      throw new Error(`IGNORED_EPHEMERAL_FILE_BUDGET_EXCEEDED:${relative}`);
    }
    if (size > normalizedLimits.maxIgnoredSingleFileBytes) {
      throw new Error(`IGNORED_EPHEMERAL_SINGLE_FILE_BUDGET_EXCEEDED:${relative}`);
    }
    ignoredBytes += size;
    if (ignoredBytes > normalizedLimits.maxIgnoredBytes) {
      throw new Error(`IGNORED_EPHEMERAL_BYTE_BUDGET_EXCEEDED:${relative}`);
    }
  };

  const walk = async (
    absoluteDirectory: string,
    relativeDirectory: string,
    inheritedIgnored: boolean,
  ): Promise<void> => {
    const directory = await opendir(absoluteDirectory);
    try {
      for await (const entry of directory) {
        const relative = relativeDirectory
          ? `${relativeDirectory}/${entry.name}`
          : entry.name;
        const absolute = path.join(absoluteDirectory, entry.name);
        const stats = await lstat(absolute);
        const ignored =
          inheritedIgnored || classifyPath(relative, policy) === "ignoredEphemeral";
        if (ignored) count(relative, stats.isDirectory() ? 0 : stats.size);
        if (stats.isDirectory()) {
          await walk(absolute, relative, ignored);
        } else if (
          !stats.isFile() &&
          !stats.isSymbolicLink()
        ) {
          throw new Error(`CANDIDATE_SPECIAL_FILE:${relative}`);
        }
      }
    } finally {
      await directory.close().catch(() => undefined);
    }
  };

  await walk(rootPath, "", false);
  return { ignoredEntries, ignoredBytes };
}
