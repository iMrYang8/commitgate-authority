import { readFile, readdir } from "node:fs/promises";
import path from "node:path";

export const OPTIONAL_ACTIVE_REPORTS = Object.freeze([
  "eval/evidence/preflight-report.json",
  "eval/evidence/demo-seed-report.json",
  "eval/evidence/demo-start-report.json",
  "eval/evidence/release-audit-report.json",
  "eval/evidence/evidence-checklist-report.md",
]);

const reportLike = (name) => /(?:^|[-_])report\.(?:json|md)$/.test(name);
const providerReport = /^provider-([a-z0-9_-]+)-report\.json$/i;

/**
 * Select exactly one Provider-scoped active report.
 *
 * A browser report is the final release selector.  Before browser evidence is
 * available, a single structurally valid report bound to the frozen source may
 * be treated as the current Provider compatibility report.  Multiple matching
 * reports deliberately produce the fail-closed placeholder so the inventory
 * rejects every ambiguous Provider report instead of silently choosing one.
 */
export async function resolveActiveProviderReport(root, {
  browserProviderId = null,
  source = null,
} = {}) {
  if (
    !/^[a-f0-9]{40}$/.test(source?.sourceRevision ?? "") ||
    !/^[a-f0-9]{64}$/.test(source?.sourceTreeHash ?? "") ||
    !Number.isInteger(source?.sourceFileCount)
  ) {
    return "eval/provider-current-report.json";
  }

  if (
    typeof browserProviderId === "string" &&
    /^[a-z0-9_-]+$/i.test(browserProviderId)
  ) {
    return `eval/provider-${browserProviderId}-report.json`;
  }

  let entries = [];
  try {
    entries = await readdir(path.join(root, "eval"), { withFileTypes: true });
  } catch {
    return "eval/provider-current-report.json";
  }
  const matches = [];
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    const parsedName = providerReport.exec(entry.name);
    if (!parsedName) continue;
    try {
      const report = JSON.parse(
        await readFile(path.join(root, "eval", entry.name), "utf8"),
      );
      if (
        report?.schemaVersion === 2 &&
        report?.kind === "real-provider-evaluation" &&
        report?.provider?.providerId === parsedName[1] &&
        report?.provider?.credentialsRecorded === false &&
        report?.source?.sourceRevision === source.sourceRevision &&
        report?.source?.sourceTreeHash === source.sourceTreeHash &&
        report?.source?.sourceFileCount === source.sourceFileCount &&
        report?.source?.workingTreeCleanAtCapture === true
      ) {
        matches.push(`eval/${entry.name}`);
      }
    } catch {
      // Malformed reports remain outside the allowlist and therefore fail.
    }
  }
  return matches.length === 1
    ? matches[0]
    : "eval/provider-current-report.json";
}

export async function activeEvidenceReportInventory(root, allowed) {
  const found = [];
  const excludedTrees = [
    "eval/history",
    "eval/independent",
    "eval/artifacts",
    "eval/fixtures",
    "eval/trusted-checks",
    "eval/demo-fixture",
  ];
  const pending = ["eval"];
  while (pending.length > 0) {
    const directory = pending.pop();
    let entries = [];
    try {
      entries = await readdir(path.join(root, directory), { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const relative = `${directory}/${entry.name}`;
      if (entry.isDirectory()) {
        if (
          !excludedTrees.some(
            (prefix) => relative === prefix || relative.startsWith(`${prefix}/`),
          ) &&
          !entry.name.startsWith(".")
        ) {
          pending.push(relative);
        }
      } else if (entry.isFile() && reportLike(entry.name)) {
        found.push(relative);
      }
    }
  }
  found.sort();
  const allowlist = new Set([...allowed, ...OPTIONAL_ACTIVE_REPORTS]);
  return {
    found,
    unexpected: found.filter((relative) => !allowlist.has(relative)),
    allowlist: [...allowlist].sort(),
  };
}
