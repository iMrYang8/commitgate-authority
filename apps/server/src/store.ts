import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { EMPTY_STATE_HASH, refreshAgentViewId } from "./state-view.js";
import type { Database } from "./types.js";

const emptyDatabase = (): Database => ({
  version: 3,
  agents: [],
  messages: [],
  runs: [],
  versions: [],
  snapshots: [],
});

function migrateDatabase(raw: unknown): Database {
  if (!raw || typeof raw !== "object") {
    throw new Error("Unsupported database format");
  }
  const parsed = raw as Record<string, unknown>;
  if (!Array.isArray(parsed.agents) || !Array.isArray(parsed.messages) || !Array.isArray(parsed.runs)) {
    throw new Error("Unsupported database format");
  }
  if (![1, 2, 3].includes(Number(parsed.version))) {
    throw new Error("Unsupported database format");
  }
  const sourceVersion = Number(parsed.version);
  const snapshots = Array.isArray(parsed.snapshots) ? parsed.snapshots as Database["snapshots"] : [];
  const rawVersions = Array.isArray(parsed.versions)
    ? parsed.versions as Array<Partial<Database["versions"][number]> & Pick<Database["versions"][number], "id" | "agentId" | "sequence" | "snapshotHash">>
    : [];
  const versions: Database["versions"] = rawVersions.map((version) => ({
    ...(version as Database["versions"][number]),
    generation: version.generation ?? Math.max(1, version.sequence),
    viewId: version.viewId ?? null,
    transitionEventId: version.transitionEventId ?? null,
    snapshotAvailable:
      version.snapshotAvailable ??
      snapshots.find(
        (snapshot) => snapshot.agentId === version.agentId && snapshot.hash === version.snapshotHash,
      )?.state !== "pruned",
  }));
  const runInputs = parsed.runs as Array<Partial<Database["runs"][number]> & Pick<Database["runs"][number], "id" | "agentId" | "status" | "prompt" | "createdAt">>;
  const agents: Database["agents"] = (parsed.agents as Array<Partial<Database["agents"][number]> & Pick<Database["agents"][number], "id" | "name" | "workspacePath">>).map((value) => {
    const head = versions.find((version) => version.id === value.headVersionId);
    const generation = value.stateGeneration ?? head?.generation ?? Math.max(1, head?.sequence ?? 1);
    const agent = {
      ...(value as Database["agents"][number]),
      codexThreadId: sourceVersion < 3 ? null : value.codexThreadId ?? null,
      sessionEpoch: (value.sessionEpoch ?? 0) + (sourceVersion < 3 ? 1 : 0),
      needsReconciliation: sourceVersion < 3 ? true : value.needsReconciliation ?? false,
      headVersionId: value.headVersionId ?? null,
      stateGeneration: generation,
      currentViewId: value.currentViewId ?? "",
      currentVersionedHash: value.currentVersionedHash ?? head?.snapshotHash ?? EMPTY_STATE_HASH,
      currentPlatformManagedHash: value.currentPlatformManagedHash ?? EMPTY_STATE_HASH,
      currentLiveStateHash: value.currentLiveStateHash ?? head?.liveStateHash ?? head?.snapshotHash ?? EMPTY_STATE_HASH,
      agentConfigVersion: value.agentConfigVersion ?? 1,
      policyVersion: value.policyVersion ?? 1,
      activeRunLeaseId: null,
      recoveryRequired: value.recoveryRequired ?? false,
    } satisfies Database["agents"][number];
    refreshAgentViewId(agent);
    return agent;
  });
  const agentViews = new Map(agents.map((agent) => [agent.id, agent.currentViewId]));
  const runs: Database["runs"] = runInputs.map((run) => ({
    ...(run as Database["runs"][number]),
    commitGate: sourceVersion < 3 ? null : run.commitGate ?? null,
    legacyReceipt:
      sourceVersion < 3
        ? run.commitGate ?? null
        : (run as Partial<Database["runs"][number]>).legacyReceipt ?? null,
    transactionStatus: run.transactionStatus ?? "TERMINAL",
    runLeaseId: run.runLeaseId ?? `legacy-${run.id}`,
    submittedViewId: run.submittedViewId ?? agentViews.get(run.agentId) ?? "legacy-unscoped",
    baseViewId: run.baseViewId ?? agentViews.get(run.agentId) ?? "legacy-unscoped",
    proposalId:
      sourceVersion < 3 ? null : run.proposalId ?? run.commitGate?.proposalId ?? null,
    evaluationContextHash:
      sourceVersion < 3
        ? null
        : run.evaluationContextHash ?? run.commitGate?.evaluationContextHash ?? null,
    permitId:
      sourceVersion < 3 ? null : run.permitId ?? run.commitGate?.permitId ?? null,
    retryOfRunId: run.retryOfRunId ?? null,
    staleCallback: run.staleCallback ?? false,
    provider: run.provider ?? run.commitGate?.provider ?? null,
  }));
  const runMap = new Map(runs.map((run) => [run.id, run]));
  const messages: Database["messages"] = (parsed.messages as Array<Partial<Database["messages"][number]> & Pick<Database["messages"][number], "id" | "agentId" | "runId" | "role" | "content" | "createdAt">>).map((message) => {
    const run = runMap.get(message.runId);
    const authority = message.authority ?? (
      message.role === "user"
        ? "INPUT"
        : sourceVersion < 3
          ? run?.legacyReceipt && run.legacyReceipt.decision !== "COMMITTED"
            ? "REJECTED"
            : "SUPERSEDED"
          : run?.commitGate?.decision === "COMMITTED"
            ? "AUTHORITATIVE"
            : run?.commitGate
              ? "REJECTED"
              : "SUPERSEDED"
    );
    return {
      ...(message as Database["messages"][number]),
      authority,
      viewId: message.viewId ?? (authority === "AUTHORITATIVE" ? agentViews.get(message.agentId) ?? null : null),
      // A Proposal is produced by an Agent run, never by the user's input.
      // Keeping INPUT unbound also makes restart projection idempotent after a
      // terminal Run acquires its proposalId.
      proposalId:
        message.proposalId ??
        (message.role === "assistant" ? run?.proposalId ?? null : null),
    };
  });
  return { version: 3, agents, messages, runs, versions, snapshots };
}

export class JsonStore {
  private data: Database = emptyDatabase();
  private queue: Promise<void> = Promise.resolve();

  constructor(private readonly filePath: string) {}

  async initialize(): Promise<void> {
    await mkdir(path.dirname(this.filePath), { recursive: true });
    try {
      const raw = await readFile(this.filePath, "utf8");
      const parsed = JSON.parse(raw) as { version?: unknown };
      this.data = migrateDatabase(parsed);
      if (parsed.version !== 3) {
        await this.persist(this.data);
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        throw error;
      }
      await this.persist();
    }
  }

  snapshot(): Database {
    return structuredClone(this.data);
  }

  async mutate<T>(mutation: (database: Database) => T | Promise<T>): Promise<T> {
    let result!: T;
    const operation = this.queue.then(async () => {
      const next = structuredClone(this.data);
      result = await mutation(next);
      await this.persist(next);
      this.data = next;
    });
    this.queue = operation.catch(() => undefined);
    await operation;
    return result;
  }

  private async persist(data: Database = this.data): Promise<void> {
    const temporaryPath = this.filePath + ".tmp";
    await writeFile(temporaryPath, JSON.stringify(data, null, 2) + "\n", {
      encoding: "utf8",
      mode: 0o600,
    });
    await rename(temporaryPath, this.filePath);
  }
}
