import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { JsonStore } from "./store.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

describe("JsonStore", () => {
  it("migrates a version 1 database without inventing gate evidence", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "launchpad-store-migration-"));
    temporaryDirectories.push(root);
    const file = path.join(root, "db.json");
    await writeFile(
      file,
      JSON.stringify({
        version: 1,
        agents: [
          {
            id: "agent-1",
            name: "Legacy",
            description: "",
            instructions: "",
            status: "ready",
            workspacePath: "/tmp/legacy",
            codexThreadId: null,
            lastError: null,
            createdAt: "2026-01-01T00:00:00.000Z",
            updatedAt: "2026-01-01T00:00:00.000Z",
          },
        ],
        messages: [],
        runs: [
          {
            id: "run-1",
            agentId: "agent-1",
            status: "completed",
            prompt: "legacy",
            output: "done",
            error: null,
            usage: null,
            startedAt: "2026-01-01T00:00:00.000Z",
            completedAt: "2026-01-01T00:00:01.000Z",
            createdAt: "2026-01-01T00:00:00.000Z",
          },
        ],
      }),
    );

    const store = new JsonStore(file);
    await store.initialize();
    const migrated = store.snapshot();
    expect(migrated.version).toBe(3);
    expect(migrated.agents[0]).toMatchObject({
      sessionEpoch: 1,
      needsReconciliation: true,
      headVersionId: null,
      stateGeneration: 1,
      activeRunLeaseId: null,
    });
    expect(migrated.runs[0]?.commitGate).toBeNull();
    expect(migrated.versions).toEqual([]);
    expect(migrated.snapshots).toEqual([]);
    expect(JSON.parse(await readFile(file, "utf8")).version).toBe(3);
  });

  it("migrates v2 receipts to read-only legacyReceipt and fences legacy messages", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "launchpad-store-v2-"));
    temporaryDirectories.push(root);
    const file = path.join(root, "db.json");
    const timestamp = "2026-01-01T00:00:00.000Z";
    const legacyGate = {
      decision: "QUARANTINED",
      failureClass: "agent_wrong",
      receiptId: "run-rejected",
      baseHash: "a".repeat(64),
      candidateHash: "b".repeat(64),
      finalHash: "a".repeat(64),
      policyHash: "c".repeat(64),
      checks: [],
      changedPaths: ["protected.txt"],
      threadDisposition: "reset",
      candidateCleanup: "deleted",
    };
    await writeFile(
      file,
      JSON.stringify({
        version: 2,
        agents: [
          {
            id: "agent-1",
            name: "V2",
            description: "",
            instructions: "",
            status: "ready",
            workspacePath: "/tmp/v2",
            codexThreadId: "legacy-thread",
            sessionEpoch: 4,
            headVersionId: null,
            lastError: null,
            createdAt: timestamp,
            updatedAt: timestamp,
          },
        ],
        runs: [
          {
            id: "run-rejected",
            agentId: "agent-1",
            status: "completed",
            prompt: "legacy rejected",
            output: "rejected output",
            error: null,
            usage: null,
            commitGate: legacyGate,
            createdAt: timestamp,
          },
          {
            id: "run-plain",
            agentId: "agent-1",
            status: "completed",
            prompt: "legacy plain",
            output: "plain output",
            error: null,
            usage: null,
            createdAt: timestamp,
          },
        ],
        messages: [
          {
            id: "message-rejected",
            agentId: "agent-1",
            runId: "run-rejected",
            role: "assistant",
            content: "rejected output",
            createdAt: timestamp,
          },
          {
            id: "message-legacy",
            agentId: "agent-1",
            runId: "run-plain",
            role: "assistant",
            content: "plain output",
            createdAt: timestamp,
          },
        ],
        versions: [],
        snapshots: [],
      }),
    );

    const store = new JsonStore(file);
    await store.initialize();
    const migrated = store.snapshot();
    expect(migrated.agents[0]).toMatchObject({
      codexThreadId: null,
      sessionEpoch: 5,
      needsReconciliation: true,
    });
    expect(migrated.runs[0]).toMatchObject({
      commitGate: null,
      legacyReceipt: { decision: "QUARANTINED" },
      proposalId: null,
      evaluationContextHash: null,
      permitId: null,
    });
    expect(migrated.messages.map((message) => message.authority)).toEqual([
      "REJECTED",
      "SUPERSEDED",
    ]);
  });

  it("does not publish a mutation in memory when persistence fails", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "launchpad-store-test-"));
    temporaryDirectories.push(root);
    const originalPath = path.join(root, "db.json");
    const store = new JsonStore(originalPath);
    await store.initialize();

    const mutableStore = store as unknown as { filePath: string };
    mutableStore.filePath = path.join(root, "missing-directory", "db.json");
    await expect(
      store.mutate((database) => {
        database.messages.push({
          id: "message-1",
          agentId: "agent-1",
          runId: "run-1",
          role: "user",
          content: "must not become visible",
          authority: "INPUT",
          viewId: null,
          proposalId: null,
          createdAt: new Date().toISOString(),
        });
      }),
    ).rejects.toThrow();
    expect(store.snapshot().messages).toEqual([]);

    mutableStore.filePath = originalPath;
    await store.mutate((database) => {
      database.messages.push({
        id: "message-2",
        agentId: "agent-1",
        runId: "run-2",
        role: "user",
        content: "queue recovered",
        authority: "INPUT",
        viewId: null,
        proposalId: null,
        createdAt: new Date().toISOString(),
      });
    });
    expect(store.snapshot().messages.map((message) => message.content)).toEqual([
      "queue recovered",
    ]);
  });
});
