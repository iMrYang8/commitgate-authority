import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { BrokerLifecycleLedger, type BrokerRunBinding } from "./lifecycle-ledger.js";

const binding: BrokerRunBinding = {
  runId: "run-1",
  agentId: "agent-1",
  runLeaseId: "lease-1",
  sessionEpoch: 4,
};

describe("Runtime Broker durable lifecycle ledger", () => {
  it("rejects closure for a binding that never launched", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "broker-ledger-unknown-"));
    try {
      const ledger = new BrokerLifecycleLedger(root);
      await expect(ledger.markAgentClosed(binding)).rejects.toThrow(
        "BROKER_RUNTIME_BINDING_UNKNOWN",
      );
      await expect(ledger.markAllClosed(binding)).rejects.toThrow(
        "BROKER_RUNTIME_BINDING_UNKNOWN",
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("permits only the monotonic Agent -> Verifier -> closed sequence", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "broker-ledger-stage-"));
    try {
      const ledger = new BrokerLifecycleLedger(root);
      await expect(ledger.beginAgent(binding)).resolves.toMatchObject({
        ...binding,
        stage: "AGENT_STARTED",
      });
      await expect(ledger.beginAgent(binding)).rejects.toThrow(
        "BROKER_AGENT_LAUNCH_REPLAY",
      );
      await expect(ledger.beginVerifier(binding)).rejects.toThrow(
        "BROKER_VERIFIER_LAUNCH_NOT_ALLOWED",
      );
      await expect(ledger.markAgentClosed(binding)).resolves.toMatchObject({
        stage: "AGENT_CLOSED",
      });
      await expect(ledger.beginAgent(binding)).rejects.toThrow(
        "BROKER_AGENT_LIFECYCLE_CLOSED",
      );
      await expect(ledger.beginVerifier(binding)).resolves.toMatchObject({
        stage: "VERIFIER_STARTED",
      });
      await expect(ledger.beginVerifier(binding)).rejects.toThrow(
        "BROKER_VERIFIER_LAUNCH_NOT_ALLOWED",
      );
      await expect(ledger.markAllClosed(binding)).resolves.toMatchObject({
        stage: "ALL_CLOSED",
      });
      await expect(ledger.beginAgent(binding)).rejects.toThrow(
        "BROKER_RUNTIME_ALL_CLOSED",
      );
      await expect(ledger.beginVerifier(binding)).rejects.toThrow(
        "BROKER_RUNTIME_ALL_CLOSED",
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("persists tombstones across Broker instances and rejects cross-binding reuse", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "broker-ledger-restart-"));
    try {
      const firstProcess = new BrokerLifecycleLedger(root);
      await firstProcess.beginAgent(binding);
      await firstProcess.markAgentClosed(binding);

      const restartedProcess = new BrokerLifecycleLedger(root);
      await expect(restartedProcess.get(binding)).resolves.toMatchObject({
        stage: "AGENT_CLOSED",
      });
      await expect(restartedProcess.beginAgent(binding)).rejects.toThrow(
        "BROKER_AGENT_LIFECYCLE_CLOSED",
      );
      await expect(restartedProcess.assertKnown({
        ...binding,
        agentId: "other-agent",
      })).rejects.toThrow("BROKER_RUNTIME_BINDING_MISMATCH");
      await expect(restartedProcess.assertKnown({
        ...binding,
        runLeaseId: "other-lease",
      })).rejects.toThrow("BROKER_RUNTIME_BINDING_MISMATCH");
      await expect(restartedProcess.assertKnown({
        ...binding,
        sessionEpoch: binding.sessionEpoch + 1,
      })).rejects.toThrow("BROKER_RUNTIME_BINDING_MISMATCH");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
