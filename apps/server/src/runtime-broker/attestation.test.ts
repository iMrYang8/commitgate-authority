import { describe, expect, it } from "vitest";
import {
  brokerAttestationKeyId,
  signBrokerAttestation,
  verifyBrokerAttestation,
} from "./attestation.js";

const key = "broker-attestation-unit-test-secret-with-32-plus-bytes";
const otherKey = "different-broker-attestation-test-secret-32-plus-bytes";

describe("Broker attestation envelope", () => {
  it("authenticates the complete canonical payload", () => {
    const signed = signBrokerAttestation({
      schemaVersion: 1 as const,
      kind: "runtime-teardown" as const,
      scope: "ALL" as const,
      runId: "run-1",
      agentId: "agent-1",
      runLeaseId: "lease-1",
      sessionEpoch: 2,
    }, key);

    expect(verifyBrokerAttestation(signed, key)).toEqual({
      schemaVersion: 1,
      kind: "runtime-teardown",
      scope: "ALL",
      runId: "run-1",
      agentId: "agent-1",
      runLeaseId: "lease-1",
      sessionEpoch: 2,
    });
    expect(signed.brokerAttestation.keyId).toBe(brokerAttestationKeyId(key));
  });

  it("rejects payload tampering and the wrong key", () => {
    const signed = signBrokerAttestation({
      schemaVersion: 1 as const,
      kind: "verifier-result" as const,
      scope: "VERIFIER" as const,
      runId: "run-1",
      agentId: "agent-1",
      runLeaseId: "lease-1",
      sessionEpoch: 2,
      proposalId: "proposal-1",
      verifierInputHash: "a".repeat(64),
      checkResultsHash: "b".repeat(64),
    }, key);

    expect(() => verifyBrokerAttestation({
      ...signed,
      proposalId: "proposal-forged",
    }, key)).toThrow("BROKER_ATTESTATION_MAC_INVALID");
    expect(() => verifyBrokerAttestation(signed, otherKey)).toThrow(
      "BROKER_ATTESTATION_ENVELOPE_INVALID",
    );
  });

  it("rejects short keys instead of silently weakening production proofs", () => {
    expect(() => signBrokerAttestation({ runId: "run-1" }, "too-short"))
      .toThrow("BROKER_ATTESTATION_KEY must contain at least 32 bytes");
  });
});
