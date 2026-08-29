import {
  createHash,
  createHmac,
  timingSafeEqual,
} from "node:crypto";
import { canonicalJson } from "../commitgate/protocol.js";

export const BROKER_ATTESTATION_ALGORITHM = "HMAC-SHA256" as const;

export interface BrokerAttestationProof {
  schemaVersion: 1;
  algorithm: typeof BROKER_ATTESTATION_ALGORITHM;
  keyId: string;
  mac: string;
}

export type SignedBrokerAttestation<TPayload extends object> =
  TPayload & { brokerAttestation: BrokerAttestationProof };

export function assertBrokerAttestationKey(secret: string): void {
  if (Buffer.byteLength(secret, "utf8") < 32) {
    throw new Error("BROKER_ATTESTATION_KEY must contain at least 32 bytes");
  }
}

export function brokerAttestationKeyId(secret: string): string {
  assertBrokerAttestationKey(secret);
  return createHash("sha256").update(secret, "utf8").digest("hex").slice(0, 24);
}

function unsignedEnvelope<TPayload extends object>(
  payload: TPayload,
  secret: string,
): {
  schemaVersion: 1;
  algorithm: typeof BROKER_ATTESTATION_ALGORITHM;
  keyId: string;
  payload: TPayload;
} {
  return {
    schemaVersion: 1,
    algorithm: BROKER_ATTESTATION_ALGORITHM,
    keyId: brokerAttestationKeyId(secret),
    payload,
  };
}

export function signBrokerAttestation<TPayload extends object>(
  payload: TPayload,
  secret: string,
): SignedBrokerAttestation<TPayload> {
  const unsigned = unsignedEnvelope(payload, secret);
  return {
    ...payload,
    brokerAttestation: {
      schemaVersion: 1,
      algorithm: BROKER_ATTESTATION_ALGORITHM,
      keyId: unsigned.keyId,
      mac: createHmac("sha256", secret)
        .update(canonicalJson(unsigned))
        .digest("hex"),
    },
  };
}

export function verifyBrokerAttestation<TPayload extends object>(
  envelope: SignedBrokerAttestation<TPayload>,
  secret: string,
): TPayload {
  assertBrokerAttestationKey(secret);
  const proof = envelope.brokerAttestation;
  if (
    proof.schemaVersion !== 1 ||
    proof.algorithm !== BROKER_ATTESTATION_ALGORITHM ||
    proof.keyId !== brokerAttestationKeyId(secret) ||
    !/^[a-f0-9]{64}$/.test(proof.mac)
  ) {
    throw new Error("BROKER_ATTESTATION_ENVELOPE_INVALID");
  }
  const { brokerAttestation: _proof, ...payload } = envelope;
  const expected = createHmac("sha256", secret)
    .update(canonicalJson({
      schemaVersion: proof.schemaVersion,
      algorithm: proof.algorithm,
      keyId: proof.keyId,
      payload,
    }))
    .digest();
  const observed = Buffer.from(proof.mac, "hex");
  if (observed.length !== expected.length || !timingSafeEqual(observed, expected)) {
    throw new Error("BROKER_ATTESTATION_MAC_INVALID");
  }
  return payload as TPayload;
}
