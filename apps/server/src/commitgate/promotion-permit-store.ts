import { randomUUID } from "node:crypto";
import { mkdir, open } from "node:fs/promises";
import path from "node:path";
import { readJson, writeJsonAtomic } from "./atomic-json.js";
import { assertContained, assertSafeIdentifier } from "./file-ops.js";
import { assertEvidenceBundle, assertStateViewRef, sha256Canonical } from "./protocol.js";
import type {
  EvidenceBundle,
  PromotionPermit,
  SealedProposal,
  SnapshotManifest,
  StateViewRef,
} from "./types.js";

const capabilityBrand: unique symbol = Symbol("CommitGatePromotionCapability");
export interface PromotionCapability {
  readonly [capabilityBrand]: true;
  readonly permit: PromotionPermit;
  readonly proposal: SealedProposal;
  readonly proposalPath: string;
  readonly proposalManifest: SnapshotManifest;
  readonly baseView: StateViewRef;
  /** Atomic local+durable one-shot consumption; the transaction must invoke this before swap. */
  readonly consume: () => Promise<PromotionPermit>;
}

export class PermitStateError extends Error {
  constructor(
    readonly code:
      | "PERMIT_REPLAY"
      | "PERMIT_EXPIRED"
      | "PERMIT_BINDING_MISMATCH"
      | "PERMIT_STATE_INVALID",
    message: string,
  ) {
    super(message);
    this.name = "PermitStateError";
  }
}

export interface IssuePermitInput {
  runId: string;
  agentId: string;
  controlPath: string;
  proposal: SealedProposal;
  baseView: StateViewRef;
  evaluationContextHash: string;
  evidence: EvidenceBundle;
  ttlMs?: number;
}

export interface ClaimPermitInput {
  agentId: string;
  controlPath: string;
  permitId: string;
  proposal: SealedProposal;
  proposalPath: string;
  proposalManifest: SnapshotManifest;
  baseView: StateViewRef;
  evaluationContextHash: string;
  evidenceDigest: string;
}

export class PromotionPermitStore {
  private readonly queues = new Map<string, Promise<void>>();

  constructor(private readonly now: () => Date = () => new Date()) {}

  async issue(input: IssuePermitInput): Promise<PromotionPermit> {
    assertSafeIdentifier(input.runId, "runId");
    assertSafeIdentifier(input.agentId, "agentId");
    assertStateViewRef(input.baseView);
    assertEvidenceBundle(input.evidence);
    if (
      input.proposal.runId !== input.runId ||
      input.proposal.agentId !== input.agentId ||
      input.proposal.baseViewId !== input.baseView.viewId ||
      input.proposal.state !== "SEALED" ||
      input.evidence.proposalId !== input.proposal.proposalId ||
      input.evidence.evaluationContextHash !== input.evaluationContextHash ||
      input.evidence.coverage !== "complete" ||
      input.evidence.requiredChecksPassed !== true ||
      input.evidence.verifierInputHash !== input.proposal.manifestHash
    ) {
      throw new PermitStateError(
        "PERMIT_BINDING_MISMATCH",
        "Permit inputs do not bind the same proposal, view and evidence",
      );
    }
    const issuedAt = this.now();
    const permitId = `k-${randomUUID()}`;
    const permit: PromotionPermit = {
      schemaVersion: 1,
      permitId,
      runId: input.runId,
      agentId: input.agentId,
      proposalId: input.proposal.proposalId,
      baseViewId: input.baseView.viewId,
      targetArtifactHash: input.proposal.artifactHash,
      evaluationContextHash: input.evaluationContextHash,
      evidenceDigest: input.evidence.digest,
      nonce: randomUUID(),
      expiresAt: new Date(
        issuedAt.getTime() + Math.max(1, input.ttlMs ?? 60_000),
      ).toISOString(),
      state: "ISSUED",
      issuedAt: issuedAt.toISOString(),
      updatedAt: issuedAt.toISOString(),
    };
    await writeJsonAtomic(this.permitPath(input.controlPath, permitId), permit);
    return permit;
  }

  async claim(input: ClaimPermitInput): Promise<PromotionCapability> {
    return this.enqueue(input.permitId, async () => {
      const permitPath = this.permitPath(input.controlPath, input.permitId);
      const permit = await readJson<PromotionPermit>(permitPath);
      this.assertBindings(permit, input);
      if (permit.state !== "ISSUED") {
        throw new PermitStateError(
          "PERMIT_REPLAY",
          `Permit is already ${permit.state}`,
        );
      }
      if (Date.parse(permit.expiresAt) <= this.now().getTime()) {
        await this.update(input.controlPath, permit, "REVOKED");
        throw new PermitStateError("PERMIT_EXPIRED", "Promotion permit expired");
      }
      const claimPath = permitPath + ".claim";
      await mkdir(path.dirname(claimPath), { recursive: true, mode: 0o700 });
      try {
        const claim = await open(claimPath, "wx", 0o600);
        await claim.writeFile(permit.nonce, "utf8");
        await claim.close();
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EEXIST") {
          throw new PermitStateError(
            "PERMIT_REPLAY",
            "Promotion permit already has a durable claim",
          );
        }
        throw error;
      }
      const consuming = await this.update(
        input.controlPath,
        permit,
        "CONSUMING",
      );
      const proposal = Object.freeze(structuredClone(input.proposal));
      const proposalManifest = Object.freeze(structuredClone(input.proposalManifest));
      const baseView = Object.freeze(structuredClone(input.baseView));
      const frozenPermit = Object.freeze(structuredClone(consuming));
      let locallyConsumed = false;
      return Object.freeze({
        [capabilityBrand]: true as const,
        permit: frozenPermit,
        proposal,
        proposalPath: input.proposalPath,
        proposalManifest,
        baseView,
        consume: async () => {
          if (locallyConsumed) {
            throw new PermitStateError("PERMIT_REPLAY", "Promotion capability was already consumed");
          }
          locallyConsumed = true;
          return this.consumeClaim(
            input.controlPath,
            frozenPermit.permitId,
            frozenPermit.nonce,
          );
        },
      });
    });
  }

  async markConsumed(
    controlPath: string,
    capability: PromotionCapability,
  ): Promise<PromotionPermit> {
    return this.enqueue(capability.permit.permitId, async () => {
      const current = await this.get(
        controlPath,
        capability.permit.permitId,
      );
      if (current.state === "CONSUMED") return current;
      if (current.state !== "CONSUMING") {
        throw new PermitStateError(
          "PERMIT_STATE_INVALID",
          `Cannot consume permit in state ${current.state}`,
        );
      }
      return this.update(controlPath, current, "CONSUMED");
    });
  }

  private async consumeClaim(
    controlPath: string,
    permitId: string,
    nonce: string,
  ): Promise<PromotionPermit> {
    return this.enqueue(permitId, async () => {
      const current = await this.get(controlPath, permitId);
      if (current.nonce !== nonce || current.state !== "CONSUMING") {
        throw new PermitStateError("PERMIT_REPLAY", "Promotion permit is no longer consumable");
      }
      return this.update(controlPath, current, "CONSUMED");
    });
  }

  async revoke(
    controlPath: string,
    permitId: string,
  ): Promise<PromotionPermit> {
    return this.enqueue(permitId, async () => {
      const current = await this.get(controlPath, permitId);
      if (current.state === "REVOKED") return current;
      if (current.state === "CONSUMED") return current;
      return this.update(controlPath, current, "REVOKED");
    });
  }

  async get(controlPath: string, permitId: string): Promise<PromotionPermit> {
    return readJson<PromotionPermit>(this.permitPath(controlPath, permitId));
  }

  private assertBindings(permit: PromotionPermit, input: ClaimPermitInput): void {
    assertStateViewRef(input.baseView);
    assertContained(input.controlPath, input.proposalPath, "proposal path");
    if (
      permit.schemaVersion !== 1 ||
      permit.permitId !== input.permitId ||
      permit.agentId !== input.agentId ||
      permit.proposalId !== input.proposal.proposalId ||
      permit.baseViewId !== input.baseView.viewId ||
      permit.targetArtifactHash !== input.proposal.artifactHash ||
      permit.evaluationContextHash !== input.evaluationContextHash ||
      permit.evidenceDigest !== input.evidenceDigest ||
      input.proposal.baseViewId !== input.baseView.viewId ||
      input.proposal.state !== "SEALED" ||
      input.proposalManifest.schemaVersion !== 2 ||
      input.proposalManifest.hash !== input.proposal.manifestHash ||
      sha256Canonical({
        manifestSchemaVersion: input.proposalManifest.schemaVersion,
        manifestHash: input.proposalManifest.hash,
        entries: input.proposalManifest.entries,
      }) !== input.proposal.artifactHash
    ) {
      throw new PermitStateError(
        "PERMIT_BINDING_MISMATCH",
        "Promotion permit binding mismatch",
      );
    }
  }

  private async update(
    controlPath: string,
    permit: PromotionPermit,
    state: PromotionPermit["state"],
  ): Promise<PromotionPermit> {
    const next = {
      ...permit,
      state,
      updatedAt: this.now().toISOString(),
    };
    await writeJsonAtomic(this.permitPath(controlPath, permit.permitId), next);
    return next;
  }

  private permitPath(controlPath: string, permitId: string): string {
    assertSafeIdentifier(permitId, "permitId");
    const result = path.join(controlPath, "permits", permitId + ".json");
    assertContained(controlPath, result, "promotion permit path");
    return result;
  }

  private async enqueue<T>(permitId: string, operation: () => Promise<T>): Promise<T> {
    const previous = this.queues.get(permitId) ?? Promise.resolve();
    let result!: T;
    const current = previous.then(async () => {
      result = await operation();
    });
    this.queues.set(permitId, current.catch(() => undefined));
    await current;
    return result;
  }
}
