import { randomUUID } from "node:crypto";
import { mkdir, open } from "node:fs/promises";
import path from "node:path";
import { readJson, writeJsonAtomic } from "./atomic-json.js";
import { assertContained, assertSafeIdentifier } from "./file-ops.js";
import type { RollbackPermit } from "./types.js";

const rollbackCapabilityBrand: unique symbol = Symbol("CommitGateRollbackCapability");

export interface RollbackCapability {
  readonly [rollbackCapabilityBrand]: true;
  readonly permit: RollbackPermit;
  readonly snapshotPath: string;
  /** Atomic local+durable one-shot consumption; invoked by WorkspaceTransaction before swap. */
  readonly consume: () => Promise<RollbackPermit>;
}

export interface IssueRollbackPermitInput {
  runId: string;
  agentId: string;
  controlPath: string;
  targetVersionId: string;
  targetSnapshotHash: string;
  expectedHeadVersionId: string;
  baseHash: string;
  ttlMs?: number;
}

export interface ClaimRollbackPermitInput {
  controlPath: string;
  rollbackPermitId: string;
  snapshotPath: string;
  targetVersionId: string;
  targetSnapshotHash: string;
  expectedHeadVersionId: string;
  baseHash: string;
}

export class RollbackPermitStore {
  private readonly queues = new Map<string, Promise<void>>();

  constructor(private readonly now: () => Date = () => new Date()) {}

  async issue(input: IssueRollbackPermitInput): Promise<RollbackPermit> {
    assertSafeIdentifier(input.runId, "runId");
    assertSafeIdentifier(input.agentId, "agentId");
    assertSafeIdentifier(input.targetVersionId, "targetVersionId");
    assertSafeIdentifier(input.expectedHeadVersionId, "expectedHeadVersionId");
    const issuedAt = this.now();
    const permit: RollbackPermit = {
      schemaVersion: 1,
      rollbackPermitId: `rk-${randomUUID()}`,
      runId: input.runId,
      agentId: input.agentId,
      targetVersionId: input.targetVersionId,
      targetSnapshotHash: input.targetSnapshotHash,
      expectedHeadVersionId: input.expectedHeadVersionId,
      baseHash: input.baseHash,
      nonce: randomUUID(),
      expiresAt: new Date(
        issuedAt.getTime() + Math.max(1, input.ttlMs ?? 60_000),
      ).toISOString(),
      state: "ISSUED",
      issuedAt: issuedAt.toISOString(),
      updatedAt: issuedAt.toISOString(),
    };
    await writeJsonAtomic(
      this.permitPath(input.controlPath, permit.rollbackPermitId),
      permit,
    );
    return permit;
  }

  async claim(input: ClaimRollbackPermitInput): Promise<RollbackCapability> {
    return this.enqueue(input.rollbackPermitId, async () => {
      assertContained(input.controlPath, input.snapshotPath, "rollback snapshot path");
      const permitPath = this.permitPath(input.controlPath, input.rollbackPermitId);
      const permit = await readJson<RollbackPermit>(permitPath);
      if (
        permit.schemaVersion !== 1 ||
        permit.rollbackPermitId !== input.rollbackPermitId ||
        permit.targetVersionId !== input.targetVersionId ||
        permit.targetSnapshotHash !== input.targetSnapshotHash ||
        permit.expectedHeadVersionId !== input.expectedHeadVersionId ||
        permit.baseHash !== input.baseHash
      ) {
        throw new Error("ROLLBACK_PERMIT_BINDING_MISMATCH");
      }
      if (permit.state !== "ISSUED") throw new Error("ROLLBACK_PERMIT_REPLAY");
      if (Date.parse(permit.expiresAt) <= this.now().getTime()) {
        await this.update(input.controlPath, permit, "REVOKED");
        throw new Error("ROLLBACK_PERMIT_EXPIRED");
      }
      const claimPath = permitPath + ".claim";
      await mkdir(path.dirname(claimPath), { recursive: true, mode: 0o700 });
      try {
        const claim = await open(claimPath, "wx", 0o600);
        await claim.writeFile(permit.nonce, "utf8");
        await claim.close();
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EEXIST") {
          throw new Error("ROLLBACK_PERMIT_REPLAY");
        }
        throw error;
      }
      const consuming = await this.update(input.controlPath, permit, "CONSUMING");
      const frozenPermit = Object.freeze(structuredClone(consuming));
      let locallyConsumed = false;
      return Object.freeze({
        [rollbackCapabilityBrand]: true as const,
        permit: frozenPermit,
        snapshotPath: input.snapshotPath,
        consume: async () => {
          if (locallyConsumed) throw new Error("ROLLBACK_PERMIT_REPLAY");
          locallyConsumed = true;
          return this.consumeClaim(
            input.controlPath,
            frozenPermit.rollbackPermitId,
            frozenPermit.nonce,
          );
        },
      });
    });
  }

  async markConsumed(
    controlPath: string,
    capability: RollbackCapability,
  ): Promise<RollbackPermit> {
    return this.enqueue(capability.permit.rollbackPermitId, async () => {
      const permit = await readJson<RollbackPermit>(
        this.permitPath(controlPath, capability.permit.rollbackPermitId),
      );
      if (permit.state === "CONSUMED") return permit;
      if (permit.state !== "CONSUMING") throw new Error("ROLLBACK_PERMIT_STATE_INVALID");
      return this.update(controlPath, permit, "CONSUMED");
    });
  }

  async get(controlPath: string, rollbackPermitId: string): Promise<RollbackPermit> {
    return readJson<RollbackPermit>(this.permitPath(controlPath, rollbackPermitId));
  }

  async revoke(controlPath: string, rollbackPermitId: string): Promise<RollbackPermit> {
    return this.enqueue(rollbackPermitId, async () => {
      const permit = await this.get(controlPath, rollbackPermitId);
      if (permit.state === "REVOKED" || permit.state === "CONSUMED") return permit;
      return this.update(controlPath, permit, "REVOKED");
    });
  }

  private async consumeClaim(
    controlPath: string,
    rollbackPermitId: string,
    nonce: string,
  ): Promise<RollbackPermit> {
    return this.enqueue(rollbackPermitId, async () => {
      const permit = await this.get(controlPath, rollbackPermitId);
      if (permit.nonce !== nonce || permit.state !== "CONSUMING") {
        throw new Error("ROLLBACK_PERMIT_REPLAY");
      }
      return this.update(controlPath, permit, "CONSUMED");
    });
  }

  private async update(
    controlPath: string,
    permit: RollbackPermit,
    state: RollbackPermit["state"],
  ): Promise<RollbackPermit> {
    const next = { ...permit, state, updatedAt: this.now().toISOString() };
    await writeJsonAtomic(
      this.permitPath(controlPath, permit.rollbackPermitId),
      next,
    );
    return next;
  }

  private permitPath(controlPath: string, rollbackPermitId: string): string {
    assertSafeIdentifier(rollbackPermitId, "rollbackPermitId");
    const permitPath = path.join(
      controlPath,
      "rollback-permits",
      rollbackPermitId + ".json",
    );
    assertContained(controlPath, permitPath, "rollback permit path");
    return permitPath;
  }

  private async enqueue<T>(key: string, operation: () => Promise<T>): Promise<T> {
    const previous = this.queues.get(key) ?? Promise.resolve();
    let result!: T;
    const current = previous.then(async () => {
      result = await operation();
    });
    this.queues.set(key, current.catch(() => undefined));
    await current;
    return result;
  }
}
