import { chmod, lstat, mkdir, readdir, rename, rm } from "node:fs/promises";
import path from "node:path";
import { readJson, writeJsonAtomic } from "./atomic-json.js";
import {
  assertContained,
  assertSafeIdentifier,
  copyWorkspace,
  pathExists,
} from "./file-ops.js";
import { buildManifest, hashManifestEntries } from "./manifest.js";
import { canonicalJson, sha256Canonical } from "./protocol.js";
import type {
  CommitGatePolicy,
  SealedProposal,
  SnapshotManifest,
} from "./types.js";

export class ProposalSealError extends Error {
  constructor(
    readonly code:
      | "CANDIDATE_INVALID"
      | "CANDIDATE_MUTATED"
      | "SEALED_PAYLOAD_CORRUPT",
    message: string,
  ) {
    super(message);
    this.name = "ProposalSealError";
  }
}

export interface SealProposalInput {
  runId: string;
  agentId: string;
  controlPath: string;
  candidatePath: string;
  baseViewId: string;
  policy: CommitGatePolicy;
  changedPathsDigest: string;
  runtimeTeardownDigest: string;
  expectedCandidateHash?: string;
  sealedAt?: string;
}

export interface ResolvedSealedProposal {
  proposal: SealedProposal;
  payloadPath: string;
  manifest: SnapshotManifest;
}

/** Metadata-only descriptor used to exercise a consumed permit replay fence. */
export interface SealedProposalDescriptor extends ResolvedSealedProposal {}

function classifyManifestFailure(error: unknown): ProposalSealError {
  const message = error instanceof Error ? error.message : String(error);
  if (/^(?:SPECIAL_FILE|SYMLINK_FILE|HARDLINK_FILE|CASEFOLD_PATH_COLLISION|UNICODE_NORMALIZATION_COLLISION):/.test(message)) {
    return new ProposalSealError("CANDIDATE_INVALID", message);
  }
  return new ProposalSealError("CANDIDATE_MUTATED", message);
}

export class SealedProposalStore {
  async seal(input: SealProposalInput): Promise<ResolvedSealedProposal> {
    assertSafeIdentifier(input.runId, "runId");
    assertSafeIdentifier(input.agentId, "agentId");
    assertContained(input.controlPath, input.candidatePath, "candidate path");
    let sourceBefore: SnapshotManifest;
    try {
      sourceBefore = await buildManifest(input.candidatePath, input.policy);
    } catch (error) {
      throw classifyManifestFailure(error);
    }
    if (input.expectedCandidateHash && sourceBefore.hash !== input.expectedCandidateHash) {
      throw new ProposalSealError(
        "CANDIDATE_MUTATED",
        "CANDIDATE_CHANGED_BEFORE_SEAL",
      );
    }

    const artifactHash = sha256Canonical({
      manifestSchemaVersion: sourceBefore.schemaVersion,
      manifestHash: sourceBefore.hash,
      entries: sourceBefore.entries,
    });
    const proposalId =
      "p-" +
      sha256Canonical({
        runId: input.runId,
        agentId: input.agentId,
        baseViewId: input.baseViewId,
        artifactHash,
        changedPathsDigest: input.changedPathsDigest,
        runtimeTeardownDigest: input.runtimeTeardownDigest,
      });
    const payloadPath = this.payloadPath(input.controlPath, artifactHash, proposalId);
    const metadataPath = this.metadataPath(input.controlPath, proposalId);

    if (await pathExists(metadataPath)) {
      const existing = await readJson<SealedProposal>(metadataPath);
      return this.resolve(input.controlPath, existing.proposalId, input.policy);
    }

    const tempPath = path.join(
      input.controlPath,
      "sealed",
      "tmp",
      `${input.runId}-${proposalId.slice(-12)}`,
    );
    assertContained(input.controlPath, tempPath, "sealed temp path");
    await rm(tempPath, { recursive: true, force: true });
    try {
      await copyWorkspace(input.candidatePath, tempPath, input.policy, {
        include: new Set(["versioned", "platformManaged"]),
      });
      const [sourceAfter, payloadManifest] = await Promise.all([
        buildManifest(input.candidatePath, input.policy),
        buildManifest(tempPath, input.policy),
      ]);
      if (
        sourceBefore.hash !== sourceAfter.hash ||
        sourceBefore.hash !== payloadManifest.hash
      ) {
        throw new ProposalSealError(
          "CANDIDATE_MUTATED",
          "CANDIDATE_MUTATED_DURING_SEAL",
        );
      }
      const copiedArtifactHash = sha256Canonical({
        manifestSchemaVersion: payloadManifest.schemaVersion,
        manifestHash: payloadManifest.hash,
        entries: payloadManifest.entries,
      });
      if (copiedArtifactHash !== artifactHash) {
        throw new ProposalSealError(
          "CANDIDATE_MUTATED",
          "SEALED_ARTIFACT_DIGEST_MISMATCH",
        );
      }
      // The gate owns the payload from this point forward. It is never exposed
      // through a writable Runtime mount; both verifier and promotion resolve
      // this same read-only content-addressed tree.
      await mkdir(path.dirname(payloadPath), { recursive: true, mode: 0o700 });
      await rename(tempPath, payloadPath);
      // Publish metadata only after the content-addressed payload has lost all
      // write bits. The intended modes remain in a signed manifest sidecar and
      // are restored only into transaction-owned staging.
      await makeReadonly(payloadPath);
      const proposal: SealedProposal = {
        schemaVersion: 1,
        proposalId,
        runId: input.runId,
        agentId: input.agentId,
        baseViewId: input.baseViewId,
        artifactHash,
        manifestHash: payloadManifest.hash,
        changedPathsDigest: input.changedPathsDigest,
        runtimeTeardownDigest: input.runtimeTeardownDigest,
        state: "SEALED",
        sealedAt: input.sealedAt ?? new Date().toISOString(),
      };
      await writeJsonAtomic(this.manifestPath(input.controlPath, proposalId), payloadManifest);
      await writeJsonAtomic(metadataPath, proposal);
      return { proposal, payloadPath, manifest: payloadManifest };
    } catch (error) {
      await makeMutable(tempPath).catch(() => undefined);
      await rm(tempPath, { recursive: true, force: true }).catch(() => undefined);
      await makeMutable(payloadPath).catch(() => undefined);
      await rm(payloadPath, { recursive: true, force: true }).catch(() => undefined);
      if (error instanceof ProposalSealError) throw error;
      throw classifyManifestFailure(error);
    }
  }

  async resolve(
    controlPath: string,
    proposalId: string,
    policy: CommitGatePolicy,
  ): Promise<ResolvedSealedProposal> {
    assertSafeIdentifier(proposalId, "proposalId");
    const proposal = await readJson<SealedProposal>(
      this.metadataPath(controlPath, proposalId),
    );
    if (
      proposal.schemaVersion !== 1 ||
      proposal.proposalId !== proposalId ||
      proposal.state !== "SEALED"
    ) {
      throw new ProposalSealError(
        "SEALED_PAYLOAD_CORRUPT",
        "SEALED_PROPOSAL_METADATA_INVALID",
      );
    }
    const payloadPath = this.payloadPath(
      controlPath,
      proposal.artifactHash,
      proposalId,
    );
    assertContained(controlPath, payloadPath, "sealed proposal payload");
    let manifest: SnapshotManifest;
    try {
      manifest = await readJson<SnapshotManifest>(
        this.manifestPath(controlPath, proposalId),
      );
      await assertReadonlySealedPayload(payloadPath, policy, manifest);
    } catch (error) {
      throw new ProposalSealError(
        "SEALED_PAYLOAD_CORRUPT",
        error instanceof Error ? error.message : String(error),
      );
    }
    const artifactHash = sha256Canonical({
      manifestSchemaVersion: manifest.schemaVersion,
      manifestHash: manifest.hash,
      entries: manifest.entries,
    });
    if (
      manifest.hash !== proposal.manifestHash ||
      artifactHash !== proposal.artifactHash
    ) {
      throw new ProposalSealError(
        "SEALED_PAYLOAD_CORRUPT",
        "SEALED_PAYLOAD_DIGEST_MISMATCH",
      );
    }
    return { proposal, payloadPath, manifest };
  }

  async describe(
    controlPath: string,
    proposalId: string,
  ): Promise<SealedProposalDescriptor> {
    assertSafeIdentifier(proposalId, "proposalId");
    const proposal = await readJson<SealedProposal>(
      this.metadataPath(controlPath, proposalId),
    );
    if (
      proposal.schemaVersion !== 1 ||
      proposal.proposalId !== proposalId ||
      !["SEALED", "DESTROYED"].includes(proposal.state)
    ) {
      throw new ProposalSealError(
        "SEALED_PAYLOAD_CORRUPT",
        "SEALED_PROPOSAL_METADATA_INVALID",
      );
    }
    const manifest = await readJson<SnapshotManifest>(
      this.manifestPath(controlPath, proposalId),
    );
    const artifactHash = sha256Canonical({
      manifestSchemaVersion: manifest.schemaVersion,
      manifestHash: manifest.hash,
      entries: manifest.entries,
    });
    if (
      manifest.schemaVersion !== 2 ||
      manifest.hash !== proposal.manifestHash ||
      artifactHash !== proposal.artifactHash
    ) {
      throw new ProposalSealError(
        "SEALED_PAYLOAD_CORRUPT",
        "SEALED_PROPOSAL_DESCRIPTOR_DIGEST_MISMATCH",
      );
    }
    return {
      proposal,
      manifest,
      payloadPath: this.payloadPath(
        controlPath,
        proposal.artifactHash,
        proposal.proposalId,
      ),
    };
  }

  async destroy(
    controlPath: string,
    proposalId: string,
  ): Promise<void> {
    assertSafeIdentifier(proposalId, "proposalId");
    const metadataPath = this.metadataPath(controlPath, proposalId);
    if (!(await pathExists(metadataPath))) return;
    const proposal = await readJson<SealedProposal>(metadataPath);
    if (proposal.state === "DESTROYED") return;
    const payloadPath = this.payloadPath(
      controlPath,
      proposal.artifactHash,
      proposal.proposalId,
    );
    await makeMutable(payloadPath).catch(() => undefined);
    await rm(payloadPath, { recursive: true, force: true });
    await writeJsonAtomic(metadataPath, {
      ...proposal,
      state: "DESTROYED" as const,
    });
  }

  private metadataPath(controlPath: string, proposalId: string): string {
    const result = path.join(controlPath, "proposals", proposalId + ".json");
    assertContained(controlPath, result, "proposal metadata path");
    return result;
  }

  private manifestPath(controlPath: string, proposalId: string): string {
    const result = path.join(controlPath, "proposals", proposalId + ".manifest.json");
    assertContained(controlPath, result, "proposal manifest path");
    return result;
  }

  private payloadPath(
    controlPath: string,
    artifactHash: string,
    proposalId: string,
  ): string {
    if (!/^[a-f0-9]{64}$/.test(artifactHash)) {
      throw new Error("Proposal artifact hash is invalid");
    }
    const result = path.join(
      controlPath,
      "sealed",
      "payloads",
      artifactHash,
      proposalId,
    );
    assertContained(controlPath, result, "proposal payload path");
    return result;
  }
}

export async function assertReadonlySealedPayload(
  payloadPath: string,
  policy: CommitGatePolicy,
  manifest: SnapshotManifest,
): Promise<void> {
  const rootBefore = await lstat(payloadPath);
  if (
    !rootBefore.isDirectory() ||
    rootBefore.isSymbolicLink() ||
    (rootBefore.mode & 0o222) !== 0
  ) {
    throw new ProposalSealError(
      "SEALED_PAYLOAD_CORRUPT",
      "SEALED_PAYLOAD_ROOT_NOT_READONLY",
    );
  }
  const physical = await buildManifest(payloadPath, policy);
  const expectedByPath = new Map(manifest.entries.map((entry) => [entry.path, entry]));
  const normalizedEntries = physical.entries.map((entry) => {
    const expected = expectedByPath.get(entry.path);
    if (
      !expected ||
      entry.type !== expected.type ||
      entry.size !== expected.size ||
      entry.contentHash !== expected.contentHash ||
      entry.linkTarget !== expected.linkTarget ||
      entry.pathClass !== expected.pathClass ||
      entry.mode !== (expected.mode & ~0o222)
    ) {
      throw new ProposalSealError(
        "SEALED_PAYLOAD_CORRUPT",
        "SEALED_PAYLOAD_ENTRY_MISMATCH:" + entry.path,
      );
    }
    return { ...entry, mode: expected.mode };
  });
  if (normalizedEntries.length !== manifest.entries.length) {
    throw new ProposalSealError(
      "SEALED_PAYLOAD_CORRUPT",
      "SEALED_PAYLOAD_ENTRY_COUNT_MISMATCH",
    );
  }
  const normalizedHash = hashManifestEntries(normalizedEntries);
  if (manifest.schemaVersion !== 2 || manifest.hash !== normalizedHash) {
    throw new ProposalSealError(
      "SEALED_PAYLOAD_CORRUPT",
      "SEALED_MANIFEST_DIGEST_MISMATCH",
    );
  }
  const rootAfter = await lstat(payloadPath);
  if (
    rootAfter.dev !== rootBefore.dev ||
    rootAfter.ino !== rootBefore.ino ||
    rootAfter.mode !== rootBefore.mode ||
    rootAfter.ctimeMs !== rootBefore.ctimeMs ||
    (rootAfter.mode & 0o222) !== 0
  ) {
    throw new ProposalSealError(
      "SEALED_PAYLOAD_CORRUPT",
      "SEALED_PAYLOAD_ROOT_CHANGED_DURING_VALIDATION",
    );
  }
}

async function makeReadonly(root: string): Promise<void> {
  const rootStats = await lstat(root);
  if (!rootStats.isDirectory() || rootStats.isSymbolicLink()) {
    throw new Error("SEALED_PAYLOAD_ROOT_INVALID");
  }
  const entries = await readdir(root, { withFileTypes: true });
  for (const entry of entries) {
    const item = path.join(root, entry.name);
    const stats = await lstat(item);
    if (stats.isSymbolicLink()) {
      throw new Error("SEALED_PAYLOAD_SYMLINK:" + item);
    }
    if (stats.isDirectory()) {
      await makeReadonly(item);
      await chmod(item, (stats.mode & 0o777) & ~0o222);
    } else if (stats.isFile()) {
      await chmod(item, (stats.mode & 0o777) & ~0o222);
    } else {
      throw new Error("SEALED_PAYLOAD_SPECIAL_FILE:" + item);
    }
  }
  await chmod(root, (rootStats.mode & 0o777) & ~0o222);
}

async function makeMutable(root: string): Promise<void> {
  if (!(await pathExists(root))) return;
  await chmod(root, 0o700);
  const entries = await readdir(root, { withFileTypes: true });
  for (const entry of entries) {
    const item = path.join(root, entry.name);
    if (entry.isDirectory()) await makeMutable(item);
    else await chmod(item, 0o600);
  }
}

export function runtimeTeardownDigest(value: unknown): string {
  return sha256Canonical({ schemaVersion: 1, teardown: canonicalJson(value) });
}
