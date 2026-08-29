import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  verifyAuthorityReceiptProof,
  type AuthorityReceiptProofBundle,
} from "../research/receipt-proof.js";
import { computeStateViewId } from "../state-view.js";
import type { StateViewRef } from "../types.js";
import type { TransitionEvent } from "../transition-log.js";
import type { EvidenceBlobRef } from "./evidence-blob-store.js";

export type ProjectedPermitState = "ISSUED" | "CONSUMING" | "CONSUMED" | "REVOKED";

export interface ProjectedProposal {
  proposalId: string;
  transitionId: string;
  baseViewId: string;
  artifactHash: string;
  manifestHash: string;
  changedPathsDigest: string;
  runtimeTeardownDigest: string | null;
  verifierInputHash: string | null;
  changedPaths: string[];
  staticFailures: string[];
  state: "SEALED" | "DESTROYED";
  exportVolumeIds: string[];
}

export interface ProjectedEvidence {
  proposalId: string;
  transitionId: string;
  evaluationContextHash: string;
  evidenceDigest: string;
  verifierInputHash: string | null;
  checkResultsHash: string | null;
  coverage: "complete" | "partial" | "unavailable";
  requiredChecksPassed: boolean;
  /** Null only for legacy V1 events whose redacted check list was inline. */
  evidenceBlob: EvidenceBlobRef | null;
  checkCount: number;
  /** V2 values are hydrated from evidenceBlob by TransitionWorker.projection(). */
  checks: Array<{
    id: string;
    status: "PASS" | "FAIL" | "ERROR" | "SKIPPED";
    exitCode: number | null;
    durationMs: number;
    outputHash: string;
    timedOut: boolean;
  }>;
  sourceRevision: string | null;
  policyHash: string | null;
}

export interface ProjectedPermit {
  permitId: string;
  transitionId: string;
  proposalId: string;
  baseViewId: string;
  targetArtifactHash: string;
  evaluationContextHash: string;
  evidenceDigest: string;
  expiresAt: string;
  state: ProjectedPermitState;
}

export interface ProjectedVersion {
  versionId: string;
  transitionId: string;
  kind: "INITIAL" | "AGENT_COMMIT" | "ROLLBACK";
  viewId: string;
  generation: number;
  workspaceHash: string;
  snapshotId: string;
  receiptId: string | null;
  rollbackTargetVersionId: string | null;
}

export interface ProjectedTerminalReceipt {
  receiptId: string;
  transitionId: string;
  decision: "COMMITTED" | "QUARANTINED" | "CONFLICTED" | "ABORTED";
  viewId: string | null;
  eventId: string;
  sequence: number;
  view: StateViewRef;
  workspaceHash: string;
  /** Authority HEAD observed immediately before this transition's disposition. */
  dispositionBaseViewId?: string | null;
  dispositionBaseGeneration?: number | null;
  dispositionBaseWorkspaceHash?: string | null;
  reasonCodes: string[];
}

export interface ProjectedReceiptProof {
  receiptId: string;
  transitionId: string;
  terminalEventId: string;
  proofEventId: string;
  sequence: number;
  bundle: AuthorityReceiptProofBundle;
}

export interface ProjectedRuntimeTeardown {
  schemaVersion: 1;
  runId: string;
  agentId: string;
  runLeaseId: string;
  sessionEpoch: number;
  scope: "AGENT" | "ALL";
  containerExited: true;
  containerRemoved: true;
  mountsReleased: true;
  source: "runtime-attestation" | "broker-reconciliation";
  digest: string;
  eventId: string;
  sequence: number;
}

export interface ProjectedTransition {
  transitionId: string;
  kind: "AGENT_COMMIT" | "ROLLBACK";
  state:
    | "PREPARED"
    | "SEALED"
    | "EVIDENCED"
    | "PERMITTED"
    | "CONSUMING"
    | "APPLIED"
    | "ACKNOWLEDGED"
    | "CANCELLED"
    | "ROLLED_BACK"
    | "REPAIRED";
  /** Present for Agent runs admitted through prepareRun; null for legacy and rollback events. */
  runId: string | null;
  runLeaseId: string | null;
  runtimeSessionEpoch: number | null;
  candidateVolumeId: string | null;
  baseViewId: string | null;
  baseWorkspaceHash: string;
  baseGeneration: number;
  appliedView: StateViewRef | null;
  appliedWorkspaceHash: string | null;
  proposalId: string | null;
  permitId: string | null;
  artifactsDestroyed: boolean;
  runtimeTeardownAgent: ProjectedRuntimeTeardown | null;
  runtimeTeardownAll: ProjectedRuntimeTeardown | null;
}

export interface WorkerProjection {
  schemaVersion: 2;
  agentId: string;
  head: {
    view: StateViewRef;
    workspaceHash: string;
    lastAppliedEventId: string;
    lastAppliedSequence: number;
  } | null;
  proposals: Record<string, ProjectedProposal>;
  evidence: Record<string, ProjectedEvidence>;
  permits: Record<string, ProjectedPermit>;
  transitions: Record<string, ProjectedTransition>;
  versions: ProjectedVersion[];
  terminalReceipts: ProjectedTerminalReceipt[];
  receiptProofs: Record<string, ProjectedReceiptProof>;
  archived: boolean;
  lastEventId: string | null;
  lastSequence: number;
  digest: string;
}

export interface WorkerHeadMarker {
  schemaVersion: 1;
  agentId: string;
  lastAppliedEventId: string | null;
  lastAppliedSequence: number;
  viewId: string | null;
  workspaceHash: string | null;
  generation: number | null;
  projectionDigest: string;
}

const sha256 = (value: unknown): string =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");

const requiredString = (payload: Record<string, unknown>, key: string): string => {
  const value = payload[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`TRANSITION_EVENT_PAYLOAD_INVALID:${key}`);
  }
  return value;
};

const assertProjectedView = (value: unknown): StateViewRef => {
  if (!value || typeof value !== "object") {
    throw new Error("TRANSITION_EVENT_VIEW_INVALID");
  }
  const view = value as StateViewRef;
  const { schemaVersion: _schemaVersion, viewId, ...input } = view;
  if (view.schemaVersion !== 1 || computeStateViewId(input) !== viewId) {
    throw new Error("TRANSITION_EVENT_VIEW_INVALID");
  }
  return view;
};

const transitionFor = (
  projection: WorkerProjection,
  transitionId: string,
): ProjectedTransition => {
  const transition = projection.transitions[transitionId];
  if (!transition) throw new Error(`TRANSITION_EVENT_ORDER_INVALID:${transitionId}`);
  return transition;
};

/** Rebuilds all P1 facts solely from the verified immutable event chain. */
export function rebuildWorkerProjection(
  agentId: string,
  events: readonly TransitionEvent[],
): WorkerProjection {
  const projection: WorkerProjection = {
    schemaVersion: 2,
    agentId,
    head: null,
    proposals: {},
    evidence: {},
    permits: {},
    transitions: {},
    versions: [],
    terminalReceipts: [],
    receiptProofs: {},
    archived: false,
    lastEventId: null,
    lastSequence: 0,
    digest: "",
  };

  for (const event of events) {
    if (event.agentId !== agentId) throw new Error("TRANSITION_EVENT_AGENT_MISMATCH");
    const payload = event.payload as Record<string, unknown>;
    switch (event.type) {
      case "AGENT_INITIALIZATION_PREPARED":
      case "LEGACY_ADOPTION_PREPARED":
      case "PROPOSAL_SEAL_PREPARED":
      case "PROPOSAL_EXPORT_PREPARED":
      case "PLATFORM_STATE_REGENERATION_PREPARED":
      case "AGENT_ARCHIVE_PREPARED":
        // Durable intents deliberately do not advance a projected fact. The
        // Worker recovery pass must first make the bound filesystem mutation
        // true, then append the existing terminal fact below. Keeping intents
        // projection-neutral prevents a pre-effect crash from manufacturing a
        // HEAD, proposal, export, or archive that never existed.
        break;
      case "AGENT_INITIALIZED":
      case "LEGACY_STATE_ADOPTED": {
        if (projection.head || projection.versions.length > 0) {
          throw new Error("AGENT_ALREADY_INITIALIZED");
        }
        const view = payload.view as StateViewRef;
        const workspaceHash = requiredString(payload, "workspaceHash");
        const versionId = requiredString(payload, "versionId");
        projection.head = {
          view,
          workspaceHash,
          lastAppliedEventId: event.eventId,
          lastAppliedSequence: event.sequence,
        };
        projection.versions.push({
          versionId,
          transitionId: event.transitionId,
          kind: "INITIAL",
          viewId: view.viewId,
          generation: view.generation,
          workspaceHash,
          snapshotId: requiredString(payload, "snapshotId"),
          receiptId: null,
          rollbackTargetVersionId: null,
        });
        break;
      }
      case "TRANSITION_PREPARED": {
        if (projection.transitions[event.transitionId]) {
          throw new Error(`TRANSITION_ALREADY_PREPARED:${event.transitionId}`);
        }
        const kind = requiredString(payload, "kind");
        if (kind !== "AGENT_COMMIT" && kind !== "ROLLBACK") {
          throw new Error("TRANSITION_KIND_INVALID");
        }
        projection.transitions[event.transitionId] = {
          transitionId: event.transitionId,
          kind,
          state: "PREPARED",
          runId: typeof payload.runId === "string" ? payload.runId : null,
          runLeaseId: typeof payload.runLeaseId === "string" ? payload.runLeaseId : null,
          runtimeSessionEpoch:
            Number.isSafeInteger(payload.sessionEpoch) && Number(payload.sessionEpoch) >= 0
              ? Number(payload.sessionEpoch)
              : null,
          candidateVolumeId:
            typeof payload.candidateVolumeId === "string"
              ? payload.candidateVolumeId
              : null,
          baseViewId:
            typeof payload.baseViewId === "string" ? payload.baseViewId : null,
          baseWorkspaceHash: requiredString(payload, "baseWorkspaceHash"),
          baseGeneration: Number(payload.baseGeneration),
          appliedView: null,
          appliedWorkspaceHash: null,
          proposalId: null,
          permitId: null,
          artifactsDestroyed: false,
          runtimeTeardownAgent: null,
          runtimeTeardownAll: null,
        };
        break;
      }
      case "RUNTIME_TEARDOWN_RECORDED": {
        const transition = transitionFor(projection, event.transitionId);
        if (!transition.runId || !transition.runLeaseId) {
          throw new Error("RUNTIME_TEARDOWN_NON_PRODUCT_TRANSITION");
        }
        const scope = requiredString(payload, "scope");
        if (scope !== "AGENT" && scope !== "ALL") {
          throw new Error("RUNTIME_TEARDOWN_SCOPE_INVALID");
        }
        const sessionEpoch = Number(payload.sessionEpoch);
        if (
          requiredString(payload, "runId") !== transition.runId ||
          requiredString(payload, "agentId") !== agentId ||
          requiredString(payload, "runLeaseId") !== transition.runLeaseId ||
          !Number.isSafeInteger(sessionEpoch) ||
          sessionEpoch < 0 ||
          (transition.runtimeSessionEpoch !== null &&
            sessionEpoch !== transition.runtimeSessionEpoch) ||
          payload.containerExited !== true ||
          payload.containerRemoved !== true ||
          payload.mountsReleased !== true
        ) {
          throw new Error("RUNTIME_TEARDOWN_BINDING_INVALID");
        }
        const source = requiredString(payload, "source");
        if (source !== "runtime-attestation" && source !== "broker-reconciliation") {
          throw new Error("RUNTIME_TEARDOWN_SOURCE_INVALID");
        }
        const record: ProjectedRuntimeTeardown = {
          schemaVersion: 1,
          runId: transition.runId,
          agentId,
          runLeaseId: transition.runLeaseId,
          sessionEpoch,
          scope,
          containerExited: true,
          containerRemoved: true,
          mountsReleased: true,
          source,
          digest: requiredString(payload, "digest"),
          eventId: event.eventId,
          sequence: event.sequence,
        };
        if (scope === "AGENT") transition.runtimeTeardownAgent = record;
        else transition.runtimeTeardownAll = record;
        break;
      }
      case "RUN_CANCELLED": {
        const transition = transitionFor(projection, event.transitionId);
        if (!["PREPARED", "SEALED", "EVIDENCED", "PERMITTED", "CANCELLED"].includes(
          transition.state,
        )) {
          throw new Error("RUN_CANCELLATION_ORDER_INVALID");
        }
        if (transition.runId && requiredString(payload, "runId") !== transition.runId) {
          throw new Error("RUN_CANCELLATION_BINDING_MISMATCH");
        }
        if (
          transition.runLeaseId &&
          requiredString(payload, "runLeaseId") !== transition.runLeaseId
        ) {
          throw new Error("RUN_CANCELLATION_BINDING_MISMATCH");
        }
        if (transition.permitId) {
          const permit = projection.permits[transition.permitId];
          if (permit && permit.state === "ISSUED") permit.state = "REVOKED";
        }
        transition.state = "CANCELLED";
        break;
      }
      case "PROPOSAL_SEALED": {
        const transition = transitionFor(projection, event.transitionId);
        if (transition.state !== "PREPARED") throw new Error("PROPOSAL_SEAL_ORDER_INVALID");
        const proposalId = requiredString(payload, "proposalId");
        const proposal: ProjectedProposal = {
          proposalId,
          transitionId: event.transitionId,
          baseViewId: requiredString(payload, "baseViewId"),
          artifactHash: requiredString(payload, "artifactHash"),
          manifestHash:
            typeof payload.manifestHash === "string"
              ? payload.manifestHash
              : requiredString(payload, "artifactHash"),
          changedPathsDigest:
            typeof payload.changedPathsDigest === "string"
              ? payload.changedPathsDigest
              : sha256(Array.isArray(payload.changedPaths) ? payload.changedPaths : []),
          runtimeTeardownDigest:
            typeof payload.runtimeTeardownDigest === "string"
              ? payload.runtimeTeardownDigest
              : null,
          verifierInputHash: null,
          changedPaths: Array.isArray(payload.changedPaths)
            ? payload.changedPaths.filter((value): value is string => typeof value === "string")
            : [],
          staticFailures: Array.isArray(payload.staticFailures)
            ? payload.staticFailures.filter((value): value is string => typeof value === "string")
            : [],
          state: "SEALED",
          exportVolumeIds: [],
        };
        projection.proposals[proposalId] = proposal;
        transition.proposalId = proposalId;
        transition.state = "SEALED";
        break;
      }
      case "PROPOSAL_EXPORTED": {
        const transition = transitionFor(projection, event.transitionId);
        const proposalId = requiredString(payload, "proposalId");
        const proposal = projection.proposals[proposalId];
        if (!proposal || transition.proposalId !== proposalId || proposal.state !== "SEALED") {
          throw new Error("PROPOSAL_EXPORT_ORDER_INVALID");
        }
        const exportVolumeId = requiredString(payload, "exportVolumeId");
        if (!proposal.exportVolumeIds.includes(exportVolumeId)) {
          proposal.exportVolumeIds.push(exportVolumeId);
          proposal.exportVolumeIds.sort();
        }
        break;
      }
      case "RUN_ARTIFACTS_DESTROYED": {
        const transition = transitionFor(projection, event.transitionId);
        const proposalId =
          typeof payload.proposalId === "string" ? payload.proposalId : null;
        if (proposalId) {
          const proposal = projection.proposals[proposalId];
          if (!proposal || transition.proposalId !== proposalId) {
            throw new Error("PROPOSAL_DESTROY_ORDER_INVALID");
          }
          proposal.state = "DESTROYED";
        }
        transition.artifactsDestroyed = true;
        break;
      }
      case "EVIDENCE_RECORDED": {
        const transition = transitionFor(projection, event.transitionId);
        if (transition.state !== "SEALED") throw new Error("EVIDENCE_ORDER_INVALID");
        if (requiredString(payload, "proposalId") !== transition.proposalId) {
          throw new Error("EVIDENCE_PROPOSAL_MISMATCH");
        }
        requiredString(payload, "evaluationContextHash");
        requiredString(payload, "evidenceDigest");
        const proposalId = requiredString(payload, "proposalId");
        const isBlobBacked = payload.schemaVersion === 2;
        const projectedChecks = !isBlobBacked && Array.isArray(payload.checks)
          ? payload.checks.filter(
              (value): value is ProjectedEvidence["checks"][number] =>
                Boolean(value) && typeof value === "object" && typeof value.id === "string",
            )
          : [];
        const evidence: ProjectedEvidence = {
          proposalId,
          transitionId: event.transitionId,
          evaluationContextHash: requiredString(payload, "evaluationContextHash"),
          evidenceDigest: requiredString(payload, "evidenceDigest"),
          verifierInputHash:
            typeof payload.verifierInputHash === "string" ? payload.verifierInputHash : null,
          checkResultsHash:
            typeof payload.checkResultsHash === "string" ? payload.checkResultsHash : null,
          coverage:
            payload.coverage === "complete" ||
            payload.coverage === "partial" ||
            payload.coverage === "unavailable"
              ? payload.coverage
              : "unavailable",
          requiredChecksPassed: payload.requiredChecksPassed === true,
          evidenceBlob: isBlobBacked
            ? {
                schemaVersion: 1,
                blobId: requiredString(payload, "evidenceBlobHash"),
                sizeBytes: Number(payload.evidenceBlobSize),
              }
            : null,
          checkCount: isBlobBacked ? Number(payload.checkCount) : projectedChecks.length,
          checks: projectedChecks,
          sourceRevision:
            typeof payload.sourceRevision === "string"
              ? payload.sourceRevision
              : payload.evaluationContext &&
                  typeof payload.evaluationContext === "object" &&
                  typeof (payload.evaluationContext as Record<string, unknown>).sourceRevision === "string"
                ? String((payload.evaluationContext as Record<string, unknown>).sourceRevision)
                : null,
          policyHash:
            typeof payload.policyHash === "string"
              ? payload.policyHash
              : payload.evaluationContext &&
                  typeof payload.evaluationContext === "object" &&
                  typeof (payload.evaluationContext as Record<string, unknown>).policyHash === "string"
                ? String((payload.evaluationContext as Record<string, unknown>).policyHash)
                : null,
        };
        if (
          evidence.evidenceBlob &&
          (!/^[a-f0-9]{64}$/.test(evidence.evidenceBlob.blobId) ||
            !Number.isSafeInteger(evidence.evidenceBlob.sizeBytes) ||
            evidence.evidenceBlob.sizeBytes <= 0 ||
            !Number.isSafeInteger(evidence.checkCount) ||
            evidence.checkCount < 0)
        ) {
          throw new Error("EVIDENCE_BLOB_REF_INVALID");
        }
        projection.evidence[proposalId] = evidence;
        const proposal = projection.proposals[proposalId];
        if (proposal) proposal.verifierInputHash = evidence.verifierInputHash;
        transition.state = "EVIDENCED";
        break;
      }
      case "PERMIT_ISSUED": {
        const transition = transitionFor(projection, event.transitionId);
        if (transition.state !== "EVIDENCED") throw new Error("PERMIT_ISSUE_ORDER_INVALID");
        const permitId = requiredString(payload, "permitId");
        if (projection.permits[permitId]) throw new Error("PERMIT_REPLAY");
        projection.permits[permitId] = {
          permitId,
          transitionId: event.transitionId,
          proposalId: requiredString(payload, "proposalId"),
          baseViewId: requiredString(payload, "baseViewId"),
          targetArtifactHash: requiredString(payload, "targetArtifactHash"),
          evaluationContextHash: requiredString(payload, "evaluationContextHash"),
          evidenceDigest: requiredString(payload, "evidenceDigest"),
          expiresAt: requiredString(payload, "expiresAt"),
          state: "ISSUED",
        };
        transition.permitId = permitId;
        transition.state = "PERMITTED";
        break;
      }
      case "PERMIT_CONSUMING": {
        const transition = transitionFor(projection, event.transitionId);
        const permitId = requiredString(payload, "permitId");
        const permit = projection.permits[permitId];
        if (!permit || permit.state !== "ISSUED" || transition.permitId !== permitId) {
          throw new Error("PERMIT_REPLAY");
        }
        permit.state = "CONSUMING";
        transition.state = "CONSUMING";
        break;
      }
      case "BACKUP_CREATED": {
        const transition = transitionFor(projection, event.transitionId);
        if (transition.state !== "CONSUMING") {
          throw new Error("BACKUP_CREATE_ORDER_INVALID");
        }
        if (requiredString(payload, "baseWorkspaceHash") !== transition.baseWorkspaceHash) {
          throw new Error("BACKUP_CREATE_BINDING_MISMATCH");
        }
        break;
      }
      case "WORKSPACE_APPLIED": {
        const transition = transitionFor(projection, event.transitionId);
        if (!["CONSUMING", "REPAIRED"].includes(transition.state)) {
          throw new Error("WORKSPACE_APPLY_ORDER_INVALID");
        }
        const view = payload.view as StateViewRef;
        const workspaceHash = requiredString(payload, "workspaceHash");
        transition.appliedView = view;
        transition.appliedWorkspaceHash = workspaceHash;
        transition.state = "APPLIED";
        projection.head = {
          view,
          workspaceHash,
          lastAppliedEventId: event.eventId,
          lastAppliedSequence: event.sequence,
        };
        break;
      }
      case "ROLLBACK_APPLIED": {
        const transition = transitionFor(projection, event.transitionId);
        if (transition.kind !== "ROLLBACK" || transition.state !== "APPLIED") {
          throw new Error("ROLLBACK_APPLY_ORDER_INVALID");
        }
        if (requiredString(payload, "workspaceHash") !== transition.appliedWorkspaceHash) {
          throw new Error("ROLLBACK_APPLY_BINDING_MISMATCH");
        }
        break;
      }
      case "PLATFORM_STATE_REGENERATED": {
        const view = payload.view as StateViewRef;
        const workspaceHash = requiredString(payload, "workspaceHash");
        projection.head = {
          view,
          workspaceHash,
          lastAppliedEventId: event.eventId,
          lastAppliedSequence: event.sequence,
        };
        break;
      }
      case "NON_COMMIT_DISPOSITIONED": {
        const transition = transitionFor(projection, event.transitionId);
        const decision = requiredString(payload, "decision") as ProjectedTerminalReceipt["decision"];
        if (!["QUARANTINED", "CONFLICTED", "ABORTED"].includes(decision)) {
          throw new Error("NON_COMMIT_DECISION_INVALID");
        }
        const restoredWorkspace = payload.restoredWorkspace === true;
        if (
          transition.state === "ACKNOWLEDGED" ||
          (transition.state === "REPAIRED" && !restoredWorkspace)
        ) {
          throw new Error("NON_COMMIT_DISPOSITION_ORDER_INVALID");
        }
        const receiptId = requiredString(payload, "receiptId");
        if (projection.terminalReceipts.some((receipt) => receipt.receiptId === receiptId)) {
          throw new Error("TERMINAL_RECEIPT_DUPLICATE");
        }
        const view = assertProjectedView(payload.view);
        const workspaceHash = requiredString(payload, "workspaceHash");
        if (view.liveStateHash !== workspaceHash) {
          throw new Error("NON_COMMIT_VIEW_WORKSPACE_MISMATCH");
        }
        if (restoredWorkspace) {
          if (
            workspaceHash !== transition.baseWorkspaceHash ||
            view.generation !== transition.baseGeneration
          ) {
            throw new Error("NON_COMMIT_RESTORED_BASE_MISMATCH");
          }
        } else {
          const head = projection.head;
          if (
            !head ||
            requiredString(payload, "previousViewId") !== head.view.viewId ||
            workspaceHash !== head.workspaceHash ||
            view.generation !== head.view.generation ||
            view.headVersionId !== head.view.headVersionId ||
            view.versionedHash !== head.view.versionedHash ||
            view.platformManagedHash !== head.view.platformManagedHash ||
            view.agentConfigVersion !== head.view.agentConfigVersion ||
            view.policyVersion !== head.view.policyVersion ||
            view.sessionEpoch !== head.view.sessionEpoch + 1
          ) {
            throw new Error("NON_COMMIT_HEAD_BINDING_MISMATCH");
          }
        }
        if (transition.permitId) {
          const permit = projection.permits[transition.permitId];
          if (permit?.state === "CONSUMED") {
            throw new Error("NON_COMMIT_PERMIT_ALREADY_CONSUMED");
          }
          if (permit) permit.state = "REVOKED";
        }
        projection.terminalReceipts.push({
          receiptId,
          transitionId: event.transitionId,
          decision,
          viewId: view.viewId,
          eventId: event.eventId,
          sequence: event.sequence,
          view,
          workspaceHash,
          dispositionBaseViewId:
            typeof payload.previousViewId === "string" ? payload.previousViewId : null,
          dispositionBaseGeneration: view.generation,
          dispositionBaseWorkspaceHash: workspaceHash,
          reasonCodes: Array.isArray(payload.reasonCodes)
            ? payload.reasonCodes.filter(
                (value): value is string => typeof value === "string",
              )
            : [],
        });
        transition.state = "ROLLED_BACK";
        projection.head = {
          view,
          workspaceHash,
          lastAppliedEventId: event.eventId,
          lastAppliedSequence: event.sequence,
        };
        break;
      }
      case "VIEW_DISPOSITIONED": {
        const decision = requiredString(payload, "decision") as ProjectedTerminalReceipt["decision"];
        if (!["COMMITTED", "QUARANTINED", "CONFLICTED", "ABORTED"].includes(decision)) {
          throw new Error("TERMINAL_DECISION_INVALID");
        }
        const view = payload.view as StateViewRef;
        const workspaceHash = requiredString(payload, "workspaceHash");
        projection.terminalReceipts.push({
          receiptId: requiredString(payload, "receiptId"),
          transitionId: event.transitionId,
          decision,
          viewId: typeof payload.viewId === "string" ? payload.viewId : null,
          eventId: event.eventId,
          sequence: event.sequence,
          view,
          workspaceHash,
          dispositionBaseViewId:
            typeof payload.previousViewId === "string" ? payload.previousViewId : null,
          dispositionBaseGeneration: view.generation,
          dispositionBaseWorkspaceHash: workspaceHash,
          reasonCodes: Array.isArray(payload.reasonCodes)
            ? payload.reasonCodes.filter(
                (value): value is string => typeof value === "string",
              )
            : [],
        });
        if (payload.view && typeof payload.view === "object") {
          projection.head = {
            view,
            workspaceHash,
            lastAppliedEventId: event.eventId,
            lastAppliedSequence: event.sequence,
          };
        }
        break;
      }
      case "TRANSITION_ACKNOWLEDGED": {
        const transition = transitionFor(projection, event.transitionId);
        if (transition.state !== "APPLIED") throw new Error("TRANSITION_ACK_ORDER_INVALID");
        const permit = transition.permitId ? projection.permits[transition.permitId] : undefined;
        if (permit) permit.state = "CONSUMED";
        const receiptId = requiredString(payload, "receiptId");
        const view = transition.appliedView!;
        projection.versions.push({
          versionId: requiredString(payload, "versionId"),
          transitionId: event.transitionId,
          kind: transition.kind,
          viewId: view.viewId,
          generation: view.generation,
          workspaceHash: transition.appliedWorkspaceHash!,
          snapshotId: requiredString(payload, "snapshotId"),
          receiptId,
          rollbackTargetVersionId:
            transition.kind === "ROLLBACK"
              ? requiredString(payload, "rollbackTargetVersionId")
              : null,
        });
        projection.terminalReceipts.push({
          receiptId,
          transitionId: event.transitionId,
          decision: "COMMITTED",
          viewId: view.viewId,
          eventId: event.eventId,
          sequence: event.sequence,
          view,
          workspaceHash: transition.appliedWorkspaceHash!,
          dispositionBaseViewId: transition.baseViewId,
          dispositionBaseGeneration: transition.baseGeneration,
          dispositionBaseWorkspaceHash: transition.baseWorkspaceHash,
          reasonCodes: [],
        });
        transition.state = "ACKNOWLEDGED";
        break;
      }
      case "RECEIPT_PROOF_RECORDED": {
        const receiptId = requiredString(payload, "receiptId");
        const terminalEventId = requiredString(payload, "terminalEventId");
        const terminalReceipt = projection.terminalReceipts.find(
          (receipt) =>
            receipt.receiptId === receiptId &&
            receipt.transitionId === event.transitionId,
        );
        const terminalEvent = events.find(
          (candidate) =>
            candidate.eventId === terminalEventId &&
            candidate.sequence < event.sequence,
        );
        const legacyBundle = payload.bundle as AuthorityReceiptProofBundle | undefined;
        const terminalEventIndex = terminalEvent
          ? events.findIndex((candidate) => candidate.eventId === terminalEvent.eventId)
          : -1;
        const bundle: AuthorityReceiptProofBundle | undefined = legacyBundle ??
          (terminalEvent && terminalEventIndex >= 0 &&
              payload.receipt && typeof payload.receipt === "object" &&
              payload.proof && typeof payload.proof === "object" &&
              typeof payload.publicKeyPem === "string"
            ? {
                schemaVersion: 3,
                receipt: payload.receipt as AuthorityReceiptProofBundle["receipt"],
                proof: payload.proof as AuthorityReceiptProofBundle["proof"],
                terminalEvent,
                predecessorEvent:
                  terminalEventIndex > 0 ? events[terminalEventIndex - 1]! : null,
                eventChain: events.slice(0, terminalEventIndex + 1),
                publicKeyPem: payload.publicKeyPem,
              }
            : undefined);
        const transition = transitionFor(projection, event.transitionId);
        const proposal = transition.proposalId
          ? projection.proposals[transition.proposalId]
          : undefined;
        const evidence = transition.proposalId
          ? projection.evidence[transition.proposalId]
          : undefined;
        const permit = transition.permitId
          ? projection.permits[transition.permitId]
          : undefined;
        if (
          !terminalReceipt ||
          !terminalEvent ||
          terminalReceipt.eventId !== terminalEventId ||
          !bundle ||
          typeof bundle !== "object"
        ) {
          throw new Error("RECEIPT_PROOF_TERMINAL_BINDING_INVALID");
        }
        const verification = verifyAuthorityReceiptProof(bundle);
        if (!verification.valid) {
          throw new Error(`RECEIPT_PROOF_INVALID:${verification.reason ?? "unknown"}`);
        }
        if (
          bundle.receipt.receiptId !== receiptId ||
          bundle.receipt.runId !== (transition.runId ?? receiptId) ||
          bundle.receipt.agentId !== agentId ||
          bundle.receipt.transitionId !== event.transitionId ||
          bundle.receipt.decision !== terminalReceipt.decision ||
          bundle.receipt.baseViewId !== transition.baseViewId ||
          bundle.receipt.finalViewId !== terminalReceipt.viewId ||
          bundle.receipt.baseGeneration !== transition.baseGeneration ||
          bundle.receipt.nextGeneration !== terminalReceipt.view.generation ||
          bundle.receipt.baseWorkspaceHash !== transition.baseWorkspaceHash ||
          bundle.receipt.finalWorkspaceHash !== terminalReceipt.workspaceHash ||
          (bundle.receipt.schemaVersion === 2 &&
            (bundle.receipt.dispositionBaseViewId !==
                terminalReceipt.dispositionBaseViewId ||
              bundle.receipt.dispositionBaseGeneration !==
                terminalReceipt.dispositionBaseGeneration ||
              bundle.receipt.dispositionBaseWorkspaceHash !==
                terminalReceipt.dispositionBaseWorkspaceHash)) ||
          bundle.receipt.proposalId !== (proposal?.proposalId ?? null) ||
          bundle.receipt.proposalArtifactHash !== (proposal?.artifactHash ?? null) ||
          bundle.receipt.verifierInputHash !== (evidence?.verifierInputHash ?? null) ||
          bundle.receipt.promotionSourceHash !== (permit?.targetArtifactHash ?? null) ||
          bundle.receipt.evaluationContextHash !== (evidence?.evaluationContextHash ?? null) ||
          bundle.receipt.evidenceDigest !== (evidence?.evidenceDigest ?? null) ||
          bundle.receipt.permitId !== (permit?.permitId ?? null) ||
          bundle.receipt.permitState !==
            (permit?.state === "CONSUMED" || permit?.state === "REVOKED" ? permit.state : null) ||
          (evidence?.sourceRevision !== null &&
            evidence?.sourceRevision !== undefined &&
            bundle.receipt.sourceRevision !== evidence.sourceRevision) ||
          bundle.proof.logSequence !== terminalEvent.sequence ||
          bundle.proof.previousDigest !== terminalEvent.previousDigest ||
          bundle.proof.eventDigest !== terminalEvent.digest
        ) {
          throw new Error("RECEIPT_PROOF_TERMINAL_BINDING_INVALID");
        }
        if (projection.receiptProofs[receiptId]) {
          throw new Error("RECEIPT_PROOF_DUPLICATE");
        }
        // A projection is returned by nearly every Worker RPC. Carrying the
        // genesis-to-terminal prefix in every receipt makes that response grow
        // quadratically with Agent history and eventually exceed the bounded
        // RPC transport. Keep a valid v2 one-hop envelope here; the Worker
        // reconstructs exactly one v3 full-chain bundle on demand from the
        // immutable log in getReceiptProof().
        const compactBundle: AuthorityReceiptProofBundle = {
          schemaVersion: 2,
          receipt: structuredClone(bundle.receipt),
          proof: structuredClone(bundle.proof),
          terminalEvent: structuredClone(terminalEvent),
          predecessorEvent:
            terminalEventIndex > 0
              ? structuredClone(events[terminalEventIndex - 1]!)
              : null,
          publicKeyPem: bundle.publicKeyPem,
        };
        const compactVerification = verifyAuthorityReceiptProof(compactBundle);
        if (!compactVerification.valid) {
          throw new Error(
            `RECEIPT_PROOF_INVALID:${compactVerification.reason ?? "unknown"}`,
          );
        }
        projection.receiptProofs[receiptId] = {
          receiptId,
          transitionId: event.transitionId,
          terminalEventId,
          proofEventId: event.eventId,
          sequence: event.sequence,
          bundle: compactBundle,
        };
        break;
      }
      case "TRANSITION_ROLLED_BACK": {
        const transition = transitionFor(projection, event.transitionId);
        if (transition.permitId) {
          const permit = projection.permits[transition.permitId];
          if (permit && permit.state !== "CONSUMED") permit.state = "REVOKED";
        }
        transition.state = "ROLLED_BACK";
        // V1 recovery/repair events may carry the restored base View.  New
        // non-commit terminals use NON_COMMIT_DISPOSITIONED instead.
        if (payload.restoredView && typeof payload.restoredView === "object") {
          const restoredView = assertProjectedView(payload.restoredView);
          const workspaceHash = requiredString(payload, "workspaceHash");
          if (
            workspaceHash !== transition.baseWorkspaceHash ||
            restoredView.liveStateHash !== workspaceHash ||
            restoredView.generation !== transition.baseGeneration
          ) {
            throw new Error("TRANSITION_ROLLBACK_VIEW_INVALID");
          }
          projection.head = {
            view: restoredView,
            workspaceHash,
            lastAppliedEventId: event.eventId,
            lastAppliedSequence: event.sequence,
          };
        }
        break;
      }
      case "REPAIR_APPLIED":
        transitionFor(projection, event.transitionId).state = "REPAIRED";
        break;
      case "AGENT_ARCHIVED":
        projection.archived = true;
        break;
      case "STALE_CALLBACK_RECORDED":
        break;
    }
    projection.lastEventId = event.eventId;
    projection.lastSequence = event.sequence;
  }

  projection.digest = sha256({
    schemaVersion: projection.schemaVersion,
    agentId: projection.agentId,
    head: projection.head,
    proposals: projection.proposals,
    evidence: projection.evidence,
    permits: projection.permits,
    transitions: projection.transitions,
    versions: projection.versions,
    terminalReceipts: projection.terminalReceipts,
    receiptProofs: projection.receiptProofs,
    archived: projection.archived,
    lastEventId: projection.lastEventId,
    lastSequence: projection.lastSequence,
  });
  return projection;
}

export class WorkerProjectionStore {
  constructor(private readonly controlRoot: string) {}

  async writeHead(projection: WorkerProjection): Promise<WorkerHeadMarker> {
    this.assertAgentId(projection.agentId);
    const marker: WorkerHeadMarker = {
      schemaVersion: 1,
      agentId: projection.agentId,
      lastAppliedEventId: projection.head?.lastAppliedEventId ?? null,
      lastAppliedSequence: projection.head?.lastAppliedSequence ?? 0,
      viewId: projection.head?.view.viewId ?? null,
      workspaceHash: projection.head?.workspaceHash ?? null,
      generation: projection.head?.view.generation ?? null,
      projectionDigest: projection.digest,
    };
    const directory = path.join(this.controlRoot, "heads");
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const destination = path.join(directory, `${projection.agentId}.json`);
    const temporary = `${destination}.tmp-${randomUUID()}`;
    await writeFile(temporary, JSON.stringify(marker, null, 2) + "\n", {
      flag: "wx",
      mode: 0o600,
    });
    await rename(temporary, destination);
    return marker;
  }

  async readHead(agentId: string): Promise<WorkerHeadMarker | null> {
    this.assertAgentId(agentId);
    try {
      return JSON.parse(
        await readFile(path.join(this.controlRoot, "heads", `${agentId}.json`), "utf8"),
      ) as WorkerHeadMarker;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw error;
    }
  }

  private assertAgentId(agentId: string): void {
    if (!/^[A-Za-z0-9_.-]{1,128}$/.test(agentId)) throw new Error("Invalid agentId");
  }
}
