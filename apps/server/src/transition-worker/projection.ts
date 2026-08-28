import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import type { StateViewRef } from "../types.js";
import type { TransitionEvent } from "../transition-log.js";

export type ProjectedPermitState = "ISSUED" | "CONSUMING" | "CONSUMED" | "REVOKED";

export interface ProjectedProposal {
  proposalId: string;
  transitionId: string;
  baseViewId: string;
  artifactHash: string;
  changedPaths: string[];
  staticFailures: string[];
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
    | "ROLLED_BACK"
    | "REPAIRED";
  baseViewId: string | null;
  baseWorkspaceHash: string;
  baseGeneration: number;
  appliedView: StateViewRef | null;
  appliedWorkspaceHash: string | null;
  proposalId: string | null;
  permitId: string | null;
}

export interface WorkerProjection {
  schemaVersion: 1;
  agentId: string;
  head: {
    view: StateViewRef;
    workspaceHash: string;
    lastAppliedEventId: string;
    lastAppliedSequence: number;
  } | null;
  proposals: Record<string, ProjectedProposal>;
  permits: Record<string, ProjectedPermit>;
  transitions: Record<string, ProjectedTransition>;
  versions: ProjectedVersion[];
  terminalReceipts: ProjectedTerminalReceipt[];
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
    schemaVersion: 1,
    agentId,
    head: null,
    proposals: {},
    permits: {},
    transitions: {},
    versions: [],
    terminalReceipts: [],
    archived: false,
    lastEventId: null,
    lastSequence: 0,
    digest: "",
  };

  for (const event of events) {
    if (event.agentId !== agentId) throw new Error("TRANSITION_EVENT_AGENT_MISMATCH");
    const payload = event.payload as Record<string, unknown>;
    switch (event.type) {
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
          baseViewId:
            typeof payload.baseViewId === "string" ? payload.baseViewId : null,
          baseWorkspaceHash: requiredString(payload, "baseWorkspaceHash"),
          baseGeneration: Number(payload.baseGeneration),
          appliedView: null,
          appliedWorkspaceHash: null,
          proposalId: null,
          permitId: null,
        };
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
          changedPaths: Array.isArray(payload.changedPaths)
            ? payload.changedPaths.filter((value): value is string => typeof value === "string")
            : [],
          staticFailures: Array.isArray(payload.staticFailures)
            ? payload.staticFailures.filter((value): value is string => typeof value === "string")
            : [],
        };
        projection.proposals[proposalId] = proposal;
        transition.proposalId = proposalId;
        transition.state = "SEALED";
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
      case "WORKSPACE_APPLIED": {
        const transition = transitionFor(projection, event.transitionId);
        if (
          transition.state !== "CONSUMING" &&
          transition.state !== "REPAIRED" &&
          transition.kind !== "ROLLBACK"
        ) {
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
      case "VIEW_DISPOSITIONED": {
        const decision = requiredString(payload, "decision") as ProjectedTerminalReceipt["decision"];
        if (!["COMMITTED", "QUARANTINED", "CONFLICTED", "ABORTED"].includes(decision)) {
          throw new Error("TERMINAL_DECISION_INVALID");
        }
        projection.terminalReceipts.push({
          receiptId: requiredString(payload, "receiptId"),
          transitionId: event.transitionId,
          decision,
          viewId: typeof payload.viewId === "string" ? payload.viewId : null,
          eventId: event.eventId,
          sequence: event.sequence,
        });
        if (payload.view && typeof payload.view === "object") {
          const view = payload.view as StateViewRef;
          projection.head = {
            view,
            workspaceHash: requiredString(payload, "workspaceHash"),
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
        });
        transition.state = "ACKNOWLEDGED";
        break;
      }
      case "TRANSITION_ROLLED_BACK": {
        const transition = transitionFor(projection, event.transitionId);
        if (transition.permitId) {
          const permit = projection.permits[transition.permitId];
          if (permit && permit.state !== "CONSUMED") permit.state = "REVOKED";
        }
        transition.state = "ROLLED_BACK";
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
    permits: projection.permits,
    transitions: projection.transitions,
    versions: projection.versions,
    terminalReceipts: projection.terminalReceipts,
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
