import type {
  Agent,
  AgentRun,
  GateReceipt,
  Message,
  SystemInfo,
  WorkspaceVersion,
} from "./types";

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code?: string,
    public readonly data?: Record<string, unknown>,
  ) {
    super(message);
  }
}

let authToken = "";

export function setAuthToken(token: string): void {
  authToken = token.trim();
}

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const headers = {
    ...(options?.body ? { "Content-Type": "application/json" } : {}),
    ...(authToken ? { Authorization: "Bearer " + authToken } : {}),
    ...options?.headers,
  };
  const response = await fetch(url, {
    ...options,
    headers,
  });
  const data = (await response.json().catch(() => ({}))) as T & { error?: string };
  if (!response.ok) {
    const errorData = data as unknown as Record<string, unknown>;
    throw new ApiError(
      data.error ?? "Request failed",
      response.status,
      typeof errorData.code === "string"
        ? errorData.code
        : undefined,
      errorData,
    );
  }
  return data;
}

export const api = {
  auth: () => request<{ required: boolean }>("/api/auth"),
  system: () => request<SystemInfo>("/api/system"),
  listAgents: () => request<{ agents: Agent[] }>("/api/agents"),
  createAgent: (body: {
    name: string;
    description: string;
    instructions: string;
  }) =>
    request<{ agent: Agent }>("/api/agents", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateAgent: (
    id: string,
    body: { name: string; description: string; instructions: string },
  ) =>
    request<{ agent: Agent }>("/api/agents/" + id, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  deleteAgent: (id: string) =>
    request<{ archivedWorkspace: string }>("/api/agents/" + id, {
      method: "DELETE",
    }),
  startAgent: (id: string) =>
    request<{ agent: Agent }>("/api/agents/" + id + "/start", {
      method: "POST",
    }),
  stopAgent: (id: string) =>
    request<{ agent: Agent }>("/api/agents/" + id + "/stop", {
      method: "POST",
    }),
  messages: (id: string) =>
    request<{ messages: Message[] }>("/api/agents/" + id + "/messages"),
  runs: (id: string) =>
    request<{ runs: AgentRun[] }>("/api/agents/" + id + "/runs"),
  sendMessage: (id: string, content: string) =>
    request<{ run: AgentRun; message: Message }>(
      "/api/agents/" + id + "/messages",
      {
        method: "POST",
        body: JSON.stringify({ content }),
      },
    ),
  run: (id: string) => request<{ run: AgentRun }>("/api/runs/" + id),
  commitGateReceipt: (id: string) =>
    request<{ receipt: GateReceipt }>("/api/runs/" + id + "/commitgate"),
  attemptPromotionReplay: (
    runId: string,
    permitId: string,
    expectedViewId: string,
  ) =>
    request<{
      code: "PERMIT_REPLAY";
      permitState: "CONSUMED";
      headUnchanged: true;
      currentViewId: string;
      currentGeneration: number;
    }>("/api/runs/" + runId + "/commitgate/promotion-attempts", {
      method: "POST",
      body: JSON.stringify({ permitId, expectedViewId }),
    }),
  versions: (agentId: string, beforeSequence?: number) =>
    request<{ versions: WorkspaceVersion[]; nextBeforeSequence: number | null }>(
      "/api/agents/" +
        agentId +
        "/versions?limit=20" +
        (beforeSequence ? "&beforeSequence=" + beforeSequence : ""),
    ),
  rollback: (
    agentId: string,
    targetVersionId: string,
    expectedHeadVersionId: string,
    expectedViewId: string,
    expectedGeneration: number,
  ) =>
    request<{ version: WorkspaceVersion; agent: Agent }>(
      "/api/agents/" + agentId + "/rollbacks",
      {
        method: "POST",
        body: JSON.stringify({
          targetVersionId,
          expectedHeadVersionId,
          expectedViewId,
          expectedGeneration,
        }),
      },
    ),
};
