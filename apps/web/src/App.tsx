import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError, setAuthToken } from "./api";
import type {
  Agent,
  AgentRun,
  CommitGateSummary,
  GateReceipt,
  Message,
  MessageAuthority,
  SystemInfo,
  WorkspaceVersion,
} from "./types";

const starterPrompts = [
  "Create a small TypeScript CLI that prints a weather summary from sample JSON.",
  "Inspect this workspace and explain what you would improve first.",
  "Build a responsive single-page todo app with tests.",
];

const emptyForm = {
  name: "",
  description: "",
  instructions:
    "Help me build and test software in this workspace. Keep changes small and explain the result.",
};

function formatTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

function StatusPill({ status }: { status: Agent["status"] }) {
  return (
    <span className={"status status-" + status}>
      <span className="status-dot" />
      {status}
    </span>
  );
}

function Spinner() {
  return <span className="spinner" aria-label="Loading" />;
}

function shortHash(value: string | null): string {
  return value ? value.slice(0, 12) : "—";
}

function shortIdentifier(value: string | null | undefined): string {
  if (!value) return "—";
  return value.length > 16 ? value.slice(0, 12) + "…" : value;
}

function displayDecision(decision: CommitGateSummary["decision"]): string {
  if (decision === "QUARANTINED") return "Rejected";
  if (decision === "COMMITTED") return "Committed";
  if (decision === "CONFLICTED") return "Conflicted";
  return "Aborted";
}

function displayAuthority(message: Message): MessageAuthority | "UNCLASSIFIED" {
  if (message.authority) return message.authority;
  return message.role === "user" ? "INPUT" : "UNCLASSIFIED";
}

function providerConfigured(system: SystemInfo | null): boolean {
  return system?.modelConfigured ?? system?.providerConfigured ?? system?.arkConfigured ?? false;
}

function providerLabel(system: SystemInfo | null): string {
  if (!system) return "Checking provider…";
  const provider = system.modelProvider ?? (system.arkConfigured ? "ark" : null);
  const model = system.modelId ?? system.arkModel;
  if (!provider) return "Model provider not configured";
  return provider.toUpperCase() + (model ? " · " + model : "");
}

function recordValue(
  source: Record<string, unknown> | null | undefined,
  ...keys: string[]
): string | null {
  if (!source) return null;
  for (const key of keys) {
    const value = source[key];
    if (typeof value === "string" && value) return value;
    if (typeof value === "number") return String(value);
  }
  return null;
}

function GateFlow({
  gate,
  receipt,
}: {
  gate: CommitGateSummary;
  receipt: GateReceipt | null;
}) {
  const baseView =
    receipt?.baseView?.viewId ?? receipt?.baseViewId ?? gate.baseViewId ?? gate.baseHash;
  const proposal =
    receipt?.proposalId ?? gate.proposalId ?? gate.candidateHash ?? null;
  const permit = receipt?.permitId ?? gate.permitId ?? null;
  const permitState = receipt?.permitState ?? gate.permitState ?? null;
  const nextView =
    receipt?.nextView?.viewId ??
    receipt?.finalViewId ??
    receipt?.nextViewId ??
    gate.nextViewId ??
    gate.finalHash;
  const committed = gate.decision === "COMMITTED";

  return (
    <div className="gate-flow" aria-label="CommitGate state transition">
      <div className="gate-flow-node">
        <span>Authoritative HEAD</span>
        <strong>{shortIdentifier(baseView)}</strong>
        <small>
          {gate.baseGeneration == null && receipt?.baseGeneration == null
            ? "base view"
            : "generation " + (gate.baseGeneration ?? receipt?.baseGeneration)}
        </small>
      </div>
      <span className="gate-flow-arrow">→</span>
      <div className="gate-flow-node">
        <span>Sealed proposal</span>
        <strong>{shortIdentifier(proposal)}</strong>
        <small>{proposal ? "immutable input" : "not issued"}</small>
      </div>
      <span className="gate-flow-arrow">→</span>
      <div className="gate-flow-node">
        <span>One-shot permit</span>
        <strong>{shortIdentifier(permit)}</strong>
        <small>{permitState ?? (committed ? "consumed" : "not issued")}</small>
      </div>
      <span className="gate-flow-arrow">→</span>
      <div className={"gate-flow-node " + (committed ? "gate-flow-next" : "gate-flow-unchanged")}>
        <span>{committed ? "Next HEAD" : "HEAD unchanged"}</span>
        <strong>{shortIdentifier(nextView)}</strong>
        <small>
          {gate.nextGeneration == null && receipt?.nextGeneration == null && receipt?.generation == null
            ? committed
              ? "authoritative"
              : "proposal not promoted"
            : "generation " +
              (gate.nextGeneration ?? receipt?.nextGeneration ?? receipt?.generation)}
        </small>
      </div>
    </div>
  );
}

type GateLifecycleName =
  | "RUN_STARTED"
  | "PROPOSAL_SEALED"
  | "VERIFICATION_COMPLETED"
  | "PERMIT_ISSUED"
  | "VIEW_COMMITTED"
  | "SESSION_RESET"
  | "RUN_ABORTED";

function GateTimeline({ gate }: { gate: CommitGateSummary }) {
  const derivedEvents: Array<{ name: GateLifecycleName; reached: boolean }> = [
    { name: "RUN_STARTED", reached: true },
    { name: "PROPOSAL_SEALED", reached: Boolean(gate.proposalId ?? gate.proposalHash) },
    {
      name: "VERIFICATION_COMPLETED",
      reached: gate.checks.length > 0 || gate.decision === "QUARANTINED",
    },
    { name: "PERMIT_ISSUED", reached: Boolean(gate.permitId) },
    { name: "VIEW_COMMITTED", reached: gate.decision === "COMMITTED" },
    { name: "SESSION_RESET", reached: gate.threadDisposition === "reset" },
    { name: "RUN_ABORTED", reached: gate.decision === "ABORTED" },
  ];
  const events = gate.lifecycle?.map((event) => ({ name: event.name, reached: true })) ?? derivedEvents;
  return (
    <ol className="gate-timeline" aria-label="CommitGate lifecycle">
      {events.filter((event) => event.reached).map((event) => (
        <li key={event.name} className="gate-timeline-complete">
          <span aria-hidden="true" />
          <strong>{event.name.replaceAll("_", " ")}</strong>
        </li>
      ))}
    </ol>
  );
}

function AuthoritativeHead({ agent }: { agent: Agent }) {
  return (
    <section className="authoritative-head" aria-label="Authoritative workspace state">
      <div className="head-title">
        <span className="eyebrow">Authoritative state</span>
        <strong>HEAD</strong>
      </div>
      <div className="head-field">
        <span>Generation</span>
        <strong>{agent.stateGeneration == null ? "—" : "g" + agent.stateGeneration}</strong>
      </div>
      <div className="head-field">
        <span>View</span>
        <code title={agent.currentViewId ?? undefined}>{shortIdentifier(agent.currentViewId)}</code>
      </div>
      <div className="head-field">
        <span>Live state</span>
        <code title={agent.currentLiveStateHash ?? agent.liveStateHash ?? undefined}>
          {shortHash(agent.currentLiveStateHash ?? agent.liveStateHash ?? null)}
        </code>
      </div>
      <div className="head-field">
        <span>Version</span>
        <code title={agent.headVersionId ?? undefined}>{shortIdentifier(agent.headVersionId)}</code>
      </div>
      <div className="head-field">
        <span>Session</span>
        <strong>epoch {agent.sessionEpoch}</strong>
      </div>
      {agent.needsReconciliation && (
        <span className="head-reconciliation">Fresh reconciliation required</span>
      )}
    </section>
  );
}

function GateCard({ run, agent }: { run: AgentRun; agent: Agent }) {
  const gate = run.commitGate;
  const [receipt, setReceipt] = useState<GateReceipt | null>(null);
  const [receiptBusy, setReceiptBusy] = useState(false);
  const [receiptError, setReceiptError] = useState<string | null>(null);
  const [replayBusy, setReplayBusy] = useState(false);
  const [replayProof, setReplayProof] = useState<string | null>(null);
  if (!gate && run.legacyReceipt) {
    return (
      <article className="gate-card gate-legacy">
        <div className="gate-card-header">
          <div>
            <span className="eyebrow">Legacy Receipt · read only</span>
            <strong>{displayDecision(run.legacyReceipt.decision)}</strong>
            <small>Not eligible for permit or replay</small>
          </div>
        </div>
      </article>
    );
  }
  if (!gate) return null;

  const loadReceipt = async () => {
    if (receipt || receiptBusy) return;
    setReceiptBusy(true);
    setReceiptError(null);
    try {
      setReceipt((await api.commitGateReceipt(run.id)).receipt);
    } catch (reason) {
      setReceiptError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setReceiptBusy(false);
    }
  };
  const attemptReplay = async () => {
    const permitId = receipt?.permitId ?? gate.permitId;
    if (!permitId || !agent.currentViewId) return;
    setReplayBusy(true);
    setReplayProof(null);
    try {
      await api.attemptPromotionReplay(run.id, permitId, agent.currentViewId);
      setReplayProof("Unexpectedly accepted");
    } catch (reason) {
      if (
        reason instanceof ApiError &&
        reason.status === 409 &&
        reason.code === "PERMIT_REPLAY" &&
        reason.data?.headUnchanged === true
      ) {
        setReplayProof(
          "Rejected — HEAD unchanged at g" + String(reason.data.currentGeneration),
        );
      } else {
        setReplayProof(reason instanceof Error ? reason.message : String(reason));
      }
    } finally {
      setReplayBusy(false);
    }
  };
  return (
    <article className={"gate-card gate-" + gate.decision.toLowerCase()}>
      <div className="gate-card-header">
        <div>
          <span className="eyebrow">
            {gate.decision === "COMMITTED" ? "Promotion Receipt" : "Non-Promotion Receipt"}
          </span>
          <strong>{displayDecision(gate.decision)}</strong>
          <small>{gate.decision}</small>
        </div>
        <span className="gate-session">Session {gate.threadDisposition}</span>
        <span className="gate-session">
          Artifact {gate.candidateCleanup === "deleted" ? "destroyed" : "cleanup pending"}
        </span>
      </div>
      <GateTimeline gate={gate} />
      <GateFlow gate={gate} receipt={receipt} />
      {gate.decision === "QUARANTINED" && (
        <div className="gate-retention" role="status">
          <span>Artifact retention: {gate.artifactRetention ?? (gate.candidateCleanup === "deleted" ? "destroyed" : "pending")}</span>
          <span>Evidence retention: {gate.evidenceRetention ?? "metadata-only"}</span>
        </div>
      )}
      <div className="gate-hashes">
        <span>base <code>{shortHash(gate.baseHash)}</code></span>
        <span>candidate <code>{shortHash(gate.candidateHash)}</code></span>
        <span>final <code>{shortHash(gate.finalHash)}</code></span>
      </div>
      {gate.failureClass && <p className="gate-failure">{gate.failureClass}</p>}
      <div className="gate-checks">
        {gate.checks.map((check) => (
          <span className={"check check-" + check.status.toLowerCase()} key={check.id}>
            {check.id}: {check.status}
          </span>
        ))}
      </div>
      {gate.changedPaths.length > 0 && (
        <details>
          <summary>{gate.changedPaths.length} changed path(s)</summary>
          <ul>{gate.changedPaths.map((item) => <li key={item}><code>{item}</code></li>)}</ul>
        </details>
      )}
      <details
        className="gate-receipt-detail"
        onToggle={(event) => {
          if (event.currentTarget.open) void loadReceipt();
        }}
      >
        <summary>Full sanitized receipt</summary>
        {receiptBusy && <p><Spinner /> Loading receipt…</p>}
        {receiptError && <p className="gate-failure">{receiptError}</p>}
        {receipt && (
          <div className="receipt-grid">
            <div className="receipt-section">
              <span className="eyebrow">Sealed proposal</span>
              <span>Proposal <code>{shortIdentifier(receipt.proposalId ?? gate.proposalId)}</code></span>
              <span>Artifact <code>{shortHash(receipt.proposalArtifactHash ?? gate.proposalHash ?? gate.proposalArtifactHash ?? null)}</code></span>
            </div>
            {gate.decision === "COMMITTED" &&
              (receipt.permitState ?? gate.permitState) === "CONSUMED" && (
                <div className="receipt-section security-proof">
                  <span className="eyebrow">Security proof</span>
                  <span>Exercise the public one-shot promotion fence.</span>
                  <button
                    type="button"
                    className="button button-ghost"
                    disabled={replayBusy}
                    onClick={() => void attemptReplay()}
                  >
                    {replayBusy ? <Spinner /> : "Attempt replay"}
                  </button>
                  {replayProof && <strong role="status">{replayProof}</strong>}
                </div>
              )}
            <div className="receipt-section">
              <span className="eyebrow">Evidence binding</span>
              <span>Context <code>{shortHash(receipt.evaluationContextHash ?? gate.evaluationContextHash ?? recordValue(receipt.evidence, "evaluationContextHash", "contextHash"))}</code></span>
              <span>Evidence <code>{shortHash(receipt.evidenceDigest ?? gate.evidenceDigest ?? recordValue(receipt.evidence, "evidenceDigest"))}</code></span>
            </div>
            <div className="receipt-section">
              <span className="eyebrow">Promotion capability</span>
              <span>Permit <code>{shortIdentifier(receipt.permitId ?? gate.permitId)}</code></span>
              <span>State <strong>{receipt.permitState ?? gate.permitState ?? "not issued"}</strong></span>
            </div>
            <div className="receipt-section">
              <span className="eyebrow">Provider identity</span>
              <span>Provider <strong>{receipt.provider?.providerId ?? gate.provider?.providerId ?? recordValue(receipt.evidence, "providerId") ?? "unreported"}</strong></span>
              <span>Gateway <code>{receipt.provider?.gateway ?? gate.provider?.gateway ?? recordValue(receipt.evidence, "gateway") ?? "—"}</code></span>
              <span>Requested model <code>{receipt.provider?.requestedModel ?? gate.provider?.requestedModel ?? recordValue(receipt.evidence, "requestedModel") ?? "—"}</code></span>
              <span>Resolved model <code>{receipt.provider?.resolvedModel ?? gate.provider?.resolvedModel ?? recordValue(receipt.evidence, "resolvedModel") ?? "—"}</code></span>
            </div>
            <span>Policy <code>{shortHash(receipt.policyHash)}</code></span>
            <span>Patch <code>{shortHash(receipt.patchHash)}</code></span>
            <span>Session epoch <strong>{receipt.sessionEpoch}</strong></span>
            <span>Version <code>{receipt.versionId ?? "—"}</code></span>
            <span>Candidate cleanup <strong>{receipt.candidateCleanup ?? "deferred"}</strong></span>
            <details className="receipt-raw-evidence">
              <summary>Sanitized evidence metadata</summary>
              <code>{JSON.stringify(receipt.evidence)}</code>
            </details>
            {receipt.reasonCodes.length > 0 && (
              <ul>
                {receipt.reasonCodes.map((reason) => <li key={reason}>{reason}</li>)}
              </ul>
            )}
            {receipt.checks.map((check) => (
              <details key={check.id}>
                <summary>{check.id} · {check.status} · {check.durationMs} ms</summary>
                <pre>{check.output || "(no output)"}</pre>
              </details>
            ))}
          </div>
        )}
      </details>
    </article>
  );
}

export default function App() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [system, setSystem] = useState<SystemInfo | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [form, setForm] = useState(emptyForm);
  const [prompt, setPrompt] = useState("");
  const [activeRun, setActiveRun] = useState<AgentRun | null>(null);
  const [versions, setVersions] = useState<WorkspaceVersion[]>([]);
  const [nextBeforeSequence, setNextBeforeSequence] = useState<number | null>(null);
  const [showHistory, setShowHistory] = useState(false);
  const [historyBusy, setHistoryBusy] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [authRequired, setAuthRequired] = useState<boolean | null>(null);
  const [authInput, setAuthInput] = useState("");
  const messageEnd = useRef<HTMLDivElement>(null);
  const selectedIdRef = useRef<string | null>(null);
  const mountedRef = useRef(true);
  const pollingRunIds = useRef(new Set<string>());
  selectedIdRef.current = selectedId;

  const selected = useMemo(
    () => agents.find((agent) => agent.id === selectedId) ?? null,
    [agents, selectedId],
  );

  const refreshAgents = useCallback(async () => {
    const { agents: next } = await api.listAgents();
    setAgents(next);
    setSelectedId((current) =>
      current && next.some((agent) => agent.id === current)
        ? current
        : (next[0]?.id ?? null),
    );
  }, []);

  const refreshMessages = useCallback(async (agentId: string) => {
    const result = await api.messages(agentId);
    if (mountedRef.current && selectedIdRef.current === agentId) {
      setMessages(result.messages);
    }
  }, []);

  const refreshVersions = useCallback(async (agentId: string) => {
    const result = await api.versions(agentId);
    if (mountedRef.current && selectedIdRef.current === agentId) {
      setVersions(result.versions);
      setNextBeforeSequence(result.nextBeforeSequence);
    }
  }, []);

  const loadOlderVersions = useCallback(async (agentId: string) => {
    if (nextBeforeSequence === null) return;
    setHistoryBusy(true);
    try {
      const result = await api.versions(agentId, nextBeforeSequence);
      if (mountedRef.current && selectedIdRef.current === agentId) {
        setVersions((current) => {
          const merged = new Map(current.map((version) => [version.id, version]));
          for (const version of result.versions) merged.set(version.id, version);
          return [...merged.values()].sort((left, right) => right.sequence - left.sequence);
        });
        setNextBeforeSequence(result.nextBeforeSequence);
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setHistoryBusy(false);
    }
  }, [nextBeforeSequence]);

  const bootstrap = useCallback(async () => {
    await Promise.all([refreshAgents(), api.system().then(setSystem)]);
  }, [refreshAgents]);

  useEffect(() => {
    mountedRef.current = true;
    void api
      .auth()
      .then(async ({ required }) => {
        if (!mountedRef.current) return;
        setAuthRequired(required);
        if (!required) await bootstrap();
      })
      .catch((reason) => setError(reason instanceof Error ? reason.message : String(reason)));
    return () => {
      mountedRef.current = false;
    };
  }, [bootstrap]);

  useEffect(() => {
    setActiveRun(null);
    setVersions([]);
    setNextBeforeSequence(null);
    setShowHistory(false);
    setShowSettings(false);
    if (!selectedId) {
      setMessages([]);
      return;
    }
    void Promise.all([refreshMessages(selectedId), api.runs(selectedId), refreshVersions(selectedId)])
      .then(([, result]) => {
        if (selectedIdRef.current !== selectedId) return;
        const latest = result.runs[0] ?? null;
        setActiveRun(latest);
        if (latest && ["queued", "running"].includes(latest.status)) {
          void pollRun(latest.id, selectedId).catch((reason) =>
            setError(reason instanceof Error ? reason.message : String(reason)),
          );
        }
      })
      .catch((reason) =>
        setError(reason instanceof Error ? reason.message : String(reason)),
      );
  }, [refreshMessages, refreshVersions, selectedId]);

  useEffect(() => {
    if (selected) {
      setForm({
        name: selected.name,
        description: selected.description,
        instructions: selected.instructions,
      });
    }
  }, [selected]);

  useEffect(() => {
    messageEnd.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, activeRun]);

  const createAgent = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { agent } = await api.createAgent(form);
      await refreshAgents();
      setSelectedId(agent.id);
      setShowCreate(false);
      setForm(emptyForm);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const saveAgent = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      await api.updateAgent(selected.id, form);
      await refreshAgents();
      setShowSettings(false);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const toggleAgent = async () => {
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      if (selected.status === "stopped") {
        await api.startAgent(selected.id);
      } else {
        await api.stopAgent(selected.id);
      }
      await refreshAgents();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const deleteAgent = async () => {
    if (!selected) return;
    if (!window.confirm("Delete " + selected.name + "? Its workspace will be archived.")) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.deleteAgent(selected.id);
      await refreshAgents();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  };

  const pollRun = async (runId: string, agentId: string) => {
    if (pollingRunIds.current.has(runId)) return;
    pollingRunIds.current.add(runId);
    try {
      while (mountedRef.current) {
        await new Promise((resolve) => window.setTimeout(resolve, 900));
        if (!mountedRef.current) return;
        const result = await api.run(runId);
        if (selectedIdRef.current === agentId) setActiveRun(result.run);
        if (!["queued", "running"].includes(result.run.status)) {
          await Promise.all([
            refreshMessages(agentId),
            refreshAgents(),
            refreshVersions(agentId),
          ]);
          return;
        }
      }
    } finally {
      pollingRunIds.current.delete(runId);
    }
  };

  const rollbackVersion = async (version: WorkspaceVersion) => {
    if (!selected || !selected.headVersionId || version.id === selected.headVersionId) return;
    if (!selected.currentViewId || selected.stateGeneration == null) {
      setError("Rollback requires the current v3 View ID and generation. Refresh this Agent after the server migration.");
      return;
    }
    if (!window.confirm(
      "Restore version #" + version.sequence + "? This creates a new audited version and resets the Codex session.",
    )) return;
    setHistoryBusy(true);
    setError(null);
    try {
      await api.rollback(
        selected.id,
        version.id,
        selected.headVersionId,
        selected.currentViewId,
        selected.stateGeneration,
      );
      await Promise.all([refreshAgents(), refreshVersions(selected.id)]);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
      await Promise.all([refreshAgents(), refreshVersions(selected.id)]);
    } finally {
      setHistoryBusy(false);
    }
  };

  const sendMessage = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!selected || !prompt.trim()) return;
    const content = prompt.trim();
    setPrompt("");
    setError(null);
    try {
      const result = await api.sendMessage(selected.id, content);
      if (selectedIdRef.current === selected.id) {
        setMessages((current) => [...current, result.message]);
        setActiveRun(result.run);
      }
      setAgents((current) =>
        current.map((agent) =>
          agent.id === selected.id ? { ...agent, status: "busy" } : agent,
        ),
      );
      await pollRun(result.run.id, selected.id);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
      setActiveRun(null);
      await refreshAgents();
    }
  };

  const unlock = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setAuthToken(authInput);
    try {
      await bootstrap();
      setAuthRequired(false);
      setAuthInput("");
    } catch (reason) {
      if (reason instanceof ApiError && reason.status === 401) {
        setError("The access token is not valid.");
      } else {
        setError(reason instanceof Error ? reason.message : String(reason));
      }
    } finally {
      setBusy(false);
    }
  };

  if (authRequired === null) {
    return (
      <main className="auth-screen">
        <section className="auth-card" aria-live="polite">
          <div className="brand-mark">A</div>
          <span className="eyebrow">Agent Launchpad</span>
          <h1>Connecting to the control plane</h1>
          {error ? <div className="error-banner" role="alert">{error}</div> : <Spinner />}
        </section>
      </main>
    );
  }

  if (authRequired) {
    return (
      <main className="auth-screen">
        <form className="auth-card" onSubmit={unlock}>
          <div className="brand-mark">A</div>
          <span className="eyebrow">Agent Launchpad</span>
          <h1>Enter the access token</h1>
          <p>This shared demo token is configured by the platform operator.</p>
          {error && <div className="error-banner" role="alert">{error}</div>}
          <label>
            Access token
            <input
              autoFocus
              type="password"
              value={authInput}
              onChange={(event) => setAuthInput(event.target.value)}
              autoComplete="current-password"
              required
            />
          </label>
          <button className="button button-primary" disabled={busy || !authInput.trim()}>
            {busy ? <Spinner /> : "Open Launchpad"}
          </button>
        </form>
      </main>
    );
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">A</div>
          <div>
            <strong>Agent Launchpad</strong>
            <span>
              {system?.runtimeProvider === "container"
                ? "Container Runtime · Codex CLI"
                : "Local process · CRUD only with CommitGate"}
            </span>
          </div>
        </div>

        <button
          className="button button-primary create-button"
          onClick={() => {
            setForm(emptyForm);
            setShowCreate(true);
          }}
        >
          <span>＋</span> Create Agent
        </button>

        <div className="sidebar-label">
          <span>Your Agents</span>
          <span>{agents.length}</span>
        </div>
        <nav className="agent-list">
          {agents.map((agent) => (
            <button
              className={"agent-card " + (agent.id === selectedId ? "selected" : "")}
              key={agent.id}
              onClick={() => setSelectedId(agent.id)}
            >
              <div className="agent-avatar">{agent.name.slice(0, 1).toUpperCase()}</div>
              <div className="agent-card-copy">
                <strong>{agent.name}</strong>
                <span>{agent.description || "Coding Agent"}</span>
              </div>
              <span className={"mini-dot mini-" + agent.status} />
            </button>
          ))}
          {agents.length === 0 && (
            <div className="empty-sidebar">
              <span>◇</span>
              Create your first coding Agent.
            </div>
          )}
        </nav>

        <div className="runtime-card">
          <span className="eyebrow">Runtime</span>
          <strong>{system?.runtime ?? "Checking…"}</strong>
          <span>
            {providerLabel(system)}
            {system?.containerEngine ? " · " + system.containerEngine : ""}
          </span>
        </div>
      </aside>

      <main className="main">
        {!providerConfigured(system) ||
        !system?.codexAvailable ||
        !system?.commitGateReady ||
        (system?.commitGateEnabled && !system.verifierAvailable) ? (
          <div className="config-banner">
            <span>!</span>
            <div>
              <strong>Runtime configuration needed</strong>
              <p>
                {!providerConfigured(system)
                  ? "Configure MODEL_PROVIDER, MODEL_API_KEY and MODEL_ID (or the compatible Ark variables) before using the Playground."
                  : !system?.commitGateReady ||
                      (system?.commitGateEnabled && !system.verifierAvailable)
                    ? "CommitGate requires the container Runtime and an available credential-free verifier."
                  : system.runtimeProvider === "container"
                    ? "The local container engine or Agent Runtime image is unavailable. Rerun npm run poc."
                    : "Codex CLI was not found. Use the Docker image or install @openai/codex."}
              </p>
            </div>
          </div>
        ) : null}

        {error && (
          <div className="error-banner" role="alert">
            <span>{error}</span>
            <button onClick={() => setError(null)}>×</button>
          </div>
        )}

        {selected ? (
          <>
            <header className="agent-header">
              <div>
                <div className="header-title-row">
                  <h1>{selected.name}</h1>
                  <StatusPill status={selected.status} />
                </div>
                <p>{selected.description || "A Codex coding Agent in an isolated workspace."}</p>
              </div>
              <div className="header-actions">
                <button
                  className="button button-ghost"
                  onClick={() => setShowHistory((value) => !value)}
                  disabled={busy}
                >
                  Versions {versions.length ? "(" + versions.length + ")" : ""}
                </button>
                <button
                  className="button button-ghost"
                  onClick={() => setShowSettings((value) => !value)}
                  disabled={busy || selected.status === "busy"}
                >
                  Settings
                </button>
                <button
                  className="button button-ghost"
                  onClick={toggleAgent}
                  disabled={busy}
                >
                  {selected.status === "stopped" ? "Start" : "Stop"}
                </button>
                <button
                  className="button button-danger"
                  onClick={deleteAgent}
                  disabled={busy || selected.status === "busy"}
                >
                  Delete
                </button>
              </div>
            </header>

            {showSettings && (
              <form className="settings-panel" onSubmit={saveAgent}>
                <div className="settings-title">
                  <div>
                    <span className="eyebrow">Agent configuration</span>
                    <h2>Instructions and identity</h2>
                  </div>
                  <button type="button" onClick={() => setShowSettings(false)}>×</button>
                </div>
                <div className="form-grid">
                  <label>
                    Name
                    <input
                      value={form.name}
                      onChange={(event) => setForm({ ...form, name: event.target.value })}
                      required
                      maxLength={80}
                    />
                  </label>
                  <label>
                    Description
                    <input
                      value={form.description}
                      onChange={(event) =>
                        setForm({ ...form, description: event.target.value })
                      }
                      maxLength={500}
                    />
                  </label>
                </div>
                <label>
                  System instructions
                  <textarea
                    value={form.instructions}
                    onChange={(event) =>
                      setForm({ ...form, instructions: event.target.value })
                    }
                    rows={5}
                    maxLength={10_000}
                  />
                </label>
                <div className="panel-footer">
                  <code>{selected.workspacePath}</code>
                  <button className="button button-primary" disabled={busy}>
                    {busy ? <Spinner /> : "Save changes"}
                  </button>
                </div>
              </form>
            )}

            {showHistory && (
              <section className="version-panel">
                <div className="settings-title">
                  <div>
                    <span className="eyebrow">Immutable history</span>
                    <h2>Workspace versions</h2>
                  </div>
                  <button type="button" onClick={() => setShowHistory(false)}>×</button>
                </div>
                <div className="version-list">
                  {versions.map((version) => {
                    const current = version.id === selected.headVersionId;
                    return (
                      <article className={"version-row " + (current ? "version-current" : "")} key={version.id}>
                        <div>
                          <strong>#{version.sequence} · {version.kind}</strong>
                          <span>{formatTime(version.createdAt)} · {shortHash(version.snapshotHash)}</span>
                        </div>
                        {current ? (
                          <span className="version-head">Current head</span>
                        ) : (
                          <button
                            className="button button-ghost"
                            disabled={historyBusy || selected.status === "busy" || version.snapshotAvailable === false}
                            onClick={() => void rollbackVersion(version)}
                          >
                            {version.snapshotAvailable === false ? "Pruned" : "Rollback"}
                          </button>
                        )}
                      </article>
                    );
                  })}
                  {versions.length === 0 && <p>No committed versions yet.</p>}
                  {nextBeforeSequence !== null && (
                    <button
                      className="button button-ghost"
                      disabled={historyBusy}
                      onClick={() => void loadOlderVersions(selected.id)}
                    >
                      {historyBusy ? "Loading…" : "Load older versions"}
                    </button>
                  )}
                </div>
              </section>
            )}

            <AuthoritativeHead agent={selected} />

            <section className="playground">
              <div className="playground-topbar">
                <div>
                  <span className="eyebrow">Playground</span>
                  <h2>Build something with your Agent</h2>
                </div>
                <div className="session-info">
                  <span className="pulse" />
                  {selected.codexThreadId ? "Session connected" : "New session"}
                  {" · epoch " + selected.sessionEpoch}
                </div>
              </div>

              <div className="messages">
                {messages.length === 0 && !activeRun ? (
                  <div className="welcome">
                    <div className="welcome-orbit">
                      <div>⌁</div>
                    </div>
                    <h3>What should {selected.name} build?</h3>
                    <p>
                      The Agent works in an isolated proposal. Only evidence-bound promotion
                      can create the authoritative workspace seen by the next turn.
                    </p>
                    <div className="prompt-grid">
                      {starterPrompts.map((item) => (
                        <button key={item} onClick={() => setPrompt(item)}>
                          <span>↗</span>
                          {item}
                        </button>
                      ))}
                    </div>
                  </div>
                ) : (
                  messages.map((message) => {
                    const authority = displayAuthority(message);
                    return (
                    <article
                      className={"message message-" + message.role + " message-authority-" + authority.toLowerCase()}
                      key={message.id}
                    >
                      <div className="message-meta">
                        <strong>{message.role === "user" ? "You" : selected.name}</strong>
                        <span className={"authority-badge authority-" + authority.toLowerCase()}>
                          {authority === "UNCLASSIFIED" ? "legacy / unclassified" : authority.toLowerCase()}
                        </span>
                        {message.viewId && <code title={message.viewId}>view {shortIdentifier(message.viewId)}</code>}
                        <span>{formatTime(message.createdAt)}</span>
                      </div>
                      <div className="message-body">{message.content}</div>
                    </article>
                    );
                  })
                )}
                {activeRun && ["queued", "running"].includes(activeRun.status) && (
                  <article className="message message-assistant thinking">
                    <div className="message-meta">
                      <strong>{selected.name}</strong>
                      <span className="authority-badge authority-provisional">provisional</span>
                      <span>working in the Agent workspace</span>
                    </div>
                    <div className="thinking-row">
                      <Spinner />
                      Codex is reading, editing, or running commands…
                    </div>
                  </article>
                )}
                {activeRun?.status === "failed" && (
                  <article className="run-error">
                    <strong>Run failed</strong>
                    <span>{activeRun.error}</span>
                  </article>
                )}
                {activeRun && !["queued", "running"].includes(activeRun.status) && (
                  <GateCard key={activeRun.id} run={activeRun} agent={selected} />
                )}
                <div ref={messageEnd} />
              </div>

              <form className="composer" onSubmit={sendMessage}>
                <textarea
                  value={prompt}
                  onChange={(event) => setPrompt(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" && !event.shiftKey) {
                      event.preventDefault();
                      event.currentTarget.form?.requestSubmit();
                    }
                  }}
                  placeholder={
                    selected.status === "stopped"
                      ? "Start this Agent to continue…"
                      : "Describe what you want the Agent to do…"
                  }
                  disabled={
                    selected.status === "stopped" ||
                    selected.status === "busy" ||
                    !system?.commitGateReady ||
                    (system?.commitGateEnabled && !system.verifierAvailable) ||
                    activeRun != null && ["queued", "running"].includes(activeRun.status)
                  }
                  rows={3}
                />
                <div className="composer-footer">
                  <span>
                    Enter to send · Shift + Enter for newline · {system?.codexSandboxMode ?? "checking sandbox"}
                  </span>
                  <button
                    className="send-button"
                    disabled={
                      !prompt.trim() ||
                      selected.status === "stopped" ||
                      selected.status === "busy" ||
                      !system?.commitGateReady ||
                      (system?.commitGateEnabled && !system.verifierAvailable) ||
                      (activeRun != null && ["queued", "running"].includes(activeRun.status))
                    }
                    aria-label="Send message"
                  >
                    ↑
                  </button>
                </div>
              </form>
            </section>
          </>
        ) : (
          <div className="no-agent">
            <div className="no-agent-art">A</div>
            <span className="eyebrow">Agent Launchpad</span>
            <h1>Your runtime is ready for an Agent.</h1>
            <p>Create a workspace, give Codex a job, and continue the conversation here.</p>
            <button
              className="button button-primary"
              onClick={() => {
                setForm(emptyForm);
                setShowCreate(true);
              }}
            >
              Create your first Agent
            </button>
          </div>
        )}
      </main>

      {showCreate && (
        <div className="modal-backdrop" onMouseDown={() => setShowCreate(false)}>
          <form
            className="modal"
            onSubmit={createAgent}
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="modal-heading">
              <div>
                <span className="eyebrow">New workspace</span>
                <h2>Create an Agent</h2>
                <p>
                  Each Agent gets an authoritative workspace, isolated proposals, and a
                  session bound to the current state view.
                </p>
              </div>
              <button type="button" onClick={() => setShowCreate(false)}>×</button>
            </div>
            <label>
              Name
              <input
                autoFocus
                placeholder="Frontend Builder"
                value={form.name}
                onChange={(event) => setForm({ ...form, name: event.target.value })}
                required
                maxLength={80}
              />
            </label>
            <label>
              Description
              <input
                placeholder="Builds polished React prototypes"
                value={form.description}
                onChange={(event) =>
                  setForm({ ...form, description: event.target.value })
                }
                maxLength={500}
              />
            </label>
            <label>
              Instructions
              <textarea
                value={form.instructions}
                onChange={(event) =>
                  setForm({ ...form, instructions: event.target.value })
                }
                rows={6}
                maxLength={10_000}
              />
            </label>
            <div className="modal-footer">
              <button
                type="button"
                className="button button-ghost"
                onClick={() => setShowCreate(false)}
              >
                Cancel
              </button>
              <button className="button button-primary" disabled={busy}>
                {busy ? <Spinner /> : "Create Agent"}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
