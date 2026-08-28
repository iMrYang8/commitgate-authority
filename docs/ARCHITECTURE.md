# CommitGate architecture — Sealed State View protocol

CommitGate remains a focused decorator around the Starter Kit `AgentRunner`.
It does not replace the Codex/Agent loop. It changes what workspace that loop
can write and introduces a trusted transition between Agent completion and the
next authoritative state.

> The only positive authority is a one-shot `PromotionPermit` bound to one
> immutable `SealedProposal`, one `EvaluationContextHash`, and one current base
> `ViewId`.

- Editable one-page diagram: [`commitgate-architecture.drawio`](commitgate-architecture.drawio)
- Reviewable SVG: [`commitgate-architecture.svg`](commitgate-architecture.svg)

## End-to-end state flow

```text
Browser / React Playground
  -> Fastify API
  -> AgentService acquires RunLease and BaseView V0
  -> Transition Worker materializes an opaque isolated candidate ref
  -> Runtime Broker launches Agent Runtime with candidate/scratch only
  -> Broker returns Runtime teardown attestation
  -> Worker imports gate-owned SealedProposal P1 and destroys the candidate
  -> Worker exports a readonly verifier ref from P1
  -> platform-owned TrustedCheckBundle runs in credential-free verifier
  -> EvaluationContextHash C1 + EvidenceBundle E1
  -> Worker records evidence and mints one-shot PromotionPermit K1
  -> Worker CAS(current ViewId == V0), consumes K1, and stages only from P1
  -> Worker rename-swap + append-only terminal events
  -> API updates product DB/message/session cache from Worker disposition
  -> authoritative View V1 / generation g+1
```

Negative outcomes do not advance the authoritative workspace:

```text
trusted policy/check rejection           -> QUARANTINED (UI: Rejected)
base View no longer current               -> CONFLICTED
Runtime/verifier/evidence/cancel failure  -> ABORTED
```

`QUARANTINED` is not a generic failure bucket. It means trusted evidence reached
an explicit negative verdict. Timeout, `ERROR`, missing output, malformed
output, and unavailable infrastructure are `ABORTED`.

## Authoritative View

A workspace hash is necessary but insufficient because content can traverse
`H0 -> H1 -> H0`. The transition protocol therefore compares a complete state
reference:

```ts
interface StateViewRef {
  schemaVersion: 1;
  viewId: string;                 // hash of the canonical fields below
  agentId: string;
  headVersionId: string;
  generation: number;             // monotonic; prevents ABA replay
  versionedHash: string;
  platformManagedHash: string;
  liveStateHash: string;
  sessionEpoch: number;
  agentConfigVersion: number;
  policyVersion: number;
}
```

Commit, rollback, and Agent-configuration/platform regeneration advance the
generation. A non-commit leaves the workspace generation unchanged but
increments the session epoch, producing a new `ViewId` and fencing old
continuations/callbacks. Agent deletion archives the directory and removes the
product record; there is no restore transition in the current product.

## Proposal ownership transfer

“Frozen candidate” means ownership transfer, not merely “we calculated a hash.”
After Runtime teardown, CommitGate imports candidate content into a gate-owned,
content-addressed sealed store:

```ts
interface SealedProposal {
  schemaVersion: 1;
  proposalId: string;
  runId: string;
  agentId: string;
  baseViewId: string;
  artifactHash: string;
  manifestHash: string;
  changedPathsDigest: string;
  runtimeTeardownDigest: string;
  state: "SEALED" | "DESTROYED";
  sealedAt: string;
}
```

Downstream code accepts `proposalId`, not a caller-controlled source path. The
Verifier, promotion staging, and version snapshot must all materialize from this
same proposal. After sealing, the original candidate is destroyed; modifying
or recreating its old pathname has no effect on the proposal.

In the production topology, a dedicated-UID Worker owns the sealed store and
the Authority/Control volumes. The API has read-only mounts and the Broker has
neither mount. Proposal modes are preserved in the manifest and restored only
into Worker-owned staging. Thus sealing is closed by content-addressed
ownership, pre/post manifest validation, opaque RPC refs, and an OS permission
boundary. The in-process `WorkspaceTransitionWriter` remains available only for
development and contract tests; production does not fall back to it.

P0 filesystem normalization permits authoritative regular directories/files
only. Symlinks, special files, hardlinks (`nlink > 1`), Unicode normalization
collisions, and case-fold collisions fail closed. Ephemeral `.git`, `.codex`,
`node_modules`, `dist`, and `coverage` trees are absent from the authoritative
state instead of being silently carried across Views.

## Evaluation context and trusted evidence

Evidence is replay-safe only when it identifies exactly what was evaluated:

```ts
interface EvaluationContext {
  runId: string;
  agentId: string;
  proposalId: string;
  baseView: StateViewRef;
  manifestSchemaVersion: number;
  policyHash: string;
  checkBundleHash: string;
  checkSpecHash: string;
  verifierImageDigest: string;
  verifierConfigHash: string;
  resourcePolicyHash: string;
  sourceRevision: string;
}
```

The policy contains the complete typed check spec: `id`, `runner`, `entrypoint`,
`args`, timeout, and scratch budget. Its entrypoint must be a regular file in a
platform-owned, content-addressed bundle. Candidate-controlled `package.json`,
PATH, test runners, or wrappers, `NODE_OPTIONS`, and `PYTHONPATH` are not
acceptance authority. This is not an ID-only registry, and the gate does not
inspect a platform-owned executable to forbid a shebang or shell internally.
Each check gets a read-only `/proposal`, read-only check bundle, clean
environment, independent scratch, and the shared per-run time/output budget.
The content-addressed trusted-bundle store currently has no pruning/retention
worker; storage growth is an operational limitation rather than part of the
acceptance protocol.

`sourceRevision` participates in the context hash, but defaults to the literal
`unverified` unless `COMMITGATE_SOURCE_REVISION` is supplied. A context hash
therefore does not by itself prove that the revision matches the clean tree;
the evidence report must bind and verify that provenance separately.

The Docker verifier has no routable network, Provider credentials, Codex home,
persistent workspace, control plane, or Docker socket. This is a verifier
boundary, not a whole-product no-egress claim.

## One-shot promotion capability

```ts
interface PromotionPermit {
  permitId: string;
  proposalId: string;
  baseViewId: string;
  targetArtifactHash: string;
  evaluationContextHash: string;
  evidenceDigest: string;
  nonce: string;
  expiresAt: string;
  state: "ISSUED" | "CONSUMING" | "CONSUMED" | "REVOKED";
}
```

The workspace transaction API accepts only `permitId` (or a dedicated rollback
permit), not a raw source path plus a `passed=true` flag. Permit consumption and
View compare-and-swap are part of one transition. A consumed, expired, revoked,
or stale-base permit cannot be replayed.

Issuance requires `coverage=complete`, `requiredChecksPassed=true`, and an
evidence verifier-input hash equal to the proposal manifest. Claiming creates a
durable exclusive claim. After checking the current View, the transaction calls
the capability's local-and-durable `consume()` exactly once immediately before
swap; both closure replay and persisted-state replay fail closed.

Rollback has its own capability type rather than reusing a promotion permit. A
`RollbackPermit` binds the target version/snapshot hash, expected head, and base
hash. The transaction hashes the snapshot before import, copies only versioned
state into staging, regenerates current platform-managed state, then hashes the
staged versioned bytes again before authorization consumption and rename-swap.
This second check closes mutation during snapshot import rather than trusting a
pre-copy check alone.

## Transition Authority boundary

All production persistent filesystem writes flow through the Transition Worker:

```text
createAgentWorkspace
materializeCandidate
sealProposal
applyPromotion
applyRollback
regeneratePlatformState
archiveAgent
recoverTransition
applyRepair
```

The static authority audit remains a defense-in-depth callsite fence; it is not
a semantic whole-program proof. The production topology adds a runtime proof:
`audit:topology` executes writes inside the API container and requires
`EROFS/EACCES` for Authority and Control, verifies that only the Worker has RW
mounts, and verifies that only the Broker has the Docker socket. These claims
exclude a hostile host/root user or a compromised container engine.

## Promotion and recovery boundary

```text
PERMIT ISSUED -> durable claim / permit CONSUMING
  -> persist protocol-complete PENDING_PROMOTION receipt
  -> build staging from sealed proposal and restore manifest-sidecar modes
  -> re-check current ViewId
  -> consume permit exactly once / permit CONSUMED
  -> persistent -> backup
  -> staging -> persistent
  -> validate target hash
  -> journal PROMOTED_PENDING_DB
  -> project next head/version/run/session state
  -> remove backup / journal ACKNOWLEDGED
  -> terminal COMMITTED receipt
  -> release admission lease
```

Process-kill recovery uses journal, permit, product head/View, persistent hash,
and backup state to select one deterministic forward/rollback outcome. Ambiguous
or externally corrupted state enters `RECOVERY_REQUIRED` rather than guessing.
The documented guarantee is process kill/restart. It is not an fsync protocol
and does not cover sudden power loss or storage-controller failure.

Receipts have a separate projection lifecycle. A protocol-complete
`PENDING_PROMOTION` receipt is persisted before rename-swap; `COMMITTED` becomes
a terminal receipt only after workspace/head/session projection is complete.
Terminal receipt bytes are immutable. Recovery never changes an old terminal
decision in place: it appends a `RECOVERY_ACKNOWLEDGED` or
`RECOVERY_ROLLED_BACK` sidecar event, from which the effective recovered state
is projected. A pre-swap pending receipt without a journal is fail-closed
against the admitted base hash.

## Message and callback fencing

```text
User request                       -> INPUT
Agent output before decision       -> PROVISIONAL
output attached to committed View  -> AUTHORITATIVE
output from non-commit             -> REJECTED
legacy/invalidated lineage         -> SUPERSEDED
```

The current product does not rebuild a Provider prompt from all historical
`INPUT`/`AUTHORITATIVE` rows. It continues the Provider thread only while the
View/session epoch remains accepted; after a non-commit, rollback, recovery, or
configuration reset it clears the thread and sends a trusted reconciliation
prefix plus the new user request. Rejected/superseded messages remain visible
in the database/UI but are not explicitly re-sent.

Every callback carries `runLeaseId + baseViewId + sessionEpoch`; stale callbacks
can append audit metadata but cannot update Agent, Run, Message authority, or
head. The execution-time fence can rebind an admitted run that is still in its
brief pre-execution `queued` window. The public API returns `409` for a new
message while the Agent is busy, so this is not a general queue behind an
active run.

## Provider identity

Provider transport is configured through a generic Responses-compatible
adapter. Ark is the primary configured provider path; OpenRouter is an alternate
development path. Receipts record provider, gateway, requested model, and
resolved model when the transport can prove it; otherwise `resolvedModel`
remains `null`. `MODEL_WIRE_API` is configuration, and retry lineage is held by
the product run record rather than being invented in a receipt. Automatic
fallback orchestration is not implemented: `retryOfRunId` is currently a
reserved field initialized to `null`. The deployed production process uses
one configured Provider; a manual Provider change needs a restart, explicit
Agent configuration/session reset, and a new run.

The production CommitGate configuration accepts model access only through the
container Runtime plus Model Relay on a dedicated internal network. The API
process must receive no upstream Provider key. The Agent receives a short-lived
HMAC bearer whose signed payload records run, Agent, and session epoch. The
relay verifies signature/TTL, an in-memory active-token registration, and its
configured model, but the HTTP request carries no independently authenticated
run/Agent/session identity; possession of the bearer is the actual request
authority. The capability may make the multiple Responses calls needed by that
run. Runtime teardown calls the authenticated admin endpoint to revoke the
nonce, and a failed activation/revocation fails closed. Because the registry is
in-memory, relay restart invalidates all outstanding capabilities and aborts
their availability. Conversely, an API crash after activation can leave the
unpersisted bearer registered at the Relay until TTL because the API process no
longer has the token needed for revocation. Revocation rejects later calls but
does not cancel an upstream request already forwarded. Production also requires
an explicit API-reachable
`MODEL_RELAY_ADMIN_URL`, and the Runtime inspects the Docker network to require
its actual `Internal` flag. Development/test profiles may still use direct mode
and are not evidence for this production boundary.

The relay mediates the Responses request path; it is not a general-purpose tool
firewall or proof of zero egress through a hostile host/container engine.

## Runtime scratch and ignored paths

The default root-level `.git`, `.codex`, `node_modules`, `dist`, and `coverage`
paths are redirected to bounded tmpfs mounts. Independently, a streaming gate
audit counts entries, aggregate bytes, and single-file size for ignored path
segments at arbitrary nesting depths; those trees are omitted before seal.

There is a deliberate P0 limitation: with a host bind-mounted candidate, an
arbitrary nested ignored directory is not placed on its own filesystem quota
during Runtime execution. It can consume host disk until teardown, after which
the streaming audit rejects it before seal. Hard aggregate runtime quota for
every nested ignored path requires the P1 per-run volume/filesystem boundary.

## UI projection

The existing polling path remains `GET /api/runs/:id`. The UI projects, without
inventing missing legacy fields:

```text
Authoritative HEAD: generation / View / live hash / version / session
Transition: HEAD -> SEALED PROPOSAL -> ONE-SHOT PERMIT -> HEAD
Receipt: proposal / context / evidence / permit / provider identities
Message: authority + View binding
Rejected: artifact destroyed / evidence metadata only
```

## P0, P1, and P2 boundary

- **P0 protocol:** sealed proposal,
  evidence-bound permit, generation/View CAS, verifier isolation, callback
  fencing, process kill/restart recovery, generic Provider adapter.
- **P1 product wiring:** separate UID transition-worker with sole RW volumes,
  append-only event fact source, typed private RPC, constrained repair CLI, and
  an explicit normalized Linux filesystem contract.
- **P2 research:** semantic-intent shadow evidence, Effect Outbox/tool
  capability mediation, signed proof bundles, and optional attestation.

The default product path now calls the Worker RPC and unified Compose enforces
sole-RW mounts. Worker manifest code checks regular file/dir shape, hardlinks,
Unicode/casefold collisions, sparse-file/EXDEV policy, and swap filesystem
identity. xattr/ACL and arbitrary ownership preservation are outside the
normalized state contract. The Worker log rebuilds transition, head, version,
permit, and terminal receipt identity/decision projections; user messages and
unavailable verbose verifier output are not invented during reconstruction.
The revision-bound Linux, recovery, live topology, and Ark clean-clone machine
gates are now verified for the default Worker authority path. `P1 hardened`
remains withheld until the required narrated three-minute submission video is
recorded and validated. P2 has neither product-path enforcement nor frozen
shadow metrics; focused code and tests do not establish `P2 research-verified`.

The evaluation tree contains an executable clean-clone Playwright driver
that builds the app/Runtime/Relay, drives the required browser decisions and
rollback, exercises the consumed-permit replay fence, and hashes trace/video/
screenshot/report artifacts. Historical **2026-08-27** machine evidence applies
only to its earlier source revision and images, not Authority V2. Every source
change requires a new clean-revision record; missing current evidence is
reported as `unverified`. The repository evidence checklist is an index, not an
external security review or independent verification.
