# CommitGate architecture — No Evidence, No Effect

CommitGate is a focused transaction boundary around an `AgentRunner`. It does
not replace the Codex/Agent loop. It changes what workspace that loop can write
and introduces a trusted transition between Agent completion and the next
authoritative state.

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

The protocol's two persistence invariants are:

```text
COMMITTED:
  sealedProposalHash
  == verifierInputHash
  == promotionSourceHash
  == finalAuthoritativeHash

NON-COMMIT:
  authoritativeAfterHash == authoritativeBeforeHash
```

The latter compares the disposition-time authoritative HEAD. For a conflict,
that may differ from the proposal's stale admission base because another valid
transition already advanced HEAD. CommitGate proves that rejecting this proposal
added no further persistent effect.

Receipts expose that derivation as:

```ts
interface EffectDispositionProof {
  candidateChanged: boolean; // compatibility projection of candidateObservation
  candidateObservation: "changed" | "unchanged" | "unobserved";
  admissionBaseHash: string;
  authoritativeBeforeHash: string;
  authoritativeAfterHash: string;
  authoritativeChanged: boolean;
  sealedProposalHash: string | null;
  verifierInputHash: string | null;
  promotionSourceHash: string | null;
  finalAuthoritativeHash: string;
  invariant: "PROMOTED_EXACT_PROPOSAL" | "NO_PERSISTENT_EFFECT";
  invariantSatisfied: boolean;
}
```

This structure is derived from Worker facts; an RPC caller does not supply
`invariantSatisfied` as authorization.

## Deployment policy packs

The deployment selects one versioned Worker-owned profile; the API never sends
arbitrary protected paths over RPC:

```text
workspace-default@1
  generic Manifest v2, budgets, ignored and platform-managed paths

deployment-protected@2
  workspace-default plus:
  .github/workflows/deploy.yml
  infra/production.yaml
  config/payment-production.json
```

The Worker persists `profile + version + policyHash + checkSpecHash` in its
Control volume. A silent profile switch fails with `POLICY_PROFILE_MISMATCH`.
Every terminal receipt binds the same identity inside its Ed25519 signature.

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

Production RPC inputs carry an expected base View and an operation, not a
caller-authored next View. The Worker derives the final generation, hashes,
head and `ViewId` from its authoritative filesystem and append-only parent
event. The API/product database can project that Worker-derived StateView but
cannot supply or overwrite it.

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

In the production topology, the Worker is the sole RW owner of the sealed store
and Authority/Control volumes. The API has read-only mounts and the Broker has
neither mount. Proposal modes are preserved in the manifest and restored only
into Worker-owned staging. Thus sealing is closed by content-addressed
ownership, pre/post manifest validation, opaque RPC refs, and an OS permission
boundary. The in-process `WorkspaceTransitionWriter` remains available only for
development and contract tests; production does not fall back to it.

The Worker derives the only admissible exchange names: `candidate-${runId}` and
`verify-${runId}`. It binds the candidate to the admitted Agent/run/lease/session
and binds the verifier export to the same run and sealed proposal. These are
opaque identifiers, not client-selected paths. Bindings are write-once: sealing
consumes and tombstones the candidate, exports refuse an existing or foreign
destination, and neither a caller nor a restarted process can rebind a terminal
name to another Agent, run, or proposal.

The Transition Worker and Runtime Broker do not share an RPC socket directory.
They publish sockets into distinct named volumes and distinct Unix groups; the
API has read-only client mounts for both, while the Broker has no mount for the
Worker socket. This prevents the Docker-socket holder from calling promotion
authority directly, rather than relying on a shared application token.

The Worker, Broker, and Runtime artifacts deliberately use numeric UID `10001`.
Worker exports are normalized to owner-only `0500/0600`, so the Broker must use
that artifact-owner UID to hash the exact export before and after verification.
This is **not** a distinct-UID isolation claim: separation comes from disjoint
mounts and socket groups (`20001` Worker RPC, `20002` Broker RPC). Only the
Worker receives Authority/Control mounts; the Broker receives neither.

The Broker also keeps a durable monotonic lifecycle ledger in its Session
volume, keyed by the exact `runId + agentId + runLeaseId + sessionEpoch`
binding. A run advances only through `AGENT_STARTED -> AGENT_CLOSED ->
VERIFIER_STARTED -> ALL_CLOSED`. Teardown/reconciliation for a binding never
launched by this Broker is rejected; after Agent closure the Agent cannot be
restarted, and after full closure neither Agent nor Verifier can be relaunched.
Those tombstones survive a Broker process restart and prevent a signed negative
attestation from being followed by a new container under the same binding.

### Broker-to-Worker evidence authentication

The Broker is the only product service that owns the Docker socket, so the
Worker cannot independently inspect Agent/Verifier containers. Production
therefore gives only Broker and Worker a per-start `0600` secret and requires
HMAC-SHA256 authenticated evidence at the authority boundary:

```text
runtime-teardown:
  runId + agentId + runLeaseId + sessionEpoch + scope
  + containerExited + containerRemoved + mountsReleased + source

verifier-result:
  run/lease/session + proposalId + verifierInputHash
  + checkSpecHash + checkResultsHash + coverage + bounded check results
  + checkBundle/image/config/resource/source pins
```

The Worker verifies the MAC, exact transition binding, proposal hash, check
results, and frozen environment pins before recording evidence. The API cannot
turn a caller-authored success boolean or unsigned JSON into a seal/permit fact.
This is an authenticity boundary relative to the shared Broker/Worker key, not
remote attestation: a compromised Broker can still lie about Docker, a
compromised Worker can accept it, and host/root controls both. It is separate
from the Relay HMAC bearer (model access) and Worker Ed25519 signature (terminal
receipt integrity).

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

Permit issuance recomputes authorization from a Worker-owned frozen contract.
It rejects proposals with static policy failures and requires exact equality
for Manifest schema, policy hash, check-spec hash, source revision, and the set
of required check IDs. It also compares the trusted-bundle hash, Verifier image
digest, Verifier config hash, and resource-policy hash with values frozen in
the Worker configuration before startup. Coverage must be complete and every expected check must
independently be `PASS` with exit code zero and no timeout. The caller-provided
`requiredChecksPassed` field is only cross-checked; it is never an
authority-bearing boolean.

`sourceRevision` participates in the context hash. Portable development/tests
may retain the literal `unverified`, while the production API, Runtime Broker,
and Transition Worker require one matching full 40-hex
`COMMITGATE_SOURCE_REVISION`. The Worker rejects product evidence whose context
does not match its frozen revision. A context hash still does not prove that an
environment value matches a clean tree; the release report separately binds
the commit, source-tree hash, and image identities.

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
a semantic whole-program proof. The release topology adds a runtime proof:
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

The Docker matrix kills the Worker and API at named protocol points and kills
Broker-owned Agent/Verifier child containers. A dedicated
`RUNTIME_BROKER_PROCESS_SIGKILL_ORPHAN_RECONCILIATION` scenario launches the
Runtime Broker as a separate Node process, kills that process with `SIGKILL`,
observes its labeled Agent child still running, and verifies that a restarted
Broker performs exact-label reconciliation before returning a
`broker-reconciliation` mount-release attestation. The Docker daemon itself
remains alive; daemon, host, and power-loss failures remain outside this claim.

Receipts have a separate projection lifecycle. A protocol-complete
`PENDING_PROMOTION` receipt is persisted before rename-swap; `COMMITTED` becomes
a terminal receipt only after workspace/head/session projection is complete.
Terminal receipt bytes are immutable. Recovery never changes an old terminal
decision in place: it appends a `RECOVERY_ACKNOWLEDGED` or
`RECOVERY_ROLLED_BACK` sidecar event, from which the effective recovered state
is projected. A pre-swap pending receipt without a journal is fail-closed
against the admitted base hash.

The Worker event stream stores bounded structured metadata and content
digests, not raw rejected source. A complete, redacted `RecordedEvidenceV2`
is written to a content-addressed blob store before `EVIDENCE_RECORDED` is
appended. Permit issuance re-reads that blob and recomputes the proposal,
evaluation-context, verifier-input, check-result, and evidence bindings. If a
blob is missing, malformed, over budget, linked, or has changed bytes or file
metadata, issuance fails closed. Deleting the mutable projection and replaying
the append-only events therefore rebuilds Proposal, Evidence, Permit, Receipt,
version, and HEAD state without treating the product database as authority.

Every terminal receipt is also bound to the terminal event sequence/digest and
signed with a Worker-owned Ed25519 key. The private key exists only in the
Worker control volume as a single-link regular `0600` file. The public proof
endpoint returns the redacted receipt, proof envelope, and public key; the
live topology audit also confirms that the API UID receives `Permission
denied` when it attempts to read that private key through its read-only control
projection. The
offline verifier checks canonical receipt bytes, event-chain binding,
Proposal/Evidence/Permit digests, source revision, and signature. This proves
origin and post-issuance integrity relative to that Worker key. It is not
remote transparency, hardware attestation, or resistance to a hostile
host/root user or compromised Worker.

For the product/browser proof, the verifier first reads the 24-hex
`authorityReceiptSigningKeyId` from `/api/system`, before any Agent run, and
later requires the returned proof key to match it. This is a pre-run TOFU
(trust-on-first-use) anchor, not an independent CA, transparency log, or
host/root-resistant identity. It detects a key substituted only after the
initial observation; it cannot make a compromised first observation trusted.

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
adapter. The repository supplies Ark and OpenRouter adapters, and Provider
choice is not part of the middleware scoring claim. A historical real E2E
capture used Ark and records that fact only for its embedded revision. A new
source identity has no current Provider claim until its report is regenerated.
New reports use
`providerE2EVerified`; historical `officialProviderE2E` and
`competitionVerified` values are read-only compatibility inputs and never
assign checklist credit. Receipts record provider, gateway, requested model,
and resolved model when the transport can prove it; otherwise `resolvedModel`
remains `null`. `MODEL_WIRE_API` is configuration, and retry lineage is held by
the product run record rather than being invented in a receipt. Automatic
fallback orchestration is not implemented: `retryOfRunId` is currently a
reserved field initialized to `null`. The deployed release process uses
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
paths are redirected to bounded tmpfs mounts. Independently, Manifest v2
classifies those names at **any path segment**. A streaming admission scan
counts their entries, aggregate bytes, and single-file size against candidate
resource quotas, while omitting their content from Proposal, Verifier input,
promotion, and the next authoritative View.

The same streaming walk has a monotonic wall-clock budget of 30 seconds by
default. Entry, byte, single-file, and time limits are all fail-closed;
exceeding the time fence produces `CANDIDATE_SCAN_TIME_BUDGET_EXCEEDED`.
Ignored entries consume these scan resources even though their contents are
excluded from the authoritative proposal.

The production Compose path mounts the single-active-run exchange as a shared
tmpfs with fixed byte and inode ceilings. An arbitrary nested ignored directory
therefore cannot grow beyond the kernel-enforced aggregate exchange budget even
before teardown. Manifest limits still enforce per-class and single-file
admission rules. This is sufficient only under the documented single-Agent
serial boundary; it is not a general multi-tenant per-run quota scheduler.

## UI projection

The existing polling path remains `GET /api/runs/:id`. The UI projects, without
inventing missing legacy fields:

```text
Authoritative HEAD: generation / View / live hash / version / session
Transition: HEAD -> SEALED PROPOSAL -> ONE-SHOT PERMIT -> HEAD
Receipt: proposal / context / evidence / permit / provider identities
Effect proof: candidate changed / persistent changed-or-unchanged / invariant
Receipt proof: terminal event binding / Ed25519 signature / public key
Message: authority + View binding
Rejected: artifact destroyed / evidence metadata only
```

## Product and research boundary

- **P0 protocol:** sealed proposal,
  evidence-bound permit, generation/View CAS, verifier isolation, callback
  fencing, process kill/restart recovery, generic Provider adapter.
- **P1 product wiring:** Transition Worker with sole RW Authority/Control
  volumes, append-only event fact source, typed private RPC, constrained repair
  CLI, and an explicit normalized Linux filesystem contract. Worker/Broker/
  Runtime artifacts share UID `10001`; service separation comes from mounts and
  socket groups, not a false distinct-UID claim.
- **Product proof closure:** complete Worker evidence projection,
  explicit effect-disposition proof, Ed25519 terminal-receipt signing, offline
  verification, real Docker process-kill evaluation, and invariant/performance
  reports.
- **Research-only:** semantic-intent shadow evidence, Effect Outbox/tool
  capability mediation, and optional hardware/remote attestation.

The invariant report uses an exact ten-item effect-capable negative-fixture
registry. Browser quarantine, abort, and permit replay include raw
authoritative before/after hashes. Three CAS and four accepted-cancellation
fixtures are separately labelled `assertion-backed` and bind to named tests;
their raw-hash fields remain `null`. The release audit rejects a missing
fixture, an unexpected fixture, or an assertion-backed observation presented
as a raw hash.

The performance report is narrower than the product topology above. It is a
Transition Worker local-filesystem microbenchmark covering seal, export,
manifest plus fixed-file deterministic probe, permit, and promotion. It does
not traverse Broker RPC or launch the product Verifier/trusted-check process,
so `deterministicProbeMs` is not Verifier-container or end-to-end latency.

The default product path now calls the Worker RPC and unified Compose enforces
sole-RW mounts. In the production Linux profile, Worker Manifest v2 checks
regular file/dir shape, hardlinks, Unicode/casefold collisions, sparse files,
expected UID/GID, normalized modes, xattrs, non-trivial ACLs, EXDEV, and swap
filesystem identity. Any xattr or non-trivial ACL is rejected rather than
preserved. Portable in-process development does not make this strong-profile
claim. The Worker log plus evidence blobs rebuild transition, head, version,
proposal, evidence, permit, terminal receipt, and proof projections; user
messages and unavailable natural-language Agent output are not invented during
reconstruction.
The expected Linux, recovery, live topology, and real-Provider clean-clone
machine gates describe the default Worker authority path only after their
reports are regenerated for one frozen source identity. `P1 hardened` remains
withheld until those gates are regenerated for
the frozen release source and the required narrated three-minute submission
video is recorded and validated. Research-only intent/outbox/attestation work
has neither product-path enforcement nor frozen metrics and receives no release
credit.

The evaluation tree contains an executable clean-clone Playwright driver
that builds the app/Runtime/Relay, drives the required browser decisions and
rollback, exercises the consumed-permit replay fence, and hashes trace/video/
screenshot/report artifacts. Historical **2026-08-27** machine evidence applies
only to its earlier source revision and images, not Authority V2. Every source
change requires a new clean-revision record; missing current evidence is
reported as `unverified`. The repository evidence checklist is an index, not an
organizer score or substitute for independent judging.
