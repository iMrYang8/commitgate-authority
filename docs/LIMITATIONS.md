# CommitGate guarantees, assumptions, and non-goals

## Exact Authority V2 claim

For one protected local-Docker run, CommitGate lets an Agent write an isolated
candidate and then transfers ownership into a gate-controlled immutable
`SealedProposal`. A proposal can become the next authoritative filesystem View
only through an unexpired, one-shot `PromotionPermit` bound to:

- that proposal/artifact digest;
- the complete Evaluation Context and trusted-evidence digest;
- the expected base View ID and generation;
- the promotion target digest.

Verifier input, promotion source, and version snapshot must derive from the same
proposal identity. A stale View, changed context, incomplete evidence, or
replayed permit cannot authorize promotion.

The corresponding receipt proof is intentionally narrow:

```text
COMMITTED:
sealedProposalHash == verifierInputHash == promotionSourceHash
                   == finalAuthoritativeHash

NON-COMMIT:
authoritativeAfterHash == authoritativeBeforeHash
```

`EffectDispositionProof` derives these values from Worker facts and labels the
result `PROMOTED_EXACT_PROPOSAL` or `NO_PERSISTENT_EFFECT`. For `CONFLICTED`, the
before hash is the disposition-time HEAD after another valid transition, not the
stale admission base. The proof means this rejected proposal caused no further
effect; it does not say no other authorized transition occurred.

This guarantee is deliberately scoped to:

- a local Docker/Linux Runtime and the recorded image identities;
- one API process plus dedicated Transition Worker, Runtime Broker and Relay;
- at most one serial state transition per Agent;
- filesystem effects under the authoritative Agent workspace;
- process kill/restart recovery at the tested journal points;
- a normal, case-sensitive filesystem with supported rename behavior;
- no hostile host/root writer bypassing the control plane.

The reported invariant rates are finite-fixture results, not estimates of a
universal production failure probability. Their denominator is the exact
ten-item effect-capable negative registry. Only three browser observations
carry raw before/after hashes; seven CAS/cancellation observations are clearly
labelled assertion-backed and retain `null` raw-hash fields.

The performance report is also deliberately narrow: it measures Worker-local
filesystem protocol phases and a manifest plus fixed-file deterministic probe.
It excludes Broker RPC, the real Verifier container, the trusted-check bundle
process, model inference, and network latency. It is not evidence for product
Verifier latency or complete Agent Run latency.

Here “immutable” is a protocol property, not an OS immutable flag. The Worker
owns sealed bytes and Authority/Control RW mounts; API sees those volumes RO,
while Broker and Relay do not mount them. Pre/post manifests, content addressing
and one-shot permits remain necessary. A host/root actor or compromised Docker
engine can still bypass this boundary.

Worker, Broker, and Runtime artifacts deliberately share numeric artifact-owner
UID `10001` because Broker must hash Worker exports normalized to `0500/0600`.
This is not distinct-UID service isolation. Authority/Control mount ownership and
separate Unix socket groups establish the service boundary; Broker and Relay do
not mount Authority/Control.

The only exchange references are Worker-derived `candidate-${runId}` and
`verify-${runId}`. Their Agent/run/lease/session/proposal bindings are write-once;
candidate sealing and terminal export states leave durable tombstones. This
prevents caller-selected paths, cross-run rebinding, and reuse after Broker/
Worker restart under the documented process threat model.

## Verifier boundary, not whole-system no-egress

The verifier receives a read-only proposal, read-only trusted-check bundle, and
bounded scratch. On the verified Docker path it has:

- `--network none`;
- no Provider key or Codex home;
- no persistent workspace or CommitGate control-root mount;
- no Docker socket;
- dropped capabilities and resource ceilings.

This establishes a **Verifier no-network boundary**. It does not establish a
whole-product no-egress boundary. A real Agent Runtime necessarily communicates
with a model Provider, and P0 does not claim complete host firewalling,
information-flow control, side-channel elimination, or mediation of arbitrary
shell/device effects.

The production configuration does fail closed unless CommitGate uses the
container Runtime, Model Relay, and a dedicated internal Agent network; it also
rejects an upstream Provider key in the API process. The relay issues a
short-lived HMAC bearer whose signed payload records run, Agent, and session
epoch, enforces one configured model, and revokes the capability nonce after
Runtime teardown. The request has no separately authenticated
run/Agent/session identity against which the relay could compare those signed
fields; possession of the bearer is the actual request authority. A capability
is multi-request because an Agent loop can require several model calls.
Activation/revocation failure is recorded in teardown evidence and prevents a
successful seal. The activation/revocation registry is in-memory: relay restart
invalidates all outstanding active capabilities and interrupts their runs. The
opposite crash ordering is not durably closed: if the API dies after activation
and loses the bearer before revocation, a holder may keep using that activated
bearer until TTL. Revocation prevents future Relay calls but cannot cancel an
upstream request that was already forwarded. Gateway responses without one
consistent parseable model identity yield `resolvedModel: null`; requested
model is not substituted as proof. The Runtime inspects the configured Docker
network and requires `Internal: true`,
but this still narrows only the model request path and does not prove complete
host egress mediation. The 2026-08-27 Ark/Playwright report verifies this Relay
path for its recorded source/image identity; it does not prove general host
egress mediation.

## Broker evidence authenticity, not remote attestation

Production mounts a generated `0600` HMAC-SHA256 key only into Runtime Broker
and Transition Worker. Broker-authenticated teardown evidence binds
run/Agent/lease/session/scope and the negative container/mount observation;
Broker-authenticated verifier evidence additionally binds proposal/input,
check specification/results/coverage, and frozen environment pins. Worker
verifies the MAC and compares those fields with its own admitted transition.

This closes the API-to-Worker gap where an unkeyed caller could fabricate a
`PASS` or `mountsReleased=true` object. It does **not** prove the Broker's Docker
observation to an external party, protect against a compromised Broker/Worker,
or resist host/root control of the secret. The Broker's durable lifecycle ledger
only enforces monotonic local history for an exact
`runId + agentId + runLeaseId + sessionEpoch` binding:

```text
AGENT_STARTED -> AGENT_CLOSED -> VERIFIER_STARTED -> ALL_CLOSED
```

Its tombstones survive Broker process restart and prevent relaunch after a
signed closure, but they are not remotely witnessed. This key/proof is distinct
from the Relay HMAC bearer and the Ed25519 terminal-receipt signature.

## Trusted-check policy boundary

The policy does not merely reference a registry ID. It stores the complete
typed check specification (`id`, runner, entrypoint, args, timeout, scratch
budget), and the entrypoint must be a regular file in the sealed
content-addressed bundle. This prevents a candidate-owned PATH, `package.json`,
or test runner from becoming acceptance authority. It does not inspect the
platform-owned executable to prohibit its own shebang/shell use, so documentation
must not claim a universal shell-wrapper ban or an ID-only registry.

Content-addressed trusted-check bundles currently have no pruning or retention
job. This does not let a candidate select its checks, but it is an unbounded
control-root storage-growth risk for long-lived deployments.

## Trusted computing base

The Authority V2 TCB includes:

- host OS, filesystem, and Docker engine;
- Fastify/AgentService projection and CommitGate protocol implementation;
- dedicated Transition Worker and hash-linked transition log;
- Runtime Broker, its durable lifecycle ledger, shared Broker/Worker HMAC key,
  and Docker engine;
- product state database as a rebuildable/cache projection plus user messages;
- State View/policy/trusted-check data;
- configured Runtime and Verifier images;
- model relay/provider adapter where used;
- local operator controlling paths, credentials, and images.

A class named “single writer” does not itself prove OS-enforced exclusivity.
`audit:authority` remains a regex/static-callsite inventory, while
`audit:topology` supplies live Docker evidence: API write probes must fail on
RO Authority/Control mounts, only Worker owns them RW, and only Broker owns the
Docker socket. Neither audit is a proof against host/root.

## Process recovery is not power-loss durability

The promotion journal and backup protocol target deterministic recovery after a
server/process/container kill and restart. The claim explicitly excludes:

- sudden power loss;
- unflushed write caches and storage-controller failure;
- an fsync ordering proof across files/directories/database;
- arbitrary filesystem corruption;
- distributed/multi-host consensus.

Ambiguous or externally corrupted state becomes `RECOVERY_REQUIRED`; the system
must not guess. This is a recoverable local admission protocol, not distributed
ACID.

The recovery evaluator is designed to kill Worker/API processes at the declared
transaction points and Broker-owned Agent/Verifier child containers. The
`RUNTIME_BROKER_PROCESS_SIGKILL_ORPHAN_RECONCILIATION` fixture also kills a
separate Runtime Broker Node process, confirms its child survives, restarts the
Broker, and requires exact-label negative-query evidence before mount release.
It does not kill the Docker daemon and does not extend the guarantee to a
host/root adversary, daemon corruption, or power loss. These scenarios become
current evidence only when the Docker recovery report is regenerated and passes
for the frozen source identity.

## Filesystem model

The authoritative View accepts normalized regular directories/files only.
The protocol fails closed on:

- symlinks and special nodes;
- hardlinks (`nlink > 1`);
- case-fold collisions;
- Unicode NFC/NFD path collisions;
- unsupported rename/filesystem behavior;
- cross-device staging/swap.

`.git`, `.codex`, `node_modules`, `dist`, and `coverage` are deterministic
non-authoritative state: they are absent from the sealed proposal, verifier
source, and next authoritative workspace. Cache/dependency/build material must
live in bounded scratch or a platform-owned offline layer. The system must not
silently preserve ignored state while claiming the View fully identifies what
the next turn can observe.

The five default ignored names are redirected to bounded scratch at the
workspace root, while Manifest v2 classifies ignored names at arbitrary path
segments and enforces entry, aggregate-byte, and single-file limits before
seal.
The manifest walk additionally enforces a monotonic wall-clock limit (30
seconds by default) and fails closed with
`CANDIDATE_SCAN_TIME_BUDGET_EXCEEDED`. Ignored entries and bytes consume scan
budgets even though their content is excluded from the proposal.
The production Worker/Broker exchange is a byte- and inode-bounded tmpfs. Under
the fixed single-Agent-serial boundary this provides a hard aggregate ceiling
for the active candidate and verifier export, including arbitrary nested
ignored content. It is not a multi-tenant per-run accounting system: concurrent
Agents would share the same ceiling and require separate volumes or project
quotas before this claim could be extended.

The manifest does not treat mtime, uid, or gid as versioned product semantics.
The production Linux Worker nevertheless requires one normalized UID/GID per
tree, rejects setuid/setgid/sticky mode bits, and invokes fixed `getfattr` /
`getfacl` binaries with bounded output and no shell. Any xattr or non-trivial
ACL fails admission. Portable in-process development does not make this claim;
the Worker health field must report `filesystemProfile=linux-strong` and the
Linux evaluator must pass before release evidence may use it.

## Decision and retention semantics

- `COMMITTED`: trusted evidence passed and a one-shot permit was consumed.
- `QUARANTINED` / UI `Rejected`: trusted policy/check evidence produced a
  negative verdict.
- `CONFLICTED`: expected head/View/generation is stale.
- `ABORTED`: cancellation, Runtime/Provider/Verifier failure, timeout, `ERROR`,
  missing/malformed evidence, or transaction failure prevented a trusted
  verdict.

Rejected artifact payloads are destroyed. Receipt/attack evidence is sanitized
metadata: path/type diff, fixture/reason identifiers, context/evidence digests,
container/image/network facts, decision, and retention state. It is not a
long-term quarantine browser and must not retain rejected source or secrets.

Terminal receipts are immutable. Promotion uses non-terminal events before
rename-swap; only a fully dispositioned and acknowledged transition becomes
terminal. Recovery appends recovery events instead of rewriting terminal
history. The default Worker log is hash-linked and append-only at the process
protocol boundary. This is tamper-evident local evidence, not a remotely
witnessed or hostile-root-proof transparency log.

Version history is projected from the same Worker event chain. Successful
commit and rollback append new generations and do not rewrite earlier events.
The product DB remains a rebuildable cache of this transition projection; user
messages are explicitly outside the Worker reconstruction guarantee.

Rollback is authorized by a distinct one-shot permit. The implementation
checks the version snapshot hash before import and the staged versioned hash
after copying, before capability consumption and swap. That closes the tested
copy-time TOCTOU window, but still assumes no hostile host/root writer or
compromised Docker engine bypasses the Worker boundary.

## Session and belief boundary

Messages are classified as `INPUT`, `PROVISIONAL`, `AUTHORITATIVE`, `REJECTED`,
or `SUPERSEDED`. Non-commit resets the local session epoch and prevents the
system from reusing the old Provider thread/session/cache. The implementation
does not reconstruct each new prompt from all current-lineage database
messages; it either continues the accepted Provider thread or, after a fence,
sends a trusted reconciliation prefix plus the new user request. Rejected and
superseded database rows remain visible but are not explicitly re-sent.

The execution fence can rebind a run during its brief admitted/pre-execution
`queued` window. There is no user-facing queue behind a busy Agent: a second
send while a run is active receives `409`.

This does not claim deletion of data already retained by a remote Provider. It
claims only that CommitGate no longer treats the rejected continuation as
current authority. If a user deliberately re-enters rejected content, it is a
new input rather than a magically rolled-back external belief.

## Provider and evidence boundary

- CommitGate evaluates a Responses-compatible Provider path; the repository
  supplies Ark and OpenRouter adapters.
- Provider choice is provenance rather than a scoring category. A historical
  recorded real clean-clone E2E used Ark for its embedded revision; it is not a
  current claim after source changes.
- New reports use the tri-state `providerE2EVerified` field. Historical
  `officialProviderE2E`, `alternateProviderVerified`, and
  `competitionVerified` fields are accepted only as read compatibility and do
  not award checklist credit.
- deterministic/FakeRunner tests establish protocol behavior, not model
  behavior;
- verifier-container tests establish the verifier boundary, not a real Agent
  E2E;
- API automation or a served frontend asset is not a clean-clone browser demo;
- `eval:browser:clean-clone` now contains an executable Playwright/Chromium
  clean-clone driver and fail-closed artifact checks, but checked-in code is not
  proof that a real Provider/browser scenario succeeded;
- with missing credentials/clean source/Docker/Chromium it exits `2` and writes
  `unverified`, and a failed scenario is `failed`;
- every earlier-revision Provider/browser report is historical evidence only
  for the identity it records; Authority V2 must regenerate it after changes;
- `audit:clean-clone` is a read-only clean-worktree CLI rerun, not browser
  evidence;
- design documents, source files, and mock fixtures are not runtime evidence;
- old evidence is stale after a protocol/source-tree change.

Automatic Provider fallback is not implemented. `retryOfRunId` is reserved but
currently initialized to `null`, and Provider configuration is process-global.
A manual Provider change needs a service restart, explicit Agent
configuration/session reset, and a new run; there is no automatic fresh
run/proposal/session orchestration to claim.

`sourceRevision` is included in `EvaluationContext`. Development/tests may use
the literal `unverified`; the production API, Runtime Broker, and Transition
Worker require the same full 40-hex configured revision, and the Worker rejects
mismatched product evidence. It becomes provenance evidence only when a
clean-revision evaluation independently binds and verifies that value against
the source-tree hash and image identities.

A checklist item is `verified`, `failed`, or `unverified` and must name evidence
bound to the current revision/source-tree hash and required image identities.
The checklist does not calculate an organizer or predicted score.

The historical recorded Ark clean-clone report verified 12/12 product scenarios
for the source identity embedded in that report; it is not current evidence for
a changed tree. The active browser contract now requires 12/12 scenarios, so
the historical 12/12 report is intentionally stale. The old repository `100/100` remains
a historical internal rubric projection, not an organizer-issued score. It is
not part of the active evidence set. Provider/browser, Linux, recovery, release
and narrated Demo evidence become `unverified` whenever the source changes and
remain so until regenerated against one clean identity.

## Explicit non-goals

- ECS or multi-server transaction semantics;
- multiple Agents sharing and writing one workspace;
- rollback of databases, SaaS calls, emails, payments, devices, or arbitrary
  external APIs;
- complete live tool firewalling or arbitrary egress prevention;
- semantic-intent correctness;
- general policy DSL or policy editing UI;
- multi-tenant hostile-user isolation;
- remotely witnessed transparency or host/root-resistant receipt signatures;
- TPM/TEE remote attestation;
- long-term rejected-artifact browsing;
- protected execution through `RUNTIME_PROVIDER=local-process`.

## P1 product path and remaining evidence gates

The default production path uses the Transition Worker over typed Unix RPC. The
Worker is the sole service with read-write Authority and
Control mounts; the API mounts them read-only, and the Runtime Broker owns the
Docker socket without mounting either tree. The Worker append-only hash-linked
event log is the transition fact source for head, generation, permit, version,
receipt identity, promotion, rollback, archive, and recovery. Product database
fields are a projection and cannot overwrite Worker state.

This wiring is implemented. Linux filesystem, recovery, topology, and
real-Provider clean-clone reports remain evidence only for the source identity
they record; a source change makes them historical until regeneration. The
broader label `P1 hardened` remains withheld until one frozen source passes all
release gates and the narrated three-minute submission Demo is recorded and
validated.
The Worker rejects symlinks, special files, hardlinks, sparse files,
Unicode/case collisions, unexpected ownership/mode, xattrs/ACLs, and checks
same-filesystem swap. Those strong claims require the Linux Worker profile and
Linux evaluator; portable development is explicitly weaker. Sealing
changes the proposal tree root to `0500` while preserving artifact modes; OS
exclusion comes from the Worker-only Authority/Control mount and volume-
ownership boundary, not from a unique Worker UID.

The Worker reconstructs transition/head/version/permit state and terminal
receipt identities/decisions. User messages remain in the product database,
and a receipt reconstructed after loss of the product projection is explicitly
marked partial rather than inventing missing verifier text.

The Worker, rather than the RPC caller or product database, derives every next
StateView from authoritative bytes plus the prior event. Receipt proof uses a
pre-run TOFU anchor: the client observes
`authorityReceiptSigningKeyId` from `/api/system` before starting the run and
requires the proof key to match. This detects post-observation substitution but
is not an externally witnessed identity and provides no hostile host/root
guarantee.

P2 contains prototype modules for semantic-intent `off|shadow` evidence and a
registered-adapter Effect Outbox. They are not integrated as product promotion
authority. Ed25519 terminal-receipt proof is integrated into the audit path,
but is intentionally not an authorization input. The frozen 200-example x
5-run stability/FPR/FNR/abstention report has not been produced, and OCI/TEE
attestation is not verified. `P2 research-verified` remains unverified.
