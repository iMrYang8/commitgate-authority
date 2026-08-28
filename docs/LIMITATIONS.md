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

This guarantee is deliberately scoped to:

- a local Docker/Linux Runtime and the recorded image identities;
- one API process plus dedicated Transition Worker, Runtime Broker and Relay;
- at most one serial state transition per Agent;
- filesystem effects under the authoritative Agent workspace;
- process kill/restart recovery at the tested journal points;
- a normal, case-sensitive filesystem with supported rename behavior;
- no hostile host/root writer bypassing the control plane.

Here “immutable” is a protocol property, not an OS immutable flag. The Worker
owns sealed bytes and Authority/Control RW mounts; API sees those volumes RO,
while Broker and Relay do not mount them. Pre/post manifests, content addressing
and one-shot permits remain necessary. A host/root actor or compromised Docker
engine can still bypass this boundary.

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
- Runtime Broker and Docker engine;
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

The five default ignored names are bounded at the workspace root, while a
streaming post-run audit covers ignored path segments at arbitrary nesting
depths and enforces entry, aggregate-byte, and single-file limits before seal.
The Worker/Broker exchange volume does not provide a strict per-run physical
disk quota for arbitrary nested ignored content during Runtime execution; a run
can consume shared exchange capacity until teardown and then be rejected. This
resource window remains a limitation even though cross-run subpaths and
promotion authority are isolated.

The manifest does not treat mtime, uid, or gid as versioned product semantics.
An operator must not infer ownership/ACL/xattr guarantees unless a corresponding
normalization test/report exists.

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

- Ark/ModelArk is the official competition path unless the organizer accepts a
  substitute.
- OpenRouter is a compatible development/alternate path.
- OpenRouter evidence must never be reported as `realModelArk`.
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
- the checked-in earlier-revision report provides historical Ark/browser
  evidence only for the identity it records; Authority V2 must regenerate it;
- `audit:clean-clone` is a read-only clean-worktree CLI rerun, not browser
  evidence;
- design documents, source files, and mock fixtures are not runtime evidence;
- old evidence is stale after a protocol/source-tree change.

Automatic Provider fallback is not implemented. `retryOfRunId` is reserved but
currently initialized to `null`, and Provider configuration is process-global.
A manual Provider change needs a service restart, explicit Agent
configuration/session reset, and a new run; there is no automatic fresh
run/proposal/session orchestration to claim.

`sourceRevision` is included in `EvaluationContext`, but defaults to the literal
`unverified` unless explicitly configured. It becomes provenance evidence only
when a clean-revision evaluation independently binds and verifies it.

A score item is `verified`, `failed`, or `unverified` and must name evidence
bound to the current revision/source-tree hash and required image identities.

The earlier Ark clean-clone report verified 10/10 product scenarios for its P0
identity. The old repository `100/100` remains a historical internal
evidence-checklist result, not an organizer-issued score. Neither is reused for
Authority V2. Current Ark/browser, Linux, recovery, release and narrated Demo
evidence remain `unverified` until regenerated against one clean identity.

## Explicit non-goals

- ECS or multi-server transaction semantics;
- multiple Agents sharing and writing one workspace;
- rollback of databases, SaaS calls, emails, payments, devices, or arbitrary
  external APIs;
- complete live tool firewalling or arbitrary egress prevention;
- semantic-intent correctness;
- general policy DSL or policy editing UI;
- multi-tenant hostile-user isolation;
- cryptographic transparency/receipt signatures;
- TPM/TEE remote attestation;
- long-term rejected-artifact browsing;
- protected execution through `RUNTIME_PROVIDER=local-process`.

## P1 product path and remaining evidence gates

The default production path now uses the dedicated-UID Transition Worker over
typed Unix RPC. The Worker is the sole service with read-write Authority and
Control mounts; the API mounts them read-only, and the Runtime Broker owns the
Docker socket without mounting either tree. The Worker append-only hash-linked
event log is the transition fact source for head, generation, permit, version,
receipt identity, promotion, rollback, archive, and recovery. Product database
fields are a projection and cannot overwrite Worker state.

This wiring is an implemented and machine-verified product property. Current
revision-bound Linux filesystem, recovery, topology, and Ark clean-clone
evidence is checked in. The broader label `P1 hardened` remains withheld until
the narrated three-minute submission Demo is recorded and validated.
The Worker rejects symlinks, special files, hardlinks, Unicode/case collisions
and checks same-filesystem swap. Sparse-file and EXDEV behavior must be proven
by the Linux evaluator; xattr/ACL and arbitrary ownership preservation remain
outside the normalized regular-file/regular-directory state contract. Sealing
changes the proposal tree root to `0500` while preserving artifact modes; OS
exclusion comes from the Worker-only UID/volume ownership boundary.

The Worker reconstructs transition/head/version/permit state and terminal
receipt identities/decisions. User messages remain in the product database,
and a receipt reconstructed after loss of the product projection is explicitly
marked partial rather than inventing missing verifier text.

P2 contains prototype modules for semantic-intent `off|shadow` evidence, a
registered-adapter Effect Outbox, and Ed25519 receipt proof/verification. They
are not integrated as product promotion authority. The frozen 200-example x
5-run stability/FPR/FNR/abstention report has not been produced, and OCI/TEE
attestation is not verified. `P2 research-verified` remains unverified.
