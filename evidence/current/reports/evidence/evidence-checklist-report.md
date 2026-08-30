# CommitGate evidence checklist

- Status: **unverified**
- Provider E2E: **verified** (ark)
- Items: **26 verified / 0 failed / 1 unverified**
- Organizer score: **not assigned**

> This is a machine-readable evidence index, not an official or predicted score.

## End-to-end middleware behavior — verified

- `verified` — Real Provider browser path; evidence: eval/provider-<provider>-report.json, eval/browser-clean-clone-report.json
- `verified` — Sealed proposal and one-shot commit; evidence: eval/protocol-report.json
- `verified` — Protected-path rejection; evidence: eval/protocol-report.json, eval/adversarial-report.json
- `verified` — View and session continuation fence; evidence: eval/protocol-report.json, eval/adversarial-report.json
- `verified` — Append-only rollback and recovery; evidence: eval/protocol-report.json, eval/recovery-report.json
- `verified` — Starter behavior and build regression; evidence: eval/evidence/check-report.json

## Technical design and integration — verified

- `verified` — State-view, proposal, evidence and permit protocol; evidence: eval/protocol-report.json
- `verified` — Persistent write authority audit; evidence: eval/authority-report.json
- `verified` — Worker and Broker product wiring; evidence: eval/evidence/p1-product-report.json
- `verified` — Live least-authority topology; evidence: eval/evidence/topology-report.json

## Verification and robustness — verified

- `verified` — Protocol, adversarial and recovery suites; evidence: eval/protocol-report.json, eval/adversarial-report.json, eval/recovery-report.json
- `verified` — Credential-free verifier container; evidence: eval/container-report.json
- `verified` — Broker SIGKILL orphan reconciliation; evidence: eval/container-report.json
- `verified` — Linux filesystem contract; evidence: eval/evidence/linux-filesystem-report.json
- `verified` — Docker process kill/restart matrix; evidence: eval/evidence/docker-recovery-report.json
- `verified` — Machine-readable non-effect and safety invariants; evidence: eval/evidence/invariants-report.json
- `verified` — Offline receipt and event binding verification; evidence: eval/evidence/receipt-verification-report.json
- `verified` — Linux Worker protocol microbenchmark p50/p95 disclosure; evidence: eval/evidence/performance-report.json
- `verified` — Candidate and environment bypass protection; evidence: eval/adversarial-report.json
- `verified` — Secret scanning and redaction; evidence: eval/evidence/secret-report.json, eval/adversarial-report.json

## Demo and reproducibility — unverified

- `verified` — One-command product smoke test; evidence: eval/evidence/demo-smoke-report.json
- `verified` — Clean-clone browser replay; evidence: eval/browser-clean-clone-report.json
- `verified` — Revision-bound documentation review; evidence: eval/evidence/documentation-review.json
- `verified` — Editable architecture artifact integrity; evidence: eval/evidence/architecture-report.json
- `verified` — Read-only clean-worktree replay; evidence: eval/independent-audit-report.json
- `verified` — Reviewer-accessible source or hash-bound archive; evidence: eval/evidence/source-delivery-report.json
- `unverified` — Narrated three-minute video; evidence: eval/evidence/demo-video-report.json

## Claim boundary

This checklist indexes revision-bound verified, failed, and unverified evidence. It assigns no organizer score and gives no preference to a model Provider.
