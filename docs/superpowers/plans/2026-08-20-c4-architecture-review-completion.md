# C4 Architecture Review Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the exact signed independent C4 architecture review authority from Issue #55 without publishing, deploying, or promoting the candidate.

**Architecture:** Keep `C4ArchitectureReviewService` as a separate authority boundary. Store one immutable review row, immutable finding rows, the exact signed payload bytes, and one append-only ledger event; admission re-verifies the canonical candidate and frozen input set inside one database transaction after the reviewer-root authority has already been accepted and consumed exactly once. Independent verification reconstructs every binding from database, TrustPlane, continuity, candidate, input, signature, payload, findings, ledger event, and ledger chain.

**Tech Stack:** Python 3.12, SQLite transactions/triggers, existing `EventLedger`, `ContinuityService`, `TrustPlane`, `C4ArchitectureInputService`, `C4ArchitectureCandidateService`, unittest.

**Spec:** GitHub Issue #55, `https://github.com/leon36000/Starcom-/issues/55`, plus `docs/superpowers/specs/2026-08-14-c4-architecture-foundation-design.md`.

## Global Constraints

- Keep `gate_effect` exactly `NO_PUBLICATION_NO_DEPLOYMENT`.
- Preserve default-deny TrustPlane behavior and the existing immutable C4 input/candidate authorities.
- Verify the exact payload bytes before UTF-8 decoding or JSON parsing.
- Re-verify candidate and input evidence inside the admission transaction.
- Keep review, membership, and finding rows immutable with SQLite triggers and append-only ledger evidence.
- Do not add publication, deployment, runtime integration, or canonical status promotion.
- Run `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 scripts/verify_repo.py` before declaring the slice complete.

---

### Task 1: Complete strict signed payload semantics

**Files:**
- Modify: `src/starcom/architecture_review.py`
- Test: `tests/test_architecture_review.py`
- Modify: `MANIFEST.sha256`

- [x] Add bounded transport checks, closed nested environment/independence schemas, closed finding codes/severities, sorted unique findings, and verdict/result consistency.
- [x] Prove malformed signed values fail with `ValidationError`, while valid signed envelopes reach the next authority gate.
- [x] Regenerate and verify the deterministic manifest.

### Task 2: Add immutable review persistence

**Files:**
- Modify: `src/starcom/architecture_review.py`
- Test: `tests/test_architecture_review.py`
- Test: `tests/test_architecture_review_verification.py`
- Modify: `MANIFEST.sha256`

- [x] Create `c4_architecture_reviews` with immutable identity, candidate/input/digest bindings, reviewer identity, canonical review timestamp, verification results, verdict, gate effect, exact payload/signature digests and bytes, admission actor/time, authorization root key, ledger event and ledger hash.
- [x] Create `c4_architecture_review_findings` keyed by `(review_id, ordinal)` with unique finding IDs and immutable triggers.
- [x] Add a deterministic `C4_ARCHITECTURE_REVIEW_ADMITTED` ledger event payload containing the stored row bindings and finding count.
- [x] Add tests that prove schema creation, exact replay idempotence, conflicting replay rejection, and direct update/delete trigger rejection.

### Task 3: Implement transactionally bound admission

**Files:**
- Modify: `src/starcom/architecture_review.py`
- Test: `tests/test_architecture_review.py`

- [x] Parse the strict signed envelope and bind its IDs/digests to the current immutable candidate and frozen input set.
- [x] Verify the candidate and input set in the same transaction, reject stale/dirty evidence, and compare the candidate’s architecture and manifest digest with the payload.
- [x] Enforce reviewer independence from candidate creator, input freezer, every frozen execution author, the admission actor, and the declared excluded identities.
- [x] Enforce `reviewed_at_utc` after candidate creation and input freeze; enforce admission time after the signed review time and reviewer-root acceptance.
- [x] Re-verify the already-consumed reviewer-root authority, append the review event, insert the review and findings atomically, and return the immutable record.

### Task 4: Implement retrieval and independent verification

**Files:**
- Modify: `src/starcom/architecture_review.py`
- Test: `tests/test_architecture_review_verification.py`

- [x] Implement `get_review`, `get_review_for_candidate`, and `get_findings` with not-found, ordering, and malformed-row fail-closed behavior.
- [x] Implement `verify_review` to reconstruct strict payload/signature, reviewer root, candidate, input set, independence, chronology, findings, event payload, event hash, and ledger chain.
- [x] Add tamper tests for stored review bindings, payload bytes, signature, findings, event fields, and chain integrity; reviewer-root decision/consumption tampering remains covered by the existing independent root verifier suite.

### Task 5: Integrated verification and handoff

**Files:**
- Modify: `MANIFEST.sha256`
- Inspect: `.github/workflows/ci.yml`, `scripts/verify_repo.py`, `AGENTS.md`

- [x] Run the focused architecture-review suite and the complete deterministic gate.
- [x] Run with `PYTHONHASHSEED=0` and `PYTHONWARNINGS=error`; compilation, 421 tests, scans, style and manifest all pass.
- [x] Confirm no publication/deployment/status-promotion path was added; the candidate gate remains `C4_ARCHITECTURE_CANDIDATE_NOT_REVIEWED`.
- [x] Re-check the final diff and leave the worktree ready for explicit review; do not push or merge without a separate instruction.
