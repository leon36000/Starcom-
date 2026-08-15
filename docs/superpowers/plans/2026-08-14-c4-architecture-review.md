# Exact-byte Signed C4 Architecture Review Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans task-by-task. Every implementation claim requires fresh test evidence.

**Goal:** Add a dedicated Ed25519 reviewer trust-root authority and admit one immutable exact-byte independent review for one C4 v3.2 candidate, without publication or deployment.

**Architecture:** `C4ArchitectureReviewService` owns reviewer roots, closed signed payload validation, independence, admission, immutable findings and independent verification. It consumes the existing C4 candidate/input services and the existing TrustPlane/Continuity authorization and signature infrastructure.

**Tech Stack:** Python 3.12, SQLite, Ed25519 through OpenSSL, STARCOM canonical JSON/SHA-256 helpers, EventLedger, TrustPlane, ContinuityService, unittest and GitHub Actions.

## Global constraints

- Base must be verified `main` SHA `60b04d3c45df231a1df6af09abaf3ee01a77adf6` or a later equivalent baseline proven green.
- Review signature verification uses the exact supplied bytes before JSON trust.
- One review maximum per immutable candidate.
- Reviewer roots and reviews are append-only and immutable.
- Root acceptance is TrustPlane-governed; review admission is cryptographically governed by the accepted root.
- No candidate mutation, publication, deployment, execution, network or canonical status promotion.
- Full repository verification must pass before PR publication.

---

## Files

- Create `src/starcom/architecture_review.py`.
- Create `tests/test_architecture_review.py`.
- Create `tests/test_architecture_review_hardening.py`.
- Modify `MANIFEST.sha256` only after GREEN.
- Keep `src/starcom/architecture_input.py` and `src/starcom/architecture_candidate.py` behavior unchanged.
- Do not modify `src/starcom/cli.py` in this slice.

---

### Task 1: Establish the RED service contract

**Public interfaces:**

```python
class C4ArchitectureReviewVerdict(str, Enum): ...
class C4ArchitectureFindingSeverity(str, Enum): ...
class C4ArchitectureFindingCode(str, Enum): ...

@dataclass(frozen=True)
class C4ArchitectureReviewerRootPreparation: ...

@dataclass(frozen=True)
class C4ArchitectureReviewerRoot: ...

@dataclass(frozen=True)
class C4ArchitectureReview: ...

@dataclass(frozen=True)
class C4ArchitectureReviewerRootVerification: ...

@dataclass(frozen=True)
class C4ArchitectureReviewVerification: ...

class C4ArchitectureReviewService:
    def prepare_reviewer_root(...): ...
    def accept_reviewer_root(...): ...
    def get_reviewer_root(...): ...
    def verify_reviewer_root(...): ...
    def admit_review(...): ...
    def get_review(...): ...
    def get_findings(...): ...
    def verify_review(...): ...
```

- [ ] Create a RED seam whose mutation/preparation methods raise `StateTransitionError("C4 architecture review authority is not implemented")`, reads raise `NotFoundError`, and verifiers return one explicit not-implemented defect.
- [ ] Build deterministic clean fake input/candidate services returning the real C4 dataclasses and current manifest/membership mappings.
- [ ] Generate an ephemeral Ed25519 keypair in the test fixture.
- [ ] Use the real Database, EventLedger, TrustPlane and ContinuityService.

Focused RED tests:

```text
test_reviewer_root_prepare_is_deterministic_and_side_effect_free
test_reviewer_root_default_deny_accept_replay_and_verify
test_exact_accepted_review_is_admitted_replayed_and_verified
test_exact_rejected_and_rework_reviews_are_valid
test_review_rejects_unaccepted_wrong_key_and_modified_exact_bytes
test_review_rejects_schema_finding_binding_and_verdict_inconsistencies
test_reviewer_independence_and_chronology_are_enforced
test_second_review_for_candidate_conflicts
test_verifier_detects_root_review_finding_consumption_and_ledger_tampering
```

- [ ] Run focused RED.
- [ ] Run complete repository verification and prove the existing 300 tests remain green.
- [ ] Commit the causal RED.

---

### Task 2: Implement reviewer trust-root authority

- [ ] Add validation helpers for IDs, timestamps, bounded bytes, Ed25519 keys and SHA-256 values.
- [ ] Create `c4_architecture_reviewer_roots` with key bytes, fingerprint, decision, acceptance actor/time and ledger linkage.
- [ ] Add no-update/no-delete triggers.
- [ ] Implement deterministic `prepare_reviewer_root()`.
- [ ] Verify exact TrustPlane request:

```text
action   = c4.architecture-reviewer.accept
resource = continuity:c4:architecture-reviewer:<key_id>
mission  = c4-architecture-reviewer:<key_id>
```

- [ ] Atomically consume as `C4_ARCHITECTURE_REVIEWER_ACCEPTED`, append the root ledger event and insert the row.
- [ ] Implement exact replay and material conflict handling.
- [ ] Implement standalone root verification: key/fingerprint, decision, request, chronology, consumption, event and chain.
- [ ] Run root tests GREEN and commit.

---

### Task 3: Implement exact payload and finding validation

- [ ] Define the exact 17-field top-level schema from the design.
- [ ] Decode with duplicate-key rejection.
- [ ] Enforce 4 MiB payload and 1024-byte signature limits.
- [ ] Verify signature before parsing/trusting payload.
- [ ] Define closed verdict, severity and finding-code enums.
- [ ] Normalize findings with exact fields, sorted unique IDs and sorted unique evidence/affected lists.
- [ ] Build the allowed evidence-reference set from the candidate manifest and input members.
- [ ] Enforce architecture/candidate/input/digest binding.
- [ ] Enforce verdict consistency rules.
- [ ] Enforce reviewer independence and chronology.
- [ ] Add semantic-focused tests and commit.

---

### Task 4: Implement immutable review admission

- [ ] Create `c4_architecture_reviews` and `c4_architecture_review_findings`.
- [ ] Add one-review-per-candidate and all digest/check constraints.
- [ ] Add no-update/no-delete triggers.
- [ ] Implement exact replay on candidate, key, payload, signature and admission actor.
- [ ] Reject competing review IDs or a second review for the candidate.
- [ ] Before and inside one transaction reverify root, signature, payload, candidate, input, independence and chronology.
- [ ] Append `C4_ARCHITECTURE_REVIEW_ADMITTED` to `continuity:c4:architecture-review:<review_id>`.
- [ ] Insert exact payload/signature bytes, row summary and contiguous canonical finding rows.
- [ ] Implement reads and focused admission tests.
- [ ] Commit admission.

---

### Task 5: Implement independent verification and falsification

`verify_review()` must recompute:

- payload/signature hashes;
- payload schema, closed fields and verdict consistency;
- reviewer-root verification and signature;
- row/payload agreement;
- finding ordinals, JSON, digests, payload equality and evidence references;
- current candidate/input verification and exact bindings;
- independence and chronology;
- review event stream, kind, actor, timestamp, payload, row hash and ledger chain.

`verify_reviewer_root()` must independently recheck root key, fingerprint, TrustPlane decision/request/consumption, event and chain.

- [ ] Add tamper tests for root key/fingerprint, review payload/signature, finding digest, candidate/input binding, authorization consumption, event actor/payload/hash and ledger chains.
- [ ] Require precise deterministic defect codes.
- [ ] Run all review tests GREEN and commit verifier hardening.

---

### Task 6: Deterministic repository proof and publication

- [ ] Regenerate `MANIFEST.sha256`.
- [ ] Record exact focused and total test counts.
- [ ] Run:

```bash
PYTHONPATH=src:. python3 scripts/verify_repo.py
python3 -m compileall -q src scripts tests
python3 scripts/secret_scan.py --root .
PYTHONPATH=src:. PYTHONHASHSEED=7 python3 -m unittest discover -s tests
PYTHONPATH=src:. PYTHONWARNINGS=error python3 -X dev -m unittest discover -s tests -p 'test_architecture_review*.py'
git diff --check
```

- [ ] Publish only through a bounded RED/GREEN workflow freezing exact base and RED refs.
- [ ] Open a documented draft PR with exact run IDs, test counts, manifest count, changed files and truth boundary.
- [ ] Merge only after merge-virtual CI passes on the exact head SHA.
- [ ] Require post-merge CI on `main` before starting issue #56 or #57.

## Completion boundary

This issue is complete only when the reviewer-root and exact review authorities are merged and post-merge green. No review artifact produced by unit tests is a production review, and no accepted test verdict publishes or deploys an architecture.
