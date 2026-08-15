# Exact-byte Signed C4 Architecture Review Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an immutable independent C4 review authority that accepts a separately trusted Ed25519 reviewer key, verifies an exact signed payload and records one accepted, rejected or rework-required review without publishing or deploying the architecture.

**Architecture:** `C4ArchitectureReviewService` owns a dedicated reviewer-root authority and one exact-byte signed review authority. The service reuses TrustPlane, ContinuityService authorization consumption/signature verification, EventLedger, and the existing C4 input/candidate verifiers. Reviewer roots, reviews and finding memberships are immutable and independently reverified.

**Tech Stack:** Python 3.12, SQLite, STARCOM canonical JSON/SHA-256 helpers, Ed25519/OpenSSL, TrustPlane, ContinuityService, EventLedger, real C4 input/candidate services, unittest, GitHub Actions.

## Global Constraints

- Start from verified `main` SHA `60b04d3c45df231a1df6af09abaf3ee01a77adf6` or a later SHA proven to contain the same 300-test C4 foundation.
- Signature verification occurs before JSON decoding or trust.
- Payload bytes are never reserialized before signature verification.
- Exact payload field set and exact finding field set are closed.
- Duplicate JSON keys fail closed.
- `gate_effect` is exactly `NO_PUBLICATION_NO_DEPLOYMENT`.
- One review maximum per candidate.
- Reviewer identity is independent from candidate creator, input freezer, all frozen input authors, root acceptance actor and review admission actor.
- Review admission performs no TrustPlane rule/decision creation and no publication/deployment.
- All persisted rows are immutable through no-update/no-delete triggers.
- Exact replay is idempotent; any material difference is a conflict.
- No canonical status promotion.

---

## File Structure

- Create `src/starcom/architecture_review.py`: enums, dataclasses, root authority, exact payload parser, review admission, reads and independent verifiers.
- Create `tests/test_architecture_review.py`: real C4 fixture, ephemeral Ed25519 keys, valid verdicts, independence, chronology and exact replay.
- Create `tests/test_architecture_review_hardening.py`: malformed payloads, verdict invariants, transaction rechecks and tamper mutations.
- Modify `MANIFEST.sha256` only after focused GREEN.
- Do not modify `src/starcom/cli.py` in this slice.

---

### Task 1: Establish causal RED contracts and real C4 fixture

**Files:**
- Create: `src/starcom/architecture_review.py`
- Create: `tests/test_architecture_review.py`
- Create: `tests/test_architecture_review_hardening.py`

**Public interfaces:**

```python
class C4ArchitectureReviewVerdict(str, Enum): ...
class C4ArchitectureVerificationResult(str, Enum): ...
class C4ArchitectureFindingSeverity(str, Enum): ...
class C4ArchitectureFindingCode(str, Enum): ...

@dataclass(frozen=True)
class C4ArchitectureReviewerRootPreparation: ...

@dataclass(frozen=True)
class C4ArchitectureReviewerRoot: ...

@dataclass(frozen=True)
class C4ArchitectureReviewFinding: ...

@dataclass(frozen=True)
class C4ArchitectureReviewRecord: ...

@dataclass(frozen=True)
class C4ArchitectureReviewVerification: ...

class C4ArchitectureReviewService:
    def prepare_reviewer_root(... ) -> C4ArchitectureReviewerRootPreparation: ...
    def accept_reviewer_root(... ) -> C4ArchitectureReviewerRoot: ...
    def get_reviewer_root(key_id: str) -> C4ArchitectureReviewerRoot: ...
    def verify_reviewer_root(key_id: str) -> C4ArchitectureReviewVerification: ...
    def admit_review(... ) -> C4ArchitectureReviewRecord: ...
    def get_review(review_id: str) -> C4ArchitectureReviewRecord: ...
    def get_findings(review_id: str) -> tuple[C4ArchitectureReviewFinding, ...]: ...
    def verify_review(review_id: str) -> C4ArchitectureReviewVerification: ...
```

- [ ] **Step 1: Create explicit RED service seam**

Define all enums and dataclasses. Mutation methods raise `StateTransitionError("C4 architecture review authority is not implemented")`. Read methods raise `NotFoundError`. Verifiers return one `C4_ARCHITECTURE_REVIEW_AUTHORITY_NOT_IMPLEMENTED` defect.

- [ ] **Step 2: Build a real C4 fixture**

In `tests/test_architecture_review.py`:

1. initialize real Database, EventLedger, TrustPlane and ContinuityService;
2. instantiate real `C4ArchitectureInputService` using `test_architecture_input.FakeExecutionEvidenceSource`;
3. explicitly authorize and freeze one input set containing `execution-no-effect` and `execution-success`;
4. instantiate real `C4ArchitectureCandidateService`;
5. create the valid v3.2 manifest and explicitly authorize/create one candidate;
6. generate ephemeral Ed25519 reviewer keys with OpenSSL;
7. instantiate `C4ArchitectureReviewService` with the shared authorities.

Use distinct identities:

- input freezer `c4-input-owner`;
- candidate creator `c4-architect`;
- frozen execution authors `author-negative`, `author-success`;
- reviewer-root acceptor `review-root-owner`;
- operational review admission actor `review-admitter`;
- independent reviewer `independent-architecture-reviewer`.

- [ ] **Step 3: Add primary RED tests**

Add these tests:

```text
test_reviewer_root_preparation_is_deterministic_and_side_effect_free
test_default_deny_then_exact_reviewer_root_is_verified_and_idempotent
test_exact_signed_accepted_review_is_admitted_verified_and_idempotent
test_exact_signed_rework_review_is_valid
test_exact_signed_rejected_review_is_valid
test_whitespace_modified_payload_with_original_signature_is_rejected
test_second_review_or_material_conflict_is_rejected
```

- [ ] **Step 4: Add hardening RED tests**

Add these tests:

```text
test_duplicate_missing_extra_fields_and_invalid_utf8_fail_closed
test_verdict_result_and_finding_invariants_fail_closed
test_reviewer_must_be_independent_from_every_disallowed_identity
test_review_timestamp_must_follow_root_input_and_candidate
test_transaction_rechecks_candidate_input_and_root
test_verifier_detects_root_payload_signature_finding_consumption_and_ledger_tampering
```

- [ ] **Step 5: Run focused causal RED**

```bash
PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test_architecture_review.py' -v
PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test_architecture_review_hardening.py' -v
```

Expected: fixture setup succeeds; only explicit unimplemented review seams are red; no import, syntax, schema or upstream C4 error appears.

- [ ] **Step 6: Run complete RED verification**

```bash
PYTHONPATH=src:. python3 scripts/verify_repo.py
```

Expected: the 300-test baseline remains green; only new review tests fail; compile, secrets and style stay green; manifest reports only new RED files/documents.

- [ ] **Step 7: Commit causal RED**

```bash
git add \
  src/starcom/architecture_review.py \
  tests/test_architecture_review.py \
  tests/test_architecture_review_hardening.py \
  docs/superpowers/specs/2026-08-14-c4-signed-review-design.md \
  docs/superpowers/plans/2026-08-14-c4-signed-review.md
git commit -m "test: define exact-byte signed C4 architecture review contract"
```

---

### Task 2: Implement the reviewer-root authority

**Files:**
- Modify: `src/starcom/architecture_review.py`
- Test: `tests/test_architecture_review.py`
- Test: `tests/test_architecture_review_hardening.py`

- [ ] **Step 1: Add validation and root schema**

Implement required text, timezone-aware timestamp and bounded-byte helpers. Create `c4_architecture_reviewer_roots` with exact public-key bytes, fingerprint, authorization, actor/time and ledger linkage. Add no-update/no-delete triggers.

- [ ] **Step 2: Implement deterministic preparation**

Validate the key with `continuity.signature_verifier.validate_public_key()`. Return action/resource/mission/context exactly as specified.

- [ ] **Step 3: Implement exact authorization checks**

Require clean `TrustPlane.verify_decision()`, allowed result and exact tuple:

```python
(
    actor,
    "c4.architecture-reviewer.accept",
    f"continuity:c4:architecture-reviewer:{key_id}",
    f"c4-architecture-reviewer:{key_id}",
    dict(preparation.context),
)
```

- [ ] **Step 4: Implement atomic acceptance**

Inside one transaction repeat key and decision validation, consume:

```text
operation_kind = C4_ARCHITECTURE_REVIEWER_ACCEPTED
operation_id = <key_id>
```

Append the root event and insert the immutable row.

- [ ] **Step 5: Implement reads, exact replay and root verifier**

Verify public-key bytes/fingerprint, standalone Ed25519 validity, authorization request/chronology, consumption, event payload/hash and ledger chain.

- [ ] **Step 6: Run focused root tests**

Run root preparation, default-deny, exact acceptance, replay, wrong-key and root-tamper tests. Expected: all pass.

- [ ] **Step 7: Commit root authority**

```bash
git add src/starcom/architecture_review.py tests/test_architecture_review*.py
git commit -m "feat: add C4 architecture reviewer trust roots"
```

---

### Task 3: Implement exact payload, findings and verdict validation

**Files:**
- Modify: `src/starcom/architecture_review.py`
- Test: `tests/test_architecture_review.py`
- Test: `tests/test_architecture_review_hardening.py`

- [ ] **Step 1: Define exact field sets and limits**

Add the 17 exact payload fields and five exact finding fields from the spec. Add 4 MiB payload and 1024-byte signature limits.

- [ ] **Step 2: Verify signature before JSON**

Given an accepted clean root, verify `signature_verifier.verify(public_key, payload, signature)` before UTF-8 decode or JSON parsing.

- [ ] **Step 3: Reject duplicate keys and malformed objects**

Use `object_pairs_hook` to reject duplicate keys at every JSON object level. Require one top-level object and exact field equality.

- [ ] **Step 4: Normalize findings**

Require findings sorted by `finding_id`, unique, exact severity/code enums, non-empty message and non-empty sorted duplicate-free evidence refs. Return deterministic mappings and dataclass records.

- [ ] **Step 5: Enforce verdict rules**

Implement exact ACCEPTED, REWORK_REQUIRED and REJECTED invariants from the spec. Reject every incoherent combination with `ValidationError`.

- [ ] **Step 6: Validate identifiers, version, digests and constants**

Require non-empty IDs/identities/environment/basis, version `3.2`, lowercase SHA-256 digests, timezone-aware review timestamp and gate effect `NO_PUBLICATION_NO_DEPLOYMENT`.

- [ ] **Step 7: Run payload/finding/verdict tests**

Expected: exact accepted/rework/rejected payloads parse; malformed exact bytes and incoherent findings fail closed.

- [ ] **Step 8: Commit payload authority**

```bash
git add src/starcom/architecture_review.py tests/test_architecture_review*.py
git commit -m "feat: validate exact signed C4 review payloads"
```

---

### Task 4: Implement immutable review admission

**Files:**
- Modify: `src/starcom/architecture_review.py`
- Test: `tests/test_architecture_review.py`
- Test: `tests/test_architecture_review_hardening.py`

- [ ] **Step 1: Create immutable review and finding schemas**

Create `c4_architecture_reviews` and `c4_architecture_review_findings`. Enforce one review per candidate, closed enums/constants, digest lengths, contiguous membership and no-update/no-delete triggers.

- [ ] **Step 2: Implement candidate/input binding checks**

Require clean candidate and input verifiers. Compare candidate, architecture, version, input set, manifest SHA-256 and input-set digest exactly.

- [ ] **Step 3: Implement chronology and independence**

Require review time not earlier than candidate creation, input freeze or root acceptance. Reject reviewer identity if it equals candidate creator, input freezer, any input author, root acceptor or admission actor.

- [ ] **Step 4: Implement exact replay and candidate uniqueness**

An exact existing review returns only after independent verification. Different bytes/key/actor or a second review for the candidate raises `ConflictError`.

- [ ] **Step 5: Implement transactional admission**

Inside one transaction repeat root, signature, payload, candidate, input, chronology and independence checks. Append `C4_ARCHITECTURE_REVIEW_ADMITTED`, insert the review and insert ordered findings.

- [ ] **Step 6: Run admission tests**

Expected: accepted/rework/rejected reviews admit and verify; second review, material conflict, dependence, chronology and transaction-race cases fail closed.

- [ ] **Step 7: Commit review admission**

```bash
git add src/starcom/architecture_review.py tests/test_architecture_review*.py
git commit -m "feat: admit immutable independent C4 architecture reviews"
```

---

### Task 5: Implement independent review verification and falsification

**Files:**
- Modify: `src/starcom/architecture_review.py`
- Test: `tests/test_architecture_review.py`
- Test: `tests/test_architecture_review_hardening.py`

- [ ] **Step 1: Reverify exact cryptographic material**

Recompute payload/signature SHA-256, verify the reviewer root and exact signature, parse the stored payload and compare every signed field to the immutable row.

- [ ] **Step 2: Reverify candidate/input/independence/chronology**

Run current candidate and input verifiers, exact binding, status, chronology and disallowed-identity checks.

- [ ] **Step 3: Reverify frozen findings**

Require contiguous ordinals, unique IDs, canonical JSON, finding hashes, payload membership equality, finding count and finding-set digest.

- [ ] **Step 4: Reverify event and chains**

Require exact stream, kind, actor, timestamp, event payload, stored hash and clean review ledger chain.

- [ ] **Step 5: Complete mutation tests**

Mutate independently:

```text
reviewer key/fingerprint
root decision/consumption/event
review payload bytes/hash
signature bytes/hash
review row identifiers/digests/verdict/results
a finding JSON/hash/ordinal
candidate or input evidence
review event actor/payload/hash
review ledger chain
```

Every mutation yields deterministic defects and no false clean result.

- [ ] **Step 6: Run all focused review tests**

```bash
PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test_architecture_review*.py' -v
```

Expected: all pass.

- [ ] **Step 7: Commit verifier hardening**

```bash
git add src/starcom/architecture_review.py tests/test_architecture_review*.py
git commit -m "test: harden C4 architecture review verification"
```

---

### Task 6: Deterministic repository proof and publication

**Files:**
- Modify: `MANIFEST.sha256`
- Verify: entire repository

- [ ] **Step 1: Regenerate manifest**

```bash
python3 scripts/build_manifest.py --root . --manifest MANIFEST.sha256 --write
```

- [ ] **Step 2: Record exact test count**

```bash
PYTHONPATH=src:. python3 - <<'PY'
import unittest
print(unittest.defaultTestLoader.discover('tests').countTestCases())
PY
```

- [ ] **Step 3: Run complete proof**

```bash
PYTHONPATH=src:. python3 scripts/verify_repo.py
python3 -m compileall -q src scripts tests
python3 scripts/secret_scan.py --root .
PYTHONPATH=src:. PYTHONHASHSEED=7 python3 -m unittest discover -s tests
PYTHONPATH=src:. PYTHONWARNINGS=error python3 -X dev -m unittest discover -s tests -p 'test_architecture_review*.py'
git diff --check
```

Every command must exit zero. Manifest, secrets and text-style findings must be clean.

- [ ] **Step 4: Publish through a bounded RED/GREEN workflow**

Freeze exact main and RED refs, reproduce only review RED, apply production exactly once, regenerate the manifest, run focused/full GREEN, recheck immutable refs and publish `fix/c4-signed-review`.

- [ ] **Step 5: Open documented draft PR**

Include exact RED/GREEN run IDs, test counts, manifest count, changed files and no-publication/no-deployment truth boundary. Include `Fixes #55`.

- [ ] **Step 6: Require merge-virtual and post-merge CI**

Merge only after PR CI succeeds on the exact head SHA. Require push-triggered deterministic verification on the merge SHA before starting #56.
