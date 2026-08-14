# Exact-byte Signed C3 Decision Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one immutable, exact-byte signed C3 qualification decision authority that freezes candidate/evaluation evidence and never executes adoption.

**Architecture:** A new `C3DecisionService` builds a deterministic snapshot from a clean C3 binding and its qualification evidence, validates a closed signed JSON contract, stores the exact payload/signature plus frozen evidence membership, and independently verifies every trust, signature, snapshot, membership, ledger, independence, and chronology invariant. The service follows the existing C2 certification pattern but remains a separate C3 authority.

**Tech Stack:** Python 3.12, SQLite, STARCOM canonical JSON/SHA-256 helpers, append-only `EventLedger`, `ContinuityService` trust roots and signature verifier, `C3QualificationGate`, `QualificationLab`, `unittest`, GitHub Actions.

## Global Constraints

- No external network or runtime integration.
- No component adoption, installation, enabling, deployment, or canonical status promotion.
- Generic `DECISION` and `ADOPTION` qualification artifacts remain C3 defects.
- Exact signed payload bytes must never be parsed and reserialized before signature verification.
- Database records and frozen membership rows are immutable through no-update/no-delete triggers.
- Every mutable prerequisite is rechecked inside the admission transaction.
- One decision maximum per C3 run.
- Full deterministic repository verification must pass before publication.

---

## File structure

- Create `src/starcom/qualification_decision.py`: verdict enum, snapshot/record/verification dataclasses, schema, snapshot builder, exact payload parser, admission, retrieval, and verifier.
- Create `tests/test_qualification_decision.py`: deterministic real-ledger C3 decision tests with a bounded upstream C2 certification fixture and deterministic signature verifier.
- Modify `MANIFEST.sha256`: generated only after GREEN.
- Keep `src/starcom/qualification.py`, `src/starcom/qualification_gate.py`, and `src/starcom/certification.py` behavior unchanged in this slice.

---

### Task 1: Establish the signed-decision RED contract

**Files:**
- Create: `tests/test_qualification_decision.py`
- Create: `src/starcom/qualification_decision.py`

**Interfaces:**
- Consumes: `Database`, `EventLedger`, `ContinuityService`, `C2CertificationService`, `C3QualificationGate`, `QualificationLab`.
- Produces:
  - `C3DecisionVerdict`
  - `C3DecisionSnapshot`
  - `C3DecisionRecord`
  - `C3DecisionVerification`
  - `C3DecisionService.snapshot(c3_run_id: str) -> C3DecisionSnapshot`
  - `C3DecisionService.admit_decision(c3_run_id: str, key_id: str, payload: bytes, signature: bytes, *, actor: str, occurred_at: str | None = None) -> C3DecisionRecord`
  - `C3DecisionService.get_decision(decision_id: str) -> C3DecisionRecord`
  - `C3DecisionService.verify_decision(decision_id: str) -> C3DecisionVerification`

- [ ] **Step 1: Create a minimal RED service seam**

Create `src/starcom/qualification_decision.py` with the public enum/dataclasses and methods above. `snapshot()`, `admit_decision()`, and `get_decision()` must raise `StateTransitionError("C3 decision authority is not implemented")`; `verify_decision()` must return a single `C3_DECISION_AUTHORITY_NOT_IMPLEMENTED` defect.

- [ ] **Step 2: Add deterministic fixtures**

In `tests/test_qualification_decision.py`:

- initialize a real `Database`, `EventLedger`, `TrustPlane`, `ContinuityService`, `QualificationLab`, and `C3QualificationGate`;
- use a bounded fake C2 certification service that returns one clean `C2CertificationRecord` and `C2CertificationVerification`;
- create the required parent `c2_certifications` row for the real C3 binding foreign key;
- use a deterministic verifier where `signature == sha256(public_key + payload).digest()`;
- accept the decision public key through the real default-deny TrustPlane flow;
- create and bind one real empty qualification run;
- record candidate/evaluation artifacts after the C3 bind.

- [ ] **Step 3: Add focused RED tests**

Add tests with these exact responsibilities:

1. `test_snapshot_is_deterministic_and_binds_candidate_evaluation_sets`
2. `test_exact_signed_selection_is_admitted_verified_and_idempotent`
3. `test_exact_signed_no_selection_is_valid`
4. `test_decision_requires_candidate_and_evaluation_evidence`
5. `test_selected_candidate_must_belong_to_snapshot`
6. `test_modified_payload_or_signature_is_rejected`
7. `test_decision_maker_must_be_independent_and_after_latest_evidence`
8. `test_second_decision_for_same_c3_run_is_rejected`
9. `test_verifier_detects_membership_and_decision_ledger_tampering`
10. `test_later_qualification_evidence_makes_decision_stale`

The canonical payload helper must emit compact sorted JSON bytes with all 18 required fields and the fixed constants from the design.

- [ ] **Step 4: Run the focused RED suite**

Run:

```bash
PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test_qualification_decision.py' -v
```

Expected: the new decision tests fail because the authority is not implemented; all fixture setup and existing upstream services remain functional.

- [ ] **Step 5: Run the complete RED repository verification**

Run:

```bash
PYTHONPATH=src:. python3 scripts/verify_repo.py
```

Expected:

- only the new decision contract is red;
- existing tests remain green;
- compile, secret scan, and text policy remain green;
- manifest reports only the intentionally unlisted new RED files and the two new reviewed design documents.

- [ ] **Step 6: Commit RED evidence**

```bash
git add src/starcom/qualification_decision.py tests/test_qualification_decision.py
git commit -m "test: define exact-byte signed C3 decision contract"
```

---

### Task 2: Implement deterministic snapshot and closed payload validation

**Files:**
- Modify: `src/starcom/qualification_decision.py`
- Test: `tests/test_qualification_decision.py`

**Interfaces:**
- `snapshot()` returns ordered candidate/evaluation members and set digests.
- `_decode_payload(payload: bytes) -> dict[str, object]` rejects duplicate keys and malformed UTF-8.
- `_parse_payload(payload: bytes) -> dict[str, object]` enforces the exact 18-field contract.

- [ ] **Step 1: Implement validation helpers**

Add:

```python
_REQUIRED_PAYLOAD_FIELDS = frozenset(
    {
        "decision_id",
        "c3_run_id",
        "qualification_run_id",
        "certificate_id",
        "qualification_head_hash",
        "candidate_count",
        "evaluation_count",
        "candidate_set_digest",
        "evaluation_set_digest",
        "verdict",
        "selected_candidate_artifact_id",
        "decision_maker_identity",
        "decision_maker_environment",
        "decided_at_utc",
        "independence_basis",
        "independent_identity_status",
        "qualification_verification_result",
        "gate_effect",
    }
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
_MAX_SIGNATURE_BYTES = 1024
```

Implement required non-empty text, RFC 3339 timezone-aware timestamp, bounded bytes, digest, and duplicate-key JSON validation following `C2CertificationService` conventions.

- [ ] **Step 2: Implement the snapshot member contract**

For each `CANDIDATE` or `EVALUATION` artifact, freeze exactly:

```python
member = {
    "artifact_id": str(row["artifact_id"]),
    "kind": str(row["kind"]),
    "material": decoded_material,
    "material_sha256": str(row["material_sha256"]),
    "recorded_at": str(row["recorded_at"]),
    "recorded_by": str(row["recorded_by"]),
    "ledger_event_id": str(row["ledger_event_id"]),
    "ledger_hash": str(row["ledger_hash"]),
}
```

Order each kind by `artifact_id`. Compute set digests with `sha256_digest(list(members))`. Read the current qualification ledger head from `ledger_events`.

- [ ] **Step 3: Implement `snapshot()`**

Require clean `C3QualificationGate.verify()`, load the binding and bound run, rebuild both sets, and return identifiers, head hash, counts, digests, latest evidence timestamp, and members.

- [ ] **Step 4: Implement verdict/selection payload validation**

Enforce:

- counts are integers and not booleans;
- counts are non-negative;
- all three digests/head hashes are lowercase SHA-256;
- fixed constants equal the design values;
- selected verdict requires a non-empty selected ID;
- no-selection verdict requires JSON `null`.

- [ ] **Step 5: Run snapshot and payload tests**

Run:

```bash
PYTHONPATH=src:. python3 -m unittest \
  tests.test_qualification_decision.C3SignedDecisionTests.test_snapshot_is_deterministic_and_binds_candidate_evaluation_sets \
  tests.test_qualification_decision.C3SignedDecisionTests.test_selected_candidate_must_belong_to_snapshot -v
```

Expected: snapshot test passes; selection test advances to the still-unimplemented admission path.

- [ ] **Step 6: Commit the snapshot layer**

```bash
git add src/starcom/qualification_decision.py tests/test_qualification_decision.py
git commit -m "feat: build deterministic C3 decision snapshots"
```

---

### Task 3: Implement immutable admission and frozen membership

**Files:**
- Modify: `src/starcom/qualification_decision.py`
- Test: `tests/test_qualification_decision.py`

**Interfaces:**
- Creates `c3_decisions` and `c3_decision_evidence`.
- `admit_decision()` writes one ledger event and immutable rows atomically.

- [ ] **Step 1: Create schema and immutability triggers**

Create `c3_decisions` with one row per decision and `UNIQUE(c3_run_id)`. Add database checks for verdicts, evidence counts, digest lengths, and verdict/selection consistency.

Create `c3_decision_evidence` with `(decision_id, kind, ordinal)` primary key, unique `(decision_id, artifact_id)`, and frozen material/provenance fields. Add no-update and no-delete triggers for both tables.

- [ ] **Step 2: Implement trust-root and signature checks**

Call `ContinuityService.verify_trust_root(key_id)`, read the exact public key bytes from `continuity_trust_roots`, and use the configured continuity signature verifier against the unmodified payload bytes.

- [ ] **Step 3: Implement snapshot agreement, selection, chronology, and independence**

Require at least one candidate and one evaluation. Compare all signed snapshot fields exactly. Require selected membership when applicable. Require `decided_at_utc >= latest_evidence_at` and `admitted_at >= decided_at_utc`.

Disallow a decision-maker matching the C2 certifier, C3 starter, qualification creator, candidate recorder, or evaluation recorder.

- [ ] **Step 4: Implement idempotency and conflict rules**

Exact reuse of decision ID, C3 run, key ID, payload bytes, signature bytes, and digests returns the existing verified record. Different material or a second decision for the C3 run raises `ConflictError`.

- [ ] **Step 5: Implement transactional rechecks and writes**

Inside one database transaction:

- recheck no competing row;
- reverify trust root and exact signature;
- reverify C3;
- rebuild the snapshot from the same connection and require equality;
- append `C3_DECISION_ADMITTED` on `continuity:c3:<c3_run_id>:decision`;
- insert the decision row;
- insert ordered candidate and evaluation membership rows.

- [ ] **Step 6: Run admission tests**

Run:

```bash
PYTHONPATH=src:. python3 -m unittest \
  tests.test_qualification_decision.C3SignedDecisionTests.test_exact_signed_selection_is_admitted_verified_and_idempotent \
  tests.test_qualification_decision.C3SignedDecisionTests.test_exact_signed_no_selection_is_valid \
  tests.test_qualification_decision.C3SignedDecisionTests.test_decision_requires_candidate_and_evaluation_evidence \
  tests.test_qualification_decision.C3SignedDecisionTests.test_modified_payload_or_signature_is_rejected \
  tests.test_qualification_decision.C3SignedDecisionTests.test_decision_maker_must_be_independent_and_after_latest_evidence \
  tests.test_qualification_decision.C3SignedDecisionTests.test_second_decision_for_same_c3_run_is_rejected -v
```

Expected: all listed tests pass.

- [ ] **Step 7: Commit admission**

```bash
git add src/starcom/qualification_decision.py tests/test_qualification_decision.py
git commit -m "feat: admit immutable signed C3 decisions"
```

---

### Task 4: Implement independent decision verification and falsification

**Files:**
- Modify: `src/starcom/qualification_decision.py`
- Test: `tests/test_qualification_decision.py`

**Interfaces:**
- `verify_decision()` returns all deterministic defect codes without mutating state.

- [ ] **Step 1: Verify exact stored cryptographic material**

Recompute payload/signature digests, parse the stored payload, verify standalone trust-root integrity, and verify the exact signature.

- [ ] **Step 2: Verify frozen membership**

Require contiguous ordinals for each kind. Parse canonical member material, recompute member digests, compare every frozen field to the referenced immutable qualification artifact, and recompute candidate/evaluation set digests and counts.

- [ ] **Step 3: Verify current C3 and staleness**

Run the C3 verifier. Rebuild the current snapshot. If its qualification head, counts, digests, or membership differ from the admitted decision snapshot, report stale-snapshot defects. This makes later evidence fail closed.

- [ ] **Step 4: Verify decision semantics and independence**

Recheck verdict/selected membership, fixed payload constants, chronology, and the current disallowed identity set.

- [ ] **Step 5: Verify decision ledger provenance**

Require the exact stream, kind, actor, timestamp, payload, stored event hash, and a clean decision stream chain.

- [ ] **Step 6: Run tamper and staleness tests**

Run:

```bash
PYTHONPATH=src:. python3 -m unittest \
  tests.test_qualification_decision.C3SignedDecisionTests.test_verifier_detects_membership_and_decision_ledger_tampering \
  tests.test_qualification_decision.C3SignedDecisionTests.test_later_qualification_evidence_makes_decision_stale -v
```

Expected: both tests pass and expose the exact intended defect codes.

- [ ] **Step 7: Run the focused suite**

```bash
PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test_qualification_decision.py' -v
```

Expected: all decision tests pass.

- [ ] **Step 8: Commit verifier hardening**

```bash
git add src/starcom/qualification_decision.py tests/test_qualification_decision.py
git commit -m "test: harden C3 decision verification"
```

---

### Task 5: Deterministic repository proof and publication

**Files:**
- Modify: `MANIFEST.sha256`
- Verify: entire repository

- [ ] **Step 1: Regenerate the deterministic manifest**

```bash
python3 scripts/build_manifest.py --root . --manifest MANIFEST.sha256 --write
```

- [ ] **Step 2: Count the complete test suite**

```bash
PYTHONPATH=src:. python3 - <<'PY'
import unittest
print(unittest.defaultTestLoader.discover('tests').countTestCases())
PY
```

Record the exact count in the publication workflow and PR evidence.

- [ ] **Step 3: Run complete repository verification**

```bash
PYTHONPATH=src:. python3 scripts/verify_repo.py
python3 -m compileall -q src scripts tests
python3 scripts/secret_scan.py --root .
PYTHONPATH=src:. PYTHONHASHSEED=7 python3 -m unittest discover -s tests
PYTHONPATH=src:. PYTHONWARNINGS=error python3 -X dev -m unittest discover -s tests -p 'test_qualification_decision.py'
git diff --check
```

Expected: every command exits zero; manifest has no missing, unlisted, or mismatched paths; secret and text-style findings are zero.

- [ ] **Step 4: Commit the deterministic manifest**

```bash
git add MANIFEST.sha256
git commit -m "build: refresh manifest for C3 signed decisions"
```

- [ ] **Step 5: Publish through a bounded control workflow**

The workflow must reproduce focused RED on the exact RED SHA, apply the production implementation exactly once, regenerate the manifest, run focused and full GREEN verification, then push a clean `fix/c3-signed-decision` branch.

- [ ] **Step 6: Open and merge a documented PR**

The PR must list exact RED/GREEN run IDs, test counts, manifest count, changed files, truth boundary, and `Fixes #38`. Merge only after merge-virtual CI passes and lock the merge to the exact head SHA.

- [ ] **Step 7: Verify post-merge `main`**

Require the push-triggered deterministic workflow on the merge SHA to complete successfully before starting the later CLI or adoption slice.
