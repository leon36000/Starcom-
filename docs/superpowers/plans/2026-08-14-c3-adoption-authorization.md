# C3 Adoption Authorization Without Execution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development or superpowers:executing-plans task-by-task. Every task follows RED → GREEN → verification.

**Goal:** Record one immutable, explicitly authorized C3 adoption intent while proving that no installation, enablement, deployment, integration, or execution occurs.

**Architecture:** A new `C3AdoptionService` prepares an exact TrustPlane request from a clean selected signed C3 decision and a mandatory rollback plan. It then consumes one exact allowed TrustPlane decision, appends an immutable authorization event, and independently verifies the decision, candidate, rollback, authorization, consumption, chronology, and ledger provenance. Execution remains a separate future authority.

**Tech stack:** Python 3.12, SQLite, STARCOM canonical JSON/SHA-256 helpers, `EventLedger`, `TrustPlane`, `ContinuityService`, `C3DecisionService`, `QualificationLab`, `unittest`, GitHub Actions.

## Global constraints

- Status is always `C3_ADOPTION_AUTHORIZED_NOT_EXECUTED`.
- No method or CLI may download, install, enable, integrate, deploy, run, or execute anything.
- One adoption authorization maximum per C3 run and signed C3 decision.
- TrustPlane action/resource/mission/context must match exactly.
- The global continuity authorization-consumption table is used once.
- Rollback material is mandatory, closed, canonical, and hashed.
- Every mutable prerequisite is repeated in the write transaction.
- No canonical project-status promotion.

---

## File structure

- Create `src/starcom/adoption.py`: status/preparation/record/verification contracts, rollback validation, preparation, admission, retrieval, and independent verifier.
- Create `tests/test_adoption.py`: real TrustPlane/C3 decision fixture with a bounded C2 certification service.
- Modify `MANIFEST.sha256` only after GREEN.
- Keep `src/starcom/qualification.py`, `src/starcom/qualification_gate.py`, `src/starcom/qualification_decision.py`, and `src/starcom/cli.py` behavior unchanged in this slice.

---

### Task 1: Establish the adoption-authorization RED contract

**Files:**
- Create: `src/starcom/adoption.py`
- Create: `tests/test_adoption.py`

- [ ] **Step 1: Add the public RED seam**

Define:

- `C3AdoptionStatus`
- `C3AdoptionPreparation`
- `C3AdoptionRecord`
- `C3AdoptionVerification`
- `C3AdoptionService.prepare()`
- `C3AdoptionService.authorize_adoption()`
- `C3AdoptionService.get_adoption()`
- `C3AdoptionService.verify_adoption()`

The RED seam raises `StateTransitionError("C3 adoption authorization is not implemented")` for preparation/admission, `NotFoundError` for retrieval, and returns `C3_ADOPTION_AUTHORITY_NOT_IMPLEMENTED` from verification.

- [ ] **Step 2: Build a deterministic real fixture**

Use real database, ledger, TrustPlane, ContinuityService, QualificationLab, C3 gate, and C3 signed-decision service. Use a deterministic signature verifier and a bounded clean C2 certification fixture.

Create a selected signed C3 decision with independent actors. Do not reconstruct 800 C2 census identities.

- [ ] **Step 3: Add focused RED tests**

Add tests for:

1. deterministic preparation and exact authorization context;
2. default deny blocking admission;
3. valid exact authorization, immutable record, verifier, and exact replay;
4. no-selection decision rejection;
5. invalid rollback contracts;
6. wrong actor/resource/mission/context rejection;
7. authorization/adoption chronology;
8. second adoption and authorization reuse;
9. transaction-time C3-decision and TrustPlane rechecks;
10. row, rollback, consumption, and ledger tampering;
11. later qualification evidence making adoption stale;
12. no execution method.

- [ ] **Step 4: Run focused RED**

```bash
PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test_adoption.py' -v
```

Expected: only the new adoption contract is red.

- [ ] **Step 5: Run complete RED repository verification**

```bash
PYTHONPATH=src:. python3 scripts/verify_repo.py
```

Expected: existing 196 tests remain green; compile/secret/style remain green; only the new module, test, spec, and plan are unlisted.

- [ ] **Step 6: Commit RED evidence**

```bash
git add src/starcom/adoption.py tests/test_adoption.py
git commit -m "test: define C3 adoption authorization contract"
```

---

### Task 2: Implement rollback validation and deterministic preparation

**Files:**
- Modify: `src/starcom/adoption.py`
- Test: `tests/test_adoption.py`

- [ ] **Step 1: Implement closed rollback validation**

Require exactly:

```python
_ROLLBACK_FIELDS = frozenset(
    {
        "strategy",
        "steps",
        "verification_steps",
        "abort_conditions",
        "requires_separate_execution_authorization",
    }
)
```

Validate non-empty strings/lists and exact Boolean `True`. Return canonical object, JSON, and SHA-256.

- [ ] **Step 2: Resolve the clean selected C3 decision**

Find the unique `c3_decisions` row by `c3_run_id`, require `verify_decision()` clean, require selected verdict, and load the selected frozen candidate membership.

- [ ] **Step 3: Recheck selected candidate material**

Parse frozen canonical material, verify its SHA-256, compare it to the immutable qualification artifact and its material digest, and bind the decision payload/head digests.

- [ ] **Step 4: Build exact TrustPlane material**

Return action/resource/mission/context exactly as specified in the design. Preparation must be deterministic and side-effect free.

- [ ] **Step 5: Run preparation and rollback tests**

```bash
PYTHONPATH=src:. python3 -m unittest \
  tests.test_adoption.C3AdoptionTests.test_preparation_is_deterministic_and_binds_exact_authorization_context \
  tests.test_adoption.C3AdoptionTests.test_invalid_rollback_contracts_are_rejected \
  tests.test_adoption.C3AdoptionTests.test_no_selection_decision_is_rejected -v
```

- [ ] **Step 6: Commit preparation layer**

```bash
git add src/starcom/adoption.py tests/test_adoption.py
git commit -m "feat: prepare exact C3 adoption authorization material"
```

---

### Task 3: Implement immutable TrustPlane-authorized admission

**Files:**
- Modify: `src/starcom/adoption.py`
- Test: `tests/test_adoption.py`

- [ ] **Step 1: Create immutable schema**

Create `c3_adoptions` with unique adoption ID, C3 run, signed decision, and TrustPlane decision. Add fixed-status and digest checks plus foreign keys. Add no-update/no-delete triggers.

- [ ] **Step 2: Implement exact authorization verification**

Require `TrustPlane.verify_decision()` clean and `get_decision()` present. Compare allowed, actor, action, resource, mission ID, and complete context exactly.

- [ ] **Step 3: Implement chronology**

Require TrustPlane `decided_at >= signed_decision.admitted_at` and adoption `authorized_at >= TrustPlane.decided_at`.

- [ ] **Step 4: Implement idempotency and conflicts**

Exact replay returns the existing verified record. Changed material, second C3 adoption, second decision adoption, or reused TrustPlane decision fails closed.

- [ ] **Step 5: Repeat checks in one transaction**

Rebuild preparation, reverify signed decision and TrustPlane decision, recheck chronology, consume the decision in `continuity_authorization_consumptions`, append the adoption event, and insert the immutable row.

- [ ] **Step 6: Run admission tests**

```bash
PYTHONPATH=src:. python3 -m unittest \
  tests.test_adoption.C3AdoptionTests.test_default_deny_blocks_adoption_authorization \
  tests.test_adoption.C3AdoptionTests.test_exact_authorization_creates_verified_not_executed_receipt \
  tests.test_adoption.C3AdoptionTests.test_wrong_actor_resource_mission_or_context_is_rejected \
  tests.test_adoption.C3AdoptionTests.test_authorization_and_adoption_chronology_is_enforced \
  tests.test_adoption.C3AdoptionTests.test_second_adoption_and_authorization_reuse_are_rejected -v
```

- [ ] **Step 7: Commit admission**

```bash
git add src/starcom/adoption.py tests/test_adoption.py
git commit -m "feat: authorize C3 adoption without execution"
```

---

### Task 4: Implement independent verification and falsification

**Files:**
- Modify: `src/starcom/adoption.py`
- Test: `tests/test_adoption.py`

- [ ] **Step 1: Verify rollback and stored record**

Reparse the stored rollback JSON, validate the closed contract, require canonical serialization, and recompute its digest.

- [ ] **Step 2: Verify signed decision and candidate**

Require a clean selected decision and compare decision/candidate/head/payload digests against the adoption row and frozen/current candidate evidence.

- [ ] **Step 3: Verify TrustPlane and consumption**

Reverify the decision, exact request, chronology, and the global authorization-consumption row.

- [ ] **Step 4: Verify ledger provenance**

Require exact stream, kind, actor, timestamp, payload, stored hash, and clean chain.

- [ ] **Step 5: Contain corruption**

Malformed rollback JSON/timestamps or tampered rows must return deterministic defects, never traceback.

- [ ] **Step 6: Run falsification tests**

```bash
PYTHONPATH=src:. python3 -m unittest \
  tests.test_adoption.C3AdoptionTests.test_transaction_rechecks_decision_and_trustplane \
  tests.test_adoption.C3AdoptionTests.test_verifier_detects_row_rollback_consumption_and_ledger_tampering \
  tests.test_adoption.C3AdoptionTests.test_later_qualification_evidence_makes_adoption_stale \
  tests.test_adoption.C3AdoptionTests.test_service_has_no_execution_method -v
```

- [ ] **Step 7: Run focused GREEN**

```bash
PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test_adoption.py' -v
```

- [ ] **Step 8: Commit verifier hardening**

```bash
git add src/starcom/adoption.py tests/test_adoption.py
git commit -m "test: harden C3 adoption authorization verification"
```

---

### Task 5: Deterministic proof and publication

**Files:**
- Modify: `MANIFEST.sha256`
- Verify: entire repository

- [ ] **Step 1: Regenerate manifest**

```bash
python3 scripts/build_manifest.py --root . --manifest MANIFEST.sha256 --write
```

- [ ] **Step 2: Count tests and run full verification**

```bash
PYTHONPATH=src:. python3 - <<'PY'
import unittest
print(unittest.defaultTestLoader.discover('tests').countTestCases())
PY
PYTHONPATH=src:. python3 scripts/verify_repo.py
python3 -m compileall -q src scripts tests
python3 scripts/secret_scan.py --root .
PYTHONPATH=src:. PYTHONHASHSEED=7 python3 -m unittest discover -s tests
PYTHONPATH=src:. PYTHONWARNINGS=error python3 -X dev -m unittest discover -s tests -p 'test_adoption.py'
git diff --check
```

- [ ] **Step 3: Publish through a bounded control workflow**

The workflow must reproduce focused RED on the exact RED SHA, apply the implementation once, refresh the manifest, run focused/full GREEN and stress checks, then push `fix/c3-adoption-authorization`.

- [ ] **Step 4: Open and merge a documented PR**

List exact run IDs, SHA values, test/manifest counts, changed files, truth boundary, and `Fixes #42`. Merge only after clean merge-virtual CI using the exact head SHA.

- [ ] **Step 5: Verify post-merge `main`**

Require push-triggered deterministic CI on the merge SHA to complete successfully before a later CLI or execution slice.
