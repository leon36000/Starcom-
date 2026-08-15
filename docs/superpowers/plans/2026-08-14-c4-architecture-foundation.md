# Immutable C4 Architecture Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an explicitly authorized, append-only C4 input-set authority and an immutable STARCOM v3.2 architecture candidate that remains unreviewed and unpublished.

**Architecture:** `C4ArchitectureInputService` freezes clean terminal C3 execution evidence behind a minimal protocol and exact TrustPlane decision. `C4ArchitectureCandidateService` validates one closed architecture manifest against the frozen input set, consumes a second exact decision and stores `C4_ARCHITECTURE_CANDIDATE_NOT_REVIEWED`. Both services use immutable SQLite rows, append-only ledgers, exact replays and independent verifiers.

**Tech Stack:** Python 3.12, SQLite, STARCOM canonical JSON/SHA-256 helpers, EventLedger, TrustPlane, ContinuityService, unittest, deterministic fake C3 evidence source, GitHub Actions.

## Global Constraints

- Work from verified `main` SHA `a1cf4b071141c053c66170c67fed53d12030f249` or a later SHA proven to contain the same 279-test baseline.
- No worker, executor, network, package manager, publication or deployment call.
- Input execution IDs are non-empty, lexicographically sorted and duplicate-free.
- Accepted C3 statuses are `SUCCEEDED`, `FAILED_NO_EFFECT` and `FAILED_ROLLED_BACK`; `ROLLBACK_FAILED` and nonterminal states are rejected.
- Every input set contains at least one `SUCCEEDED` execution.
- `architecture_version` is the JSON string `"3.2"`.
- Candidate state and manifest gate effect are exactly `C4_ARCHITECTURE_CANDIDATE_NOT_REVIEWED`.
- TrustPlane decisions are exact, allowed, clean, chronological and consumed once.
- Every persisted C4 row is immutable through no-update and no-delete triggers.
- Exact replay is idempotent; any material difference is a conflict.
- No canonical product status promotion.

---

## File Structure

- Create `src/starcom/architecture_input.py`: C3 evidence protocol, input dataclasses, schema, preparation, freeze, reads and input verifier.
- Create `src/starcom/architecture_candidate.py`: manifest validator, candidate dataclasses, schema, preparation, creation, reads and candidate verifier.
- Create `tests/test_architecture_input.py`: input-set behavior, authorization, replay, status policy and falsification.
- Create `tests/test_architecture_candidate.py`: manifest semantics, authorization, replay and falsification.
- Modify `MANIFEST.sha256` only after all focused tests are green.
- Do not modify `src/starcom/cli.py` in this slice.

---

### Task 1: Establish the C4 RED contracts and deterministic evidence fixture

**Files:**
- Create: `src/starcom/architecture_input.py`
- Create: `src/starcom/architecture_candidate.py`
- Create: `tests/test_architecture_input.py`
- Create: `tests/test_architecture_candidate.py`

**Interfaces:**

`src/starcom/architecture_input.py` produces:

```python
class C4ExecutionEvidenceSource(Protocol):
    def get_execution(self, execution_id: str) -> C3AdoptionExecutionRecord: ...
    def verify_execution(
        self, execution_id: str
    ) -> C3AdoptionExecutionVerification: ...

    @staticmethod
    def terminal_result_digest(record: C3AdoptionExecutionRecord) -> str: ...

@dataclass(frozen=True)
class C4ArchitectureInputPreparation:
    input_set_id: str
    execution_ids: tuple[str, ...]
    member_count: int
    success_count: int
    negative_evidence_count: int
    input_set_digest: str
    author_identities: tuple[str, ...]
    action: str
    resource: str
    mission_id: str
    context: Mapping[str, Any]

@dataclass(frozen=True)
class C4ArchitectureInputSet:
    input_set_id: str
    member_count: int
    success_count: int
    negative_evidence_count: int
    input_set_digest: str
    author_identities: tuple[str, ...]
    authorization_decision_id: str
    frozen_at: str
    frozen_by: str
    ledger_event_id: str
    ledger_hash: str

@dataclass(frozen=True)
class C4ArchitectureInputVerification:
    input_set_id: str
    defects: tuple[str, ...]

class C4ArchitectureInputService:
    def prepare_freeze(
        self, input_set_id: str, execution_ids: Sequence[str]
    ) -> C4ArchitectureInputPreparation: ...
    def freeze(... ) -> C4ArchitectureInputSet: ...
    def get_input_set(self, input_set_id: str) -> C4ArchitectureInputSet: ...
    def get_members(self, input_set_id: str) -> tuple[Mapping[str, Any], ...]: ...
    def verify_input_set(
        self, input_set_id: str
    ) -> C4ArchitectureInputVerification: ...
```

`src/starcom/architecture_candidate.py` produces:

```python
class C4ArchitectureCandidateStatus(str, Enum):
    NOT_REVIEWED = "C4_ARCHITECTURE_CANDIDATE_NOT_REVIEWED"

@dataclass(frozen=True)
class C4ArchitectureCandidatePreparation:
    candidate_id: str
    architecture_id: str
    architecture_version: str
    input_set_id: str
    input_set_digest: str
    manifest_sha256: str
    adr_count: int
    port_count: int
    binding_count: int
    nfr_count: int
    stage_order: tuple[str, ...]
    status: C4ArchitectureCandidateStatus
    action: str
    resource: str
    mission_id: str
    context: Mapping[str, Any]

@dataclass(frozen=True)
class C4ArchitectureCandidate:
    candidate_id: str
    architecture_id: str
    architecture_version: str
    input_set_id: str
    input_set_digest: str
    manifest_sha256: str
    status: C4ArchitectureCandidateStatus
    authorization_decision_id: str
    created_at: str
    created_by: str
    ledger_event_id: str
    ledger_hash: str

@dataclass(frozen=True)
class C4ArchitectureCandidateVerification:
    candidate_id: str
    defects: tuple[str, ...]

class C4ArchitectureCandidateService:
    def prepare_create(... ) -> C4ArchitectureCandidatePreparation: ...
    def create_candidate(... ) -> C4ArchitectureCandidate: ...
    def get_candidate(self, candidate_id: str) -> C4ArchitectureCandidate: ...
    def get_manifest(self, candidate_id: str) -> Mapping[str, Any]: ...
    def verify_candidate(
        self, candidate_id: str
    ) -> C4ArchitectureCandidateVerification: ...
```

- [ ] **Step 1: Create explicit RED seams**

Create the public types above. `prepare_freeze`, `freeze`, `prepare_create` and `create_candidate` raise `StateTransitionError("C4 architecture foundation is not implemented")`. Read methods raise the appropriate `NotFoundError`. Verifiers return one `C4_ARCHITECTURE_FOUNDATION_NOT_IMPLEMENTED` defect.

- [ ] **Step 2: Build `FakeExecutionEvidenceSource`**

In `tests/test_architecture_input.py`, create real `C3AdoptionExecutionRecord` objects for:

- `execution-success` with status `SUCCEEDED`;
- `execution-no-effect` with status `FAILED_NO_EFFECT`;
- `execution-rolled-back` with status `FAILED_ROLLED_BACK`;
- `execution-rollback-failed` with status `ROLLBACK_FAILED`;
- `execution-running` with status `RUNNING`.

Use distinct candidate IDs, digests and `requested_by` identities. Implement `verify_execution()` with a configurable defect map and use `C3AdoptionExecutionService.terminal_result_digest()` for terminal records.

- [ ] **Step 3: Add focused input RED tests**

Add these tests:

```text
test_prepare_freeze_is_deterministic_and_side_effect_free
test_default_deny_then_exact_freeze_is_verified_and_idempotent
test_freeze_accepts_success_plus_clean_negative_evidence
test_freeze_rejects_unsorted_duplicate_nonterminal_dirty_and_rollback_failed_inputs
test_freeze_requires_at_least_one_success
test_conflicting_input_replay_is_rejected
test_input_verifier_detects_member_digest_consumption_and_ledger_tampering
```

Use real Database, EventLedger, TrustPlane and ContinuityService. Every mutation must require an exact TrustPlane decision.

- [ ] **Step 4: Add focused candidate RED tests**

Create a valid manifest fixture and add:

```text
test_prepare_candidate_is_deterministic_and_side_effect_free
test_default_deny_then_valid_candidate_is_verified_and_idempotent
test_manifest_rejects_missing_owner_or_orphan_port
test_manifest_rejects_missing_test_proof_mapping_or_mission_stage
test_manifest_rejects_failed_execution_binding_and_missing_success_binding
test_manifest_rejects_incomplete_vertical_benchmark
test_conflicting_candidate_or_architecture_reuse_is_rejected
test_candidate_verifier_detects_manifest_consumption_and_ledger_tampering
```

- [ ] **Step 5: Run exact RED suites**

Run:

```bash
PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test_architecture_input.py' -v
PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test_architecture_candidate.py' -v
```

Expected: fixture setup passes and only the explicit C4 seams fail.

- [ ] **Step 6: Run complete RED verification**

```bash
PYTHONPATH=src:. python3 scripts/verify_repo.py
```

Expected: all 279 baseline tests remain green; only the new C4 tests are red; compile, secret scan and text policy are green; manifest reports only new RED files/documents.

- [ ] **Step 7: Commit the causal RED**

```bash
git add \
  src/starcom/architecture_input.py \
  src/starcom/architecture_candidate.py \
  tests/test_architecture_input.py \
  tests/test_architecture_candidate.py \
  docs/superpowers/specs/2026-08-14-c4-architecture-foundation-design.md \
  docs/superpowers/plans/2026-08-14-c4-architecture-foundation.md
git commit -m "test: define immutable C4 architecture foundation contract"
```

---

### Task 2: Implement immutable C4 input-set freezing

**Files:**
- Modify: `src/starcom/architecture_input.py`
- Test: `tests/test_architecture_input.py`

**Interfaces:**
- Consumes the protocol and dataclasses from Task 1.
- Produces a verified immutable input set used by the candidate service.

- [ ] **Step 1: Add validation helpers and closed status policy**

Implement required text, timezone-aware RFC 3339 timestamp, lowercase SHA-256, sorted/unique execution IDs and the allowed terminal set:

```python
_ALLOWED_TERMINAL = {
    C3AdoptionExecutionStatus.SUCCEEDED,
    C3AdoptionExecutionStatus.FAILED_NO_EFFECT,
    C3AdoptionExecutionStatus.FAILED_ROLLED_BACK,
}
```

Reject `ROLLBACK_FAILED`, `RUNNING` and `REQUESTED_NOT_EXECUTED` with `StateTransitionError`.

- [ ] **Step 2: Build one exact frozen member mapping**

Implement `_snapshot_execution(execution_id)` using only the fields listed in the spec. Require a clean source verifier. Compute `terminal_result_digest` through the injected source. Normalize blank errors to `None`.

- [ ] **Step 3: Implement deterministic preparation**

`prepare_freeze()` builds ordered members, counts success/negative evidence, requires at least one success, computes `sha256_digest(list(members))`, derives sorted author identities and returns the exact TrustPlane request material.

- [ ] **Step 4: Create immutable schema**

Create:

```sql
c4_architecture_input_sets
c4_architecture_input_members
```

Add uniqueness, count and digest checks plus no-update/no-delete triggers. Store canonical author JSON and canonical member JSON.

- [ ] **Step 5: Implement exact decision verification**

The expected request tuple is:

```python
(
    actor,
    "c4.architecture-input.freeze",
    f"continuity:c4:architecture-input:{input_set_id}",
    f"c4-architecture:{input_set_id}",
    dict(preparation.context),
)
```

Require `TrustPlane.verify_decision()`, allowed result, exact tuple and chronology.

- [ ] **Step 6: Implement atomic freeze**

Inside one transaction, rebuild preparation, recheck decision, consume it as:

```text
operation_kind = C4_ARCHITECTURE_INPUT_FROZEN
operation_id = <input_set_id>
```

Append ledger kind `C4_ARCHITECTURE_INPUT_FROZEN`, insert the set row and contiguous membership rows.

- [ ] **Step 7: Implement reads and exact replay**

`get_input_set()` and `get_members()` parse only canonical JSON objects. Exact replay verifies the stored input set before returning it. Different execution list, decision or actor raises `ConflictError`.

- [ ] **Step 8: Implement independent input verification**

Verify memberships, ordinals, member digests, current source snapshots, set digest/counts/authors, decision, consumption, event payload/hash and ledger chain. Deduplicate defects while preserving deterministic order.

- [ ] **Step 9: Run focused GREEN**

```bash
PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test_architecture_input.py' -v
```

Expected: all input tests pass; candidate tests remain red only because candidate code is not implemented.

- [ ] **Step 10: Commit input authority**

```bash
git add src/starcom/architecture_input.py tests/test_architecture_input.py
git commit -m "feat: freeze verified C4 architecture input sets"
```

---

### Task 3: Implement the closed STARCOM v3.2 manifest validator

**Files:**
- Modify: `src/starcom/architecture_candidate.py`
- Test: `tests/test_architecture_candidate.py`

**Interfaces:**
- Consumes `C4ArchitectureInputService.get_input_set()`, `get_members()` and `verify_input_set()`.
- Produces `_normalize_manifest(manifest) -> tuple[dict[str, object], str, str]` where the tuple is normalized mapping, canonical JSON and SHA-256.

- [ ] **Step 1: Define exact field sets**

Add frozensets for the top-level manifest, ADR, port, binding, vertical benchmark and NFR schemas exactly as written in the spec. Unknown or missing fields raise `ValidationError`.

- [ ] **Step 2: Implement sorted unique nested collections**

Require top-level lists sorted by their identity fields. Require string lists sorted, duplicate-free and non-empty where specified. Reject booleans as scalar IDs or counts.

- [ ] **Step 3: Validate ADR and port ownership**

Build `port_by_id` and require unique capabilities. Require every port to be referenced by an ADR whose owner equals `owner_authority`. Every ADR evidence execution must exist in the input set.

- [ ] **Step 4: Validate Mission Fabric**

Require exactly:

```python
_STAGE_ORDER = ("RESEARCH", "ARTIFACT", "ACTION", "MONITOR")
```

Every stage has at least one existing port and every port appears in at least one stage.

- [ ] **Step 5: Validate component bindings**

Map input members by execution ID. Require exactly one binding for every successful member and none for negative evidence. Candidate ID/digest must match the member. Port IDs must exist and capability IDs must equal the capabilities derived from those ports.

- [ ] **Step 6: Validate vertical benchmark and NFRs**

Require exact stage order and stage maps. For each stage, benchmark test/proof IDs must be subsets of the union exposed by that stage's ports. Validate non-empty end-to-end IDs and closed NFR objects.

- [ ] **Step 7: Normalize and hash**

Return the normalized mapping, `canonical_json(normalized)` and `sha256_digest(normalized)`.

- [ ] **Step 8: Run semantic validation tests**

```bash
PYTHONPATH=src:. python3 -m unittest \
  tests.test_architecture_candidate.C4ArchitectureCandidateTests.test_manifest_rejects_missing_owner_or_orphan_port \
  tests.test_architecture_candidate.C4ArchitectureCandidateTests.test_manifest_rejects_missing_test_proof_mapping_or_mission_stage \
  tests.test_architecture_candidate.C4ArchitectureCandidateTests.test_manifest_rejects_failed_execution_binding_and_missing_success_binding \
  tests.test_architecture_candidate.C4ArchitectureCandidateTests.test_manifest_rejects_incomplete_vertical_benchmark -v
```

Expected: all listed semantic tests pass while persistence tests remain red.

- [ ] **Step 9: Commit manifest validator**

```bash
git add src/starcom/architecture_candidate.py tests/test_architecture_candidate.py
git commit -m "feat: validate closed STARCOM v3.2 architecture manifests"
```

---

### Task 4: Implement immutable C4 candidate creation and verification

**Files:**
- Modify: `src/starcom/architecture_candidate.py`
- Test: `tests/test_architecture_candidate.py`

**Interfaces:**
- Produces the public candidate service methods from Task 1.

- [ ] **Step 1: Create candidate schema and triggers**

Create `c4_architecture_candidates` with unique `candidate_id` and `architecture_id`, canonical manifest JSON, manifest SHA-256, input-set binding, status, authorization, creation actor/time and ledger linkage. Add no-update/no-delete triggers.

- [ ] **Step 2: Implement deterministic preparation**

Require a clean input set, normalize the manifest and return exact counts, stage order, status and TrustPlane request material.

- [ ] **Step 3: Implement candidate authorization checks**

The expected request tuple is:

```python
(
    actor,
    "c4.architecture-candidate.create",
    f"continuity:c4:architecture-candidate:{candidate_id}",
    f"c4-architecture:{architecture_id}",
    dict(preparation.context),
)
```

Require a clean allowed decision, exact tuple and chronology.

- [ ] **Step 4: Implement atomic creation**

Inside one transaction, repeat input verification and manifest normalization, consume the decision as:

```text
operation_kind = C4_ARCHITECTURE_CANDIDATE_CREATED
operation_id = <candidate_id>
```

Append ledger kind `C4_ARCHITECTURE_CANDIDATE_CREATED` and insert the immutable row with status `C4_ARCHITECTURE_CANDIDATE_NOT_REVIEWED`.

- [ ] **Step 5: Implement reads and exact replay**

`get_candidate()` returns the immutable summary. `get_manifest()` parses the stored object. Exact replay requires the same candidate ID, architecture ID, input set, manifest bytes, decision and actor and must pass the independent verifier.

- [ ] **Step 6: Implement candidate verification**

Reverify input set, canonical manifest, stored counts/IDs/status, TrustPlane decision, consumption, ledger event/payload/hash and chain. Any stale or tampered input makes the candidate dirty.

- [ ] **Step 7: Run focused GREEN**

```bash
PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test_architecture_candidate.py' -v
```

Expected: all candidate tests pass.

- [ ] **Step 8: Run both C4 suites**

```bash
PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test_architecture_*.py' -v
```

Expected: every C4 foundation test passes.

- [ ] **Step 9: Commit candidate authority**

```bash
git add src/starcom/architecture_candidate.py tests/test_architecture_candidate.py
git commit -m "feat: create immutable unreviewed C4 architecture candidates"
```

---

### Task 5: Falsification, deterministic repository proof and publication

**Files:**
- Modify: `tests/test_architecture_input.py`
- Modify: `tests/test_architecture_candidate.py`
- Modify: `MANIFEST.sha256`

- [ ] **Step 1: Complete mutation coverage**

Mutate independently:

```text
input member JSON
input member digest
input-set digest
input decision request
input authorization consumption
input ledger actor/payload/hash
candidate manifest JSON
candidate manifest SHA-256
candidate input-set binding
candidate status
candidate decision request
candidate authorization consumption
candidate ledger actor/payload/hash
```

Each mutation must yield one precise deterministic defect and no false clean verdict.

- [ ] **Step 2: Regenerate deterministic manifest**

```bash
python3 scripts/build_manifest.py --root . --manifest MANIFEST.sha256 --write
```

- [ ] **Step 3: Record exact test count**

```bash
PYTHONPATH=src:. python3 - <<'PY'
import unittest
print(unittest.defaultTestLoader.discover('tests').countTestCases())
PY
```

Use the resulting exact count in the publication workflow and PR body.

- [ ] **Step 4: Run complete verification**

```bash
PYTHONPATH=src:. python3 scripts/verify_repo.py
python3 -m compileall -q src scripts tests
python3 scripts/secret_scan.py --root .
PYTHONPATH=src:. PYTHONHASHSEED=7 python3 -m unittest discover -s tests
PYTHONPATH=src:. PYTHONWARNINGS=error python3 -X dev -m unittest discover -s tests -p 'test_architecture_*.py'
git diff --check
```

Every command must exit zero. Manifest missing/unlisted/mismatched paths, secret findings and text-style findings must all be zero.

- [ ] **Step 5: Commit deterministic proof**

```bash
git add MANIFEST.sha256 tests/test_architecture_input.py tests/test_architecture_candidate.py
git commit -m "test: harden C4 architecture foundation falsification"
```

- [ ] **Step 6: Publish through a bounded RED/GREEN workflow**

The workflow must:

1. freeze exact `main` and RED refs;
2. reproduce only the C4 RED failures;
3. apply production files exactly once;
4. regenerate the manifest;
5. run focused and full GREEN verification;
6. recheck immutable refs;
7. publish `fix/c4-architecture-foundation`.

- [ ] **Step 7: Open a documented draft PR**

The PR must list exact RED/GREEN run IDs, test counts, manifest count, exact changed files and the no-review/no-publication/no-deployment truth boundary. Include `Fixes #59`.

- [ ] **Step 8: Require merge-virtual and post-merge CI**

Merge only after pull-request CI passes on the exact head SHA. Then require the push-triggered deterministic workflow on the merge SHA to pass before starting #55.
