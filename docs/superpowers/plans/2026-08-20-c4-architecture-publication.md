# C4 Architecture Publication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** implement Issue #57 as a separately authorized, append-only C4 publication registry that records an accepted architecture manifest as `C4_ARCHITECTURE_PUBLISHED_NOT_DEPLOYED` without deployment, execution, runtime integration, component adoption, or global status promotion.

**Architecture:** Add one `C4ArchitecturePublicationService` over the existing canonical database, ledger, TrustPlane, continuity consumption table, C4 input service, candidate service, and review service. `prepare()` reads and independently verifies the candidate, frozen input set, and accepted review without mutation; `publish()` rechecks every binding inside one SQLite transaction, consumes the exact single-use decision, appends one publication ledger event, and inserts one immutable registry row. `verify_publication()` reconstructs the same graph and detects row, manifest, decision, consumption, event, and chain tampering.

**Tech Stack:** Python 3.12, SQLite transactions and immutable triggers, existing `EventLedger`, `TrustPlane`, `ContinuityService`, C4 input/candidate/review services, `unittest`.

**Spec:** GitHub Issue #57 — https://github.com/leon36000/Starcom-/issues/57

## Global Constraints

- TrustPlane action is exactly `c4.architecture.publish`.
- Authorization context binds publication ID, candidate/architecture/input-set IDs, manifest SHA-256, input-set digest, review ID, reviewer identity, review payload/signature digests, accepted verdict, and mode `PUBLISH_ARCHITECTURE_NOT_DEPLOY`.
- Publication status is exactly `C4_ARCHITECTURE_PUBLISHED_NOT_DEPLOYED`.
- `prepare()` is deterministic and side-effect free.
- Only exact `C4_ARCHITECTURE_ACCEPTED` reviews with clean candidate/input/review verification are eligible.
- Publication consumes one allowed, verified, exact, single-use decision atomically with the immutable row and ledger event.
- Replay with unchanged material returns the original row; changed material conflicts.
- Candidate manifest bytes and candidate status are never modified; no global canonical status is promoted.
- No publication method may deploy, execute, install, run, integrate a runtime, adopt a component, or access the network.

---

### Task 1: Publication contract and RED tests

**Files:**
- Create: `src/starcom/architecture_publication.py` (only after RED is observed)
- Test: `tests/test_architecture_publication.py`
- Create: `docs/superpowers/plans/2026-08-20-c4-architecture-publication.md`

**Interfaces:**
- Test constructs `C4ArchitecturePublicationService(database, ledger, trust, continuity, inputs, candidates, reviews)`.
- Test consumes `prepare(publication_id, candidate_id, review_id)`, `publish(publication_id, candidate_id, review_id, authorization_decision_id, actor, occurred_at)`, `get_publication(publication_id)`, `get_manifest(publication_id)`, and `verify_publication(publication_id)`.
- Test expects `C4ArchitecturePublicationPreparation`, `C4ArchitecturePublication`, `C4ArchitecturePublicationVerification`, and `C4ArchitecturePublicationStatus` to be importable.

- [x] **Step 1: Write the failing test**

Cover the first vertical slice with a real canonical graph and a fixture accepted review: deterministic side-effect-free preparation, exact action/resource/mission/context, default deny, explicit authorization, atomic publication, stored manifest equality, exact status, one ledger event, clean verification, and no candidate mutation.

- [x] **Step 2: Run the focused test to verify the expected RED**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:tests:. python3 -m unittest discover -s tests -p 'test_architecture_publication.py' -v
```

Expected: import or constructor failure because the publication service does not exist yet; no production implementation is present at this step.

- [x] **Step 3: Add the minimum service contract and schema**

Create the immutable `c4_architecture_publications` table with unique candidate, architecture, review, decision, ledger-event, and digest bindings, plus update/delete triggers. Define the dataclasses and exact constants without adding CLI or external effects.

- [x] **Step 4: Run the focused test to verify the first GREEN slice**

Run the same focused command and require the initial happy path to pass with the publication row, manifest, event, and status persisted.

### Task 2: Exact authorization and atomic admission

**Files:**
- Modify: `src/starcom/architecture_publication.py`
- Test: `tests/test_architecture_publication.py`

**Interfaces:**
- `prepare()` returns an exact TrustPlane request context containing all Issue #57 binding fields.
- `publish()` requires an existing allowed decision whose subject equals `actor`, action/resource/mission/context match exactly, decision time is strictly after review admission, and publication time is not earlier than the decision.

- [x] **Step 1: Add RED tests for default deny, wrong request material, chronology, and decision reuse**
- [x] **Step 2: Run the focused tests and confirm the service contract is RED before implementation**
- [x] **Step 3: Implement exact request validation and `_consume_authorization()` inside the publication transaction**
- [x] **Step 4: Run the focused tests and confirm GREEN**

### Task 3: Replay, conflicts, and fail-closed verification

**Files:**
- Modify: `src/starcom/architecture_publication.py`
- Test: `tests/test_architecture_publication.py`

**Interfaces:**
- Exact replay returns the original immutable publication even if the caller supplies a later replay timestamp.
- Any changed publication ID, candidate, review, manifest, digest, decision, actor, or material binding raises `ConflictError`.
- `verify_publication()` returns a defect tuple and never mutates state.

- [x] **Step 1: Add RED tamper tests**

Test row tampering after dropping the trigger, candidate manifest tampering, review/candidate/input digest mismatch, authorization consumption tampering, decision request tampering, ledger payload/actor/kind/stream/hash tampering, broken publication chain, missing row, and duplicate publication attempts.

- [x] **Step 2: Run the focused tests and confirm the service contract is RED before implementation**
- [x] **Step 3: Implement independent reconstruction of candidate, input, review, decision, consumption, publication payload, ledger event, and ledger chain**
- [x] **Step 4: Run the focused suite and confirm GREEN**

### Task 4: Canonical Runtime integration and repository gates

**Files:**
- Modify: `src/starcom/cli.py` (construct one canonical publication service; no publication CLI unless a separate issue requires it)
- Modify: `MANIFEST.sha256`
- Test: `tests/test_architecture_publication.py`

**Interfaces:**
- `Runtime.open()` exposes `architecture_publication` using the same database, ledger, TrustPlane, continuity, input, candidate, and review instances.
- No method in the publication service invokes a worker, executor, adapter, package manager, network, deploy, run, install, or component adoption path.

- [x] **Step 1: Add RED constructor graph test**
- [x] **Step 2: Wire the service into `Runtime` and run focused tests**
- [x] **Step 3: Regenerate `MANIFEST.sha256` and run compile/diff checks**
- [x] **Step 4: Run deterministic repository gate with `PYTHONHASHSEED=0` and `PYTHONWARNINGS=error`**
- [x] **Step 5: Inspect final diff and confirm no forbidden effect path was added**

## Verification evidence before integration

- RED observed before implementation: `ModuleNotFoundError: starcom.architecture_publication`; the later negative/tamper cases were added as the GREEN/falsification expansion.
- Focused publication suite: 12 tests passed.
- C4 input/candidate/review regression: 147 tests passed.
- Deterministic repository gate: 438 tests passed; compile, secret scan (0 findings), text-style (0 findings), and manifest (111/111) passed.
- Publication code contains no worker, executor, adapter, package-manager, network, deploy, execute, install, run, or adoption call.

### Task 5: Integration evidence

- [ ] Commit the verified implementation on `recovery/issue57-c4-publication`.
- [ ] Push, open a PR linked to #57, and wait for the exact-head GitHub verification job to succeed.
- [ ] Merge only with the expected head SHA and fast-forward local `main`.
- [ ] Run the full post-merge gate on the merge commit.
- [ ] Update this plan with evidence and produce the exact source archive and reprise report.

## Boundary evidence

This authority makes an accepted manifest canonical only in the internal C4 publication registry. It does not alter the candidate manifest or status, does not promote any global product state, and does not claim that STARCOM is the complete product.
