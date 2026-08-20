# C7 exact-byte final evidence pack authority Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Admit and independently verify one immutable exact-byte signed C7 final evidence pack bound to clean C4, C5, and PASS C6 authorities while keeping the result explicitly not released.

**Architecture:** Add `C7FinalPackService` in `src/starcom/final_pack.py`. It derives a deterministic upstream chain snapshot, parses a closed pack and manifest contract, persists immutable rows and ledger provenance, and independently verifies every binding. Wire one shared instance into `Runtime` without adding release or promotion behavior.

**Tech Stack:** Python 3.12, stdlib `sqlite3`, canonical JSON/SHA-256, existing Continuity signature verification, EventLedger, unittest.

**Spec:** `docs/superpowers/specs/2026-08-20-c7-final-evidence-pack-design.md`

## Global Constraints

- The signed payload has exactly the closed fields in the C7 design.
- C4, C5, and C6 are revalidated before admission and inside the admission transaction.
- C6 must be `C6_PASS_NO_BLOCKING_FINDINGS` with `PROCEED_TO_C7_FINAL_PACK`.
- The admitted gate effect is always `C7_FINAL_PACK_ADMITTED_NOT_RELEASED`.
- `release_status` is always `NOT_RELEASED`.
- `external_runtime_integration_status` and `live_census_certification_status` are always `NOT_PROVEN`.
- Every mandatory evidence kind occurs exactly once and binds its top-level digest.
- Packager and verifier are distinct and independent of all upstream material identities.
- Assessment packaging occurs strictly after the latest C4/C5/C6 evidence timestamp.
- Exact replay is idempotent; changed material, key, signature, upstream authority, or actor is a conflict.
- All pack/manifest/ledger material is immutable or append-only.
- No automatic release, publish, deploy, execute, promote, adoption, issue write, or external runtime integration.

---

### Task 1: Record design and establish the RED surface

**Files:**
- Create: `docs/superpowers/specs/2026-08-20-c7-final-evidence-pack-design.md`
- Create: `docs/superpowers/plans/2026-08-20-c7-final-evidence-pack.md`
- Create: `tests/test_final_pack.py`

**Interfaces:**
- Consume the existing `RedTeamGraph` fixture from `tests/test_red_team.py` so C7 tests use a real C5/C6 admission path and the existing C4 contract fixture.
- Produce `C7FinalPackService`, `C7FinalPackSnapshot`, and `C7FinalPackVerification` names required by later tasks.

- [x] Write the design/spec and plan with exact fields, constants, manifest kinds, chronology, provenance, and truth boundary.
- [ ] Write a `FinalPackGraph` wrapper that admits a PASS C6 assessment at `T6`, builds a signed C7 payload at `T7`, and owns a separate C7 verifier/root key.
- [ ] Add failing tests for deterministic snapshot, strict import surface, and `ModuleNotFoundError` before production implementation.
- [ ] Run `PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_final_pack.py' -q` and record the expected RED failure.
- [ ] Commit only the design, plan, and RED test surface.

### Task 2: Implement strict parser and immutable pack/manifest schema

**Files:**
- Create: `src/starcom/final_pack.py`
- Modify: `tests/test_final_pack.py`

**Interfaces:**
- `C7FinalPackService.__init__(database, ledger, *dependencies, signature_verifier=None, **named)` discovers trust, continuity, architecture, execution plan, and red-team authorities.
- `C7FinalPackService.snapshot(assessment_id) -> C7FinalPackSnapshot`.
- `C7FinalPackService.prepare(pack_id, assessment_id, payload=None) -> C7FinalPackPreparation`.
- `C7FinalPackService.admit_pack(assessment_id, key_id, payload, signature, *, actor, occurred_at=None) -> C7FinalPack`.

- [ ] Add tests for duplicate keys, invalid UTF-8/constants, missing/extra fields, fixed-status violations, malformed manifest entries, duplicate IDs/kinds, unsorted entries, missing mandatory kinds, invalid digests, and wrong top-level/manifest digest associations.
- [ ] Implement exact JSON parsing while reusing the existing C5 validation helpers to avoid duplicated production validation logic.
- [ ] Create `c7_final_packs` and `c7_final_pack_manifest` with exact digest checks, uniqueness constraints, foreign keys, and update/delete triggers.
- [ ] Run parser/schema tests and assert rejected payloads create no C7 rows.

### Task 3: Implement clean C4/C5/C6 chain snapshot and chronology

**Files:**
- Modify: `src/starcom/final_pack.py`
- Modify: `tests/test_final_pack.py`

**Interfaces:**
- `snapshot(assessment_id)` returns the current C4/C5/C6 identifiers, payload digests, snapshot digests, C3 digest, provenance digest, latest evidence timestamp, identity exclusion tuple, and `chain_snapshot_digest`.
- `verify_pack` treats any changed upstream snapshot or C6 verdict as stale.

- [ ] Add tests for absent/dirty C4, absent/dirty C5, absent/dirty/non-PASS C6, C4/C5/C6 binding mismatches, upstream identity reuse, and pre-evidence packaging timestamps.
- [ ] Implement C4 baseline and snapshot verification, C5 plan and C6-bound snapshot verification, and C6 PASS/recommendation checks.
- [ ] Implement deterministic provenance and chain snapshot digests, latest-evidence max calculation, and exact upstream identity exclusion.
- [ ] Run the chain/chronology tests green.

### Task 4: Implement exact-byte admission, replay, manifest persistence, and ledger

**Files:**
- Modify: `src/starcom/final_pack.py`
- Modify: `tests/test_final_pack.py`

**Interfaces:**
- Admission persists exact payload/signature bytes and ordered manifest rows, then appends `C7_FINAL_PACK_ADMITTED` on `continuity:c7:final-pack:<pack_id>`.
- `get_pack(pack_id) -> C7FinalPack` and `get_manifest(pack_id) -> tuple[Mapping[str, object], ...]` return stored material without mutation.

- [ ] Add tests for default-deny C7 root, exact signature bytes, admission, exact replay with one event, second pack conflict, changed bytes/key/signature/actor conflicts, and in-transaction upstream revalidation.
- [ ] Implement bounded bytes, signature verification, conflict detection, atomic pack/manifest/event insertion, and admission-time chronology.
- [ ] Run admission/replay tests green and assert one immutable pack and one ledger event for exact replay.

### Task 5: Implement independent verifier and Runtime wiring

**Files:**
- Modify: `src/starcom/final_pack.py`
- Modify: `src/starcom/cli.py`
- Modify: `tests/test_final_pack.py`

**Interfaces:**
- `verify_pack(pack_id) -> C7FinalPackVerification`, with aliases `verify` and `verify_final_pack`.
- Runtime contains one `final_pack: C7FinalPackService`; property `c7_final_pack` returns the same object.

- [ ] Add tamper tests for pack rows, manifest rows/digests/order, payload/signature digests, ledger event/chain, C4/C5/C6 evolution, and invalid fixed statuses.
- [ ] Implement independent reconstruction of payload, manifest digest bindings, upstream chain, signature, immutable members, and provenance.
- [ ] Add Runtime identity/surface tests ensuring no forbidden release/publish/deploy/execute/promote method exists and no CLI mutation command is exposed.
- [ ] Run focused C7 tests and existing smoke/CLI regressions.

### Task 6: Manifest, repository evidence, and integration

**Files:**
- Modify: `MANIFEST.sha256`
- Modify: `docs/superpowers/plans/2026-08-20-c7-final-evidence-pack.md`
- Inspect: all C7 changed files and final diff.

- [ ] Regenerate the manifest and run `git diff --check`.
- [ ] Run the complete deterministic gate with `PYTHONHASHSEED=0 PYTHONWARNINGS=error`.
- [ ] Scan the C7 production surface for release/publish/deploy/execute/promote/issue-write methods.
- [ ] Commit C7 paths, push one PR for issue #64, and verify CI/Sonar on the exact head SHA.
- [ ] Merge only the verified SHA, pull `main`, rerun the final gate, create a SHA-256 checked source archive, write the French reprise report, and close the issue.

## Verification evidence

Record only evidence from commands that actually ran:

- Initial RED: pending.
- Focused C7 suite: pending.
- C4/C5/C6 regression suites: pending.
- Runtime/policy smoke: pending.
- Full deterministic gate: pending.
- CI/Sonar exact-head result: pending.
- Post-merge `main` SHA, gate, archive SHA-256, and report path: pending.

## Truth boundary

The final state remains `C7_FINAL_PACK_ADMITTED_NOT_RELEASED`. It does not certify a live census, external runtime integration, component adoption, a product release candidate, or a production release.
