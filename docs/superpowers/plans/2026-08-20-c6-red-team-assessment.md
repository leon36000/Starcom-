# C6 exact-byte red-team assessment authority Implementation Plan

> For agentic workers: use the repository's TDD, verification, and isolated-worktree practices. Steps use checkbox syntax for tracking.

Goal: Admit and independently verify one immutable exact-byte signed C6 red-team assessment bound to a clean C5 execution plan while keeping release and promotion explicitly blocked except for the signed PASS recommendation.

Architecture: Add `C6RedTeamService` with a deterministic C5 snapshot binder, closed attack/findings parser, derived verdict validator, immutable assessment/member tables, exact replay handling, append-only ledger provenance, and an independent verifier. Wire one shared instance into `Runtime` without adding correction or release behavior.

Tech Stack: Python 3.12, stdlib sqlite3, existing canonical JSON/SHA-256 helpers, Continuity Ed25519 verification, EventLedger, unittest.

Spec: docs/superpowers/specs/2026-08-20-c6-red-team-assessment-design.md

## Global constraints

- The signed payload has exactly the closed fields in the C6 design.
- The C5 snapshot is recomputed before admission and inside the admission transaction.
- `C6_FAIL_REMEDIATION_REQUIRED` and `C6_BLOCKED_INSUFFICIENT_EVIDENCE` always produce `BLOCK_C7`.
- Only a derived PASS may contain `PROCEED_TO_C7_FINAL_PACK`.
- Assessment, attack-case, finding, and ledger rows are immutable/append-only.
- Exact replay is idempotent; changed material, key, signature, plan, or actor is a conflict.
- Assessor and adjudicator are independent of all C5/C4 material identities.
- No automatic remediation, issue write, release, deployment, promotion, or execution path.
- Every production behavior follows a focused failing test and a focused green test.

---

### Task 1: Record the design and establish the RED surface

Files:
- Create: docs/superpowers/specs/2026-08-20-c6-red-team-assessment-design.md
- Create: docs/superpowers/plans/2026-08-20-c6-red-team-assessment.md
- Create: tests/test_red_team.py

- [x] Write a deterministic fake C5 fixture, trust-root fixture, exact payload builder, and first public-contract tests.
- [x] Run the focused test and confirm the import/constructor is RED because `starcom.red_team` does not exist.
- [x] Commit only the design and RED test surface.

### Task 2: Implement the closed parser and immutable schema

Files:
- Create: src/starcom/red_team.py
- Modify: tests/test_red_team.py

- [x] Add tests for duplicate keys, invalid UTF-8/JSON constants, missing/extra fields, invalid digests, closed nested fields, verdict contradictions, and empty attack cases.
- [x] Implement strict exact-byte JSON parsing, bounded bytes, all closed enums, sorted memberships, and optional C5 remediation work-item references.
- [x] Create immutable assessment, attack-case, and finding tables with foreign keys, unique bindings, and update/delete triggers.
- [x] Run the focused parser/schema suite green and assert rejected payloads write no C6 rows.

### Task 3: Implement C5 snapshot binding, chronology, independence, and verdict derivation

Files:
- Modify: src/starcom/red_team.py
- Modify: tests/test_red_team.py

- [x] Add failing tests for missing/dirty/stale C5, C5 payload/provenance tamper, pre-C5 assessment timestamps, assessor/adjudicator collisions, upstream identity reuse, and verdict inconsistencies.
- [x] Implement deterministic C5 snapshot reconstruction with ordered work/gate digests, provenance event/hash, latest evidence timestamp, and material identity exclusion set.
- [x] Implement the fail-first/blocked-second/pass-only verdict derivation and require the signed booleans/recommendation to match it.
- [x] Run focused C5-binding and semantic tests green.

### Task 4: Implement exact-byte admission, replay, and ledger persistence

Files:
- Modify: src/starcom/red_team.py
- Modify: tests/test_red_team.py

- [x] Add failing tests for default-deny trust root, exact signature bytes, admission, exact replay, second-assessment conflict, changed payload conflict, and admission-time chronology.
- [x] Implement `admit_assessment(plan_id, key_id, payload, signature, actor, occurred_at=None)` with outside/inside transaction revalidation.
- [x] Append `C6_RED_TEAM_ASSESSMENT_ADMITTED` to `continuity:c6:red-team:<assessment_id>` and insert the ordered attack/findings members atomically.
- [x] Run focused admission/replay tests green and assert one row/event for exact replay.

### Task 5: Implement independent reads and tamper verification

Files:
- Modify: src/starcom/red_team.py
- Modify: tests/test_red_team.py

- [x] Add failing tamper tests for payload/member digests, C5 staleness, ledger kind, and immutable rows.
- [x] Implement `get_assessment`, `get_attack_cases`, `get_findings`, and `verify_assessment` without trusting admission-time state.
- [x] Return stable, deduplicated defect codes and keep all read/verify aliases side-effect free.
- [x] Run all focused C6 tests green.

### Task 6: Wire Runtime without operational side effects

Files:
- Modify: src/starcom/cli.py
- Modify: tests/test_red_team.py

- [x] Add a failing Runtime identity/surface test.
- [x] Wire one `C6RedTeamService` after the shared C5 service and expose `Runtime.red_team` plus `Runtime.c6_red_team`.
- [x] Do not add CLI mutation commands or any automatic remediation/release/promotion behavior.
- [x] Run C6 tests and existing smoke/CLI tests.

### Task 7: Manifest, repository policy, and evidence

Files:
- Modify: MANIFEST.sha256
- Modify: docs/superpowers/plans/2026-08-20-c6-red-team-assessment.md

- [x] Regenerate `MANIFEST.sha256` and inspect only the expected paths.
- [x] Record focused RED/GREEN, real-C5 smoke, forbidden-surface scan, and final gate evidence after execution.
- [x] Run repository policy tests and `git diff --check`.

### Task 8: Final verification and integration

Files:
- Inspect all changed files and the final diff.

- [x] Run the focused C6 suite with `PYTHONHASHSEED=0 PYTHONWARNINGS=error`.
- [x] Run the deterministic repository gate: compile, complete tests, secret scan, text-style, and manifest.
- [ ] Commit only C6 paths, push one PR for issue #63, and verify CI on the exact head SHA.
- [ ] Merge only the verified SHA after CI/review checks.
- [ ] Pull merged `main`, rerun the final gate, create an archive with SHA-256, and write a French reprise report preserving the C6 truth boundary and guardrails.

## Verification evidence before integration

Evidence recorded from commands that actually ran:

- Initial RED: `ModuleNotFoundError: No module named 'starcom.red_team'` before implementation.
- Focused C6 suite: **7/7 PASS**.
- The focused C6 fixture now admits a real C5 execution-plan graph and keeps distinct C5/C6 trust-root keys; the suite remains **7/7 PASS**.
- C5 execution-plan regression suite: **6/6 PASS**.
- C4 architecture regression suites: **165/165 PASS**.
- Runtime smoke: **1/1 PASS**; repository policy: **6/6 PASS**.
- Real-C5-to-C6 smoke: **REAL_C5_C6_OK**, with C5 verification and C6 verification both true.
- Forbidden operational-surface scan: no matching method definitions in `src/starcom/red_team.py`.
- Manifest after implementation: **122 entries**, no missing, mismatched, or unlisted paths.
- Full deterministic gate: **PASS** on the implementation worktree; **457/457 tests** in 211.087 seconds.
- Compilation: **PASS**; secret scan: **0 findings**; text-style: **0 findings**; manifest: **122/122** with no mismatch, missing, or unlisted paths.
- CI exact-head run and merge SHA: pending.

## Next boundary

After C6, the next authority is C7 final-pack review. C6 must not be treated as a release approval, external red-team certification, or proof that the full product has been assessed.
