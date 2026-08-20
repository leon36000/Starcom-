# C5 exact-byte execution plan authority Implementation Plan

> For agentic workers: REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox ([ ]/[x]) syntax for tracking.

Goal: Admit and verify one immutable exact-byte signed C5 master plan bound to a clean C4 baseline while keeping execution explicitly NOT_STARTED.

Architecture: Add a focused C5ExecutionPlanService with its own closed payload parser, deterministic C4 snapshot binder, immutable plan/work-item/gate tables, and append-only ledger event. Wire one instance into Runtime without adding any execution path.

Tech Stack: Python 3.12, stdlib sqlite3, existing canonical JSON/SHA-256 helpers, Continuity Ed25519 verification, TrustPlane, EventLedger, unittest.

Spec: docs/superpowers/specs/2026-08-20-c5-execution-plan-design.md

## Global Constraints

- plan_version is exactly 1.0.0.
- architecture_version is exactly 3.2.0.
- execution_status is exactly NOT_STARTED.
- gate_effect is exactly C5_EXECUTION_PLAN_ADMITTED_NOT_STARTED.
- Signature verification uses exact payload bytes and an accepted Continuity trust root.
- C4 must verify cleanly inside and outside the admission transaction.
- work_items and release_gates are sorted, unique, reference-valid, and immutably stored.
- execution_policy.fail_closed, require_proof, and stop_on_verification_failure are always true.
- No method named start, run, execute, schedule, or dispatch; no network, subprocess, worker, deployment, release, or promotion side effect.
- Every production behavior is introduced after a focused failing test and is followed by a focused green test.

---

### Task 1: Record the design and establish the RED test surface

Files:
- Create: docs/superpowers/specs/2026-08-20-c5-execution-plan-design.md
- Create: docs/superpowers/plans/2026-08-20-c5-execution-plan.md
- Create: tests/test_execution_plan.py

Interfaces:
- Tests consume C5ExecutionPlanService from starcom.execution_plan.
- The fixture consumes the existing C4 service contract: get_baseline(), verify_baseline(), and snapshot().

- [x] Step 1: Write the failing test fixture and first public contract test.

  Build a temporary SQLite graph with real Database, EventLedger, TrustPlane, ContinuityService, a deterministic clean C4 service fixture, and a wished-for C5ExecutionPlanService. Add a payload builder that creates one root work item and one proof gate, then assert that snapshot(), prepare(), and the service import exist.

- [x] Step 2: Run the focused test to verify RED.

  Run:
  PYTHONPATH=src PYTHONWARNINGS=error python3 -m unittest discover -s tests -p 'test_execution_plan.py' -v

  Expected: import or constructor failure because starcom.execution_plan and C5ExecutionPlanService do not yet exist.

- [x] Step 3: Commit the design and RED test only.

  git add -- docs/superpowers/specs/2026-08-20-c5-execution-plan-design.md docs/superpowers/plans/2026-08-20-c5-execution-plan.md tests/test_execution_plan.py
  git commit -m "test(c5): define exact-byte execution plan contract"

### Task 2: Add models, closed parser, and immutable schema

Files:
- Create: src/starcom/execution_plan.py
- Modify: tests/test_execution_plan.py

Interfaces:
- Produce C5ExecutionPlanSnapshot, C5ExecutionPlanPreparation, C5ExecutionPlan, and C5ExecutionPlanVerification dataclasses.
- Produce C5ExecutionPlanService.__init__(database, ledger, *dependencies, signature_verifier=None, **named).
- Produce snapshot(architecture_id), prepare(plan_id, architecture_id, payload=None), and aliases only after the first RED cycle.

- [ ] Step 1: Add tests for constants, strict JSON, nested schemas, and table creation.

  Assert valid values parse, while duplicate keys, invalid UTF-8, JSON constants, missing/extra fields, invalid digests, wrong versions/status/effect, unsorted IDs, duplicate IDs, malformed policy, empty gates, and invalid nested field sets raise ValidationError without writing rows.

- [ ] Step 2: Run the new tests and confirm the parser/schema behavior is RED.

  Run:
  PYTHONPATH=src PYTHONWARNINGS=error python3 -m unittest discover -s tests -p 'test_execution_plan.py' -v

  Expected: failure because the parser and schema do not yet implement the contract.

- [ ] Step 3: Write the smallest parser and schema.

  Use json.loads with object_pairs_hook, strict UTF-8, canonical JSON for stored nested members, lowercase SHA-256 validation, sorted/unique list checks, closed nested field sets, and deterministic SQLite DDL with update/delete triggers for the three C5 tables.

- [ ] Step 4: Run the focused parser/schema tests.

  Run:
  PYTHONPATH=src PYTHONWARNINGS=error python3 -m unittest discover -s tests -p 'test_execution_plan.py' -v

  Expected: PASS with no warnings and no C5 rows for rejected payloads.

### Task 3: Implement C4 snapshot binding and DAG/policy/gate validation

Files:
- Modify: src/starcom/execution_plan.py
- Modify: tests/test_execution_plan.py

Interfaces:
- snapshot(architecture_id) returns a deterministic C5ExecutionPlanSnapshot containing the C4 baseline ID, architecture/version, C4 payload digest, C3 snapshot digest, C4 evidence/admission chronology, material identities, and a snapshot digest.
- Internal validation returns normalized work items, policy, gates, and derived membership digests for later admission/verification.

- [ ] Step 1: Add failing tests for C4 binding, chronology, identity independence, missing references, self-edges, and cycles.

  Mutate the clean C4 fixture and payload one invariant at a time. Assert that dirty/stale C4, a planner/reviewer collision with C4/C3 actors, a pre-C4 planned_at_utc, an unknown dependency, a self-edge, and a cycle fail closed with the documented domain exception.

- [ ] Step 2: Run the tests and confirm each failure is caused by the missing implementation.

  Run:
  PYTHONPATH=src PYTHONWARNINGS=error python3 -m unittest discover -s tests -p 'test_execution_plan.py' -v

- [ ] Step 3: Implement deterministic C4 reconstruction and validation.

  Locate the baseline by architecture ID or baseline ID, require verify_baseline().ok, compare current C4 payload/C3 digests, derive the exact excluded identity set, compare planned_at_utc against all upstream timestamps, validate every reference, and use a deterministic Kahn traversal to reject cyclic dependencies.

- [ ] Step 4: Run the focused binding/DAG tests.

  Run:
  PYTHONPATH=src PYTHONWARNINGS=error python3 -m unittest discover -s tests -p 'test_execution_plan.py' -v

### Task 4: Implement exact-byte admission, replay, and ledger persistence

Files:
- Modify: src/starcom/execution_plan.py
- Modify: tests/test_execution_plan.py

Interfaces:
- admit_plan(architecture_id, key_id, payload, signature, actor, occurred_at=None) returns C5ExecutionPlan.
- Aliases: admit_execution_plan = admit_plan, admit = admit_plan, prepare_plan = prepare.
- Exact replay returns the original record; a material or actor conflict raises ConflictError.

- [ ] Step 1: Add failing tests for default deny, exact signature bytes, admission, replay, and conflict.

  Verify no root means IntegrityError; accept a root explicitly, admit the exact bytes, replay with a different call timestamp, mutate one whitespace byte, and retry with a different payload/key/actor. Assert one plan row, one event, and unchanged bytes.

- [ ] Step 2: Run the tests RED.

  Run:
  PYTHONPATH=src PYTHONWARNINGS=error python3 -m unittest discover -s tests -p 'test_execution_plan.py' -v

- [ ] Step 3: Implement atomic admission.

  Re-parse and revalidate outside the transaction, verify the trust root and exact signature, then repeat C4 snapshot, trust-root, signature, and payload checks inside one transaction. Append C5_EXECUTION_PLAN_ADMITTED to continuity:c5:execution-plan:<plan_id>, insert the plan and ordered memberships, and map unique races to strict replay/conflict outcomes.

- [ ] Step 4: Run the focused admission tests GREEN.

  Run:
  PYTHONPATH=src PYTHONWARNINGS=error python3 -m unittest discover -s tests -p 'test_execution_plan.py' -v

### Task 5: Implement independent reads and verification hardening

Files:
- Modify: src/starcom/execution_plan.py
- Modify: tests/test_execution_plan.py

Interfaces:
- get_plan(plan_id), get_work_items(plan_id), get_release_gates(plan_id) return immutable stored values.
- verify_plan(plan_id) returns C5ExecutionPlanVerification; aliases get, verify, and verify_execution_plan are read-only.

- [ ] Step 1: Add failing tamper tests.

  Admit a clean plan, then independently tamper with payload/signature digests, C4 rows, work-item/gate rows, event kind/stream/payload/hash/timestamp, and ledger chain. Assert verify_plan() returns ok == False with stable defect codes; also assert a missing plan fails closed.

- [ ] Step 2: Run tamper tests RED.

  Run:
  PYTHONPATH=src PYTHONWARNINGS=error python3 -m unittest discover -s tests -p 'test_execution_plan.py' -v

- [ ] Step 3: Implement independent verification.

  Rebuild normalized payload/material from storage and current C4, compare all fields and digests, re-run DAG/policy/gate/identity/chronology checks, validate table memberships and ordinals, check event payload/receipt/stream/chain, and deduplicate defects without trusting the admission path.

- [ ] Step 4: Run all focused C5 tests.

  Run:
  PYTHONPATH=src PYTHONWARNINGS=error python3 -m unittest discover -s tests -p 'test_execution_plan.py' -v

### Task 6: Wire the shared Runtime without an execution surface

Files:
- Modify: src/starcom/cli.py
- Modify: tests/test_execution_plan.py

Interfaces:
- Runtime.execution_plan is the one shared C5ExecutionPlanService.
- Runtime.c5_execution_plan returns that same object.

- [ ] Step 1: Add a failing Runtime identity/surface test.

  Open Runtime(":memory:"), assert the alias identity and shared database/ledger/continuity/C4 references, and assert forbidden method names are absent from the service.

- [ ] Step 2: Run the test RED.

  Run:
  PYTHONPATH=src PYTHONWARNINGS=error python3 -m unittest discover -s tests -p 'test_execution_plan.py' -v

- [ ] Step 3: Wire the service after C4 construction and pass it through the dataclass constructor.

  Do not add CLI mutation commands or create any implicit TrustPlane authorization. Keep the existing canonical truth unchanged.

- [ ] Step 4: Run C5 tests and the existing CLI smoke tests.

  Run:
  PYTHONPATH=src PYTHONWARNINGS=error python3 -m unittest discover -s tests -p 'test_execution_plan.py' -v
  PYTHONPATH=src PYTHONWARNINGS=error python3 -m unittest discover -s tests -p 'test_smoke.py' -v

### Task 7: Regenerate repository manifest and document the integrated C5 boundary

Files:
- Modify: MANIFEST.sha256
- Modify: docs/superpowers/plans/2026-08-20-c5-execution-plan.md

- [ ] Step 1: Add/complete verification evidence in the plan.

  Record the focused RED/GREEN commands, targeted regression result, forbidden-surface scan, and the final commit/CI evidence only after those commands have actually run.

- [ ] Step 2: Run manifest generation and inspect the exact diff.

  Run:
  python3 scripts/build_manifest.py
  git diff -- MANIFEST.sha256 docs/superpowers/plans/2026-08-20-c5-execution-plan.md

- [ ] Step 3: Run repository policy tests.

  Run:
  PYTHONPATH=src PYTHONWARNINGS=error python3 -m unittest discover -s tests -p 'test_repo_policy.py' -v

### Task 8: Verify, commit, push, CI-verify, merge, and archive

Files:
- Inspect only: all changed files and git diff --check output.

- [ ] Step 1: Inspect scope and run focused verification.

  git status --short
  git diff --check
  PYTHONPATH=src PYTHONHASHSEED=0 PYTHONWARNINGS=error python3 -m unittest discover -s tests -p 'test_execution_plan.py' -v

- [ ] Step 2: Run the deterministic repository gate.

  PYTHONHASHSEED=0 PYTHONWARNINGS=error python3 scripts/verify_repo.py

  Expected: compile exit 0, all tests green, secret/text scans zero, manifest clean.

- [ ] Step 3: Commit only the C5 paths.

  git add -- src/starcom/execution_plan.py src/starcom/cli.py tests/test_execution_plan.py MANIFEST.sha256 docs/superpowers/specs/2026-08-20-c5-execution-plan-design.md docs/superpowers/plans/2026-08-20-c5-execution-plan.md
  git commit -m "feat(c5): add signed execution plan authority"

- [ ] Step 4: Push and create one PR against main.

  git push -u origin recovery/issue62-c5-execution-plan

  Create one PR for issue #62, verify its exact head SHA, wait for deterministic CI and review checks, then merge only that SHA.

- [ ] Step 5: Pull the merged main, rerun the final gate, and create source/report artifacts.

  Generate a git archive from the merged main commit, compute SHA-256, verify the C5 module/tests/plan/manifest are present, and write a French reprise report that preserves C5_EXECUTION_PLAN_ADMITTED_NOT_STARTED and all external truth guardrails.

## Verification evidence before integration

- Baseline on main@b087c58: 444/444 tests, compile/scans/style/manifest green.
- C5 focused suite: 6/6 tests PASS.
- C4 regression suite: 6/6 tests PASS.
- Repository policy suite: 6/6 tests PASS; smoke suite: 1/1 PASS.
- Full deterministic gate on commit 5a0f3fc: 450/450 tests PASS in 216.950 seconds.
- Compilation: PASS; secret scan: 0 findings; text-style: 0 findings.
- Manifest: 118 entries checked, with mismatched/missing/unlisted all empty.
- Real-C4 smoke: a signed plan was admitted and independently verified through the C4 service using the C4 c3_run_id binding.
- Remaining integration action: push, CI-verify, SHA-checked merge, and source/report archive.
