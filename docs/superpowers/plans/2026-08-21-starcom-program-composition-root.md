# STARCOM unified composition root and cross-block verifier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an explicit `StarcomProgram` that composes the complete current STARCOM authority graph from one shared database and proves its internal integrity without external effects.

**Architecture:** Move the constructor sequence currently embedded in `cli.Runtime.open` into `src/starcom/program.py`. Use a closed, explicit registry of stable authority IDs, dependency names, module/class metadata, and factories; keep `Runtime` as a compatibility alias so the CLI does not own a second composition graph. Add a read-only verifier that checks the fixed SQLite schema inventory, foreign keys, catalog/dependency resolution, shared-object identity, ledger integrity, forbidden root surface, and canonical blocked truth.

**Tech Stack:** Python 3 standard library, `dataclasses`, `types.MappingProxyType`, SQLite through the existing `Database`, existing STARCOM services, `unittest`, deterministic repository scripts.

**Spec:** `docs/superpowers/specs/2026-08-21-starcom-program-composition-root-design.md`

## Global Constraints

- Preserve the canonical truth boundary: `RC_BLOCKED_EXTERNAL_EVIDENCE`, `NOT_RELEASED`, and all four external statuses remain `NOT_PROVEN`.
- Use exactly one `Database`, `EventLedger`, `TrustPlane`, `ContinuityService`, and `DurableOutbox` per `StarcomProgram`.
- Composition is explicit and deterministic; no plugin discovery, network, subprocess, worker, adoption, deployment, publication, promotion, or release effect is allowed.
- Missing mandatory dependencies fail closed with `ValidationError` and structured authority/dependency details.
- Work in `/home/pc1/.local/share/forgeai-controller/worktrees/starcom-issue70-composition-root` on `recovery/issue70-composition-root`; never write implementation changes on `main`.
- Follow RED → GREEN → REFACTOR and run `PYTHONPATH=src:. python3 scripts/verify_repo.py` before publication.
- Never commit credentials, private keys, `.env` files, local databases, model weights, or unredacted user data.

---

### Task 1: Add the failing composition-root contract tests

**Files:**
- Create: `tests/test_program.py`
- Read: `src/starcom/cli.py`, `src/starcom/errors.py`, `docs/superpowers/specs/2026-08-21-starcom-program-composition-root-design.md`

**Interfaces:**
- Consumes: the not-yet-existing `starcom.program.StarcomProgram`, `AuthorityDescriptor`, `ProgramTruth`, and `ProgramVerification` names.
- Produces: the executable RED contract for the new root; no production code changes in this task.

- [ ] **Step 1: Write the failing construction and catalog tests**

Create a `unittest.TestCase` that opens `StarcomProgram` on a temporary SQLite path and asserts the following exact public behavior:

~~~python
program = StarcomProgram.open(self.db_path)
self.addCleanup(program.close)
self.assertEqual(program.database.path, str(self.db_path))
self.assertEqual(
    [entry.name for entry in program.catalog],
    sorted(entry.name for entry in program.catalog),
)
self.assertEqual(len({entry.name for entry in program.catalog}), len(program.catalog))
self.assertIs(program.authority("c7.final_pack"), program.final_pack)
self.assertTrue(program.verify().ok, program.verify().defects)
~~~

Assert that the catalog contains these stable IDs and expected implementation classes:

~~~text
core.proof -> starcom.proof.ProofEngine
core.missions -> starcom.mission.MissionKernel
core.research -> starcom.research.ResearchCampaign
c1.continuity -> starcom.continuity.ContinuityService
c2.recollection -> starcom.recollection.C2RecollectionService
c2.census -> starcom.census.C2CensusService
c2.certification -> starcom.certification.C2CertificationService
c3.qualification -> starcom.qualification.QualificationLab
c3.gate -> starcom.qualification_gate.C3QualificationGate
c3.decision -> starcom.qualification_decision.C3DecisionService
c3.adoption -> starcom.adoption.C3AdoptionService
c3.execution -> starcom.adoption_execution.C3AdoptionExecutionService
c3.executor_registry -> starcom.executor_registry.C3ExecutorRegistry
c4.input -> starcom.architecture_input.C4ArchitectureInputService
c4.candidate -> starcom.architecture_candidate.C4ArchitectureCandidateService
c4.review -> starcom.architecture_review.C4ArchitectureReviewService
c4.publication -> starcom.architecture_publication.C4ArchitecturePublicationService
c4.architecture -> starcom.architecture.C4ArchitectureService
c5.execution_plan -> starcom.execution_plan.C5ExecutionPlanService
c6.red_team -> starcom.red_team.C6RedTeamService
c7.final_pack -> starcom.final_pack.C7FinalPackService
12a.research_marathon -> starcom.research_marathon.ResearchMarathonService
16.creative_jobs -> starcom.creative.CreativeJobService
17.cockpit -> starcom.cockpit.CockpitService
18.deployment -> starcom.deployment.DeploymentFabricService
19.release_candidate -> starcom.release_candidate.ReleaseCandidateService
~~~

Assert each descriptor exposes a tuple of dependency names and each dependency resolves through the program component map. Assert the five shared objects are present exactly once by identity:

~~~python
shared = {
    "database": program.database,
    "ledger": program.ledger,
    "trust": program.trust,
    "continuity": program.continuity,
    "outbox": program.outbox,
}
for entry in program.catalog:
    authority = program.authority(entry.name)
    for field, expected in shared.items():
        if hasattr(authority, field):
            self.assertIs(getattr(authority, field), expected, (entry.name, field))
~~~

- [ ] **Step 2: Add fail-closed dependency, lifecycle, and compatibility tests**

Add tests that assert:

~~~python
with self.assertRaises(ValidationError) as raised:
    StarcomProgram._resolve_dependencies(
        "c4.input", ("database", "missing.required"), {"database": object()}
    )
self.assertEqual(raised.exception.code, "VALIDATION_ERROR")
self.assertEqual(raised.exception.details["authority"], "c4.input")
self.assertEqual(
    raised.exception.details["missing_dependencies"], ["missing.required"]
)
~~~

Open the same file twice sequentially, record the table names and ledger row count after the first open, close it, reopen it, and assert the catalog, table names, and ledger count are identical. Assert `close()` can be called twice without raising.

Import `Runtime` from `starcom.cli`, open it on a temporary path, and assert it exposes the existing `runtime.c3`, `runtime.architecture_baseline`, `runtime.c5_execution_plan`, `runtime.c6_red_team`, `runtime.c7_final_pack`, `runtime.creative`, and `runtime.rc_assessment` aliases.

- [ ] **Step 3: Add verifier defect and safety tests**

Cover the fixed checks with isolated temporary programs:

~~~python
verification = program.verify()
self.assertIsInstance(verification, ProgramVerification)
self.assertEqual(verification.truth, ProgramTruth())
self.assertTrue(verification.foreign_keys_ok)
self.assertTrue(verification.schema_ok)
self.assertTrue(verification.catalog_ok)
self.assertTrue(verification.dependencies_ok)
self.assertTrue(verification.ledger_ok)
self.assertTrue(verification.surfaces_ok)
self.assertTrue(verification.canonical_truth_ok)
self.assertTrue(
    set(("run", "execute", "deploy", "release", "publish", "promote"))
    .isdisjoint(dir(program))
)
~~~

Drop `cockpit_snapshots` in a temporary in-memory program and assert `SCHEMA_TABLE_MISSING:cockpit_snapshots` appears in defects. Create a table named `unexpected_program_table` and assert `SCHEMA_TABLE_UNEXPECTED:unexpected_program_table` appears. Replace one authority's `.database` attribute with a distinct `Database` object and assert a shared-identity defect. Patch `socket.socket`, `subprocess.run`, and `subprocess.Popen` around `StarcomProgram.open(":memory:")` and assert none is called.

- [ ] **Step 4: Run the RED tests**

Run:

~~~bash
PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test_program.py' -v
~~~

Expected result: collection or test failures because `starcom.program` and `StarcomProgram` do not exist yet. Do not weaken the tests to make this initial run pass.

- [ ] **Step 5: Commit the RED contract**

~~~bash
git add tests/test_program.py
git commit -m "test: define unified Starcom composition contract"
~~~

### Task 2: Implement the explicit program model and deterministic construction graph

**Files:**
- Create: `src/starcom/program.py`
- Modify: `src/starcom/__init__.py`
- Test: `tests/test_program.py`

**Interfaces:**
- Consumes: all existing authority constructors and `Database`, `EventLedger`, `TrustPlane`, `ContinuityService`, and `DurableOutbox`.
- Produces: `AuthorityDescriptor`, `ProgramTruth`, `ProgramVerification`, and `StarcomProgram.open`, `.authority`, `.catalog`, `.verify`, and `.close`.

- [ ] **Step 1: Define immutable result and descriptor types**

Add these frozen dataclasses with the exact fields needed by the tests and verifier:

~~~python
@dataclass(frozen=True)
class AuthorityDescriptor:
    name: str
    module: str
    class_name: str
    attribute: str
    dependencies: tuple[str, ...]

@dataclass(frozen=True)
class ProgramTruth:
    project_state: str = "RC_BLOCKED_EXTERNAL_EVIDENCE"
    release_status: str = "NOT_RELEASED"
    live_census_certification_status: str = "NOT_PROVEN"
    external_runtime_integration_status: str = "NOT_PROVEN"
    component_adoption_status: str = "NOT_PROVEN"
    real_deployment_status: str = "NOT_PROVEN"

@dataclass(frozen=True)
class ProgramVerification:
    defects: tuple[str, ...]
    foreign_keys_ok: bool
    schema_ok: bool
    catalog_ok: bool
    dependencies_ok: bool
    ledger_ok: bool
    surfaces_ok: bool
    canonical_truth_ok: bool
    checked_tables: tuple[str, ...]
    checked_streams: int
    truth: ProgramTruth

    @property
    def ok(self) -> bool:
        return not self.defects
~~~

Keep result values immutable and sort every defect, table, stream, and catalog output before returning it.

- [ ] **Step 2: Encode the closed descriptor registry and construction order**

Define a module-level tuple of descriptors for the 26 authorities listed in Task 1. Use the exact IDs from the list, actual `__module__` strings, attribute names, and these dependencies:

~~~text
core.proof: database, ledger
core.missions: database, ledger, trust, proof
core.research: database, ledger
c1.continuity: database, ledger, trust
c2.recollection: database, ledger, continuity, research
c2.census: database, ledger, recollection, research
c2.certification: database, ledger, continuity, recollection, census
c3.qualification: database, ledger
c3.gate: database, ledger, certification, qualification
c3.decision: database, ledger, continuity, certification, c3, qualification
c3.adoption: database, ledger, trust, continuity, c3_decision, qualification
c3.execution: database, ledger, trust, continuity, adoption, outbox
c3.executor_registry: database, ledger, trust, continuity
c4.input: database, ledger, trust, continuity, adoption_execution
c4.candidate: database, ledger, trust, continuity, architecture_input
c4.review: database, ledger, trust, continuity, architecture_input, architecture_candidate
c4.publication: database, ledger, trust, continuity, architecture_input, architecture_candidate, architecture_review
c4.architecture: database, ledger, trust, continuity, c3_decision, adoption, adoption_execution
c5.execution_plan: database, ledger, trust, continuity, architecture
c6.red_team: database, ledger, trust, continuity, execution_plan
c7.final_pack: database, ledger, trust, continuity, architecture, execution_plan, red_team
12a.research_marathon: database, ledger, trust, continuity, final_pack, research, outbox
16.creative_jobs: database, ledger, trust, outbox
17.cockpit: database, ledger, trust
18.deployment: database, ledger, trust, continuity
19.release_candidate: database, ledger, trust, continuity
~~~

Construct prerequisites in the same topological order, with the shared `outbox` created once between C3 adoption authorization and C3 execution. Use named local variables or a component mapping; do not use reflection to infer constructors. Keep the current `cli.Runtime.open` constructor arguments equivalent, including the optional signature verifier passed to `ContinuityService`.

- [ ] **Step 3: Implement fail-closed dependency resolution**

Implement the tested helper with a stable signature:

~~~python
@staticmethod
def _resolve_dependencies(
    authority: str,
    dependency_names: tuple[str, ...],
    components: Mapping[str, object],
) -> tuple[object, ...]:
    ...
~~~

It must reject duplicate dependency names, collect all missing names in sorted order, and raise:

~~~python
ValidationError(
    "mandatory authority dependency is unknown",
    {"authority": authority, "missing_dependencies": missing},
)
~~~

Factories must call this helper before constructing each authority so an unknown dependency cannot be silently replaced.

- [ ] **Step 4: Implement `StarcomProgram.open`, `authority`, and `close`**

Make `StarcomProgram` own the existing Runtime fields and aliases. `open(path, signature_verifier=None)` must initialize `Database`, call `database.initialize()`, construct the graph, and close the database before re-raising if any constructor fails. Store the component mapping behind `MappingProxyType`; expose `catalog` as the sorted descriptor tuple. `authority(name)` accepts canonical IDs and the existing attribute-name aliases, returning a service or raising `NotFoundError` with the requested name.

Make `close()` idempotent with a private closed flag. Do not add any root method named `run`, `execute`, `deploy`, `release`, `publish`, or `promote`.

- [ ] **Step 5: Export the root without changing package truth**

Update `src/starcom/__init__.py` only to expose `StarcomProgram` alongside `__version__`:

~~~python
__all__ = ["__version__", "StarcomProgram"]
~~~

Do not change the version or canonical status strings.

- [ ] **Step 6: Run the construction tests GREEN**

Run:

~~~bash
PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test_program.py' -v
~~~

Expected result: all construction, catalog, identity, dependency, lifecycle, safety, and compatibility tests pass.

- [ ] **Step 7: Commit the construction root**

~~~bash
git add src/starcom/program.py src/starcom/__init__.py tests/test_program.py
git commit -m "feat: add deterministic Starcom composition root"
~~~

### Task 3: Replace the duplicated CLI runtime graph with the program root

**Files:**
- Modify: `src/starcom/cli.py:1-305`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_smoke.py`

**Interfaces:**
- Consumes: `StarcomProgram` and its existing authority attributes/properties.
- Produces: one composition implementation for both library callers and CLI handlers.

- [ ] **Step 1: Remove the duplicate Runtime dataclass and constructor sequence**

Remove the service imports used only by the old `Runtime` dataclass, import `StarcomProgram`, and define the compatibility name before the handler annotations:

~~~python
from .program import StarcomProgram

Runtime = StarcomProgram
Handler = Callable[["Runtime", argparse.Namespace], tuple[Any, int]]
~~~

Keep imports that CLI handlers still use directly, including command payload types and `MissionState`. Do not change handler function names, parser commands, JSON output, exit codes, or the `runtime.close()` `finally` block.

- [ ] **Step 2: Run CLI and smoke regression tests**

Run:

~~~bash
PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test_cli.py' -v
PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test_smoke.py' -v
~~~

Expected result: all existing CLI commands continue to create the same database schemas and return the same JSON behavior, while `Runtime.open` resolves to `StarcomProgram.open`.

- [ ] **Step 3: Commit the compatibility migration**

~~~bash
git add src/starcom/cli.py tests/test_cli.py tests/test_smoke.py
git commit -m "refactor: route CLI through StarcomProgram"
~~~

### Task 4: Implement and harden the cross-block verifier

**Files:**
- Modify: `src/starcom/program.py`
- Modify: `tests/test_program.py`

**Interfaces:**
- Consumes: the live program component map, `EventLedger.verify`, SQLite read-only metadata, and the fixed `ProgramTruth` values.
- Produces: deterministic `ProgramVerification` from `StarcomProgram.verify()`.

- [ ] **Step 1: Add the fixed schema inventory**

Define one sorted tuple containing exactly these non-internal tables created by the current complete graph:

~~~text
block19_rc_assessments, block19_rc_benchmarks, block19_rc_evidence,
block19_rc_gates, block19_rc_red_team_cases,
c2_census_identities, c2_certification_members, c2_certifications,
c2_recollections,
c3_adoption_execution_requests, c3_adoption_execution_transitions,
c3_adoptions, c3_decision_evidence, c3_decisions,
c3_executor_descriptors, c3_executor_qualifications,
c3_executor_qualifier_roots, c3_executor_transitions,
c3_qualification_bindings,
c4_architecture_baseline_members, c4_architecture_baselines,
c4_architecture_candidates, c4_architecture_input_members,
c4_architecture_input_sets, c4_architecture_publications,
c4_architecture_review_findings, c4_architecture_reviewer_roots,
c4_architecture_reviews,
c5_execution_plan_release_gates, c5_execution_plan_work_items,
c5_execution_plans,
c6_red_team_assessments, c6_red_team_attack_cases,
c6_red_team_findings,
c7_final_pack_manifest, c7_final_packs,
cockpit_command_transitions, cockpit_commands, cockpit_sessions,
cockpit_snapshots,
continuity_authorization_consumptions, continuity_incidents,
continuity_recovery_publications, continuity_reviews,
continuity_trust_roots,
creative_job_inputs, creative_job_transitions, creative_jobs,
deployment_assignments, deployment_bundles, deployment_nodes,
durable_effects, ledger_events, mission_transitions, missions,
proof_certificates, proof_claims, proof_evidence, proof_verifications,
qualification_artifacts, qualification_runs,
research_attempts, research_campaigns, research_cursors,
research_marathon_completions, research_marathon_partition_attempts,
research_marathon_partitions, research_marathon_profiles,
research_marathon_transitions, research_marathons,
research_observations, research_receipts,
schema_meta, trust_decisions, trust_grants, trust_policy_rules
~~~

Query `sqlite_master` with `type = 'table'` and exclude names beginning with `sqlite_`. Compare sets, emit `SCHEMA_TABLE_MISSING:table_name` and `SCHEMA_TABLE_UNEXPECTED:table_name` using the concrete table name, and keep `checked_tables` sorted.

- [ ] **Step 2: Add read-only SQLite and ledger checks**

In `verify()` read `PRAGMA foreign_keys`, `PRAGMA foreign_key_check`, and `EventLedger.verify()`. Emit stable defects `FOREIGN_KEYS_DISABLED`, `FOREIGN_KEY_VIOLATION:table:rowid:parent` with the concrete SQLite values, and `LEDGER_INVALID:ledger_defect_code` for each reported ledger defect. Do not call `initialize`, insert, update, delete, or any authority admission method. Record `checked_streams` from the ledger verification result.

- [ ] **Step 3: Add catalog, dependency, shared-identity, surface, and truth checks**

Compare every descriptor to the actual instance type (`__module__`, `__name__`) and its canonical attribute. Validate sorted/unique descriptor IDs and every dependency name. For every known shared field present on an authority, compare object identity to the root's shared component. Emit defects with the authority ID and field, for example `SHARED_INSTANCE_MISMATCH:c3.execution:outbox`.

Check only `dir(self)` for forbidden root operation names and emit `FORBIDDEN_ROOT_SURFACE:operation_name` using the concrete operation name. Build `ProgramTruth()` on every verification and compare it to the fixed expected value; emit `CANONICAL_TRUTH_MISMATCH` if any value differs. Return all defects sorted and set each boolean to the absence of defects for that category.

- [ ] **Step 4: Run verifier mutation tests and refactor**

Run:

~~~bash
PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test_program.py' -v
python3 -m compileall -q src/starcom/program.py tests/test_program.py
~~~

Expected result: all clean and mutated verifier cases pass, with no subprocess or network calls during composition. Refactor only after the RED/GREEN assertions pass, preserving stable defect codes and exact API names.

- [ ] **Step 5: Commit the verifier**

~~~bash
git add src/starcom/program.py tests/test_program.py
git commit -m "feat: add cross-block program verifier"
~~~

### Task 5: Run repository-wide verification and prepare evidence

**Files:**
- Modify: `MANIFEST.sha256` only through `scripts/build_manifest.py --write` after all source changes are complete.
- Read: `AGENTS.md`, `CONTRIBUTING.md`, `scripts/verify_repo.py`, workflow definitions under `.github/workflows/`.

**Interfaces:**
- Consumes: the complete issue #70 implementation on `recovery/issue70-composition-root`.
- Produces: fresh deterministic local evidence suitable for a PR and CI gate.

- [ ] **Step 1: Run focused and compatibility tests**

~~~bash
PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test_program.py' -v
PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test_cli.py' -v
PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test_smoke.py' -v
python3 -W error -m unittest discover -s tests -p 'test_program.py' -v
~~~

Expected result: zero failures and zero warnings promoted to errors.

- [ ] **Step 2: Run the full suite and compilation**

~~~bash
PYTHONPATH=src:. python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests scripts
~~~

Expected result: the full suite remains green with the baseline count or a documented increase from the new tests; compilation exits 0.

- [ ] **Step 3: Refresh and verify the manifest**

~~~bash
PYTHONPATH=src:. python3 scripts/build_manifest.py --write
PYTHONPATH=src:. python3 scripts/verify_repo.py
git diff --check
~~~

Expected result: manifest, repository policy, text style, secret scan, and verifier steps all pass. Inspect the manifest diff to ensure it contains only intended source/spec/test files and no local database or secret.

- [ ] **Step 4: Run deterministic hash-seed checks**

~~~bash
for seed in 0 1 42; do
  PYTHONHASHSEED="$seed" PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test_program.py' -q
  PYTHONHASHSEED="$seed" PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test_cli.py' -q
done
~~~

Expected result: every seed exits 0 and produces no order-dependent failure.

- [ ] **Step 5: Commit the final local evidence changes**

~~~bash
git add MANIFEST.sha256 docs/superpowers/plans/2026-08-21-starcom-program-composition-root.md
git commit -m "chore: refresh issue 70 evidence manifest"
git status --short --branch
~~~

Expected result: only the intended branch commits are present and the worktree is clean.

### Task 6: Publish, verify independent gates, and merge

**Files:**
- No further source edits unless a fresh test, CI, review, or Sonar finding identifies a concrete defect.

**Interfaces:**
- Consumes: the clean issue #70 branch and local evidence from Task 5.
- Produces: merged PR, closed issue #70, and a post-merge verification receipt.

- [ ] **Step 1: Push the branch and open the PR**

~~~bash
git push -u origin recovery/issue70-composition-root
git rev-parse HEAD
~~~

Create a PR targeting `main` with title `feat: add unified Starcom composition root (#70)`, link `Closes #70`, state the internal-only truth boundary, and include the local test/manifest evidence. Record the PR number and exact head SHA.

- [ ] **Step 2: Poll CI and review/Sonar evidence**

Use the GitHub connector to fetch the PR, its workflow runs, and comments. Wait in bounded intervals until required CI checks complete. A failed check must be diagnosed locally and corrected on the branch; never merge on a pending or failed required gate. Confirm Sonar Quality Gate is green and inspect new-code issues/duplication before merge.

- [ ] **Step 3: Merge with the expected head SHA**

After CI, review, and Sonar gates are green, merge with:

~~~text
repository_full_name = leon36000/Starcom-
merge_method = merge
expected_head_sha = the exact recorded PR head SHA
~~~

Use the GitHub merge connector and record the merge commit SHA. If GitHub rejects the expected SHA because the branch moved, refetch the PR and revalidate all gates before retrying.

- [ ] **Step 4: Close the issue only after the merged PR is verified**

Fetch the merged PR and issue #70. Confirm `merged=true`, base `main`, and the merge commit is reachable from remote main. The PR body's `Closes #70` should close it automatically; if not, update the issue to `closed` with reason `completed` and a link to the merge commit.

- [ ] **Step 5: Update canonical main and run post-merge verification**

~~~bash
git -C /home/pc1/STARCOM fetch origin main
git -C /home/pc1/STARCOM merge --ff-only origin/main
git -C /home/pc1/STARCOM status --short --branch
PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test_program.py' -q
PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test_cli.py' -q
PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test_smoke.py' -q
PYTHONPATH=src:. python3 scripts/verify_repo.py
~~~

Expected result: canonical `/home/pc1/STARCOM` is clean and aligned with `origin/main`, the new focused/compatibility tests pass, and the repository verifier is green. Package the exact post-merge SHA, test counts, CI URL, Sonar URL, and manifest hash into the final handoff.
