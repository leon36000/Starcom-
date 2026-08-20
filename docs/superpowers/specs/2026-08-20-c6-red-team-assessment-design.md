# C6 exact-byte red-team assessment authority — design

## Intent

Add a read/admit/verify authority for one signed C6 red-team assessment of one admitted C5 execution plan. C6 records attack cases and findings as auditable material, derives a closed verdict, and never repairs, executes, releases, deploys, promotes, or writes an external issue.

The implementation is a deterministic SQLite authority using the existing `Database`, `EventLedger`, `ContinuityService`, and `C5ExecutionPlanService` contracts. It preserves exact payload bytes and uses the accepted Continuity trust root for signature verification.

## Upstream binding

`C6RedTeamService.snapshot(plan_id)` must:

1. Load the C5 plan by `plan_id`.
2. Require `verify_plan(plan_id).ok`.
3. Recompute the SHA-256 of the stored C5 payload and compare it with the C5 record.
4. Read ordered C5 work items and release gates and compute their canonical material digests and counts.
5. Verify the C5 admission event exists on `continuity:c5:execution-plan:<plan_id>`, has kind `C5_EXECUTION_PLAN_ADMITTED`, actor/timestamp/hash matching the plan, and belongs to a clean ledger chain.
6. Bind the C5 plan ID, architecture ID, versions, payload digest, work/gate counts and digests, provenance event/hash, and the latest C5 evidence timestamp.
7. Derive the material identity exclusion set from C5 upstream exclusions plus the planner, reviewer, and C5 admission actor.

The resulting material is hashed with canonical JSON into `c5_snapshot_digest`. Missing, dirty, stale, malformed, or contradictory C5 material raises `IntegrityError` and cannot be admitted.

## Closed signed payload

The top-level payload has exactly these fields:

```text
assessment_id
plan_id
architecture_id
plan_payload_sha256
c5_snapshot_digest
threat_model_digest
attack_cases
findings
verdict
remediation_required
release_recommendation
assessor_identity
assessor_environment
adjudicator_identity
adjudicator_environment
assessed_at_utc
independence_basis
gate_effect
```

The exact constants are:

```text
C6_PASS_NO_BLOCKING_FINDINGS
C6_FAIL_REMEDIATION_REQUIRED
C6_BLOCKED_INSUFFICIENT_EVIDENCE
PROCEED_TO_C7_FINAL_PACK
BLOCK_C7
C6_RED_TEAM_ASSESSMENT_ADMITTED_NO_RELEASE
```

`attack_cases` is a non-empty list sorted by unique `attack_case_id`. Each item has exactly:

```text
attack_case_id, category, target, method, invariant_expected,
evidence_digest, outcome
```

Categories are closed to `AUTHORITY`, `INTEGRITY`, `PROVENANCE`, `DEPENDENCY`, `BOUNDARY`, and `RECOVERY`. Outcomes are `PASS`, `FAIL`, or `BLOCKED`.

`findings` is a list sorted by unique `finding_id`. Each item has exactly:

```text
finding_id, attack_case_id, severity, title, description_digest,
evidence_digest, status, remediation_work_item_id
```

`remediation_work_item_id` is either JSON `null` or an existing C5 work-item ID. Severities are `INFO`, `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL`; statuses are `OPEN`, `REMEDIATED`, and `ACCEPTED_RISK`.

The independence object has exactly `excluded_identities` (sorted unique strings) and `statement` (non-empty string). The assessor and adjudicator must be distinct, neither may be in the C5 material identity set, and the signed exclusion list must equal the derived upstream set.

## Derived verdict

The service accepts only a payload whose declared outcome matches the derived outcome:

- Any attack `FAIL` or any `HIGH`/`CRITICAL` finding with status `OPEN` derives `C6_FAIL_REMEDIATION_REQUIRED`, sets `remediation_required=true`, and requires `BLOCK_C7`.
- If no failure exists but any attack is `BLOCKED`, the result derives `C6_BLOCKED_INSUFFICIENT_EVIDENCE`, sets `remediation_required=false`, and requires `BLOCK_C7`.
- Otherwise every attack must be `PASS`, the result derives `C6_PASS_NO_BLOCKING_FINDINGS`, sets `remediation_required=false`, and alone permits `PROCEED_TO_C7_FINAL_PACK`.

The failure branch takes precedence over blocked evidence when both are present, so a known failing invariant cannot be hidden by an insufficient-evidence case.

`assessed_at_utc` must be strictly after the latest C5 evidence timestamp. Admission time must be at or after the signed assessment time.

## Persistence and provenance

The service creates three immutable tables:

- `c6_red_team_assessments`, unique by `assessment_id`, `plan_id`, and payload digest;
- `c6_red_team_attack_cases`, ordered and unique within an assessment;
- `c6_red_team_findings`, ordered and unique within an assessment.

Update/delete triggers protect all three tables. Admission appends exactly one event to `continuity:c6:red-team:<assessment_id>` with kind `C6_RED_TEAM_ASSESSMENT_ADMITTED`, inserts the assessment and ordered members in one transaction, and rechecks the C5 snapshot, trust root, exact signature, and payload bindings inside that transaction.

An exact replay returns the original record without another event. A different assessment for the same C5 plan, changed bytes, signature, key, or actor is a material conflict.

## Independent verification

`verify_assessment(assessment_id)` reconstructs the signed payload, recomputes all digests and derived semantics, rechecks the current C5 snapshot, verifies the Continuity signature, validates immutable member rows, checks the ledger event and chain, and returns stable defect codes rather than trusting the admission path. Any C5 evolution or tamper makes the C6 result stale or invalid.

The service exposes read-only aliases (`get`, `verify`, and `verify_red_team_assessment`) only. It has no `start`, `run`, `execute`, `schedule`, `dispatch`, `repair`, `release`, `deploy`, `promote`, or `publish` method.

## Truth boundary

Fixtures prove the mechanism with deterministic evidence. A passing C6 assessment is not an external red-team engagement for the whole product and does not authorize a C7 final pack or release by itself.
