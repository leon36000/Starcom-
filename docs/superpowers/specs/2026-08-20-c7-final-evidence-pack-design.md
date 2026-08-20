# C7 exact-byte final evidence pack authority — design

## Intent

Add a read/admit/verify authority for one signed C7 final evidence pack assembled from a clean C4 architecture baseline, a clean C5 execution plan, and a clean C6 red-team assessment. The pack freezes hashed evidence and provenance, is immutable and independently verifiable, and is never published, released, deployed, promoted, or executed.

The implementation uses the existing SQLite `Database`, append-only `EventLedger`, `ContinuityService`, C4 architecture authority, C5 execution-plan authority, and C6 red-team authority. It preserves the exact signed payload bytes and makes every upstream snapshot binding explicit.

## Upstream admission boundary

`C7FinalPackService.snapshot(assessment_id)` must:

1. Load the C6 assessment and require `verify_assessment(assessment_id).ok`.
2. Require the C6 verdict `C6_PASS_NO_BLOCKING_FINDINGS`, recommendation `PROCEED_TO_C7_FINAL_PACK`, and gate effect `C6_RED_TEAM_ASSESSMENT_ADMITTED_NO_RELEASE`.
3. Recompute the C6 snapshot for its C5 plan and require the stored assessment to bind the current C5 payload and snapshot digest.
4. Load the C5 plan, require `verify_plan(plan_id).ok`, and recompute its C4-bound snapshot.
5. Load the C4 baseline referenced by the C5 plan, require `verify_baseline(baseline_id).ok`, and recompute the current C4 snapshot.
6. Require C4/C5 architecture, version, payload, C3 snapshot, and C4 snapshot bindings to agree.
7. Derive a C6 snapshot digest from the exact C6 assessment identifiers, payload digest, verdict, timestamps, provenance, and current C5 snapshot.
8. Derive a provenance digest from the C4 payload/snapshot and C5/C6 ledger heads.
9. Derive `chain_snapshot_digest` from the complete C4/C5/C6 identity, digest, provenance, evidence-time, and material-identity boundary.
10. Set `latest_evidence_at` to the maximum timestamp across C4, C5, C6 assessment, and C6 admission evidence. Signed packaging must occur strictly after this timestamp.
11. Derive a sorted material-identity exclusion set from C4/C5/C6 upstream identities, C6 assessor/adjudicator, and the C6 admission actor.

Missing, dirty, stale, malformed, contradictory, or non-PASS upstream material raises `IntegrityError` and cannot be admitted.

## Closed signed payload

The top-level payload has exactly these fields:

```text
pack_id
pack_version
baseline_id
architecture_id
architecture_version
architecture_payload_sha256
c4_snapshot_digest
plan_id
plan_version
plan_payload_sha256
c5_snapshot_digest
assessment_id
assessment_payload_sha256
c6_snapshot_digest
c3_snapshot_digest
chain_snapshot_digest
evidence_manifest
sbom_digest
test_report_digest
security_report_digest
provenance_digest
reproducibility_digest
rollback_evidence_digest
packager_identity
packager_environment
verifier_identity
verifier_environment
packaged_at_utc
independence_basis
release_status
external_runtime_integration_status
live_census_certification_status
gate_effect
```

The exact fixed values are:

```text
pack_version = 1.0.0
release_status = NOT_RELEASED
external_runtime_integration_status = NOT_PROVEN
live_census_certification_status = NOT_PROVEN
gate_effect = C7_FINAL_PACK_ADMITTED_NOT_RELEASED
```

`evidence_manifest` is a non-empty sorted list with unique `artifact_id`. Every item has exactly:

```text
artifact_id
artifact_kind
source_phase
digest
media_type
required
```

The closed mandatory artifact kinds are:

```text
C4_ARCHITECTURE_BASELINE
C5_EXECUTION_PLAN
C6_RED_TEAM_ASSESSMENT
TEST_REPORT
SECURITY_REPORT
SBOM
PROVENANCE
REPRODUCIBILITY
ROLLBACK_EVIDENCE
```

Each mandatory kind occurs exactly once, has `required = true`, and binds to the corresponding top-level digest. The C4/C5/C6 entries bind to the architecture, plan, and assessment payload digests; the remaining entries bind to `test_report_digest`, `security_report_digest`, `sbom_digest`, `provenance_digest`, `reproducibility_digest`, and `rollback_evidence_digest`. `source_phase` is closed to `C4`, `C5`, `C6`, and `C7`; `media_type` is a non-empty text value.

`independence_basis` has exactly `excluded_identities` and `statement`. The list is sorted and unique and must equal the derived upstream identity boundary. Packager and verifier must be distinct and neither may be in that boundary.

## Persistence and provenance

The service creates two immutable tables:

- `c7_final_packs`, unique by `pack_id`, C6 `assessment_id`, and exact payload digest;
- `c7_final_pack_manifest`, ordered and unique within a pack by `artifact_id` and `artifact_kind`.

Update/delete triggers protect both tables. Admission appends exactly one `C7_FINAL_PACK_ADMITTED` event to `continuity:c7:final-pack:<pack_id>` and inserts the pack plus ordered manifest rows atomically. It rechecks the complete C4/C5/C6 snapshot, C6 PASS authority, trust root, exact signature, manifest bindings, and chronology inside the transaction.

An exact replay returns the original pack without another ledger event. A second pack for the same C6 assessment, changed bytes, key, signature, plan, assessment, or actor is a conflict.

## Independent verification and Runtime boundary

`verify_pack(pack_id)` reconstructs the exact signed payload from the stored row, recomputes the upstream chain snapshot, revalidates C4/C5/C6, verifies the Continuity signature, checks immutable manifest rows, checks event and ledger-chain provenance, validates all fixed non-release statuses, and returns stable deduplicated defect codes. Any upstream evolution makes the pack stale.

The service exposes only `snapshot`, `prepare`, `admit_pack`, `get_pack`, `get_manifest`, and `verify_pack` (plus read/verify aliases). It has no method named or behaving as release, publish, deploy, execute, promote, or equivalent. Runtime exposes one shared `C7FinalPackService` through `final_pack` and `c7_final_pack` without CLI mutation commands.

## Truth boundary

The admitted result is `C7_FINAL_PACK_ADMITTED_NOT_RELEASED`. Deterministic evidence fixtures prove the mechanism and exact bindings; they do not certify a live census, external runtime integration, component adoption, a complete product release candidate, or production release authorization.
