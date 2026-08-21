# Block 19 exact-byte Release Candidate assessment authority — design

## Intent

Add a signed, immutable and fail-closed authority for the integrated Block 19
Release Candidate assessment. The authority records the internal evidence
boundary for blocks 12A-LIVE through 18, structured benchmarks, red-team cases
and release gates. It derives readiness but never accepts a caller-supplied
verdict, release state or gate effect.

The authority uses the existing SQLite `Database`, append-only `EventLedger`,
`ContinuityService` and Ed25519 verifier. It does not contact a live runtime,
publish an artifact, deploy a component, promote a build or execute a job.

## Closed signed payload

The payload is strict UTF-8 JSON with exactly these top-level fields:

```text
assessment_id
assessment_version
evidence_manifest
benchmarks
red_team_cases
release_gates
live_census_certification_status
external_runtime_integration_status
component_adoption_status
real_deployment_status
assessor_identity
assessor_environment
reviewer_identity
reviewer_environment
assessed_at_utc
reviewed_at_utc
independence_basis
```

The payload deliberately has no `verdict`, `release_status` or `gate_effect`
field. Those values are derived by the service and persisted only as audited
material after derivation.

`evidence_manifest` is a sorted, unique list containing exactly these
`evidence_id` values:

```text
12A-LIVE
12B-BLUEPRINT
12C-SIMULATION
13-ARTIFACTS
14-SOFTWARE-STUDIO
15-ASSISTANT
16-CREATIVE
17-COCKPIT
18-DEPLOYMENT
```

Each entry has exactly `evidence_id`, `artifact_id`, `digest` and `status`.
`status` is `PROVEN` or `NOT_PROVEN`; an internal `NOT_PROVEN` entry is an
internal verification failure, not a release approval.

Each benchmark has exactly `benchmark_id`, `domain`, `metric`, `unit`,
`threshold`, `observed`, `direction`, `pass` and `evidence_digest`.
`direction` is `MINIMUM` or `MAXIMUM`; the service recomputes the numeric
comparison and rejects a contradictory declared boolean. Benchmark IDs are
sorted and unique.

Each red-team case has exactly `case_id`, `category`, `severity`, `outcome`
and `evidence_digest`. Each gate has exactly `gate_id`, `status` and
`evidence_digest`. Outcomes and gate statuses are closed to `PASS`, `FAIL` and
`BLOCKED`; all identifiers are sorted and unique.

The four external statuses are independently closed to `PROVEN` and
`NOT_PROVEN`:

```text
live_census_certification_status
external_runtime_integration_status
component_adoption_status
real_deployment_status
```

`independence_basis` has exactly `excluded_identities` and `statement`.
Identity lists are sorted and unique. Assessor and reviewer identities must be
distinct, and chronology must satisfy:

```text
assessed_at_utc <= reviewed_at_utc <= admitted_at
```

## Derived state and truth boundary

The service derives the following closed result:

```text
internal failure -> RC_BLOCKED_VERIFICATION_FAILURE
internal clean + any external NOT_PROVEN -> RC_BLOCKED_EXTERNAL_EVIDENCE
internal clean + all external PROVEN -> RC_READY_FOR_INDEPENDENT_RELEASE_REVIEW
release_status -> NOT_RELEASED
gate_effect -> BLOCK19_RC_ASSESSMENT_ADMITTED_NOT_RELEASED
```

Even the ready-for-independent-review result is only a review readiness
statement. It is not publication, promotion, deployment or execution
authority. Until all four external statuses are proven, the canonical state is
`RC_BLOCKED_EXTERNAL_EVIDENCE`.

## Persistence and verification

The service creates one immutable assessment table and four immutable ordered
membership tables for evidence, benchmarks, red-team cases and gates. Every
membership stores canonical material, its digest and the admission ledger
hash. Update/delete triggers protect every table.

Admission preserves the exact payload and signature bytes, verifies the
Continuity trust root and Ed25519 signature, derives all status values, appends
one `BLOCK19_RC_ASSESSMENT_ADMITTED` event to
`continuity:block19:release-candidate:<assessment_id>`, and inserts all rows in
one transaction. Exact replay returns the original record without another
event. A changed identifier, version, payload, signature, key or actor is a
conflict; a second assessment for the same version is refused.

`verify_assessment` reconstructs the payload and every membership, rechecks
digests, signature, trust root, chronology, derived verdict, immutable
provenance and the ledger chain. It returns stable defect codes and never
changes state.

The public surface is limited to preparation/snapshot, admission, reads and
verification aliases. No method named `release`, `publish`, `deploy`,
`promote` or `execute` exists on the authority.
