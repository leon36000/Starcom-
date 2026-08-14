# C3 adoption authorization without execution

**Date:** 2026-08-14
**Issue:** #42
**Status:** implementation-ready

## Purpose

A clean signed C3 decision may select a candidate, but selection is not adoption. STARCOM therefore needs a separate sovereign authority that records explicit owner intent while still prohibiting installation, enablement, deployment, execution, or external integration.

This design introduces one immutable state only:

```text
C3_ADOPTION_AUTHORIZED_NOT_EXECUTED
```

A later and separately authorized execution protocol will be required before any component can become active.

## Chosen approach

The adoption authority is a dedicated `C3AdoptionService` rather than a generic qualification `ADOPTION` artifact.

A generic artifact is unsuitable because it does not independently prove:

- the selected signed C3 decision is still clean;
- the exact selected candidate and material digest;
- the human or service identity authorizing the action;
- a TrustPlane decision scoped to the exact adoption material;
- a mandatory rollback plan;
- one-time authorization consumption;
- immutable authorization provenance;
- explicit non-execution.

The new service prepares an exact TrustPlane request, admits one immutable authorization receipt, and independently verifies it. It contains no execution method.

## Public contracts

### `C3AdoptionStatus`

A closed enum with exactly:

- `AUTHORIZED_NOT_EXECUTED = "C3_ADOPTION_AUTHORIZED_NOT_EXECUTED"`

### `C3AdoptionPreparation`

A deterministic read model containing:

- `c3_run_id`;
- signed `c3_decision_id`;
- selected `candidate_artifact_id`;
- selected candidate `material_sha256`;
- signed decision `payload_sha256`;
- signed decision `qualification_head_hash`;
- canonical rollback plan and SHA-256;
- TrustPlane action, resource, mission ID, and exact context.

Preparation is side-effect free and creates no TrustPlane decision or adoption row.

### `C3AdoptionRecord`

An immutable authorization receipt containing:

- `adoption_id`;
- `c3_run_id`;
- `c3_decision_id`;
- selected candidate artifact ID and material SHA-256;
- signed decision payload and qualification-head SHA-256 values;
- TrustPlane authorization decision ID;
- canonical rollback-plan JSON and SHA-256;
- fixed status `C3_ADOPTION_AUTHORIZED_NOT_EXECUTED`;
- authorization actor and timestamp;
- ledger event ID and hash.

### `C3AdoptionVerification`

A deterministic list of defects. `ok` is true only when the record, signed decision, selected candidate, TrustPlane authorization, authorization consumption, rollback contract, chronology, and ledger provenance are all clean.

## Mandatory rollback contract

The rollback object has exactly these fields:

```json
{
  "strategy": "non-empty string",
  "steps": ["one or more non-empty strings"],
  "verification_steps": ["one or more non-empty strings"],
  "abort_conditions": ["one or more non-empty strings"],
  "requires_separate_execution_authorization": true
}
```

No field may be missing or unexpected. Lists must be non-empty and contain only non-empty strings. The Boolean must be exactly `true`, not an integer or truthy substitute.

The canonical representation is produced by `canonical_json()` and its digest by `sha256_digest()`.

## Preparation and exact TrustPlane request

`prepare(c3_run_id, rollback_plan)` performs these read-only checks:

1. find the unique signed C3 decision for the run;
2. require `C3DecisionService.verify_decision()` to be clean;
3. require verdict `C3_CANDIDATE_SELECTED` and a selected candidate ID;
4. load the exact frozen `CANDIDATE` membership from `c3_decision_evidence`;
5. require its material digest to agree with the selected immutable qualification artifact;
6. validate and canonicalize the rollback plan.

It returns the exact authorization material:

```text
action      = c3.adoption.authorize
resource    = continuity:c3:<c3_run_id>:adoption:<candidate_artifact_id>
mission_id  = <c3_run_id>
```

The exact context is:

```json
{
  "authorization_mode": "AUTHORIZE_ONLY_NOT_EXECUTE",
  "c3_decision_id": "...",
  "candidate_artifact_id": "...",
  "candidate_material_sha256": "...",
  "decision_payload_sha256": "...",
  "qualification_head_hash": "...",
  "rollback_plan_sha256": "..."
}
```

The authorizing subject is intentionally not embedded in preparation. It is supplied to TrustPlane and later must equal the `actor` admitting the adoption authorization.

## Authorization prerequisites

`authorize_adoption()` requires:

- a clean preparation at call time;
- a clean, existing TrustPlane decision;
- `allowed = true`;
- exact equality of subject, action, resource, mission ID, and context;
- TrustPlane decision timestamp not earlier than the signed C3 decision admission;
- adoption authorization timestamp not earlier than the TrustPlane decision timestamp.

Default deny, a wrong actor, broad resource, altered context, wrong mission, or stale/tampered signed decision fails closed.

## Persistence

### `c3_adoptions`

One immutable authorization per C3 run and one per signed C3 decision.

Database constraints enforce:

- one `adoption_id`;
- unique `c3_run_id`;
- unique `c3_decision_id`;
- unique `authorization_decision_id`;
- digest lengths;
- fixed status;
- foreign keys to C3 binding, C3 decision, selected qualification artifact, and TrustPlane decision.

No-update and no-delete triggers make the receipt append-only.

### Global authorization consumption

The service uses the already sovereign `continuity_authorization_consumptions` table so one TrustPlane decision cannot authorize another continuity operation.

The exact consumption is:

```text
operation_kind = C3_ADOPTION_AUTHORIZED
operation_id   = <adoption_id>
consumed_by    = <actor>
consumed_at    = <authorized_at>
```

Reusing the same TrustPlane decision or operation ID fails closed.

## Admission transaction

Before entering the transaction, the service validates preparation, authorization, chronology, and idempotency.

Inside one write transaction it repeats all mutable checks:

1. reject a competing adoption ID, C3 run, signed decision, or TrustPlane decision;
2. rebuild preparation from the same database state;
3. reverify the signed C3 decision;
4. reverify and reload the TrustPlane decision;
5. recheck exact subject/action/resource/mission/context and chronology;
6. consume the authorization decision globally;
7. append `C3_ADOPTION_AUTHORIZED_NOT_EXECUTED` to `continuity:c3:<c3_run_id>:adoption`;
8. insert the immutable adoption receipt.

Any change aborts the transaction without partial state.

Exact replay of the same adoption ID and all bound material returns the existing record after independent verification. Reuse with changed material is a conflict.

## Ledger contract

Stream:

```text
continuity:c3:<c3_run_id>:adoption
```

Kind:

```text
C3_ADOPTION_AUTHORIZED_NOT_EXECUTED
```

Payload:

```json
{
  "adoption_id": "...",
  "authorization_decision_id": "...",
  "c3_decision_id": "...",
  "c3_run_id": "...",
  "candidate_artifact_id": "...",
  "candidate_material_sha256": "...",
  "decision_payload_sha256": "...",
  "qualification_head_hash": "...",
  "rollback_plan_sha256": "...",
  "status": "C3_ADOPTION_AUTHORIZED_NOT_EXECUTED"
}
```

## Independent verification

`verify_adoption()` rechecks:

- stored fixed status and all SHA-256 fields;
- rollback JSON, exact field set, list contents, required Boolean, canonical JSON, and digest;
- clean signed C3 decision and selected verdict;
- adoption candidate equals the selected candidate;
- decision payload and qualification-head digests;
- frozen candidate membership and current immutable qualification artifact digest;
- clean TrustPlane decision;
- exact subject/action/resource/mission/context;
- authorization and adoption chronology;
- exact global authorization-consumption row;
- adoption ledger stream, kind, actor, timestamp, payload, record hash, and chain.

Later qualification evidence makes the signed C3 decision stale. Adoption verification then inherits the decision defects and becomes fail-closed.

## Error behavior

- malformed rollback material or identifiers: `ValidationError`;
- missing decision, candidate, adoption, or authorization: `NotFoundError` or bounded authorization error;
- no-selection verdict, wrong candidate/context/actor/mission, or invalid chronology: `StateTransitionError` or `AuthorizationError`;
- dirty signed decision, tampered evidence, or dirty TrustPlane decision: `IntegrityError` or `AuthorizationError`;
- reused authorization/operation or conflicting adoption: `ConflictError` or `AuthorizationError`.

No error path creates partial adoption state.

## Testing strategy

Tests use real `Database`, `EventLedger`, `TrustPlane`, `ContinuityService`, `QualificationLab`, `C3QualificationGate`, and `C3DecisionService`. Only the upstream C2 certification service is a bounded clean fixture, avoiding reconstruction of 800 census identities in every test.

Tests cover:

- deterministic preparation and rollback digest;
- default deny;
- valid exact authorization, immutable receipt, verification, and exact replay;
- no-selection decision rejection;
- invalid rollback plans;
- wrong actor, action, resource, mission, or context;
- authorization and adoption chronology;
- second adoption and authorization reuse;
- transaction-time decision and TrustPlane rechecks;
- row, rollback, consumption, and ledger tampering;
- later qualification evidence making adoption stale;
- absence of any execution method.

## Explicit non-goals

This slice does not:

- expose an adoption CLI;
- download or install software;
- enable, run, deploy, or integrate a candidate;
- call any external runtime or network service;
- create an execution authorization;
- implement rollback execution;
- promote C3 or any canonical product status;
- declare any component adopted or active.
