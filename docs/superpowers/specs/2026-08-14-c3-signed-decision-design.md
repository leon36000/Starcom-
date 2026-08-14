# Exact-byte signed C3 decision authority

**Date:** 2026-08-14
**Issue:** #38
**Status:** implementation-ready

## Purpose

C3 currently proves that a qualification run starts from one exact verified C2 certificate, that the run was empty at the binding boundary, and that generic decision or adoption artifacts cannot silently become sovereign outcomes.

This design adds the missing sovereign decision authority. It converts the append-only candidate and evaluation evidence of one C3 run into one exact-byte signed terminal decision. The decision may select one candidate or conclude that no candidate is selected. It never adopts, installs, integrates, enables, deploys, or promotes a component.

## Chosen approach

STARCOM will use an exact-byte signed decision snapshot, following the already proven C2 certification pattern.

The alternatives were rejected for these reasons:

1. A plain generic `DECISION` qualification artifact has no independent trust root, exact signature, frozen membership, or terminal verifier and is already intentionally rejected by C3.
2. A TrustPlane authorization alone proves permission to act, not the evidentiary correctness of the selected candidate.
3. Reusing a generic ProofEngine claim would still require a structured decision record and a frozen mapping to qualification evidence.

The signed snapshot keeps evidence, authority, and later adoption separate.

## Components

### `C3DecisionVerdict`

A closed enum with exactly:

- `C3_CANDIDATE_SELECTED`
- `C3_NO_SELECTION`

### `C3DecisionSnapshot`

A deterministic read model built only from a clean C3 binding and its bound qualification run. It contains:

- C3, qualification-run, and C2-certificate identifiers;
- the current qualification ledger head hash;
- ordered candidate members;
- ordered evaluation members;
- candidate and evaluation counts;
- SHA-256 digests of both ordered sets;
- the latest included evidence timestamp.

Each frozen member contains the artifact ID, kind, exact material object, material SHA-256, recorded timestamp, recorder identity, ledger event ID, and ledger hash.

Candidates and evaluations are ordered by artifact ID. Their set digests are computed with STARCOM canonical JSON and `sha256_digest()` over the ordered member list.

Generic `DECISION` or `ADOPTION` artifacts make the C3 verifier dirty and therefore prevent snapshot admission.

### `C3DecisionRecord`

An immutable stored decision containing:

- decision and target identifiers;
- trust-root key ID;
- exact payload and signature bytes plus their SHA-256 digests;
- decision-maker identity and environment;
- verdict and selected candidate ID;
- qualification head, counts, and set digests;
- decision time and independence basis;
- admission actor/time;
- decision ledger event ID and hash.

There is at most one decision per C3 run.

### `C3DecisionService`

The service owns snapshot generation, exact payload validation, signature verification, independence checks, admission, retrieval, and independent verification.

It depends explicitly on:

- `Database`
- `EventLedger`
- `ContinuityService`
- `C2CertificationService`
- `C3QualificationGate`
- `QualificationLab`

It performs no network access and no adoption side effect.

## Exact signed payload

The UTF-8 JSON object has exactly these fields:

- `decision_id`
- `c3_run_id`
- `qualification_run_id`
- `certificate_id`
- `qualification_head_hash`
- `candidate_count`
- `evaluation_count`
- `candidate_set_digest`
- `evaluation_set_digest`
- `verdict`
- `selected_candidate_artifact_id`
- `decision_maker_identity`
- `decision_maker_environment`
- `decided_at_utc`
- `independence_basis`
- `independent_identity_status`
- `qualification_verification_result`
- `gate_effect`

The fixed values are:

- `independent_identity_status = SATISFIED`
- `qualification_verification_result = PASS`
- `gate_effect = NO_ADOPTION_EXECUTED`

For `C3_CANDIDATE_SELECTED`, `selected_candidate_artifact_id` is a non-empty string and must identify a candidate in the frozen snapshot.

For `C3_NO_SELECTION`, `selected_candidate_artifact_id` is JSON `null`.

Duplicate JSON keys, malformed UTF-8, non-object payloads, missing fields, unexpected fields, malformed digests, invalid timestamps, booleans supplied as counts, and unknown verdicts fail closed.

## Evidence and decision prerequisites

A terminal decision requires:

- a clean `C3QualificationGate.verify()` result;
- at least one candidate;
- at least one evaluation;
- an accepted trust root whose standalone verifier is clean;
- a valid signature over the exact payload bytes;
- payload counts, digests, identifiers, and head hash that exactly match the current snapshot;
- a decision timestamp not earlier than the latest candidate or evaluation evidence;
- an admission timestamp not earlier than the signed decision timestamp;
- an independent decision-maker identity.

The decision-maker may not equal:

- the C2 certifier identity;
- the C3 binding starter;
- the qualification-run creator;
- any candidate recorder;
- any evaluation recorder.

The operational admission actor is not treated as the decision-maker and may be a service agent.

## Persistence

### `c3_decisions`

One immutable row per decision and one decision per C3 run. It stores exact payload/signature bytes and all decision summary fields. Database checks enforce allowed verdicts, minimum evidence counts, digest lengths, and verdict/selection consistency.

### `c3_decision_evidence`

Immutable frozen membership rows with:

- decision ID;
- kind `CANDIDATE` or `EVALUATION`;
- zero-based ordinal;
- artifact ID;
- canonical material JSON and digest;
- recorded time and recorder;
- artifact ledger event ID and hash.

Primary keys and uniqueness constraints prevent ordinal reuse, artifact duplication within a decision, or evidence reassignment.

Both tables have no-update and no-delete triggers.

## Admission transaction

Before the transaction, the service validates the exact payload, trust root, signature, snapshot match, selection, independence, and chronology.

Inside the write transaction it repeats all mutable checks:

1. confirm no competing decision exists;
2. reverify the trust root and exact signature;
3. reverify the C3 gate;
4. rebuild the snapshot from the same database connection;
5. require byte-for-byte-equivalent snapshot material;
6. append `C3_DECISION_ADMITTED` to `continuity:c3:<c3_run_id>:decision`;
7. insert the immutable decision row;
8. insert all frozen candidate and evaluation membership rows.

Any race, changed evidence, dirty gate, changed trust root, or invalid signature aborts the transaction.

Exact replay of the same decision ID, C3 run, key, payload, and signature returns the stored record after full verification. Reusing a decision ID with different material, or attempting a second decision for the same C3 run, is a conflict.

## Independent verification

`verify_decision()` rechecks:

- exact payload parsing and stored-field agreement;
- payload and signature SHA-256 values;
- standalone trust-root integrity;
- exact signature validity;
- clean C3 verification;
- frozen candidate/evaluation ordinals and memberships;
- each member against the current immutable qualification artifact and ledger linkage;
- candidate/evaluation set digests and counts;
- selected candidate membership and verdict consistency;
- independence and chronology;
- decision ledger event stream, kind, actor, timestamp, payload, stored hash, and chain;
- the current qualification head and current snapshot against the admitted decision snapshot.

Any candidate or evaluation appended after admission changes the qualification head and current snapshot. The verifier reports the decision as stale and adoption must remain blocked.

## Error behavior

- malformed input: `ValidationError`;
- invalid signature, dirty trust root, dirty C3, or tampering: `IntegrityError` or verifier defects;
- insufficient/mismatched evidence, invalid selection, chronology, or independence: `StateTransitionError`;
- identifier or C3-run reuse with different material: `ConflictError`;
- missing records: `NotFoundError`.

All failures are fail-closed and write no partial decision state.

## Testing strategy

Focused tests use a deterministic local signature verifier and a real TrustPlane/Continuity trust-root acceptance flow. The C3 binding and qualification ledger are real; only the upstream C2 certification service is a bounded clean fixture to avoid rebuilding 800 census identities in every test.

Tests cover:

- deterministic snapshot and closed payload contract;
- valid signed selection, retrieval, verification, and exact replay;
- valid signed no-selection decision;
- missing candidate/evaluation evidence;
- selected candidate not present;
- modified payload or invalid signature;
- non-independent decision maker;
- decision timestamp before latest evidence;
- transaction-time snapshot recheck;
- second decision conflict;
- frozen membership and ledger tampering;
- evidence appended after decision causing stale verification.

The complete repository suite, deterministic manifest, compilation, secret scan, text policy, a hash-seed rerun, and warnings-as-errors focused run must pass before publication.

## Explicit non-goals

This slice does not:

- adopt or integrate a component;
- create external runtime adapters;
- execute network requests;
- promote C3 or any canonical project status;
- replace the generic qualification laboratory;
- permit generic `DECISION` or `ADOPTION` artifacts inside C3;
- implement a decision CLI.

A later issue will expose the service through a thin CLI. Another separate issue will implement explicitly authorized adoption based on a clean selected decision.
