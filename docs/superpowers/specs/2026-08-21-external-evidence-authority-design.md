# STARCOM exact-byte external evidence authority — design

## Boundary

Issue #71 adds a local, signed-evidence admission authority for four closed
categories. It proves the admission mechanism and verification invariants only;
it does not contact a live runtime, create a deployment, authorize adoption, or
change STARCOM's canonical external truth. `ProgramTruth` therefore remains
`RC_BLOCKED_EXTERNAL_EVIDENCE` with all four external statuses `NOT_PROVEN`.

## Contract

`ExternalEvidenceService` consumes the existing `Database`, `EventLedger`,
`ContinuityService`, and injected signature verifier. It exposes only
preparation, admission, retrieval, verification, and a read-only four-category
snapshot. No method named `run`, `execute`, `deploy`, `release`, `publish`, or
`promote` is added.

The signed payload is strict UTF-8 JSON with exactly:

```text
evidence_id, kind, subject_id, operator_identity, reviewer_identity,
reviewer_environment, captured_at_utc, valid_until_utc, claims,
evidence_items, independence_basis, result, gate_effect
```

`kind` is one of `LIVE_CENSUS_CERTIFICATION`,
`EXTERNAL_RUNTIME_INTEGRATION`, `COMPONENT_ADOPTION`, or `REAL_DEPLOYMENT`.
`result` is exactly `PROVEN` and `gate_effect` is exactly
`EXTERNAL_EVIDENCE_ADMITTED_NO_RELEASE`.

Claims are closed by kind: census requires an integer identity count of at
least 800, independent certification, and census/certificate SHA-256 digests;
runtime requires runtime/version, handshake, health, and durable roundtrip
`PASS`; adoption requires component/version, installation, enablement, and
rollback `PASS`; deployment requires deployment/node, bundle, health, and
rollback `PASS`. Evidence items are sorted and unique by `item_id` and contain
only `item_id`, `kind`, `digest`, and `media_type`.

The independence object contains only sorted unique `excluded_identities` and
non-empty `statement`. Operator and reviewer identities must differ. Timestamps
must satisfy `captured_at_utc <= valid_until_utc`, with admission before
expiration. The service rejects expired, malformed, duplicate, substituted, or
tampered material fail-closed.

## Persistence and verification

One immutable `external_evidence_records` row stores exact payload/signature
bytes, all digests, derived category fields, trust-root key, timestamps, and
ledger receipt. One immutable `external_evidence_items` table stores ordered
item material and per-item digests. Update/delete triggers protect both.

Admission verifies the accepted Continuity trust root and signature over the
original payload bytes, derives the record, appends exactly one
`EXTERNAL_EVIDENCE_ADMITTED` event on
`continuity:external-evidence:<evidence_id>`, and inserts record/items in one
transaction. Exact replay returns the same record without a second event;
material, key, signature, operator, or reviewer conflicts are rejected.

`verify_evidence` reconstructs exact payload bytes from storage only to compare
against the stored bytes, rechecks stored digests, signature, root, claims,
items, expiration, immutable provenance, and ledger chain. `snapshot()` returns
`PROVEN` only for a clean, non-expired record for each category; missing or
dirty categories return `NOT_PROVEN`.

## Composition

`StarcomProgram.open` creates exactly one `ExternalEvidenceService` over the
existing shared database, ledger, and continuity objects. The authority is
catalogued as `19.external_evidence`; it has no network, subprocess, or external
effect during construction. The existing release-candidate authority remains
separate and continues to derive its own non-release blocked truth.
