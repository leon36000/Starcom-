# Exact-byte signed C4 architecture review authority

**Date:** 2026-08-14
**Issue:** #55
**Status:** implementation-ready

## Purpose

The C4 foundation stores one immutable architecture input set and one immutable STARCOM v3.2 candidate in state `C4_ARCHITECTURE_CANDIDATE_NOT_REVIEWED`. This design adds the independent cryptographic review authority required before any architecture publication.

The authority accepts a dedicated Ed25519 reviewer trust root through an exact TrustPlane decision, then admits one exact-byte signed review for one candidate. It never changes the candidate row, publishes a manifest, deploys a component, invokes a worker, performs network access or promotes a global canonical product state.

## Components

### `C4ArchitectureReviewVerdict`

Closed values:

- `C4_ARCHITECTURE_ACCEPTED`
- `C4_ARCHITECTURE_REJECTED`
- `C4_ARCHITECTURE_REWORK_REQUIRED`

### `C4ArchitectureFindingSeverity`

Closed values:

- `INFO`
- `LOW`
- `MEDIUM`
- `HIGH`
- `CRITICAL`

### `C4ArchitectureFindingCode`

Closed values:

- `AUTHORITY_ADR_GAP`
- `PORT_OWNERSHIP_GAP`
- `MISSION_FABRIC_GAP`
- `CAPABILITY_TEST_PROOF_GAP`
- `COMPONENT_BINDING_GAP`
- `VERTICAL_BENCHMARK_GAP`
- `NON_FUNCTIONAL_REQUIREMENT_GAP`
- `SECURITY_CONTROL_GAP`
- `EVIDENCE_BINDING_GAP`
- `INDEPENDENCE_OR_PROVENANCE_GAP`
- `DOCUMENTATION_IMPROVEMENT`

### Root and review records

The public service types are:

- `C4ArchitectureReviewerRootPreparation`
- `C4ArchitectureReviewerRoot`
- `C4ArchitectureReview`
- `C4ArchitectureReviewerRootVerification`
- `C4ArchitectureReviewVerification`
- `C4ArchitectureReviewService`

The service depends on the real `Database`, `EventLedger`, `TrustPlane`, `ContinuityService`, `C4ArchitectureInputService` and `C4ArchitectureCandidateService`.

## Reviewer trust-root authority

### Preparation

```python
prepare_reviewer_root(
    key_id: str,
    public_key: bytes,
) -> C4ArchitectureReviewerRootPreparation
```

The key must be a valid Ed25519 public key under the configured continuity signature verifier. The preparation is deterministic and read-only.

TrustPlane request:

- action: `c4.architecture-reviewer.accept`
- resource: `continuity:c4:architecture-reviewer:<key_id>`
- mission: `c4-architecture-reviewer:<key_id>`
- context:
  - `key_id`
  - `public_key_fingerprint_sha256`
  - `algorithm = Ed25519`
  - `purpose = C4_ARCHITECTURE_INDEPENDENT_REVIEW`
  - `gate_effect = REVIEWER_TRUST_ROOT_ACCEPTED_NO_REVIEW`

### Acceptance

```python
accept_reviewer_root(
    key_id: str,
    public_key: bytes,
    *,
    authorization_decision_id: str,
    actor: str,
    occurred_at: str | None = None,
) -> C4ArchitectureReviewerRoot
```

Acceptance requires a clean, allowed, exact, chronological and unconsumed TrustPlane decision. The transaction consumes the decision as `C4_ARCHITECTURE_REVIEWER_ACCEPTED`, appends the same event kind on `continuity:c4:architecture-reviewer:<key_id>`, and inserts one immutable root row.

Exact replay of the same key bytes, decision and actor returns the existing verified root. Any difference is a conflict.

A root is not trusted merely because it appears in a signed review. It must first exist in the accepted root table and pass standalone verification.

## Exact review payload

The UTF-8 JSON object has exactly these top-level fields:

- `review_id`
- `candidate_id`
- `architecture_id`
- `architecture_version`
- `input_set_id`
- `input_set_digest`
- `manifest_sha256`
- `reviewer_identity`
- `reviewer_environment`
- `reviewed_at`
- `independence_basis`
- `structural_verification_result`
- `security_verification_result`
- `evidence_binding_result`
- `findings`
- `verdict`
- `gate_effect`

Closed values:

- `architecture_version = 3.2`
- each verification result is `PASS` or `FAIL`
- `gate_effect = NO_PUBLICATION_NO_DEPLOYMENT`

Payload size is limited to 4 MiB and signature size to 1024 bytes. Malformed UTF-8, non-object JSON, duplicate keys, missing fields and unexpected fields fail closed.

Signature verification occurs over the exact input bytes before the payload is trusted. The service never reserializes the payload before signature verification.

## Finding contract

Every finding has exactly:

- `finding_id`
- `code`
- `severity`
- `title`
- `description`
- `affected_ids`
- `evidence_refs`
- `recommendation`

Findings are ordered lexicographically by `finding_id`, and IDs are unique. `affected_ids` and `evidence_refs` are non-empty, sorted and duplicate-free string lists. Code and severity use the closed enums above.

Each evidence reference must identify either:

- the frozen input set ID;
- a frozen execution ID;
- the candidate ID, architecture ID or manifest digest;
- an ADR ID, port ID, capability ID, binding ID, benchmark ID, NFR ID, test ID or proof ID present in the candidate manifest.

This prevents findings from claiming evidence outside the reviewed candidate and input set.

## Verdict consistency

`C4_ARCHITECTURE_ACCEPTED` requires:

- all three verification results equal `PASS`;
- no finding with severity `MEDIUM`, `HIGH` or `CRITICAL`.

`C4_ARCHITECTURE_REJECTED` requires:

- at least one verification result equal `FAIL`;
- at least one `CRITICAL` finding.

`C4_ARCHITECTURE_REWORK_REQUIRED` requires:

- no `CRITICAL` finding;
- at least one failed verification result or one `MEDIUM` or `HIGH` finding.

Rejected and rework reviews require at least one finding. An accepted review may have zero findings or only `INFO` and `LOW` findings.

## Candidate and evidence binding

Before admission the service independently requires:

- `C4ArchitectureCandidateService.verify_candidate(candidate_id)` is clean;
- candidate state is exactly `C4_ARCHITECTURE_CANDIDATE_NOT_REVIEWED`;
- `C4ArchitectureInputService.verify_input_set(input_set_id)` is clean;
- candidate and payload architecture IDs, version, input-set ID/digest and manifest SHA-256 all match exactly;
- the candidate currently references the same input set;
- the manifest and input evidence references used by findings are current.

The same mutable checks are repeated inside the write transaction.

## Reviewer independence

The payload reviewer identity must be distinct from every relevant author or admission actor:

- candidate creator;
- input-set freezer;
- every identity in the input set's frozen `author_identities`;
- reviewer-root acceptance actor;
- review admission actor.

Blank identities are invalid. String comparison is exact after trimming surrounding whitespace during validation.

## Chronology

The review timestamp must be timezone-aware RFC 3339 and not earlier than:

- candidate creation time;
- input-set freeze time.

Admission time must not be earlier than:

- review time;
- reviewer-root acceptance time.

## Persistence

### `c4_architecture_reviewer_roots`

Stores:

- key ID;
- exact public-key bytes;
- fingerprint;
- acceptance decision, time and actor;
- ledger event ID and hash.

### `c4_architecture_reviews`

Stores:

- review, candidate, architecture and input identifiers;
- key ID;
- exact payload and signature bytes;
- payload and signature SHA-256 values;
- reviewer identity/environment;
- verification results;
- verdict and review time;
- independence basis;
- admission time and actor;
- review ledger event and hash.

`review_id` is primary and `candidate_id` is unique: one terminal independent review per immutable candidate in this slice.

### `c4_architecture_review_findings`

Stores contiguous finding ordinals, finding ID, canonical finding JSON and finding SHA-256. Primary key is `(review_id, ordinal)` and `(review_id, finding_id)` is unique.

All three tables have no-update and no-delete triggers.

## Review admission

```python
admit_review(
    candidate_id: str,
    key_id: str,
    payload: bytes,
    signature: bytes,
    *,
    actor: str,
    occurred_at: str | None = None,
) -> C4ArchitectureReview
```

Admission performs:

1. bounded raw-byte validation;
2. accepted reviewer-root verification;
3. Ed25519 verification over the exact payload bytes;
4. closed payload and finding validation;
5. candidate/input binding, verdict, independence and chronology checks;
6. exact replay and competing-candidate checks;
7. repetition of root, signature, candidate, input and snapshot checks inside one transaction;
8. append of `C4_ARCHITECTURE_REVIEW_ADMITTED` on `continuity:c4:architecture-review:<review_id>`;
9. insertion of the immutable review and finding rows.

No TrustPlane decision is generated for the review. The cryptographic reviewer root is the review authority; TrustPlane governs only root acceptance.

Exact replay requires identical candidate, key ID, exact payload bytes, exact signature bytes and admission actor. Different material or a second review for the candidate is a conflict.

## Review verifier

`verify_review(review_id)` independently rechecks:

- stored payload and signature SHA-256 values;
- duplicate-safe exact payload schema;
- standalone reviewer-root integrity, decision request, consumption, event and ledger chain;
- Ed25519 signature over stored exact payload bytes;
- stored row fields against payload;
- findings ordinals, canonical JSON, digest, payload equality and evidence references;
- verdict consistency;
- candidate and input verifiers and exact current bindings;
- reviewer independence and chronology;
- review ledger stream, kind, actor, timestamp, payload, row hash and chain.

Any later corruption of the candidate, input set, root, decision, consumption, finding, payload, signature or ledger makes the review fail closed.

## Testing strategy

Tests use:

- a real SQLite database, EventLedger, TrustPlane and ContinuityService;
- deterministic clean candidate/input service fixtures returning the real C4 dataclasses;
- ephemeral OpenSSL Ed25519 keys for exact-byte tests;
- real TrustPlane root acceptance and authorization consumption.

Required tests cover:

- deterministic root preparation without side effects;
- root default deny, exact acceptance, replay and verification;
- valid exact accepted review, replay and verification;
- exact rejected and rework verdicts;
- whitespace mutation with original signature;
- wrong key and unaccepted root;
- missing/extra/duplicate payload fields;
- unsorted, duplicate, unknown-code and invalid-evidence findings;
- candidate/input/digest mismatch;
- reviewer identity colliding with candidate creator, input freezer, input author, root accepter or admission actor;
- review chronology;
- verdict/result/finding inconsistency;
- second candidate review conflict;
- root row, review row, finding, consumption, event and ledger tampering.

## Explicit non-goals

This slice does not:

- modify the C4 candidate or input set;
- publish or deploy an architecture;
- invoke a C3 worker or executor;
- activate or adopt a component;
- expose a CLI;
- perform network access;
- promote any global canonical product state.
