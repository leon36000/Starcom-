# Exact-byte signed C4 architecture review

**Date:** 2026-08-14
**Issue:** #55
**Status:** implementation-ready

## Purpose

STARCOM can now freeze verified terminal C3 evidence and create one immutable STARCOM v3.2 architecture candidate with status `C4_ARCHITECTURE_CANDIDATE_NOT_REVIEWED`.

This design adds a separate independent-review authority. It accepts an explicitly trusted Ed25519 reviewer key, verifies a signature over the exact review payload bytes, rechecks the candidate and input set, enforces reviewer independence and stores one immutable review per candidate.

Even `C4_ARCHITECTURE_ACCEPTED` means only that an independent reviewer accepted the exact candidate. This authority never publishes, deploys, activates, integrates or promotes the architecture.

## Components

### `C4ArchitectureReviewVerdict`

Closed values:

- `C4_ARCHITECTURE_ACCEPTED`
- `C4_ARCHITECTURE_REJECTED`
- `C4_ARCHITECTURE_REWORK_REQUIRED`

### `C4ArchitectureVerificationResult`

Closed values:

- `PASS`
- `FAIL`

The payload carries independent results for structure, security and evidence binding.

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
- `PORT_CONTRACT_GAP`
- `MISSION_FABRIC_GAP`
- `COMPONENT_BINDING_GAP`
- `VERTICAL_BENCHMARK_GAP`
- `NON_FUNCTIONAL_REQUIREMENT_GAP`
- `SECURITY_BOUNDARY_GAP`
- `EVIDENCE_BINDING_GAP`

### `C4ArchitectureReviewService`

The service owns:

- deterministic reviewer-root preparation;
- exact TrustPlane reviewer-root acceptance;
- standalone reviewer-root verification;
- exact-byte review admission;
- immutable review and finding reads;
- independent review verification.

Dependencies:

- `Database`
- `EventLedger`
- `TrustPlane`
- `ContinuityService`
- `C4ArchitectureInputService`
- `C4ArchitectureCandidateService`

The shared `ContinuityService` supplies the configured Ed25519 signature verifier and the existing exact single-use authorization-consumption authority.

## Reviewer trust root

### Preparation

```python
C4ArchitectureReviewService.prepare_reviewer_root(
    key_id: str,
    public_key: bytes,
) -> C4ArchitectureReviewerRootPreparation
```

Preparation validates a non-empty bounded Ed25519 public key and returns:

- key ID;
- SHA-256 fingerprint of the exact public-key bytes;
- algorithm `Ed25519`;
- purpose `C4_ARCHITECTURE_REVIEW`;
- action `c4.architecture-reviewer.accept`;
- resource `continuity:c4:architecture-reviewer:<key_id>`;
- mission ID `c4-architecture-reviewer:<key_id>`;
- exact context containing the four identity fields above.

Preparation is read-only and cannot trust a key.

### Acceptance

```python
C4ArchitectureReviewService.accept_reviewer_root(
    key_id: str,
    public_key: bytes,
    *,
    authorization_decision_id: str,
    actor: str,
    occurred_at: str | None = None,
) -> C4ArchitectureReviewerRoot
```

Acceptance requires a clean allowed TrustPlane decision whose subject, action, resource, mission and context exactly match the preparation. The acceptance timestamp cannot predate that decision.

Inside one transaction the service repeats the key and decision checks, consumes the authorization as:

```text
operation_kind = C4_ARCHITECTURE_REVIEWER_ACCEPTED
operation_id = <key_id>
```

It appends `C4_ARCHITECTURE_REVIEWER_ACCEPTED` to `continuity:c4:architecture-reviewer:<key_id>` and inserts one immutable root row.

Exact replay of the same key bytes, authorization and actor returns the existing independently verified root. Any changed material is a conflict. The reviewer key cannot authorize itself merely by appearing in a payload.

## Exact signed review payload

The payload is a UTF-8 JSON object with exactly these fields:

- `review_id`
- `candidate_id`
- `architecture_id`
- `architecture_version`
- `input_set_id`
- `manifest_sha256`
- `input_set_digest`
- `reviewer_identity`
- `reviewer_environment`
- `independence_basis`
- `reviewed_at_utc`
- `structural_verification_result`
- `security_verification_result`
- `evidence_binding_result`
- `verdict`
- `findings`
- `gate_effect`

Closed values:

- `architecture_version = 3.2`
- `gate_effect = NO_PUBLICATION_NO_DEPLOYMENT`

Payload and signature limits follow existing exact-byte authorities: payload at most 4 MiB and signature at most 1024 bytes.

The service performs these operations in order:

1. verify the accepted reviewer root independently;
2. verify the Ed25519 signature over the exact payload bytes;
3. decode UTF-8;
4. parse JSON while rejecting duplicate keys;
5. enforce the exact closed schema and semantics.

No payload reserialization occurs before signature verification.

## Findings

`findings` is a list sorted lexicographically by `finding_id`, with unique IDs. It may be empty.

Each finding is an object with exactly:

- `finding_id`
- `severity`
- `code`
- `message`
- `evidence_refs`

`evidence_refs` is a non-empty sorted duplicate-free list of non-empty strings. The payload can reference ADR IDs, port IDs, binding IDs, test IDs, proof IDs, execution IDs or other exact immutable evidence identifiers.

Every finding is normalized into a deterministic mapping and frozen in a membership table with its ordinal, canonical JSON and SHA-256.

## Verdict invariants

The three verification results and finding severities determine which verdict is valid.

### `C4_ARCHITECTURE_ACCEPTED`

Requires:

- structural result `PASS`;
- security result `PASS`;
- evidence-binding result `PASS`;
- no `MEDIUM`, `HIGH` or `CRITICAL` finding.

Accepted reviews may contain only `INFO` or `LOW` observations. They still publish and deploy nothing.

### `C4_ARCHITECTURE_REWORK_REQUIRED`

Requires:

- all three verification results `PASS`;
- at least one `MEDIUM` finding;
- no `HIGH` or `CRITICAL` finding.

### `C4_ARCHITECTURE_REJECTED`

Requires at least one of:

- one verification result `FAIL`;
- one `HIGH` finding;
- one `CRITICAL` finding.

A verdict that does not match these deterministic rules is rejected before admission.

## Candidate, input and independence checks

Before and inside the admission transaction the service requires:

- `C4ArchitectureCandidateService.verify_candidate(candidate_id)` is clean;
- candidate status is exactly `C4_ARCHITECTURE_CANDIDATE_NOT_REVIEWED`;
- `C4ArchitectureInputService.verify_input_set(input_set_id)` is clean;
- candidate and input-set IDs/digests exactly match the payload;
- architecture ID/version and manifest SHA-256 exactly match the candidate;
- the review timestamp is not earlier than candidate creation, input freezing or reviewer-root acceptance.

The reviewer identity must differ from every identity in this disallowed set:

- candidate creator;
- input-set freezer;
- every frozen input-set author identity;
- reviewer-root acceptance actor;
- review admission actor.

Whitespace is stripped only for identity comparison after the exact signed field has been validated as a non-empty string. Case is preserved and comparison is exact.

## Persistence

### `c4_architecture_reviewer_roots`

Immutable fields:

- key ID;
- exact public-key bytes;
- public-key fingerprint;
- acceptance time and actor;
- TrustPlane decision ID;
- ledger event ID and hash.

### `c4_architecture_reviews`

One immutable row per review and one review per candidate. Fields include:

- review/candidate/architecture/input IDs;
- architecture version;
- manifest and input-set digests;
- reviewer-root key ID;
- exact payload and signature bytes;
- payload and signature SHA-256 values;
- reviewer identity and environment;
- independence basis;
- review timestamp;
- three verification results;
- verdict;
- finding count and finding-set digest;
- fixed gate effect;
- admission time and actor;
- ledger event ID and hash.

### `c4_architecture_review_findings`

Immutable frozen membership rows:

- review ID;
- contiguous ordinal;
- finding ID;
- canonical finding JSON;
- finding SHA-256.

Primary keys and uniqueness constraints prevent ordinal or finding-ID reuse. All three tables have no-update and no-delete triggers.

## Review admission

```python
C4ArchitectureReviewService.admit_review(
    candidate_id: str,
    key_id: str,
    payload: bytes,
    signature: bytes,
    *,
    actor: str,
    occurred_at: str | None = None,
) -> C4ArchitectureReviewRecord
```

The service validates exact bytes, root, signature, payload, verdict, candidate, input, chronology and independence before opening the transaction.

Inside one transaction it repeats every mutable check, verifies that no competing review exists, appends `C4_ARCHITECTURE_REVIEW_ADMITTED` to `continuity:c4:architecture-review:<review_id>`, inserts the review row and inserts all ordered findings.

Review admission does not require a second TrustPlane decision: authority derives from the separately accepted reviewer root, exact signature and all independent proof gates. The operational admission actor cannot equal the reviewer.

Exact replay requires the same review ID, candidate, key ID, payload bytes, signature bytes and admission actor. The existing review must independently verify before it is returned. Reusing a review ID with different material or admitting a second review for the candidate is a conflict.

## Review ledger payload

The event payload binds:

- review ID;
- candidate, architecture and input-set IDs;
- manifest and input-set digests;
- reviewer-root key ID;
- payload and signature SHA-256 values;
- reviewer identity;
- verdict;
- three verification results;
- finding count and finding-set digest;
- `gate_effect = NO_PUBLICATION_NO_DEPLOYMENT`.

The operational admission actor and timestamp remain ledger envelope fields.

## Independent verification

### Reviewer-root verifier

`verify_reviewer_root(key_id)` rechecks:

- public-key size and Ed25519 validity;
- stored fingerprint;
- TrustPlane decision verification;
- exact request and chronology;
- exact authorization consumption;
- root event stream, kind, actor, timestamp, payload, hash and ledger chain.

### Review verifier

`verify_review(review_id)` rechecks:

- payload/signature SHA-256 values;
- reviewer-root verifier;
- exact signature over stored bytes;
- closed payload parsing and stored-field agreement;
- candidate and input verifiers;
- exact candidate/input/digest binding;
- review chronology;
- reviewer independence;
- findings ordinals, canonical JSON, hashes, count and set digest;
- verdict invariants;
- review event stream, kind, actor, timestamp, payload, hash and ledger chain.

Any root, payload, signature, candidate, input, finding, row, event or ledger mutation makes the result fail closed.

## Error behavior

- malformed fields, duplicate JSON keys, invalid UTF-8, invalid timestamps/digests, findings or verdict combinations: `ValidationError`;
- missing candidate, input, reviewer root or review: `NotFoundError` or a fail-closed state error as appropriate;
- invalid key, signature, dirty root/candidate/input or tampered stored evidence: `IntegrityError`;
- reviewer dependence or incoherent chronology: `StateTransitionError`;
- denied/mismatched/dirty reviewer-root authorization: `AuthorizationError`;
- review/root identity reuse with different material or a second candidate review: `ConflictError`.

## Testing strategy

Tests use:

- real Database, EventLedger, TrustPlane and ContinuityService;
- real C4 input/candidate service records created from a deterministic C3 evidence source;
- ephemeral Ed25519 keys generated at runtime;
- exact raw payload/signature bytes.

Coverage includes:

- deterministic side-effect-free root preparation;
- default deny and exact root acceptance;
- valid accepted, rework-required and rejected reviews;
- whitespace mutation with original signature;
- wrong key, key substitution and unaccepted root;
- duplicate/missing/extra payload fields;
- verdict/result/finding invariant failures;
- reviewer matching every disallowed identity;
- review timestamp before root/input/candidate;
- exact replay and second-review conflicts;
- transaction-time candidate/input/root rechecks;
- root, payload, signature, finding membership, consumption, event and ledger tampering.

## Explicit non-goals

This slice does not:

- expose a CLI;
- publish or deploy an architecture;
- create a publication record;
- mutate the C4 candidate or input set;
- activate a component or external runtime;
- perform network access;
- promote C4 or any canonical product status.
