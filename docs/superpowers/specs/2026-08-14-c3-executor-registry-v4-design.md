# Exact-byte signed and revocable C3 executor registry v4

**Date:** 2026-08-14
**Issue:** #48
**Status:** implementation-ready

## Purpose

The durable C3 worker currently receives an injected executor identified by a string. Before any production adapter can exist, STARCOM needs a sovereign authority that binds that identity to immutable implementation material, an independent exact-byte qualification, an explicit enablement decision and a terminal revocation state.

No executor is usable by default. This slice does not modify the worker; pre-effect worker enforcement is tracked by #49 and starts only after this registry is merged and independently verified.

## Closed state model

The append-only states are exactly:

- `C3_EXECUTOR_REGISTERED_DISABLED`
- `C3_EXECUTOR_QUALIFIED_DISABLED`
- `C3_EXECUTOR_ENABLED`
- `C3_EXECUTOR_REVOKED`

Allowed transitions:

- none -> registered disabled
- registered disabled -> qualified disabled
- qualified disabled -> enabled
- registered disabled -> revoked
- qualified disabled -> revoked
- enabled -> revoked

`REVOKED` is terminal. Registration and qualification never enable an executor.

## Immutable descriptor

A descriptor contains exactly:

- `executor_id`
- `implementation_name`
- `implementation_version`
- `implementation_digest`
- `artifact_digest`
- `entrypoint`
- `supported_sandbox_profiles`
- `network_mode`
- `capabilities`

Both digests are lowercase SHA-256. Lists are non-empty, sorted and duplicate-free. `network_mode` is `DENY` or `ALLOWLIST_ONLY`. The canonical descriptor JSON and its digest are stored exactly once.

## Separate TrustPlane authorities

Every mutation requires a distinct, exact, single-use TrustPlane decision:

- registration: `c3.executor.register`
- qualifier root acceptance: `c3.executor.qualifier.accept`
- qualification: `c3.executor.qualify`
- enablement: `c3.executor.enable`
- revocation: `c3.executor.revoke`

Resource forms:

- `continuity:c3:executor:<executor_id>:register`
- `continuity:c3:executor-qualifier:<key_id>`
- `continuity:c3:executor:<executor_id>:qualify`
- `continuity:c3:executor:<executor_id>:enable`
- `continuity:c3:executor:<executor_id>:revoke`

Mission IDs are stable and operation-specific. Contexts bind all identifiers, prior/requested states and cryptographic digests. The service verifies and consumes each decision atomically with its immutable row and ledger event.

## Qualifier root authority

Qualification uses a dedicated Ed25519 public key accepted through `c3.executor.qualifier.accept`.

The acceptance context binds:

- `key_id`
- exact public-key SHA-256 fingerprint
- algorithm `Ed25519`
- purpose `C3_EXECUTOR_QUALIFICATION`

The public key is stored as exact bytes. No private key is persisted. Root rows and their ledger provenance are immutable and independently verified.

## Exact qualification payload

The UTF-8 JSON object has exactly these fields:

- `qualification_id`
- `executor_id`
- `descriptor_digest`
- `report_digest`
- `test_suite_digest`
- `reviewer_identity`
- `reviewer_environment`
- `independence_basis`
- `sandbox_profiles_tested`
- `network_mode_tested`
- `verdict`
- `qualified_at`
- `gate_effect`

Closed values:

- `verdict = QUALIFIED`
- `gate_effect = QUALIFIED_DISABLED_NO_ENABLEMENT`

Arrays are non-empty, sorted and duplicate-free. Unknown fields, missing fields, duplicate keys, malformed UTF-8, malformed timestamps and invalid digests fail closed.

The service verifies the Ed25519 signature over the exact input bytes before trusting the parsed object. It stores the exact payload and signature bytes with their SHA-256 digests. Whitespace changes with the original signature must fail.

The reviewer identity must differ from the descriptor registrant. Qualification time must follow registration and qualifier-root acceptance.

## Persistence

### `c3_executor_descriptors`

Immutable canonical descriptor, descriptor digest, registrant, registration decision, timestamp and ledger receipt.

### `c3_executor_qualifier_roots`

Immutable exact public key bytes, fingerprint, acceptance decision, timestamp and ledger receipt.

### `c3_executor_qualifications`

Immutable exact payload/signature bytes, their hashes, key ID, reviewer identity, qualification/admission timestamps, qualification decision and ledger receipt.

### `c3_executor_transitions`

Append-only contiguous state transitions with operation, canonical metadata, actor, exact consumed decision, timestamp and ledger receipt.

All four tables use no-update and no-delete triggers.

## Idempotence and conflict rules

Exact replay of registration, root acceptance, qualification, enablement or revocation returns the existing verified record even when the caller supplies a later operation timestamp.

Any identifier reuse with materially different descriptor, key, payload, signature, decision, actor or terminal revocation reason raises `ConflictError`.

A consumed decision cannot authorize another operation. A revoked executor cannot be qualified or enabled again.

## Independent verification

`verify(executor_id)` recomputes and checks:

- descriptor closed schema, canonical JSON, columns and digest
- exact registration decision request, consumption and chronology
- qualifier-root key validity, fingerprint, decision, consumption, event and ledger chain
- qualification payload/signature hashes and Ed25519 signature
- exact qualification schema and descriptor binding
- reviewer independence and chronology
- exact qualification decision request and consumption
- contiguous legal transitions
- exact enable/revoke decisions and consumptions
- transition event stream, kind, actor, timestamp, payload, stored hash and ledger chain
- terminal revocation semantics

Verification is read-only and deterministic. Any dirty prerequisite prevents attestation.

## Read-only attestation

`attest()` succeeds only when:

- registry verification is clean
- current state is exactly `C3_EXECUTOR_ENABLED`
- implementation version and digest match
- requested sandbox profile is qualified
- network requirements are compatible with the descriptor mode
- no revocation is present

It returns the current registry head hash. It writes no state.

## Test strategy

The suite generates ephemeral Ed25519 keys at runtime and covers:

- default deny for every authority
- registration remains disabled
- exact replay and material conflicts
- root acceptance and key substitution
- exact signed qualification and whitespace mutation
- duplicate/extra/missing payload fields
- reviewer independence
- qualification remains disabled
- separate enablement and attestation mismatch cases
- terminal revocation and exact replay
- descriptor, root, payload, signature, decision, consumption, transition and ledger tampering

## Explicit non-goals

This slice does not:

- register or enable a production executor
- modify `C3AdoptionExecutionWorker`
- execute an adapter
- perform network access
- install or adopt a real component
- change `NO_COMPONENT_ADOPTION` or `NO_EXTERNAL_RUNTIME_INTEGRATED`
- promote canonical project status
