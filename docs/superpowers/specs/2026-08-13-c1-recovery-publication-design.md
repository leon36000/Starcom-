# C1 Signed Review Admission and Recovery Publication Design

**Date:** 2026-08-13
**Status:** approved bounded execution design

## Goal

Add a native fail-closed protocol that can accept an owner-authorized reviewer public key, verify the exact bytes of a signed Task 5 disposition, preserve the artifacts immutably, and publish recovery exactly once.

This slice does not import the missing historical reviewer bytes and does not claim C1 recovery was executed. Current truth remains:

```text
TASK5_DISPOSITION = RECOLLECT_REQUIRED
C1_INDEPENDENT_REVIEW = REPORTED_COMPLETE
C1_RECOVERY_PUBLICATION = NOT_PROVEN_EXECUTED_IN_THIS_RUNTIME
```

## Architecture

A new `starcom.continuity` module will contain:

- an OpenSSL-backed Ed25519 verifier using argument arrays, no shell, bounded input sizes, a timeout, and fail-closed errors;
- a `ContinuityService` backed by SQLite;
- immutable trust-root, review, publication, and authorization-consumption records;
- append-only ledger events for every accepted transition;
- an observational verifier that never repairs state.

The closed incident states are:

```text
RECOVERY_REQUIRED
RECOVERY_PUBLISHED_RECOLLECT_REQUIRED
```

There is deliberately no `PASS`, `COMPLETE`, or `RECOVERED` state.

## Signed review contract

The exact signed JSON bytes are stored as a BLOB and hashed without normalization. The parsed top-level object must contain the fields required by the historical Task 5 handoff, including reviewer identity and environment, archive digest, review time, independence basis, commands, evidence paths and hashes, reasoning, and the result fields below.

Recovery publication requires these exact signed values:

```text
receipt_snapshot_observation_result = PASS
wave_order_result = CONFIRMS_W3_TO_W2
attempt_boundary_result = POSSIBLE_UNQUANTIFIED_CONFIRMED
disposition = RECOLLECT_REQUIRED
gate_effect = NO_GATE_CHANGE
independent_identity_status = SATISFIED
```

## Trust Plane contracts

Trust-root acceptance requires an allowed, verifiable decision matching:

```text
action = continuity.trust-root.accept
resource = continuity:trust-root:<key_id>
```

Recovery publication requires an allowed, verifiable decision matching:

```text
action = continuity.recovery.publish
resource = continuity:incident:<incident_id>
```

The decision subject must equal the actor performing the operation. Each decision is consumed once.

## Persistence and idempotency

The service owns five tables: incidents, trust roots, reviews, recovery publications, and authorization consumptions. Trust roots, reviews, publications, and consumptions are immutable through triggers. Incident status changes only in the same transaction as the publication record and ledger event.

Identical replays return the original receipt. Reuse of an identifier with different bytes or metadata is a conflict. Publication is unique per incident and preserves the `RECOLLECT_REQUIRED` disposition.

## Verification

`verify_incident` checks hashes, signature validity, signed fields, trust decisions, ledger payloads and chains, publication uniqueness, and status consistency. It reports defects without changing state.

## Scope

The first slice exposes Python APIs and tests. A sensitive CLI is deferred until the protocol itself passes deterministic verification.

## Test requirements

Tests must prove default deny, valid admission, tamper rejection, malformed-review rejection, exact authorization matching, one-time publication, idempotency, conflicting replay rejection, and database/ledger tamper detection.

The slice is accepted only after GitHub Actions passes compilation, the full test suite, secret scan, text policy, and manifest verification. This does not equal C1 completion.