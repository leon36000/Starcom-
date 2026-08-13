# C1 Signed Review Admission and Recovery Publication Design

**Date:** 2026-08-13  
**Status:** bounded protocol implemented; historical admission not executed  
**Delivery branch:** `work/c1-core-20260813`

## Goal

Provide a native fail-closed protocol that can accept an owner-authorized reviewer public key, verify the exact bytes of a signed Task 5 disposition, preserve those artifacts immutably, and publish recovery exactly once.

This slice does not import the missing historical reviewer bytes and does not claim C1 recovery was executed. Current truth remains:

```text
TASK5_DISPOSITION = RECOLLECT_REQUIRED
C1_INDEPENDENT_REVIEW = REPORTED_COMPLETE
C1_RECOVERY_PUBLICATION = NOT_PROVEN_EXECUTED_IN_THIS_RUNTIME
```

## Architecture

`starcom.continuity` contains:

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

There is deliberately no `PASS`, `COMPLETE`, or generic `RECOVERED` state.

## Signed review contract

The exact signed JSON bytes are stored as a BLOB and hashed without normalization. The parsed top-level object must contain reviewer identity and environment, archive digest, review time, independence basis, commands, evidence paths and hashes, reasoning, and all required result fields.

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

The service owns five tables: incidents, trust roots, reviews, recovery publications, and authorization consumptions. Trust roots, reviews, publications, and consumptions are immutable through SQLite triggers. Incident status changes only in the same transaction as the publication record and ledger event.

Identical replays return the original receipt. Reuse of an identifier with different bytes or metadata is a conflict. Publication is unique per incident and preserves the `RECOLLECT_REQUIRED` disposition.

## Verification boundary

The implemented verifier checks:

- incident, review, and publication ledger records and stream chains;
- public-key, payload, and signature digests;
- exact-byte signature validity;
- signed field consistency and recovery eligibility;
- publication Trust Plane decision integrity and exact request matching;
- publication authorization consumption;
- status/publication consistency.

A falsification pass found that observational verification does not yet independently revalidate the Trust Plane decision and consumption that originally accepted the reviewer trust root. That hardening item is tracked in issue #5. The transaction path still validates and consumes the decision before trust-root acceptance; the missing item is later independent revalidation.

This limitation is excluded from the bounded completion claim and prevents any historical C1 promotion.

## Test strategy

No private key is committed. The suite uses:

- a static public Ed25519 key, payload, and signature vector to prove the real OpenSSL path;
- an injected deterministic verifier for state-machine and tamper tests;
- immutable-table bypass only inside explicit negative tests to prove detection.

Tests cover default deny, valid admission, signature and payload tampering, malformed review rejection, exact publication authorization, one-time publication, idempotency, conflicting replay rejection, and stored-state tamper detection.

## Scope

The first slice exposes Python APIs and tests. A sensitive CLI is deferred until the protocol and all required audit links pass deterministic verification.

The slice may be accepted only after GitHub Actions passes compilation, the full bounded test suite, secret scan, text policy, and manifest verification. Acceptance of this slice does not equal completion of C1.