# C1 Recovery Publication Implementation Plan

> Executed on a bounded branch with RED -> GREEN evidence. Delivery branch: `work/c1-core-20260813`.

**Goal:** implement a fail-closed, ledgered protocol for admitting signed independent Task 5 reviews and explicitly publishing the `RECOLLECT_REQUIRED` recovery state.

**Architecture:** `ContinuityService` coordinates SQLite persistence, `TrustPlane` decisions, `EventLedger` receipts, and an injected signature verifier. `OpenSSLEd25519Verifier` is the production verifier. No historical artifact is treated as present unless its exact bytes are admitted.

**Tech:** Python 3.11+, SQLite, standard library, OpenSSL command line, `unittest`.

---

## Task 1: Establish RED protocol tests — complete

**Created:** `tests/test_continuity.py`

1. Added a static public Ed25519 key, exact payload, and signature vector for the production OpenSSL path. No private key material enters the repository.
2. Added failing tests for default-denied trust-root acceptance, signed-review admission, tamper rejection, malformed review rejection, exact recovery authorization, idempotency, conflicts, and verification defects.
3. Preserved the original RED GitHub Actions run: `31754396500` on commit `4cffe3a3378ebcac25929ab972ef20f72d97e91b`.
4. The RED failure was exactly `ModuleNotFoundError: starcom.continuity`; the 79 pre-existing tests remained green.

## Task 2: Implement exact-byte signature verification — complete

**Created:** `src/starcom/continuity.py`

1. Added closed incident states and immutable result dataclasses.
2. Added a `SignatureVerifier` protocol.
3. Implemented `OpenSSLEd25519Verifier` with bounded inputs, temporary files, no shell, timeout, and fail-closed results.
4. Proved that the public fixture verifies and a one-byte payload change fails.

## Task 3: Implement persistence and trust-root admission — complete

1. Created incident, trust-root, review, publication, and authorization-consumption tables.
2. Added immutable update/delete triggers for append-only records.
3. Implemented exact Trust Plane decision validation and single-use consumption.
4. Implemented incident creation and trust-root acceptance with ledger receipts and idempotency.

## Task 4: Implement signed-review admission — complete

1. Parse and validate the historical Task 5 disposition fields.
2. Verify exact bytes against an accepted reviewer key.
3. Store payload and signature BLOBs plus SHA-256 digests.
4. Ledger bounded metadata and digests rather than private material.
5. Support identical replay and reject conflicting reuse.

## Task 5: Implement explicit recovery publication — complete

1. Require an admitted review with the exact eligible `RECOLLECT_REQUIRED` findings.
2. Require an allowed, untampered, exact-match Trust Plane decision.
3. Atomically insert publication, consume authorization, append the ledger event, and transition to `RECOVERY_PUBLISHED_RECOLLECT_REQUIRED`.
4. Preserve the disposition and prohibit automatic C2 start.
5. Support identical replay and reject competing publication.

## Task 6: Implement bounded state verification — complete with explicit limitation

The implemented verifier recomputes review/publication hashes, re-runs Ed25519 verification, validates signed fields, cross-checks publication authorization, verifies relevant ledger records and chains, and detects status disagreement and payload tampering.

A separate falsification pass at commit `ed8c6bb2346820a4d20980ecf42e3075a9e50498` added two stronger tests. GitHub Actions run `31754808515` executed 89 tests: 87 passed and two failed because the verifier does not yet independently revalidate the decision and consumption that originally accepted the trust root.

That gap is preserved as RED evidence and tracked in issue #5. It is not hidden, removed, or represented as complete.

## Task 7: Update documentation and manifest — in progress

1. Document the implemented mechanism without claiming historical artifact admission or C1 completion.
2. Record the exact remaining blockers:
   - sealed historical public artifacts are absent;
   - issue #5 remains open.
3. Rebuild the deterministic manifest from the final branch tree.
4. Run `python scripts/verify_repo.py` through GitHub Actions.

## Task 8: Review and publish — pending final evidence

1. Inspect the complete diff for scope, security, and truth-boundary errors.
2. Run fresh full verification on the final head.
3. Open a draft pull request with exact test evidence and limitations.
4. Do not merge until all checks pass and review finds no material issue.

## Completion boundary

Completion of this plan means only that the bounded mechanism has fresh repository evidence. It does not mean:

- the historical reviewer artifacts were admitted;
- C1 recovery was executed;
- issue #5 was fixed;
- C2 was started;
- STARCOM is a complete product.