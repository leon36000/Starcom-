# C1 Recovery Publication Implementation Plan

> Execute on `feature/c1-recovery-publication` with RED -> GREEN -> REFACTOR and fresh GitHub Actions evidence.

**Goal:** implement a fail-closed, ledgered protocol for admitting signed independent Task 5 reviews and explicitly publishing the `RECOLLECT_REQUIRED` recovery state.

**Architecture:** `ContinuityService` coordinates SQLite persistence, `TrustPlane` decisions, `EventLedger` receipts, and an injected signature verifier. `OpenSSLEd25519Verifier` is the production verifier. No historical artifact is treated as present unless its exact bytes are admitted.

**Tech:** Python 3.11+, SQLite, standard library, OpenSSL command line, `unittest`.

---

## Task 1: Establish RED protocol tests

**Create:** `tests/test_continuity.py`

1. Add fixture helpers that generate an ephemeral Ed25519 keypair with OpenSSL and sign exact JSON bytes.
2. Add failing tests for incident creation, default-denied trust-root acceptance, allowed acceptance, signed review admission, tamper rejection, recovery authorization, idempotency, conflicts, and verification defects.
3. Update `MANIFEST.sha256` so the repository fails for missing production behavior rather than only an unlisted file.
4. Push the RED commit and retain the failed GitHub Actions run as evidence.

## Task 2: Implement the signature verifier

**Create:** `src/starcom/continuity.py`

1. Add closed enums and immutable result dataclasses.
2. Add `SignatureVerifier` protocol.
3. Implement `OpenSSLEd25519Verifier` with bounded inputs, temporary files, no shell, timeout, and fail-closed validation errors.
4. Run the focused tests; signature tests must turn GREEN while service tests remain RED.

## Task 3: Implement persistence and trust-root admission

**Modify:** `src/starcom/continuity.py`

1. Create incidents, trust roots, reviews, publications, and authorization-consumption tables.
2. Add immutable triggers for all append-only records.
3. Implement exact Trust Plane decision validation and single-use consumption.
4. Implement incident creation and trust-root acceptance with ledger receipts and idempotency.
5. Run focused tests.

## Task 4: Implement signed review admission

**Modify:** `src/starcom/continuity.py`

1. Parse and validate the historical Task 5 disposition fields.
2. Verify exact bytes with the accepted reviewer key.
3. Store payload and signature BLOBs plus SHA-256 digests.
4. Ledger only bounded metadata and digests.
5. Implement identical replay and conflicting replay behavior.
6. Run focused tests.

## Task 5: Implement explicit recovery publication

**Modify:** `src/starcom/continuity.py`

1. Require an admitted eligible `RECOLLECT_REQUIRED` review.
2. Require an allowed, untampered, exact-match Trust Plane decision.
3. Atomically insert the publication, consume authorization, append the ledger event, and transition the incident to `RECOVERY_PUBLISHED_RECOLLECT_REQUIRED`.
4. Preserve disposition semantics and prohibit automatic C2 start.
5. Add idempotent replay and conflict checks.
6. Run focused tests.

## Task 6: Implement independent state verification

**Modify:** `src/starcom/continuity.py`

1. Recompute public-key, payload, and signature digests.
2. Re-run Ed25519 verification.
3. Validate stored review fields and publication eligibility.
4. Cross-check Trust Plane decisions and all ledger events.
5. Detect status/publication disagreement and tampering.
6. Run focused and full tests.

## Task 7: Update package documentation and manifest

**Modify:** `README.md`, `docs/status/CANONICAL-STATE.md`, `MANIFEST.sha256`

1. Document the implemented protocol without claiming historical artifact admission or C1 completion.
2. Record the exact remaining blocker: missing sealed public reviewer artifacts in this repository.
3. Rebuild the deterministic manifest.
4. Run `python scripts/verify_repo.py` through GitHub Actions.

## Task 8: Review and publish

1. Inspect the complete diff for scope, security, and truth-boundary errors.
2. Run fresh full verification on the final head.
3. Open a draft pull request with exact test evidence and limitations.
4. Do not merge until all checks pass and review finds no material issue.