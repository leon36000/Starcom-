# C3 executor registry v4 implementation plan

## Goal

Implement issue #48 as a sovereign, exact-byte signed, explicitly enabled and terminally revocable executor registry. Preserve the worker boundary for issue #49.

## Task 1 — RED contract

Create:

- `src/starcom/executor_registry.py`
- `tests/test_executor_registry.py`
- `tests/test_executor_registry_hardening.py`
- `tests/test_executor_registry_idempotency.py`

Define the public enums, records, preparation, verification and attestation interfaces. The seam raises a deterministic not-implemented domain error.

Add 18 focused tests covering registration, qualifier root, qualification, enablement, revocation, idempotence and independent falsification. Confirm the 234 prior tests remain green and only registry behavior is red.

## Task 2 — descriptor registration

Implement closed descriptor validation and canonicalization, immutable descriptor/transition tables, exact `c3.executor.register` preparation, default-deny authorization verification, single-use consumption and append-only ledgering.

Prove exact replay and material conflict behavior.

## Task 3 — qualifier root

Implement exact Ed25519 public-key validation, fingerprint binding, deterministic `c3.executor.qualifier.accept` preparation, atomic acceptance and independent root verification.

No private key or implicit root acceptance is allowed.

## Task 4 — exact signed qualification

Implement duplicate-key-safe UTF-8 JSON parsing, closed field validation, signature verification over exact bytes, descriptor/proof binding, reviewer independence, chronology and atomic `c3.executor.qualify` consumption.

Store exact payload/signature bytes and end only in `C3_EXECUTOR_QUALIFIED_DISABLED`.

## Task 5 — enable and revoke

Implement separate exact preparations and mutations for:

- `c3.executor.enable`
- `c3.executor.revoke`

Enable only from qualified-disabled. Revoke from registered, qualified or enabled. Revocation is terminal. Exact replays are idempotent; changed material conflicts.

## Task 6 — verifier and attestation

Recompute descriptor/root/qualification/decision/consumption/transition/event/ledger invariants. Add read-only attestation for enabled identity, version, digest, sandbox and network compatibility.

Run every mutation test against targeted tampering of immutable rows, TrustPlane decisions/consumptions and ledger provenance.

## Task 7 — deterministic publication

Refresh `MANIFEST.sha256`, then require:

- focused registry suites
- exact total of 252 tests
- `scripts/verify_repo.py`
- compile
- secret scan
- text style
- full `PYTHONHASHSEED=7` rerun
- registry tests under warnings-as-errors and `-X dev`
- `git diff --check`

Publish through a bounded workflow only after exact RED reproduction. Open a documented PR with `Fixes #48`, require merge-virtual CI, merge with an expected head SHA and verify post-merge `main` before starting #49.

## Completion boundary

Completion proves the registry authority only. It does not register a production executor or authorize the worker to perform an external effect.
