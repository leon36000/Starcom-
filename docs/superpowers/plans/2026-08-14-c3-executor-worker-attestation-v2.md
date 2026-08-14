# Registry-attested C3 worker v2 implementation plan

## Goal

Implement issue #49 by requiring a fresh, enabled executor-registry attestation before every possible adapter effect, including every recovered lease.

## Task 1 — RED integration contract

Create `tests/test_executor_worker_attestation.py` with a real database, durable execution service and merged `C3ExecutorRegistry`.

Generate an ephemeral Ed25519 qualifier key and explicitly drive a deterministic fake executor through registered, qualified, enabled and revoked states.

Add twelve focused tests:

1. missing registration
2. registered-disabled
3. qualified-disabled
4. enabled success
5. revoked after execution admission
6. wrong implementation version
7. wrong implementation digest
8. unsupported sandbox
9. network request under `DENY`
10. dirty registry
11. crash/recovery re-attests and preserves one effect
12. post-crash revocation triggers compensating rollback, never false no-effect

Before implementation, all focused failures must be causally attributable to the worker lacking the registry dependency/attestation gate. The 259 prior tests remain green.

## Task 2 — runtime identity contract

Modify `C3AdoptionExecutor` to require `implementation_version` and `implementation_digest`.

Give `DisabledC3AdoptionExecutor` fixed disabled values. Update deterministic test executors with stable fixture identity material.

## Task 3 — pre-effect registry gate

Inject one `C3ExecutorRegistry` into `C3AdoptionExecutionWorker`.

After immutable request verification and executor-ID comparison, but before `RUNNING`, call `registry.attest()` with exact runtime identity, sandbox and network requirement.

For requested-not-executed state, any registry domain failure terminalizes `FAILED_NO_EFFECT` with zero adapter calls.

## Task 4 — recovered RUNNING safety

Re-attest on every claimed lease. If registry attestation fails while the domain request is already `RUNNING`, treat the prior effect as uncertain and invoke rollback with `execution_result=None`.

Persist `FAILED_ROLLED_BACK` or `ROLLBACK_FAILED` and complete the outbox handler only after the terminal transition is durable.

## Task 5 — preserve existing execution tests

Add a bounded deterministic test attestor to `tests/test_adoption_execution.py`. It accepts only the existing fixture executor identity, version, digest, sandbox and network-deny plan.

Pass that attestor to all existing worker tests. Adapt hardening tests to use the same fixture. Do not weaken any execution, rollback, crash or falsification assertion.

## Task 6 — deterministic verification

Refresh `MANIFEST.sha256` and require:

- twelve new attestation tests
- existing ten execution tests
- existing six execution hardening tests
- exact full count of 271 tests
- repository verification
- compile
- secret scan
- text style
- full alternate hash-seed run
- all execution/attestation tests under warnings-as-errors and `-X dev`
- `git diff --check`

## Task 7 — publication

Publish through a bounded workflow that reproduces the exact RED SHA, applies the production and fixture patch once, runs every gate and creates `fix/c3-executor-worker-attestation-v2`.

Open a documented PR with `Fixes #49`, require merge-virtual CI, lock the merge to the exact head SHA and verify post-merge `main` before proceeding.

## Completion boundary

Completion proves registry enforcement around deterministic local test executors. It does not register a production executor or perform a real external adoption.
