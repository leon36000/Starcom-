# Registry-attested C3 worker implementation plan

## Goal

Require a fresh, clean, enabled executor-registry attestation before every C3 worker effect while preserving durable crash recovery and mandatory rollback semantics.

## Scope

Modify only the worker/executor contract and focused execution tests. Do not register or enable production executors, expose a worker CLI, access the network, or promote canonical project state.

## Task 1: establish exact RED

- Use the 12 tests in `tests/test_executor_worker_attestation.py`.
- Confirm the existing 259 tests remain green.
- Confirm the failures are isolated to the missing registry dependency and runtime attestation fields.

## Task 2: extend the executor contract

- Add `implementation_version` and `implementation_digest` to `C3AdoptionExecutor`.
- Give `DisabledC3AdoptionExecutor` explicit disabled identity material.
- Require a `C3ExecutorRegistry` instance in `C3AdoptionExecutionWorker`.
- Update pre-existing deterministic execution fixtures to inject an explicit bounded registry double.

## Task 3: attest before RUNNING

For every claimed outbox lease:

1. verify the immutable execution request;
2. verify exact executor identity;
3. call `registry.attest()` with version, digest, sandbox and network requirements;
4. only after a clean attestation append `RUNNING` and call `validate()`.

A missing, disabled, revoked, dirty or mismatched executor must terminate `FAILED_NO_EFFECT` before any adapter call.

## Task 4: preserve uncertain-effect rollback

When a recovered request is already `RUNNING`, a new attestation failure cannot be declared no-effect. The worker must:

- treat effect state as uncertain;
- attempt idempotent rollback with the same execution idempotency key;
- record `FAILED_ROLLED_BACK` on success;
- record `ROLLBACK_FAILED` on failure or rollback exception;
- never call `execute()` again after the failed attestation.

## Task 5: verify and publish

- Run the 10 existing execution tests.
- Run the 6 existing execution hardening tests.
- Run the 12 new worker-attestation tests.
- Require 271/271 repository tests.
- Regenerate and verify `MANIFEST.sha256`.
- Run compile, secret scan, text policy, alternate hash seed, warnings-as-errors and `git diff --check`.
- Publish a clean feature branch through a bounded workflow.
- Require merge-virtual CI, exact head SHA, merge, and post-merge CI before starting issue #50.
