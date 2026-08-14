# Registry-attested C3 worker design v2

**Issue:** #49  
**Base:** `main` after executor registry PR #53  
**Truth boundary:** no production executor, no real adoption, no worker CLI.

## Fresh-attestation invariant

A claimed durable C3 execution effect may reach `RUNNING` only after a fresh `C3ExecutorRegistry.attest()` succeeds for the injected executor's exact ID, implementation version, implementation digest, requested sandbox profile, and network requirement.

The worker does not register, qualify, enable, or revoke executors. It only reads and verifies the existing sovereign registry.

## First-claim failure

When the current execution state is `REQUESTED_NOT_EXECUTED`, any identity or registry failure is a proven pre-effect failure:

- terminal state: `C3_ADOPTION_EXECUTION_FAILED_NO_EFFECT`;
- `effect_started = false`;
- zero calls to `validate`, `execute`, or `rollback`;
- canonical receipt phase `executor-registry-attestation` or `executor-selection`.

## Recovered RUNNING failure

When the current execution state is already `RUNNING`, a previous worker may have begun an external effect before crashing. A later registry failure, including revocation, must not be labeled no-effect.

The recovered worker therefore:

- does not call `execute()` again;
- attempts idempotent rollback using the same request and idempotency key;
- records a canonical uncertain-effect execution receipt;
- records `FAILED_ROLLED_BACK` if rollback succeeds;
- records `ROLLBACK_FAILED` if rollback fails or raises;
- preserves the outbox terminal result digest and independent execution verifier.

## Runtime identity contract

`C3AdoptionExecutor` exposes:

- `executor_id`
- `implementation_version`
- `implementation_digest`

`DisabledC3AdoptionExecutor` exposes explicit disabled values but remains unregistered and therefore fail-closed.

## Error receipt

The pre-effect receipt contains only non-secret material:

- phase;
- requested and observed executor IDs;
- observed implementation version and digest;
- sandbox profile;
- network requirement;
- stable adapter idempotency key;
- normalized exception type and bounded message.

No qualifier public key, signed payload, signature, secret, token, or private material is copied into worker receipts.
