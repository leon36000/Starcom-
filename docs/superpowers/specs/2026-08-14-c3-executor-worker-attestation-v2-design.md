# Registry-attested C3 execution worker v2

**Date:** 2026-08-14
**Issue:** #49
**Status:** implementation-ready

## Purpose

The durable C3 execution authority can safely admit and replay an external effect, but the worker currently trusts an injected object after comparing only `executor_id`. The worker must require a fresh attestation from the independently verified executor registry before every possible effect.

This slice links the already merged authorities from #46 and #48. It does not mutate the registry and does not register a production executor.

## Runtime executor identity

`C3AdoptionExecutor` requires exactly these immutable runtime identity attributes in addition to its methods:

- `executor_id`
- `implementation_version`
- `implementation_digest`

`DisabledC3AdoptionExecutor` exposes fixed disabled identity material and remains unregistered.

`C3AdoptionExecutionWorker` receives one `C3ExecutorRegistry` instance. It never creates, qualifies, enables or revokes an executor.

## Pre-effect gate

For a newly requested execution, after claiming the durable lease and verifying the immutable execution request, the worker performs:

1. exact executor ID comparison;
2. registry `attest()` using runtime version/digest;
3. sandbox profile from the signed execution plan;
4. `requires_network` from the signed execution plan;
5. exact enabled and non-revoked registry state.

Only a successful attestation permits the `RUNNING` transition and `executor.validate()`.

A domain failure before the first `RUNNING` transition produces `C3_ADOPTION_EXECUTION_FAILED_NO_EFFECT`, completes the durable handler with a terminal result digest and calls none of `validate`, `execute` or `rollback`.

The receipt contains no key bytes or secrets. It binds phase, requested/observed identity, version, digest, sandbox, network requirement, stable idempotency key and normalized error type/message.

## Recovered RUNNING executions

A recovered lease whose domain status is already `RUNNING` may represent an effect that began before a crash. The worker still re-attests the registry before retry.

If re-attestation succeeds, normal idempotent execution replay continues with the same adapter idempotency key.

If re-attestation fails while the request is already `RUNNING`, the worker must not report `FAILED_NO_EFFECT`. It treats the previous effect as uncertain and invokes the pre-authorized compensating rollback duty with `execution_result=None`:

- successful rollback -> `C3_ADOPTION_EXECUTION_FAILED_ROLLED_BACK`
- failed or uncertain rollback -> `C3_ADOPTION_EXECUTION_ROLLBACK_FAILED`

Registry revocation blocks new effects but does not erase the mandatory rollback duty for an uncertain prior effect.

## Failure taxonomy

Before first RUNNING, these conditions are terminal no-effect:

- executor absent from registry
- registered but disabled
- qualified but disabled
- revoked
- registry verification dirty
- wrong implementation version
- wrong implementation digest
- unsupported sandbox
- network requested under `DENY`
- injected executor ID mismatch

Unknown infrastructure/programming exceptions are not converted into a false domain result; the lease remains recoverable.

## Retry guarantees

Attestation occurs on every claim, including after lease recovery. No attestation result is cached. The executor receives the same stable idempotency key on every replay.

## Test strategy

A real registry is used for integration tests. Tests generate an ephemeral Ed25519 qualifier key and explicitly perform:

- registration
- qualifier-root acceptance
- exact signed qualification
- separate enablement
- optional revocation

Twelve focused tests cover all pre-effect states, exact runtime mismatch cases, sandbox/network policy, dirty registry, enabled success, crash/retry attestation count and post-crash revocation rollback.

Existing execution behavior tests retain their focus through a bounded test attestor that only accepts the deterministic fixture identity. Production code accepts only the real `C3ExecutorRegistry` interface.

## Non-goals

This slice does not:

- register or enable a production executor
- add an executor or worker CLI
- perform network access
- execute a real component
- change `NO_COMPONENT_ADOPTION` or `NO_EXTERNAL_RUNTIME_INTEGRATED`
- promote canonical project status
