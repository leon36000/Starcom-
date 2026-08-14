# Durable C3 adoption execution authority

**Date:** 2026-08-14
**Issue:** #46
**Status:** implementation-ready

## Purpose

STARCOM already separates a signed C3 qualification decision from a later adoption authorization. The adoption authority produces only `C3_ADOPTION_AUTHORIZED_NOT_EXECUTED` and exposes no execution method.

This design adds a third, separately authorized authority that may execute the selected adoption through the existing durable outbox. Admission and external effect handling remain separate. No production executor is enabled by default.

## Chosen architecture

Execution uses two phases:

1. `C3AdoptionExecutionService.request_execution()` verifies an existing adoption authorization, verifies a new exact TrustPlane decision for `c3.adoption.execute`, consumes that decision, persists an immutable execution request and enqueues one durable outbox effect in the same database transaction.
2. `C3AdoptionExecutionWorker.process_next()` claims the effect through the existing lease protocol, re-verifies the request, invokes an injected idempotent executor and writes append-only execution transitions and receipts.

The existing `DurableOutbox` remains the sole queue, lease, retry and idempotency authority. It gains one `enqueue_in_transaction()` primitive containing the current enqueue logic; the public `enqueue()` becomes a transaction-owning wrapper around that primitive.

## Closed execution plan

The execution plan is a JSON object with exactly:

- `component_ref`: non-empty component reference;
- `source_digest`: lowercase SHA-256 of the source package or immutable source descriptor;
- `target_environment`: non-empty environment identity;
- `sandbox_profile`: non-empty sandbox/policy profile;
- `preconditions`: non-empty list of non-empty strings;
- `postconditions`: non-empty list of non-empty strings;
- `requires_network`: boolean;
- `network_allowlist`: list of non-empty strings, empty only when `requires_network` is false;
- `requires_separate_rollback_authorization`: exactly false because rollback is pre-authorized as a mandatory compensating action by the execution request.

The plan is canonicalized with STARCOM canonical JSON and bound by SHA-256.

## TrustPlane preparation

`prepare()` binds:

- execution ID;
- adoption ID and C3 run ID;
- signed C3 decision ID;
- selected candidate artifact ID and immutable material digest;
- adoption rollback-plan digest;
- decision payload digest and qualification head;
- executor ID;
- execution-plan digest;
- outbox effect ID;
- stable adapter idempotency key.

The exact request is:

- action: `c3.adoption.execute`;
- resource: `continuity:c3:<run>:adoption:<adoption>:execution:<candidate>`;
- mission ID: the C3 run;
- context: all bound identifiers and digests plus `execution_mode=DURABLE_OUTBOX_SEPARATE_WORKER`.

Preparing the request has no side effect and creates no TrustPlane rule, decision, consumption, execution row or outbox effect.

## Persistence

### `c3_adoption_execution_requests`

One immutable request per execution ID, adoption ID and outbox effect ID. It stores exact identifiers, plan JSON/digest, executor ID, TrustPlane decision, outbox effect, request actor/time, the request ledger event and hash.

### `c3_adoption_execution_transitions`

Append-only status transitions with monotonically increasing sequence per execution. Each row stores:

- status;
- worker identity when applicable;
- effect-started flag;
- canonical execution receipt and digest when available;
- canonical rollback receipt and digest when available;
- normalized error text when applicable;
- timestamp;
- transition ledger event and hash.

Both tables use no-update and no-delete triggers.

## Status model

Closed statuses:

- `C3_ADOPTION_EXECUTION_REQUESTED_NOT_EXECUTED`
- `C3_ADOPTION_EXECUTION_RUNNING`
- `C3_ADOPTION_EXECUTION_SUCCEEDED`
- `C3_ADOPTION_EXECUTION_FAILED_NO_EFFECT`
- `C3_ADOPTION_EXECUTION_FAILED_ROLLED_BACK`
- `C3_ADOPTION_EXECUTION_ROLLBACK_FAILED`

Only the last four are terminal. `ROLLBACK_FAILED` explicitly covers an effect whose final state is unsafe or uncertain; it can never be interpreted as successful adoption.

## Executor contract

`C3AdoptionExecutor` is injected into the worker and exposes:

- `executor_id`;
- `validate(request)` before any effect;
- `execute(request)` using the request's stable idempotency key;
- `rollback(request, execution_result, reason)` using the same idempotency domain.

An execution result declares:

- whether the business operation succeeded;
- whether an effect began;
- pre-state digest;
- post-state digest when known;
- a structured canonical receipt;
- an optional normalized error.

A rollback result declares success/failure, restored-state digest when known, a structured receipt and an optional error.

`DisabledC3AdoptionExecutor` is the default fail-closed implementation. Its validation rejects before effect. No production adapter is registered in this slice.

## Admission transaction

`request_execution()` performs all immutable validations before and inside one database transaction:

1. validate IDs and closed execution plan;
2. verify the adoption authorization independently;
3. verify the selected candidate and signed decision bindings;
4. verify the exact TrustPlane execution decision and chronology;
5. reject prior consumption, competing execution or material conflict;
6. repeat adoption and TrustPlane verification inside the transaction;
7. consume the execution decision;
8. append the execution-request ledger event;
9. insert the immutable request and initial transition;
10. call `DurableOutbox.enqueue_in_transaction()` with the exact effect ID, topic, payload and idempotency material.

The executor is never called from admission.

Exact replay of identical material returns the existing clean request. Reusing any identity with different material fails closed.

## Worker protocol

The worker claims only topic `c3.adoption.execute` from the durable outbox.

Before effect it verifies:

- outbox payload and effect/request identity;
- immutable execution request;
- adoption authorization;
- TrustPlane decision and consumption;
- current transition history;
- executor ID and plan digest.

It appends `RUNNING`, calls `validate()` and then `execute()`.

Terminal handling:

- success: store execution receipt and `SUCCEEDED`;
- explicit failure before effect: store receipt and `FAILED_NO_EFFECT`;
- explicit failure after effect: mandatory rollback;
- execution exception: effect state is treated as uncertain and mandatory rollback is attempted with no trusted execution result;
- successful rollback: `FAILED_ROLLED_BACK`;
- failed or uncertain rollback: `ROLLBACK_FAILED`.

A business-terminal result marks the outbox message `SUCCEEDED` because the durable handler completed and persisted a terminal domain outcome. A lease or infrastructure failure before terminal persistence uses the outbox retry mechanism.

Crash replay uses the same effect ID and adapter idempotency key. Repeated `execute()` or `rollback()` calls must return the same adapter result and must not duplicate the effect.

## Independent verification

`verify_execution()` rechecks:

- request row immutability and closed plan contract;
- adoption verification and exact bound fields;
- TrustPlane decision, request, chronology and consumption;
- outbox effect topic, payload, status, attempts, result digest and ledger chain;
- request ledger provenance;
- contiguous transition sequence;
- allowed transition graph;
- transition event kind, payload, actor, time, hash and chain;
- execution and rollback receipt canonical JSON and SHA-256;
- terminal receipt requirements for each status;
- absence of false success when rollback failed or effect state is uncertain.

## Testing strategy

Tests use a real database, ledger, TrustPlane, continuity consumption table, adoption authorization service and durable outbox. Upstream signed-decision/adoption fixture construction may reuse existing deterministic helpers.

A deterministic fake executor records calls by idempotency key and supports:

- success;
- failure before effect;
- failure after effect plus successful rollback;
- failure after effect plus failed rollback;
- exception with uncertain effect plus rollback;
- stable replay after worker lease recovery.

Tests cover atomic admission, exact authorization, default deny, idempotency/conflicts, no adapter call during admission, double claim, stale worker, crash/retry, every terminal status, rollback enforcement and verifier tamper detection.

## Explicit non-goals

This slice does not:

- register a real package manager, installer, runtime or deployment executor;
- perform network access or external side effects;
- expose an execution CLI;
- claim a real component adoption;
- change `NO_COMPONENT_ADOPTION` or `NO_EXTERNAL_RUNTIME_INTEGRATED`;
- promote C3 or any canonical project status.
