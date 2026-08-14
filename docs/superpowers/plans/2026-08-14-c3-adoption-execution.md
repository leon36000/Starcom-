# C3 adoption execution implementation plan

## Goal

Implement issue #46 as a separate, fail-closed execution authority using the existing durable outbox. Preserve the current adoption authorization boundary and keep every real executor disabled by default.

## Task 1: extend the existing outbox transaction seam

Files:

- modify `src/starcom/durable.py`;
- modify `tests/test_durable.py`.

Steps:

1. Add a RED test proving `enqueue_in_transaction()` participates in a caller-owned transaction and rolls back with the caller.
2. Add a RED test proving `enqueue()` and `enqueue_in_transaction()` share identical idempotency/conflict behavior.
3. Move the current enqueue implementation into `enqueue_in_transaction(connection, ...)`.
4. Keep `enqueue()` as a thin `with database.transaction()` wrapper.
5. Run focused durable tests, full verification and manifest refresh.

## Task 2: define execution types and RED service seam

Files:

- add `src/starcom/adoption_execution.py`;
- add `tests/test_adoption_execution.py`.

Steps:

1. Define closed enums/dataclasses/protocols:
   - statuses;
   - preparation;
   - request/current record;
   - executor result;
   - rollback result;
   - verification;
   - executor protocol;
   - disabled executor.
2. Add a RED `C3AdoptionExecutionService` seam with `prepare`, `request_execution`, `get_execution` and `verify_execution`.
3. Build deterministic upstream C3/adoption fixture using existing service-level helpers.
4. Prove RED only for new execution behavior while prior tests stay green.

## Task 3: implement atomic admission

Files:

- modify `src/starcom/adoption_execution.py`;
- extend `tests/test_adoption_execution.py`.

Steps:

1. Create immutable request and transition tables/triggers.
2. Implement exact closed-plan validation/canonicalization.
3. Implement deterministic TrustPlane preparation.
4. Verify adoption, selected candidate and signed decision bindings.
5. Verify exact execution authorization and chronology.
6. Consume authorization, append request/initial transition and enqueue outbox effect in one transaction.
7. Implement exact replay and conflict rejection.
8. Test default deny, wrong actor/resource/mission/context, stale adoption, reuse and transaction race rechecks.
9. Prove admission never calls an executor.

## Task 4: implement worker and fake executor tests

Files:

- modify `src/starcom/adoption_execution.py`;
- extend `tests/test_adoption_execution.py`.

Steps:

1. Implement `C3AdoptionExecutionWorker` using `DurableOutbox.claim()`.
2. Re-verify request before effect and append `RUNNING`.
3. Implement success and every fail-closed terminal path.
4. Attempt rollback after any post-effect failure or uncertain exception.
5. Persist canonical receipts/digests and terminal ledger events.
6. Mark the outbox handler successful only after terminal domain persistence.
7. Use outbox failure/retry for infrastructure failure before terminal persistence.
8. Test success, no-effect failure, rolled-back failure, rollback failure and uncertain exception.
9. Test disabled executor and executor-ID mismatch.

## Task 5: prove crash, lease and idempotency behavior

Files:

- extend `tests/test_adoption_execution.py`.

Steps:

1. Simulate a claimed lease expiring before terminal completion.
2. Recover the lease through the existing outbox.
3. Re-run the worker with the same adapter idempotency key.
4. Prove no duplicate effect and one terminal outcome.
5. Prove stale worker completion cannot alter the outbox.
6. Prove double claim remains impossible.

## Task 6: independent verifier falsification

Files:

- extend `tests/test_adoption_execution.py`.

Tamper independently with:

- request plan/digest;
- adoption ID/candidate binding;
- TrustPlane decision or consumption;
- outbox topic/payload/effect identity/result digest;
- transition sequence/status/actor/time/payload/hash;
- execution receipt;
- rollback receipt;
- terminal status versus receipt semantics.

Each mutation must produce a precise verifier defect and must never be interpreted as successful execution.

## Task 7: repository verification and publication

1. Refresh `MANIFEST.sha256`.
2. Run focused tests.
3. Run the complete suite with an exact expected count.
4. Run `scripts/verify_repo.py`.
5. Run compile, secret scan and text-style policy.
6. Run a full suite with a fixed alternate `PYTHONHASHSEED`.
7. Run focused execution tests with warnings-as-errors and `-X dev`.
8. Run `git diff --check`.
9. Publish a bounded product branch only after all gates pass.
10. Open a draft PR with RED/GREEN evidence and the no-real-adoption truth boundary.
11. Require merge-virtual CI and exact head SHA.
12. Merge and require post-merge CI on `main`.

## Completion boundary

The task is complete only when the durable execution authority, disabled executor, deterministic fake-executor tests and independent verifier are merged and post-merge green.

It is not permission to execute a real component. A real executor adapter remains separate work and must undergo its own qualification, authorization, sandbox, rollback and proof gates.
