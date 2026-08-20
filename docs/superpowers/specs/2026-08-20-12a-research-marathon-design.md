# 12A-LIVE Research Marathon Coordinator Design

## Outcome

Issue #65 adds a durable, self-hosted and fail-closed coordinator for the 12A-LIVE research marathon. The coordinator admits a signed exact-byte plan, persists immutable profile and partition memberships, and turns an authorized start into reclaimable durable outbox effects. It never performs source I/O, fetches, HTTP calls, or adapter dispatch.

The implementation is deliberately a coordinator boundary. It proves durable orchestration and evidence linkage; it does not claim that 800 identities were observed, that a live census is certified, or that an external integration exists.

## Exact-byte plan contract

The signed UTF-8 payload is canonical JSON with exactly these top-level keys:

```text
marathon_id
plan_version
c7_pack_id
campaign_id
source_profiles
partitions
minimum_identity_target
max_parallelism
request_timeout_seconds
retry_policy
coordinator_identity
coordinator_environment
reviewer_identity
reviewer_environment
planned_at_utc
independence_basis
state
gate_effect
```

The plan is admitted only when `plan_version` is `1.0.0`, `state` is `PLANNED_NOT_STARTED`, `gate_effect` is `12A_LIVE_RESEARCH_MARATHON_PLANNED_NO_NETWORK`, the C7 pack is clean and admitted as not released/not proven, the referenced campaign exists and has zero attempts/receipts/observations/cursors, there are at least 48 profiles and 240 partitions, and the identity target is at least 800.

Profiles are closed objects with exactly `profile_id`, `source_id`, `source_kind`, `source_ref`, `request_template`, `request_policy_digest`, and `enabled`. Profile IDs and source IDs are unique and sorted; source references are opaque data, never executed. Partitions are closed objects with exactly `partition_id`, `profile_id`, `partition_key`, and `request`. Partition IDs are unique and sorted, profile references resolve, and `(profile_id, partition_key)` is unique. Retry policy is a closed object containing `max_attempts`, `retry_delay_seconds`, and `backoff_multiplier`.

The coordinator and reviewer identities must be distinct and must not occur in the C7 independence exclusion set. The plan stores payload and signature bytes plus their SHA-256 digests. Ed25519 verification uses the configured Continuity trust root and the exact payload bytes.

## Persistence and invariants

`ResearchMarathonService` owns these tables:

* `research_marathons`: immutable plan and signature record, one row per marathon.
* `research_marathon_profiles`: immutable, ordinal, digest-bound profile membership.
* `research_marathon_partitions`: immutable, ordinal, digest-bound partition membership.
* `research_marathon_transitions`: append-only state transitions with monotonically increasing sequence and TrustPlane decision linkage.
* `research_marathon_partition_attempts`: durable outbox-attempt to `ResearchCampaign` attempt mapping.
* `research_marathon_completions`: immutable partition completion evidence and canonical result digest.

The plan admission event is `12A_RESEARCH_MARATHON_PLAN_ADMITTED` on `research:marathon:<marathon_id>`. State transitions are `PLANNED_NOT_STARTED`, `ACTIVE`, `PAUSED`, and `COMPLETE_PENDING_CERTIFICATION`. A plan can be admitted only once; conflicts never overwrite existing material.

## Authorized start

Start requires an allowed TrustPlane decision for action `research.marathon.start` and resource `research:marathon:<marathon_id>`. The decision context must be exactly the pack ID, campaign ID, plan digest, profile count, partition count, target 800, and configured parallelism. The transaction revalidates the C7 pack, plan, and empty campaign, appends the `ACTIVE` transition, and enqueues exactly one effect per partition in one database transaction. Effect IDs are `research:marathon:<marathon_id>:partition:<partition_id>` and the topic is isolated as `research.marathon.partition:<marathon_id>`. No source code path is called during start.

## Worker/evidence boundary

`claim` only leases effects on the marathon topic while the marathon is `ACTIVE`. `begin_partition_attempt` validates the lease and calls `ResearchCampaign.begin_attempt` before any hypothetical worker request; its request key includes marathon, partition, and durable attempt number. The coordinator exposes no request transport.

`complete_partition` accepts only durable evidence already recorded through `ResearchCampaign`: every mapped attempt must have a receipt, at least one receipt must be `SUCCESS`, and every successful attempt must have a matching observation and cursor. The canonical partition result digest binds partition material, all attempts, receipts, observations, and cursors. The outbox effect is marked `SUCCEEDED` only in the same transaction as the completion proof.

Expired leases are recovered by the existing outbox and produce a fresh attempt number on the next claim. Missing receipts, mismatched leases, tampered membership, and conflicting idempotency material fail closed.

`close_pending_certification` moves to `COMPLETE_PENDING_CERTIFICATION` only after all 240 partitions have durable completion proofs, all effects are succeeded, and the underlying campaign verifier is clean. It never emits a census certificate.

## Independent verification and tests

`verify` reconstructs the exact payload, signature, trust root, C7 binding, campaign emptiness/proof, ordered memberships, transition/decision links, outbox effects and statuses, partition attempt mappings, ResearchCampaign evidence, and canonical completion digests. It returns defect codes rather than mutating state.

Tests deterministically build 48 profiles and 240 partitions and cover malformed plans, default-deny start, atomic effect fan-out, pre-request ledger ordering, success proof requirements, lease recovery, tampering, idempotence, and completion pending certification. Full repository verification remains the final gate: tests, bytecode compilation, secret scan, text style, manifest, hash-seed determinism, warnings-as-errors, CI, and Sonar.
