# C5 exact-byte execution plan authority — design

## Goal

Add a C5ExecutionPlanService that admits and independently verifies one immutable, exact-byte signed master plan bound to a clean C4 architecture baseline. The admitted state is always C5_EXECUTION_PLAN_ADMITTED_NOT_STARTED; this component never starts, schedules, dispatches, executes, deploys, or promotes work.

## Scope and non-goals

In scope:

- reconstructing a deterministic snapshot from an admitted C4 baseline;
- validating a closed JSON contract and its nested work-item/policy/gate structures;
- validating sorted unique identifiers, SHA-256 digests, references, chronology, identity independence, and DAG acyclicity;
- verifying an Ed25519 signature over the exact payload bytes under an accepted Continuity trust root;
- atomically persisting the plan, work-item memberships, release-gate memberships, and a ledger event;
- exact replay idempotence and material-conflict rejection;
- independent verification of all stored material and the current C4 snapshot;
- one shared Runtime service instance.

Out of scope:

- creating TrustPlane rules, grants, or decisions implicitly;
- starting or running any work item;
- scheduling, dispatching, workers, executors, subprocesses, network access, deployment, release, or product promotion;
- declaring C5 globally complete or changing STARCOM’s external-evidence truth.

## Boundaries

src/starcom/execution_plan.py owns the C5 contract and persistence. It receives the existing Database, EventLedger, ContinuityService, and C4ArchitectureService graph; it does not open another database or create another trust root. Runtime.open() constructs it after the C4 architecture service and exposes it as Runtime.execution_plan plus the stable alias Runtime.c5_execution_plan.

The service surface is deliberately finite:

- snapshot(architecture_id) — read-only C4 snapshot reconstruction;
- prepare(plan_id, architecture_id, payload=None) — deterministic authorization context, no state change;
- admit_plan(architecture_id, key_id, payload, signature, actor, occurred_at=None) — exact-byte admission;
- get_plan(plan_id), get_work_items(plan_id), get_release_gates(plan_id) — immutable reads;
- verify_plan(plan_id) — independent verification.

Compatibility aliases prepare_plan, admit, get, verify, and verify_execution_plan may point only to the methods above. No execution method is present.

## Signed payload contract

The top-level JSON object has exactly these fields, with no duplicate keys and no extra or missing fields:

    plan_id
    plan_version
    architecture_id
    architecture_version
    architecture_payload_sha256
    c3_snapshot_digest
    work_items
    execution_policy
    release_gates
    risk_register_digest
    resource_model_digest
    verification_strategy_digest
    planner_identity
    planner_environment
    reviewer_identity
    reviewer_environment
    planned_at_utc
    independence_basis
    execution_status
    gate_effect

The constants are:

    plan_version = 1.0.0
    architecture_version = 3.2.0
    execution_status = NOT_STARTED
    gate_effect = C5_EXECUTION_PLAN_ADMITTED_NOT_STARTED

Each work_items entry has exactly:

    work_item_id, phase, title, owner_role, dependencies, input_digests,
    outputs, acceptance_checks, risk_level, human_gate_required

work_item_id values are unique and the array is sorted by ID. dependencies, input_digests, outputs, and acceptance_checks are sorted, duplicate-free lists; input values are lowercase SHA-256 digests, while outputs and checks are non-empty strings. Dependencies must refer to existing work items, never self-reference, and form an acyclic directed graph. Risk levels are LOW, MEDIUM, HIGH, or CRITICAL.

execution_policy has exactly:

    max_parallelism, fail_closed, require_proof,
    stop_on_verification_failure, human_gate_actions

max_parallelism is a positive integer; the three booleans are all true; human_gate_actions is a sorted, duplicate-free list of non-empty strings.

Each release_gates entry has exactly:

    gate_id, title, required_work_item_ids, proof_digests, human_gate_required

Gate IDs are unique and sorted; required work-item references and proof digests are sorted and duplicate-free. At least one gate is required, each gate references existing work items, and each gate carries at least one valid proof digest.

independence_basis has exactly excluded_identities and statement. The exclusion list is sorted and duplicate-free and must equal all material C4/C3 identities observed by the snapshot. Planner and reviewer identities are distinct from each other and from that exclusion set.

## C4 binding and chronology

snapshot(architecture_id) locates the C4 baseline by architecture ID or baseline ID, requires verify_baseline() to be clean, and rechecks the current C4 payload digest and C3 snapshot digest. The C5 snapshot digest commits to the baseline ID, architecture/version, payload digest, C3 snapshot digest, C4 admission time, C4 evidence time, and material identity set.

planned_at_utc must be strictly after every C4 evidence timestamp and the C4 baseline admission timestamp. Admission repeats snapshot construction, signature verification, and all payload checks inside the database transaction; a changed C4 snapshot aborts the transaction.

## Persistence and ledger

The service creates three immutable tables:

- c5_execution_plans — signed plan row, C4 binding, derived membership digests, identities, status, signature material, admission metadata, and ledger receipt;
- c5_execution_plan_work_items — ordered normalized work-item membership and material digest;
- c5_execution_plan_release_gates — ordered normalized gate membership and material digest.

Update and delete triggers protect all three tables. plan_id, architecture_id, and payload digest are unique. The admission event uses stream continuity:c5:execution-plan:<plan_id> and kind C5_EXECUTION_PLAN_ADMITTED. The event payload contains only stable IDs/digests/status and is checked against the stored row. Ledger chain verification is part of verify_plan().

An exact replay with the same plan ID, architecture ID, key, payload, signature, and actor returns the original record without a second event; a different plan, payload, key, signature, or actor conflicts closed.

## Verification matrix

verify_plan() reports defects rather than trusting the row. It rechecks:

1. stored binary/digest integrity and strict payload parsing;
2. accepted trust root and exact signature;
3. C4 baseline existence, cleanliness, payload digest, current C3 snapshot digest, and C5 freshness;
4. top-level and nested contract values, sorted orders, references, digests, policy constants, and DAG;
5. planner/reviewer independence and signed chronology;
6. work-item/gate row counts, ordinals, canonical JSON, material digests, bindings, and current membership material;
7. stored row-to-payload equality;
8. event stream, event kind, actor, timestamp, payload, receipt hash, and ledger chain.

Any malformed or stale upstream C4 state makes the C5 plan unverifiable.

## Test strategy

Use a real temporary SQLite graph with a clean C4 fixture and an ephemeral deterministic signature verifier. Tests must watch RED before production code, then cover:

- clean C4 snapshot and deterministic C5 preparation;
- default-deny trust root and exact-byte admission/replay;
- duplicate/extra/missing fields, invalid UTF-8, invalid digests, wrong constants, unsorted/duplicate lists, missing references, self-edge, and cyclic DAG;
- invalid execution policy, empty gates, missing proof, and broken gate references;
- planner/reviewer collisions with C4/C3 identities and pre-C4 chronology;
- immutable row/membership tampering and stale/dirty C4 rejection;
- signature or whitespace mutation, event/chain tampering, and material conflicts;
- absence of forbidden execution surface and shared Runtime wiring.
