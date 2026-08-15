# Immutable C4 architecture foundation

**Date:** 2026-08-14
**Issue:** #59
**Status:** implementation-ready

## Purpose

C4 produces the target STARCOM v3.2 architecture only after C3 evidence is frozen and independently verifiable. The current repository contains no C4 input-set or candidate authority, while the later review and publication issues require both.

This design adds two sovereign, append-only authorities:

1. `C4ArchitectureInputService` freezes a deterministic set of clean terminal C3 execution evidence.
2. `C4ArchitectureCandidateService` creates one immutable, explicitly authorized architecture v3.2 candidate from that input set.

The candidate remains `C4_ARCHITECTURE_CANDIDATE_NOT_REVIEWED`. This slice performs no independent review, publication, deployment, runtime integration or canonical status promotion.

## Architectural boundaries

The two services share only explicit public contracts.

`C4ArchitectureInputService` depends on:

- `Database`
- `EventLedger`
- `TrustPlane`
- `ContinuityService`
- a `C4ExecutionEvidenceSource` protocol implemented by `C3AdoptionExecutionService`

`C4ArchitectureCandidateService` depends on:

- `Database`
- `EventLedger`
- `TrustPlane`
- `ContinuityService`
- `C4ArchitectureInputService`

Neither service invokes an executor, worker, package manager, network adapter or publication authority.

## C3 evidence source contract

The input service consumes this minimal protocol:

```python
class C4ExecutionEvidenceSource(Protocol):
    def get_execution(self, execution_id: str) -> C3AdoptionExecutionRecord: ...
    def verify_execution(
        self, execution_id: str
    ) -> C3AdoptionExecutionVerification: ...

    @staticmethod
    def terminal_result_digest(record: C3AdoptionExecutionRecord) -> str: ...
```

Using a protocol keeps the C4 authority independently testable while the production runtime injects the real `C3AdoptionExecutionService`.

## C4 input set

### Eligibility

An input set contains a non-empty, lexicographically sorted and duplicate-free list of execution IDs.

Every member must:

- exist;
- pass `verify_execution()` with zero defects;
- be terminal;
- have a terminal result digest matching the frozen material.

Allowed terminal statuses:

- `C3_ADOPTION_EXECUTION_SUCCEEDED`
- `C3_ADOPTION_EXECUTION_FAILED_NO_EFFECT`
- `C3_ADOPTION_EXECUTION_FAILED_ROLLED_BACK`

`C3_ADOPTION_EXECUTION_ROLLBACK_FAILED` is rejected because the external state is unsafe or uncertain.

At least one member must be `SUCCEEDED`. Failed-no-effect and failed-rolled-back executions may remain as negative evidence but can never become active component bindings.

### Frozen member

Each ordered member freezes exactly:

- `execution_id`
- `adoption_id`
- `c3_run_id`
- `c3_decision_id`
- `candidate_artifact_id`
- `candidate_material_sha256`
- `decision_payload_sha256`
- `qualification_head_hash`
- `executor_id`
- `execution_plan_sha256`
- `authorization_decision_id`
- terminal `status`
- `execution_receipt_sha256`
- `rollback_receipt_sha256`
- `effect_started`
- normalized `error`
- `requested_at`
- `requested_by`
- `transition_sequence`
- `terminal_result_digest`

The author-identity set is the sorted, duplicate-free set of non-empty `requested_by` identities. It is frozen on the input-set row for later independent-review separation.

### Canonical digest

`input_set_digest` is:

```python
sha256_digest(list(ordered_member_mappings))
```

No database row ID, ledger event ID or wall-clock freeze timestamp enters this digest.

### Preparation

```python
C4ArchitectureInputService.prepare_freeze(
    input_set_id: str,
    execution_ids: Sequence[str],
) -> C4ArchitectureInputPreparation
```

The result contains:

- input-set ID;
- ordered execution IDs;
- member count;
- success count;
- negative-evidence count;
- input-set digest;
- author identities;
- exact action, resource, mission and context.

TrustPlane contract:

- action: `c4.architecture-input.freeze`
- resource: `continuity:c4:architecture-input:<input_set_id>`
- mission: `c4-architecture:<input_set_id>`

The context binds all preparation fields and `gate_effect=C4_ARCHITECTURE_INPUT_FROZEN_NO_CANDIDATE`.

Preparation is read-only.

### Freeze transaction

```python
C4ArchitectureInputService.freeze(
    input_set_id: str,
    execution_ids: Sequence[str],
    *,
    authorization_decision_id: str,
    actor: str,
    occurred_at: str | None = None,
) -> C4ArchitectureInputSet
```

Before and inside one transaction the service:

1. rebuilds the preparation;
2. verifies the exact TrustPlane decision;
3. enforces decision chronology;
4. rejects prior decision consumption or competing material;
5. consumes the decision as `C4_ARCHITECTURE_INPUT_FROZEN`;
6. appends `C4_ARCHITECTURE_INPUT_FROZEN` on `continuity:c4:architecture-input:<input_set_id>`;
7. inserts the immutable input-set row;
8. inserts contiguous ordered membership rows.

Exact replay of identical IDs, authorization, actor and material returns the existing clean record. Any material difference is a conflict.

## C4 architecture candidate

### Top-level manifest

The canonical JSON object has exactly:

- `architecture_id`
- `architecture_version`
- `title`
- `authority_adrs`
- `ports`
- `mission_fabric`
- `component_bindings`
- `vertical_benchmark`
- `non_functional_requirements`
- `gate_effect`

Closed values:

- `architecture_version = 3.2`
- `gate_effect = C4_ARCHITECTURE_CANDIDATE_NOT_REVIEWED`

The manifest is supplied as a mapping, normalized, serialized with `canonical_json()` and hashed with `sha256_digest()`.

### Authority ADR contract

Every ADR has exactly:

- `adr_id`
- `title`
- `decision`
- `rationale`
- `authority_owner`
- `affected_port_ids`
- `evidence_execution_ids`

ADRs are ordered by `adr_id`. IDs are unique. String lists are sorted and duplicate-free. Every evidence execution belongs to the frozen input set.

Every port must appear in at least one ADR whose `authority_owner` exactly equals that port's owner.

### Sovereign port contract

Every port has exactly:

- `port_id`
- `capability_id`
- `owner_authority`
- `contract_digest`
- `test_ids`
- `proof_ids`

Ports are ordered by `port_id`. Port IDs and capability IDs are unique. The contract digest is lowercase SHA-256. Test and proof lists are non-empty, sorted and duplicate-free.

This directly enforces capability → port → test → proof.

### Universal Computer Mission Fabric

`mission_fabric` is an object with exactly these keys:

- `RESEARCH`
- `ARTIFACT`
- `ACTION`
- `MONITOR`

Each value is a non-empty, sorted, duplicate-free list of existing port IDs. Every declared port appears in at least one stage.

### Component bindings

Every binding has exactly:

- `binding_id`
- `execution_id`
- `candidate_artifact_id`
- `candidate_material_sha256`
- `port_ids`
- `capability_ids`

Bindings are ordered by `binding_id` and unique.

Each binding must reference a frozen `SUCCEEDED` execution. Candidate ID and digest must match the frozen member. `port_ids` must exist. `capability_ids` must exactly equal the sorted set of capabilities owned by those ports.

Every frozen successful execution appears in exactly one active binding. Negative evidence cannot be actively bound.

### Vertical benchmark

`vertical_benchmark` has exactly:

- `benchmark_id`
- `stage_order`
- `stage_test_ids`
- `stage_proof_ids`
- `end_to_end_test_id`
- `end_to_end_proof_id`

`stage_order` is exactly:

```json
["RESEARCH", "ARTIFACT", "ACTION", "MONITOR"]
```

`stage_test_ids` and `stage_proof_ids` contain exactly the four stage keys. Each stage list is non-empty, sorted and duplicate-free.

For each stage, the listed tests and proofs must be subsets of the union declared by that stage's ports. This proves a complete Research → Artifact → Action → Monitor chain without claiming the benchmark has executed.

### Non-functional requirements

Each NFR has exactly:

- `requirement_id`
- `category`
- `statement`
- `verification_method`
- `test_ids`
- `proof_ids`

NFRs are ordered by requirement ID. Lists are non-empty, sorted and duplicate-free.

### Candidate preparation

```python
C4ArchitectureCandidateService.prepare_create(
    candidate_id: str,
    *,
    input_set_id: str,
    manifest: Mapping[str, Any],
) -> C4ArchitectureCandidatePreparation
```

The service requires a clean input set and a valid manifest. The preparation binds:

- candidate ID;
- architecture ID and version;
- input-set ID and digest;
- manifest SHA-256;
- counts of ADRs, ports, bindings and NFRs;
- exact stage order;
- status and gate effect;
- exact action, resource, mission and context.

TrustPlane contract:

- action: `c4.architecture-candidate.create`
- resource: `continuity:c4:architecture-candidate:<candidate_id>`
- mission: `c4-architecture:<architecture_id>`

Preparation is read-only.

### Candidate transaction

```python
C4ArchitectureCandidateService.create_candidate(
    candidate_id: str,
    *,
    input_set_id: str,
    manifest: Mapping[str, Any],
    authorization_decision_id: str,
    actor: str,
    occurred_at: str | None = None,
) -> C4ArchitectureCandidate
```

The transaction repeats input-set and manifest validation, verifies and consumes the exact decision, appends `C4_ARCHITECTURE_CANDIDATE_CREATED` and stores one immutable candidate.

One candidate ID and one architecture ID can each identify only one immutable candidate. Exact replay returns the existing clean record.

## Persistence

### `c4_architecture_input_sets`

Stores preparation summary, canonical author identities, authorization, freeze time/actor and ledger linkage.

### `c4_architecture_input_members`

Stores ordered frozen member JSON and member digest. Primary key `(input_set_id, ordinal)` plus unique `(input_set_id, execution_id)`.

### `c4_architecture_candidates`

Stores exact canonical manifest JSON, manifest SHA-256, architecture identifiers, input-set digest, status, authorization, creation time/actor and ledger linkage.

All three tables have no-update and no-delete triggers.

## Independent verification

### Input set verifier

`verify_input_set()` rechecks:

- row and membership schema;
- contiguous ordinals;
- member canonical JSON and digests;
- set count, success/negative counts, authors and input-set digest;
- every current C3 execution verification and exact frozen material;
- terminal-status policy;
- TrustPlane decision request, allow result and chronology;
- exact authorization consumption;
- ledger stream, kind, actor, timestamp, payload, row hash and chain.

### Candidate verifier

`verify_candidate()` rechecks:

- input-set verification;
- canonical manifest JSON and manifest SHA-256;
- closed nested schemas and all semantic links;
- stored counts and identifiers;
- status `C4_ARCHITECTURE_CANDIDATE_NOT_REVIEWED`;
- TrustPlane decision request, allow result and chronology;
- exact authorization consumption;
- ledger stream, kind, actor, timestamp, payload, row hash and chain.

Any later corruption of C3 evidence, input memberships, manifest, authorization or ledger makes the relevant verifier fail closed.

## Error behavior

- malformed IDs, lists, digests, timestamps or manifest fields: `ValidationError`;
- missing execution, input set or candidate: `NotFoundError`;
- dirty execution/input or cryptographic/provenance corruption: `IntegrityError`;
- nonterminal, rollback-failed, no-success, invalid binding or incomplete architecture semantics: `StateTransitionError`;
- identifier reuse with different material or a second candidate for one architecture: `ConflictError`;
- denied, mismatched, dirty or consumed TrustPlane decision: `AuthorizationError`.

## Testing strategy

Unit tests use a deterministic `FakeExecutionEvidenceSource` returning real `C3AdoptionExecutionRecord` dataclasses and verification results. This enables complete terminal-status and negative-evidence coverage without forging production database rows.

Tests use the real Database, EventLedger, TrustPlane and ContinuityService for all C4 writes, decisions, consumption and ledger behavior.

Required tests cover:

- deterministic side-effect-free preparations;
- default deny for input and candidate;
- success plus negative-evidence freeze;
- nonterminal, dirty, duplicate, unsorted, rollback-failed and no-success rejection;
- exact replay and conflict behavior;
- valid architecture v3.2 candidate;
- missing owner ADR, orphan port, missing test/proof mapping, missing mission stage, failed-execution binding and incomplete vertical benchmark rejection;
- membership, digest, decision, consumption, manifest, event and chain tampering.

## Explicit non-goals

This slice does not:

- accept an independent C4 reviewer key;
- admit a signed C4 disposition;
- publish or deploy an architecture;
- invoke a C3 worker or executor;
- perform network access;
- claim that a vertical benchmark executed;
- certify C4 completion;
- promote any canonical product state.
