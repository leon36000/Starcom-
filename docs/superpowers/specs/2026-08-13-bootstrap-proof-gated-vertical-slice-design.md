# STARCOM Bootstrap and Proof-Gated Vertical Slice Design

**Date:** 2026-08-13  
**Repository:** `leon36000/Starcom-`  
**Status:** approved by the owner's standing instruction to execute the existing STARCOM plan autonomously  
**Scope:** reconstructive bootstrap because the canonical GitHub repository is empty and the complete historical source tree is not mounted in the current execution environment

## 1. Context and truth preservation

The repository is empty. The available continuity material establishes an advanced design and reference history, but not a complete mounted source tree. This bootstrap therefore must not claim to import, reproduce, or certify historical implementations that are unavailable byte-for-byte.

The repository will preserve the following truth:

```text
PRODUCT_NOT_IMPLEMENTED
NO_EXTERNAL_RUNTIME_INTEGRATED
NO_COMPONENT_ADOPTION
LIVE_800_PLUS_CENSUS_NOT_CERTIFIED
TASK5_DISPOSITION = RECOLLECT_REQUIRED
C1_INDEPENDENT_REVIEW = REPORTED_COMPLETE
C1_RECOVERY_PUBLICATION = NOT_PROVEN_EXECUTED_IN_THIS_RUNTIME
```

Historical test totals may be recorded as continuity facts, but they are not current-repository test evidence. Current evidence begins with fresh commands executed against this repository.

## 2. Approaches considered

### A. Wait for the historical source archive

This maximizes byte-for-byte continuity, but leaves the canonical GitHub repository empty and creates another operational pause. It also cannot be completed from the current runtime because the archive is not mounted.

### B. Reconstruct a narrow, real vertical slice behind stable sovereign contracts — selected

Build a small but production-shaped core using only the Python standard library: canonical serialization, append-only hash-chained ledger, default-deny Trust Plane, role-separated Proof Engine, Mission Kernel, durable outbox, and a research-attempt ledger that records an attempt before an external request. This directly addresses the Task 5 failure mode and creates an executable foundation for C2.

This approach is selected because it produces real, testable software without fabricating the missing historical implementation.

### C. Scaffold every STARCOM phase immediately

This would create broad directory coverage but mostly empty modules and interfaces. It conflicts with the prohibition on stubs and would increase maintenance surface before the core authority model is proven.

## 3. Release boundary

The first repository release is **R0.1 — Proof-Gated Mission Core**. It is not the complete STARCOM product.

R0.1 must provide:

1. deterministic canonical JSON and SHA-256 digests;
2. a SQLite append-only ledger with per-stream hash chains;
3. a default-deny Trust Plane with explicit rules and time-bounded grants;
4. a Proof Engine enforcing author/verifier/certifier separation;
5. a Mission Kernel with explicit state transitions and idempotency;
6. a durable outbox with lease-based claiming and retry accounting;
7. a Research Campaign ledger that records every attempt before request execution, enforces monotonic waves, and fails closed on incomplete receipts;
8. a CLI exposing initialization, mission, research, trust, proof, and verification commands;
9. deterministic repository verification and CI;
10. current-run evidence containing exact commands, results, and hashes.

## 4. Architecture

```text
CLI
 │
 ├── Mission Kernel ────────┐
 ├── Trust Plane            │
 ├── Proof Engine           ├── SQLite Unit of Work
 ├── Research Campaign      │       │
 └── Durable Outbox ────────┘       ├── append-only event ledger
                                    ├── idempotency records
                                    ├── grants / proof records
                                    └── outbox / research attempts
```

The package uses hexagonal boundaries without speculative adapters. SQLite is the first real adapter. PostgreSQL/Neon and Temporal are future adapters after their contracts are exercised by this slice.

## 5. Component boundaries

### `canonical`

Owns deterministic conversion of supported values into canonical JSON bytes and SHA-256 digests. It rejects unsupported values instead of guessing.

### `ledger`

Owns schema creation, transactional append, optimistic stream-head checks, event reading, and full chain verification. Each record hash commits to stream, sequence, event metadata, canonical payload, previous hash, and timestamp.

### `trust`

Owns subjects, actions, resources, policy rules, grants, and authorization receipts. Default is deny. Explicit deny overrides allow. Expired and consumed grants cannot authorize.

### `proof`

Owns claims, evidence references, independent verification, and terminal certificates. The same actor cannot author and verify or certify the same claim. A certificate commits to the claim, evidence digests, verification, and policy version.

### `mission`

Owns mission state and legal transitions. A transition writes an event and idempotency record atomically. Sensitive transitions require an authorization receipt; terminal success requires a valid proof certificate.

### `durable`

Owns an outbox row lifecycle: pending, leased, succeeded, retryable failure, terminal failure. Delivery is at-least-once; handlers receive a stable idempotency key. The system never claims exactly-once external effects.

### `research`

Owns campaigns, waves, attempts, receipts, observations, and cursor checkpoints. An attempt row and ledger event must exist before an external request. Wave numbers cannot decrease. Campaign verification fails when any attempt lacks a terminal receipt or when linkage is incomplete.

### `cli`

Owns machine-readable command interfaces. Success emits JSON to stdout; errors emit structured JSON to stderr and non-zero exit codes.

## 6. Data and transaction rules

- SQLite foreign keys are enabled.
- Write transactions use `BEGIN IMMEDIATE`.
- Timestamps are UTC RFC 3339 with microseconds and `Z`.
- IDs are UUIDv4 strings unless caller-supplied idempotency keys are required.
- Canonical payloads are stored as compact sorted-key JSON.
- No mutable update is allowed for event payloads.
- Mutable operational tables are reconciled against immutable ledger events.
- Every externally meaningful transition returns a receipt containing IDs and hashes.

## 7. Error handling

Domain failures use typed exceptions with stable error codes. CLI error payloads contain `error`, `message`, and optional `details`, but no tracebacks by default. SQLite integrity failures are translated into domain errors where possible. Chain verification returns all detected defects instead of stopping at the first one.

## 8. Security model

- default deny;
- explicit grants with expiry and optional single-use consumption;
- no secrets stored in repository fixtures;
- no private signing keys committed;
- no shell interpolation in the CLI;
- strict path handling for database and evidence files;
- deterministic secret-pattern scan before publication;
- no dependency on unpinned external runtime packages in R0.1.

## 9. Testing and proof

Tests are written before implementation for each component. The suite includes:

- canonicalization vectors and rejection cases;
- ledger tamper detection and concurrent-head conflicts;
- policy precedence, grant expiry, and single-use behavior;
- proof role-separation attacks;
- invalid mission transitions and idempotent replay;
- outbox lease recovery and retry limits;
- research wave regression, missing receipts, and linkage defects;
- end-to-end mission/research/proof flow;
- CLI contract tests;
- mutation-style tests that directly modify SQLite rows and expect verification failure.

The verification script runs compilation, unit tests, repository policy checks, manifest verification, and secret scanning. Evidence is generated from fresh output and must never copy historical PASS counts.

## 10. Non-goals for R0.1

- no claim of complete STARCOM implementation;
- no live 800+ census;
- no external model/runtime integration;
- no OpenCode/Hermes/OpenClaw adoption;
- no Web, desktop, or mobile UI;
- no PostgreSQL/Neon deployment;
- no Temporal server dependency;
- no automatic trust-root acceptance;
- no execution of historical C1 recovery without the sealed artifacts.

## 11. Forward compatibility

The next slices can add PostgreSQL/Neon and Temporal behind tested repository and workflow ports, then build the C2 live collection runner, evidence/artifact engine, Software Studio, Computer/Assistant, Creative Studio, Cockpit, packaging, and Phase 19 release gates. Stable identifiers, canonical receipts, and proof contracts in R0.1 are the compatibility anchor.
