# STARCOM external evidence authority — implementation plan

**Goal:** Implement issue #71 as a deterministic exact-byte signed evidence
authority, integrate it into `StarcomProgram`, and preserve the canonical
`NOT_PROVEN` external truth.

## Constraints

- Follow RED → GREEN → REFACTOR.
- Reuse the existing Continuity trust-root and signature-verifier boundary.
- No network, subprocess, external runtime, deployment, release, or implicit
  TrustPlane decision.
- Keep exact payload and signature bytes; never verify re-serialized bytes.
- Immutable SQLite rows/triggers, append-only ledger provenance, exact replay,
  conflict rejection, expiration and category claim validation.
- Run the complete repository verification and update the manifest.

## Tasks

### 1. RED contract

- Add `tests/test_external_evidence.py` for all four categories, exact-byte
  signatures, category claim failures, census `<800`, expiration, whitespace
  mutation, key substitution, replay/conflict, tamper detection, snapshots,
  and no-release surface.
- Add composition-root assertions for one shared database/ledger/continuity,
  catalog membership, schema, and canonical truth.
- Run focused tests and commit the expected RED state.

### 2. Service

- Add `src/starcom/external_evidence.py` with frozen record, snapshot,
  preparation, and verification results.
- Implement strict parsing, closed category contracts, bounded bytes, exact
  trust-root/signature verification, immutable schema, admission, replay,
  retrieval, verification, and snapshot.
- Use stable defect codes and deterministic ordering.

### 3. Composition

- Add `19.external_evidence` to the explicit descriptor registry and construct
  the service after Continuity in `StarcomProgram.open`.
- Extend the program's exact schema inventory and shared-identity checks.
- Preserve Runtime compatibility aliases and `ProgramTruth` values.

### 4. Verification and publication

- Run focused tests, full tests, compileall, manifest, secret/style scans,
  warnings-as-errors, and hash-seed checks.
- Push the isolated branch, open a PR closing #71, monitor CI/Sonar, merge only
  after the exact head and required checks are green.
- Fast-forward canonical `main` and rerun `scripts/verify_repo.py`.
