# STARCOM Bootstrap and Proof-Gated Vertical Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bootstrap the empty canonical repository with a real, fail-closed STARCOM R0.1 vertical slice spanning canonical hashes, ledger, trust, proof, missions, durable outbox, research attempts, CLI, CI, and fresh verification evidence.

**Architecture:** A standard-library Python package uses SQLite as a transactional adapter. Sovereign components communicate through typed dataclasses and immutable receipts, while every important transition is committed to a per-stream hash-chained event ledger. The repository remains explicit that this is a reconstructed R0.1 foundation, not the unavailable historical product tree.

**Tech Stack:** Python 3.11+, SQLite 3, `unittest`, `argparse`, GitHub Actions on Ubuntu, standard-library hashing/JSON/UUID/datetime modules.

## Global Constraints

- Preserve `PRODUCT_NOT_IMPLEMENTED` until the complete product exists.
- Do not claim historical source import or historical test reproduction.
- Default-deny all sensitive actions.
- Separate author, verifier, and certifier identities.
- Record research attempts before request execution.
- Enforce monotonically increasing research waves.
- Never claim exactly-once external effects; use at-least-once plus idempotency.
- Use no external runtime dependencies in R0.1.
- Commit no secrets or private signing keys.
- Use deterministic canonical JSON and SHA-256 receipts.
- No `@latest`, floating dependencies, placeholders, or stubs.

---

## File map

- `pyproject.toml` — package metadata and CLI entry point.
- `README.md` — product truth, setup, architecture, and commands.
- `AGENTS.md` — agent execution and proof rules.
- `.gitignore` — secrets, caches, databases, generated evidence.
- `src/starcom/canonical.py` — canonical values, JSON bytes, digests, UTC timestamps.
- `src/starcom/errors.py` — stable typed domain errors.
- `src/starcom/db.py` — SQLite connection, schema, and transaction helpers.
- `src/starcom/ledger.py` — immutable per-stream event chains and verification.
- `src/starcom/trust.py` — policy rules, grants, authorization receipts.
- `src/starcom/proof.py` — claims, evidence, verification, certification.
- `src/starcom/mission.py` — mission aggregate and state transitions.
- `src/starcom/durable.py` — outbox enqueue/lease/complete/fail/recover.
- `src/starcom/research.py` — campaign/wave/attempt/receipt/verification model.
- `src/starcom/cli.py` — JSON CLI.
- `src/starcom/__main__.py` — `python -m starcom` entry point.
- `scripts/verify_repo.py` — deterministic verification orchestrator.
- `scripts/secret_scan.py` — repository secret-pattern scanner.
- `scripts/build_manifest.py` — source manifest generator/verifier.
- `tests/` — component, integration, CLI, and tamper tests.
- `.github/workflows/ci.yml` — pinned CI workflow.
- `docs/status/CANONICAL-STATE.md` — recovered and current truth.
- `docs/proof/R0.1-VERIFICATION.md` — fresh command evidence.

### Task 1: Repository governance and packaging

**Files:**
- Create: `pyproject.toml`
- Create: `README.md`
- Create: `AGENTS.md`
- Create: `.gitignore`
- Create: `src/starcom/__init__.py`
- Create: `src/starcom/__main__.py`
- Create: `docs/status/CANONICAL-STATE.md`

**Interfaces:**
- Produces package `starcom`, version `0.1.0`, and a `starcom` CLI entry point.

- [ ] Write a smoke test that imports `starcom`, checks `__version__ == "0.1.0"`, and invokes `python -m starcom --help`.
- [ ] Run the smoke test and confirm it fails before package creation.
- [ ] Add packaging, metadata, governance files, and a minimal CLI parser that exposes help only.
- [ ] Run the smoke test and confirm it passes.
- [ ] Commit `chore: bootstrap STARCOM R0.1 repository`.

### Task 2: Canonical serialization and typed errors

**Files:**
- Create: `src/starcom/canonical.py`
- Create: `src/starcom/errors.py`
- Create: `tests/test_canonical.py`

**Interfaces:**
- Produces `utc_now() -> str`, `canonical_json_bytes(value: object) -> bytes`, `canonical_json(value: object) -> str`, and `sha256_digest(value: object | bytes) -> str`.
- Produces `StarcomError(code, message, details=None)` and specialized subclasses.

- [ ] Write tests for sorted compact JSON, Unicode preservation, UTC datetime normalization, set/NaN/bytes rejection, and stable SHA-256 vectors.
- [ ] Run `python -m unittest tests.test_canonical -v` and confirm failures.
- [ ] Implement strict recursive normalization and error types.
- [ ] Run the test module and confirm pass.
- [ ] Commit `feat: add canonical serialization and domain errors`.

### Task 3: SQLite schema and hash-chained ledger

**Files:**
- Create: `src/starcom/db.py`
- Create: `src/starcom/ledger.py`
- Create: `tests/test_ledger.py`

**Interfaces:**
- Produces `Database(path)`, `Database.initialize()`, and `Database.transaction()`.
- Produces `EventLedger.append(stream_id, kind, payload, actor, expected_head=None, event_id=None, occurred_at=None) -> EventReceipt`.
- Produces `EventLedger.read_stream(stream_id) -> list[LedgerEvent]` and `verify(stream_id=None) -> ChainVerification`.

- [ ] Write failing tests for first append, chained appends, expected-head conflict, duplicate event ID, stream reading, and direct-row tamper detection.
- [ ] Run ledger tests and record expected failures.
- [ ] Implement schema, transactions, immutable event writes, and full-chain verification.
- [ ] Run ledger tests and confirm pass.
- [ ] Commit `feat: add tamper-evident SQLite ledger`.

### Task 4: Default-deny Trust Plane

**Files:**
- Create: `src/starcom/trust.py`
- Create: `tests/test_trust.py`

**Interfaces:**
- Produces `PolicyRule`, `Grant`, `AuthorizationRequest`, `AuthorizationDecision`, and `TrustPlane`.
- `TrustPlane.authorize(request, now=None, consume=True) -> AuthorizationDecision` writes a ledger receipt.

- [ ] Write failing tests for default deny, wildcard allow, explicit-deny precedence, condition matching, expiration, mission scope, and single-use grant consumption.
- [ ] Run trust tests and confirm failures.
- [ ] Implement rules and grants with deterministic precedence and receipts.
- [ ] Run trust tests and confirm pass.
- [ ] Commit `feat: implement default-deny Trust Plane`.

### Task 5: Role-separated Proof Engine

**Files:**
- Create: `src/starcom/proof.py`
- Create: `tests/test_proof.py`

**Interfaces:**
- Produces `ProofEngine.create_claim`, `attach_evidence`, `verify_claim`, `certify_claim`, and `get_certificate`.
- A certificate contains a canonical digest over claim, evidence, verification, certifier, and policy version.

- [ ] Write failing tests for claim creation, evidence digest validation, author/verifier separation, verifier/certifier separation, rejected verification, missing evidence, certificate tamper detection, and idempotent repeated certification.
- [ ] Run proof tests and confirm failures.
- [ ] Implement proof tables, state rules, role separation, and terminal certificate verification.
- [ ] Run proof tests and confirm pass.
- [ ] Commit `feat: add role-separated Proof Engine`.

### Task 6: Mission Kernel

**Files:**
- Create: `src/starcom/mission.py`
- Create: `tests/test_mission.py`

**Interfaces:**
- Produces `MissionKernel.create`, `get`, and `transition`.
- States: `CREATED`, `PLANNED`, `AUTHORIZED`, `RUNNING`, `PAUSED`, `SUCCEEDED`, `FAILED`, `CANCELLED`.
- Sensitive transitions consume a valid authorization receipt; `SUCCEEDED` requires a valid proof certificate.

- [ ] Write failing tests for legal path, illegal transitions, authorization requirement, terminal immutability, success certificate requirement, idempotent replay, and same-key/different-payload rejection.
- [ ] Run mission tests and confirm failures.
- [ ] Implement aggregate replay, transition table, atomic idempotency, and receipts.
- [ ] Run mission tests and confirm pass.
- [ ] Commit `feat: implement proof-gated Mission Kernel`.

### Task 7: Durable outbox

**Files:**
- Create: `src/starcom/durable.py`
- Create: `tests/test_durable.py`

**Interfaces:**
- Produces `DurableOutbox.enqueue`, `claim`, `succeed`, `fail`, `recover_expired`, and `get`.
- Stable `effect_id` is the handler idempotency key.

- [ ] Write failing tests for enqueue idempotency, lease exclusivity, success, retryable failure, retry exhaustion, lease recovery, and stale-worker rejection.
- [ ] Run durable tests and confirm failures.
- [ ] Implement lease-based outbox transitions and ledger receipts.
- [ ] Run durable tests and confirm pass.
- [ ] Commit `feat: add durable at-least-once outbox`.

### Task 8: Research campaign and pre-request attempt ledger

**Files:**
- Create: `src/starcom/research.py`
- Create: `tests/test_research.py`

**Interfaces:**
- Produces `ResearchCampaign.create`, `begin_attempt`, `record_receipt`, `record_observation`, `checkpoint_cursor`, and `verify`.
- `begin_attempt` atomically persists the attempt before any caller can issue a request.
- Wave numbers are monotonically non-decreasing per campaign.

- [ ] Write failing tests for normal W1→W2 flow, W3→W2 rejection, receipt without attempt rejection, duplicate request key idempotency, missing receipt failure, snapshot/observation/cursor linkage, and successful campaign verification.
- [ ] Run research tests and confirm failures.
- [ ] Implement campaign tables, linkage rules, wave guard, and fail-closed verification report.
- [ ] Run research tests and confirm pass.
- [ ] Commit `feat: add pre-request research evidence ledger`.

### Task 9: JSON CLI and end-to-end flow

**Files:**
- Modify: `src/starcom/cli.py`
- Modify: `src/starcom/__main__.py`
- Create: `tests/test_cli.py`
- Create: `tests/test_integration_flow.py`

**Interfaces:**
- Commands: `init`, `ledger verify`, `mission create`, `mission transition`, `research create`, `research begin-attempt`, `research receipt`, `research verify`, and `doctor`.

- [ ] Write failing CLI tests for JSON success/errors, exit codes, and database persistence.
- [ ] Write an integration test covering campaign collection, trust authorization, mission execution, proof certification, and terminal mission success.
- [ ] Run CLI/integration tests and confirm failures.
- [ ] Implement commands and structured error mapping.
- [ ] Run CLI/integration tests and confirm pass.
- [ ] Commit `feat: expose STARCOM R0.1 JSON CLI`.

### Task 10: Deterministic repository verification and CI

**Files:**
- Create: `scripts/secret_scan.py`
- Create: `scripts/build_manifest.py`
- Create: `scripts/verify_repo.py`
- Create: `.github/workflows/ci.yml`
- Create: `MANIFEST.sha256`
- Create: `tests/test_repo_policy.py`

**Interfaces:**
- `python scripts/verify_repo.py` returns zero only when compilation, tests, policy, secret scan, and manifest checks pass.

- [ ] Write failing repository-policy tests for `@latest`, private-key headers, placeholder tokens, untracked manifest entries, and generated database files.
- [ ] Implement scanners and manifest support.
- [ ] Generate the first manifest.
- [ ] Pin every GitHub Action to a full commit SHA.
- [ ] Run `python scripts/verify_repo.py` and confirm pass.
- [ ] Commit `ci: add deterministic verification gates`.

### Task 11: Independent local verification evidence

**Files:**
- Create: `docs/proof/R0.1-VERIFICATION.md`
- Create: `docs/proof/R0.1-TEST-OUTPUT.txt`
- Create: `docs/proof/R0.1-FILE-HASHES.sha256`

**Interfaces:**
- Produces a human-readable proof record tied to the exact source tree.

- [ ] Run the full verifier in a fresh temporary database and capture stdout/stderr and exit code.
- [ ] Run the full unit suite independently with verbosity.
- [ ] Compute hashes of source, tests, workflow, manifest, and proof documents.
- [ ] Document exact environment, commands, test count, limitations, and current canonical state.
- [ ] Re-run manifest and verifier after proof generation.
- [ ] Commit `proof: record fresh R0.1 verification evidence`.

### Task 12: Publish through GitHub review

**Files:**
- No new product files unless publication verification finds a defect.

**Interfaces:**
- Produces branch `bootstrap/r0.1-proof-gated-core`, a pushed commit series, and a draft pull request against `main`.

- [ ] Confirm repository identity and permissions.
- [ ] Scan staged content for secrets and private keys.
- [ ] Publish an initial non-product commit on `main` only if required to establish the empty repository.
- [ ] Create the bootstrap branch and transfer the verified tree without force-push.
- [ ] Open a draft PR with exact tests, limitations, and truth-state declarations.
- [ ] Read GitHub Actions results and fix any failures without weakening gates.
- [ ] Keep the PR draft until an independent review gate is available.
