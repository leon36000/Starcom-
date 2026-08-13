# STARCOM

STARCOM is being built as a self-hosted, proof-gated agentic operating system. This repository contains the reconstructed **R0.1 Proof-Gated Mission Core** plus a bounded C1 continuity protocol. It is not the complete product and it is not a byte-for-byte import of the unavailable historical source tree.

## Current truth

```text
PRODUCT_NOT_IMPLEMENTED
NO_EXTERNAL_RUNTIME_INTEGRATED
NO_COMPONENT_ADOPTION
LIVE_800_PLUS_CENSUS_NOT_CERTIFIED
TASK5_DISPOSITION = RECOLLECT_REQUIRED
C1_INDEPENDENT_REVIEW = REPORTED_COMPLETE
C1_RECOVERY_PUBLICATION = NOT_PROVEN_EXECUTED_IN_THIS_RUNTIME
```

The repository currently provides:

- deterministic receipts and a tamper-evident append-only ledger;
- a default-deny Trust Plane;
- role-separated proof and terminal certificates;
- a durable Mission Kernel and outbox;
- a pre-request research-attempt ledger;
- exact-byte Ed25519 verification for independent Task 5 dispositions;
- immutable trust-root, review, authorization-consumption, and recovery-publication records;
- a one-time recovery-publication transition that preserves `RECOLLECT_REQUIRED` and never converts it into `PASS`.

The historical reviewer public key, exact signed disposition bytes, and signature are not present in this repository. The implemented protocol therefore proves the mechanism only; it does not prove historical artifact admission or C1 recovery execution.

A known hardening gap in trust-root authorization revalidation is tracked in issue #5 and remains outside the completion claim for this bounded slice.

## Local use

```bash
PYTHONPATH=src python -m starcom --help
PYTHONPATH=src python -m starcom doctor
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/verify_repo.py
```

R0.1 has no Python package dependency outside the standard library. The continuity signature verifier requires an available OpenSSL command-line runtime.

## Development doctrine

- no false `DONE`;
- tests and hashes are evidence, not decoration;
- default deny for sensitive actions;
- author, verifier, and certifier are separate roles;
- research attempts are persisted before requests;
- external effects are at-least-once with idempotency, never falsely described as exactly-once;
- private keys and secrets are never committed;
- historical reports remain provenance inputs until their exact public artifacts are admitted and verified.

See `docs/status/CANONICAL-STATE.md`, the design under `docs/superpowers/specs/`, and the implementation plan under `docs/superpowers/plans/`.