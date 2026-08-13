# STARCOM

STARCOM is being built as a self-hosted, proof-gated agentic operating system. This repository currently contains the reconstructed **R0.1 Proof-Gated Mission Core**, not the complete product and not a byte-for-byte import of the unavailable historical source tree.

## Current truth

```text
PRODUCT_NOT_IMPLEMENTED
NO_EXTERNAL_RUNTIME_INTEGRATED
NO_COMPONENT_ADOPTION
LIVE_800_PLUS_CENSUS_NOT_CERTIFIED
TASK5_DISPOSITION = RECOLLECT_REQUIRED
```

The current slice establishes deterministic receipts, a tamper-evident ledger, a default-deny Trust Plane, role-separated proof, a Mission Kernel, durable effects, and a pre-request research-attempt ledger.

## Local use

```bash
PYTHONPATH=src python -m starcom --help
PYTHONPATH=src python -m starcom doctor
python -m unittest discover -s tests -v
```

No external runtime dependencies are required for R0.1.

## Development doctrine

- no false `DONE`;
- tests and hashes are evidence, not decoration;
- default deny for sensitive actions;
- author, verifier, and certifier are separate roles;
- research attempts are persisted before requests;
- external effects are at-least-once with idempotency, never falsely described as exactly-once;
- private keys and secrets are never committed.

See `docs/status/CANONICAL-STATE.md`, the design under `docs/superpowers/specs/`, and the implementation plan under `docs/superpowers/plans/`.
