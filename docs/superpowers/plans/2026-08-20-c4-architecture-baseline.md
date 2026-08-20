# C4 architecture v3.2 baseline implementation plan

> Issue: [#61](https://github.com/leon36000/Starcom-/issues/61)

## Goal

Admit one exact-byte signed C4 architecture v3.2 baseline bound to a freshly reconstructed, independently verified C3 snapshot. Store immutable baseline and snapshot memberships with append-only ledger provenance. Keep the result explicitly non-deployed and external runtime integration `NOT_PROVEN`.

## Guardrails

- No worker, executor, subprocess, package manager, network, download, install, deployment or product-status promotion.
- A clean accepted Continuity Ed25519 trust root is required before signature verification.
- Payload parsing is strict UTF-8 JSON with duplicate-key rejection, a closed field set and exact-byte signature verification.
- A selected C3 candidate requires one clean C3 adoption authorization; any absent or non-successful execution remains represented as evidence and never becomes adoption.
- Architect and reviewer identities are distinct from one another and every material C3 actor.
- A baseline is unique per C3 run; exact replay is idempotent and every material conflict fails closed.
- Admission rechecks the C3 snapshot inside the transaction; later C3 evidence or any upstream mutation makes verification stale.

## TDD sequence

- [x] Add the public snapshot, baseline and verification contracts and a causal RED test seam.
- [x] Add strict payload, trust-root, chronology, independence and C3 binding tests.
- [x] Implement deterministic C3 snapshot reconstruction, immutable tables/memberships and exact-byte admission.
- [x] Implement independent verification of payload, signature, snapshot, adoption/execution references, ledger event and chain.
- [x] Run focused tests, C4 regressions and the deterministic repository gate.
- [x] Regenerate `MANIFEST.sha256` after GREEN.
- [ ] Commit, push, CI-verify and merge only after head-SHA checks.

## Verification evidence

Observed evidence before integration:

- Initial RED: `ModuleNotFoundError: No module named 'starcom.architecture'`.
- Focused baseline suite: **6/6 PASS**.
- C4 regression suite (`test_architecture*.py`): **165/165 PASS**.
- Runtime composition smoke tests: **4/4 PASS**.
- Deterministic repository gate: **444/444 tests PASS** with `PYTHONHASHSEED=0` and `PYTHONWARNINGS=error`.
- Compilation: PASS; secret scan: **0 findings**; text-style: **0 findings**; manifest: **114/114**.
- Falsification covers duplicate/extra fields, exact-byte whitespace mutation, invalid signature/root, selected candidate without adoption, chronology, identity collision, immutable row/membership tampering and deterministic replay.
