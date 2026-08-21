# Block 19 Release Candidate assessment authority — implementation plan

Spec: `docs/superpowers/specs/2026-08-21-release-candidate-design.md`

## Contract

- [x] Freeze the exact 12A→18 evidence IDs and closed payload fields.
- [x] Freeze benchmark comparison directions, red-team/gate statuses and four
  external statuses.
- [x] Freeze derived readiness, `NOT_RELEASED` truth boundary and immutable
  ledger event.

## TDD and implementation

- [x] Add focused RED tests for malformed payloads, numeric benchmark
  consistency, blocked verification, blocked external evidence, ready review,
  exact replay/conflicts, tampering and runtime wiring.
- [x] Implement strict parsing and exact-byte Ed25519 admission.
- [x] Implement immutable assessment plus evidence/benchmark/red-team/gate
  memberships and ledger provenance.
- [x] Derive verdict, release status and gate effect; never accept them from
  signed input.
- [x] Wire the shared service into `Runtime` without adding an operational
  release surface.

## Verification and handoff

- [x] Run focused, full, compile, secret, style, manifest, hash-seed and
  warnings-as-errors gates.
- [ ] Push a review branch, merge the PR, confirm remote CI and close issue
  #69.
- [ ] Produce a fresh source archive, SHA-256 and a French continuation report.
