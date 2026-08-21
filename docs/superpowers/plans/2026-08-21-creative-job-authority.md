# Block 16 creative job authority implementation plan

**Goal:** implement issue #66 as a durable, content-addressed, fail-closed authority that requests multimodal jobs without executing them.

## TDD sequence

- [x] Read issue #66 and audit the existing Runtime, TrustPlane, DurableOutbox, canonical JSON, and transaction contracts.
- [x] Add the focused contract suite and confirm the RED state with the missing `starcom.creative` module.
- [ ] Implement closed enums, dataclasses, prompt/digest validation, canonical plan material, and side-effect-free `prepare()`.
- [ ] Implement immutable job/input/transition schema and exact TrustPlane decision binding.
- [ ] Implement atomic `request()` admission with one outbox effect and strict replay/conflict handling.
- [ ] Implement `get()` and independent `verify()` with tamper defect codes.
- [ ] Wire one shared service into Runtime and refresh `MANIFEST.sha256`.
- [ ] Run focused tests, full deterministic gate, source network audit, CI, merge, archive, and handoff report.

## Invariants

- Five closed job types only.
- Prompt is exact bytes, strict UTF-8, and SHA-256 addressed.
- Inputs and digests are closed, sorted, unique, and never read from disk during admission.
- Default deny remains effective; decisions are explicit, exact, and single-use per creative job.
- Admission is one transaction across immutable request, transition, ledger, and outbox.
- No method or import can perform generation, rendering, synthesis, transcription, processing, execution, running, networking, filesystem access, subprocesses, microphone, camera, or GPU work.
- The terminal truth remains `CREATIVE_JOB_REQUESTED_NOT_EXECUTED`.
