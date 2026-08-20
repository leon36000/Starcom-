# C4 Architecture Review CLI Implementation Plan

**Goal:** expose the already merged `C4ArchitectureReviewService` through the exact-byte, non-publishing `architecture-review` CLI required by Issue #56.

**Scope:** add only `prepare-reviewer-root`, `accept-reviewer-root`, `admit`, `get`, `verify-root`, and `verify`. The CLI must share the canonical `Runtime` graph and must not add publication, deployment, execution, installation, network, or status-promotion paths.

**Contract:** raw public-key, payload, and signature files are read as bytes; no normalization or re-serialization occurs before the service/verifier receives them. File and argument failures are structured `VALIDATION_ERROR` responses without tracebacks. Clean verifiers exit `0`; dirty verifiers exit `3`; admission and read failures retain the existing STARCOM error boundary.

## RED → GREEN tasks

- [x] Add CLI contract tests for all six commands, exact byte forwarding, default deny, explicit root acceptance, exact signed admission, `get`, and clean verification.
- [x] Add negative CLI tests for whitespace mutation, missing/unreadable files, wrong authorization decision, dirty root/review verification, and forbidden publishing/execution command names.
- [x] Wire the canonical C4 input, candidate, and review services into `Runtime` without creating a second graph.
- [x] Add handlers and parser definitions that delegate directly to the C4 review service and preserve machine-readable output/exit codes.
- [x] Run focused CLI tests, then the deterministic repository gate with hash-seed and warnings-as-errors.
- [x] Run a real subprocess smoke with OpenSSL Ed25519 and inspect the final diff before integration.

## Verification evidence

- Focused suite: 5 tests passed, including OpenSSL Ed25519 subprocess admission and whitespace-mutation rejection.
- Existing CLI suites: 44 tests passed.
- Repository gate: 426 tests passed; compile, secret scan (0 findings), text-style (0 findings), and manifest (108/108) passed.

## Boundary evidence

The resulting CLI makes review authority operable only. A valid accepted review remains `NO_PUBLICATION_NO_DEPLOYMENT`; Issue #57 publication remains a separate authority and is not implemented here.
