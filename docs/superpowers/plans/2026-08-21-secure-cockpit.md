# Block 17 secure cockpit implementation plan

**Goal:** implement issue #67 as a zero-dependency, local WSGI cockpit that visualizes an immutable snapshot and authorizes commands without executing them.

## TDD sequence

- [x] Audit issue #67 and confirm no existing Web/WSGI authority or external dependency.
- [ ] Add RED tests for snapshot, hashed sessions, TrustPlane command admission, WSGI auth/CSRF/body limits, headers, tampering, and no-execution surface.
- [ ] Implement closed snapshot/session/command contracts and immutable SQLite/ledger storage.
- [ ] Implement exact decision binding, replay/conflict rules, snapshot revalidation, and independent verification.
- [ ] Implement the bounded WSGI routes and security headers, then wire one service into Runtime.
- [ ] Run focused tests, full deterministic gate, source audit, CI, merge, archive, and handoff report.

## Invariants

- Raw bearer/CSRF values never enter persistent storage or HTTP responses.
- Authentication and CSRF use independent hashes and constant-time comparison.
- Every mutation is default-deny and requires a pre-existing exact TrustPlane decision.
- Snapshots and commands are immutable/append-only; no update/delete path is exposed.
- WSGI is callable only; no socket, proxy, external origin, subprocess, browser, shell, or command dispatcher exists.
- The only command truth is `COCKPIT_COMMAND_AUTHORIZED_NOT_EXECUTED`.
