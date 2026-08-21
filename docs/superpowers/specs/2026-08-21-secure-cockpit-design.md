# Block 17 secure local Web Cockpit design

## Boundary

`CockpitService` stores an immutable operational snapshot, hashes local session credentials, and admits an explicitly authorized command. `CockpitWSGIApp` is a pure WSGI callable for in-process tests and local embedding; it never opens a listener, creates a client, proxies a request, or invokes a command. The only command state is `COCKPIT_COMMAND_AUTHORIZED_NOT_EXECUTED`.

## Snapshot contract

`prepare_snapshot()` is deterministic and side-effect free. Its payload has exactly:

- `project_state` and `current_phase` non-empty strings;
- non-negative `test_count`;
- `canonical_truth` non-empty string;
- sorted unique `services` entries with exactly `service_id` and `status`;
- sorted unique `alerts` entries with exactly `alert_id`, `severity`, and `message`;
- RFC 3339 `updated_at_utc`.

`admit_snapshot()` writes one immutable row and one ledger event. `get_latest_snapshot()` selects the latest admitted snapshot by its canonical timestamp and verifies its digest. Snapshot material is never updated or deleted.

## Sessions

`create_session()` accepts or generates two independent random values: a bearer token and a CSRF token. Only SHA-256 digests are persisted. The raw credentials are returned once to the local provisioning caller and are never included in HTML or API responses. Authentication uses constant-time digest comparison and rejects missing, mismatched, or expired sessions. Session rows are immutable and all session identity/expiry facts are ledgered.

## Command authority

The six closed command types are `START`, `PAUSE`, `RESUME`, `CANCEL`, `APPROVE`, and `REJECT`. `prepare_command()` binds a command ID, session, current snapshot ID/digest, type, target, parameters digest, and session subject into:

- action `cockpit.command.authorize`;
- resource `cockpit:command:<command_id>`;
- mission `cockpit-command:<command_id>`;
- exact TrustPlane context.

`authorize_command()` requires an already-created allowed decision. It re-authenticates the session subject, rechecks the snapshot digest inside the admission transaction, rejects decision reuse, and atomically appends the command event, immutable command row, initial transition, and command memberships. It never creates a TrustPlane rule/decision and never dispatches the command. Exact replay returns the original record; changed material conflicts.

## WSGI surface

`CockpitWSGIApp` implements only:

- `GET /` — static local HTML shell with no token or secret;
- `GET /api/v1/health` — minimal non-sensitive health response;
- authenticated `GET /api/v1/snapshot` — latest snapshot;
- authenticated, CSRF-protected `POST /api/v1/commands` — admits a command using a pre-existing decision;
- authenticated `GET /api/v1/commands/<command_id>` — reads one command.

Bearer authentication uses `Authorization: Bearer <token>` and `X-Cockpit-Session`; POST also requires `X-CSRF-Token`. JSON bodies are strict UTF-8, bounded, object-only, and require `Content-Type: application/json`. Every response has CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and `Cache-Control: no-store`. No CORS header, credential endpoint, private key, token, or CSRF value is emitted.

## Verification and truth boundary

The verifier reconstructs snapshot canonical JSON/digest and ledger chain, session hash/expiry facts, command context and parameters digest, TrustPlane decision/consumption, command transition, and all ledger links. It returns stable defect codes for tampering and stale snapshots. Tests use a WSGI `BytesIO` harness and never open a socket. The result proves local visualization and authorization only; it does not prove public hosting, desktop/mobile control, node control, or command execution.
