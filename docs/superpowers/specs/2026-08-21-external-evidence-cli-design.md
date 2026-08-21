# STARCOM external evidence CLI — design

## Boundary

`python -m starcom.external_evidence_cli` exposes only `admit`, `get`,
`verify`, and `snapshot` for the existing `ExternalEvidenceService`. It never
creates a TrustPlane rule, authorization decision, trust root, release,
publication, deployment, promotion, execution, or external connection.

## Exact-byte contract

`admit` reads `--payload-file` and `--signature-file` with `Path.read_bytes()`
and passes those bytes unchanged to the shared service. It accepts the evidence
identifier, key identifier, actor, and optional admission timestamp. Missing or
unreadable files produce structured JSON errors without tracebacks.

`get` returns one stored record. `verify` returns the structured verification
and exits `0` only when clean, otherwise `3`. `snapshot` is read-only and
returns the four category statuses, optionally evaluated at `--as-of`.

All successful responses are JSON on stdout; domain errors are JSON on stderr.
The canonical truth remains `RC_BLOCKED_EXTERNAL_EVIDENCE` and `NOT_PROVEN`.
