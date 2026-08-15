# C3 executor registry CLI implementation plan

## Goal

Implement issue #50 as a thin, exact-byte, non-executing CLI over the verified `C3ExecutorRegistry`.

## Task 1: establish RED

- Add `tests/test_executor_registry_cli.py`.
- Generate ephemeral Ed25519 keys only in temporary test directories.
- Exercise the complete register -> qualifier root -> exact signed qualify -> enable -> attest -> revoke lifecycle through subprocess CLI calls.
- Prove current `main` fails only because `executor-registry` does not exist.
- Preserve all 271 existing tests.

## Task 2: compose one shared registry

- Import `C3ExecutorRegistry` into `src/starcom/cli.py`.
- Add one `Runtime.executor_registry` field.
- Construct it from the existing database, ledger, TrustPlane and continuity signature verifier.
- Add no secondary policy, signature or persistence implementation.

## Task 3: add thin handlers

- Parse descriptor JSON with the existing JSON-object helper.
- Read qualifier public key, payload and signature with the existing raw-byte file helper.
- Delegate preparation and mutation calls without implicit authorization.
- Return descriptor plus current state for `get`.
- Map `verify` to exit 0/3.
- Keep `attest` read-only.

## Task 4: add the closed parser surface

Expose exactly the 13 commands in the design. Require explicit actor and authorization decision for mutations. Do not expose worker, process, execute, install, deploy or run.

## Task 5: verify and publish

- Run focused CLI tests.
- Require the exact complete test count.
- Regenerate and verify `MANIFEST.sha256`.
- Run repository verification, compile, secret scan, text policy, alternate hash seed, warnings-as-errors and `git diff --check`.
- Publish through a bounded RED/GREEN workflow.
- Review the exact diff.
- Require merge-virtual CI and exact head SHA.
- Merge and require post-merge CI before starting further runtime work.

## Completion boundary

Completion means the administrative registry protocol is reproducible from the CLI without any implicit authority or execution path. It does not mean a production executor is registered or a component is adopted.
