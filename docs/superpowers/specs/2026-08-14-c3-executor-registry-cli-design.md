# Exact-byte C3 executor registry CLI

**Date:** 2026-08-14
**Issue:** #50
**Base:** `7fa1bf1f44b7d9df738a9fd6681bcfde13f818d3`

## Purpose

Expose the already verified sovereign executor registry through a thin canonical JSON CLI. The CLI delegates to one shared `C3ExecutorRegistry` instance and never creates policy, authorization, qualification, enablement, revocation, worker activity or external effects implicitly.

## Runtime composition

`Runtime` owns one registry constructed from the existing database, event ledger, TrustPlane and continuity signature verifier. No parallel trust or signature implementation is introduced.

## Command surface

The top-level command is `executor-registry` with exactly:

- `prepare-register`
- `register`
- `prepare-qualifier-root`
- `accept-qualifier-root`
- `prepare-qualify`
- `qualify`
- `prepare-enable`
- `enable`
- `prepare-revoke`
- `revoke`
- `get`
- `verify`
- `attest`

No `worker`, `process`, `execute`, `run`, `install`, `deploy` or equivalent command exists.

## Exact-byte inputs

The CLI reads these files as raw bytes using the existing fail-closed file reader:

- qualifier Ed25519 public key;
- signed qualification JSON payload;
- qualification signature.

It performs no decoding, whitespace normalization, key ordering or re-serialization before registry signature verification. Missing or unreadable files produce structured `VALIDATION_ERROR` output with no traceback.

## Preparation commands

Each `prepare-*` command returns only the exact action, resource, mission and context required for a separately requested TrustPlane decision. Preparation is deterministic and side-effect-free.

## Mutation commands

Each mutation requires an existing `authorization_decision_id`, actor and optional explicit timestamp. The CLI never adds a rule, requests an authorization or substitutes an actor. The registry remains the only authority for exact-request validation, single-use consumption, chronology, idempotency, conflicts and append-only writes.

## Read commands

- `get` returns both immutable descriptor and current state.
- `verify` returns exit 0 only for a clean verifier and exit 3 otherwise.
- `attest` is read-only and fails closed unless the executor is clean, enabled and compatible with the supplied implementation, sandbox and network requirements.

## Test matrix

Tests prove:

- deterministic side-effect-free registration preparation;
- default deny, explicit registration and disabled state;
- exact public-key bytes, missing-file errors and key substitution rejection;
- exact signed qualification bytes and whitespace mutation rejection;
- qualification remains disabled;
- separate enable decision and successful read-only attestation;
- separate terminal revocation and failed attestation afterward;
- wrong context, wrong actor and decision reuse write no transition;
- no worker or execution subcommand.

Private keys exist only in temporary test directories and are never persisted by STARCOM.

## Truth boundary

This CLI administers trust metadata only. It registers no production executor, invokes no worker or adapter, performs no network access, adopts no component and promotes no canonical product state.
