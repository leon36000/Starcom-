# STARCOM canonical repository state

**Repository:** `leon36000/Starcom-`
**Bootstrap date:** 2026-08-13

## Recovered continuity facts

The available continuity documents describe an advanced architecture and historical reference implementations. The complete historical source tree is not mounted in the current runtime, so those implementations and test totals are not represented as current repository evidence.

The independent C1 review is reported complete with disposition `RECOLLECT_REQUIRED` and a valid Ed25519 signature. The current repository does not contain the exact sealed reviewer public key, disposition bytes, or signature needed to prove that trust-root acceptance or recovery publication was executed.

## Current repository truth

```text
REPOSITORY_BOOTSTRAP = IN_PROGRESS
PRODUCT_NOT_IMPLEMENTED
NO_EXTERNAL_RUNTIME_INTEGRATED
NO_COMPONENT_ADOPTION
LIVE_800_PLUS_CENSUS_NOT_CERTIFIED
TASK5_DISPOSITION = RECOLLECT_REQUIRED
C1_INDEPENDENT_REVIEW = REPORTED_COMPLETE
C1_PROTOCOL_IMPLEMENTATION = PRESENT_AS_BOUNDED_REFERENCE
C1_HISTORICAL_ARTIFACT_ADMISSION = NOT_EXECUTED
C1_RECOVERY_PUBLICATION = NOT_PROVEN_EXECUTED_IN_THIS_RUNTIME
```

## Fresh implementation evidence

The bounded continuity protocol can:

1. create a `RECOVERY_REQUIRED` incident bound to an archive digest;
2. accept a reviewer public key only through an exact, allowed Trust Plane decision;
3. verify exact signed JSON bytes with Ed25519;
4. store immutable signed-review and signature material with SHA-256 digests;
5. require exact signed findings for `RECOLLECT_REQUIRED`;
6. require a second exact Trust Plane decision for publication;
7. consume each authorization once;
8. publish `RECOVERY_PUBLISHED_RECOLLECT_REQUIRED` atomically with a ledger receipt;
9. reject any attempt to transform that disposition into `PASS`.

Static public Ed25519 fixture bytes prove the OpenSSL verification path. Deterministic injected verification is used for state-machine tests so no private-key material enters the repository.

## Known limitation

Issue #5 tracks an independent-verifier hardening gap: `verify_incident` does not yet revalidate the Trust Plane decision and authorization-consumption record that originally accepted the reviewer trust root. The transaction path itself validates and consumes that decision before acceptance, but the later observational verification is not yet complete for that link.

This limitation is explicit and does not authorize a canonical promotion.

## Promotion rule

Only fresh evidence produced by this repository may promote its implementation status. Historical reports remain provenance inputs, not substituted test results. C1 can be promoted only after the exact historical public artifacts are admitted, all applicable verification gaps are closed, and an explicit recovery publication receipt is independently verified.