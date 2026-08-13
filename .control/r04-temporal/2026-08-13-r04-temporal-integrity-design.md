# STARCOM R0.4 — Temporal Integrity Design

**Date:** 2026-08-13  
**Status:** reference evidence hardening; no live recollection executed

## Objective

A hash chain proves that stored event bytes have not changed unnoticed, but it does not by itself prove that event time is coherent. R0.4 adds an independently verifiable temporal model for recollection evidence.

## Temporal invariants

1. Every timestamp is strict UTC RFC 3339 ending in `Z`.
2. Fractional seconds are optional and limited to one through six digits.
3. Campaign creation is the first temporal boundary.
4. Event time never regresses within a campaign.
5. Attempt preparation cannot precede campaign creation or the prior event.
6. A terminal outcome cannot precede its attempt preparation.
7. A retry cannot be backdated behind a prior terminal event.
8. Finalization cannot precede campaign creation or the latest event.
9. State-row timestamps and their corresponding event timestamps must match exactly.
10. Verification detects chronology defects even when an attacker recomputes the hash chain.

## Write-time enforcement

Temporal checks happen inside the same SQLite transaction as the state transition. A regressing event causes rollback of the state row and event append.

The bounded executor validates caller-supplied `prepared_at` and `terminal_at` before creating a new attempt or invoking the injected adapter. Invalid local parameters therefore produce no durable attempt and no external side effect.

## Verification-time enforcement

`verify_campaign` independently checks:

- timestamp syntax and calendar validity;
- event sequence chronology;
- campaign lifecycle chronology;
- prepare/terminal row-to-event equality;
- terminal-after-prepare ordering;
- final-event/finalized-row equality;
- temporal consistency after a fully recomputed event hash chain.

## Truth boundary

```text
R0.4_TEMPORAL_INTEGRITY = IMPLEMENTED_REFERENCE_MECHANISM
LIVE_ADAPTER = NOT_ENABLED
C2_LIVE_RECOLLECTION = NOT_EXECUTED
LIVE_800_PLUS_CENSUS_NOT_CERTIFIED
C1_RECOVERY_PUBLICATION = NOT_PROVEN_EXECUTED_IN_THIS_RUNTIME
PRODUCT_NOT_IMPLEMENTED
```
