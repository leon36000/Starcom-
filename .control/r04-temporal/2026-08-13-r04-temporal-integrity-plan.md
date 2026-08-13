# STARCOM R0.4 — Temporal Integrity Implementation Plan

1. Add failing tests for malformed, backdated, and regressing timestamps.
2. Parse timestamps as strict UTC RFC 3339 calendar instants.
3. Enforce nondecreasing event time inside the ledger transaction.
4. Cross-check campaign, prepare, terminal, and finalization row timestamps with their events.
5. Detect terminal-before-prepare and finalization-before-history defects.
6. Reject retries backdated behind earlier evidence.
7. Validate executor timestamps before durable preparation or adapter execution.
8. Recalculate event hashes in negative tests and confirm chronology remains independently detectable.
9. Preserve equal timestamps as valid for deterministic tests and coarse clocks.
10. Run focused tests, the complete suite, verifier, compilation, policy scan, multiple hash seeds, and Python development mode.
11. Publish an independent versioned verification report.
12. Keep all external, live-data, adoption, and product gates fail-closed.
