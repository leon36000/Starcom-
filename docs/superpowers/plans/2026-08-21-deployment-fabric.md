# Block 18 implementation plan

1. Freeze the closed bundle, node, assignment, and truth-boundary contracts.
2. Write RED tests for six platforms, strict validation, default deny, exact replay, decision reuse, compatibility, tampering, key validation, and forbidden execution surfaces.
3. Implement immutable SQLite records, canonical digests, ledger events, and TrustPlane consumption.
4. Wire one shared service into `Runtime`.
5. Run focused tests, full deterministic verification, secret/style scans, and manifest generation.
6. Push a PR closing issue #68, validate GitHub Actions, merge, rerun `main`, and archive the exact source and evidence report.
