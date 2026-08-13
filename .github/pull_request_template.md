## Scope

Describe exactly what changes and what remains blocked.

## Evidence

- [ ] Fresh tests run on the exact head commit
- [ ] `python3 scripts/verify_repo.py` passes
- [ ] SHA-256 manifest verifies
- [ ] No committed secret/private key/local database
- [ ] GitHub Actions green

## Authority and trust

- [ ] No framework/model is treated as sovereign authority
- [ ] Default-deny policy is preserved
- [ ] Author, verifier and certifier remain separated where required
- [ ] No blocked state is promoted without its exact external evidence

## Durability

- [ ] Idempotency and retry semantics are stated honestly
- [ ] External effects are reconciliable
- [ ] Rollback/recovery behavior is tested

## Current truth after this PR

List all product-level statuses that remain `BLOCKED`, `NOT_IMPLEMENTED`, or `NOT_CERTIFIED`.
