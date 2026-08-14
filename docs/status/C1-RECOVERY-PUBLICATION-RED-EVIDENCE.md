# C1 recovery publication — RED evidence

Date: 2026-08-13

GitHub Actions run `31754808515` executed 89 tests.

Two falsification tests failed because the current incident verifier did not yet revalidate:

- the decision that authorized acceptance of the reviewer root;
- the single-use consumption record bound to that decision.

All 87 other tests passed. Compilation passed. The secret scanner and text policy reported zero findings. The deterministic manifest remained intentionally stale while the branch was under construction.

This record is evidence of an open verification gap. It is not a completion claim and it does not change the canonical C1 status.