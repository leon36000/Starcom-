# STARCOM agent rules

1. Read `docs/status/CANONICAL-STATE.md` before changing behavior.
2. Use a separate branch/worktree for every writing agent.
3. Follow RED → GREEN → REFACTOR for behavior changes.
4. Never change a `BLOCKED` state to `PASS` without the exact gate evidence.
5. Never claim the historical codebase was imported unless its bytes and provenance are present.
6. Never commit credentials, `.env` files, private keys, local databases, model weights, or unredacted user data.
7. Every important state change needs a deterministic receipt and, where applicable, a ledger event.
8. Trust is default-deny. No adapter or model is a sovereign authority.
9. Terminal success requires independent verification and certification.
10. Run `python scripts/verify_repo.py` before publication once the script exists.
