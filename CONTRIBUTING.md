# Contributing to STARCOM

## Required workflow

1. Read `AGENTS.md` and `docs/status/CANONICAL-STATE.md`.
2. Work on an isolated branch/worktree.
3. Write a failing test before changing behavior.
4. Implement the smallest correct change.
5. Run the focused tests, then the full repository verifier.
6. Commit evidence with accurate scope; never promote absent external gates.
7. Open a pull request and wait for independent CI/review.

## Before publication

```bash
PYTHONPATH=src:. python3 scripts/verify_repo.py
PYTHONPATH=src:. python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests scripts
```

No false `DONE`, no force-push to `main`, no dependency on `@latest`, and no secret or private key in Git history.
