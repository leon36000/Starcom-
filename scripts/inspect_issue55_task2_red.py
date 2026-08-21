from __future__ import annotations

import inspect
import io
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
for entry in (ROOT / "src", ROOT / "tests", ROOT):
    value = str(entry)
    if value not in sys.path:
        sys.path.insert(0, value)

from test_architecture_review import C4ArchitectureReviewTests  # noqa: E402


METHOD = "test_root_exact_replay_detects_malformed_ledger_event_without_raising"
OUTPUT = ROOT / "issue55_task2_red_inspection.json"


def main() -> int:
    method = getattr(C4ArchitectureReviewTests, METHOD)
    source = inspect.getsource(method)
    test = C4ArchitectureReviewTests(METHOD)
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(
        unittest.TestSuite([test])
    )
    records = []
    for outcome, collection in (("FAIL", result.failures), ("ERROR", result.errors)):
        for item, traceback_text in collection:
            records.append(
                {
                    "outcome": outcome,
                    "test_id": item.id(),
                    "traceback": traceback_text,
                }
            )
    payload = {
        "method": METHOD,
        "declaring_module": method.__module__,
        "source_file": inspect.getsourcefile(method),
        "source_start_line": inspect.getsourcelines(method)[1],
        "source": source,
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "was_successful": result.wasSuccessful(),
        "runner_output": stream.getvalue(),
        "records": records,
    }
    OUTPUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
