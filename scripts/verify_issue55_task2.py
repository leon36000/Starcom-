from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPOSITORY_ROOT / "src"
TESTS_ROOT = REPOSITORY_ROOT / "tests"
SUMMARY_PATH = REPOSITORY_ROOT / "issue55_task2_summary.json"
for entry in (str(SRC_ROOT), str(TESTS_ROOT), str(REPOSITORY_ROOT)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from test_architecture_review import C4ArchitectureReviewTests  # noqa: E402
from test_architecture_review_verification import (  # noqa: E402
    C4ArchitectureReviewerRootVerificationTests,
    C4ArchitectureReviewVerificationTests,
)
from test_issue55_validation_snapshot import Issue55ValidationSnapshotTests  # noqa: E402


ALLOWED_TASK3_FAILURE_METHODS = {
    "test_invalid_utf8_bad_signature_fails_integrity_before_parser_semantics",
    "test_malformed_json_bad_signature_fails_integrity_before_parser_semantics",
    "test_validly_signed_invalid_utf8_reaches_validation_only_after_verifier_call",
    "test_validly_signed_nested_duplicate_key_json_rejected_after_verifier_call",
    "test_validly_signed_top_level_duplicate_key_json_rejected_after_verifier_call",
}
TASK2_METHOD_PREFIXES = (
    "test_constructor_",
    "test_prepare_reviewer_root_",
    "test_default_deny_",
    "test_root_",
)
NOT_IMPLEMENTED_MARKER = "C4 architecture review is not implemented"


def _test_method(test: unittest.case.TestCase) -> str:
    return test.id().rsplit(".", 1)[-1]


def _records(result: unittest.TestResult) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for outcome, collection in (("FAIL", result.failures), ("ERROR", result.errors)):
        for test, traceback_text in collection:
            records.append(
                {
                    "outcome": outcome,
                    "id": test.id(),
                    "method": _test_method(test),
                    "traceback": traceback_text,
                }
            )
    for test in getattr(result, "unexpectedSuccesses", ()):
        records.append(
            {
                "outcome": "UNEXPECTED_SUCCESS",
                "id": test.id(),
                "method": _test_method(test),
                "traceback": "",
            }
        )
    return records


def _run(suite: unittest.TestSuite, label: str) -> unittest.TestResult:
    print(f"\n===== {label} =====", flush=True)
    return unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)


def _focused_suite() -> tuple[unittest.TestSuite, int]:
    loader = unittest.defaultTestLoader
    suite = unittest.TestSuite()
    selected = [
        method
        for method in loader.getTestCaseNames(C4ArchitectureReviewTests)
        if method.startswith(TASK2_METHOD_PREFIXES)
    ]
    for method in selected:
        suite.addTest(C4ArchitectureReviewTests(method))
    suite.addTests(loader.loadTestsFromTestCase(C4ArchitectureReviewerRootVerificationTests))
    suite.addTests(loader.loadTestsFromTestCase(C4ArchitectureReviewVerificationTests))
    suite.addTests(loader.loadTestsFromTestCase(Issue55ValidationSnapshotTests))
    return suite, suite.countTestCases()


def _full_suite() -> unittest.TestSuite:
    return unittest.defaultTestLoader.discover(
        start_dir=str(TESTS_ROOT),
        pattern="test_*.py",
    )


def _write_summary(summary: dict[str, object]) -> str:
    rendered = json.dumps(summary, indent=2, sort_keys=True)
    SUMMARY_PATH.write_text(rendered + "\n", encoding="utf-8")
    return rendered


def main() -> int:
    focused, focused_count = _focused_suite()
    focused_result = _run(focused, "ISSUE 55 TASK2 FOCUSED GATE")
    focused_records = _records(focused_result)

    full = _full_suite()
    full_count = full.countTestCases()
    full_result = _run(full, "FULL REPOSITORY CLASSIFICATION GATE")
    full_records = _records(full_result)

    observed_allowed = {
        record["method"]
        for record in full_records
        if record["method"] in ALLOWED_TASK3_FAILURE_METHODS
    }
    missing_allowed = sorted(ALLOWED_TASK3_FAILURE_METHODS - observed_allowed)
    unexpected = [
        {
            "outcome": record["outcome"],
            "id": record["id"],
            "method": record["method"],
            "first_causal_line": next(
                (
                    line.strip()
                    for line in reversed(record["traceback"].splitlines())
                    if line.strip()
                ),
                "",
            ),
        }
        for record in full_records
        if record["method"] not in ALLOWED_TASK3_FAILURE_METHODS
    ]
    wrong_task3_cause = sorted(
        record["method"]
        for record in full_records
        if record["method"] in ALLOWED_TASK3_FAILURE_METHODS
        and NOT_IMPLEMENTED_MARKER not in record["traceback"]
    )
    duplicate_allowed = sorted(
        method
        for method in ALLOWED_TASK3_FAILURE_METHODS
        if sum(record["method"] == method for record in full_records) != 1
    )

    focused_ok = focused_result.wasSuccessful()
    full_classification_ok = not (
        missing_allowed or unexpected or wrong_task3_cause or duplicate_allowed
    )
    gate_ok = focused_ok and full_classification_ok

    summary: dict[str, object] = {
        "gate": "STARCOM_C4_ISSUE55_TASK2",
        "result": "PASS" if gate_ok else "FAIL",
        "focused": {
            "tests_run": focused_result.testsRun,
            "expected_count": focused_count,
            "failures": len(focused_result.failures),
            "errors": len(focused_result.errors),
            "unexpected_successes": len(
                getattr(focused_result, "unexpectedSuccesses", ())
            ),
            "records": [
                {
                    "outcome": record["outcome"],
                    "id": record["id"],
                    "method": record["method"],
                }
                for record in focused_records
            ],
        },
        "full_repository": {
            "tests_discovered": full_count,
            "tests_run": full_result.testsRun,
            "failures": len(full_result.failures),
            "errors": len(full_result.errors),
            "unexpected_successes": len(
                getattr(full_result, "unexpectedSuccesses", ())
            ),
            "allowed_task3_failures_observed": sorted(observed_allowed),
            "allowed_task3_failures_missing": missing_allowed,
            "allowed_task3_duplicate_or_missing_count": duplicate_allowed,
            "allowed_task3_wrong_cause": wrong_task3_cause,
            "unexpected_records": unexpected,
        },
    }
    rendered = _write_summary(summary)
    print("\n===== MACHINE-READABLE SUMMARY =====", flush=True)
    print(rendered, flush=True)
    print(
        "STARCOM_ISSUE55_TASK2_GATE=" + ("PASS" if gate_ok else "FAIL"),
        flush=True,
    )
    return 0 if gate_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
