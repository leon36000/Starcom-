from __future__ import annotations

import hashlib
from pathlib import Path
import unittest


class Issue55ValidationSnapshotTests(unittest.TestCase):
    def test_exact_local_candidate_files_are_under_ci(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        expected = {
            "src/starcom/architecture_review.py": "ac0c937511e6693d3214a6a97a2aeac5a0f6a104d8f3cb82fe81855a835e1c0e",
            "tests/test_architecture_review.py": "366d5d66a7d53c61489701c2fdca7621cfe52e392ae8d8ee0cd42164f0e1b821",
            "tests/test_architecture_review_verification.py": "d4eaa923705e9569b33943a8ace8da147d51580a1150481a9835ee0e97c71d4a",
        }
        observed = {
            path: hashlib.sha256((repository_root / path).read_bytes()).hexdigest()
            for path in expected
        }
        self.assertEqual(expected, observed)
