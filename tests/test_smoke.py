from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PackageSmokeTests(unittest.TestCase):
    def test_version_and_module_help(self) -> None:
        sys.path.insert(0, str(ROOT / "src"))
        import starcom  # type: ignore[import-not-found]

        self.assertEqual(starcom.__version__, "0.1.0")

        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        result = subprocess.run(
            [sys.executable, "-m", "starcom", "--help"],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("STARCOM", result.stdout)
        self.assertIn("doctor", result.stdout)


if __name__ == "__main__":
    unittest.main()
