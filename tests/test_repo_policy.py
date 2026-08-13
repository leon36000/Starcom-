from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from scripts.build_manifest import build_manifest, render_manifest, verify_manifest
from scripts.secret_scan import scan_repository


class RepositoryPolicyTests(unittest.TestCase):
    def test_scanner_rejects_latest_github_action(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            workflow = root / ".github" / "workflows" / "ci.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text("steps:\n  - uses: actions/checkout@latest\n", encoding="utf-8")
            codes = {finding.code for finding in scan_repository(root)}
            self.assertIn("UNPINNED_GITHUB_ACTION", codes)

    def test_scanner_rejects_private_key_material(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            secret = root / "src" / "leaked.py"
            secret.parent.mkdir(parents=True)
            header = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
            secret.write_text(f'KEY = "{header}"\n', encoding="utf-8")
            findings = scan_repository(root)
            self.assertTrue(any(item.code == "PRIVATE_KEY_MATERIAL" for item in findings))

    def test_scanner_rejects_placeholder_tokens_in_production_code(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            source = root / "src" / "starcom" / "unfinished.py"
            source.parent.mkdir(parents=True)
            source.write_text("# TODO implement this path\n", encoding="utf-8")
            codes = {finding.code for finding in scan_repository(root)}
            self.assertIn("PRODUCTION_PLACEHOLDER", codes)

    def test_scanner_rejects_floating_build_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            (root / "pyproject.toml").write_text(
                '[build-system]\nrequires = ["setuptools>=75"]\n',
                encoding="utf-8",
            )
            codes = {finding.code for finding in scan_repository(root)}
            self.assertIn("FLOATING_DEPENDENCY", codes)

    def test_scanner_rejects_generated_database_files(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            (root / "runtime.sqlite3").write_bytes(b"SQLite format 3\x00")
            findings = scan_repository(root)
            self.assertTrue(any(item.code == "DATABASE_ARTIFACT" for item in findings))

    def test_manifest_detects_missing_unlisted_and_tampered_files(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            (root / "src").mkdir()
            tracked = root / "src" / "tracked.py"
            tracked.write_text("VALUE = 1\n", encoding="utf-8")
            manifest_path = root / "MANIFEST.sha256"
            manifest_path.write_text(render_manifest(build_manifest(root)), encoding="utf-8")
            clean = verify_manifest(root, manifest_path)
            self.assertTrue(clean.ok, clean)

            tracked.write_text("VALUE = 2\n", encoding="utf-8")
            tampered = verify_manifest(root, manifest_path)
            self.assertIn("src/tracked.py", tampered.mismatched)

            tracked.write_text("VALUE = 1\n", encoding="utf-8")
            (root / "src" / "unlisted.py").write_text("VALUE = 3\n", encoding="utf-8")
            unlisted = verify_manifest(root, manifest_path)
            self.assertIn("src/unlisted.py", unlisted.unlisted)

            manifest_path.write_text(
                manifest_path.read_text(encoding="utf-8")
                + f"{'0' * 64}  src/missing.py\n",
                encoding="utf-8",
            )
            missing = verify_manifest(root, manifest_path)
            self.assertIn("src/missing.py", missing.missing)


if __name__ == "__main__":
    unittest.main()
