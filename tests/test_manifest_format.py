from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from scripts.build_manifest import parse_manifest, render_manifest


class ManifestFormatTests(unittest.TestCase):
    def test_render_and_parse_use_four_digest_segments(self) -> None:
        digest = "a" * 64
        rendered = render_manifest({"src/example.py": digest})
        expected_digest = ":".join(["a" * 16] * 4)
        self.assertEqual(rendered, f"{expected_digest}  src/example.py\n")
        with tempfile.TemporaryDirectory() as tempdir:
            path = Path(tempdir) / "MANIFEST.sha256"
            path.write_text(rendered, encoding="utf-8")
            self.assertEqual(parse_manifest(path), {"src/example.py": digest})

    def test_unsegmented_digest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            path = Path(tempdir) / "MANIFEST.sha256"
            path.write_text(f"{'a' * 64}  src/example.py\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                parse_manifest(path)


if __name__ == "__main__":
    unittest.main()
