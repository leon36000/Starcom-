from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from scripts.manifest_shards import load_manifest_shards


class SplitManifestDigestTests(unittest.TestCase):
    @staticmethod
    def half(character: str) -> str:
        return "".join([character * 8] * 4)

    def test_two_halves_reassemble_sha256(self) -> None:
        left = self.half("a")
        right = self.half("b")
        with tempfile.TemporaryDirectory() as tempdir:
            shard = Path(tempdir) / "MANIFEST.00.sha256"
            shard.write_text(
                f"left:{left}  src/example.py\nright:{right}  src/example.py\n",
                encoding="utf-8",
            )
            self.assertEqual(
                load_manifest_shards([shard]),
                {"src/example.py": left + right},
            )

    def test_missing_half_is_rejected(self) -> None:
        left = self.half("a")
        with tempfile.TemporaryDirectory() as tempdir:
            shard = Path(tempdir) / "MANIFEST.00.sha256"
            shard.write_text(f"left:{left}  src/example.py\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_manifest_shards([shard])

    def test_duplicate_half_is_rejected(self) -> None:
        left = self.half("a")
        other = self.half("b")
        right = self.half("c")
        with tempfile.TemporaryDirectory() as tempdir:
            shard = Path(tempdir) / "MANIFEST.00.sha256"
            shard.write_text(
                f"left:{left}  src/example.py\n"
                f"left:{other}  src/example.py\n"
                f"right:{right}  src/example.py\n",
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_manifest_shards([shard])


if __name__ == "__main__":
    unittest.main()
