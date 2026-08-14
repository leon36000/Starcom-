from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from scripts.manifest_shards import load_manifest_shards, verify_manifest_shards


class ManifestShardTests(unittest.TestCase):
    def test_load_reassembles_four_fixed_segments(self) -> None:
        digest = "a" * 64
        rendered = ":".join(["a" * 16] * 4)
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            shard = root / "MANIFEST.00.sha256"
            shard.write_text(f"{rendered}  src/example.py\n", encoding="utf-8")
            self.assertEqual(load_manifest_shards([shard]), {"src/example.py": digest})

    def test_load_reassembles_eight_short_segments(self) -> None:
        digest = "c" * 64
        rendered = ":".join(["c" * 8] * 8)
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            shard = root / "MANIFEST.00.sha256"
            shard.write_text(f"{rendered}  src/example.py\n", encoding="utf-8")
            self.assertEqual(load_manifest_shards([shard]), {"src/example.py": digest})

    def test_load_reassembles_sixteen_tiny_segments(self) -> None:
        digest = "d" * 64
        rendered = ":".join(["d" * 4] * 16)
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            shard = root / "MANIFEST.00.sha256"
            shard.write_text(f"{rendered}  src/example.py\n", encoding="utf-8")
            self.assertEqual(load_manifest_shards([shard]), {"src/example.py": digest})

    def test_percent_encoded_path_is_decoded(self) -> None:
        digest = "e" * 64
        rendered = ":".join(["e" * 8] * 8)
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            shard = root / "MANIFEST.00.sha256"
            shard.write_text(
                f"{rendered}  src/example%2Epy\n",
                encoding="utf-8",
            )
            self.assertEqual(load_manifest_shards([shard]), {"src/example.py": digest})

    def test_path_traversal_is_rejected_after_decoding(self) -> None:
        rendered = ":".join(["f" * 8] * 8)
        with tempfile.TemporaryDirectory() as tempdir:
            shard = Path(tempdir) / "MANIFEST.00.sha256"
            shard.write_text(f"{rendered}  src/%2E%2E/escape.py\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_manifest_shards([shard])

    def test_duplicate_path_across_shards_is_rejected(self) -> None:
        rendered = ":".join(["b" * 16] * 4)
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            first = root / "MANIFEST.00.sha256"
            second = root / "MANIFEST.01.sha256"
            first.write_text(f"{rendered}  src/example.py\n", encoding="utf-8")
            second.write_text(f"{rendered}  src/example.py\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_manifest_shards([first, second])

    def test_verifier_detects_tampering_and_unlisted_files(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            source = root / "src" / "example.py"
            source.parent.mkdir(parents=True)
            source.write_text("VALUE = 1\n", encoding="utf-8")
            import hashlib

            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            rendered = ":".join(digest[index : index + 16] for index in range(0, 64, 16))
            shard = root / "MANIFEST.00.sha256"
            shard.write_text(f"{rendered}  src/example.py\n", encoding="utf-8")
            self.assertTrue(verify_manifest_shards(root, [shard]).ok)

            source.write_text("VALUE = 2\n", encoding="utf-8")
            self.assertIn(
                "src/example.py",
                verify_manifest_shards(root, [shard]).mismatched,
            )

            source.write_text("VALUE = 1\n", encoding="utf-8")
            (root / "src" / "extra.py").write_text("VALUE = 3\n", encoding="utf-8")
            self.assertIn(
                "src/extra.py",
                verify_manifest_shards(root, [shard]).unlisted,
            )


if __name__ == "__main__":
    unittest.main()
