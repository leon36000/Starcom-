from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from scripts.manifest_shards import load_manifest_shards


class DecimalManifestDigestTests(unittest.TestCase):
    def test_decimal_bytes_reassemble_sha256(self) -> None:
        digest = "01" * 32
        rendered = "dec:" + ",".join(["1"] * 32)
        with tempfile.TemporaryDirectory() as tempdir:
            shard = Path(tempdir) / "MANIFEST.00.sha256"
            shard.write_text(f"{rendered}  src/example.py\n", encoding="utf-8")
            self.assertEqual(load_manifest_shards([shard]), {"src/example.py": digest})

    def test_decimal_byte_out_of_range_is_rejected(self) -> None:
        rendered = "dec:" + ",".join(["256"] + ["1"] * 31)
        with tempfile.TemporaryDirectory() as tempdir:
            shard = Path(tempdir) / "MANIFEST.00.sha256"
            shard.write_text(f"{rendered}  src/example.py\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_manifest_shards([shard])


if __name__ == "__main__":
    unittest.main()
