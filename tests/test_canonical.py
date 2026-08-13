from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
import hashlib
import math
import unittest
from uuid import UUID

from starcom.canonical import canonical_json, canonical_json_bytes, sha256_digest, utc_now
from starcom.errors import StarcomError, ValidationError


@dataclass(frozen=True)
class Sample:
    name: str
    count: int


class CanonicalTests(unittest.TestCase):
    def test_canonical_json_is_sorted_compact_and_unicode_preserving(self) -> None:
        value = {"z": 1, "é": "été", "a": [True, None, 2]}
        self.assertEqual(
            canonical_json(value),
            '{"a":[true,null,2],"z":1,"é":"été"}',
        )

    def test_datetime_is_normalized_to_utc_microseconds(self) -> None:
        source = datetime(2026, 8, 13, 8, 30, 1, 1234, tzinfo=timezone(timedelta(hours=-4)))
        self.assertEqual(
            canonical_json({"at": source}),
            '{"at":"2026-08-13T12:30:01.001234Z"}',
        )

    def test_dataclass_and_uuid_are_normalized(self) -> None:
        value = {
            "item": Sample(name="alpha", count=2),
            "id": UUID("12345678-1234-5678-1234-567812345678"),
        }
        self.assertEqual(
            canonical_json(value),
            '{"id":"12345678-1234-5678-1234-567812345678","item":{"count":2,"name":"alpha"}}',
        )

    def test_naive_datetime_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValidationError, "timezone-aware"):
            canonical_json(datetime(2026, 8, 13, 12, 0, 0))

    def test_non_string_mapping_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValidationError, "string keys"):
            canonical_json({1: "bad"})

    def test_unsupported_types_are_rejected(self) -> None:
        for value in ({1, 2}, b"secret", complex(1, 2)):
            with self.subTest(value=repr(value)):
                with self.assertRaises(ValidationError):
                    canonical_json(value)

    def test_non_finite_float_is_rejected(self) -> None:
        for value in (math.nan, math.inf, -math.inf):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValidationError, "finite"):
                    canonical_json(value)

    def test_sha256_digest_hashes_exact_bytes_or_canonical_value(self) -> None:
        self.assertEqual(sha256_digest(b"abc"), hashlib.sha256(b"abc").hexdigest())
        self.assertEqual(
            sha256_digest({"b": 2, "a": 1}),
            hashlib.sha256(b'{"a":1,"b":2}').hexdigest(),
        )

    def test_utc_now_has_canonical_utc_shape(self) -> None:
        value = utc_now()
        self.assertRegex(value, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")

    def test_domain_error_has_stable_machine_payload(self) -> None:
        error = StarcomError("EXAMPLE", "failed", {"field": "value"})
        self.assertEqual(str(error), "failed")
        self.assertEqual(
            error.to_dict(),
            {"error": "EXAMPLE", "message": "failed", "details": {"field": "value"}},
        )


if __name__ == "__main__":
    unittest.main()
