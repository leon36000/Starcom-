from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

import starcom.continuity as service_contracts
import starcom.continuity_types as canonical_contracts
from starcom.db import Database
from starcom.ledger import EventLedger
from starcom.trust import TrustPlane


ARCHIVE_SHA256 = "5609915904205503ebcdcc548d9b8171fd6d9ba9bf9d1bb9f1ebb036bf8fae7f"


class ContinuityTypeAuthorityTests(unittest.TestCase):
    def test_service_exports_are_exact_canonical_contract_classes(self) -> None:
        names = (
            "IncidentStatus",
            "SignatureVerifier",
            "IncidentRecord",
            "TrustRootReceipt",
            "ReviewAdmission",
            "RecoveryPublication",
            "ContinuityVerification",
        )
        for name in names:
            with self.subTest(name=name):
                self.assertIs(
                    getattr(service_contracts, name),
                    getattr(canonical_contracts, name),
                )

    def test_serialized_contract_values_are_preserved(self) -> None:
        self.assertEqual(
            [member.value for member in canonical_contracts.IncidentStatus],
            [
                "RECOVERY_REQUIRED",
                "RECOVERY_PUBLISHED_RECOLLECT_REQUIRED",
            ],
        )

    def test_service_returns_canonical_incident_record(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            database = Database(Path(tempdir) / "types.sqlite3")
            database.initialize()
            try:
                ledger = EventLedger(database)
                trust = TrustPlane(database, ledger)
                service = service_contracts.ContinuityService(database, ledger, trust)
                incident = service.create_incident(
                    "type-authority",
                    reviewed_archive_sha256=ARCHIVE_SHA256,
                    actor="owner",
                    occurred_at="2026-08-14T05:00:00.000000Z",
                )
                self.assertIsInstance(incident, canonical_contracts.IncidentRecord)
                self.assertIs(
                    incident.status,
                    canonical_contracts.IncidentStatus.RECOVERY_REQUIRED,
                )
                loaded = service.get_incident("type-authority")
                self.assertIsInstance(loaded, canonical_contracts.IncidentRecord)
                self.assertEqual(loaded.disposition, "RECOLLECT_REQUIRED")
            finally:
                database.close()


if __name__ == "__main__":
    unittest.main()
