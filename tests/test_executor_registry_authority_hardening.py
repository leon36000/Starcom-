from __future__ import annotations

import json
import unittest

import test_executor_registry as registry_fixture

from starcom.errors import IntegrityError


class C3ExecutorRegistryAuthorityHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.helper = registry_fixture.C3ExecutorRegistryTests(
            methodName="test_exact_signed_qualification_does_not_enable"
        )
        self.helper.setUp()
        self.database = self.helper.database
        self.registry = self.helper.registry

    def tearDown(self) -> None:
        self.helper.tearDown()

    def root_row(self):  # type: ignore[no-untyped-def]
        row = self.database.connection.execute(
            "SELECT * FROM c3_executor_qualifier_roots WHERE key_id = ?",
            ("qualifier-key",),
        ).fetchone()
        self.assertIsNotNone(row)
        return row

    def test_exact_qualifier_root_replay_reverifies_existing_authority(self) -> None:
        self.helper.accept_root()
        row = self.root_row()
        self.database.connection.execute(
            "DROP TRIGGER c3_executor_qualifier_roots_no_update"
        )
        self.database.connection.execute(
            """
            UPDATE c3_executor_qualifier_roots
            SET public_key_fingerprint_sha256 = ? WHERE key_id = ?
            """,
            ("0" * 64, "qualifier-key"),
        )

        with self.assertRaises(IntegrityError):
            self.registry.accept_qualifier_root(
                "qualifier-key",
                self.helper.public_key.read_bytes(),
                authorization_decision_id=str(row["authorization_decision_id"]),
                actor=str(row["accepted_by"]),
                occurred_at=registry_fixture.R6,
            )

    def test_qualification_rejects_dirty_qualifier_root_before_signature_trust(self) -> None:
        self.helper.register()
        self.helper.accept_root()
        self.database.connection.execute(
            "DROP TRIGGER c3_executor_qualifier_roots_no_update"
        )
        self.database.connection.execute(
            """
            UPDATE c3_executor_qualifier_roots
            SET public_key_fingerprint_sha256 = ? WHERE key_id = ?
            """,
            ("0" * 64, "qualifier-key"),
        )
        payload = self.helper.qualification_payload()
        signature = self.helper.sign(payload)

        with self.assertRaises(IntegrityError):
            self.registry.prepare_qualification(
                "fake-executor",
                "qualifier-key",
                payload,
                signature,
            )

    def test_enable_rejects_dirty_qualification_authority(self) -> None:
        self.helper.register()
        self.helper.accept_root()
        self.helper.qualify()
        row = self.database.connection.execute(
            """
            SELECT payload FROM c3_executor_qualifications
            WHERE executor_id = ?
            """,
            ("fake-executor",),
        ).fetchone()
        self.assertIsNotNone(row)
        assert row is not None
        self.database.connection.execute(
            "DROP TRIGGER c3_executor_qualifications_no_update"
        )
        self.database.connection.execute(
            """
            UPDATE c3_executor_qualifications SET payload = ?
            WHERE executor_id = ?
            """,
            (bytes(row["payload"]) + b" ", "fake-executor"),
        )

        with self.assertRaises(IntegrityError):
            self.registry.prepare_enable("fake-executor")

    def test_exact_enable_replay_reverifies_existing_registry(self) -> None:
        self.helper.register()
        self.helper.accept_root()
        self.helper.qualify()
        self.helper.enable()
        current = self.registry.get_current("fake-executor")
        self.database.connection.execute(
            "DROP TRIGGER c3_executor_descriptors_no_update"
        )
        self.database.connection.execute(
            """
            UPDATE c3_executor_descriptors SET implementation_digest = ?
            WHERE executor_id = ?
            """,
            ("9" * 64, "fake-executor"),
        )

        with self.assertRaises(IntegrityError):
            self.registry.enable(
                "fake-executor",
                authorization_decision_id=current.authorization_decision_id,
                actor=current.transitioned_by,
                occurred_at=registry_fixture.R6,
            )

    def test_verifier_detects_descriptor_row_provenance_tampering(self) -> None:
        self.helper.register()
        self.database.connection.execute(
            "DROP TRIGGER c3_executor_descriptors_no_update"
        )
        self.database.connection.execute(
            """
            UPDATE c3_executor_descriptors SET registered_by = ?
            WHERE executor_id = ?
            """,
            ("intruder", "fake-executor"),
        )

        verification = self.registry.verify("fake-executor")

        self.assertFalse(verification.ok)
        self.assertIn(
            "C3_EXECUTOR_DESCRIPTOR_PROVENANCE_MISMATCH",
            verification.defects,
        )

    def test_verifier_detects_qualification_row_provenance_tampering(self) -> None:
        self.helper.register()
        self.helper.accept_root()
        self.helper.qualify()
        self.database.connection.execute(
            "DROP TRIGGER c3_executor_qualifications_no_update"
        )
        self.database.connection.execute(
            """
            UPDATE c3_executor_qualifications SET admitted_by = ?
            WHERE executor_id = ?
            """,
            ("intruder", "fake-executor"),
        )

        verification = self.registry.verify("fake-executor")

        self.assertFalse(verification.ok)
        self.assertIn(
            "C3_EXECUTOR_QUALIFICATION_PROVENANCE_MISMATCH",
            verification.defects,
        )

    def test_verifier_checks_exact_qualifier_root_event_payload(self) -> None:
        self.helper.register()
        self.helper.accept_root()
        self.helper.qualify()
        root = self.root_row()
        self.database.connection.execute("DROP TRIGGER ledger_events_no_update")
        self.database.connection.execute(
            "UPDATE ledger_events SET payload_json = ? WHERE event_id = ?",
            (
                json.dumps(
                    {"key_id": "different-key"},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                str(root["ledger_event_id"]),
            ),
        )

        verification = self.registry.verify("fake-executor")

        self.assertFalse(verification.ok)
        self.assertIn(
            "C3_EXECUTOR_QUALIFIER_ROOT_EVENT_PAYLOAD_MISMATCH",
            verification.defects,
        )


if __name__ == "__main__":
    unittest.main()
