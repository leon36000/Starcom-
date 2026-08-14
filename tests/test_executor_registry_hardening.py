from __future__ import annotations

import json
from pathlib import Path
import subprocess
import unittest

import test_executor_registry as registry_fixture

from starcom.errors import IntegrityError, ValidationError


class C3ExecutorRegistryHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.helper = registry_fixture.C3ExecutorRegistryTests(
            methodName="test_exact_signed_qualification_does_not_enable"
        )
        self.helper.setUp()
        self.database = self.helper.database
        self.registry = self.helper.registry
        self.root = self.helper.root

    def tearDown(self) -> None:
        self.helper.tearDown()

    def sign_with_new_key(self, payload: bytes) -> bytes:
        private_key = self.root / "substitute-private.pem"
        signature_path = self.root / "substitute.sig"
        payload_path = self.root / "substitute.json"
        payload_path.write_bytes(payload)
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                str(private_key),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(private_key),
                "-rawin",
                "-in",
                str(payload_path),
                "-out",
                str(signature_path),
            ],
            check=True,
            capture_output=True,
        )
        return signature_path.read_bytes()

    def test_duplicate_key_and_extra_signed_field_are_rejected(self) -> None:
        self.helper.register()
        self.helper.accept_root()
        payload = self.helper.qualification_payload()
        duplicate = payload.decode("utf-8").replace(
            '"qualification_id":"qualification-fake-executor"',
            '"qualification_id":"qualification-fake-executor",'
            '"qualification_id":"qualification-replaced"',
            1,
        ).encode("utf-8")
        duplicate_signature = self.helper.sign(duplicate)
        with self.assertRaises(ValidationError):
            self.registry.prepare_qualification(
                "fake-executor",
                "qualifier-key",
                duplicate,
                duplicate_signature,
            )

        value = json.loads(payload.decode("utf-8"))
        value["unexpected"] = "must fail closed"
        extra = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        extra_signature = self.helper.sign(extra)
        with self.assertRaises(ValidationError):
            self.registry.prepare_qualification(
                "fake-executor",
                "qualifier-key",
                extra,
                extra_signature,
            )

    def test_key_substitution_is_rejected_before_payload_trust(self) -> None:
        self.helper.register()
        self.helper.accept_root()
        payload = self.helper.qualification_payload()
        substitute_signature = self.sign_with_new_key(payload)

        with self.assertRaises(IntegrityError):
            self.registry.prepare_qualification(
                "fake-executor",
                "qualifier-key",
                payload,
                substitute_signature,
            )

    def test_verifier_detects_descriptor_digest_and_column_tampering(self) -> None:
        self.helper.register()
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

        verification = self.registry.verify("fake-executor")

        self.assertFalse(verification.ok)
        self.assertIn("C3_EXECUTOR_DESCRIPTOR_MISMATCH", verification.defects)

    def test_verifier_detects_qualifier_root_fingerprint_tampering(self) -> None:
        self.helper.register()
        self.helper.accept_root()
        self.helper.qualify()
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

        verification = self.registry.verify("fake-executor")

        self.assertFalse(verification.ok)
        self.assertIn("C3_EXECUTOR_QUALIFIER_ROOT_INVALID", verification.defects)

    def test_verifier_detects_stored_qualification_payload_tampering(self) -> None:
        self.helper.register()
        self.helper.accept_root()
        self.helper.qualify()
        self.database.connection.execute(
            "DROP TRIGGER c3_executor_qualifications_no_update"
        )
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
            """
            UPDATE c3_executor_qualifications SET payload = ?
            WHERE executor_id = ?
            """,
            (bytes(row["payload"]) + b" ", "fake-executor"),
        )

        verification = self.registry.verify("fake-executor")

        self.assertFalse(verification.ok)
        self.assertIn(
            "C3_EXECUTOR_QUALIFICATION_PAYLOAD_SHA256_MISMATCH",
            verification.defects,
        )
        self.assertIn(
            "C3_EXECUTOR_QUALIFICATION_SIGNATURE_INVALID",
            verification.defects,
        )

    def test_verifier_detects_registration_and_root_consumption_tampering(self) -> None:
        self.helper.register()
        descriptor = self.registry.get_descriptor("fake-executor")
        self.database.connection.execute(
            "DROP TRIGGER continuity_authorization_consumptions_no_update"
        )
        self.database.connection.execute(
            """
            UPDATE continuity_authorization_consumptions SET operation_id = ?
            WHERE decision_id = ?
            """,
            ("different-executor", descriptor.authorization_decision_id),
        )
        registration_verification = self.registry.verify("fake-executor")
        self.assertFalse(registration_verification.ok)
        self.assertIn(
            "C3_EXECUTOR_CONSUMPTION_MISMATCH:1",
            registration_verification.defects,
        )

        self.helper.accept_root()
        self.helper.qualify()
        root = self.registry.get_qualifier_root("qualifier-key")
        self.database.connection.execute(
            """
            UPDATE continuity_authorization_consumptions SET operation_kind = ?
            WHERE decision_id = ?
            """,
            ("WRONG_OPERATION", root.authorization_decision_id),
        )
        root_verification = self.registry.verify("fake-executor")
        self.assertFalse(root_verification.ok)
        self.assertIn(
            "C3_EXECUTOR_QUALIFIER_ROOT_CONSUMPTION_MISMATCH",
            root_verification.defects,
        )

    def test_verifier_detects_transition_ledger_actor_and_payload_tampering(self) -> None:
        self.helper.register()
        transition = self.database.connection.execute(
            """
            SELECT ledger_event_id FROM c3_executor_transitions
            WHERE executor_id = ? AND sequence = 1
            """,
            ("fake-executor",),
        ).fetchone()
        self.assertIsNotNone(transition)
        assert transition is not None
        self.database.connection.execute("DROP TRIGGER ledger_events_no_update")
        self.database.connection.execute(
            "UPDATE ledger_events SET actor = ?, payload_json = ? WHERE event_id = ?",
            (
                "intruder",
                json.dumps(
                    {"executor_id": "different-executor"},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                str(transition["ledger_event_id"]),
            ),
        )

        verification = self.registry.verify("fake-executor")

        self.assertFalse(verification.ok)
        self.assertIn("C3_EXECUTOR_LEDGER_ACTOR_MISMATCH:1", verification.defects)
        self.assertIn("C3_EXECUTOR_LEDGER_PAYLOAD_MISMATCH:1", verification.defects)
        self.assertTrue(
            any(
                defect.startswith("C3_EXECUTOR_LEDGER_CHAIN:")
                for defect in verification.defects
            ),
            verification.defects,
        )


if __name__ == "__main__":
    unittest.main()
