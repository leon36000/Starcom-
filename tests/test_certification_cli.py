from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from starcom.census import C2CensusService
from starcom.certification import C2CertificationService
from starcom.continuity import ContinuityService
from starcom.db import Database
from starcom.ledger import EventLedger
from starcom.recollection import C2RecollectionService
from starcom.research import ReceiptOutcome, ResearchCampaign
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule, TrustPlane


ARCHIVE_SHA256 = "5609915904205503ebcdcc548d9b8171fd6d9ba9bf9d1bb9f1ebb036bf8fae7f"
SNAPSHOT_DIGEST = hashlib.sha256(b"certification-cli-snapshot").hexdigest()
T0 = "2026-08-14T07:00:00.000000Z"
T1 = "2026-08-14T07:01:00.000000Z"
T2 = "2026-08-14T07:02:00.000000Z"
T3 = "2026-08-14T07:03:00.000000Z"
T4 = "2026-08-14T07:04:00.000000Z"
T5 = "2026-08-14T07:05:00.000000Z"
T6 = "2026-08-14T07:06:00.000000Z"
T7 = "2026-08-14T07:07:00.000000Z"
T8 = "2026-08-14T07:08:00.000000Z"
T9 = "2026-08-14T07:09:00.000000Z"
T10 = "2026-08-14T07:10:00.000000Z"
T11 = "2026-08-14T07:11:00.000000Z"


class C2CertificationCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.class_tempdir = tempfile.TemporaryDirectory()
        cls.base_root = Path(cls.class_tempdir.name)
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.base_db_path = cls.base_root / "eligible-base.sqlite3"
        cls.reviewer_private = cls.base_root / "reviewer-private.pem"
        cls.reviewer_public = cls.base_root / "reviewer-public.pem"
        cls.certifier_private = cls.base_root / "certifier-private.pem"
        cls.certifier_public = cls.base_root / "certifier-public.pem"
        cls.payload_path = cls.base_root / "C2-CERTIFICATION.json"
        cls.signature_path = cls.base_root / "C2-CERTIFICATION.sig"
        cls._generate_keypair(cls.reviewer_private, cls.reviewer_public)
        cls._generate_keypair(cls.certifier_private, cls.certifier_public)
        cls._build_eligible_base_database()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.class_tempdir.cleanup()

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.db_path = self.root / "starcom.sqlite3"
        shutil.copy2(self.base_db_path, self.db_path)
        self.env = os.environ.copy()
        self.env["PYTHONPATH"] = str(self.repo_root / "src")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    @staticmethod
    def _run_openssl(arguments: list[str]) -> None:
        subprocess.run(
            ["openssl", *arguments],
            check=True,
            capture_output=True,
        )

    @classmethod
    def _generate_keypair(cls, private_key: Path, public_key: Path) -> None:
        cls._run_openssl(
            ["genpkey", "-algorithm", "ED25519", "-out", str(private_key)]
        )
        cls._run_openssl(
            [
                "pkey",
                "-in",
                str(private_key),
                "-pubout",
                "-out",
                str(public_key),
            ]
        )

    @classmethod
    def _sign_file(
        cls,
        private_key: Path,
        payload_path: Path,
        signature_path: Path,
    ) -> None:
        cls._run_openssl(
            [
                "pkeyutl",
                "-sign",
                "-inkey",
                str(private_key),
                "-rawin",
                "-in",
                str(payload_path),
                "-out",
                str(signature_path),
            ]
        )

    @staticmethod
    def _allow(
        trust: TrustPlane,
        *,
        action: str,
        resource: str,
        rule_id: str,
        now: str,
    ) -> str:
        trust.add_rule(
            PolicyRule(rule_id, PolicyEffect.ALLOW, "owner", action, resource),
            actor="owner",
            occurred_at=T0,
        )
        decision = trust.authorize(
            AuthorizationRequest(subject="owner", action=action, resource=resource),
            now=now,
        )
        if not decision.allowed:
            raise AssertionError("fixture authorization was unexpectedly denied")
        return decision.decision_id

    @staticmethod
    def _review_payload() -> bytes:
        value = {
            "review_id": "review-certification-cli",
            "reviewer_identity": "independent-c1-cli-reviewer",
            "review_environment": "isolated-certification-cli-fixture",
            "reviewed_archive_sha256": ARCHIVE_SHA256,
            "reviewed_at_utc": T1,
            "independence_basis": "separate generated reviewer key",
            "independent_identity_status": "SATISFIED",
            "commands_and_exit_codes": [{"command": "verify", "exit_code": 0}],
            "receipt_snapshot_observation_result": "PASS",
            "wave_order_result": "CONFIRMS_W3_TO_W2",
            "attempt_boundary_result": "POSSIBLE_UNQUANTIFIED_CONFIRMED",
            "disposition": "RECOLLECT_REQUIRED",
            "evidence_paths_and_hashes": [
                {"path": "review.json", "sha256": "a" * 64}
            ],
            "reasoning": "The explicit fixture requires C2 recollection.",
            "gate_effect": "NO_GATE_CHANGE",
        }
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )

    @classmethod
    def _build_eligible_base_database(cls) -> None:
        database = Database(cls.base_db_path)
        database.initialize()
        try:
            ledger = EventLedger(database)
            trust = TrustPlane(database, ledger)
            continuity = ContinuityService(database, ledger, trust)
            research = ResearchCampaign(database, ledger)
            recollection = C2RecollectionService(
                database,
                ledger,
                continuity,
                research,
            )
            census = C2CensusService(
                database,
                ledger,
                recollection,
                research,
            )
            certification = C2CertificationService(
                database,
                ledger,
                continuity,
                recollection,
                census,
            )

            continuity.create_incident(
                "task5",
                reviewed_archive_sha256=ARCHIVE_SHA256,
                actor="owner",
                occurred_at=T0,
            )
            research.create(
                campaign_id="c2-campaign",
                name="Task 5 explicit certification CLI fixture",
                actor="owner",
                occurred_at=T0,
            )

            reviewer_decision = cls._allow(
                trust,
                action="continuity.trust-root.accept",
                resource="continuity:trust-root:reviewer-certification-cli",
                rule_id="allow-reviewer-certification-cli",
                now=T1,
            )
            continuity.accept_trust_root(
                "reviewer-certification-cli",
                cls.reviewer_public.read_bytes(),
                decision_id=reviewer_decision,
                actor="owner",
                occurred_at=T1,
            )
            review_payload_path = cls.base_root / "C1-REVIEW.json"
            review_signature_path = cls.base_root / "C1-REVIEW.sig"
            review_payload = cls._review_payload()
            review_payload_path.write_bytes(review_payload)
            cls._sign_file(
                cls.reviewer_private,
                review_payload_path,
                review_signature_path,
            )
            review = continuity.admit_review(
                "task5",
                "reviewer-certification-cli",
                review_payload,
                review_signature_path.read_bytes(),
                actor="owner",
                occurred_at=T2,
            )
            recovery_decision = cls._allow(
                trust,
                action="continuity.recovery.publish",
                resource="continuity:incident:task5",
                rule_id="allow-recovery-certification-cli",
                now=T3,
            )
            continuity.publish_recovery(
                "task5",
                review.review_id,
                publication_id="publication-certification-cli",
                idempotency_key="publish-certification-cli",
                decision_id=recovery_decision,
                actor="owner",
                occurred_at=T3,
            )
            recollection.start(
                "c2-run",
                incident_id="task5",
                campaign_id="c2-campaign",
                minimum_identity_target=800,
                actor="owner",
                occurred_at=T4,
            )

            certifier_decision = cls._allow(
                trust,
                action="continuity.trust-root.accept",
                resource="continuity:trust-root:certifier-certification-cli",
                rule_id="allow-certifier-certification-cli",
                now=T5,
            )
            continuity.accept_trust_root(
                "certifier-certification-cli",
                cls.certifier_public.read_bytes(),
                decision_id=certifier_decision,
                actor="owner",
                occurred_at=T5,
            )

            research.begin_attempt(
                "c2-campaign",
                attempt_id="attempt-certification-cli",
                wave=1,
                request_key="request-certification-cli",
                source_id="github",
                request={"url": "https://example.invalid/certification-cli"},
                actor="collector",
                occurred_at=T6,
            )
            research.record_receipt(
                "attempt-certification-cli",
                receipt_id="receipt-certification-cli",
                outcome=ReceiptOutcome.SUCCESS,
                status_code=200,
                snapshot_digest=SNAPSHOT_DIGEST,
                metadata={"fixture": True},
                actor="collector",
                occurred_at=T6,
            )
            research.checkpoint_cursor(
                "c2-campaign",
                wave=1,
                cursor_key="page",
                value={"page": 1},
                attempt_id="attempt-certification-cli",
                cursor_id="cursor-certification-cli",
                actor="collector",
                occurred_at=T7,
            )
            for index in range(800):
                identity_key = f"identity-{index:04d}"
                observation_id = f"observation-{index:04d}"
                content_digest = hashlib.sha256(identity_key.encode("utf-8")).hexdigest()
                research.record_observation(
                    "attempt-certification-cli",
                    observation_id=observation_id,
                    snapshot_digest=SNAPSHOT_DIGEST,
                    content_digest=content_digest,
                    data={"identity": identity_key, "fixture": True},
                    actor="collector",
                    occurred_at=T7,
                )
                census.register_identity(
                    "c2-run",
                    identity_id=f"identity-record-{index:04d}",
                    identity_key=identity_key,
                    source_id="github",
                    attempt_id="attempt-certification-cli",
                    observation_id=observation_id,
                    actor="collector",
                    occurred_at=T8,
                )

            snapshot = certification.snapshot("c2-run")
            payload = {
                "certificate_id": "certificate-certification-cli",
                "recollection_id": snapshot.recollection_id,
                "incident_id": snapshot.incident_id,
                "campaign_id": snapshot.campaign_id,
                "identity_count": snapshot.identity_count,
                "required_target": snapshot.required_target,
                "identity_set_digest": snapshot.identity_set_digest,
                "certifier_identity": "independent-certifier-cli",
                "certifier_environment": "isolated-cli-certifier",
                "certified_at_utc": T10,
                "independence_basis": "separate generated certifier key and identity",
                "independent_identity_status": "SATISFIED",
                "census_verification_result": "PASS",
                "verdict": "C2_CENSUS_CERTIFIED",
                "gate_effect": "NO_CANONICAL_PROMOTION",
            }
            cls.payload_path.write_bytes(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                )
            )
            cls._sign_file(
                cls.certifier_private,
                cls.payload_path,
                cls.signature_path,
            )
            database.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            database.close()

    def run_cli(
        self,
        *args: str,
        db_path: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "starcom",
                "--db",
                str(db_path or self.db_path),
                *args,
            ],
            cwd=self.repo_root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
        )

    @staticmethod
    def decode_stdout(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
        if not result.stdout.strip():
            raise AssertionError(result.stderr)
        return json.loads(result.stdout)

    @staticmethod
    def decode_stderr(result: subprocess.CompletedProcess[str]) -> dict[str, object]:
        if not result.stderr.strip():
            raise AssertionError(result.stdout)
        return json.loads(result.stderr)

    def success(self, result: subprocess.CompletedProcess[str]) -> dict[str, object]:
        self.assertEqual(result.returncode, 0, result.stderr)
        return self.decode_stdout(result)

    def admit(
        self,
        *,
        payload_path: Path | None = None,
        signature_path: Path | None = None,
        db_path: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return self.run_cli(
            "certification",
            "admit",
            "--recollection-id",
            "c2-run",
            "--key-id",
            "certifier-certification-cli",
            "--payload-file",
            str(payload_path or self.payload_path),
            "--signature-file",
            str(signature_path or self.signature_path),
            "--actor",
            "admission-agent",
            "--occurred-at",
            T11,
            db_path=db_path,
        )

    def test_snapshot_admit_get_and_verify_preserve_exact_bytes(self) -> None:
        snapshot = self.success(
            self.run_cli(
                "certification",
                "snapshot",
                "--recollection-id",
                "c2-run",
            )
        )["result"]  # type: ignore[index]
        self.assertEqual(snapshot["identity_count"], 800)  # type: ignore[index]
        self.assertEqual(snapshot["required_target"], 800)  # type: ignore[index]
        self.assertEqual(snapshot["latest_identity_at"], T8)  # type: ignore[index]
        self.assertNotIn("members", snapshot)

        tampered_path = self.root / "tampered-certification.json"
        tampered_path.write_bytes(self.payload_path.read_bytes() + b" ")
        rejected = self.admit(payload_path=tampered_path)
        self.assertEqual(rejected.returncode, 2)
        rejected_payload = self.decode_stderr(rejected)
        self.assertEqual(rejected_payload["error"], "INTEGRITY_ERROR")
        self.assertEqual(
            rejected_payload["message"],
            "C2 certification signature is invalid",
        )

        admitted = self.success(self.admit())["result"]  # type: ignore[index]
        expected_payload_sha256 = hashlib.sha256(self.payload_path.read_bytes()).hexdigest()
        expected_signature_sha256 = hashlib.sha256(
            self.signature_path.read_bytes()
        ).hexdigest()
        self.assertEqual(admitted["payload_sha256"], expected_payload_sha256)  # type: ignore[index]
        self.assertEqual(admitted["signature_sha256"], expected_signature_sha256)  # type: ignore[index]

        with sqlite3.connect(self.db_path) as connection:
            row = connection.execute(
                "SELECT payload, signature FROM c2_certifications WHERE certificate_id = ?",
                ("certificate-certification-cli",),
            ).fetchone()
        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual(bytes(row[0]), self.payload_path.read_bytes())
        self.assertEqual(bytes(row[1]), self.signature_path.read_bytes())

        loaded = self.success(
            self.run_cli(
                "certification",
                "get",
                "--certificate-id",
                "certificate-certification-cli",
            )
        )["result"]  # type: ignore[index]
        self.assertEqual(loaded["identity_count"], 800)  # type: ignore[index]
        verified = self.success(
            self.run_cli(
                "certification",
                "verify",
                "--certificate-id",
                "certificate-certification-cli",
            )
        )["result"]  # type: ignore[index]
        self.assertTrue(verified["ok"])  # type: ignore[index]
        self.assertEqual(verified["defects"], [])  # type: ignore[index]

    def test_verify_returns_exit_three_after_membership_tampering(self) -> None:
        self.success(self.admit())
        with sqlite3.connect(self.db_path) as connection:
            connection.execute("DROP TRIGGER c2_certification_members_no_update")
            connection.execute(
                """
                UPDATE c2_certification_members
                SET evidence_digest = ?
                WHERE certificate_id = ? AND ordinal = 0
                """,
                ("0" * 64, "certificate-certification-cli"),
            )
            connection.commit()

        result = self.run_cli(
            "certification",
            "verify",
            "--certificate-id",
            "certificate-certification-cli",
        )

        self.assertEqual(result.returncode, 3, result.stderr)
        verification = self.decode_stdout(result)["result"]  # type: ignore[index]
        self.assertFalse(verification["ok"])  # type: ignore[index]
        self.assertIn(
            "C2_CERT_MEMBER_MATERIAL_MISMATCH:0",
            verification["defects"],  # type: ignore[index]
        )

    def test_missing_files_are_structured_and_create_no_upstream_evidence(self) -> None:
        empty_db = self.root / "empty.sqlite3"
        missing_payload = self.root / "missing-certification.json"
        missing_signature = self.root / "missing-certification.sig"

        result = self.admit(
            payload_path=missing_payload,
            signature_path=missing_signature,
            db_path=empty_db,
        )

        self.assertEqual(result.returncode, 2)
        error = self.decode_stderr(result)
        self.assertEqual(error["error"], "VALIDATION_ERROR")
        self.assertEqual(error["message"], "payload_file could not be read")
        self.assertNotIn("Traceback", result.stderr)
        with sqlite3.connect(empty_db) as connection:
            for table in (
                "continuity_incidents",
                "continuity_trust_roots",
                "research_campaigns",
                "c2_recollections",
                "research_attempts",
                "research_observations",
                "c2_census_identities",
                "c2_certifications",
            ):
                count = connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                self.assertEqual(count, 0, table)


if __name__ == "__main__":
    unittest.main()
