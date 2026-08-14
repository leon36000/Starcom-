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
SNAPSHOT_DIGEST = hashlib.sha256(b"qualification-cli-snapshot").hexdigest()
CERTIFICATE_ID = "certificate-qualification-cli"
T0 = "2026-08-14T08:00:00.000000Z"
T1 = "2026-08-14T08:01:00.000000Z"
T2 = "2026-08-14T08:02:00.000000Z"
T3 = "2026-08-14T08:03:00.000000Z"
T4 = "2026-08-14T08:04:00.000000Z"
T5 = "2026-08-14T08:05:00.000000Z"
T6 = "2026-08-14T08:06:00.000000Z"
T7 = "2026-08-14T08:07:00.000000Z"
T8 = "2026-08-14T08:08:00.000000Z"
T9 = "2026-08-14T08:09:00.000000Z"
T10 = "2026-08-14T08:10:00.000000Z"
T11 = "2026-08-14T08:11:00.000000Z"
Q0 = "2026-08-14T08:20:00.000000Z"
Q1 = "2026-08-14T08:21:00.000000Z"
Q2 = "2026-08-14T08:22:00.000000Z"


class QualificationAndC3CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.class_tempdir = tempfile.TemporaryDirectory()
        cls.base_root = Path(cls.class_tempdir.name)
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.base_db_path = cls.base_root / "certified-c2.sqlite3"
        cls.reviewer_private = cls.base_root / "reviewer-private.pem"
        cls.reviewer_public = cls.base_root / "reviewer-public.pem"
        cls.certifier_private = cls.base_root / "certifier-private.pem"
        cls.certifier_public = cls.base_root / "certifier-public.pem"
        cls._generate_keypair(cls.reviewer_private, cls.reviewer_public)
        cls._generate_keypair(cls.certifier_private, cls.certifier_public)
        cls._build_certified_database()

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
    def _sign_bytes(cls, private_key: Path, payload: bytes, name: str) -> bytes:
        payload_path = cls.base_root / f"{name}.json"
        signature_path = cls.base_root / f"{name}.sig"
        payload_path.write_bytes(payload)
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
        return signature_path.read_bytes()

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
            raise AssertionError("fixture authorization unexpectedly denied")
        return decision.decision_id

    @staticmethod
    def _review_payload() -> bytes:
        value = {
            "review_id": "review-qualification-cli",
            "reviewer_identity": "independent-qualification-cli-reviewer",
            "review_environment": "isolated-qualification-cli-fixture",
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
    def _build_certified_database(cls) -> None:
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
                name="Task 5 certified census for qualification CLI",
                actor="owner",
                occurred_at=T0,
            )
            reviewer_decision = cls._allow(
                trust,
                action="continuity.trust-root.accept",
                resource="continuity:trust-root:reviewer-qualification-cli",
                rule_id="allow-reviewer-qualification-cli",
                now=T1,
            )
            continuity.accept_trust_root(
                "reviewer-qualification-cli",
                cls.reviewer_public.read_bytes(),
                decision_id=reviewer_decision,
                actor="owner",
                occurred_at=T1,
            )
            review_payload = cls._review_payload()
            review = continuity.admit_review(
                "task5",
                "reviewer-qualification-cli",
                review_payload,
                cls._sign_bytes(
                    cls.reviewer_private,
                    review_payload,
                    "qualification-cli-review",
                ),
                actor="owner",
                occurred_at=T2,
            )
            recovery_decision = cls._allow(
                trust,
                action="continuity.recovery.publish",
                resource="continuity:incident:task5",
                rule_id="allow-recovery-qualification-cli",
                now=T3,
            )
            continuity.publish_recovery(
                "task5",
                review.review_id,
                publication_id="publication-qualification-cli",
                idempotency_key="publish-qualification-cli",
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
                resource="continuity:trust-root:certifier-qualification-cli",
                rule_id="allow-certifier-qualification-cli",
                now=T5,
            )
            continuity.accept_trust_root(
                "certifier-qualification-cli",
                cls.certifier_public.read_bytes(),
                decision_id=certifier_decision,
                actor="owner",
                occurred_at=T5,
            )
            research.begin_attempt(
                "c2-campaign",
                attempt_id="attempt-qualification-cli",
                wave=1,
                request_key="request-qualification-cli",
                source_id="github",
                request={"url": "https://example.invalid/qualification-cli"},
                actor="collector",
                occurred_at=T6,
            )
            research.record_receipt(
                "attempt-qualification-cli",
                receipt_id="receipt-qualification-cli",
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
                attempt_id="attempt-qualification-cli",
                cursor_id="cursor-qualification-cli",
                actor="collector",
                occurred_at=T7,
            )
            for index in range(800):
                identity_key = f"identity-{index:04d}"
                observation_id = f"observation-{index:04d}"
                content_digest = hashlib.sha256(identity_key.encode("utf-8")).hexdigest()
                research.record_observation(
                    "attempt-qualification-cli",
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
                    attempt_id="attempt-qualification-cli",
                    observation_id=observation_id,
                    actor="collector",
                    occurred_at=T8,
                )

            snapshot = certification.snapshot("c2-run")
            certificate_value = {
                "certificate_id": CERTIFICATE_ID,
                "recollection_id": snapshot.recollection_id,
                "incident_id": snapshot.incident_id,
                "campaign_id": snapshot.campaign_id,
                "identity_count": snapshot.identity_count,
                "required_target": snapshot.required_target,
                "identity_set_digest": snapshot.identity_set_digest,
                "certifier_identity": "independent-qualification-cli-certifier",
                "certifier_environment": "isolated-qualification-cli-certifier",
                "certified_at_utc": T10,
                "independence_basis": "separate generated certifier key and identity",
                "independent_identity_status": "SATISFIED",
                "census_verification_result": "PASS",
                "verdict": "C2_CENSUS_CERTIFIED",
                "gate_effect": "NO_CANONICAL_PROMOTION",
            }
            certificate_payload = json.dumps(
                certificate_value,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            certification.admit_certification(
                "c2-run",
                "certifier-qualification-cli",
                certificate_payload,
                cls._sign_bytes(
                    cls.certifier_private,
                    certificate_payload,
                    "qualification-cli-certificate",
                ),
                actor="admission-agent",
                occurred_at=T11,
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

    def create_run(self, *, db_path: Path | None = None, run_id: str = "qualification-run"):
        return self.run_cli(
            "qualification",
            "create-run",
            "--qualification-run-id",
            run_id,
            "--name",
            "Explicit component qualification",
            "--actor",
            "lab-owner",
            "--occurred-at",
            Q0,
            db_path=db_path,
        )

    def record_candidate(
        self,
        *,
        db_path: Path | None = None,
        run_id: str = "qualification-run",
        artifact_id: str = "candidate-a",
    ):
        return self.run_cli(
            "qualification",
            "record-artifact",
            "--qualification-run-id",
            run_id,
            "--artifact-id",
            artifact_id,
            "--kind",
            "CANDIDATE",
            "--material-json",
            '{"component_id":"candidate-a","version":"1.0.0"}',
            "--actor",
            "evaluator",
            "--occurred-at",
            Q2,
            db_path=db_path,
        )

    def start_c3(self, *, db_path: Path | None = None, certificate_id: str = CERTIFICATE_ID):
        return self.run_cli(
            "c3",
            "start",
            "--c3-run-id",
            "c3-run",
            "--qualification-run-id",
            "qualification-run",
            "--certificate-id",
            certificate_id,
            "--actor",
            "c3-owner",
            "--occurred-at",
            Q1,
            db_path=db_path,
        )

    def test_generic_qualification_commands_are_explicit_and_machine_readable(self) -> None:
        fresh_db = self.root / "generic.sqlite3"
        created = self.success(self.create_run(db_path=fresh_db))["result"]  # type: ignore[index]
        self.assertEqual(created["qualification_run_id"], "qualification-run")  # type: ignore[index]

        loaded = self.success(
            self.run_cli(
                "qualification",
                "get-run",
                "--qualification-run-id",
                "qualification-run",
                db_path=fresh_db,
            )
        )["result"]  # type: ignore[index]
        self.assertEqual(loaded, created)

        candidate = self.success(self.record_candidate(db_path=fresh_db))["result"]  # type: ignore[index]
        self.assertEqual(candidate["kind"], "CANDIDATE")  # type: ignore[index]
        self.assertEqual(candidate["material"]["component_id"], "candidate-a")  # type: ignore[index]

        artifact = self.success(
            self.run_cli(
                "qualification",
                "get-artifact",
                "--artifact-id",
                "candidate-a",
                db_path=fresh_db,
            )
        )["result"]  # type: ignore[index]
        self.assertEqual(artifact, candidate)

        verified = self.success(
            self.run_cli(
                "qualification",
                "verify",
                "--qualification-run-id",
                "qualification-run",
                db_path=fresh_db,
            )
        )["result"]  # type: ignore[index]
        self.assertTrue(verified["ok"])  # type: ignore[index]
        self.assertEqual(
            verified["artifact_counts"],  # type: ignore[index]
            {"ADOPTION": 0, "CANDIDATE": 1, "DECISION": 0, "EVALUATION": 0},
        )
        with sqlite3.connect(fresh_db) as connection:
            c3_count = connection.execute(
                "SELECT COUNT(*) FROM c3_qualification_bindings"
            ).fetchone()[0]
            self.assertEqual(c3_count, 0)

    def test_explicit_certificate_can_start_c3_then_accept_post_bind_candidate(self) -> None:
        self.success(self.create_run())
        binding = self.success(self.start_c3())["result"]  # type: ignore[index]
        self.assertEqual(binding["certificate_id"], CERTIFICATE_ID)  # type: ignore[index]
        self.assertEqual(binding["identity_count"], 800)  # type: ignore[index]

        loaded = self.success(
            self.run_cli("c3", "get", "--c3-run-id", "c3-run")
        )["result"]  # type: ignore[index]
        self.assertEqual(loaded, binding)
        first_verify = self.success(
            self.run_cli("c3", "verify", "--c3-run-id", "c3-run")
        )["result"]  # type: ignore[index]
        self.assertTrue(first_verify["ok"])  # type: ignore[index]

        self.success(self.record_candidate())
        qualification_verify = self.success(
            self.run_cli(
                "qualification",
                "verify",
                "--qualification-run-id",
                "qualification-run",
            )
        )["result"]  # type: ignore[index]
        self.assertTrue(qualification_verify["ok"])  # type: ignore[index]
        self.assertEqual(qualification_verify["artifact_counts"]["CANDIDATE"], 1)  # type: ignore[index]
        self.assertEqual(qualification_verify["artifact_counts"]["ADOPTION"], 0)  # type: ignore[index]
        final_verify = self.success(
            self.run_cli("c3", "verify", "--c3-run-id", "c3-run")
        )["result"]  # type: ignore[index]
        self.assertTrue(final_verify["ok"])  # type: ignore[index]

    def test_nonempty_qualification_run_cannot_be_bound_to_c3(self) -> None:
        self.success(self.create_run())
        self.success(self.record_candidate())

        rejected = self.start_c3()

        self.assertEqual(rejected.returncode, 2)
        error = self.decode_stderr(rejected)
        self.assertEqual(error["error"], "INVALID_STATE_TRANSITION")
        self.assertEqual(error["message"], "qualification run must be empty at C3 binding")
        missing = self.run_cli("c3", "get", "--c3-run-id", "c3-run")
        self.assertEqual(missing.returncode, 2)
        self.assertEqual(self.decode_stderr(missing)["error"], "NOT_FOUND")

    def test_missing_certificate_creates_no_upstream_evidence_implicitly(self) -> None:
        fresh_db = self.root / "missing.sqlite3"

        rejected = self.start_c3(
            db_path=fresh_db,
            certificate_id="missing-certificate",
        )

        self.assertEqual(rejected.returncode, 2)
        self.assertEqual(self.decode_stderr(rejected)["error"], "NOT_FOUND")
        with sqlite3.connect(fresh_db) as connection:
            for table in (
                "continuity_incidents",
                "research_campaigns",
                "c2_recollections",
                "c2_census_identities",
                "c2_certifications",
                "qualification_runs",
                "qualification_artifacts",
                "c3_qualification_bindings",
            ):
                count = connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                self.assertEqual(count, 0, table)


if __name__ == "__main__":
    unittest.main()
