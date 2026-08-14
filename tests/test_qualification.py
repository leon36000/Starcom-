from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from starcom.canonical import sha256_digest
from starcom.db import Database
from starcom.errors import ConflictError, NotFoundError
from starcom.ledger import EventLedger
from starcom.qualification import QualificationArtifactKind, QualificationLab


T0 = "2026-08-14T07:00:00.000000Z"
T1 = "2026-08-14T07:01:00.000000Z"
T2 = "2026-08-14T07:02:00.000000Z"


class QualificationLabTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.tempdir.name) / "qualification.sqlite3")
        self.db.initialize()
        self.ledger = EventLedger(self.db)
        self.lab = QualificationLab(self.db, self.ledger)

    def tearDown(self) -> None:
        self.db.close()
        self.tempdir.cleanup()

    def create_run(self):
        return self.lab.create_run(
            "qualification-run",
            name="Independent component qualification",
            actor="lab-owner",
            occurred_at=T0,
        )

    def record(
        self,
        artifact_id: str,
        kind: QualificationArtifactKind,
        material: dict[str, object],
        *,
        actor: str = "evaluator",
        occurred_at: str = T1,
    ):
        return self.lab.record_artifact(
            "qualification-run",
            artifact_id=artifact_id,
            kind=kind,
            material=material,
            actor=actor,
            occurred_at=occurred_at,
        )

    def test_empty_run_is_generic_verified_and_idempotent(self) -> None:
        first = self.create_run()
        replay = self.lab.create_run(
            "qualification-run",
            name="Independent component qualification",
            actor="lab-owner",
            occurred_at=T2,
        )

        self.assertEqual(first, replay)
        self.assertEqual(self.lab.get_run(first.qualification_run_id), first)
        verification = self.lab.verify(first.qualification_run_id)
        self.assertTrue(verification.ok, verification.defects)
        self.assertEqual(
            verification.artifact_counts,
            {kind.value: 0 for kind in QualificationArtifactKind},
        )
        event = self.db.connection.execute(
            "SELECT * FROM ledger_events WHERE event_id = ?",
            (first.ledger_event_id,),
        ).fetchone()
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event["stream_id"], "qualification:run:qualification-run")
        self.assertEqual(event["kind"], "QUALIFICATION_RUN_CREATED")

        with self.assertRaises(ConflictError):
            self.lab.create_run(
                "qualification-run",
                name="Different qualification",
                actor="lab-owner",
                occurred_at=T2,
            )

    def test_all_artifact_kinds_are_append_only_counted_and_verified(self) -> None:
        self.create_run()
        records = []
        for index, kind in enumerate(QualificationArtifactKind):
            material = {
                "component_id": f"component-{index}",
                "kind": kind.value,
                "score": index,
            }
            records.append(
                self.record(
                    f"artifact-{index}",
                    kind,
                    material,
                    occurred_at=T1,
                )
            )

        for record in records:
            self.assertEqual(self.lab.get_artifact(record.artifact_id), record)
            self.assertEqual(record.material_sha256, sha256_digest(dict(record.material)))
        verification = self.lab.verify("qualification-run")
        self.assertTrue(verification.ok, verification.defects)
        self.assertEqual(
            verification.artifact_counts,
            {kind.value: 1 for kind in QualificationArtifactKind},
        )

    def test_artifact_exact_replay_is_idempotent_and_conflict_is_rejected(self) -> None:
        self.create_run()
        material = {"component_id": "candidate-a", "version": "1.0.0"}
        first = self.record(
            "candidate-a",
            QualificationArtifactKind.CANDIDATE,
            material,
        )
        event_count = len(self.ledger.read_stream("qualification:run:qualification-run"))

        replay = self.record(
            "candidate-a",
            QualificationArtifactKind.CANDIDATE,
            material,
            occurred_at=T2,
        )

        self.assertEqual(first, replay)
        self.assertEqual(
            len(self.ledger.read_stream("qualification:run:qualification-run")),
            event_count,
        )
        with self.assertRaises(ConflictError):
            self.record(
                "candidate-a",
                QualificationArtifactKind.CANDIDATE,
                {"component_id": "candidate-a", "version": "2.0.0"},
            )
        with self.assertRaises(NotFoundError):
            self.lab.record_artifact(
                "missing-run",
                artifact_id="orphan",
                kind=QualificationArtifactKind.CANDIDATE,
                material={},
                actor="evaluator",
                occurred_at=T1,
            )

    def test_verifier_detects_material_tampering(self) -> None:
        self.create_run()
        record = self.record(
            "candidate-a",
            QualificationArtifactKind.CANDIDATE,
            {"component_id": "candidate-a", "version": "1.0.0"},
        )
        self.db.connection.execute("DROP TRIGGER qualification_artifacts_no_update")
        self.db.connection.execute(
            "UPDATE qualification_artifacts SET material_json = ? WHERE artifact_id = ?",
            ('{"component_id":"candidate-a","version":"9.9.9"}', record.artifact_id),
        )

        verification = self.lab.verify("qualification-run")

        self.assertFalse(verification.ok)
        self.assertIn(
            f"QUALIFICATION_ARTIFACT_MATERIAL_DIGEST_MISMATCH:{record.artifact_id}",
            verification.defects,
        )
        self.assertIn(
            f"QUALIFICATION_ARTIFACT_LEDGER_PAYLOAD_MISMATCH:{record.artifact_id}",
            verification.defects,
        )

    def test_verifier_detects_repointed_artifact_event_stream(self) -> None:
        self.create_run()
        record = self.record(
            "candidate-a",
            QualificationArtifactKind.CANDIDATE,
            {"component_id": "candidate-a"},
        )
        forged = self.ledger.append(
            "qualification:run:shadow",
            "QUALIFICATION_ARTIFACT_RECORDED",
            {
                "artifact_id": record.artifact_id,
                "qualification_run_id": record.qualification_run_id,
                "kind": record.kind.value,
                "material": dict(record.material),
                "material_sha256": record.material_sha256,
            },
            actor=record.recorded_by,
            occurred_at=record.recorded_at,
        )
        self.db.connection.execute("DROP TRIGGER qualification_artifacts_no_update")
        self.db.connection.execute(
            """
            UPDATE qualification_artifacts
            SET ledger_event_id = ?, ledger_hash = ?
            WHERE artifact_id = ?
            """,
            (forged.event_id, forged.record_hash, record.artifact_id),
        )

        verification = self.lab.verify("qualification-run")

        self.assertFalse(verification.ok)
        self.assertIn(
            f"QUALIFICATION_ARTIFACT_LEDGER_STREAM_MISMATCH:{record.artifact_id}",
            verification.defects,
        )

    def test_verifier_detects_repointed_run_event_actor(self) -> None:
        run = self.create_run()
        forged = self.ledger.append(
            "qualification:run:qualification-run",
            "QUALIFICATION_RUN_CREATED",
            {
                "qualification_run_id": run.qualification_run_id,
                "name": run.name,
            },
            actor="intruder",
            occurred_at=run.created_at,
        )
        self.db.connection.execute("DROP TRIGGER qualification_runs_no_update")
        self.db.connection.execute(
            """
            UPDATE qualification_runs
            SET ledger_event_id = ?, ledger_hash = ?
            WHERE qualification_run_id = ?
            """,
            (forged.event_id, forged.record_hash, run.qualification_run_id),
        )

        verification = self.lab.verify("qualification-run")

        self.assertFalse(verification.ok)
        self.assertIn("QUALIFICATION_RUN_LEDGER_ACTOR_MISMATCH", verification.defects)


if __name__ == "__main__":
    unittest.main()
