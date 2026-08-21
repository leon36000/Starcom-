from __future__ import annotations

from importlib import import_module
from pathlib import Path
import tempfile
import unittest
from unittest import TestCase
from unittest.mock import patch

from starcom.db import Database
from starcom.errors import ValidationError
from starcom.program import ProgramTruth, ProgramVerification, StarcomProgram


EXPECTED_AUTHORITIES = {
    "core.proof": ("starcom.proof", "ProofEngine"),
    "core.missions": ("starcom.mission", "MissionKernel"),
    "core.research": ("starcom.research", "ResearchCampaign"),
    "c1.continuity": ("starcom.continuity", "ContinuityService"),
    "c2.recollection": ("starcom.recollection", "C2RecollectionService"),
    "c2.census": ("starcom.census", "C2CensusService"),
    "c2.certification": ("starcom.certification", "C2CertificationService"),
    "c3.qualification": ("starcom.qualification", "QualificationLab"),
    "c3.gate": ("starcom.qualification_gate", "C3QualificationGate"),
    "c3.decision": ("starcom.qualification_decision", "C3DecisionService"),
    "c3.adoption": ("starcom.adoption", "C3AdoptionService"),
    "c3.execution": ("starcom.adoption_execution", "C3AdoptionExecutionService"),
    "c3.executor_registry": ("starcom.executor_registry", "C3ExecutorRegistry"),
    "c4.input": ("starcom.architecture_input", "C4ArchitectureInputService"),
    "c4.candidate": ("starcom.architecture_candidate", "C4ArchitectureCandidateService"),
    "c4.review": ("starcom.architecture_review", "C4ArchitectureReviewService"),
    "c4.publication": (
        "starcom.architecture_publication",
        "C4ArchitecturePublicationService",
    ),
    "c4.architecture": ("starcom.architecture", "C4ArchitectureService"),
    "c5.execution_plan": ("starcom.execution_plan", "C5ExecutionPlanService"),
    "c6.red_team": ("starcom.red_team", "C6RedTeamService"),
    "c7.final_pack": ("starcom.final_pack", "C7FinalPackService"),
    "12a.research_marathon": (
        "starcom.research_marathon",
        "ResearchMarathonService",
    ),
    "16.creative_jobs": ("starcom.creative", "CreativeJobService"),
    "17.cockpit": ("starcom.cockpit", "CockpitService"),
    "18.deployment": ("starcom.deployment", "DeploymentFabricService"),
    "19.release_candidate": (
        "starcom.release_candidate",
        "ReleaseCandidateService",
    ),
    "19.external_evidence": (
        "starcom.external_evidence",
        "ExternalEvidenceService",
    ),
}


def table_names(program: StarcomProgram) -> tuple[str, ...]:
    rows = program.database.connection.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    return tuple(str(row[0]) for row in rows)


class StarcomProgramTests(TestCase):
    def setUp(self) -> None:
        self.tempdir = self.enterContext(tempfile.TemporaryDirectory())
        self.db_path = Path(self.tempdir) / "program.sqlite3"

    def test_opens_complete_graph_with_stable_catalog(self) -> None:
        program = StarcomProgram.open(self.db_path)
        self.addCleanup(program.close)

        self.assertEqual(program.database.path, str(self.db_path))
        names = tuple(entry.name for entry in program.catalog)
        self.assertEqual(names, tuple(sorted(names)))
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(set(names), set(EXPECTED_AUTHORITIES))
        for entry in program.catalog:
            module = import_module(entry.module)
            implementation = getattr(module, entry.class_name)
            authority = program.authority(entry.name)
            self.assertIsInstance(authority, implementation)
            self.assertEqual(entry.attribute, next(
                attribute
                for attribute, value in vars(program).items()
                if value is authority
            ))
            self.assertIsInstance(entry.dependencies, tuple)

        self.assertIs(program.authority("c7.final_pack"), program.final_pack)
        self.assertIs(program.authority("final_pack"), program.final_pack)
        self.assertTrue(program.verify().ok, program.verify().defects)

    def test_all_declared_shared_dependencies_use_one_instance(self) -> None:
        program = StarcomProgram.open(self.db_path)
        self.addCleanup(program.close)
        shared = {
            "database": program.database,
            "ledger": program.ledger,
            "trust": program.trust,
            "continuity": program.continuity,
            "outbox": program.outbox,
        }

        for entry in program.catalog:
            authority = program.authority(entry.name)
            for field, expected in shared.items():
                if hasattr(authority, field):
                    self.assertIs(getattr(authority, field), expected, (entry.name, field))

    def test_unknown_mandatory_dependency_fails_closed(self) -> None:
        with self.assertRaises(ValidationError) as raised:
            StarcomProgram._resolve_dependencies(
                "c4.input",
                ("database", "missing.required"),
                {"database": object()},
            )

        self.assertEqual(raised.exception.code, "VALIDATION_ERROR")
        self.assertEqual(raised.exception.details["authority"], "c4.input")
        self.assertEqual(
            raised.exception.details["missing_dependencies"], ["missing.required"]
        )

    def test_reopening_same_database_is_idempotent(self) -> None:
        first = StarcomProgram.open(self.db_path)
        first_catalog = first.catalog
        first_tables = table_names(first)
        first_ledger_count = first.database.connection.execute(
            "SELECT COUNT(*) FROM ledger_events"
        ).fetchone()[0]
        first.close()
        first.close()

        second = StarcomProgram.open(self.db_path)
        self.addCleanup(second.close)
        second_ledger_count = second.database.connection.execute(
            "SELECT COUNT(*) FROM ledger_events"
        ).fetchone()[0]
        self.assertEqual(second.catalog, first_catalog)
        self.assertEqual(table_names(second), first_tables)
        self.assertEqual(second_ledger_count, first_ledger_count)
        self.assertTrue(second.verify().ok, second.verify().defects)

    def test_runtime_compatibility_aliases_remain_available(self) -> None:
        from starcom.cli import Runtime

        runtime = Runtime.open(self.db_path)
        self.addCleanup(runtime.close)
        self.assertIsInstance(runtime, StarcomProgram)
        self.assertIs(runtime.architecture_baseline, runtime.architecture)
        self.assertIs(runtime.c5_execution_plan, runtime.execution_plan)
        self.assertIs(runtime.c6_red_team, runtime.red_team)
        self.assertIs(runtime.c7_final_pack, runtime.final_pack)
        self.assertIs(runtime.creative, runtime.creative_jobs)
        self.assertIs(runtime.rc_assessment, runtime.release_candidate)

    def test_clean_verifier_exposes_all_gate_results(self) -> None:
        program = StarcomProgram.open(self.db_path)
        self.addCleanup(program.close)

        verification = program.verify()
        self.assertIsInstance(verification, ProgramVerification)
        self.assertEqual(verification.truth, ProgramTruth())
        self.assertTrue(verification.foreign_keys_ok)
        self.assertTrue(verification.schema_ok)
        self.assertTrue(verification.catalog_ok)
        self.assertTrue(verification.dependencies_ok)
        self.assertTrue(verification.ledger_ok)
        self.assertTrue(verification.surfaces_ok)
        self.assertTrue(verification.canonical_truth_ok)
        self.assertEqual(verification.defects, ())
        self.assertTrue(
            {"run", "execute", "deploy", "release", "publish", "promote"}.isdisjoint(
                dir(program)
            )
        )

    def test_verifier_reports_missing_schema(self) -> None:
        program = StarcomProgram.open(self.db_path)
        self.addCleanup(program.close)
        program.database.connection.execute("DROP TABLE cockpit_snapshots")

        verification = program.verify()
        self.assertFalse(verification.ok)
        self.assertIn("SCHEMA_TABLE_MISSING:cockpit_snapshots", verification.defects)

    def test_verifier_reports_unexpected_schema(self) -> None:
        program = StarcomProgram.open(self.db_path)
        self.addCleanup(program.close)
        program.database.connection.execute(
            "CREATE TABLE unexpected_program_table (value TEXT NOT NULL)"
        )

        verification = program.verify()
        self.assertFalse(verification.ok)
        self.assertIn(
            "SCHEMA_TABLE_UNEXPECTED:unexpected_program_table",
            verification.defects,
        )

    def test_verifier_reports_shared_instance_mismatch(self) -> None:
        program = StarcomProgram.open(self.db_path)
        self.addCleanup(program.close)
        replacement = Database(":memory:")
        self.addCleanup(replacement.close)
        program.c3.database = replacement

        verification = program.verify()
        self.assertFalse(verification.ok)
        self.assertIn(
            "SHARED_INSTANCE_MISMATCH:c3.gate:database",
            verification.defects,
        )

    def test_composition_does_not_use_network_or_subprocess(self) -> None:
        with (
            patch("socket.socket") as socket,
            patch("subprocess.run") as run,
            patch("subprocess.Popen") as popen,
        ):
            program = StarcomProgram.open(":memory:")
            program.close()

        socket.assert_not_called()
        run.assert_not_called()
        popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
