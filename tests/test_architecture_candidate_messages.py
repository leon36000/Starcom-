from __future__ import annotations

import unittest

import test_architecture_candidate as candidate_fixture

from starcom.adoption_execution import C3AdoptionExecutionStatus
from starcom.errors import StateTransitionError


class C4ArchitectureCandidateMessageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.helper = candidate_fixture.C4ArchitectureCandidateTests(
            methodName="test_prepare_candidate_is_deterministic_and_side_effect_free"
        )
        self.helper.setUp()

    def tearDown(self) -> None:
        self.helper.tearDown()

    def prepare(self, candidate_id: str, manifest: dict[str, object]) -> None:
        self.helper.candidates.prepare_create(
            candidate_id,
            input_set_id="input-set-c4",
            manifest=manifest,
        )

    def test_owner_mismatch_reports_missing_matching_authority_adr(self) -> None:
        manifest = self.helper.valid_manifest()
        manifest["ports"][0]["owner_authority"] = "OTHER_AUTHORITY"  # type: ignore[index]

        with self.assertRaisesRegex(
            StateTransitionError,
            "port owner lacks matching authority ADR",
        ):
            self.prepare("candidate-owner-message", manifest)

    def test_orphan_port_reports_missing_matching_authority_adr(self) -> None:
        manifest = self.helper.valid_manifest()
        manifest["authority_adrs"][0]["affected_port_ids"] = [  # type: ignore[index]
            "port-artifact",
            "port-monitor",
            "port-research",
        ]

        with self.assertRaisesRegex(
            StateTransitionError,
            "port owner lacks matching authority ADR",
        ):
            self.prepare("candidate-orphan-message", manifest)

    def test_failed_binding_reports_success_requirement(self) -> None:
        negative = next(
            member
            for member in self.helper.inputs.members
            if member["status"]
            == C3AdoptionExecutionStatus.FAILED_NO_EFFECT.value
        )
        manifest = self.helper.valid_manifest()
        binding = manifest["component_bindings"][0]  # type: ignore[index]
        binding["execution_id"] = negative["execution_id"]
        binding["candidate_artifact_id"] = negative["candidate_artifact_id"]
        binding["candidate_material_sha256"] = negative[
            "candidate_material_sha256"
        ]

        with self.assertRaisesRegex(
            StateTransitionError,
            "component binding requires a successful frozen execution",
        ):
            self.prepare("candidate-failed-binding-message", manifest)

    def test_missing_success_binding_reports_exact_coverage_requirement(self) -> None:
        manifest = self.helper.valid_manifest()
        manifest["component_bindings"] = []

        with self.assertRaisesRegex(
            StateTransitionError,
            "every successful execution requires exactly one component binding",
        ):
            self.prepare("candidate-missing-binding-message", manifest)

    def test_incomplete_benchmark_reports_stage_port_mismatch(self) -> None:
        manifest = self.helper.valid_manifest()
        manifest["vertical_benchmark"]["stage_test_ids"]["ACTION"] = [  # type: ignore[index]
            "test-not-owned-by-action-port"
        ]

        with self.assertRaisesRegex(
            StateTransitionError,
            "vertical benchmark stage tests are not exposed by mission ports",
        ):
            self.prepare("candidate-benchmark-message", manifest)


if __name__ == "__main__":
    unittest.main()
