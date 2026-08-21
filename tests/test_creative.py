from __future__ import annotations

from pathlib import Path
import inspect
import tempfile
import unittest
from unittest.mock import patch

from starcom.cli import Runtime
from starcom.creative import (
    CreativeJobService,
    CreativeJobStatus,
    CreativeJobType,
)
from starcom.errors import AuthorizationError, ConflictError, ValidationError
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule


T0 = "2026-08-20T12:00:00.000000Z"
T1 = "2026-08-20T12:00:01.000000Z"


class CreativeJobTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.runtime = Runtime.open(Path(self.tempdir.name) / "creative.sqlite3")
        self.service = CreativeJobService(
            self.runtime.database,
            self.runtime.ledger,
            self.runtime.trust,
            self.runtime.outbox,
        )
        self.runtime.trust.add_rule(
            PolicyRule(
                rule_id="creative-allow",
                effect=PolicyEffect.ALLOW,
                subject="operator-a",
                action="creative.job.request",
                resource="creative:job:*",
            ),
            actor="policy-admin",
            occurred_at=T0,
        )

    def tearDown(self) -> None:
        self.runtime.close()
        self.tempdir.cleanup()

    def preparation(self, job_id: str = "job-1", **overrides: object):
        values: dict[str, object] = {
            "job_id": job_id,
            "job_type": CreativeJobType.IMAGE,
            "owner": "logical-owner",
            "prompt": b"draw a deterministic tree",
            "model_id": "model-v1",
            "executor_id": "executor-local-v1",
            "executor_descriptor_digest": "b" * 64,
            "input_artifacts": [
                {
                    "artifact_id": "input-a",
                    "digest": "a" * 64,
                    "media_type": "image/png",
                }
            ],
            "output_media_type": "image/png",
            "safety_profile": {
                "profile_id": "strict-v1",
                "mode": "STRICT",
                "allow_sensitive": False,
                "max_output_bytes": 1048576,
            },
            "safety_policy_digest": "c" * 64,
            "seed_configuration": {
                "seed": 7,
                "options": {"temperature": 0.2},
            },
            "network_requirements": {
                "mode": "NONE",
                "egress_allowed": False,
            },
            "idempotency_key": f"creative-request:{job_id}",
        }
        values.update(overrides)
        return self.service.prepare(**values)

    def decision(self, preparation, *, subject: str = "operator-a", context=None):
        return self.runtime.trust.authorize(
            AuthorizationRequest(
                subject=subject,
                action=preparation.action,
                resource=preparation.resource,
                mission_id=preparation.mission_id,
                context=(
                    dict(preparation.authorization_context)
                    if context is None
                    else dict(context)
                ),
            ),
            now=T1,
        )


class CreativeJobContractTests(CreativeJobTestBase):
    def test_prepare_is_deterministic_and_side_effect_free(self) -> None:
        before_jobs = self.runtime.database.connection.execute(
            "SELECT COUNT(*) FROM creative_jobs"
        ).fetchone()[0]
        first = self.preparation()
        second = self.preparation()
        self.assertEqual(first, second)
        self.assertEqual(before_jobs, 0)
        self.assertEqual(
            self.runtime.database.connection.execute(
                "SELECT COUNT(*) FROM durable_effects"
            ).fetchone()[0],
            0,
        )

    def test_five_closed_job_types_admit_with_exact_outbox_effect(self) -> None:
        outputs = {
            CreativeJobType.IMAGE: "image/png",
            CreativeJobType.TEXT_TO_SPEECH: "audio/wav",
            CreativeJobType.SPEECH_TO_TEXT: "application/json",
            CreativeJobType.AUDIO: "audio/wav",
            CreativeJobType.VIDEO: "video/mp4",
        }
        for index, job_type in enumerate(CreativeJobType, start=1):
            preparation = self.preparation(
                job_id=f"job-type-{index}",
                job_type=job_type,
                output_media_type=outputs[job_type],
            )
            decision = self.decision(preparation)
            record = self.service.request(
                preparation,
                authorization_decision_id=decision.decision_id,
                actor="operator-a",
                occurred_at=f"2026-08-20T12:01:0{index}.000000Z",
            )
            self.assertEqual(record.status, CreativeJobStatus.REQUESTED_NOT_EXECUTED)
            self.assertEqual(record.prompt_bytes, b"draw a deterministic tree")
            effect = self.runtime.outbox.get(preparation.effect_id)
            self.assertEqual(effect.topic, "creative.job.request")
            self.assertEqual(effect.status.value, "PENDING")
            self.assertEqual(effect.payload["request_digest"], preparation.request_digest)
            self.assertTrue(self.service.verify(preparation.job_id).ok)

    def test_default_deny_and_wrong_context_never_create_a_job(self) -> None:
        preparation = self.preparation("job-denied")
        denied = self.decision(preparation, subject="untrusted-operator")
        self.assertFalse(denied.allowed)
        with self.assertRaises(AuthorizationError):
            self.service.request(
                preparation,
                authorization_decision_id=denied.decision_id,
                actor="untrusted-operator",
            )

        wrong_context = dict(preparation.authorization_context)
        wrong_context["prompt_digest"] = "0" * 64
        wrong = self.decision(preparation, context=wrong_context)
        with self.assertRaises(AuthorizationError):
            self.service.request(
                preparation,
                authorization_decision_id=wrong.decision_id,
                actor="operator-a",
            )
        self.assertEqual(
            self.runtime.database.connection.execute(
                "SELECT COUNT(*) FROM creative_jobs"
            ).fetchone()[0],
            0,
        )

    def test_exact_replay_is_idempotent_and_decision_is_single_use(self) -> None:
        preparation = self.preparation("job-replay")
        decision = self.decision(preparation)
        first = self.service.request(
            preparation,
            authorization_decision_id=decision.decision_id,
            actor="operator-a",
            occurred_at=T1,
        )
        replay = self.service.request(
            preparation,
            authorization_decision_id=decision.decision_id,
            actor="operator-a",
            occurred_at="2026-08-20T12:00:02.000000Z",
        )
        self.assertEqual(first, replay)

        second_preparation = self.preparation("job-replay-2")
        with self.assertRaises(ConflictError):
            self.service.request(
                second_preparation,
                authorization_decision_id=decision.decision_id,
                actor="operator-a",
            )

    def test_closed_inputs_prompt_and_media_constraints_fail_closed(self) -> None:
        with self.assertRaises(ValidationError):
            self.preparation(
                "job-invalid-input",
                input_artifacts=[
                    {
                        "artifact_id": "input-a",
                        "digest": "not-a-digest",
                        "media_type": "image/png",
                    }
                ],
            )
        with self.assertRaises(ValidationError):
            self.preparation(
                "job-invalid-prompt",
                prompt=b"\xff",
            )
        with self.assertRaises(ValidationError):
            self.preparation(
                "job-invalid-profile",
                safety_profile={
                    "profile_id": "strict-v1",
                    "mode": "STRICT",
                    "allow_sensitive": False,
                    "max_output_bytes": 100,
                    "unexpected": True,
                },
            )
        with self.assertRaises(ValidationError):
            self.preparation(
                "job-invalid-output",
                job_type=CreativeJobType.VIDEO,
                output_media_type="image/png",
            )
        with self.assertRaises(ValidationError):
            self.preparation("job-missing-inputs", input_artifacts=None)


class CreativeJobIntegrityTests(CreativeJobTestBase):
    def admitted(self, job_id: str = "job-integrity"):
        preparation = self.preparation(job_id)
        decision = self.decision(preparation)
        self.service.request(
            preparation,
            authorization_decision_id=decision.decision_id,
            actor="operator-a",
            occurred_at=T1,
        )
        return preparation

    def test_prompt_tampering_is_reported_by_independent_verifier(self) -> None:
        preparation = self.admitted()
        self.runtime.database.connection.execute("DROP TRIGGER creative_jobs_no_update")
        self.runtime.database.connection.execute(
            "UPDATE creative_jobs SET prompt_bytes = ? WHERE job_id = ?",
            (b"tampered prompt", preparation.job_id),
        )
        verification = self.service.verify(preparation.job_id)
        self.assertFalse(verification.ok)
        self.assertIn("PROMPT_DIGEST_MISMATCH", verification.defects)

    def test_transaction_rolls_back_job_transition_ledger_and_effect(self) -> None:
        preparation = self.preparation("job-rollback")
        decision = self.decision(preparation)
        with patch.object(
            self.service.outbox,
            "enqueue_in_transaction",
            side_effect=RuntimeError("forced outbox failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "forced outbox failure"):
                self.service.request(
                    preparation,
                    authorization_decision_id=decision.decision_id,
                    actor="operator-a",
                )
        self.assertEqual(
            self.runtime.database.connection.execute(
                "SELECT COUNT(*) FROM creative_jobs"
            ).fetchone()[0],
            0,
        )
        self.assertEqual(
            self.runtime.database.connection.execute(
                "SELECT COUNT(*) FROM creative_job_transitions"
            ).fetchone()[0],
            0,
        )
        self.assertEqual(
            self.runtime.database.connection.execute(
                "SELECT COUNT(*) FROM durable_effects"
            ).fetchone()[0],
            0,
        )
        admitted = self.service.request(
            preparation,
            authorization_decision_id=decision.decision_id,
            actor="operator-a",
        )
        self.assertEqual(admitted.status, CreativeJobStatus.REQUESTED_NOT_EXECUTED)

    def test_service_has_no_generation_or_execution_surface(self) -> None:
        forbidden = {
            "generate",
            "render",
            "synthesize",
            "transcribe",
            "execute",
            "process",
            "run",
        }
        self.assertTrue(forbidden.isdisjoint(dir(self.service)))
        source = inspect.getsource(CreativeJobService).lower()
        for token in ("urllib", "requests", "http", "socket", "subprocess", "gpu"):
            self.assertNotIn(token, source)


class CreativeJobRuntimeTests(unittest.TestCase):
    def test_runtime_exposes_one_shared_creative_job_service(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = Runtime.open(Path(directory) / "runtime.sqlite3")
            try:
                service = runtime.creative_jobs
                self.assertIsInstance(service, CreativeJobService)
                self.assertIs(service.database, runtime.database)
                self.assertIs(service.ledger, runtime.ledger)
                self.assertIs(service.trust, runtime.trust)
                self.assertIs(service.outbox, runtime.outbox)
            finally:
                runtime.close()


if __name__ == "__main__":
    unittest.main()
