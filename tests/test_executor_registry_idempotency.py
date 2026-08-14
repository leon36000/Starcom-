from __future__ import annotations

import unittest

import test_executor_registry as registry_fixture

from starcom.errors import ConflictError


class C3ExecutorRegistryIdempotencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.helper = registry_fixture.C3ExecutorRegistryTests(
            methodName="test_exact_signed_qualification_does_not_enable"
        )
        self.helper.setUp()
        self.registry = self.helper.registry

    def tearDown(self) -> None:
        self.helper.tearDown()

    def test_exact_signed_qualification_replay_is_idempotent(self) -> None:
        self.helper.register()
        self.helper.accept_root()
        payload = self.helper.qualification_payload()
        signature = self.helper.sign(payload)
        preparation = self.registry.prepare_qualification(
            "fake-executor",
            "qualifier-key",
            payload,
            signature,
        )
        decision = self.helper.authorize(
            preparation,
            subject="qualification-admitter",
            rule_id="allow-qualification",
            now=registry_fixture.R3,
        )
        first = self.registry.qualify(
            "fake-executor",
            "qualifier-key",
            payload,
            signature,
            authorization_decision_id=decision.decision_id,
            actor="qualification-admitter",
            occurred_at=registry_fixture.R3,
        )
        replay = self.registry.qualify(
            "fake-executor",
            "qualifier-key",
            payload,
            signature,
            authorization_decision_id=decision.decision_id,
            actor="qualification-admitter",
            occurred_at=registry_fixture.R6,
        )

        self.assertEqual(first, replay)
        changed_payload = self.helper.qualification_payload(
            qualification_id="qualification-changed"
        )
        changed_signature = self.helper.sign(changed_payload)
        with self.assertRaises(ConflictError):
            self.registry.qualify(
                "fake-executor",
                "qualifier-key",
                changed_payload,
                changed_signature,
                authorization_decision_id=decision.decision_id,
                actor="qualification-admitter",
                occurred_at=registry_fixture.R6,
            )

    def test_exact_enable_replay_is_idempotent_and_new_decision_conflicts(self) -> None:
        self.helper.register()
        self.helper.accept_root()
        self.helper.qualify()
        preparation = self.registry.prepare_enable("fake-executor")
        decision = self.helper.authorize(
            preparation,
            subject="executor-enabler",
            rule_id="allow-enable",
            now=registry_fixture.R4,
        )
        first = self.registry.enable(
            "fake-executor",
            authorization_decision_id=decision.decision_id,
            actor="executor-enabler",
            occurred_at=registry_fixture.R4,
        )
        replay = self.registry.enable(
            "fake-executor",
            authorization_decision_id=decision.decision_id,
            actor="executor-enabler",
            occurred_at=registry_fixture.R6,
        )
        self.assertEqual(first, replay)

        reused_preparation = preparation
        second_decision = self.helper.authorize(
            reused_preparation,
            subject="executor-enabler",
            rule_id="allow-enable-second",
            now=registry_fixture.R5,
        )
        with self.assertRaises(ConflictError):
            self.registry.enable(
                "fake-executor",
                authorization_decision_id=second_decision.decision_id,
                actor="executor-enabler",
                occurred_at=registry_fixture.R6,
            )


if __name__ == "__main__":
    unittest.main()
