from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from starcom.continuity import ContinuityService
from starcom.db import Database
from starcom.errors import (
    AuthorizationError,
    ConflictError,
    IntegrityError,
    StateTransitionError,
)
from starcom.executor_registry import (
    C3ExecutorNetworkMode,
    C3ExecutorRegistry,
    C3ExecutorState,
)
from starcom.ledger import EventLedger
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule, TrustPlane


R0 = "2026-08-14T15:00:00.000000Z"
R1 = "2026-08-14T15:01:00.000000Z"
R2 = "2026-08-14T15:02:00.000000Z"
R3 = "2026-08-14T15:03:00.000000Z"
R4 = "2026-08-14T15:04:00.000000Z"
R5 = "2026-08-14T15:05:00.000000Z"
R6 = "2026-08-14T15:06:00.000000Z"
IMPLEMENTATION_DIGEST = "1" * 64
ARTIFACT_DIGEST = "2" * 64
REPORT_DIGEST = "3" * 64
TEST_SUITE_DIGEST = "4" * 64


class C3ExecutorRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.database = Database(self.root / "registry.sqlite3")
        self.database.initialize()
        self.ledger = EventLedger(self.database)
        self.trust = TrustPlane(self.database, self.ledger)
        self.continuity = ContinuityService(
            self.database,
            self.ledger,
            self.trust,
        )
        self.registry = C3ExecutorRegistry(
            self.database,
            self.ledger,
            self.trust,
            self.continuity,
        )
        self.private_key = self.root / "qualifier-private.pem"
        self.public_key = self.root / "qualifier-public.pem"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                str(self.private_key),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(self.private_key),
                "-pubout",
                "-out",
                str(self.public_key),
            ],
            check=True,
            capture_output=True,
        )

    def tearDown(self) -> None:
        self.database.close()
        self.tempdir.cleanup()

    @staticmethod
    def descriptor() -> dict[str, object]:
        return {
            "executor_id": "fake-executor",
            "implementation_name": "Deterministic fake executor",
            "implementation_version": "1.0.0",
            "implementation_digest": IMPLEMENTATION_DIGEST,
            "artifact_digest": ARTIFACT_DIGEST,
            "entrypoint": "tests.fake_executor:DeterministicExecutor",
            "supported_sandbox_profiles": ["starcom-c3-default-deny-v1"],
            "network_mode": "DENY",
            "capabilities": ["apply", "rollback"],
        }

    def qualification_payload(
        self,
        *,
        reviewer: str = "independent-reviewer",
        qualification_id: str = "qualification-fake-executor",
    ) -> bytes:
        preparation = self.registry.prepare_registration(self.descriptor())
        value = {
            "qualification_id": qualification_id,
            "executor_id": "fake-executor",
            "descriptor_digest": preparation.context["descriptor_digest"],
            "report_digest": REPORT_DIGEST,
            "test_suite_digest": TEST_SUITE_DIGEST,
            "reviewer_identity": reviewer,
            "reviewer_environment": "isolated-qualifier-vm",
            "independence_basis": "separate process, key and workspace",
            "sandbox_profiles_tested": ["starcom-c3-default-deny-v1"],
            "network_mode_tested": "DENY",
            "verdict": "QUALIFIED",
            "qualified_at": R3,
            "gate_effect": "QUALIFIED_DISABLED_NO_ENABLEMENT",
        }
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )

    def sign(self, payload: bytes) -> bytes:
        payload_path = self.root / "qualification.json"
        signature_path = self.root / "qualification.sig"
        payload_path.write_bytes(payload)
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(self.private_key),
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

    def authorize(
        self,
        preparation,
        *,
        subject: str,
        rule_id: str,
        now: str,
        context: dict[str, object] | None = None,
    ):
        self.trust.add_rule(
            PolicyRule(
                rule_id,
                PolicyEffect.ALLOW,
                subject,
                preparation.action,
                preparation.resource,
            ),
            actor="owner",
            occurred_at=R0,
        )
        return self.trust.authorize(
            AuthorizationRequest(
                subject=subject,
                action=preparation.action,
                resource=preparation.resource,
                mission_id=preparation.mission_id,
                context=context or preparation.context,
            ),
            now=now,
        )

    def register(self) -> None:
        preparation = self.registry.prepare_registration(self.descriptor())
        decision = self.authorize(
            preparation,
            subject="registry-operator",
            rule_id="allow-register",
            now=R1,
        )
        self.assertTrue(decision.allowed)
        descriptor = self.registry.register(
            self.descriptor(),
            authorization_decision_id=decision.decision_id,
            actor="registry-operator",
            occurred_at=R1,
        )
        self.assertEqual(descriptor.executor_id, "fake-executor")

    def accept_root(self) -> None:
        public_key = self.public_key.read_bytes()
        preparation = self.registry.prepare_qualifier_root(
            "qualifier-key",
            public_key,
        )
        decision = self.authorize(
            preparation,
            subject="root-owner",
            rule_id="allow-root",
            now=R2,
        )
        self.assertTrue(decision.allowed)
        self.registry.accept_qualifier_root(
            "qualifier-key",
            public_key,
            authorization_decision_id=decision.decision_id,
            actor="root-owner",
            occurred_at=R2,
        )

    def qualify(self, *, reviewer: str = "independent-reviewer") -> None:
        payload = self.qualification_payload(reviewer=reviewer)
        signature = self.sign(payload)
        preparation = self.registry.prepare_qualification(
            "fake-executor",
            "qualifier-key",
            payload,
            signature,
        )
        decision = self.authorize(
            preparation,
            subject="qualification-admitter",
            rule_id="allow-qualification",
            now=R3,
        )
        self.assertTrue(decision.allowed)
        self.registry.qualify(
            "fake-executor",
            "qualifier-key",
            payload,
            signature,
            authorization_decision_id=decision.decision_id,
            actor="qualification-admitter",
            occurred_at=R3,
        )

    def enable(self) -> None:
        preparation = self.registry.prepare_enable("fake-executor")
        decision = self.authorize(
            preparation,
            subject="executor-enabler",
            rule_id="allow-enable",
            now=R4,
        )
        self.assertTrue(decision.allowed)
        self.registry.enable(
            "fake-executor",
            authorization_decision_id=decision.decision_id,
            actor="executor-enabler",
            occurred_at=R4,
        )

    def test_registration_is_default_deny_and_remains_disabled(self) -> None:
        preparation = self.registry.prepare_registration(self.descriptor())
        denied = self.trust.authorize(
            AuthorizationRequest(
                subject="registry-operator",
                action=preparation.action,
                resource=preparation.resource,
                mission_id=preparation.mission_id,
                context=preparation.context,
            ),
            now=R1,
        )
        self.assertFalse(denied.allowed)
        with self.assertRaises(AuthorizationError):
            self.registry.register(
                self.descriptor(),
                authorization_decision_id=denied.decision_id,
                actor="registry-operator",
                occurred_at=R1,
            )

        self.register()

        self.assertEqual(
            self.registry.get_current("fake-executor").state,
            C3ExecutorState.REGISTERED_DISABLED,
        )
        with self.assertRaises(StateTransitionError):
            self.registry.attest(
                "fake-executor",
                implementation_version="1.0.0",
                implementation_digest=IMPLEMENTATION_DIGEST,
                sandbox_profile="starcom-c3-default-deny-v1",
                requires_network=False,
            )

    def test_registration_replay_is_idempotent_and_material_conflict_fails(self) -> None:
        preparation = self.registry.prepare_registration(self.descriptor())
        decision = self.authorize(
            preparation,
            subject="registry-operator",
            rule_id="allow-register",
            now=R1,
        )
        first = self.registry.register(
            self.descriptor(),
            authorization_decision_id=decision.decision_id,
            actor="registry-operator",
            occurred_at=R1,
        )
        replay = self.registry.register(
            self.descriptor(),
            authorization_decision_id=decision.decision_id,
            actor="registry-operator",
            occurred_at=R6,
        )
        self.assertEqual(first, replay)
        changed = dict(self.descriptor())
        changed["implementation_version"] = "2.0.0"
        with self.assertRaises(ConflictError):
            self.registry.register(
                changed,
                authorization_decision_id=decision.decision_id,
                actor="registry-operator",
                occurred_at=R6,
            )

    def test_qualifier_root_is_separately_default_denied_and_idempotent(self) -> None:
        public_key = self.public_key.read_bytes()
        preparation = self.registry.prepare_qualifier_root(
            "qualifier-key",
            public_key,
        )
        denied = self.trust.authorize(
            AuthorizationRequest(
                subject="root-owner",
                action=preparation.action,
                resource=preparation.resource,
                mission_id=preparation.mission_id,
                context=preparation.context,
            ),
            now=R2,
        )
        self.assertFalse(denied.allowed)
        with self.assertRaises(AuthorizationError):
            self.registry.accept_qualifier_root(
                "qualifier-key",
                public_key,
                authorization_decision_id=denied.decision_id,
                actor="root-owner",
                occurred_at=R2,
            )

        decision = self.authorize(
            preparation,
            subject="root-owner",
            rule_id="allow-root",
            now=R2,
        )
        first = self.registry.accept_qualifier_root(
            "qualifier-key",
            public_key,
            authorization_decision_id=decision.decision_id,
            actor="root-owner",
            occurred_at=R2,
        )
        replay = self.registry.accept_qualifier_root(
            "qualifier-key",
            public_key,
            authorization_decision_id=decision.decision_id,
            actor="root-owner",
            occurred_at=R6,
        )
        self.assertEqual(first, replay)
        self.assertEqual(
            self.registry.get_qualifier_root("qualifier-key"),
            first,
        )

    def test_exact_signed_qualification_does_not_enable(self) -> None:
        self.register()
        self.accept_root()

        self.qualify()

        qualification = self.registry.get_qualification("fake-executor")
        self.assertEqual(
            qualification.qualification_id,
            "qualification-fake-executor",
        )
        self.assertEqual(
            self.registry.get_current("fake-executor").state,
            C3ExecutorState.QUALIFIED_DISABLED,
        )
        verification = self.registry.verify("fake-executor")
        self.assertTrue(verification.ok, verification.defects)
        with self.assertRaises(StateTransitionError):
            self.registry.attest(
                "fake-executor",
                implementation_version="1.0.0",
                implementation_digest=IMPLEMENTATION_DIGEST,
                sandbox_profile="starcom-c3-default-deny-v1",
                requires_network=False,
            )

    def test_modified_payload_with_original_signature_is_rejected(self) -> None:
        self.register()
        self.accept_root()
        payload = self.qualification_payload()
        signature = self.sign(payload)

        with self.assertRaises(IntegrityError):
            self.registry.prepare_qualification(
                "fake-executor",
                "qualifier-key",
                payload + b" ",
                signature,
            )

    def test_reviewer_must_be_independent_from_registrant(self) -> None:
        self.register()
        self.accept_root()
        payload = self.qualification_payload(reviewer="registry-operator")
        signature = self.sign(payload)

        with self.assertRaises(StateTransitionError):
            self.registry.prepare_qualification(
                "fake-executor",
                "qualifier-key",
                payload,
                signature,
            )

    def test_enable_requires_separate_decision_and_attests_exact_runtime(self) -> None:
        self.register()
        self.accept_root()
        self.qualify()

        self.enable()

        current = self.registry.get_current("fake-executor")
        self.assertEqual(current.state, C3ExecutorState.ENABLED)
        attestation = self.registry.attest(
            "fake-executor",
            implementation_version="1.0.0",
            implementation_digest=IMPLEMENTATION_DIGEST,
            sandbox_profile="starcom-c3-default-deny-v1",
            requires_network=False,
        )
        self.assertEqual(attestation.state, C3ExecutorState.ENABLED)
        self.assertEqual(attestation.network_mode, C3ExecutorNetworkMode.DENY)
        mismatch_cases = (
            {
                "implementation_version": "2.0.0",
                "implementation_digest": IMPLEMENTATION_DIGEST,
                "sandbox_profile": "starcom-c3-default-deny-v1",
                "requires_network": False,
            },
            {
                "implementation_version": "1.0.0",
                "implementation_digest": "9" * 64,
                "sandbox_profile": "starcom-c3-default-deny-v1",
                "requires_network": False,
            },
            {
                "implementation_version": "1.0.0",
                "implementation_digest": IMPLEMENTATION_DIGEST,
                "sandbox_profile": "unknown-sandbox",
                "requires_network": False,
            },
            {
                "implementation_version": "1.0.0",
                "implementation_digest": IMPLEMENTATION_DIGEST,
                "sandbox_profile": "starcom-c3-default-deny-v1",
                "requires_network": True,
            },
        )
        for arguments in mismatch_cases:
            with self.subTest(arguments=arguments):
                with self.assertRaises(StateTransitionError):
                    self.registry.attest("fake-executor", **arguments)

    def test_revocation_is_immediate_terminal_and_exact_replay_is_idempotent(self) -> None:
        self.register()
        self.accept_root()
        self.qualify()
        self.enable()
        reason = "implementation digest compromised"
        preparation = self.registry.prepare_revoke(
            "fake-executor",
            reason=reason,
        )
        decision = self.authorize(
            preparation,
            subject="security-owner",
            rule_id="allow-revoke",
            now=R5,
        )
        first = self.registry.revoke(
            "fake-executor",
            reason=reason,
            authorization_decision_id=decision.decision_id,
            actor="security-owner",
            occurred_at=R5,
        )
        replay = self.registry.revoke(
            "fake-executor",
            reason=reason,
            authorization_decision_id=decision.decision_id,
            actor="security-owner",
            occurred_at=R6,
        )
        self.assertEqual(first, replay)
        self.assertEqual(first.state, C3ExecutorState.REVOKED)
        with self.assertRaises(StateTransitionError):
            self.registry.prepare_enable("fake-executor")
        with self.assertRaises(StateTransitionError):
            self.registry.attest(
                "fake-executor",
                implementation_version="1.0.0",
                implementation_digest=IMPLEMENTATION_DIGEST,
                sandbox_profile="starcom-c3-default-deny-v1",
                requires_network=False,
            )
        with self.assertRaises(ConflictError):
            self.registry.revoke(
                "fake-executor",
                reason="different reason",
                authorization_decision_id=decision.decision_id,
                actor="security-owner",
                occurred_at=R6,
            )

    def test_wrong_context_actor_and_decision_reuse_fail_closed(self) -> None:
        preparation = self.registry.prepare_registration(self.descriptor())
        wrong_context = dict(preparation.context)
        wrong_context["descriptor_digest"] = "0" * 64
        decision = self.authorize(
            preparation,
            subject="registry-operator",
            rule_id="allow-register",
            now=R1,
            context=wrong_context,
        )
        self.assertTrue(decision.allowed)
        with self.assertRaises(AuthorizationError):
            self.registry.register(
                self.descriptor(),
                authorization_decision_id=decision.decision_id,
                actor="registry-operator",
                occurred_at=R1,
            )
        with self.assertRaises(AuthorizationError):
            self.registry.register(
                self.descriptor(),
                authorization_decision_id=decision.decision_id,
                actor="different-actor",
                occurred_at=R1,
            )
        count = self.database.connection.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
            ("c3_executor_descriptors",),
        ).fetchone()[0]
        if count:
            registered = self.database.connection.execute(
                "SELECT COUNT(*) FROM c3_executor_descriptors",
            ).fetchone()[0]
            self.assertEqual(registered, 0)


if __name__ == "__main__":
    unittest.main()
