from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from starcom.canonical import sha256_digest
from starcom.db import Database
from starcom.durable import DurableOutbox, EffectStatus
from starcom.ledger import EventLedger
from starcom.mission import MissionKernel, MissionState
from starcom.proof import ProofEngine, VerificationVerdict
from starcom.research import ReceiptOutcome, ResearchCampaign
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule, TrustPlane


T0 = "2026-08-13T12:00:00.000000Z"
T1 = "2026-08-13T12:01:00.000000Z"
T2 = "2026-08-13T12:02:00.000000Z"
T3 = "2026-08-13T12:03:00.000000Z"
T4 = "2026-08-13T12:04:00.000000Z"
T5 = "2026-08-13T12:05:00.000000Z"
T5A = "2026-08-13T12:05:30.000000Z"
T6 = "2026-08-13T12:06:00.000000Z"
T7 = "2026-08-13T12:07:00.000000Z"
SNAPSHOT = "a" * 64
CONTENT = "b" * 64


class ProofGatedVerticalSliceTests(unittest.TestCase):
    def test_research_to_authorized_mission_to_certified_success(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            database = Database(Path(tempdir) / "starcom.sqlite3")
            self.addCleanup(database.close)
            database.initialize()
            ledger = EventLedger(database)
            trust = TrustPlane(database, ledger)
            proof = ProofEngine(database, ledger)
            missions = MissionKernel(database, ledger, trust, proof)
            durable = DurableOutbox(database, ledger)
            research = ResearchCampaign(database, ledger)

            campaign = research.create(
                campaign_id="campaign-r0.1",
                name="R0.1 verification campaign",
                actor="owner",
                occurred_at=T0,
            )
            attempt = research.begin_attempt(
                campaign.campaign_id,
                attempt_id="attempt-1",
                wave=1,
                request_key="official-source-1",
                source_id="source:official",
                request={"query": "STARCOM acceptance evidence"},
                actor="agent:researcher",
                occurred_at=T1,
            )
            research.record_receipt(
                attempt.attempt_id,
                receipt_id="receipt-1",
                outcome=ReceiptOutcome.SUCCESS,
                status_code=200,
                snapshot_digest=SNAPSHOT,
                metadata={"content_type": "application/json"},
                actor="agent:researcher",
                occurred_at=T2,
            )
            research.record_observation(
                attempt.attempt_id,
                observation_id="observation-1",
                snapshot_digest=SNAPSHOT,
                content_digest=CONTENT,
                data={"acceptance": "observed"},
                actor="agent:researcher",
                occurred_at=T2,
            )
            research.checkpoint_cursor(
                campaign.campaign_id,
                cursor_id="cursor-1",
                wave=1,
                cursor_key="official-source",
                value={"complete": True},
                attempt_id=attempt.attempt_id,
                actor="agent:researcher",
                occurred_at=T3,
            )
            campaign_verification = research.verify(campaign.campaign_id)
            self.assertTrue(campaign_verification.ok, campaign_verification.defects)

            trust.add_rule(
                PolicyRule(
                    "mission-operators",
                    PolicyEffect.ALLOW,
                    "agent:operator",
                    "mission:*",
                    "mission:*",
                ),
                actor="owner",
                occurred_at=T0,
            )
            mission = missions.create(
                mission_id="mission-r0.1",
                title="Certify R0.1 vertical slice",
                objective="Reach terminal success only after independent proof.",
                owner="owner",
                occurred_at=T0,
            )
            missions.transition(
                mission.mission_id,
                MissionState.PLANNED,
                actor="agent:operator",
                idempotency_key="plan-r0.1",
                occurred_at=T1,
            )
            authorize = trust.authorize(
                AuthorizationRequest(
                    subject="agent:operator",
                    action="mission:authorize",
                    resource=f"mission:{mission.mission_id}",
                    mission_id=mission.mission_id,
                ),
                now=T2,
            )
            missions.transition(
                mission.mission_id,
                MissionState.AUTHORIZED,
                actor="agent:operator",
                idempotency_key="authorize-r0.1",
                authorization_decision_id=authorize.decision_id,
                occurred_at=T3,
            )
            run = trust.authorize(
                AuthorizationRequest(
                    subject="agent:operator",
                    action="mission:run",
                    resource=f"mission:{mission.mission_id}",
                    mission_id=mission.mission_id,
                ),
                now=T4,
            )
            missions.transition(
                mission.mission_id,
                MissionState.RUNNING,
                actor="agent:operator",
                idempotency_key="run-r0.1",
                authorization_decision_id=run.decision_id,
                occurred_at=T4,
            )

            effect = durable.enqueue(
                effect_id="effect-r0.1",
                topic="artifact.publish",
                payload={"campaign_id": campaign.campaign_id},
                actor="agent:operator",
                occurred_at=T4,
            )
            lease = durable.claim("worker:artifact", now=T5)[0]
            durable.succeed(
                effect.effect_id,
                worker_id=lease.worker_id,
                lease_token=lease.lease_token,
                result_digest=sha256_digest({"artifact": "R0.1 report"}),
                occurred_at=T5A,
            )
            self.assertEqual(durable.get(effect.effect_id).status, EffectStatus.SUCCEEDED)

            claim = proof.create_claim(
                claim_id="claim-r0.1",
                subject_type="mission",
                subject_id=mission.mission_id,
                statement="R0.1 acceptance criteria passed.",
                author="agent:builder",
                policy_version="policy-r0.1",
                occurred_at=T4,
            )
            proof.attach_evidence(
                claim.claim_id,
                evidence_id="evidence-r0.1",
                kind="campaign-verification",
                uri="starcom://research/campaign-r0.1",
                digest=sha256_digest(campaign_verification),
                metadata={"defects": list(campaign_verification.defects)},
                attached_by="agent:builder",
                occurred_at=T5,
            )
            proof.verify_claim(
                claim.claim_id,
                verifier="agent:reviewer",
                verdict=VerificationVerdict.APPROVED,
                notes="Recomputed the campaign and ledger chains.",
                occurred_at=T6,
            )
            certificate = proof.certify_claim(
                claim.claim_id,
                certifier="agent:certifier",
                occurred_at=T7,
            )
            self.assertTrue(proof.verify_certificate(certificate.certificate_id).ok)
            missions.transition(
                mission.mission_id,
                MissionState.SUCCEEDED,
                actor="agent:operator",
                idempotency_key="succeed-r0.1",
                certificate_id=certificate.certificate_id,
                occurred_at=T7,
            )

            terminal = missions.get(mission.mission_id)
            self.assertEqual(terminal.state, MissionState.SUCCEEDED)
            chain = ledger.verify()
            self.assertTrue(chain.ok, chain.defects)
            self.assertGreaterEqual(chain.checked_streams, 6)


if __name__ == "__main__":
    unittest.main()
