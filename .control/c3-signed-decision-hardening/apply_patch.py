from __future__ import annotations

from pathlib import Path


MODULE = Path("src/starcom/qualification_decision.py")
SPEC = Path("docs/superpowers/specs/2026-08-14-c3-signed-decision-design.md")
PLAN = Path("docs/superpowers/plans/2026-08-14-c3-signed-decision.md")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(
            f"bounded patch refused for {label}: expected one target, found {count}"
        )
    return source.replace(old, new, 1)


def patch_module() -> None:
    source = MODULE.read_text(encoding="utf-8")

    source = replace_once(
        source,
        '''        evidence = (*candidates, *evaluations)\n        latest_evidence_at = None\n        if evidence:\n            latest_evidence_at = max(\n                (str(member["recorded_at"]) for member in evidence),\n                key=self._as_datetime,\n            )\n''',
        '''        evidence = (*candidates, *evaluations)\n        latest_evidence_at = None\n        if evidence:\n            validated_times: list[str] = []\n            for member in evidence:\n                recorded_at = str(member["recorded_at"])\n                try:\n                    self._timestamp(recorded_at, "recorded_at")\n                except ValidationError as exc:\n                    raise IntegrityError(\n                        "qualification artifact timestamp is invalid",\n                        {"artifact_id": str(member["artifact_id"])},\n                    ) from exc\n                validated_times.append(recorded_at)\n            latest_evidence_at = max(validated_times, key=self._as_datetime)\n''',
        "snapshot timestamp validation",
    )

    source = replace_once(
        source,
        '''        if (\n            snapshot.latest_evidence_at is not None\n            and self._as_datetime(str(value["decided_at_utc"]))\n            < self._as_datetime(snapshot.latest_evidence_at)\n        ):\n''',
        '''        decided_at = self._timestamp(value["decided_at_utc"], "decided_at_utc")\n        if (\n            snapshot.latest_evidence_at is not None\n            and self._as_datetime(decided_at)\n            < self._as_datetime(snapshot.latest_evidence_at)\n        ):\n''',
        "decision timestamp validation",
    )

    source = replace_once(
        source,
        '''    @staticmethod\n    def _ledger_payload(record: C3DecisionRecord) -> dict[str, object]:\n''',
        '''    def _assert_admission_time(self, admitted_at: str, decided_at: str) -> None:\n        admitted = self._timestamp(admitted_at, "admitted_at")\n        decided = self._timestamp(decided_at, "decided_at_utc")\n        if self._as_datetime(admitted) < self._as_datetime(decided):\n            raise StateTransitionError(\n                "admission predates the signed C3 decision"\n            )\n\n    @staticmethod\n    def _ledger_payload(record: C3DecisionRecord) -> dict[str, object]:\n''',
        "admission chronology helper",
    )

    source = replace_once(
        source,
        '''        self._assert_independent(decision_maker_identity, snapshot)\n\n        try:\n''',
        '''        self._assert_independent(decision_maker_identity, snapshot)\n        self._assert_admission_time(occurred_at, str(value["decided_at_utc"]))\n\n        try:\n''',
        "pre-transaction admission chronology",
    )

    source = replace_once(
        source,
        '''                self._assert_independent(decision_maker_identity, current_snapshot)\n                provisional = C3DecisionRecord(\n''',
        '''                self._assert_independent(decision_maker_identity, current_snapshot)\n                self._assert_admission_time(\n                    occurred_at,\n                    str(value["decided_at_utc"]),\n                )\n                provisional = C3DecisionRecord(\n''',
        "transactional admission chronology",
    )

    source = replace_once(
        source,
        '''        frozen_candidates: list[Mapping[str, Any]] = []\n        frozen_evaluations: list[Mapping[str, Any]] = []\n        expected_ordinals = {"CANDIDATE": 0, "EVALUATION": 0}\n''',
        '''        frozen_candidates: list[Mapping[str, Any]] = []\n        frozen_evaluations: list[Mapping[str, Any]] = []\n        valid_recorded_times: list[str] = []\n        expected_ordinals = {"CANDIDATE": 0, "EVALUATION": 0}\n''',
        "verifier timestamp accumulator",
    )

    source = replace_once(
        source,
        '''            member = self._member_from_frozen_row(frozen)\n            material = member["material"]\n''',
        '''            member = self._member_from_frozen_row(frozen)\n            recorded_at = str(member["recorded_at"])\n            try:\n                self._timestamp(recorded_at, "recorded_at")\n            except ValidationError:\n                defects.append(\n                    f"C3_DECISION_EVIDENCE_RECORDED_AT_INVALID:{label}"\n                )\n            else:\n                valid_recorded_times.append(recorded_at)\n            material = member["material"]\n''',
        "frozen evidence timestamp validation",
    )

    source = replace_once(
        source,
        '''        latest_evidence_at = None\n        frozen_all = (*frozen_candidates, *frozen_evaluations)\n        if frozen_all:\n            latest_evidence_at = max(\n                (str(member["recorded_at"]) for member in frozen_all),\n                key=self._as_datetime,\n            )\n''',
        '''        latest_evidence_at = None\n        if valid_recorded_times:\n            latest_evidence_at = max(\n                valid_recorded_times,\n                key=self._as_datetime,\n            )\n''',
        "fail-closed frozen evidence chronology",
    )

    source = replace_once(
        source,
        '''        try:\n            self._assert_evidence_selection_and_time(semantic_value, frozen_snapshot)\n        except StateTransitionError:\n            defects.append("C3_DECISION_SEMANTICS_OR_CHRONOLOGY_INVALID")\n        try:\n            self._assert_independent(record.decision_maker_identity, frozen_snapshot)\n        except StateTransitionError:\n            defects.append("C3_DECISION_INDEPENDENCE_INVALID")\n''',
        '''        try:\n            self._assert_evidence_selection_and_time(semantic_value, frozen_snapshot)\n        except (StateTransitionError, ValidationError, ValueError):\n            defects.append("C3_DECISION_SEMANTICS_OR_CHRONOLOGY_INVALID")\n        try:\n            self._assert_independent(record.decision_maker_identity, frozen_snapshot)\n        except StateTransitionError:\n            defects.append("C3_DECISION_INDEPENDENCE_INVALID")\n        try:\n            self._assert_admission_time(record.admitted_at, record.decided_at_utc)\n        except (StateTransitionError, ValidationError, ValueError):\n            defects.append("C3_DECISION_ADMISSION_CHRONOLOGY_INVALID")\n''',
        "verifier chronology containment",
    )

    MODULE.write_text(source, encoding="utf-8")


def patch_docs() -> None:
    spec = SPEC.read_text(encoding="utf-8")
    spec = replace_once(
        spec,
        "- a decision timestamp not earlier than the latest candidate or evaluation evidence;\n",
        "- a decision timestamp not earlier than the latest candidate or evaluation evidence;\n"
        "- an admission timestamp not earlier than the signed decision timestamp;\n",
        "design admission chronology",
    )
    SPEC.write_text(spec, encoding="utf-8")

    plan = PLAN.read_text(encoding="utf-8")
    plan = replace_once(
        plan,
        "Require `decided_at_utc >= latest_evidence_at`.\n",
        "Require `decided_at_utc >= latest_evidence_at` and "
        "`admitted_at >= decided_at_utc`.\n",
        "plan admission chronology",
    )
    PLAN.write_text(plan, encoding="utf-8")


def main() -> int:
    patch_module()
    patch_docs()
    print("patched C3 decision chronology and verifier robustness")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
