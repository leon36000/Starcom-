from __future__ import annotations

from pathlib import Path


ledger_path = Path("src/starcom/recollection.py")
ledger = ledger_path.read_text(encoding="utf-8")

if "from datetime import datetime" not in ledger:
    ledger = ledger.replace(
        "from dataclasses import dataclass\n",
        "from dataclasses import dataclass\nfrom datetime import datetime\n",
        1,
    )

ledger = ledger.replace(
    '_ERROR_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")\n',
    '_ERROR_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")\n'
    '_UTC_TIMESTAMP = re.compile(\n'
    '    r"^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,6})?Z$"\n'
    ')\n',
    1,
)

old_timestamp = '''def _timestamp(value: str) -> str:
    if not isinstance(value, str) or "T" not in value or not value.endswith("Z"):
        raise ValueError("timestamps must be UTC RFC 3339 strings ending in Z")
    return value
'''
new_timestamp = '''def _parse_timestamp(value: str) -> datetime:
    if not isinstance(value, str) or not _UTC_TIMESTAMP.fullmatch(value):
        raise ValueError("timestamps must be strict UTC RFC 3339 values ending in Z")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("timestamp is not a valid calendar instant") from exc


def _timestamp(value: str) -> str:
    _parse_timestamp(value)
    return value
'''
if old_timestamp not in ledger:
    raise SystemExit("strict timestamp anchor not found")
ledger = ledger.replace(old_timestamp, new_timestamp, 1)

old_event_query = '''        prior = self.connection.execute(
            "SELECT sequence,event_hash FROM recollection_events "
            "WHERE campaign_id=? ORDER BY sequence DESC LIMIT 1",
            (campaign_id,),
        ).fetchone()
        sequence = 1 if prior is None else int(prior["sequence"]) + 1
'''
new_event_query = '''        prior = self.connection.execute(
            "SELECT sequence,event_hash,recorded_at FROM recollection_events "
            "WHERE campaign_id=? ORDER BY sequence DESC LIMIT 1",
            (campaign_id,),
        ).fetchone()
        if prior is not None and _parse_timestamp(recorded_at) < _parse_timestamp(prior["recorded_at"]):
            raise ValueError("recollection event timestamps cannot regress")
        sequence = 1 if prior is None else int(prior["sequence"]) + 1
'''
if old_event_query not in ledger:
    raise SystemExit("event monotonicity anchor not found")
ledger = ledger.replace(old_event_query, new_event_query, 1)

old_event_state = '''        previous = "0" * 64
        expected_sequence = 1
        for row in rows:
'''
new_event_state = '''        previous = "0" * 64
        previous_time: datetime | None = None
        expected_sequence = 1
        for row in rows:
'''
if old_event_state not in ledger:
    raise SystemExit("event verification state anchor not found")
ledger = ledger.replace(old_event_state, new_event_state, 1)

old_event_previous = '''            if row["previous_hash"] != previous:
                defects.append(f"EVENT_PREVIOUS_HASH_MISMATCH:{sequence}")
            try:
                payload = json.loads(row["payload_json"])
'''
new_event_previous = '''            if row["previous_hash"] != previous:
                defects.append(f"EVENT_PREVIOUS_HASH_MISMATCH:{sequence}")
            try:
                current_time = _parse_timestamp(row["recorded_at"])
            except ValueError:
                defects.append(f"EVENT_TIMESTAMP_INVALID:{sequence}")
                current_time = None
            if current_time is not None:
                if previous_time is not None and current_time < previous_time:
                    defects.append(f"EVENT_TIMESTAMP_REGRESSION:{sequence}")
                previous_time = current_time
            try:
                payload = json.loads(row["payload_json"])
'''
if old_event_previous not in ledger:
    raise SystemExit("event timestamp verification anchor not found")
ledger = ledger.replace(old_event_previous, new_event_previous, 1)

old_campaign_start = '''        campaign = self._campaign(campaign_id)
        defects = self._event_defects(campaign_id)
        items = self.connection.execute(
'''
new_campaign_start = '''        campaign = self._campaign(campaign_id)
        defects = self._event_defects(campaign_id)
        try:
            campaign_created_time = _parse_timestamp(campaign["created_at"])
        except ValueError:
            defects.append("CAMPAIGN_CREATED_AT_INVALID")
            campaign_created_time = None
        campaign_finalized_time: datetime | None = None
        if campaign["finalized_at"] is not None:
            try:
                campaign_finalized_time = _parse_timestamp(campaign["finalized_at"])
            except ValueError:
                defects.append("CAMPAIGN_FINALIZED_AT_INVALID")
        if campaign["status"] == "FINALIZED" and campaign["finalized_at"] is None:
            defects.append("FINALIZED_CAMPAIGN_MISSING_FINALIZED_AT")
        if campaign["status"] != "FINALIZED" and campaign["finalized_at"] is not None:
            defects.append("UNFINALIZED_CAMPAIGN_HAS_FINALIZED_AT")
        items = self.connection.execute(
'''
if old_campaign_start not in ledger:
    raise SystemExit("campaign temporal verification anchor not found")
ledger = ledger.replace(old_campaign_start, new_campaign_start, 1)

old_event_collections = '''        plan_events: list[dict[str, Any]] = []
        prepare_events: dict[str, list[dict[str, Any]]] = {}
        terminal_events: dict[str, list[dict[str, Any]]] = {}
        final_events: list[tuple[int, dict[str, Any]]] = []
        unknown_events: list[str] = []
        for event in self.connection.execute(
            "SELECT sequence,event_type,payload_json FROM recollection_events "
            "WHERE campaign_id=? ORDER BY sequence",
            (campaign_id,),
        ).fetchall():
'''
new_event_collections = '''        plan_events: list[tuple[dict[str, Any], str]] = []
        prepare_events: dict[str, list[tuple[dict[str, Any], str]]] = {}
        terminal_events: dict[str, list[tuple[dict[str, Any], str]]] = {}
        final_events: list[tuple[int, dict[str, Any], str]] = []
        unknown_events: list[str] = []
        for event in self.connection.execute(
            "SELECT sequence,event_type,payload_json,recorded_at FROM recollection_events "
            "WHERE campaign_id=? ORDER BY sequence",
            (campaign_id,),
        ).fetchall():
'''
if old_event_collections not in ledger:
    raise SystemExit("temporal event collection anchor not found")
ledger = ledger.replace(old_event_collections, new_event_collections, 1)

ledger = ledger.replace(
    '                plan_events.append(payload)\n',
    '                plan_events.append((payload, str(event["recorded_at"])))\n',
    1,
)
ledger = ledger.replace(
    '                    prepare_events.setdefault(attempt_id, []).append(payload)\n',
    '                    prepare_events.setdefault(attempt_id, []).append(\n'
    '                        (payload, str(event["recorded_at"]))\n'
    '                    )\n',
    1,
)
ledger = ledger.replace(
    '                    terminal_events.setdefault(attempt_id, []).append(payload)\n',
    '                    terminal_events.setdefault(attempt_id, []).append(\n'
    '                        (payload, str(event["recorded_at"]))\n'
    '                    )\n',
    1,
)
ledger = ledger.replace(
    '                final_events.append((int(event["sequence"]), payload))\n',
    '                final_events.append(\n'
    '                    (int(event["sequence"]), payload, str(event["recorded_at"]))\n'
    '                )\n',
    1,
)

old_attempt_digest = '''                if attempt["request_digest"] != plan_item["request_digest"]:
                    defects.append(f"ATTEMPT_REQUEST_DIGEST_MISMATCH:{attempt_id}")
                prepared_payloads = prepare_events.get(attempt_id, [])
'''
new_attempt_digest = '''                if attempt["request_digest"] != plan_item["request_digest"]:
                    defects.append(f"ATTEMPT_REQUEST_DIGEST_MISMATCH:{attempt_id}")
                try:
                    prepared_time = _parse_timestamp(attempt["prepared_at"])
                except ValueError:
                    defects.append(f"ATTEMPT_PREPARED_AT_INVALID:{attempt_id}")
                    prepared_time = None
                prepared_payloads = prepare_events.get(attempt_id, [])
'''
if old_attempt_digest not in ledger:
    raise SystemExit("attempt prepared timestamp anchor not found")
ledger = ledger.replace(old_attempt_digest, new_attempt_digest, 1)

old_prepare_compare = '''                    if prepared_payloads[0] != expected_prepare:
                        defects.append(f"ATTEMPT_PREPARE_EVENT_MISMATCH:{attempt_id}")
                if attempt["state"] != "TERMINAL":
'''
new_prepare_compare = '''                    prepared_payload, prepared_event_time = prepared_payloads[0]
                    if prepared_payload != expected_prepare:
                        defects.append(f"ATTEMPT_PREPARE_EVENT_MISMATCH:{attempt_id}")
                    if prepared_event_time != attempt["prepared_at"]:
                        defects.append(f"ATTEMPT_PREPARE_EVENT_TIME_MISMATCH:{attempt_id}")
                if attempt["state"] != "TERMINAL":
'''
if old_prepare_compare not in ledger:
    raise SystemExit("prepare event time anchor not found")
ledger = ledger.replace(old_prepare_compare, new_prepare_compare, 1)

old_terminal_compare = '''                    if terminal_payloads[0] != expected_terminal:
                        defects.append(f"ATTEMPT_TERMINAL_EVENT_MISMATCH:{attempt_id}")
                kind = attempt["terminal_kind"]
'''
new_terminal_compare = '''                    terminal_payload, terminal_event_time = terminal_payloads[0]
                    if terminal_payload != expected_terminal:
                        defects.append(f"ATTEMPT_TERMINAL_EVENT_MISMATCH:{attempt_id}")
                    if terminal_event_time != attempt["terminal_at"]:
                        defects.append(f"ATTEMPT_TERMINAL_EVENT_TIME_MISMATCH:{attempt_id}")
                try:
                    terminal_time = _parse_timestamp(attempt["terminal_at"])
                except (TypeError, ValueError):
                    defects.append(f"ATTEMPT_TERMINAL_AT_INVALID:{attempt_id}")
                    terminal_time = None
                if (
                    prepared_time is not None
                    and terminal_time is not None
                    and terminal_time < prepared_time
                ):
                    defects.append(f"ATTEMPT_TERMINAL_BEFORE_PREPARE:{attempt_id}")
                kind = attempt["terminal_kind"]
'''
if old_terminal_compare not in ledger:
    raise SystemExit("terminal event time anchor not found")
ledger = ledger.replace(old_terminal_compare, new_terminal_compare, 1)

old_plan_event = '''        if len(plan_events) != 1:
            defects.append("CAMPAIGN_PLAN_EVENT_COUNT_INVALID")
        elif plan_events[0] != expected_plan_event:
            defects.append("CAMPAIGN_PLAN_EVENT_MISMATCH")
'''
new_plan_event = '''        if len(plan_events) != 1:
            defects.append("CAMPAIGN_PLAN_EVENT_COUNT_INVALID")
        else:
            plan_payload, plan_event_time = plan_events[0]
            if plan_payload != expected_plan_event:
                defects.append("CAMPAIGN_PLAN_EVENT_MISMATCH")
            if plan_event_time != campaign["created_at"]:
                defects.append("CAMPAIGN_PLAN_EVENT_TIME_MISMATCH")
'''
if old_plan_event not in ledger:
    raise SystemExit("plan event temporal anchor not found")
ledger = ledger.replace(old_plan_event, new_plan_event, 1)

old_final_unpack = '''                final_sequence, final_payload = final_events[0]
                if final_sequence != self.event_count(campaign_id):
'''
new_final_unpack = '''                final_sequence, final_payload, final_event_time = final_events[0]
                if final_sequence != self.event_count(campaign_id):
'''
if old_final_unpack not in ledger:
    raise SystemExit("final event unpack anchor not found")
ledger = ledger.replace(old_final_unpack, new_final_unpack, 1)

old_final_digest_check = '''                prior_digest = final_payload.get("evidence_digest_before_final_event")
                if not isinstance(prior_digest, str) or len(prior_digest) != 64:
                    defects.append("CAMPAIGN_FINAL_EVENT_PRIOR_DIGEST_INVALID")
            if campaign["evidence_digest"] != self.evidence_digest(campaign_id):
'''
new_final_digest_check = '''                prior_digest = final_payload.get("evidence_digest_before_final_event")
                if not isinstance(prior_digest, str) or len(prior_digest) != 64:
                    defects.append("CAMPAIGN_FINAL_EVENT_PRIOR_DIGEST_INVALID")
                if final_event_time != campaign["finalized_at"]:
                    defects.append("CAMPAIGN_FINAL_EVENT_TIME_MISMATCH")
                if (
                    campaign_created_time is not None
                    and campaign_finalized_time is not None
                    and campaign_finalized_time < campaign_created_time
                ):
                    defects.append("CAMPAIGN_FINALIZED_BEFORE_CREATION")
            if campaign["evidence_digest"] != self.evidence_digest(campaign_id):
'''
if old_final_digest_check not in ledger:
    raise SystemExit("final temporal verification anchor not found")
ledger = ledger.replace(old_final_digest_check, new_final_digest_check, 1)
ledger_path.write_text(ledger, encoding="utf-8")

executor_path = Path("src/starcom/recollection_executor.py")
executor = executor_path.read_text(encoding="utf-8")
executor = executor.replace(
    '''    RecollectionIncomplete,\n''',
    '''    RecollectionIncomplete,\n    RecollectionNotFound,\n''',
    1,
)
if "from .canonical import utc_now" not in executor:
    executor = executor.replace(
        "from .recollection import (\n",
        "from .canonical import utc_now\nfrom .recollection import (\n",
        1,
    )

old_validator = '''def _validate_terminal_timestamp(value: str | None) -> None:
    if value is None:
        return
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("terminal_at must be a UTC RFC 3339 string ending in Z")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("terminal_at must be a valid UTC RFC 3339 timestamp") from exc
'''
new_validator = '''def _parse_utc_timestamp(name: str, value: str) -> datetime:
    if not isinstance(value, str) or "T" not in value or not value.endswith("Z"):
        raise ValueError(f"{name} must be a UTC RFC 3339 timestamp ending in Z")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{name} must be a valid UTC RFC 3339 timestamp") from exc
'''
if old_validator not in executor:
    raise SystemExit("executor timestamp parser anchor not found")
executor = executor.replace(old_validator, new_validator, 1)

old_execute_start = '''    ) -> ExecutionResult:
        _validate_terminal_timestamp(terminal_at)
        preparation = self.ledger.prepare_attempt_with_status(
            campaign_id,
            item_id,
            attempt_id,
            prepared_at=prepared_at,
        )
'''
new_execute_start = '''    ) -> ExecutionResult:
        terminal_time = (
            None
            if terminal_at is None
            else _parse_utc_timestamp("terminal_at", terminal_at)
        )
        try:
            self.ledger.get_attempt(attempt_id)
        except RecollectionNotFound:
            effective_prepared_at = prepared_at or utc_now()
            prepared_time = _parse_utc_timestamp("prepared_at", effective_prepared_at)
            if terminal_time is not None and terminal_time < prepared_time:
                raise ValueError("terminal_at cannot precede prepared_at")
        else:
            effective_prepared_at = prepared_at
        preparation = self.ledger.prepare_attempt_with_status(
            campaign_id,
            item_id,
            attempt_id,
            prepared_at=effective_prepared_at,
        )
'''
if old_execute_start not in executor:
    raise SystemExit("executor chronological preflight anchor not found")
executor = executor.replace(old_execute_start, new_execute_start, 1)
executor_path.write_text(executor, encoding="utf-8")
