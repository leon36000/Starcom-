from __future__ import annotations

from pathlib import Path


PATH = Path("/tmp/starcom-c3-executor-registry/executor_registry.py")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(
            f"registry idempotency hardening refused for {label}: expected one target, found {count}"
        )
    return source.replace(old, new, 1)


def main() -> int:
    source = PATH.read_text(encoding="utf-8")
    source = replace_once(
        source,
        '''        value, payload_sha, signature_sha, descriptor, _ = (\n            self._qualification_material(\n                executor_id,\n                key_id,\n                payload,\n                signature,\n                require_registered_state=True,\n            )\n        )\n        actor = self._required_text(actor, "actor")\n''',
        '''        value, payload_sha, signature_sha, descriptor, _ = (\n            self._qualification_material(\n                executor_id,\n                key_id,\n                payload,\n                signature,\n                require_registered_state=False,\n            )\n        )\n        actor = self._required_text(actor, "actor")\n''',
        "qualification replay material validation",
    )
    source = replace_once(
        source,
        '''            return self._qualification_from_row(existing)\n        preparation = self.prepare_qualification(\n            executor_id, key_id, payload, signature\n        )\n''',
        '''            verification = self.verify(executor_id)\n            if not verification.ok:\n                raise IntegrityError(\n                    "existing executor qualification failed verification",\n                    {"executor_id": executor_id, "defects": list(verification.defects)},\n                )\n            return self._qualification_from_row(existing)\n        if self.get_current(executor_id).state is not (\n            C3ExecutorState.REGISTERED_DISABLED\n        ):\n            raise StateTransitionError(\n                "executor qualification requires REGISTERED_DISABLED"\n            )\n        preparation = self.prepare_qualification(\n            executor_id, key_id, payload, signature\n        )\n''',
        "qualification replay before state gate",
    )
    source = replace_once(
        source,
        '''        actor = self._required_text(actor, "actor")\n        occurred_at = self._timestamp(occurred_at or utc_now())\n        preparation = self.prepare_revoke(executor_id, reason=reason)\n        decision = self._assert_authorization(\n''',
        '''        actor = self._required_text(actor, "actor")\n        reason = self._required_text(reason, "reason")\n        occurred_at = self._timestamp(occurred_at or utc_now())\n        current = self.get_current(executor_id)\n        if current.state is C3ExecutorState.REVOKED:\n            transition = self.database.connection.execute(\n                """\n                SELECT * FROM c3_executor_transitions\n                WHERE executor_id = ? AND sequence = ?\n                """,\n                (executor_id, current.transition_sequence),\n            ).fetchone()\n            if transition is None:\n                raise IntegrityError("revoked executor transition is missing")\n            try:\n                metadata = json.loads(str(transition["metadata_json"]))\n            except (json.JSONDecodeError, TypeError) as exc:\n                raise IntegrityError("revoked executor metadata is invalid") from exc\n            exact = (\n                str(transition["operation"]) == "REVOKE"\n                and str(transition["authorization_decision_id"])\n                == authorization_decision_id\n                and str(transition["transitioned_by"]) == actor\n                and isinstance(metadata, dict)\n                and metadata.get("reason") == reason\n            )\n            if not exact:\n                raise ConflictError(\n                    "revoked executor replay conflicts with terminal material",\n                    {"executor_id": executor_id},\n                )\n            verification = self.verify(executor_id)\n            if not verification.ok:\n                raise IntegrityError(\n                    "existing executor revocation failed verification",\n                    {"executor_id": executor_id, "defects": list(verification.defects)},\n                )\n            return current\n        preparation = self.prepare_revoke(executor_id, reason=reason)\n        decision = self._assert_authorization(\n''',
        "terminal revocation replay",
    )
    source = replace_once(
        source,
        '''        current = self.get_current(executor_id)\n        sequence = current.transition_sequence + 1\n''',
        '''        current = self.get_current(executor_id)\n        sequence = current.transition_sequence + 1\n''',
        "single post-authorization current state",
    )
    PATH.write_text(source, encoding="utf-8")
    print("hardened qualification and revocation exact replay idempotency")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
