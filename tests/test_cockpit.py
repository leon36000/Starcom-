from __future__ import annotations

from io import BytesIO
import inspect
import json
from pathlib import Path
import tempfile
import unittest

from starcom.cli import Runtime
from starcom.cockpit import (
    CockpitCommandType,
    CockpitCommandStatus,
    CockpitService,
    CockpitWSGIApp,
)
from starcom.errors import AuthorizationError, ConflictError, ValidationError
from starcom.trust import AuthorizationRequest, PolicyEffect, PolicyRule


T0 = "2026-08-21T12:00:00.000000Z"
T1 = "2026-08-21T12:00:01.000000Z"
T2 = "2026-08-21T12:00:02.000000Z"
FUTURE = "2099-01-01T00:00:00.000000Z"


class CockpitTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.runtime = Runtime.open(Path(self.tempdir.name) / "cockpit.sqlite3")
        self.service = CockpitService(
            self.runtime.database,
            self.runtime.ledger,
            self.runtime.trust,
        )
        self.snapshot = self.service.admit_snapshot(
            self.service.prepare_snapshot("snapshot-1", self.snapshot_payload()),
            actor="snapshot-authority",
            occurred_at=T0,
        )
        self.credentials = self.service.create_session(
            "session-1",
            "operator-a",
            token="bearer-secret",
            csrf_token="csrf-secret",
            expires_at=FUTURE,
            actor="session-authority",
            occurred_at=T1,
        )
        self.runtime.trust.add_rule(
            PolicyRule(
                rule_id="cockpit-command-allow",
                effect=PolicyEffect.ALLOW,
                subject="operator-a",
                action="cockpit.command.authorize",
                resource="cockpit:command:*",
            ),
            actor="policy-admin",
            occurred_at=T2,
        )

    def tearDown(self) -> None:
        self.runtime.close()
        self.tempdir.cleanup()

    @staticmethod
    def snapshot_payload() -> dict[str, object]:
        return {
            "project_state": "RC_BLOCKED_EXTERNAL_EVIDENCE",
            "current_phase": "BLOCK17_COCKPIT",
            "test_count": 482,
            "canonical_truth": "NOT_RELEASED",
            "services": [
                {"service_id": "ledger", "status": "PASS"},
                {"service_id": "trust", "status": "PASS"},
            ],
            "alerts": [
                {
                    "alert_id": "external-evidence",
                    "severity": "INFO",
                    "message": "external evidence remains not proven",
                }
            ],
            "updated_at_utc": T1,
        }

    def preparation(self, command_id: str = "command-1", **overrides: object):
        values: dict[str, object] = {
            "command_id": command_id,
            "session_id": "session-1",
            "snapshot_id": "snapshot-1",
            "command_type": CockpitCommandType.START,
            "target": "starcom-program",
            "parameters": {"reason": "operator review", "dry_run": True},
        }
        values.update(overrides)
        return self.service.prepare_command(**values)

    def decision(self, preparation, *, context=None, subject="operator-a"):
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
            now=T2,
        )

    def call_wsgi(
        self,
        app: CockpitWSGIApp,
        path: str,
        *,
        method: str = "GET",
        body: bytes = b"",
        headers: dict[str, str] | None = None,
    ) -> tuple[str, dict[str, str], bytes]:
        captured: dict[str, object] = {}

        def start_response(status, response_headers, exc_info=None):  # type: ignore[no-untyped-def]
            captured["status"] = status
            captured["headers"] = dict(response_headers)

        request_headers: dict[str, str] = {}
        for key, value in (headers or {}).items():
            normalized = key.upper().replace("-", "_")
            if normalized not in {"CONTENT_TYPE", "CONTENT_LENGTH"} and not normalized.startswith("HTTP_"):
                normalized = "HTTP_" + normalized
            request_headers[normalized] = value
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "QUERY_STRING": "",
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "8080",
            "SERVER_PROTOCOL": "HTTP/1.1",
            "wsgi.version": (1, 0),
            "wsgi.url_scheme": "http",
            "wsgi.input": BytesIO(body),
            "wsgi.errors": BytesIO(),
            "wsgi.multithread": False,
            "wsgi.multiprocess": False,
            "wsgi.run_once": False,
            "CONTENT_LENGTH": str(len(body)),
            **request_headers,
        }
        result = b"".join(app(environ, start_response))
        return str(captured["status"]), captured["headers"], result  # type: ignore[return-value]


class CockpitContractTests(CockpitTestBase):
    def test_snapshot_prepare_is_deterministic_and_snapshot_is_immutable(self) -> None:
        first = self.service.prepare_snapshot("snapshot-next", self.snapshot_payload())
        second = self.service.prepare_snapshot("snapshot-next", self.snapshot_payload())
        self.assertEqual(first, second)
        self.assertEqual(self.service.get_latest_snapshot().snapshot_id, "snapshot-1")
        self.assertTrue(self.service.verify_snapshot("snapshot-1").ok)
        with self.assertRaises(ValidationError):
            self.service.prepare_snapshot(
                "bad-snapshot",
                {**self.snapshot_payload(), "unexpected": True},
            )

    def test_sessions_store_only_hashes_and_expiration_is_enforced(self) -> None:
        row = self.runtime.database.connection.execute(
            "SELECT token_hash, csrf_hash FROM cockpit_sessions WHERE session_id = ?",
            ("session-1",),
        ).fetchone()
        self.assertNotEqual(row["token_hash"], "bearer-secret")
        self.assertNotEqual(row["csrf_hash"], "csrf-secret")
        authenticated = self.service.authenticate(
            "session-1", "bearer-secret", now=T2
        )
        self.assertEqual(authenticated.subject, "operator-a")
        self.service.verify_csrf(authenticated, "csrf-secret")
        with self.assertRaises(AuthorizationError):
            self.service.authenticate("session-1", "wrong", now=T2)
        with self.assertRaises(AuthorizationError):
            self.service.authenticate("session-1", "bearer-secret", now="2100-01-01T00:00:00.000000Z")

    def test_command_default_deny_exact_admission_and_verify(self) -> None:
        preparation = self.preparation()
        denied = self.decision(preparation, subject="untrusted")
        self.assertFalse(denied.allowed)
        with self.assertRaises(AuthorizationError):
            self.service.authorize_command(
                preparation,
                authorization_decision_id=denied.decision_id,
                actor="untrusted",
                occurred_at=T2,
            )

        decision = self.decision(preparation)
        record = self.service.authorize_command(
            preparation,
            authorization_decision_id=decision.decision_id,
            actor="operator-a",
            occurred_at="2026-08-21T12:00:03.000000Z",
        )
        self.assertEqual(record.status, CockpitCommandStatus.AUTHORIZED_NOT_EXECUTED)
        self.assertEqual(self.service.get_command("command-1"), record)
        self.assertTrue(self.service.verify_command("command-1").ok)

    def test_command_context_replay_and_decision_reuse_are_strict(self) -> None:
        preparation = self.preparation("command-replay")
        decision = self.decision(preparation)
        first = self.service.authorize_command(
            preparation,
            authorization_decision_id=decision.decision_id,
            actor="operator-a",
            occurred_at=T2,
        )
        self.assertEqual(
            self.service.authorize_command(
                preparation,
                authorization_decision_id=decision.decision_id,
                actor="operator-a",
                occurred_at="2026-08-21T12:00:04.000000Z",
            ),
            first,
        )
        second = self.preparation("command-other")
        with self.assertRaises(ConflictError):
            self.service.authorize_command(
                second,
                authorization_decision_id=decision.decision_id,
                actor="operator-a",
            )
        wrong_context = dict(self.preparation("command-wrong").authorization_context)
        wrong_context["parameters_digest"] = "0" * 64
        wrong_decision = self.decision(
            self.preparation("command-wrong"), context=wrong_context
        )
        with self.assertRaises(AuthorizationError):
            self.service.authorize_command(
                self.preparation("command-wrong"),
                authorization_decision_id=wrong_decision.decision_id,
                actor="operator-a",
            )

    def test_snapshot_and_command_tampering_are_detected(self) -> None:
        preparation = self.preparation("command-tamper")
        decision = self.decision(preparation)
        self.service.authorize_command(
            preparation,
            authorization_decision_id=decision.decision_id,
            actor="operator-a",
            occurred_at=T2,
        )
        self.runtime.database.connection.execute("DROP TRIGGER cockpit_commands_no_update")
        self.runtime.database.connection.execute(
            "UPDATE cockpit_commands SET parameters_json = ? WHERE command_id = ?",
            ('{"tampered":true}', "command-tamper"),
        )
        verification = self.service.verify_command("command-tamper")
        self.assertFalse(verification.ok)
        self.assertIn("COMMAND_PARAMETERS_DIGEST_MISMATCH", verification.defects)

    def test_runtime_uses_one_shared_cockpit_service(self) -> None:
        self.assertIs(self.runtime.cockpit.database, self.runtime.database)
        self.assertIs(self.runtime.cockpit.ledger, self.runtime.ledger)
        self.assertIs(self.runtime.cockpit.trust, self.runtime.trust)


class CockpitWSGITests(CockpitTestBase):
    def test_health_shell_headers_and_authenticated_snapshot(self) -> None:
        app = CockpitWSGIApp(self.service)
        status, headers, body = self.call_wsgi(app, "/api/v1/health")
        self.assertEqual(status, "200 OK")
        self.assertEqual(json.loads(body), {"ok": True, "service": "starcom-cockpit"})
        for name in (
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
            "Cache-Control",
        ):
            self.assertIn(name, headers)

        status, _, body = self.call_wsgi(app, "/")
        self.assertEqual(status, "200 OK")
        self.assertIn(b"STARCOM Cockpit", body)
        self.assertNotIn(b"bearer-secret", body)
        status, _, _ = self.call_wsgi(app, "/api/v1/snapshot")
        self.assertEqual(status, "401 Unauthorized")

        auth_headers = {
            "Authorization": "Bearer bearer-secret",
            "X-Cockpit-Session": "session-1",
        }
        status, _, body = self.call_wsgi(
            app,
            "/api/v1/snapshot",
            headers=auth_headers,
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(json.loads(body)["snapshot_id"], "snapshot-1")
        self.assertNotIn(b"csrf-secret", body)

    def test_post_requires_json_auth_and_csrf_and_admits_command(self) -> None:
        app = CockpitWSGIApp(self.service)
        preparation = self.preparation("command-web")
        decision = self.decision(preparation)
        body = json.dumps(
            {
                "command_id": "command-web",
                "snapshot_id": "snapshot-1",
                "command_type": "START",
                "target": "starcom-program",
                "parameters": dict(preparation.parameters),
                "authorization_decision_id": decision.decision_id,
            },
            separators=(",", ":"),
        ).encode()
        auth_headers = {
            "Authorization": "Bearer bearer-secret",
            "X-Cockpit-Session": "session-1",
        }
        status, _, _ = self.call_wsgi(
            app,
            "/api/v1/commands",
            method="POST",
            body=body,
            headers=auth_headers | {"Content-Type": "application/json"},
        )
        self.assertEqual(status, "403 Forbidden")
        status, _, response = self.call_wsgi(
            app,
            "/api/v1/commands",
            method="POST",
            body=body,
            headers=auth_headers
            | {"Content-Type": "application/json", "X-CSRF-Token": "csrf-secret"},
        )
        self.assertEqual(status, "201 Created")
        self.assertNotIn(b"bearer-secret", response)
        self.assertNotIn(b"csrf-secret", response)

        status, _, response = self.call_wsgi(
            app,
            "/api/v1/commands/command-web",
            headers=auth_headers,
        )
        self.assertEqual(status, "200 OK")
        self.assertEqual(json.loads(response)["status"], "COCKPIT_COMMAND_AUTHORIZED_NOT_EXECUTED")

        status, _, _ = self.call_wsgi(
            app,
            "/api/v1/commands",
            method="POST",
            body=body,
            headers=auth_headers
            | {"Content-Type": "text/plain", "X-CSRF-Token": "csrf-secret"},
        )
        self.assertEqual(status, "415 Unsupported Media Type")

    def test_wsgi_body_limit_method_and_unknown_route_are_bounded(self) -> None:
        app = CockpitWSGIApp(self.service, max_body_bytes=32)
        auth_headers = {
            "Authorization": "Bearer bearer-secret",
            "X-Cockpit-Session": "session-1",
            "X-CSRF-Token": "csrf-secret",
            "Content-Type": "application/json",
        }
        status, _, _ = self.call_wsgi(
            app,
            "/api/v1/commands",
            method="POST",
            body=b"{" + b"x" * 64,
            headers=auth_headers,
        )
        self.assertEqual(status, "413 Request Entity Too Large")
        status, _, _ = self.call_wsgi(app, "/api/v1/health", method="POST")
        self.assertEqual(status, "405 Method Not Allowed")
        status, _, _ = self.call_wsgi(app, "/unknown")
        self.assertEqual(status, "404 Not Found")

    def test_no_execution_or_external_transport_surface(self) -> None:
        service_forbidden = {
            "execute",
            "run",
            "dispatch",
            "browser",
            "shell",
            "file",
        }
        app_forbidden = service_forbidden | {"proxy", "open_socket"}
        self.assertTrue(service_forbidden.isdisjoint(dir(self.service)))
        self.assertTrue(app_forbidden.isdisjoint(dir(CockpitWSGIApp(self.service))))
        source = inspect.getsource(CockpitWSGIApp).lower()
        for token in ("socket", "subprocess", "websocket", "proxy", "requests"):
            self.assertNotIn(token, source)


if __name__ == "__main__":
    unittest.main()
