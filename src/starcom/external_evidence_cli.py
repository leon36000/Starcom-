from __future__ import annotations

import argparse
from dataclasses import asdict
import base64
import json
import os
from pathlib import Path
import sys
from collections.abc import Sequence
from typing import Any

from .canonical import canonical_json
from .errors import StarcomError, ValidationError
from .program import StarcomProgram


class JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValidationError("invalid command arguments", {"reason": message})


def _database_path(raw: str) -> str:
    if raw == ":memory:":
        return raw
    return str(Path(raw).expanduser().resolve())


def _read_file_bytes(raw: str, field: str) -> bytes:
    path = Path(raw).expanduser()
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ValidationError(
            f"{field} could not be read",
            {"path": str(path), "type": type(exc).__name__},
        ) from exc


def _record_payload(record: Any) -> dict[str, object]:
    result = asdict(record)
    result.pop("payload", None)
    result.pop("signature", None)
    result["payload_base64"] = base64.b64encode(record.payload).decode("ascii")
    result["signature_base64"] = base64.b64encode(record.signature).decode("ascii")
    return result


def _emit_success(result: Any) -> None:
    print(canonical_json({"ok": True, "result": result}))


def _emit_error(error: StarcomError) -> None:
    print(canonical_json(error.to_dict()), file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    parser = JsonArgumentParser(
        prog="starcom.external_evidence_cli",
        description="STARCOM exact-byte external evidence reader",
    )
    parser.add_argument("--db", default=os.environ.get("STARCOM_DB", "starcom.sqlite3"))
    commands = parser.add_subparsers(dest="command", required=True)

    admit = commands.add_parser("admit", help="admit exact-byte signed evidence")
    admit.add_argument("--evidence-id", required=True)
    admit.add_argument("--key-id", required=True)
    admit.add_argument("--payload-file", required=True)
    admit.add_argument("--signature-file", required=True)
    admit.add_argument("--actor", required=True)
    admit.add_argument("--occurred-at")

    get = commands.add_parser("get", help="read one admitted evidence record")
    get.add_argument("--evidence-id", required=True)

    verify = commands.add_parser("verify", help="verify one evidence record")
    verify.add_argument("--evidence-id", required=True)
    verify.add_argument("--as-of")

    snapshot = commands.add_parser("snapshot", help="read the four category statuses")
    snapshot.add_argument("--as-of")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    runtime: StarcomProgram | None = None
    try:
        args = parser.parse_args(argv)
        args.db = _database_path(args.db)
        runtime = StarcomProgram.open(args.db)
        service = runtime.external_evidence
        if args.command == "admit":
            record = service.admit_evidence(
                args.evidence_id,
                args.key_id,
                _read_file_bytes(args.payload_file, "payload_file"),
                _read_file_bytes(args.signature_file, "signature_file"),
                actor=args.actor,
                occurred_at=args.occurred_at,
            )
            _emit_success(_record_payload(record))
            return 0
        if args.command == "get":
            _emit_success(_record_payload(service.get_evidence(args.evidence_id)))
            return 0
        if args.command == "verify":
            verification = service.verify_evidence(args.evidence_id, as_of=args.as_of)
            payload = asdict(verification)
            payload["ok"] = verification.ok
            _emit_success(payload)
            return 0 if verification.ok else 3
        _emit_success(service.snapshot(as_of=args.as_of))
        return 0
    except StarcomError as exc:
        _emit_error(exc)
        return 2
    except Exception as exc:
        if os.environ.get("STARCOM_DEBUG") == "1":
            raise
        _emit_error(
            StarcomError(
                "INTERNAL_ERROR",
                "unexpected internal failure",
                {"type": type(exc).__name__},
            )
        )
        return 1
    finally:
        if runtime is not None:
            runtime.close()


if __name__ == "__main__":
    raise SystemExit(main())
