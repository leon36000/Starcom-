from __future__ import annotations

from pathlib import Path


PATH = Path("src/starcom/cli.py")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(
            f"bounded patch refused for {label}: expected one target, found {count}"
        )
    return source.replace(old, new, 1)


def main() -> int:
    source = PATH.read_text(encoding="utf-8")

    source = replace_once(
        source,
        '''from .qualification import QualificationArtifactKind, QualificationLab\nfrom .qualification_gate import C3QualificationGate\n''',
        '''from .qualification import QualificationArtifactKind, QualificationLab\nfrom .qualification_decision import C3DecisionService\nfrom .qualification_gate import C3QualificationGate\n''',
        "C3 decision service import",
    )

    source = replace_once(
        source,
        '''    qualification: QualificationLab\n    c3: C3QualificationGate\n\n    @classmethod\n''',
        '''    qualification: QualificationLab\n    c3: C3QualificationGate\n    c3_decision: C3DecisionService\n\n    @classmethod\n''',
        "runtime decision field",
    )

    source = replace_once(
        source,
        '''            c3 = C3QualificationGate(\n                database,\n                ledger,\n                certification,\n                qualification,\n            )\n            return cls(\n''',
        '''            c3 = C3QualificationGate(\n                database,\n                ledger,\n                certification,\n                qualification,\n            )\n            c3_decision = C3DecisionService(\n                database,\n                ledger,\n                continuity,\n                certification,\n                c3,\n                qualification,\n            )\n            return cls(\n''',
        "runtime decision construction",
    )

    source = replace_once(
        source,
        '''                certification,\n                qualification,\n                c3,\n            )\n''',
        '''                certification,\n                qualification,\n                c3,\n                c3_decision,\n            )\n''',
        "runtime decision return",
    )

    source = replace_once(
        source,
        '''def _c3_verify(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    verification = runtime.c3.verify(args.c3_run_id)\n    return _verification_payload(verification), 0 if verification.ok else 3\n\n\ndef _trust_add_rule(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n''',
        '''def _c3_verify(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    verification = runtime.c3.verify(args.c3_run_id)\n    return _verification_payload(verification), 0 if verification.ok else 3\n\n\ndef _c3_decision_snapshot(\n    runtime: Runtime, args: argparse.Namespace\n) -> tuple[Any, int]:\n    snapshot = runtime.c3_decision.snapshot(args.c3_run_id)\n    return {\n        "c3_run_id": snapshot.c3_run_id,\n        "qualification_run_id": snapshot.qualification_run_id,\n        "certificate_id": snapshot.certificate_id,\n        "qualification_head_hash": snapshot.qualification_head_hash,\n        "candidate_count": snapshot.candidate_count,\n        "evaluation_count": snapshot.evaluation_count,\n        "candidate_set_digest": snapshot.candidate_set_digest,\n        "evaluation_set_digest": snapshot.evaluation_set_digest,\n        "latest_evidence_at": snapshot.latest_evidence_at,\n        "candidate_artifact_ids": [\n            str(member["artifact_id"]) for member in snapshot.candidates\n        ],\n        "evaluation_artifact_ids": [\n            str(member["artifact_id"]) for member in snapshot.evaluations\n        ],\n    }, 0\n\n\ndef _c3_decision_admit(\n    runtime: Runtime, args: argparse.Namespace\n) -> tuple[Any, int]:\n    payload = _read_file_bytes(args.payload_file, "payload_file")\n    signature = _read_file_bytes(args.signature_file, "signature_file")\n    return runtime.c3_decision.admit_decision(\n        args.c3_run_id,\n        args.key_id,\n        payload,\n        signature,\n        actor=args.actor,\n        occurred_at=args.occurred_at,\n    ), 0\n\n\ndef _c3_decision_get(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    return runtime.c3_decision.get_decision(args.decision_id), 0\n\n\ndef _c3_decision_verify(\n    runtime: Runtime, args: argparse.Namespace\n) -> tuple[Any, int]:\n    verification = runtime.c3_decision.verify_decision(args.decision_id)\n    return _verification_payload(verification), 0 if verification.ok else 3\n\n\ndef _trust_add_rule(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n''',
        "C3 decision CLI handlers",
    )

    source = replace_once(
        source,
        '''    c3_verify = c3_commands.add_parser("verify")\n    c3_verify.add_argument("--c3-run-id", required=True)\n    _set_handler(c3_verify, _c3_verify)\n\n    trust = top.add_parser("trust", help="manage default-deny policy and decisions")\n''',
        '''    c3_verify = c3_commands.add_parser("verify")\n    c3_verify.add_argument("--c3-run-id", required=True)\n    _set_handler(c3_verify, _c3_verify)\n\n    c3_decision = top.add_parser(\n        "c3-decision",\n        help="manage exact-byte independently signed C3 qualification decisions",\n    )\n    c3_decision_commands = c3_decision.add_subparsers(\n        dest="c3_decision_command", required=True\n    )\n\n    c3_decision_snapshot = c3_decision_commands.add_parser("snapshot")\n    c3_decision_snapshot.add_argument("--c3-run-id", required=True)\n    _set_handler(c3_decision_snapshot, _c3_decision_snapshot)\n\n    c3_decision_admit = c3_decision_commands.add_parser("admit")\n    c3_decision_admit.add_argument("--c3-run-id", required=True)\n    c3_decision_admit.add_argument("--key-id", required=True)\n    c3_decision_admit.add_argument("--payload-file", required=True)\n    c3_decision_admit.add_argument("--signature-file", required=True)\n    c3_decision_admit.add_argument("--actor", required=True)\n    _add_occurred_at(c3_decision_admit)\n    _set_handler(c3_decision_admit, _c3_decision_admit)\n\n    c3_decision_get = c3_decision_commands.add_parser("get")\n    c3_decision_get.add_argument("--decision-id", required=True)\n    _set_handler(c3_decision_get, _c3_decision_get)\n\n    c3_decision_verify = c3_decision_commands.add_parser("verify")\n    c3_decision_verify.add_argument("--decision-id", required=True)\n    _set_handler(c3_decision_verify, _c3_decision_verify)\n\n    trust = top.add_parser("trust", help="manage default-deny policy and decisions")\n''',
        "C3 decision CLI parser",
    )

    PATH.write_text(source, encoding="utf-8")
    print("patched src/starcom/cli.py with thin exact-byte C3 decision CLI")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
