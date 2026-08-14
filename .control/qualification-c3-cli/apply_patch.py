from __future__ import annotations

from pathlib import Path


PATH = Path("src/starcom/cli.py")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(
            f"bounded qualification CLI patch refused for {label}: "
            f"expected one target, found {count}"
        )
    return source.replace(old, new, 1)


def main() -> int:
    source = PATH.read_text(encoding="utf-8")

    source = replace_once(
        source,
        '''from .proof import ProofEngine, VerificationVerdict\nfrom .recollection import C2RecollectionService\n''',
        '''from .proof import ProofEngine, VerificationVerdict\nfrom .qualification import QualificationArtifactKind, QualificationLab\nfrom .qualification_gate import C3QualificationGate\nfrom .recollection import C2RecollectionService\n''',
        "qualification imports",
    )

    source = replace_once(
        source,
        '''    census: C2CensusService\n    certification: C2CertificationService\n''',
        '''    census: C2CensusService\n    certification: C2CertificationService\n    qualification: QualificationLab\n    c3: C3QualificationGate\n''',
        "runtime fields",
    )

    source = replace_once(
        source,
        '''            certification = C2CertificationService(\n                database,\n                ledger,\n                continuity,\n                recollection,\n                census,\n            )\n            return cls(\n                database,\n                ledger,\n                trust,\n                proof,\n                missions,\n                research,\n                continuity,\n                recollection,\n                census,\n                certification,\n            )\n''',
        '''            certification = C2CertificationService(\n                database,\n                ledger,\n                continuity,\n                recollection,\n                census,\n            )\n            qualification = QualificationLab(database, ledger)\n            c3 = C3QualificationGate(\n                database,\n                ledger,\n                certification,\n                qualification,\n            )\n            return cls(\n                database,\n                ledger,\n                trust,\n                proof,\n                missions,\n                research,\n                continuity,\n                recollection,\n                census,\n                certification,\n                qualification,\n                c3,\n            )\n''',
        "runtime initialization",
    )

    source = replace_once(
        source,
        '''def _certification_verify(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    verification = runtime.certification.verify_certificate(args.certificate_id)\n    return _verification_payload(verification), 0 if verification.ok else 3\n\n\ndef _trust_add_rule(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n''',
        '''def _certification_verify(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    verification = runtime.certification.verify_certificate(args.certificate_id)\n    return _verification_payload(verification), 0 if verification.ok else 3\n\n\ndef _qualification_create_run(\n    runtime: Runtime, args: argparse.Namespace\n) -> tuple[Any, int]:\n    return runtime.qualification.create_run(\n        args.qualification_run_id,\n        name=args.name,\n        actor=args.actor,\n        occurred_at=args.occurred_at,\n    ), 0\n\n\ndef _qualification_get_run(\n    runtime: Runtime, args: argparse.Namespace\n) -> tuple[Any, int]:\n    return runtime.qualification.get_run(args.qualification_run_id), 0\n\n\ndef _qualification_record_artifact(\n    runtime: Runtime, args: argparse.Namespace\n) -> tuple[Any, int]:\n    return runtime.qualification.record_artifact(\n        args.qualification_run_id,\n        artifact_id=args.artifact_id,\n        kind=QualificationArtifactKind(args.kind),\n        material=_json_object(args.material_json, "material_json"),\n        actor=args.actor,\n        occurred_at=args.occurred_at,\n    ), 0\n\n\ndef _qualification_get_artifact(\n    runtime: Runtime, args: argparse.Namespace\n) -> tuple[Any, int]:\n    return runtime.qualification.get_artifact(args.artifact_id), 0\n\n\ndef _qualification_verify(\n    runtime: Runtime, args: argparse.Namespace\n) -> tuple[Any, int]:\n    verification = runtime.qualification.verify(args.qualification_run_id)\n    return _verification_payload(verification), 0 if verification.ok else 3\n\n\ndef _c3_start(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    return runtime.c3.start(\n        args.c3_run_id,\n        qualification_run_id=args.qualification_run_id,\n        certificate_id=args.certificate_id,\n        actor=args.actor,\n        occurred_at=args.occurred_at,\n    ), 0\n\n\ndef _c3_get(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    return runtime.c3.get(args.c3_run_id), 0\n\n\ndef _c3_verify(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n    verification = runtime.c3.verify(args.c3_run_id)\n    return _verification_payload(verification), 0 if verification.ok else 3\n\n\ndef _trust_add_rule(runtime: Runtime, args: argparse.Namespace) -> tuple[Any, int]:\n''',
        "qualification and C3 handlers",
    )

    source = replace_once(
        source,
        '''    certification_verify = certification_commands.add_parser("verify")\n    certification_verify.add_argument("--certificate-id", required=True)\n    _set_handler(certification_verify, _certification_verify)\n\n    trust = top.add_parser("trust", help="manage default-deny policy and decisions")\n''',
        '''    certification_verify = certification_commands.add_parser("verify")\n    certification_verify.add_argument("--certificate-id", required=True)\n    _set_handler(certification_verify, _certification_verify)\n\n    qualification = top.add_parser(\n        "qualification",\n        help="manage generic append-only component qualification evidence",\n    )\n    qualification_commands = qualification.add_subparsers(\n        dest="qualification_command", required=True\n    )\n\n    qualification_create_run = qualification_commands.add_parser("create-run")\n    qualification_create_run.add_argument("--qualification-run-id", required=True)\n    qualification_create_run.add_argument("--name", required=True)\n    qualification_create_run.add_argument("--actor", required=True)\n    _add_occurred_at(qualification_create_run)\n    _set_handler(qualification_create_run, _qualification_create_run)\n\n    qualification_get_run = qualification_commands.add_parser("get-run")\n    qualification_get_run.add_argument("--qualification-run-id", required=True)\n    _set_handler(qualification_get_run, _qualification_get_run)\n\n    qualification_record_artifact = qualification_commands.add_parser(\n        "record-artifact"\n    )\n    qualification_record_artifact.add_argument(\n        "--qualification-run-id", required=True\n    )\n    qualification_record_artifact.add_argument("--artifact-id", required=True)\n    qualification_record_artifact.add_argument(\n        "--kind",\n        required=True,\n        choices=[item.value for item in QualificationArtifactKind],\n    )\n    qualification_record_artifact.add_argument("--material-json", required=True)\n    qualification_record_artifact.add_argument("--actor", required=True)\n    _add_occurred_at(qualification_record_artifact)\n    _set_handler(qualification_record_artifact, _qualification_record_artifact)\n\n    qualification_get_artifact = qualification_commands.add_parser("get-artifact")\n    qualification_get_artifact.add_argument("--artifact-id", required=True)\n    _set_handler(qualification_get_artifact, _qualification_get_artifact)\n\n    qualification_verify = qualification_commands.add_parser("verify")\n    qualification_verify.add_argument("--qualification-run-id", required=True)\n    _set_handler(qualification_verify, _qualification_verify)\n\n    c3 = top.add_parser(\n        "c3",\n        help="manage the exact-C2-certificate-gated C3 qualification binding",\n    )\n    c3_commands = c3.add_subparsers(dest="c3_command", required=True)\n\n    c3_start = c3_commands.add_parser("start")\n    c3_start.add_argument("--c3-run-id", required=True)\n    c3_start.add_argument("--qualification-run-id", required=True)\n    c3_start.add_argument("--certificate-id", required=True)\n    c3_start.add_argument("--actor", required=True)\n    _add_occurred_at(c3_start)\n    _set_handler(c3_start, _c3_start)\n\n    c3_get = c3_commands.add_parser("get")\n    c3_get.add_argument("--c3-run-id", required=True)\n    _set_handler(c3_get, _c3_get)\n\n    c3_verify = c3_commands.add_parser("verify")\n    c3_verify.add_argument("--c3-run-id", required=True)\n    _set_handler(c3_verify, _c3_verify)\n\n    trust = top.add_parser("trust", help="manage default-deny policy and decisions")\n''',
        "qualification and C3 parsers",
    )

    PATH.write_text(source, encoding="utf-8")
    print("patched src/starcom/cli.py with thin qualification and C3 commands")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
