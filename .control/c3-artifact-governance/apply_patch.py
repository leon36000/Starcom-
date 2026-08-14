from __future__ import annotations

from pathlib import Path


PATH = Path("src/starcom/qualification_gate.py")


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
        '''        artifacts = self.database.connection.execute(
            """
            SELECT artifact_id, recorded_at FROM qualification_artifacts
            WHERE qualification_run_id = ? ORDER BY artifact_id
            """,
            (binding.qualification_run_id,),
        ).fetchall()
        try:
''',
        '''        artifacts = self.database.connection.execute(
            """
            SELECT artifact_id, kind, recorded_at FROM qualification_artifacts
            WHERE qualification_run_id = ? ORDER BY artifact_id
            """,
            (binding.qualification_run_id,),
        ).fetchall()
        for artifact in artifacts:
            artifact_id = str(artifact["artifact_id"])
            artifact_kind = str(artifact["kind"])
            if artifact_kind == "DECISION":
                defects.append(
                    f"C3_UNGOVERNED_DECISION_ARTIFACT:{artifact_id}"
                )
            elif artifact_kind == "ADOPTION":
                defects.append(
                    f"C3_UNAUTHORIZED_ADOPTION_ARTIFACT:{artifact_id}"
                )
        try:
''',
        "C3 qualification artifact governance",
    )
    PATH.write_text(source, encoding="utf-8")
    print("patched C3 verifier with fail-closed decision/adoption governance")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
