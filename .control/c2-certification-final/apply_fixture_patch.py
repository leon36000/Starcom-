from __future__ import annotations

from pathlib import Path


PATH = Path("tests/test_certification.py")


def main() -> int:
    source = PATH.read_text(encoding="utf-8")
    old = '''    def test_below_target_is_rejected(self) -> None:\n        payload = self.certification_payload(certificate_id="certificate-below-target")\n'''
    new = '''    def test_below_target_is_rejected(self) -> None:\n        self.add_identity(0)\n        payload = self.certification_payload(certificate_id="certificate-below-target")\n'''
    count = source.count(old)
    if count != 1:
        raise SystemExit(
            "bounded certification fixture patch refused: "
            f"expected one target, found {count}"
        )
    PATH.write_text(source.replace(old, new, 1), encoding="utf-8")
    print("below-target certification fixture now contains one clean evidence-bound identity")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
