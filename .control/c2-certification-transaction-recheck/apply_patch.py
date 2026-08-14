from __future__ import annotations

import argparse
from pathlib import Path


TEST_PATH = Path("tests/test_certification.py")
SERVICE_PATH = Path("src/starcom/certification.py")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise SystemExit(
            f"bounded certification transaction patch refused for {label}: "
            f"expected one target, found {count}"
        )
    return source.replace(old, new, 1)


def patch_tests() -> None:
    source = TEST_PATH.read_text(encoding="utf-8")
    tests = '''    def test_census_is_rechecked_inside_admission_transaction(self) -> None:\n        self.add_identities(800)\n        payload = self.certification_payload(\n            certificate_id="certificate-census-race"\n        )\n        signature = self.sign(CERTIFIER_KEY, payload)\n\n        class CensusTamperingService(C2CertificationService):\n            def _assert_independent(self, certifier_identity, snapshot):  # type: ignore[no-untyped-def]\n                super()._assert_independent(certifier_identity, snapshot)\n                self.database.connection.execute(\n                    "DROP TRIGGER research_observations_no_update"\n                )\n                self.database.connection.execute(\n                    """\n                    UPDATE research_observations\n                    SET content_digest = ?\n                    WHERE observation_id = ?\n                    """,\n                    ("0" * 64, "observation-0000"),\n                )\n\n        racing = CensusTamperingService(\n            self.db,\n            self.ledger,\n            self.continuity,\n            self.recollection,\n            self.census,\n        )\n\n        with self.assertRaisesRegex(\n            IntegrityError,\n            "C2 census verification failed",\n        ):\n            racing.admit_certification(\n                "c2-run",\n                "certifier-c2",\n                payload,\n                signature,\n                actor="admission-agent",\n                occurred_at=C10,\n            )\n        count = self.db.connection.execute(\n            "SELECT COUNT(*) FROM c2_certifications"\n        ).fetchone()[0]\n        self.assertEqual(count, 0)\n\n    def test_trust_root_is_rechecked_inside_admission_transaction(self) -> None:\n        self.add_identities(800)\n        payload = self.certification_payload(\n            certificate_id="certificate-trust-root-race"\n        )\n        signature = self.sign(CERTIFIER_KEY, payload)\n\n        class TrustRootTamperingService(C2CertificationService):\n            def _assert_independent(self, certifier_identity, snapshot):  # type: ignore[no-untyped-def]\n                super()._assert_independent(certifier_identity, snapshot)\n                self.database.connection.execute(\n                    "DROP TRIGGER continuity_trust_roots_no_update"\n                )\n                self.database.connection.execute(\n                    """\n                    UPDATE continuity_trust_roots\n                    SET fingerprint_sha256 = ?\n                    WHERE key_id = ?\n                    """,\n                    ("0" * 64, "certifier-c2"),\n                )\n\n        racing = TrustRootTamperingService(\n            self.db,\n            self.ledger,\n            self.continuity,\n            self.recollection,\n            self.census,\n        )\n\n        with self.assertRaisesRegex(\n            IntegrityError,\n            "certifier trust root verification failed",\n        ):\n            racing.admit_certification(\n                "c2-run",\n                "certifier-c2",\n                payload,\n                signature,\n                actor="admission-agent",\n                occurred_at=C10,\n            )\n        count = self.db.connection.execute(\n            "SELECT COUNT(*) FROM c2_certifications"\n        ).fetchone()[0]\n        self.assertEqual(count, 0)\n\n\n'''
    source = replace_once(
        source,
        '''\n\nif __name__ == "__main__":\n    unittest.main()\n''',
        '''\n\n''' + tests + '''if __name__ == "__main__":\n    unittest.main()\n''',
        "transaction race tests",
    )
    TEST_PATH.write_text(source, encoding="utf-8")
    print("added census and trust-root TOCTOU admission attacks")


def patch_production() -> None:
    source = SERVICE_PATH.read_text(encoding="utf-8")
    source = replace_once(
        source,
        '''                current_snapshot = self._snapshot_from_connection(\n                    connection,\n                    recollection_id,\n                )\n''',
        '''                current_public_key = self._assert_trust_root(key_id)\n                if not self.continuity.signature_verifier.verify(\n                    current_public_key,\n                    payload,\n                    signature,\n                ):\n                    raise IntegrityError("C2 certification signature is invalid")\n                current_census_verification = self.census.verify(recollection_id)\n                if not current_census_verification.ok:\n                    raise IntegrityError(\n                        "C2 census verification failed",\n                        {\n                            "recollection_id": recollection_id,\n                            "defects": list(current_census_verification.defects),\n                        },\n                    )\n                current_snapshot = self._snapshot_from_connection(\n                    connection,\n                    recollection_id,\n                )\n''',
        "transaction-locked sovereign rechecks",
    )
    SERVICE_PATH.write_text(source, encoding="utf-8")
    print("certification admission now rechecks trust root, signature and census under BEGIN IMMEDIATE")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("tests", "production"))
    args = parser.parse_args()
    if args.mode == "tests":
        patch_tests()
    else:
        patch_production()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
