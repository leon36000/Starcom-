from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile


MAX_PUBLIC_KEY_BYTES = 8 * 1024
MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
MAX_SIGNATURE_BYTES = 1024


class OpenSSLEd25519Verifier:
    """Verify exact bytes with Ed25519 through a bounded OpenSSL process."""

    def __init__(self, executable: str = "openssl", timeout_seconds: float = 5.0) -> None:
        self.executable = executable
        self.timeout_seconds = timeout_seconds

    def _run(self, arguments: list[str]) -> subprocess.CompletedProcess[bytes] | None:
        try:
            return subprocess.run(
                [self.executable, *arguments],
                check=False,
                capture_output=True,
                timeout=self.timeout_seconds,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            return None

    @staticmethod
    def _bounded(value: bytes, maximum: int) -> bool:
        return isinstance(value, bytes) and 0 < len(value) <= maximum

    def validate_public_key(self, public_key_pem: bytes) -> bool:
        if not self._bounded(public_key_pem, MAX_PUBLIC_KEY_BYTES):
            return False
        with tempfile.TemporaryDirectory(prefix="starcom-ed25519-") as directory:
            key_path = Path(directory) / "reviewer-public.pem"
            key_path.write_bytes(public_key_pem)
            result = self._run(
                ["pkey", "-pubin", "-in", str(key_path), "-text_pub", "-noout"]
            )
            return bool(
                result is not None
                and result.returncode == 0
                and b"ED25519" in result.stdout.upper()
            )

    def verify(self, public_key_pem: bytes, payload: bytes, signature: bytes) -> bool:
        if not self.validate_public_key(public_key_pem):
            return False
        if not self._bounded(payload, MAX_PAYLOAD_BYTES):
            return False
        if not self._bounded(signature, MAX_SIGNATURE_BYTES):
            return False
        with tempfile.TemporaryDirectory(prefix="starcom-ed25519-") as directory:
            root = Path(directory)
            key_path = root / "reviewer-public.pem"
            payload_path = root / "disposition.json"
            signature_path = root / "disposition.sig"
            key_path.write_bytes(public_key_pem)
            payload_path.write_bytes(payload)
            signature_path.write_bytes(signature)
            result = self._run(
                [
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(key_path),
                    "-rawin",
                    "-in",
                    str(payload_path),
                    "-sigfile",
                    str(signature_path),
                ]
            )
            return bool(result is not None and result.returncode == 0)
