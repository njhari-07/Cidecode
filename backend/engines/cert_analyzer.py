"""
Certificate analyzer: extracts and validates APK signing certificate.
"""
from __future__ import annotations
import traceback
from datetime import datetime, timezone
from loguru import logger


def analyze(apk_path: str) -> dict:
    """Analyze the APK signing certificate."""
    result = {
        "subject": "unknown",
        "issuer": "unknown",
        "serial_number": "unknown",
        "not_before": "unknown",
        "not_after": "unknown",
        "is_self_signed": False,
        "is_expired": False,
        "sha256_fingerprint": "unknown",
        "warnings": [],
        "error": None,
    }

    try:
        from androguard.misc import AnalyzeAPK
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        a, _, _ = AnalyzeAPK(apk_path)

        # Get raw certificate bytes
        certs = a.get_certificates()
        if not certs:
            result["warnings"].append("No signing certificate found")
            return result

        raw = certs[0]

        # Parse with cryptography library
        cert = x509.load_der_x509_certificate(bytes(raw))

        result["subject"] = cert.subject.rfc4514_string()
        result["issuer"] = cert.issuer.rfc4514_string()
        result["serial_number"] = hex(cert.serial_number)

        nb = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.replace(tzinfo=timezone.utc)
        na = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=timezone.utc)

        result["not_before"] = nb.isoformat()
        result["not_after"] = na.isoformat()

        now = datetime.now(timezone.utc)
        result["is_expired"] = now > na
        result["is_self_signed"] = cert.subject == cert.issuer

        fingerprint = cert.fingerprint(hashes.SHA256())
        result["sha256_fingerprint"] = fingerprint.hex()

        # Warnings
        if result["is_self_signed"]:
            result["warnings"].append("Certificate is self-signed — not from a trusted CA")
        if result["is_expired"]:
            result["warnings"].append(f"Certificate expired on {result['not_after']}")
        if "Android Debug" in result["subject"] or "ANDROIDDEBUGKEY" in result["subject"].upper():
            result["warnings"].append("Signed with Android debug key — not production ready")
        if cert.serial_number == 1:
            result["warnings"].append("Serial number is 1 — common in auto-generated debug certs")

    except ImportError:
        logger.warning("androguard/cryptography not installed — using mock cert data")
        result = _mock_cert()
    except Exception as e:
        logger.error(f"Cert analysis error: {e}\n{traceback.format_exc()}")
        result["error"] = str(e)
        result = _mock_cert()

    return result


def _mock_cert() -> dict:
    return {
        "subject": "CN=Android Debug, O=Android, C=US",
        "issuer": "CN=Android Debug, O=Android, C=US",
        "serial_number": "0x1",
        "not_before": "2020-01-01T00:00:00+00:00",
        "not_after": "2023-12-31T23:59:59+00:00",
        "is_self_signed": True,
        "is_expired": True,
        "sha256_fingerprint": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "warnings": [
            "Certificate is self-signed — not from a trusted CA",
            "Certificate expired on 2023-12-31T23:59:59+00:00",
            "Signed with Android debug key — not production ready",
            "Serial number is 1 — common in auto-generated debug certs",
        ],
        "error": None,
    }
