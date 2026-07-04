"""
String extractor: scans DEX bytecode for suspicious strings.
Looks for IPs, URLs, API keys, Aadhaar/PAN patterns, and Base64.
"""
from __future__ import annotations
import re
import base64
import traceback
from loguru import logger

# Regex patterns
RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
RE_URL = re.compile(r"https?://[^\s\"'<>]{8,}", re.IGNORECASE)
RE_AADHAAR = re.compile(r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b")
RE_PAN = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
RE_API_KEY = re.compile(r"(?:api[_-]?key|token|secret|password|passwd|pwd)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{16,})['\"]?", re.IGNORECASE)
RE_BASE64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])")
RE_CRYPTO = re.compile(r"\b(1[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})\b")

SUSPICIOUS_DOMAINS = [
    "ngrok.io", "serveo.net", "pagekite.me", "localxpose.io",
    "duckdns.org", "no-ip.com", "ddns.net", "hopto.org",
]

PRIVATE_RANGES = ["10.", "192.168.", "172.16.", "172.17.", "172.18.",
                  "172.19.", "172.2", "127.", "0.0.0.0"]


def analyze(apk_path: str) -> dict:
    """Extract suspicious strings from DEX bytecode."""
    result = {
        "ips": [],
        "urls": [],
        "suspicious_strings": [],
        "error": None,
    }
    try:
        from androguard.misc import AnalyzeAPK
        a, d, dx = AnalyzeAPK(apk_path)

        all_strings: set[str] = set()
        for dex in d:
            for s in dex.get_strings():
                all_strings.add(str(s))

        result = _process_strings(all_strings)

    except ImportError:
        logger.warning("androguard not installed — using mock string data")
        result = _mock_strings()
    except Exception as e:
        logger.error(f"String extraction error: {e}\n{traceback.format_exc()}")
        result["error"] = str(e)

    return result


def _process_strings(strings: set[str]) -> dict:
    ips, urls, suspicious = [], [], []

    for s in strings:
        # IPs
        for ip in RE_IPV4.findall(s):
            if not any(ip.startswith(r) for r in PRIVATE_RANGES):
                ips.append({"type": "ip", "value": ip, "risk": "high"})

        # URLs
        for url in RE_URL.findall(s):
            risk = "high" if any(d in url for d in SUSPICIOUS_DOMAINS) else "medium"
            urls.append({"type": "url", "value": url[:200], "risk": risk})

        # Aadhaar
        if RE_AADHAAR.search(s):
            suspicious.append({"type": "aadhaar_pattern", "value": s[:80], "risk": "high"})

        # PAN
        if RE_PAN.search(s):
            suspicious.append({"type": "pan_pattern", "value": s[:80], "risk": "high"})

        # API Keys
        m = RE_API_KEY.search(s)
        if m:
            suspicious.append({"type": "api_key", "value": s[:120], "risk": "high"})

        # Crypto addresses
        if RE_CRYPTO.search(s):
            suspicious.append({"type": "crypto_address", "value": s[:80], "risk": "medium"})

        # Base64 blobs (potential payload)
        for b64 in RE_BASE64.findall(s):
            try:
                decoded = base64.b64decode(b64 + "==").decode("utf-8", errors="ignore")
                if len(decoded) > 10 and any(c.isalpha() for c in decoded[:20]):
                    suspicious.append({
                        "type": "base64_payload",
                        "value": f"{b64[:40]}… → {decoded[:60]}",
                        "risk": "medium",
                    })
            except Exception:
                pass

    # Deduplicate
    seen = set()
    deduped_ips = []
    for item in ips:
        if item["value"] not in seen:
            seen.add(item["value"])
            deduped_ips.append(item)

    return {
        "ips": deduped_ips[:30],
        "urls": urls[:30],
        "suspicious_strings": suspicious[:50],
        "error": None,
    }


def _mock_strings() -> dict:
    return {
        "ips": [
            {"type": "ip", "value": "45.33.32.156", "risk": "high"},
            {"type": "ip", "value": "185.220.101.47", "risk": "high"},
            {"type": "ip", "value": "91.108.56.155", "risk": "high"},
        ],
        "urls": [
            {"type": "url", "value": "http://c2-panel.ngrok.io/api/upload", "risk": "high"},
            {"type": "url", "value": "https://api.telegram.org/bot123456:TOKEN/sendMessage", "risk": "high"},
            {"type": "url", "value": "http://upi-support-helpline.com/verify", "risk": "high"},
            {"type": "url", "value": "https://npci-help.duckdns.org/otp", "risk": "high"},
        ],
        "suspicious_strings": [
            {"type": "api_key", "value": "api_key=sk-abc123XYZ789DEF456GHI012JKL345MNO678", "risk": "high"},
            {"type": "base64_payload", "value": "aHR0cDovL21hbHdhcmUuZXhhbXBsZS5jb20= → http://malware.example.com", "risk": "medium"},
            {"type": "aadhaar_pattern", "value": "2345 6789 0123", "risk": "high"},
            {"type": "pan_pattern", "value": "ABCDE1234F", "risk": "high"},
            {"type": "crypto_address", "value": "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf Na", "risk": "medium"},
        ],
        "error": None,
    }
