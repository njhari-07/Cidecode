"""
AbuseIPDB integration: check extracted IPs for abuse reports.
Falls back to mock data if API key not configured.
"""
from __future__ import annotations
import os
import httpx
from loguru import logger

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"


async def analyze(ips: list[str]) -> dict:
    """Check IPs against AbuseIPDB."""
    if not ips:
        return {"checked_ips": [], "max_confidence": 0, "flagged_ips": []}

    if not ABUSEIPDB_API_KEY:
        logger.info("No AbuseIPDB API key — returning mock data")
        return _mock_abuseipdb(ips)

    flagged = []
    max_confidence = 0

    async with httpx.AsyncClient(timeout=20) as client:
        for ip in ips[:10]:  # Limit API calls
            try:
                resp = await client.get(
                    f"{ABUSEIPDB_BASE}/check",
                    headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": False},
                )
                resp.raise_for_status()
                data = resp.json().get("data", {})
                confidence = data.get("abuseConfidenceScore", 0)
                if confidence > 20:
                    flagged.append({
                        "ip": ip,
                        "confidence": confidence,
                        "total_reports": data.get("totalReports", 0),
                        "country": data.get("countryCode", "??"),
                        "isp": data.get("isp", "Unknown"),
                        "usage_type": data.get("usageType", "Unknown"),
                    })
                    max_confidence = max(max_confidence, confidence)
            except Exception as e:
                logger.error(f"AbuseIPDB error for {ip}: {e}")

    return {
        "checked_ips": ips[:10],
        "max_confidence": max_confidence,
        "flagged_ips": flagged,
    }


def _mock_abuseipdb(ips: list[str]) -> dict:
    mock_flagged = []
    for ip in ips[:3]:
        mock_flagged.append({
            "ip": ip,
            "confidence": 98,
            "total_reports": 312,
            "country": "RU",
            "isp": "Frantech Solutions",
            "usage_type": "Data Center/Web Hosting/Transit",
        })
    return {
        "checked_ips": ips,
        "max_confidence": 98,
        "flagged_ips": mock_flagged,
    }
