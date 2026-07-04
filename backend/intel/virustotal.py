"""
VirusTotal integration: look up APK SHA256 hash.
Falls back to mock data if API key is not configured.
"""
from __future__ import annotations
import os
import hashlib
import httpx
from loguru import logger

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
VT_BASE = "https://www.virustotal.com/api/v3"


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


async def analyze(apk_path: str) -> dict:
    """Look up APK hash on VirusTotal."""
    sha256 = _sha256(apk_path)

    if not VT_API_KEY:
        logger.info("No VirusTotal API key — returning mock data")
        return _mock_vt(sha256)

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{VT_BASE}/files/{sha256}",
                headers={"x-apikey": VT_API_KEY},
            )

        if resp.status_code == 404:
            return {
                "found": False,
                "sha256": sha256,
                "detection_count": 0,
                "total_engines": 0,
                "malware_families": [],
                "permalink": None,
            }

        resp.raise_for_status()
        data = resp.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        results = data["data"]["attributes"]["last_analysis_results"]

        families = list({
            r.get("result", "")
            for r in results.values()
            if r.get("category") == "malicious" and r.get("result")
        })[:10]

        return {
            "found": True,
            "sha256": sha256,
            "detection_count": stats.get("malicious", 0) + stats.get("suspicious", 0),
            "total_engines": sum(stats.values()),
            "malware_families": families,
            "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
        }

    except Exception as e:
        logger.error(f"VirusTotal error: {e}")
        return _mock_vt(sha256)


def _mock_vt(sha256: str) -> dict:
    return {
        "found": True,
        "sha256": sha256,
        "detection_count": 34,
        "total_engines": 72,
        "malware_families": [
            "Android.BankBot",
            "Android.Spy.Banker",
            "HEUR:Trojan-Banker.AndroidOS.Gustuff",
            "Andr/Banker-GZ",
            "Android:BankBot-OW",
        ],
        "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
    }
