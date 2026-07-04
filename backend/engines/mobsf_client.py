"""
MobSF Static Analysis API Client
=================================
Integrates with MobSF's REST API for its static analysis features.
MobSF runs as a separate Docker container (see docker-compose.yml).

Only static analysis is used — dynamic analysis requires KVM/Android emulator
which is not available on Windows.

Environment variables:
  MOBSF_URL     = http://localhost:8008  (MobSF container URL)
  MOBSF_API_KEY = (from MobSF Settings page — auto-generated on first run)

Gracefully returns {"available": False} if MobSF is not running.
"""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
from typing import Optional

import httpx
from loguru import logger

MOBSF_URL     = os.getenv("MOBSF_URL", "http://localhost:8008")
MOBSF_API_KEY = os.getenv("MOBSF_API_KEY", "")
MOBSF_TIMEOUT = int(os.getenv("MOBSF_TIMEOUT", "180"))   # 3 min


# ── Availability check ─────────────────────────────────────────────────────────

async def _mobsf_available() -> bool:
    """Ping MobSF health endpoint."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(f"{MOBSF_URL}/api/v1/")
            return r.status_code < 500
    except Exception:
        return False


# ── Upload APK to MobSF ────────────────────────────────────────────────────────

async def _upload(apk_path: str) -> Optional[dict]:
    """Upload APK to MobSF and return {hash, file_name, scan_type, status}."""
    apk_abs = Path(apk_path)
    if not apk_abs.exists():
        return None

    headers = {"Authorization": MOBSF_API_KEY}

    try:
        async with httpx.AsyncClient(timeout=MOBSF_TIMEOUT) as client:
            with open(apk_abs, "rb") as f:
                r = await client.post(
                    f"{MOBSF_URL}/api/v1/upload",
                    headers=headers,
                    files={"file": (apk_abs.name, f, "application/octet-stream")},
                )
            r.raise_for_status()
            return r.json()
    except Exception as e:
        logger.warning(f"MobSF upload failed: {e}")
        return None


# ── Trigger scan ───────────────────────────────────────────────────────────────

async def _scan(file_hash: str, file_name: str, scan_type: str = "apk") -> bool:
    """Trigger MobSF static analysis scan."""
    headers = {"Authorization": MOBSF_API_KEY}
    try:
        async with httpx.AsyncClient(timeout=MOBSF_TIMEOUT) as client:
            r = await client.post(
                f"{MOBSF_URL}/api/v1/scan",
                headers=headers,
                data={"hash": file_hash, "file_name": file_name, "scan_type": scan_type},
            )
            r.raise_for_status()
            return True
    except Exception as e:
        logger.warning(f"MobSF scan trigger failed: {e}")
        return False


# ── Get report ────────────────────────────────────────────────────────────────

async def _get_report(file_hash: str) -> Optional[dict]:
    """Retrieve the full JSON static analysis report from MobSF."""
    headers = {"Authorization": MOBSF_API_KEY}
    try:
        async with httpx.AsyncClient(timeout=MOBSF_TIMEOUT) as client:
            r = await client.post(
                f"{MOBSF_URL}/api/v1/report_json",
                headers=headers,
                data={"hash": file_hash},
            )
            r.raise_for_status()
            return r.json()
    except Exception as e:
        logger.warning(f"MobSF report fetch failed: {e}")
        return None


# ── Result normalizer ─────────────────────────────────────────────────────────

def _as_list(value) -> list:
    """Safely coerce a value to list — handles dict, list, str, None."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return list(value.values())
    return [value]


def _normalize_report(raw: dict) -> dict:
    """
    Extract the key fields we care about from MobSF's verbose JSON report.
    Returns a slim, structured dict for our results page.
    """
    permissions = raw.get("permissions", {})
    dangerous_perms = [
        {"name": k, "status": v.get("status", ""), "info": v.get("info", "")}
        for k, v in permissions.items()
        if v.get("status") in ("dangerous", "signature", "signatureOrSystem")
    ]

    # Security findings
    code_analysis = raw.get("code_analysis", {})
    findings = []
    for issue_id, issue in code_analysis.items():
        if isinstance(issue, dict):
            findings.append({
                "title":    issue.get("metadata", {}).get("cvss", issue_id),
                "severity": issue.get("metadata", {}).get("severity", "info").upper(),
                "desc":     issue.get("metadata", {}).get("description", "")[:200],
                "files":    list(issue.get("files", {}).keys())[:3],
            })

    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda x: sev_order.get(x["severity"], 5))

    # MobSF security score (0–100, higher = more secure)
    apkid = raw.get("apkid", {})
    security_score = raw.get("security_score", None)

    return {
        "available":        True,
        "app_name":         raw.get("app_name", ""),
        "package_name":     raw.get("package_name", ""),
        "version_name":     raw.get("version_name", ""),
        "min_sdk":          raw.get("min_sdk", ""),
        "target_sdk":       raw.get("target_sdk", ""),
        "security_score":   security_score,
        "dangerous_perms":  dangerous_perms[:20],
        "findings":         findings[:30],
        "apkid":            apkid,  # packer/obfuscation detection
        "strings":          _as_list(raw.get("strings"))[:50],
        "urls":             _as_list(raw.get("urls"))[:30],
        "emails":           _as_list(raw.get("emails"))[:10],
        "firebase_urls":    _as_list(raw.get("firebase_urls"))[:10],
        "playstore_details": raw.get("playstore_details", {}),
        "certificate_info": raw.get("certificate_info", {}),
        "mobsf_version":    raw.get("mobsf_version", ""),
    }


# ── Public API ─────────────────────────────────────────────────────────────────

async def analyze(apk_path: str) -> dict:
    """
    Full MobSF static analysis pipeline.
    Returns a structured dict compatible with the analysis result schema.

    On failure (MobSF not running, API key missing, timeout):
    Returns {"available": False, "error": "..."}
    """
    if not MOBSF_API_KEY:
        return {
            "available": False,
            "error": "MOBSF_API_KEY not set. Add it to .env after starting MobSF.",
        }

    # 1. Check MobSF is up
    if not await _mobsf_available():
        return {
            "available": False,
            "error": "MobSF container not running. Start it with: docker-compose up mobsf -d",
        }

    logger.info("MobSF is reachable — uploading APK...")

    # 2. Upload
    upload_result = await _upload(apk_path)
    if not upload_result:
        return {"available": False, "error": "Failed to upload APK to MobSF"}

    file_hash = upload_result.get("hash")
    file_name = upload_result.get("file_name", Path(apk_path).name)
    logger.info(f"MobSF upload OK — hash: {file_hash}")

    # 3. Trigger scan
    scan_ok = await _scan(file_hash, file_name)
    if not scan_ok:
        return {"available": False, "error": "MobSF scan trigger failed"}

    # 4. Get report (MobSF scans synchronously on the scan endpoint)
    logger.info("Fetching MobSF report...")
    raw_report = await _get_report(file_hash)
    if not raw_report:
        return {"available": False, "error": "MobSF report fetch failed"}

    logger.info("MobSF analysis complete")
    return _normalize_report(raw_report)
