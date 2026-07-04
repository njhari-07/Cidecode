"""
AlienVault OTX pulse lookup for IPs and domains.
"""
from __future__ import annotations

import os

import httpx


OTX_API_KEY = os.getenv("OTX_API_KEY", "")
OTX_BASE = "https://otx.alienvault.com/api/v1"


async def _lookup(client: httpx.AsyncClient, indicator_type: str, value: str) -> dict:
    path_type = "IPv4" if indicator_type == "ip" else "domain"
    resp = await client.get(f"{OTX_BASE}/indicators/{path_type}/{value}/general")
    resp.raise_for_status()
    data = resp.json()
    pulses = data.get("pulse_info", {}).get("pulses", [])
    return {
        "type": indicator_type,
        "value": value,
        "pulse_count": data.get("pulse_info", {}).get("count", len(pulses)),
        "reputation": data.get("reputation"),
        "malware_families": [
            pulse.get("malware_families", [])
            for pulse in pulses[:5]
            if pulse.get("malware_families")
        ],
        "pulse_names": [pulse.get("name", "") for pulse in pulses[:5] if pulse.get("name")],
    }


async def analyze(ips: list[str], domains: list[str]) -> dict:
    indicators = [("ip", ip) for ip in dict.fromkeys(ips)][:15]
    indicators += [("domain", domain) for domain in dict.fromkeys(domains)][:15]

    if not indicators:
        return {"available": True, "checked": 0, "hits": []}

    if not OTX_API_KEY:
        return {
            "available": False,
            "error": "OTX_API_KEY not configured",
            "checked": 0,
            "hits": [],
        }

    hits: list[dict] = []
    async with httpx.AsyncClient(timeout=15, headers={"X-OTX-API-KEY": OTX_API_KEY}) as client:
        for indicator_type, value in indicators:
            try:
                hit = await _lookup(client, indicator_type, value)
                if hit.get("pulse_count", 0) > 0:
                    hits.append(hit)
            except Exception:
                continue

    return {
        "available": True,
        "checked": len(indicators),
        "hits": hits,
    }
