"""
ASN / hosting provider lookup.

Uses ipwho.is when available. Without network access or if the service fails,
the module returns an unavailable marker plus deterministic local hints.
"""
from __future__ import annotations

import ipaddress
import os

import httpx


ASN_LOOKUP_ENABLED = os.getenv("ASN_LOOKUP_ENABLED", "true").lower() not in {"0", "false", "no"}


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast)
    except ValueError:
        return False


def _local_hint(ip: str) -> dict:
    return {
        "ip": ip,
        "asn": None,
        "org": "Unknown",
        "country": None,
        "hosting": False,
        "source": "local",
    }


async def analyze(ips: list[str]) -> dict:
    public_ips = []
    for ip in ips:
        if ip not in public_ips and _is_public_ip(ip):
            public_ips.append(ip)

    if not public_ips:
        return {"available": True, "checked": 0, "results": []}

    if not ASN_LOOKUP_ENABLED:
        return {
            "available": False,
            "error": "ASN_LOOKUP_ENABLED is disabled",
            "checked": 0,
            "results": [_local_hint(ip) for ip in public_ips[:25]],
        }

    results: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            for ip in public_ips[:25]:
                try:
                    resp = await client.get(f"https://ipwho.is/{ip}")
                    data = resp.json()
                    if not data.get("success", True):
                        results.append(_local_hint(ip))
                        continue
                    connection = data.get("connection") or {}
                    org = connection.get("org") or connection.get("isp") or "Unknown"
                    lowered = org.lower()
                    hosting = any(word in lowered for word in (
                        "cloud", "hosting", "data center", "datacenter", "vps",
                        "digitalocean", "aws", "amazon", "google", "azure", "ovh",
                        "hetzner", "linode", "oracle",
                    ))
                    results.append({
                        "ip": ip,
                        "asn": connection.get("asn"),
                        "org": org,
                        "country": data.get("country_code"),
                        "hosting": hosting,
                        "source": "ipwho.is",
                    })
                except Exception:
                    results.append(_local_hint(ip))
    except Exception as exc:
        return {
            "available": False,
            "error": str(exc),
            "checked": 0,
            "results": [_local_hint(ip) for ip in public_ips[:25]],
        }

    return {
        "available": True,
        "checked": len(results),
        "results": results,
    }
