"""
Static ↔ dynamic correlation engine.

Compares indicators found in APK code/resources against sandbox and PCAP
observations to expose hidden C2 infrastructure and behaviour confirmation.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse


_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")


def _host(value: str) -> str:
    raw = str(value or "").strip().lower().rstrip(".")
    if not raw:
        return ""
    if "://" in raw:
        parsed = urlparse(raw)
        return (parsed.hostname or "").lower().rstrip(".")
    return raw.split("/")[0].split(":")[0].rstrip(".")


def _string_values(strings: dict, key: str) -> list[str]:
    values = []
    for item in strings.get(key, []) or []:
        value = item.get("value") if isinstance(item, dict) else str(item)
        if value and value not in values:
            values.append(value)
    return values


def _network_domains(network: dict) -> set[str]:
    domains: set[str] = set()
    for item in network.get("dns_queries", []) or []:
        domains.add(_host(item.get("domain", "")))
    for item in network.get("http_hosts", []) or []:
        domains.add(_host(item.get("host", "")))
    for item in network.get("tls_sni", []) or []:
        domains.add(_host(str(item)))
    return {d for d in domains if d}


def _network_ips(network: dict) -> set[str]:
    ips = set()
    for item in network.get("remote_ips", []) or []:
        ip = item.get("ip")
        if ip:
            ips.add(str(ip))
    return ips


def _dynamic_endpoints(dynamic: dict) -> set[str]:
    smali = dynamic.get("smali_analysis") or {}
    values = set()
    for endpoint in smali.get("network_endpoints", []) or []:
        value = str(endpoint)
        host = _host(value)
        if host:
            values.add(host)
        values.update(_IP_RE.findall(value))
    return values


def _severity(weight: int) -> str:
    if weight >= 85:
        return "CRITICAL"
    if weight >= 60:
        return "HIGH"
    if weight >= 35:
        return "MEDIUM"
    return "LOW"


def correlate(
    manifest: dict,
    strings: dict,
    dynamic: dict | None = None,
    network: dict | None = None,
    india_ioc: dict | None = None,
    mobsf: dict | None = None,
    threat_intel: dict | None = None,
) -> dict:
    dynamic = dynamic or {}
    network = network or {}
    india_ioc = india_ioc or {}
    mobsf = mobsf or {}
    threat_intel = threat_intel or {}

    static_urls = _string_values(strings, "urls")
    static_ips = set(_string_values(strings, "ips"))
    static_domains = {_host(url) for url in static_urls if _host(url)}
    static_domains.update(_host(url) for url in (mobsf.get("urls") or []) if _host(url))
    static_domains = {d for d in static_domains if d}

    runtime_domains = _network_domains(network)
    runtime_ips = _network_ips(network)
    sandbox_endpoints = _dynamic_endpoints(dynamic)
    runtime_domains.update(v for v in sandbox_endpoints if not _IP_RE.match(v))
    runtime_ips.update(v for v in sandbox_endpoints if _IP_RE.match(v))

    matches: list[dict] = []
    for domain in sorted(static_domains & runtime_domains):
        matches.append({
            "type": "domain",
            "value": domain,
            "static_source": "extracted strings / MobSF",
            "dynamic_source": "PCAP DNS/HTTP/TLS or sandbox endpoint",
            "severity": "HIGH",
            "explanation": "Domain is hardcoded in the APK and was also observed during runtime/network analysis.",
        })
    for ip in sorted(static_ips & runtime_ips):
        matches.append({
            "type": "ip",
            "value": ip,
            "static_source": "extracted strings",
            "dynamic_source": "PCAP remote connection or sandbox endpoint",
            "severity": "CRITICAL",
            "explanation": "IP is embedded statically and appears in runtime network activity.",
        })

    hidden_runtime = []
    for domain in sorted(runtime_domains - static_domains):
        hidden_runtime.append({
            "type": "domain",
            "value": domain,
            "severity": "MEDIUM",
            "explanation": "Runtime domain was not found in static strings; it may be generated, decrypted, or resolved indirectly.",
        })
    for ip in sorted(runtime_ips - static_ips):
        hidden_runtime.append({
            "type": "ip",
            "value": ip,
            "severity": "MEDIUM",
            "explanation": "Runtime IP was not found in static strings; it may be resolved dynamically or reached by native code.",
        })

    india_values = set(india_ioc.get("matched_domains", []) or []) | set(india_ioc.get("matched_ips", []) or [])
    india_values.update(hit.get("value") for hit in network.get("india_ioc_hits", []) or [] if hit.get("value"))
    threat_hits = []
    for value in sorted(india_values):
        if value in static_domains or value in static_ips or value in runtime_domains or value in runtime_ips:
            threat_hits.append({
                "type": "india_ioc",
                "value": value,
                "severity": "HIGH",
                "explanation": "Indicator overlaps with India-focused threat intelligence.",
            })

    permissions = {p.get("name", "") for p in manifest.get("permissions", []) or [] if isinstance(p, dict)}
    behaviour_links = []
    if any("INTERNET" in p for p in permissions) and (runtime_domains or runtime_ips):
        behaviour_links.append("INTERNET permission is supported by observed network traffic.")
    if any("READ_SMS" in p or "RECEIVE_SMS" in p for p in permissions):
        behaviour_links.append("SMS permission increases risk when combined with C2 or banking indicators.")
    if dynamic.get("behavioral_score", {}).get("flags"):
        behaviour_links.extend(dynamic["behavioral_score"]["flags"][:5])

    score = min(
        100,
        len(matches) * 30
        + len(threat_hits) * 20
        + min(len(hidden_runtime), 8) * 5
        + (15 if network.get("beaconing_alerts") else 0)
        + (15 if network.get("dga_suspects") else 0),
    )

    return {
        "available": True,
        "score": score,
        "severity": _severity(score),
        "summary": (
            f"{len(matches)} static/runtime matches, "
            f"{len(hidden_runtime)} runtime-only indicators, "
            f"{len(threat_hits)} threat-intel overlaps."
        ),
        "matches": matches[:100],
        "hidden_runtime_indicators": hidden_runtime[:100],
        "threat_intel_overlaps": threat_hits[:100],
        "behaviour_links": behaviour_links[:25],
        "static_counts": {
            "domains": len(static_domains),
            "ips": len(static_ips),
        },
        "dynamic_counts": {
            "domains": len(runtime_domains),
            "ips": len(runtime_ips),
        },
        "threat_intel": threat_intel,
    }
