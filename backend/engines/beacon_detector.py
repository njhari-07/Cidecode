"""
Beaconing detector for C2-like periodic network contacts.
"""
from __future__ import annotations

from collections import defaultdict


MIN_CONTACTS = 5
MAX_INTERVAL_SEC = 600
LOW_JITTER_CV = 0.25


def _coefficient_of_variation(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    if mean <= 0:
        return 0.0
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return (variance ** 0.5) / mean


def analyze_timestamps(ip_timestamps: dict[str, list[float]]) -> dict:
    """Analyze per-IP timestamps and return beacon alerts."""
    alerts: list[dict] = []
    for ip, timestamps in ip_timestamps.items():
        ordered = sorted(float(ts) for ts in timestamps)
        if len(ordered) < MIN_CONTACTS:
            continue
        intervals = [
            ordered[i + 1] - ordered[i]
            for i in range(len(ordered) - 1)
            if 0 < ordered[i + 1] - ordered[i] <= MAX_INTERVAL_SEC
        ]
        if len(intervals) < MIN_CONTACTS - 1:
            continue

        jitter = _coefficient_of_variation(intervals)
        if jitter <= LOW_JITTER_CV:
            average = sum(intervals) / len(intervals)
            alerts.append({
                "ip": ip,
                "contact_count": len(ordered),
                "avg_interval_sec": round(average, 1),
                "jitter_cv": round(jitter, 3),
                "confidence": "HIGH" if jitter < 0.10 else "MEDIUM",
                "description": (
                    f"Periodic contact pattern: {len(ordered)} contacts, "
                    f"average interval {average:.0f}s, jitter CV {jitter:.2f}"
                ),
            })

    alerts.sort(key=lambda item: (item["confidence"] == "HIGH", item["contact_count"]), reverse=True)
    return {
        "available": True,
        "alert_count": len(alerts),
        "alerts": alerts,
    }


def analyze_remote_ips(remote_ips: list[dict]) -> dict:
    """
    Fallback beacon analysis when exact packet timestamps are unavailable.

    This does not claim regular timing; it identifies repeated C2-shaped contacts
    so the UI still has a useful behaviour timeline from stored summaries.
    """
    synthetic: dict[str, list[float]] = defaultdict(list)
    for item in remote_ips:
        count = int(item.get("count", 0) or 0)
        if count >= MIN_CONTACTS:
            synthetic[item.get("ip", "unknown")] = [float(i * 60) for i in range(min(count, 40))]
    return analyze_timestamps(synthetic)
