"""
DGA detector using lexical heuristics.

This module is intentionally dependency-free so it can run during PCAP analysis,
static URL extraction, and report generation without external services.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlparse


_IP_LIKE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_COMMON_WORDS = {
    "api", "app", "cdn", "cloud", "data", "dev", "login", "mail", "mobile",
    "pay", "secure", "service", "static", "support", "update", "verify",
    "web", "www",
}


def entropy(value: str) -> float:
    """Return Shannon entropy for a string."""
    if not value:
        return 0.0
    counts = Counter(value.lower())
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _hostname(value: str) -> str:
    raw = str(value or "").strip().lower().rstrip(".")
    if not raw:
        return ""
    if "://" in raw:
        parsed = urlparse(raw)
        return (parsed.hostname or "").lower().rstrip(".")
    return raw.split("/")[0].split(":")[0]


def score_domain(domain_or_url: str, query_count: int = 1) -> dict:
    """
    Score a domain for DGA-like properties.

    The score is heuristic evidence, not a verdict by itself.
    """
    domain = _hostname(domain_or_url)
    if not domain or _IP_LIKE.match(domain):
        return {
            "domain": domain,
            "query_count": query_count,
            "entropy": 0.0,
            "score": 0,
            "is_dga": False,
            "reasons": [],
        }

    labels = [label for label in domain.split(".") if label]
    main = labels[0] if labels else domain
    ent = round(entropy(main), 2)
    vowel_count = sum(1 for c in main if c in "aeiou")
    digit_count = sum(1 for c in main if c.isdigit())
    consonant_runs = re.findall(r"[bcdfghjklmnpqrstvwxyz]{5,}", main)

    score = 0
    reasons: list[str] = []
    if len(main) >= 12:
        score += 20
        reasons.append("long leading label")
    if ent >= 3.8:
        score += 35
        reasons.append(f"high entropy ({ent})")
    if digit_count >= 3:
        score += 15
        reasons.append("multiple digits")
    if len(main) >= 10 and vowel_count / max(len(main), 1) < 0.25:
        score += 15
        reasons.append("low vowel ratio")
    if consonant_runs:
        score += 15
        reasons.append("long consonant run")
    if main in _COMMON_WORDS:
        score = max(0, score - 30)
        reasons.append("common service label")

    return {
        "domain": domain,
        "query_count": query_count,
        "entropy": ent,
        "score": min(score, 100),
        "is_dga": score >= 50,
        "reasons": reasons,
    }


def analyze_domains(domains: list[str] | set[str] | tuple[str, ...]) -> dict:
    """Analyze a collection of domains/URLs and return DGA suspects."""
    counts = Counter(_hostname(d) for d in domains if _hostname(d))
    suspects = [
        score_domain(domain, count)
        for domain, count in counts.items()
    ]
    suspects = [item for item in suspects if item["is_dga"]]
    suspects.sort(key=lambda item: (item["score"], item["entropy"], item["query_count"]), reverse=True)
    return {
        "available": True,
        "total_domains": len(counts),
        "suspect_count": len(suspects),
        "suspects": suspects[:100],
    }
