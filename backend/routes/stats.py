"""
Stats route: returns dashboard statistics.
"""
from __future__ import annotations
import json
from fastapi import APIRouter
from backend.db import database

router = APIRouter()


@router.get("/stats")
async def get_stats():
    """Return aggregated statistics for the dashboard."""
    base = await database.get_stats()

    # ── Enrich with ML family breakdown ───────────────────────────────────────
    family_counts: dict[str, int] = {}
    india_targeted = 0
    pcap_count = 0

    async with database.async_session_factory() as session:
        from sqlalchemy import select
        rows = (await session.execute(select(database.AnalysisRecord))).scalars().all()
        for r in rows:
            try:
                data = json.loads(r.result_json)
                # ML family
                ml = data.get("ml_classification") or {}
                family = ml.get("family", "Unknown")
                family_counts[family] = family_counts.get(family, 0) + 1
                # India targeted
                if ml.get("is_india_targeted"):
                    india_targeted += 1
            except Exception:
                pass

        # PCAP records
        try:
            pcap_rows = (await session.execute(select(database.PCAPRecord))).scalars().all()
            pcap_count = len(pcap_rows)
        except Exception:
            pass

    base["family_breakdown"] = family_counts
    base["india_targeted"] = india_targeted
    base["pcap_scans"] = pcap_count
    return base
