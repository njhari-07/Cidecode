"""
Health check router — returns component-level status for monitoring.
"""
from __future__ import annotations
import os
import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter
from loguru import logger

router = APIRouter(tags=["Health"])


async def _check_db() -> dict:
    """Ping the PostgreSQL database."""
    try:
        from backend.db.database import engine
        async with engine.connect() as conn:
            await conn.execute(__import__("sqlalchemy").text("SELECT 1"))
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


async def _check_elasticsearch() -> dict:
    """Ping Elasticsearch / Bonsai if configured."""
    es_url = os.getenv("ELASTICSEARCH_URL", "")
    if not es_url:
        return {"status": "disabled"}
    try:
        from backend.db import elastic
        # A basic index existence check
        await elastic.setup_index()
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


async def _check_virustotal() -> dict:
    """Confirm the VT API key is configured (no network call)."""
    key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not key or key == "your_virustotal_api_key_here":
        return {"status": "not_configured"}
    return {"status": "configured"}


@router.get("/health")
async def health_check():
    """
    Lightweight liveness probe — returns instantly.
    Used by Docker / Kubernetes readiness checks.
    """
    return {
        "status": "ok",
        "service": "DroidRaksha API",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/health/detailed")
async def health_check_detailed():
    """
    Detailed readiness probe — checks each component in parallel.
    Useful for monitoring dashboards and alerting.
    """
    db_result, es_result, vt_result = await asyncio.gather(
        _check_db(),
        _check_elasticsearch(),
        _check_virustotal(),
        return_exceptions=False,
    )

    components = {
        "database": db_result,
        "elasticsearch": es_result,
        "virustotal": vt_result,
    }

    # Overall status: degraded if any critical component is erroring
    critical_ok = db_result.get("status") == "ok"
    overall = "ok" if critical_ok else "degraded"

    return {
        "status": overall,
        "service": "DroidRaksha API",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "components": components,
    }
