"""
Sandbox REST API Routes
========================
Endpoints for triggering and retrieving sandbox analysis.

Routes:
  POST /api/sandbox/{analysis_id}/trigger  — re-run sandbox on existing analysis
  GET  /api/sandbox/{analysis_id}          — get sandbox result for an analysis
  GET  /api/sandbox/status                 — check if sandbox (Docker) is available
"""
from __future__ import annotations
import os
from fastapi import APIRouter, HTTPException, BackgroundTasks
from loguru import logger

from backend.db import database
from backend.engines import sandbox_engine, mobsf_client

router = APIRouter()

UPLOAD_DIR = os.getenv("UPLOAD_DIR", "./uploads")


# ── Helper ─────────────────────────────────────────────────────────────────────

async def _get_apk_path(analysis_id: str) -> str | None:
    """Resolve APK path from analysis record."""
    import json, os
    result = await database.get_analysis(analysis_id)
    if not result:
        return None
    hashes = result.get("hashes", {})
    sha256 = hashes.get("sha256") if isinstance(hashes, dict) else None
    if sha256:
        apk_path = os.path.join(UPLOAD_DIR, f"{sha256}.apk")
        if os.path.exists(apk_path):
            return apk_path
    return None


async def _run_sandbox_and_save(analysis_id: str, apk_path: str) -> None:
    """Background task: run sandbox + MobSF and patch result in DB."""
    result = await database.get_analysis(analysis_id)
    if not result:
        return

    logger.info(f"Running sandbox for analysis {analysis_id[:8]}...")

    # Run Frida offline sandbox (sync — runs Docker subprocess)
    import asyncio
    loop = asyncio.get_event_loop()
    sandbox_result = await loop.run_in_executor(None, sandbox_engine.run, apk_path)
    result["dynamic"] = sandbox_result

    # Run MobSF (async)
    mobsf_result = await mobsf_client.analyze(apk_path)
    result["mobsf"] = mobsf_result

    await database.save_analysis(result)
    logger.info(f"Sandbox complete for {analysis_id[:8]} — "
                f"sandbox={sandbox_result.get('sandbox_available')} "
                f"mobsf={mobsf_result.get('available')}")


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.get("/sandbox/status")
async def sandbox_status():
    """Check if Docker sandbox is available."""
    import subprocess
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=10,
        )
        docker_ok = result.returncode == 0 and bool(result.stdout.strip())
        docker_version = result.stdout.strip() if docker_ok else None
    except Exception as e:
        docker_ok = False
        docker_version = None

    # Check MobSF
    mobsf_ok = await mobsf_client._mobsf_available()

    return {
        "docker_available":  docker_ok,
        "docker_version":    docker_version,
        "mobsf_available":   mobsf_ok,
        "mobsf_url":         os.getenv("MOBSF_URL", "http://localhost:8008"),
        "sandbox_enabled":   os.getenv("SANDBOX_ENABLED", "true").lower() == "true",
    }


@router.get("/sandbox/{analysis_id}")
async def get_sandbox_result(analysis_id: str):
    """Get dynamic analysis results for a completed analysis."""
    result = await database.get_analysis(analysis_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found")

    dynamic = result.get("dynamic")
    mobsf   = result.get("mobsf")

    if dynamic is None and mobsf is None:
        return {
            "analysis_id": analysis_id,
            "sandbox_run": False,
            "message":     "Sandbox has not been run for this analysis yet. Use POST /trigger.",
        }

    return {
        "analysis_id": analysis_id,
        "sandbox_run": True,
        "dynamic":     dynamic,
        "mobsf":       mobsf,
    }


@router.post("/sandbox/{analysis_id}/trigger")
async def trigger_sandbox(analysis_id: str, background_tasks: BackgroundTasks):
    """
    (Re-)trigger sandbox analysis for an existing APK analysis.
    Runs in background — poll GET /sandbox/{analysis_id} for results.
    """
    result = await database.get_analysis(analysis_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found")

    apk_path = await _get_apk_path(analysis_id)
    if not apk_path:
        raise HTTPException(
            status_code=404,
            detail="APK file not found on disk. Re-upload the APK to enable sandbox.",
        )

    background_tasks.add_task(_run_sandbox_and_save, analysis_id, apk_path)

    return {
        "analysis_id": analysis_id,
        "status":      "triggered",
        "message":     "Sandbox analysis started. Check GET /api/sandbox/{analysis_id} for results.",
        "apk_path":    apk_path,
    }
