"""
Upload route — accepts APK, validates, then submits async Celery job.
Returns {job_id, status: "queued"} immediately so the UI can connect
to the WebSocket for real-time progress.

Cache hit (same SHA256 seen before) → returns full result instantly
without re-queuing since the file was already analysed.
"""
from __future__ import annotations
import hashlib
import os
import uuid

from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from typing import Optional
from loguru import logger

from backend.db import database

router = APIRouter()

UPLOAD_DIR = os.getenv("UPLOAD_DIR", "./uploads")
MAX_FILE_SIZE = 700 * 1024 * 1024  # 700 MB
MAX_PCAP_SIZE = 200 * 1024 * 1024  # 200 MB
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(os.path.join(UPLOAD_DIR, "pcaps"), exist_ok=True)


def _is_apk(filename: str, data: bytes) -> bool:
    return filename.lower().endswith(".apk") and data[:2] == b"PK"


def _is_pcap(filename: str, data: bytes) -> bool:
    """Accept .pcap or .pcapng files by magic bytes."""
    lower = filename.lower()
    if not (lower.endswith(".pcap") or lower.endswith(".pcapng")):
        return False
    # pcap magic: 0xd4c3b2a1 (LE) or 0xa1b2c3d4 (BE)
    # pcapng magic: 0x0a0d0d0a
    if len(data) < 4:
        return False
    magic = data[:4]
    return magic in (
        b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
        b"\x0a\x0d\x0d\x0a",
    )


@router.post("/upload")
async def upload_apk(file: UploadFile = File(...)):
    """
    Upload an APK. Returns immediately with a job_id and WebSocket URL.
    Frontend connects to /api/ws/{job_id} for live progress.
    On cache hit, returns the existing result directly.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    data = await file.read()

    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File too large (max 700MB)")

    if not _is_apk(file.filename, data):
        raise HTTPException(status_code=400, detail="Invalid file — only .apk files accepted")

    # Compute SHA256 for deduplication
    sha256 = hashlib.sha256(data).hexdigest()

    # ── Cache hit ────────────────────────────────────────────────────────────
    cached = await database.get_analysis_by_hash(sha256)
    if cached:
        logger.info(f"Cache hit for {sha256[:16]}...")
        # Ensure APK is still on disk (needed for file tree / manifest)
        apk_path = os.path.join(UPLOAD_DIR, f"{sha256}.apk")
        if not os.path.exists(apk_path):
            with open(apk_path, "wb") as f_out:
                f_out.write(data)
        # Return cached result with a sentinel job_id so the UI skips progress
        return {
            "job_id": "cached",
            "status": "complete",
            "cached": True,
            "result": cached,
        }

    # ── Save APK persistently ────────────────────────────────────────────────
    apk_path = os.path.join(UPLOAD_DIR, f"{sha256}.apk")
    if not os.path.exists(apk_path):
        with open(apk_path, "wb") as f_out:
            f_out.write(data)
        logger.info(f"Saved APK → {apk_path}")
        
        # Upload to S3/R2 if configured
        from backend.storage.s3 import upload_file as s3_upload
        await s3_upload(apk_path, f"apks/{sha256}.apk")

    # ── Submit Celery task ───────────────────────────────────────────────────
    job_id = str(uuid.uuid4())
    try:
        from backend.worker.tasks import run_analysis_task
        run_analysis_task.apply_async(
            args=[apk_path, file.filename, job_id],
            task_id=job_id,
            queue="analysis",
        )
        logger.info(f"Queued analysis job {job_id[:8]}... for {file.filename}")
    except Exception as e:
        # Celery/Redis unavailable — fall back to synchronous analysis
        logger.warning(f"Celery unavailable ({e}), falling back to sync analysis")
        from backend.engines import static_analyzer
        result = await static_analyzer.run(apk_path, file.filename)
        await database.save_analysis(result)
        return {
            "job_id": "sync",
            "status": "complete",
            "cached": False,
            "result": result,
        }

    return {
        "job_id": job_id,
        "status": "queued",
        "cached": False,
        "ws_url": f"/api/ws/{job_id}",
    }


@router.post("/upload/pcap")
async def upload_pcap(
    file: UploadFile = File(...),
    analysis_id: Optional[str] = Form(None),
):
    """
    Upload a .pcap or .pcapng file.

    Optional: pass `analysis_id` (an existing APK scan ID) to link the
    network report to that scan. The network tab on the results page
    will then show this data alongside the APK analysis.

    Returns: { pcap_id, status, network: <PCAPResult> }
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    data = await file.read()

    if len(data) > MAX_PCAP_SIZE:
        raise HTTPException(status_code=413, detail="PCAP too large (max 200MB)")

    if not _is_pcap(file.filename, data):
        raise HTTPException(
            status_code=400,
            detail="Invalid file — only .pcap / .pcapng files accepted",
        )

    # ── Save PCAP ────────────────────────────────────────────────────────────
    pcap_id   = str(uuid.uuid4())
    pcap_path = os.path.join(UPLOAD_DIR, "pcaps", f"{pcap_id}.pcap")
    with open(pcap_path, "wb") as f_out:
        f_out.write(data)
    logger.info(f"Saved PCAP → {pcap_path} ({len(data):,} bytes)")

    # Upload to S3/R2 if configured
    from backend.storage.s3 import upload_file as s3_upload
    await s3_upload(pcap_path, f"pcaps/{pcap_id}.pcap")

    # ── Run PCAP analysis (sync — fast enough for ≤200MB) ───────────────────
    from backend.engines import pcap_analyzer

    # If linked to an APK scan, pass its India IOC data for cross-referencing
    india_ioc_data = None
    linked_result  = None
    if analysis_id:
        linked_result = await database.get_analysis(analysis_id)
        if linked_result:
            india_ioc_data = linked_result.get("india_ioc")

    network = pcap_analyzer.analyze(pcap_path, india_ioc_data=india_ioc_data)

    # ── Patch the linked APK result with network data ────────────────────────
    if linked_result and network.get("available"):
        linked_result["network"] = network
        linked_result["pcap_id"] = pcap_id
        from backend.engines import correlation_engine
        linked_result["correlation"] = correlation_engine.correlate(
            manifest=linked_result.get("manifest", {}),
            strings=linked_result.get("strings", {}),
            dynamic=linked_result.get("dynamic", {}),
            network=network,
            india_ioc=linked_result.get("india_ioc", {}),
            mobsf=linked_result.get("mobsf", {}),
            threat_intel={
                "virustotal": linked_result.get("virustotal", {}),
                "abuseipdb": linked_result.get("abuseipdb", {}),
                "asn": linked_result.get("asn", {}),
                "otx": linked_result.get("otx", {}),
            },
        )
        await database.save_analysis(linked_result)
        logger.info(f"Patched analysis {analysis_id} with PCAP network data")

    # ── Save standalone PCAP record ──────────────────────────────────────────
    await database.save_pcap_result(pcap_id, file.filename, analysis_id, network)

    return {
        "pcap_id": pcap_id,
        "status": "complete",
        "linked_analysis_id": analysis_id,
        "network": network,
    }
