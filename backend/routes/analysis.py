"""
Analysis retrieval routes — P2: File Tree + Manifest XML endpoints.
P6: JADX Decompilation endpoints.
"""
from __future__ import annotations
import os
from fastapi import APIRouter, HTTPException
from backend.db import database
from backend.engines import file_tree as ft
from backend.engines import jadx_decompiler

router = APIRouter()

# We store the apk path alongside results; fall back to uploads dir
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "./uploads")


async def _get_apk_path_for(analysis_id: str) -> str | None:
    """Find the saved APK file for a given analysis ID."""
    result = await database.get_analysis(analysis_id)
    if not result:
        return None

    data = result if isinstance(result, dict) else (result.__dict__ if hasattr(result, "__dict__") else {})

    # Primary: uploads/{sha256}.apk — this is how upload.py now saves APKs
    sha256 = None
    hashes = data.get("hashes", {})
    if isinstance(hashes, dict):
        sha256 = hashes.get("sha256")
    elif isinstance(hashes, str):
        import json
        try:
            sha256 = json.loads(hashes).get("sha256")
        except Exception:
            pass

    if sha256:
        apk_path = os.path.join(UPLOAD_DIR, f"{sha256}.apk")
        if os.path.exists(apk_path):
            return apk_path

    # Fallback: scan uploads dir for any file containing the first 16 chars of sha256
    if sha256 and os.path.isdir(UPLOAD_DIR):
        for fname in os.listdir(UPLOAD_DIR):
            if fname.endswith(".apk") and sha256[:16] in fname:
                return os.path.join(UPLOAD_DIR, fname)

    return None


@router.get("/analysis/{analysis_id}")
async def get_analysis(analysis_id: str):
    """Get a completed analysis result by ID."""
    result = await database.get_analysis(analysis_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return result


@router.get("/analysis/{analysis_id}/download")
async def download_apk(analysis_id: str):
    """
    Returns a secure S3 Presigned URL to download the original APK file.
    Valid for 15 minutes.
    """
    from backend.storage import s3
    from fastapi.responses import RedirectResponse
    
    result = await database.get_analysis(analysis_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found")
        
    data = result if isinstance(result, dict) else dict(result)
    hashes = data.get("hashes", {})
    sha256 = hashes.get("sha256")
    
    if not sha256:
        raise HTTPException(status_code=404, detail="APK hash not available")
        
    object_name = f"apks/{sha256}.apk"
    url = await s3.get_presigned_url(object_name, expiration=900)
    
    if url:
        return RedirectResponse(url=url, status_code=307)
    
    raise HTTPException(status_code=404, detail="APK not found in Cloud Storage or S3 not configured")


@router.get("/analysis/{analysis_id}/filetree")
async def get_file_tree(analysis_id: str):
    """
    P2 — Return the decoded APK file structure as a nested JSON tree.
    Flags suspicious entries: hidden DEX, .so in assets, encrypted binaries.
    """
    apk_path = await _get_apk_path_for(analysis_id)
    if not apk_path:
        # Return empty tree with helpful error rather than 404
        return {
            "tree": [],
            "stats": {},
            "error": "APK file not available on disk (only metadata stored). Re-upload to enable file tree.",
        }

    result = ft.extract_file_tree(apk_path)
    return result


@router.get("/analysis/{analysis_id}/manifest")
async def get_manifest_xml(analysis_id: str):
    """
    P2 — Return the decoded AndroidManifest.xml as a human-readable string.
    Uses Androguard's AXML decoder for binary XML.
    """
    apk_path = await _get_apk_path_for(analysis_id)
    if not apk_path:
        return {
            "xml_string": None,
            "error": "APK file not available on disk. Re-upload to enable manifest viewer.",
        }

    result = ft.get_manifest_xml(apk_path)
    return result


@router.get("/analysis/{analysis_id}/decompile")
async def get_decompile_tree(analysis_id: str):
    """
    P6 — Return the decompiled package/class tree for the APK.
    Runs jadx on-demand (cached by SHA256) and returns a nested file tree.
    """
    apk_path = await _get_apk_path_for(analysis_id)
    if not apk_path:
        return {
            "available": False,
            "tree": [],
            "error": "APK file not available on disk. Re-upload to enable decompilation.",
        }
    return jadx_decompiler.get_class_tree(apk_path)


@router.get("/analysis/{analysis_id}/decompile/{class_path:path}")
async def get_class_source(analysis_id: str, class_path: str):
    """
    P6 — Return the decompiled Java source for a specific class file.
    `class_path` is relative to the sources root, e.g. "com/example/MainActivity.java"
    """
    apk_path = await _get_apk_path_for(analysis_id)
    if not apk_path:
        return {
            "available": False,
            "class_path": class_path,
            "source": None,
            "error": "APK file not available on disk. Re-upload to enable decompilation.",
        }
    return jadx_decompiler.get_class_source(apk_path, class_path)
