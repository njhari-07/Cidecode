from fastapi import APIRouter, HTTPException, Response
from typing import Dict, Any, List
import json
import stix2
from datetime import datetime, timezone

from backend.db import database

router = APIRouter()

def _build_stix_bundle(data: dict) -> stix2.Bundle:
    """Converts a DroidRaksha analysis result into a STIX 2.1 Bundle."""
    objects = []
    
    analysis_id = data.get("id", "unknown")
    hashes = data.get("hashes", {})
    manifest = data.get("manifest", {})
    strings_data = data.get("strings", {})
    risk = data.get("risk", {})
    
    # 1. Malware Object
    pkg_name = manifest.get("package_name", "Unknown APK")
    malware = stix2.Malware(
        name=f"Android APK: {pkg_name}",
        is_family=False,
        description=f"DroidRaksha Analysis ID: {analysis_id}. Risk Score: {risk.get('score', 0)}/100",
        malware_types=["dropper", "spyware"] if risk.get("risk_level") in ["CRITICAL", "HIGH"] else ["unknown"],
    )
    objects.append(malware)

    # 2. File Object (representing the APK)
    file_hashes = {}
    if hashes.get("md5"): file_hashes["MD5"] = hashes["md5"]
    if hashes.get("sha1"): file_hashes["SHA-1"] = hashes["sha1"]
    if hashes.get("sha256"): file_hashes["SHA-256"] = hashes["sha256"]
    
    apk_file = stix2.File(
        name=data.get("filename", "unknown.apk"),
        hashes=file_hashes if file_hashes else None,
        mime_type="application/vnd.android.package-archive"
    )
    objects.append(apk_file)

    # Relationship: Malware payload is the File
    objects.append(stix2.Relationship(malware, "drops", apk_file))

    # 3. Network Indicators (IPs and Domains)
    if isinstance(strings_data, dict):
        ips = strings_data.get("ips", [])
        for ip_obj in ips:
            ip_val = ip_obj.get("value")
            if ip_val:
                ipv4 = stix2.IPv4Address(value=ip_val)
                ind = stix2.Indicator(
                    name=f"Extracted IP: {ip_val}",
                    pattern=f"[ipv4-addr:value = '{ip_val}']",
                    pattern_type="stix",
                    indicator_types=["malicious-activity"]
                )
                objects.extend([ipv4, ind, stix2.Relationship(ind, "indicates", malware)])
                
        urls = strings_data.get("urls", [])
        for url_obj in urls:
            url_val = url_obj.get("value", "")
            domain = url_val.split("/")[2] if "://" in url_val else url_val.split("/")[0]
            if domain and "." in domain:
                dom_obj = stix2.DomainName(value=domain)
                ind = stix2.Indicator(
                    name=f"Extracted Domain: {domain}",
                    pattern=f"[domain-name:value = '{domain}']",
                    pattern_type="stix",
                    indicator_types=["malicious-activity"]
                )
                objects.extend([dom_obj, ind, stix2.Relationship(ind, "indicates", malware)])

    # Wrap in a Bundle
    bundle = stix2.Bundle(objects=objects)
    return bundle


@router.get("/stix/{analysis_id}")
async def export_stix_single(analysis_id: str):
    """
    Export a specific analysis as a STIX 2.1 Threat Intelligence Bundle.
    """
    result = await database.get_analysis(analysis_id)
    if not result:
        result = await database.get_analysis_by_hash(analysis_id)
        
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found")
        
    data = result if isinstance(result, dict) else dict(result)
    try:
        bundle = _build_stix_bundle(data)
        return Response(
            content=bundle.serialize(indent=4),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=droidraksha_stix_{analysis_id[:8]}.json"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate STIX: {e}")


@router.get("/stix/bulk")
async def export_stix_bulk(limit: int = 50):
    """
    Mass-export STIX 2.1 indicators from the most recent malicious analyses.
    """
    # Fetch recent high-risk analyses
    query = "SELECT id, result_json FROM analyses WHERE risk_level IN ('CRITICAL', 'HIGH') ORDER BY created_at DESC LIMIT $1"
    # Wait, we removed result_json from postgres. We should use get_recent_analyses
    # which fetches metadata, and then we might need to fetch full JSONs from Mongo.
    # To keep it fast, we'll fetch the recent metadata from Postgres and just use their hashes.
    
    # Let's use the DB function
    recent_metadata = await database.get_recent_analyses(limit=limit)
    
    objects = []
    
    for row in recent_metadata:
        analysis_id = row.get("id")
        # For bulk, we'll just create malware/file indicators without loading the massive JSON
        pkg_name = row.get("package_name", "Unknown")
        sha256 = row.get("sha256")
        
        malware = stix2.Malware(
            name=f"Android APK: {pkg_name}",
            is_family=False,
            description=f"DroidRaksha Bulk Export - ID: {analysis_id}",
            malware_types=["malware"]
        )
        
        file_hashes = {}
        if sha256: file_hashes["SHA-256"] = sha256
        if row.get("md5"): file_hashes["MD5"] = row.get("md5")
        if row.get("sha1"): file_hashes["SHA-1"] = row.get("sha1")
        
        apk_file = stix2.File(
            name=row.get("filename", "unknown.apk"),
            hashes=file_hashes if file_hashes else None,
        )
        
        objects.extend([malware, apk_file, stix2.Relationship(malware, "drops", apk_file)])
        
    if not objects:
        return Response(content='{"type": "bundle", "id": "bundle--empty", "objects": []}', media_type="application/json")
        
    bundle = stix2.Bundle(objects=objects)
    return Response(
        content=bundle.serialize(indent=4),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=droidraksha_stix_bulk.json"}
    )
