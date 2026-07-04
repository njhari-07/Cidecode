from fastapi import APIRouter, Query, HTTPException
from typing import List, Dict, Any

from backend.db import elastic

router = APIRouter()

@router.get("/", response_model=List[Dict[str, Any]])
async def search_threat_intel(
    q: str = Query(..., description="The IP, domain, hash, or filename to search for", min_length=2)
):
    """
    Query the Bonsai Elasticsearch cluster for Indicators of Compromise
    across all historical analyses.
    """
    try:
        results = await elastic.search_iocs(query=q)
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
