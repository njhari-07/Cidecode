import os
import logging
from elasticsearch import AsyncElasticsearch

logger = logging.getLogger(__name__)

BONSAI_URL = os.getenv("BONSAI_URL")

# Initialize client only if URL is provided
es_client = AsyncElasticsearch(BONSAI_URL) if BONSAI_URL else None
INDEX_NAME = "droidraksha_iocs"


async def setup_index():
    """Create the Elasticsearch index if it doesn't exist."""
    if not es_client:
        return
    try:
        exists = await es_client.indices.exists(index=INDEX_NAME)
        if not exists:
            await es_client.indices.create(
                index=INDEX_NAME,
                mappings={
                    "properties": {
                        "analysis_id": {"type": "keyword"},
                        "filename": {"type": "text"},
                        "type": {"type": "keyword"},  # 'ip', 'domain', 'hash'
                        "value": {"type": "keyword"},
                        "timestamp": {"type": "date"},
                    }
                },
            )
            logger.info(f"Created Elasticsearch index: {INDEX_NAME}")
    except Exception as e:
        logger.error(f"Failed to setup Elasticsearch index: {e}")


async def index_analysis(analysis_result: dict):
    """
    Extracts IPs, Domains, and Hashes from a complete analysis result
    and indexes them into Elasticsearch for global threat hunting.
    """
    if not es_client:
        return

    analysis_id = analysis_result.get("id")
    filename = analysis_result.get("filename", "unknown")
    timestamp = analysis_result.get("created_at")

    docs = []
    
    # 1. Hashes
    hashes = analysis_result.get("hashes", {})
    for algo, val in hashes.items():
        if algo in ("md5", "sha1", "sha256"):
            docs.append({"type": "hash", "value": val})

    # 2. Strings (IPs and Domains)
    strings_data = analysis_result.get("strings", {})
    for ip_entry in strings_data.get("ips", []):
        docs.append({"type": "ip", "value": ip_entry.get("value")})
        
    for url_entry in strings_data.get("urls", []):
        val = url_entry.get("value", "")
        # Very basic domain extraction
        domain = val.split("/")[2] if "://" in val else val.split("/")[0]
        if domain:
            docs.append({"type": "domain", "value": domain})

    # Bulk index
    operations = []
    for doc in docs:
        if not doc.get("value"):
            continue
        operations.append({"index": {"_index": INDEX_NAME}})
        doc["analysis_id"] = analysis_id
        doc["filename"] = filename
        doc["timestamp"] = timestamp
        operations.append(doc)

    if operations:
        try:
            await es_client.bulk(operations=operations)
            logger.info(f"Indexed {len(docs)} IOCs into Elasticsearch for {analysis_id}")
        except Exception as e:
            logger.error(f"Failed to index IOCs: {e}")


async def search_iocs(query: str, size: int = 50):
    """
    Search for an exact or partial IOC match across all analyses.
    """
    if not es_client:
        return []

    try:
        # Wildcard search on value, match on filename
        response = await es_client.search(
            index=INDEX_NAME,
            query={
                "bool": {
                    "should": [
                        {"wildcard": {"value": f"*{query}*"}},
                        {"match": {"filename": query}}
                    ]
                }
            },
            size=size,
            sort=[{"timestamp": "desc"}]
        )
        return [hit["_source"] for hit in response["hits"]["hits"]]
    except Exception as e:
        logger.error(f"Elasticsearch search failed: {e}")
        return []
