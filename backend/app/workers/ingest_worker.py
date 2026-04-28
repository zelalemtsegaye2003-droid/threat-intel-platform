from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

from app.workers.celery_app import celery_app
from app.services.enrichment import FeedIngestor, EnrichmentService, AttackMapper
from app.services.correlation import CorrelationEngine
from app.db.postgres import get_db
from app.db.qdrant_db import get_qdrant


@celery_app.task(bind=True, max_retries=3)
def ingest_feeds_task(self):
    """Periodic task to ingest external threat feeds."""
    asyncio.run(_ingest_feeds())


@celery_app.task(bind=True)
def process_ioc_task(self, ioc_data: dict[str, Any]):
    """Process a new IOC: enrich, vectorize, and add to graph."""
    asyncio.run(_process_ioc(ioc_data))


@celery_app.task(bind=True)
def correlate_iocs_task(self, ioc_id: str):
    """Find correlations for an IOC."""
    asyncio.run(_correlate_ioc(ioc_id))


@celery_app.task
def update_graph_metrics():
    """Update graph metrics periodically."""
    asyncio.run(_update_metrics())


async def _ingest_feeds() -> dict[str, Any]:
    """Ingest all enabled feeds."""
    results = {"otx": {}, "abuse_ch": {}, "errors": []}

    ingestor = FeedIngestor()
    try:
        # AlienVault OTX
        results["otx"] = await ingestor.ingest_alienvault_otx()

        # Abuse.ch
        results["abuse_ch"] = await ingestor.ingest_abuse_ch()

    except Exception as e:
        results["errors"].append(str(e))
    finally:
        await ingestor.close()

    return results


async def _process_ioc(ioc_data: dict[str, Any]) -> None:
    """Full processing pipeline for a new IOC."""
    # 1. Enrich IOC
    enrichment = EnrichmentService()
    enriched = await enrichment.enrich_ioc(ioc_data)

    # 2. Map to ATT&CK techniques
    mapper = AttackMapper()
    techniques = await mapper.map_ioc_to_techniques(enriched)

    # 3. Generate embedding and index in Qdrant
    vector_svc = VectorService()
    await vector_svc.index_ioc(enriched)

    # 4. Add to Neo4j graph
    correlation = CorrelationEngine()
    await correlation.add_ioc_to_graph(enriched)

    # 5. Save to PostgreSQL (would be done in actual implementation)
    # This is handled by the API endpoint


async def _correlate_ioc(ioc_id: str) -> list[dict[str, Any]]:
    """Find correlations for an IOC."""
    correlation = CorrelationEngine()
    return await correlation.find_related_iocs(ioc_id, max_depth=3)


async def _update_metrics() -> dict[str, Any]:
    """Update and cache graph metrics."""
    from app.db.redis_db import get_redis

    correlation = CorrelationEngine()
    landscape = await correlation.build_threat_landscape()

    # Cache the results
    redis = await get_redis()
    import json
    await redis.setex(
        "graph:metrics:latest",
        1800,  # 30 minutes
        json.dumps(landscape),
    )

    return landscape
