from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

from app.workers.celery_app import celery_app
from app.db.neo4j_db import get_neo4j, create_relationship


@celery_app.task
def detect_relationships_task():
    """Detect and create relationships between existing nodes."""
    asyncio.run(_detect_relationships())


@celery_app.task
def cleanup_old_data():
    """Clean up old, inactive IOCs and expired data."""
    asyncio.run(_cleanup())


async def _detect_relationships() -> dict[str, Any]:
    """Analyze graph and suggest new relationships."""
    driver = await get_neo4j()

    results = {
        "relationships_created": 0,
        "suggestions": [],
    }

    async with driver.session() as session:
        # Find IOCs sharing same threat actor
        result = await session.run(
            """
            MATCH (a:Actor)-[:INDICATES]->(i1:IOC)
            MATCH (a)-[:INDICATES]->(i2:IOC)
            WHERE i1.id < i2.id
            WITH i1, i2, a
            MERGE (i1)-[r:RELATED_TO]->(i2)
            SET r.common_actor = a.name,
                r.detected_at = datetime()
            RETURN count(r) AS rel_count
            """,
            datetime=datetime.utcnow().isoformat(),
        )
        record = await result.single()
        if record:
            results["relationships_created"] = record["rel_count"]

    return results


async def _cleanup() -> dict[str, Any]:
    """Remove old inactive IOCs and expired data."""
    from app.db.postgres import get_db

    results = {"iocs_deleted": 0}

    async with get_db() as conn:
        # Delete IOCs inactive for over 90 days
        result = await conn.execute(
            """
            DELETE FROM iocs
            WHERE active = FALSE 
            AND last_seen < NOW() - INTERVAL '90 days'
            """
        )
        results["iocs_deleted"] = result

    return results
