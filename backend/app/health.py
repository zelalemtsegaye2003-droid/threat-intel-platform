from __future__ import annotations

from typing import Any
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from app.db.postgres import get_db, close_db
from app.db.neo4j_db import get_neo4j, close_neo4j
from app.db.qdrant_db import get_qdrant, close_qdrant
from app.db.redis_db import get_redis, close_redis
from app.logging_config import get_logger

logger = get_logger(__name__)

health_router = APIRouter(tags=["Health"])


@health_router.get("/health", summary="Overall health check")
async def health_check() -> dict[str, Any]:
    """Quick health check - returns 200 if API is alive."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "version": "0.1.0",
    }


@health_router.get("/health/deep", summary="Deep health check with all services")
async def deep_health_check() -> dict[str, Any]:
    """Comprehensive health check verifying all database connections."""
    results = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "services": {},
    }

    # Check PostgreSQL
    try:
        conn = await get_db().__anext__()
        await conn.execute("SELECT 1")
        results["services"]["postgres"] = {"status": "healthy", "type": "relational"}
        logger.info("health_postgres_ok")
    except Exception as e:
        results["services"]["postgres"] = {"status": "unhealthy", "error": str(e)}
        results["status"] = "degraded"
        logger.error("health_postgres_failed", error=str(e))

    # Check Neo4j
    try:
        driver = await get_neo4j()
        async with driver.session() as session:
            await session.run("RETURN 1")
        results["services"]["neo4j"] = {"status": "healthy", "type": "graph"}
        logger.info("health_neo4j_ok")
    except Exception as e:
        results["services"]["neo4j"] = {"status": "unhealthy", "error": str(e)}
        results["status"] = "degraded"
        logger.error("health_neo4j_failed", error=str(e))

    # Check Qdrant
    try:
        client = await get_qdrant()
        collections = client.get_collections()
        results["services"]["qdrant"] = {
            "status": "healthy",
            "type": "vector",
            "collections": len(collections.collections),
        }
        logger.info("health_qdrant_ok")
    except Exception as e:
        results["services"]["qdrant"] = {"status": "unhealthy", "error": str(e)}
        results["status"] = "degraded"
        logger.error("health_qdrant_failed", error=str(e))

    # Check Redis
    try:
        redis = await get_redis()
        await redis.ping()
        results["services"]["redis"] = {
            "status": "healthy",
            "type": "cache",
            "connected_clients": await redis.info("clients"),
        }
        logger.info("health_redis_ok")
    except Exception as e:
        results["services"]["redis"] = {"status": "unhealthy", "error": str(e)}
        results["status"] = "degraded"
        logger.error("health_redis_failed", error=str(e))

    # Check RabbitMQ (via management API if available)
    try:
        import httpx
        rmq_url = "http://rabbitmq:15672/api/overview"
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(rmq_url)
            if response.status_code == 200:
                data = response.json()
                results["services"]["rabbitmq"] = {
                    "status": "healthy",
                    "type": "messaging",
                    "queue_count": data.get("queue_totals", {}).get("queues", 0),
                }
                logger.info("health_rabbitmq_ok")
            else:
                raise Exception(f"HTTP {response.status_code}")
    except Exception as e:
        results["services"]["rabbitmq"] = {
            "status": "unhealthy" if "error" not in str(e).lower() else "unreachable",
            "error": str(e)[:200],
        }
        results["status"] = "degraded"
        logger.error("health_rabbitmq_failed", error=str(e))

    # Set overall status
    unhealthy_count = sum(
        1 for s in results["services"].values() if s.get("status") != "healthy"
    )
    if unhealthy_count > 0:
        results["status"] = "degraded" if unhealthy_count < len(results["services"]) else "unhealthy"

    return results