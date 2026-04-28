from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from asyncpg import Connection
from typing import Any

from app.db.postgres import get_db
from app.models.response import DataResponse

router = APIRouter()


@router.get("/status")
async def feed_status(
    conn: Connection = Depends(get_db),
):
    """Get status of all feeds."""
    rows = await conn.fetch(
        """
        SELECT id, name, feed_type, enabled, last_ingestion
        FROM feeds
        ORDER BY name
        """
    )
    return {
        "success": True,
        "data": [dict(row) for row in rows]
    }


@router.post("/ingest")
async def trigger_ingestion(
    feed_id: str,
    force: bool = False,
    conn: Connection = Depends(get_db),
):
    """Trigger feed ingestion."""
    # Check if feed exists
    feed = await conn.fetchrow(
        "SELECT * FROM feeds WHERE id = $1",
        feed_id
    )
    if not feed:
        raise HTTPException(404, "Feed not found")
    
    # Here you would typically queue a background job
    # For now, return a placeholder response
    return {
        "success": True,
        "message": f"Ingestion triggered for feed: {feed['name']}",
        "data": {
            "feed_id": feed_id,
            "status": "pending",
            "force": force
        }
    }


@router.post("/register")
async def register_feed(
    name: str,
    url: str | None = None,
    feed_type: str = "taxii",
    config: dict[str, Any] | None = None,
    conn: Connection = Depends(get_db),
):
    """Register a new feed."""
    row = await conn.fetchrow(
        """
        INSERT INTO feeds (name, url, feed_type, config)
        VALUES ($1, $2, $3, $4)
        RETURNING *
        """,
        name, url, feed_type, config or {}
    )
    
    return {
        "success": True,
        "message": "Feed registered successfully",
        "data": dict(row)
    }
