from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from asyncpg import Connection
from typing import Any

from app.db.postgres import get_db
from app.services import EnhancedEnrichmentService, DeduplicationService
from app.models.ioc import IOCCreate, IOCResponse
from app.models.response import DataResponse

router = APIRouter()

# Initialize services
enrichment_svc = EnhancedEnrichmentService()
dedup_svc = DeduplicationService()


@router.post("/enrich/{ioc_id}")
async def enrich_ioc(
    ioc_id: str,
    conn: Connection = Depends(get_db),
):
    """Enrich an existing IOC with additional data."""
    row = await conn.fetchrow("SELECT * FROM iocs WHERE id = $1", ioc_id)
    if not row:
        raise HTTPException(404, "IOC not found")
    
    ioc_data = dict(row)
    
    # Enrich IOC
    enriched = await enrichment_svc.enrich_ioc(ioc_data)
    
    # Update metadata in DB
    await conn.execute(
        "UPDATE iocs SET metadata = $1, updated_at = NOW() WHERE id = $2",
        enriched.get("metadata", {}),
        ioc_id,
    )
    
    return {
        "success": True,
        "message": "IOC enriched successfully",
        "data": enriched,
    }


@router.post("/dedup-check")
async def check_duplicate(
    ioc: IOCCreate,
    conn: Connection = Depends(get_db),
):
    """Check if an IOC is a duplicate."""
    existing = await dedup_svc.find_existing_ioc(
        conn, ioc.value, ioc.type
    )
    
    similar = await dedup_svc.find_similar_iocs(
        conn, ioc.value
    )
    
    return {
        "success": True,
        "data": {
            "is_duplicate": existing is not None,
            "existing": dict(existing) if existing else None,
            "similar": similar[:5],  # Limit to 5 results
        }
    }


@router.post("/bulk-dedup")
async def bulk_dedup(
    iocs: list[IOCCreate],
    conn: Connection = Depends(get_db),
):
    """Process bulk IOCs with deduplication."""
    created, updated = await dedup_svc.check_duplicate_in_batch(conn, iocs)
    
    return {
        "success": True,
        "message": f"{len(created)} created, {len(updated)} updated",
        "data": {
            "created": created,
            "updated": updated,
        }
    }
