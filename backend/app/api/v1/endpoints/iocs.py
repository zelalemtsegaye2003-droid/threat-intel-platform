from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from asyncpg import Connection
from pydantic import BaseModel
from datetime import datetime
from typing import Any
from fastapi import Request

from app.db.postgres import get_db
from app.models.ioc import IOCCreate, IOCResponse, IOCUpdate
from app.models.response import DataResponse, ListResponse
from app.auth import (
    get_current_user, require_admin, require_analyst, require_viewer,
    log_audit
)

router = APIRouter()


@router.get("/", response_model=ListResponse)
async def list_iocs(
    page: int = 1,
    page_size: int = 50,
    ioc_type: str | None = None,
    threat_level: str | None = None,
    active_only: bool = True,
    conn: Connection = Depends(get_db),
    current_user: dict = Depends(require_viewer),
):
    """List IOCs with filters."""
    offset = (page - 1) * page_size
    
    # Build WHERE clause
    conditions = ["1=1"]
    params = {"limit": page_size, "offset": offset}
    
    if ioc_type:
        conditions.append("type = $type")
        params["type"] = ioc_type
    if threat_level:
        conditions.append("threat_level = $threat_level")
        params["threat_level"] = threat_level
    if active_only:
        conditions.append("active = TRUE")
    
    where_clause = " AND ".join(conditions)
    
    # Get total count
    total = await conn.fetchval(
        f"SELECT COUNT(*) FROM iocs WHERE {where_clause}",
        **params
    )
    
    # Get data
    rows = await conn.fetch(
        f"""
        SELECT id, type, value, threat_level, confidence, source, 
               first_seen, last_seen, active, metadata, stix_id,
               created_at, updated_at
        FROM iocs
        WHERE {where_clause}
        ORDER BY created_at DESC
        LIMIT $limit OFFSET $offset
        """,
        **params
    )
    
    iocs = [dict(row) for row in rows]
    
    return {
        "success": True,
        "data": iocs,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size,
    }


@router.post("/", response_model=DataResponse[IOCResponse])
async def create_ioc(
    ioc: IOCCreate,
    conn: Connection = Depends(get_db),
    current_user: dict = Depends(require_analyst),
    request: Request = None,
):
    """Create a new IOC."""
    # Check for duplicates
    existing = await conn.fetchrow(
        "SELECT id FROM iocs WHERE value = $1 AND type = $2",
        ioc.value, ioc.type
    )
    if existing:
        raise HTTPException(409, "IOC already exists")
    
    # Insert new IOC
    row = await conn.fetchrow(
        """
        INSERT INTO iocs (type, value, threat_level, confidence, source, metadata)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
        """,
        ioc.type, ioc.value, ioc.threat_level, 
        ioc.confidence, ioc.source, ioc.metadata
    )
    
    # Audit log
    await log_audit(
        conn, current_user['username'], "create", "ioc",
        str(row['id']), f"Created {ioc.type}: {ioc.value}",
        request.client.host if request and request.client else None
    )
    
    return {
        "success": True,
        "message": "IOC created successfully",
        "data": dict(row)
    }


@router.get("/{ioc_id}", response_model=DataResponse[IOCResponse])
async def get_ioc(
    ioc_id: str,
    conn: Connection = Depends(get_db),
    current_user: dict = Depends(require_viewer),
):
    """Get IOC details by ID."""
    row = await conn.fetchrow(
        "SELECT * FROM iocs WHERE id = $1",
        ioc_id
    )
    if not row:
        raise HTTPException(404, "IOC not found")
    
    return {
        "success": True,
        "data": dict(row)
    }


@router.put("/{ioc_id}", response_model=DataResponse[IOCResponse])
async def update_ioc(
    ioc_id: str,
    ioc: IOCUpdate,
    conn: Connection = Depends(get_db),
    current_user: dict = Depends(require_analyst),
    request: Request = None,
):
    """Update an IOC."""
    # Build update query dynamically
    updates = []
    params = {"id": ioc_id}
    if ioc.threat_level is not None:
        updates.append("threat_level = $threat_level")
        params["threat_level"] = ioc.threat_level
    if ioc.confidence is not None:
        updates.append("confidence = $confidence")
        params["confidence"] = ioc.confidence
    if ioc.active is not None:
        updates.append("active = $active")
        params["active"] = ioc.active
    if ioc.metadata is not None:
        updates.append("metadata = $metadata")
        params["metadata"] = ioc.metadata
    
    updates.append("updated_at = NOW()")
    
    query = f"""
        UPDATE iocs 
        SET {', '.join(updates)}
        WHERE id = $id
        RETURNING *
    """
    
    row = await conn.fetchrow(query, **params)
    if not row:
        raise HTTPException(404, "IOC not found")
    
    # Audit log
    await log_audit(
        conn, current_user['username'], "update", "ioc",
        ioc_id, f"Updated IOC fields",
        request.client.host if request and request.client else None
    )
    
    return {
        "success": True,
        "message": "IOC updated successfully",
        "data": dict(row)
    }


@router.delete("/{ioc_id}")
async def delete_ioc(
    ioc_id: str,
    conn: Connection = Depends(get_db),
    current_user: dict = Depends(require_analyst),
    request: Request = None,
):
    """Delete an IOC."""
    result = await conn.execute(
        "DELETE FROM iocs WHERE id = $1",
        ioc_id
    )
    if result == "DELETE 0":
        raise HTTPException(404, "IOC not found")
    
    # Audit log
    await log_audit(
        conn, current_user['username'], "delete", "ioc",
        ioc_id, None,
        request.client.host if request and request.client else None
    )
    
    return {
        "success": True,
        "message": "IOC deleted successfully"
    }


@router.post("/bulk", response_model=DataResponse[list])
async def bulk_create_iocs(
    iocs: list[IOCCreate],
    conn: Connection = Depends(get_db),
    current_user: dict = Depends(require_analyst),
    request: Request = None,
):
    """Bulk create IOCs."""
    created = []
    for ioc in iocs:
        try:
            row = await conn.fetchrow(
                """
                INSERT INTO iocs (type, value, threat_level, confidence, source, metadata)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (value, type) DO UPDATE SET
                    last_seen = NOW(),
                    threat_level = EXCLUDED.threat_level
                RETURNING *
                """,
                ioc.type, ioc.value, ioc.threat_level,
                ioc.confidence, ioc.source, ioc.metadata
            )
            if row:
                created.append(dict(row))
        except Exception as e:
            continue  # Skip duplicates/errors
    
    # Audit log
    await log_audit(
        conn, current_user['username'], "bulk_create", "ioc",
        None, f"Bulk created/updated {len(created)} IOCs",
        request.client.host if request and request.client else None
    )
    
    return {
        "success": True,
        "message": f"{len(created)} IOCs created/updated",
        "data": created
    }
