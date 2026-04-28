from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from asyncpg import Connection
from typing import Any

from app.db.postgres import get_db
from app.models.ioc import CampaignDB as CampaignCreate
from app.models.response import DataResponse, ListResponse

router = APIRouter()


@router.get("/")
async def list_campaigns(
    page: int = 1,
    page_size: int = 50,
    active_only: bool = True,
    conn: Connection = Depends(get_db),
):
    """List campaigns."""
    offset = (page - 1) * page_size
    
    conditions = ["1=1"]
    if active_only:
        conditions.append("active = TRUE")
    where = " AND ".join(conditions)
    
    total = await conn.fetchval(
        f"SELECT COUNT(*) FROM campaigns WHERE {where}"
    )
    
    rows = await conn.fetch(
        f"""
        SELECT id, name, description, campaign_types, objective,
               first_seen, last_seen, created_at, updated_at
        FROM campaigns
        WHERE {where}
        ORDER BY last_seen DESC NULLS LAST
        LIMIT $1 OFFSET $2
        """,
        page_size, offset
    )
    
    return {
        "success": True,
        "data": [dict(row) for row in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.post("/")
async def create_campaign(
    campaign: CampaignCreate,
    conn: Connection = Depends(get_db),
):
    """Create a new campaign."""
    row = await conn.fetchrow(
        """
        INSERT INTO campaigns (name, description, campaign_types, objective)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
        """,
        campaign.name, campaign.description, 
        campaign.campaign_types, campaign.objective
    )
    
    return {
        "success": True,
        "message": "Campaign created successfully",
        "data": dict(row)
    }


@router.get("/{campaign_id}")
async def get_campaign(
    campaign_id: str,
    conn: Connection = Depends(get_db),
):
    """Get campaign details."""
    row = await conn.fetchrow(
        "SELECT * FROM campaigns WHERE id = $1",
        campaign_id
    )
    if not row:
        raise HTTPException(404, "Campaign not found")
    
    return {
        "success": True,
        "data": dict(row)
    }
