from __future__ import annotations

from fastapi import APIRouter, Depends
from asyncpg import Connection
from pydantic import BaseModel
from typing import Optional

from app.db.postgres import get_db

router = APIRouter()


class ActorCreate(BaseModel):
    name: str
    aliases: list[str] = []
    actor_types: list[str] = []
    sophistication: Optional[str] = None
    resource_level: Optional[str] = None
    goals: list[str] = []
    motivation: Optional[str] = None
    description: Optional[str] = None


class ActorResponse(ActorCreate):
    id: str
    active: bool = True
    stix_id: Optional[str] = None
    created_at: str
    updated_at: str


@router.get("/")
async def list_actors(
    page: int = 1,
    page_size: int = 50,
    active_only: bool = True,
    conn: Connection = Depends(get_db),
):
    """List threat actors."""
    offset = (page - 1) * page_size
    
    conditions = ["1=1"]
    if active_only:
        conditions.append("active = TRUE")
    
    where = " AND ".join(conditions)
    
    total = await conn.fetchval(
        f"SELECT COUNT(*) FROM threat_actors WHERE {where}"
    )
    
    rows = await conn.fetch(
        f"""
        SELECT id, name, aliases, actor_types, sophistication, 
               resource_level, goals, motivation, description,
               active, stix_id, created_at, updated_at
        FROM threat_actors
        WHERE {where}
        ORDER BY name
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
async def create_actor(
    actor: ActorCreate,
    conn: Connection = Depends(get_db),
):
    """Create a new threat actor."""
    row = await conn.fetchrow(
        """
        INSERT INTO threat_actors 
            (name, aliases, actor_types, sophistication, resource_level, goals, motivation, description)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING *
        """,
        actor.name, actor.aliases, actor.actor_types,
        actor.sophistication, actor.resource_level, actor.goals,
        actor.motivation, actor.description
    )
    
    return {
        "success": True,
        "message": "Threat actor created",
        "data": dict(row)
    }


@router.get("/{actor_id}")
async def get_actor(
    actor_id: str,
    conn: Connection = Depends(get_db),
):
    """Get threat actor details."""
    row = await conn.fetchrow(
        "SELECT * FROM threat_actors WHERE id = $1",
        actor_id
    )
    if not row:
        from fastapi import HTTPException
        raise HTTPException(404, "Threat actor not found")
    return {
        "success": True,
        "data": dict(row)
    }


@router.get("/{actor_id}/graph")
async def get_actor_graph(
    actor_id: str,
    depth: int = 2,
    conn: Connection = Depends(get_db),
):
    """Get threat actor relationship graph."""
    from app.db.neo4j_db import find_related_nodes
    
    graph_data = await find_related_nodes(actor_id, max_depth=depth)
    
    return {
        "success": True,
        "data": graph_data
    }
