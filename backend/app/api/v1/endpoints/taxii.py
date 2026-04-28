from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Any

from app.models.stix import Bundle
from app.models.response import DataResponse

router = APIRouter()


class TAXIIIngestRequest(BaseModel):
    collection_url: str
    api_key: str | None = None


class TAXIIPushRequest(BaseModel):
    bundle: Bundle
    collection_id: str = "default"


@router.get("/collections")
async def list_taxii_collections():
    """List available TAXII collections."""
    return {
        "success": True,
        "message": "TAXII collections endpoint (implementation pending)",
        "data": {
            "collections": [
                {"id": "default", "title": "Default Collection"},
            ]
        }
    }


@router.post("/push")
async def push_to_taxii(request: TAXIIPushRequest):
    """Push STIX bundle to TAXII collection."""
    return {
        "success": True,
        "message": "TAXII push endpoint (implementation pending)",
        "data": {
            "collection_id": request.collection_id,
            "bundle_id": request.bundle.id,
        }
    }


@router.post("/ingest")
async def ingest_from_taxii(request: TAXIIIngestRequest):
    """Ingest data from TAXII server."""
    return {
        "success": True,
        "message": "TAXII ingest endpoint (implementation pending)",
        "data": {
            "collection_url": request.collection_url,
            "status": "pending"
        }
    }
