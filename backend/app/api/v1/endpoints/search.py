from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Any

from app.models.response import DataResponse

router = APIRouter()


class SearchQuery(BaseModel):
    query: str
    limit: int = 10
    filters: dict[str, Any] | None = None


class SemanticSearchQuery(BaseModel):
    query: str
    collection: str = "ioc_embeddings"
    limit: int = 10
    score_threshold: float = 0.7


@router.post("/text")
async def text_search(query: SearchQuery):
    """Search IOCs by text query."""
    # This would query PostgreSQL full-text search
    return {
        "success": True,
        "message": "Text search endpoint (implementation pending)",
        "data": {
            "query": query.query,
            "results": []
        }
    }


@router.post("/semantic")
async def semantic_search(query: SemanticSearchQuery):
    """Semantic vector search using Qdrant."""
    from app.db.qdrant_db import get_qdrant
    from sentence_transformers import SentenceTransformer
    
    # Load model and generate embedding
    model = SentenceTransformer('all-MiniLM-L6-v2')
    query_embedding = model.encode(query.query).tolist()
    
    # Search in Qdrant
    client = await get_qdrant()
    results = client.search(
        collection_name=query.collection,
        query_vector=query_embedding,
        limit=query.limit,
        score_threshold=query.score_threshold,
    )
    
    return {
        "success": True,
        "data": {
            "query": query.query,
            "results": [
                {"id": hit.id, "score": hit.score, "payload": hit.payload}
                for hit in results
            ]
        }
    }


@router.post("/stix")
async def stix_search(query: dict[str, Any]):
    """Search using STIX 2.1 patterns."""
    return {
        "success": True,
        "message": "STIX pattern search endpoint (implementation pending)",
        "data": query
    }
