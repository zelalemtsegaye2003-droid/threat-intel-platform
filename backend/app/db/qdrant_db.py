from __future__ import annotations

from qdrant_client import QdrantClient, models
from typing import Any

from app.config import get_settings

settings = get_settings()

_client: QdrantClient | None = None


async def init_qdrant() -> None:
    """Initialize Qdrant client and collections."""
    global _client
    _client = QdrantClient(
        host=settings.qdrant_host,
        port=settings.qdrant_port,
    )
    # Create collections if they don't exist
    await create_collections()


async def get_qdrant() -> QdrantClient:
    """Get Qdrant client instance."""
    if _client is None:
        await init_qdrant()
    return _client


async def create_collections() -> None:
    """Create required collections."""
    if _client is None:
        return

    collections = [
        {
            "name": "ioc_embeddings",
            "vectors": models.VectorParams(size=384, distance=models.Distance.COSINE),
            "payload_schema": {
                "ioc_id": models.PayloadSchemaType.KEYWORD,
                "ioc_type": models.PayloadSchemaType.KEYWORD,
                "value": models.PayloadSchemaType.TEXT,
                "threat_level": models.PayloadSchemaType.KEYWORD,
                "source": models.PayloadSchemaType.KEYWORD,
            },
        },
        {
            "name": "report_embeddings",
            "vectors": models.VectorParams(size=384, distance=models.Distance.COSINE),
            "payload_schema": {
                "report_id": models.PayloadSchemaType.KEYWORD,
                "title": models.PayloadSchemaType.TEXT,
                "summary": models.PayloadSchemaType.TEXT,
            },
        },
    ]

    for collection in collections:
        try:
            _client.get_collection(collection["name"])
        except Exception:
            _client.create_collection(
                collection_name=collection["name"],
                vectors_config=collection["vectors"],
                on_disk_payload=True,
            )


async def upsert_point(
    collection: str,
    point_id: str,
    vector: list[float],
    payload: dict[str, Any],
) -> None:
    """Insert or update a point in Qdrant."""
    if _client is None:
        await init_qdrant()
    _client.upsert(
        collection_name=collection,
        points=[
            models.PointStruct(
                id=point_id,
                vector=vector,
                payload=payload,
            )
        ],
    )


async def search_similar(
    collection: str,
    query_vector: list[float],
    limit: int = 10,
    score_threshold: float = 0.7,
) -> list[dict]:
    """Search for similar vectors in Qdrant."""
    if _client is None:
        await init_qdrant()
    results = _client.search(
        collection_name=collection,
        query_vector=query_vector,
        limit=limit,
        score_threshold=score_threshold,
    )
    return [
        {"id": hit.id, "score": hit.score, "payload": hit.payload}
        for hit in results
    ]


async def close_qdrant() -> None:
    """Close Qdrant client."""
    global _client
    if _client:
        _client.close()
        _client = None
