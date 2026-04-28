from __future__ import annotations

import redis.asyncio as redis
from redis.asyncio import Redis
from typing import Any

from app.config import get_settings

settings = get_settings()

_client: Redis | None = None


async def init_redis() -> None:
    """Initialize Redis connection."""
    global _client
    _client = redis.from_url(
        settings.redis_url,
        decode_responses=True,
    )
    # Test connection
    await _client.ping()


async def get_redis() -> Redis:
    """Get Redis client instance."""
    if _client is None:
        await init_redis()
    return _client


async def close_redis() -> None:
    """Close Redis connection."""
    global _client
    if _client:
        await _client.aclose()
        _client = None


# ========================
# Cache Operations
# ========================

async def cache_set(key: str, value: Any, ttl: int = 3600) -> None:
    """Set a value in cache with TTL."""
    client = await get_redis()
    await client.setex(key, ttl, str(value))


async def cache_get(key: str) -> str | None:
    """Get a value from cache."""
    client = await get_redis()
    return await client.get(key)


async def cache_delete(key: str) -> None:
    """Delete a value from cache."""
    client = await get_redis()
    await client.delete(key)


# ========================
# Session Management
# ========================

async def store_session(session_id: str, user_data: dict[str, Any]) -> None:
    """Store user session."""
    await cache_set(f"session:{session_id}", user_data, ttl=86400)  # 24 hours


async def get_session(session_id: str) -> dict[str, Any] | None:
    """Retrieve user session."""
    client = await get_redis()
    data = await client.get(f"session:{session_id}")
    if data:
        import json
        return json.loads(data)
    return None


# ========================
# Pub/Sub for Real-time Updates
# ========================

async def publish_event(channel: str, event_data: dict[str, Any]) -> None:
    """Publish event to channel."""
    client = await get_redis()
    import json
    await client.publish(channel, json.dumps(event_data))


async def subscribe_to_channel(channel: str):
    """Subscribe to a Redis channel for real-time updates."""
    client = await get_redis()
    pubsub = client.pubsub()
    await pubsub.subscribe(channel)
    return pubsub
