#!/usr/bin/env python3
"""
Test script to verify all services are working correctly.
Run: python scripts/test_services.py
"""

from __future__ import annotations

import asyncio
import sys


async def test_postgres():
    """Test PostgreSQL connection."""
    try:
        import asyncpg
        settings = None
        from app.config import get_settings
        settings = get_settings()
        
        conn = await asyncpg.connect(dsn=settings.database_url)
        result = await conn.fetchval("SELECT version()")
        print(f"✓ PostgreSQL: {result[:50]}...")
        await conn.close()
        return True
    except Exception as e:
        print(f"✗ PostgreSQL: {e}")
        return False


async def test_neo4j():
    """Test Neo4j connection."""
    try:
        from neo4j import AsyncGraphDatabase
        from app.config import get_settings
        settings = get_settings()
        
        driver = AsyncGraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
        )
        await driver.verify_connectivity()
        print(f"✓ Neo4j: Connected")
        await driver.close()
        return True
    except Exception as e:
        print(f"✗ Neo4j: {e}")
        return False


async def test_qdrant():
    """Test Qdrant connection."""
    try:
        from qdrant_client import QdrantClient
        from app.config import get_settings
        settings = get_settings()
        
        client = QdrantClient(
            host=settings.qdrant_host,
            port=settings.qdrant_port,
        )
        collections = client.get_collections()
        print(f"✓ Qdrant: {len(collections.collections)} collections")
        return True
    except Exception as e:
        print(f"✗ Qdrant: {e}")
        return False


async def test_redis():
    """Test Redis connection."""
    try:
        import redis.asyncio as redis
        from app.config import get_settings
        settings = get_settings()
        
        client = redis.from_url(settings.redis_url)
        await client.ping()
        print(f"✓ Redis: Connected")
        await client.close()
        return True
    except Exception as e:
        print(f"✗ Redis: {e}")
        return False


async def test_ollama():
    """Test Ollama LLM connection."""
    try:
        import httpx
        from app.config import get_settings
        settings = get_settings()
        
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{settings.ollama_base_url}/api/tags")
            if response.status_code == 200:
                models = response.json().get("models", [])
                print(f"✓ Ollama: {len(models)} models available")
                if models:
                    print(f"  - First model: {models[0].get('name', 'unknown')}")
                return True
        print(f"✗ Ollama: No response from API")
        return False
    except Exception as e:
        print(f"✗ Ollama: {e}")
        return False


async def main():
    """Run all tests."""
    print("=" * 60)
    print("Threat Intelligence Platform - Service Test Suite")
    print("=" * 60)
    print()
    
    # Load settings
    try:
        from app.config import get_settings
        get_settings()
    except Exception as e:
        print(f"✗ Configuration error: {e}")
        print("  Make sure .env file exists and is properly configured.")
        sys.exit(1)
    
    print("Testing services...")
    print("-" * 60)
    
    results = []
    results.append(("PostgreSQL", await test_postgres()))
    results.append(("Neo4j", await test_neo4j()))
    results.append(("Qdrant", await test_qdrant()))
    results.append(("Redis", await test_redis()))
    results.append(("Ollama LLM", await test_ollama()))
    
    print()
    print("-" * 60)
    print("Summary:")
    print("-" * 60)
    
    all_passed = True
    for name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"  {name:20s} {status}")
        if not passed:
            all_passed = False
    
    print()
    if all_passed:
        print("✓ All services are operational!")
        sys.exit(0)
    else:
        print("✗ Some services failed. Check the errors above.")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
