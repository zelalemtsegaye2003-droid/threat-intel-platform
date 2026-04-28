#!/usr/bin/env python3
"""
Initialize Qdrant collections for Threat Intelligence Platform.
Run this after Qdrant is up and running.
"""

from __future__ import annotations

import sys
from qdrant_client import QdrantClient, models


def init_qdrant_collections():
    """Create required Qdrant collections."""
    client = QdrantClient(host="localhost", port=6333)
    
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
        {
            "name": "actor_embeddings",
            "vectors": models.VectorParams(size=384, distance=models.Distance.COSINE),
            "payload_schema": {
                "actor_id": models.PayloadSchemaType.KEYWORD,
                "name": models.PayloadSchemaType.TEXT,
                "sophistication": models.PayloadSchemaType.KEYWORD,
            },
        },
    ]

    for collection in collections:
        try:
            client.get_collection(collection_name=collection["name"])
            print(f"Collection '{collection['name']}' already exists.")
        except Exception:
            # Collection doesn't exist, create it
            client.create_collection(
                collection_name=collection["name"],
                vectors_config=collection["vectors"],
            )
            
            # Set payload schema
            if "payload_schema" in collection:
                for field_name, field_type in collection["payload_schema"].items():
                    try:
                        client.create_payload_index(
                            collection_name=collection["name"],
                            field_name=field_name,
                            field_schema=field_type,
                        )
                    except Exception as e:
                        print(f"  Warning: Could not create index for {field_name}: {e}")
            
            print(f"✓ Created collection '{collection['name']}'")

    print("\n✓ Qdrant initialization complete!")


def test_qdrant_connection():
    """Test Qdrant connection and basic operations."""
    try:
        client = QdrantClient(host="localhost", port=6333)
        
        # Test connection
        collections = client.get_collections()
        print(f"✓ Connected to Qdrant. Found {len(collections.collections)} collections.")
        
        # List collections
        for collection in collections.collections:
            info = client.get_collection(collection.name)
            print(f"  - {collection.name}: {info.points_count} points")
        
        return True
    except Exception as e:
        print(f"✗ Failed to connect to Qdrant: {e}")
        return False


if __name__ == "__main__":
    print("=" * 50)
    print("Qdrant Initialization for Threat Intelligence Platform")
    print("=" * 50)
    
    # Test connection first
    print("\n1. Testing Qdrant connection...")
    if not test_qdrant_connection():
        print("\n✗ Qdrant is not available. Make sure it's running:")
        print("  docker-compose up -d qdrant")
        sys.exit(1)
    
    # Initialize collections
    print("\n2. Initializing collections...")
    init_qdrant_collections()
    
    print("\n" + "=" * 50)
    print("Done! You can now use Qdrant for vector search.")
    print("=" * 50)
