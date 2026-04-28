from __future__ import annotations

from neo4j import AsyncGraphDatabase, AsyncDriver
from typing import Any

from app.config import get_settings

settings = get_settings()

_driver: AsyncDriver | None = None


async def init_neo4j() -> None:
    """Initialize Neo4j connection."""
    global _driver
    _driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password),
    )
    # Verify connectivity
    await _driver.verify_connectivity()


async def get_neo4j() -> AsyncDriver:
    """Get Neo4j driver instance."""
    if _driver is None:
        await init_neo4j()
    return _driver


async def close_neo4j() -> None:
    """Close Neo4j driver."""
    global _driver
    if _driver:
        await _driver.close()
        _driver = None


# ========================
# Graph Operations
# ========================

async def create_ioc_node(ioc_data: dict[str, Any]) -> None:
    """Create IOC node in Neo4j."""
    driver = await get_neo4j()
    async with driver.session() as session:
        await session.run("""
            MERGE (i:IOC {id: $id})
            SET i.type = $type,
                i.value = $value,
                i.threat_level = $threat_level,
                i.source = $source,
                i.first_seen = datetime()
            """, **ioc_data)


async def create_actor_node(actor_data: dict[str, Any]) -> None:
    """Create Threat Actor node in Neo4j."""
    driver = await get_neo4j()
    async with driver.session() as session:
        await session.run("""
            MERGE (a:Actor {id: $id})
            SET a.name = $name,
                a.sophistication = $sophistication,
                a.motivation = $motivation
            """, **actor_data)


async def create_relationship(
    source_id: str,
    target_id: str,
    rel_type: str,
    properties: dict[str, Any] | None = None,
) -> None:
    """Create relationship between two nodes."""
    driver = await get_neo4j()
    props = properties or {}
    async with driver.session() as session:
        await session.run(f"""
            MATCH (a {{id: $source_id}})
            MATCH (b {{id: $target_id}})
            MERGE (a)-[r:{rel_type}]->(b)
            SET r += $props
            """,
            source_id=source_id,
            target_id=target_id,
            props=props,
        )


async def find_related_nodes(
    node_id: str,
    rel_types: list[str] | None = None,
    max_depth: int = 2,
) -> list[dict]:
    """Find nodes related to a given node."""
    driver = await get_neo4j()
    rel_pattern = ":".join(rel_types) if rel_types else ""
    query = f"""
        MATCH (n {{id: $node_id}})
        CALL apoc.path.expand(
            n,
            "{rel_pattern}|*",
            NULL,
            {{minLevel: 1, maxLevel: $max_depth}}
        ) YIELD path
        WITH [node IN nodes(path) WHERE node <> n | node] AS related
        UNWIND related AS r
        RETURN DISTINCT r
    """
    async with driver.session() as session:
        result = await session.run(query, node_id=node_id, max_depth=max_depth)
        return await result.data()
