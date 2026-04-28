from __future__ import annotations

from typing import Any, Optional
from datetime import datetime
from uuid import UUID

from app.db.neo4j_db import (
    create_ioc_node,
    create_actor_node,
    create_relationship,
    find_related_nodes,
)


class CorrelationEngine:
    """Graph-based correlation engine for threat intelligence."""

    async def add_ioc_to_graph(self, ioc: dict[str, Any]) -> None:
        """Add IOC node to Neo4j graph."""
        await create_ioc_node({
            "id": str(ioc.get("id", "")),
            "type": ioc.get("type", ""),
            "value": ioc.get("value", ""),
            "threat_level": ioc.get("threat_level", "medium"),
            "source": ioc.get("source", ""),
        })

    async def add_actor_to_graph(self, actor: dict[str, Any]) -> None:
        """Add Threat Actor node to Neo4j graph."""
        await create_actor_node({
            "id": str(actor.get("id", "")),
            "name": actor.get("name", ""),
            "sophistication": actor.get("sophistication"),
            "motivation": actor.get("motivation"),
        })

    async def link_ioc_to_actor(
        self, ioc_id: str, actor_id: str, confidence: int = 75
    ) -> None:
        """Link an IOC to a threat actor."""
        await create_relationship(
            source_id=ioc_id,
            target_id=actor_id,
            rel_type="INDICATES",
            properties={
                "confidence": confidence,
                "linked_at": datetime.utcnow().isoformat(),
            },
        )

    async def link_malware_to_actor(
        self, malware_id: str, actor_id: str
    ) -> None:
        """Link malware to a threat actor (uses/employs)."""
        await create_relationship(
            source_id=actor_id,
            target_id=malware_id,
            rel_type="USES",
        )

    async def link_campaign_to_actor(
        self, campaign_id: str, actor_id: str
    ) -> None:
        """Attribute a campaign to a threat actor."""
        await create_relationship(
            source_id=campaign_id,
            target_id=actor_id,
            rel_type="ATTRIBUTED_TO",
        )

    async def find_related_iocs(
        self, ioc_id: str, max_depth: int = 2
    ) -> list[dict[str, Any]]:
        """Find IOCs related to a given IOC through graph traversal."""
        return await find_related_nodes(
            node_id=ioc_id,
            max_depth=max_depth,
        )

    async def find_attack_paths(
        self, source_ioc_id: str, target_ioc_id: str
    ) -> list[dict[str, Any]]:
        """Find attack paths between two IOCs."""
        from app.db.neo4j_db import get_neo4j

        driver = await get_neo4j()
        async with driver.session() as session:
            result = await session.run(
                """
                MATCH path = shortestPath(
                    (a)-[*]->(b)
                )
                WHERE a.id = $source_id AND b.id = $target_id
                RETURN path
                """,
                source_id=source_ioc_id,
                target_id=target_ioc_id,
            )
            return await result.data()

    async def detect_campaign_patterns(self) -> list[dict[str, Any]]:
        """Detect potential campaign patterns in the graph."""
        from app.db.neo4j_db import get_neo4j

        driver = await get_neo4j()
        async with driver.session() as session:
            # Find clusters of IOCs with shared attributes
            result = await session.run(
                """
                MATCH (i:IOC)-[:INDICATES]->(a:Actor)
                WITH a, collect(i) AS iocs
                WHERE count(i) >= 3
                RETURN a.name AS actor, 
                       count(iocs) AS ioc_count,
                       [i IN iocs | i.value] AS ioc_values
                ORDER BY ioc_count DESC
                LIMIT 10
                """
            )
            return await result.data()

    async def build_threat_landscape(self) -> dict[str, Any]:
        """Build a summary of the threat landscape from the graph."""
        from app.db.neo4j_db import get_neo4j

        driver = await get_neo4j()
        async with driver.session() as session:
            # Count nodes by type
            result = await session.run(
                """
                MATCH (n)
                RETURN labels(n)[0] AS node_type, count(n) AS count
                """
            )
            counts = {record["node_type"]: record["count"] for record in await result.data()}

            # Find most connected actors
            result = await session.run(
                """
                MATCH (a:Actor)-[r]->()
                RETURN a.name AS actor, count(r) AS connections
                ORDER BY connections DESC
                LIMIT 5
                """
            )
            top_actors = await result.data()

            return {
                "node_counts": counts,
                "top_actors": top_actors,
                "generated_at": datetime.utcnow().isoformat(),
            }
