from __future__ import annotations

from typing import Any
from datetime import datetime
from uuid import UUID

from asyncpg import Connection

from app.db.postgres import get_db


class DeduplicationService:
    """IOC deduplication and correlation service."""

    async def find_existing_ioc(
        self, conn: Connection, value: str, ioc_type: str
    ) -> dict[str, Any] | None:
        """Find an existing IOC by value and type."""
        row = await conn.fetchrow(
            "SELECT * FROM iocs WHERE value = $1 AND type = $2",
            value, ioc_type,
        )
        if row:
            return dict(row)
        return None

    async def find_similar_iocs(
        self,
        conn: Connection,
        value: str,
        threshold: float = 0.85,
    ) -> list[dict[str, Any]]:
        """Find IOCs that are similar (for fuzzy matching)."""
        # Simple similarity: same first 24 chars for hashes, same /24 for IPs
        similar = []

        # For IPs, check same /24 network
        if "." in value and value.replace(".", "").isdigit():
            parts = value.split(".")
            if len(parts) == 4:
                network = ".".join(parts[:3]) + ".%"
                rows = await conn.fetch(
                    "SELECT * FROM iocs WHERE value LIKE $1 AND type = 'ipv4'",
                    network,
                )
                similar.extend([dict(row) for row in rows])

        # For domains, check parent domain
        if "." in value and "ip" not in value:
            parts = value.split(".")
            if len(parts) >= 2:
                parent = ".".join(parts[-2:])
                rows = await conn.fetch(
                    "SELECT * FROM iocs WHERE value LIKE $1 OR value = $2",
                    f"%.{parent}",
                    parent,
                )
                similar.extend([dict(row) for row in rows])

        return similar

    async def merge_ioc_data(
        self,
        existing: dict[str, Any],
        new_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Merge new IOC data with existing."""
        merged = existing.copy()

        # Update last_seen
        merged["last_seen"] = datetime.utcnow()

        # Merge metadata
        if "metadata" in new_data:
            if "metadata" not in merged:
                merged["metadata"] = {}
            merged["metadata"].update(new_data.get("metadata", {}))

        # Update threat level (use highest)
        threat_levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        existing_level = threat_levels.get(existing.get("threat_level", "medium"), 1)
        new_level = threat_levels.get(new_data.get("threat_level", "medium"), 1)
        if new_level > existing_level:
            merged["threat_level"] = new_data["threat_level"]

        # Update confidence (average)
        existing_conf = existing.get("confidence", 0)
        new_conf = new_data.get("confidence", 0)
        merged["confidence"] = (existing_conf + new_conf) // 2

        return merged

    async def create_or_update_ioc(
        self,
        conn: Connection,
        ioc_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Create new IOC or update existing."""
        existing = await self.find_existing_ioc(
            conn, ioc_data["value"], ioc_data["type"]
        )

        if existing:
            # Update existing
            merged = await self.merge_ioc_data(existing, ioc_data)
            await conn.execute(
                """UPDATE iocs 
                SET last_seen = $1, threat_level = $2, confidence = $3, 
                    metadata = $4, updated_at = NOW()
                WHERE id = $5""",
                merged["last_seen"],
                merged["threat_level"],
                merged["confidence"],
                merged["metadata"],
                existing["id"],
            )
            return {**merged, "id": existing["id"], "action": "updated"}
        else:
            # Create new
            row = await conn.fetchrow(
                """INSERT INTO iocs (type, value, threat_level, confidence, source, metadata)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING *""",
                ioc_data["type"],
                ioc_data["value"],
                ioc_data.get("threat_level", "medium"),
                ioc_data.get("confidence", 75),
                ioc_data.get("source", "manual"),
                ioc_data.get("metadata", {}),
            )
            return {**dict(row), "action": "created"}

    async def check_duplicate_in_batch(
        self,
        conn: Connection,
        iocs: list[dict[str, Any]],
    ) -> tuple[list[dict], list[dict]]:
        """Process a batch of IOCs, handling duplicates."""
        created = []
        updated = []

        for ioc in iocs:
            result = await self.create_or_update_ioc(conn, ioc)
            if result["action"] == "created":
                created.append(result)
            else:
                updated.append(result)

        return created, updated

    async def find_related_by_hash(
        self,
        conn: Connection,
        file_hash: str,
    ) -> list[dict[str, Any]]:
        """Find IOCs related to a file hash (same malware family)."""
        rows = await conn.fetch(
            """SELECT i.* FROM iocs i
            WHERE i.metadata->>'hash_info' LIKE $1
            OR i.value = $2""",
            f"%{file_hash}%",
            file_hash,
        )
        return [dict(row) for row in rows]

    async def find_related_by_actor(
        self,
        conn: Connection,
        actor_name: str,
    ) -> list[dict[str, Any]]:
        """Find IOCs associated with a threat actor."""
        # This would query Neo4j in full implementation
        # For now, search by metadata
        rows = await conn.fetch(
            """SELECT i.* FROM iocs i
            WHERE i.metadata->>'actor' ILIKE $1
            OR i.source ILIKE $2""",
            f"%{actor_name}%",
            f"%{actor_name}%",
        )
        return [dict(row) for row in rows]
