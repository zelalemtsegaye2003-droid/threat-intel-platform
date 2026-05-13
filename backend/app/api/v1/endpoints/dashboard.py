from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from asyncpg import Connection

from app.db.postgres import get_db
from app.auth import require_viewer

router = APIRouter()


@router.get("/summary")
async def get_platform_summary(conn: Connection = Depends(get_db), _: dict = Depends(require_viewer)):
    """Get platform summary statistics for the dashboard."""
    # IOC counts by type
    ioc_types = await conn.fetch(
        "SELECT type, COUNT(*) as count FROM iocs WHERE active = TRUE GROUP BY type"
    )

    # IOC counts by threat level
    threat_levels = await conn.fetch(
        "SELECT threat_level, COUNT(*) as count FROM iocs WHERE active = TRUE GROUP BY threat_level"
    )

    # Total counts
    total_iocs = await conn.fetchval("SELECT COUNT(*) FROM iocs WHERE active = TRUE")
    total_actors = await conn.fetchval("SELECT COUNT(*) FROM threat_actors WHERE active = TRUE")
    total_malware = await conn.fetchval("SELECT COUNT(*) FROM malware WHERE active = TRUE")
    total_campaigns = await conn.fetchval("SELECT COUNT(*) FROM campaigns WHERE active = TRUE")
    total_feeds = await conn.fetchval("SELECT COUNT(*) FROM feeds")
    total_users = await conn.fetchval("SELECT COUNT(*) FROM users WHERE is_active = TRUE")

    # Critical/High IOCs
    critical_count = await conn.fetchval(
        "SELECT COUNT(*) FROM iocs WHERE active = TRUE AND threat_level = 'critical'"
    )
    high_count = await conn.fetchval(
        "SELECT COUNT(*) FROM iocs WHERE active = TRUE AND threat_level = 'high'"
    )
    medium_count = await conn.fetchval(
        "SELECT COUNT(*) FROM iocs WHERE active = TRUE AND threat_level = 'medium'"
    )
    low_count = await conn.fetchval(
        "SELECT COUNT(*) FROM iocs WHERE active = TRUE AND threat_level = 'low'"
    )

    # Recent activity (last 10 audit logs with usernames)
    recent_activity = await conn.fetch(
        """SELECT a.action, a.resource, a.resource_id, a.timestamp, a.username
           FROM audit_logs a
           ORDER BY a.timestamp DESC
           LIMIT 10"""
    )

    # Time series: IOC creation per day for last 30 days
    ioc_trends = await conn.fetch(
        """
        SELECT
            DATE(created_at) as date,
            COUNT(*) as count
        FROM iocs
        WHERE created_at >= NOW() - INTERVAL '30 days'
        GROUP BY DATE(created_at)
        ORDER BY date
        """
    )

    # Map query results to serializable formats
    ioc_by_type = {row["type"]: row["count"] for row in ioc_types}
    ioc_by_threat = {row["threat_level"]: row["count"] for row in threat_levels}
    activity = [
        {
            "time": row["timestamp"].isoformat() if hasattr(row["timestamp"], "isoformat") else str(row["timestamp"]),
            "action": row["action"],
            "resource": row["resource"],
            "detail": f"{row['resource']}: {row['resource_id']}" if row["resource_id"] else row["resource"],
            "username": row["username"] or "system",
        }
        for row in recent_activity
    ]
    trends = [
        {"date": row["date"].isoformat() if hasattr(row["date"], "isoformat") else str(row["date"]), "iocs": row["count"]}
        for row in ioc_trends
    ]

    return {
        "success": True,
        "data": {
            "totalIocs": total_iocs,
            "totalActors": total_actors,
            "totalMalware": total_malware,
            "totalCampaigns": total_campaigns,
            "totalFeeds": total_feeds,
            "totalUsers": total_users,
            "criticalCount": critical_count,
            "highCount": high_count,
            "mediumCount": medium_count,
            "lowCount": low_count,
            "iocByType": ioc_by_type,
            "iocByThreatLevel": ioc_by_threat,
            "recentActivity": activity,
            "iocTrends": trends,
            "topIocs": (await conn.fetch(
                "SELECT value, type, threat_level FROM iocs WHERE active = TRUE ORDER BY confidence DESC LIMIT 5"
            )) if total_iocs > 0 else [],
        },
    }


@router.get("/health")
async def health_check():
    """Quick health check endpoint."""
    return {"status": "ok"}