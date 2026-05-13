from __future__ import annotations

import asyncpg
from asyncpg import Pool
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from app.config import get_settings

settings = get_settings()

# Global connection pool
_pool: Pool | None = None


async def init_db() -> None:
    """Initialize database connection pool."""
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(
            dsn=settings.database_url,
            min_size=5,
            max_size=20,
            command_timeout=60,
        )
        # Create tables if not exist
        await create_tables()


async def get_db() -> AsyncGenerator[asyncpg.Connection, None]:
    """Dependency for database connection."""
    if _pool is None:
        await init_db()
    async with _pool.acquire() as conn:
        yield conn


async def create_tables() -> None:
    """Create database tables if they don't exist."""
    async with _pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                type VARCHAR(50) NOT NULL,
                value TEXT NOT NULL,
                threat_level VARCHAR(20) NOT NULL DEFAULT 'medium',
                confidence INTEGER CHECK (confidence >= 0 AND confidence <= 100),
                source VARCHAR(255),
                first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                active BOOLEAN DEFAULT TRUE,
                metadata JSONB DEFAULT '{}',
                stix_id VARCHAR(255),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                UNIQUE(value, type)
            );

            CREATE TABLE IF NOT EXISTS threat_actors (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name VARCHAR(255) NOT NULL UNIQUE,
                aliases TEXT[],
                actor_types TEXT[],
                sophistication VARCHAR(100),
                resource_level VARCHAR(100),
                goals TEXT[],
                motivation VARCHAR(255),
                description TEXT,
                stix_id VARCHAR(255),
                active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS malware (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name VARCHAR(255) NOT NULL,
                aliases TEXT[],
                malware_types TEXT[],
                is_family BOOLEAN DEFAULT FALSE,
                description TEXT,
                stix_id VARCHAR(255),
                first_seen TIMESTAMP WITH TIME ZONE,
                last_seen TIMESTAMP WITH TIME ZONE,
                active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS campaigns (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name VARCHAR(255) NOT NULL,
                description TEXT,
                campaign_types TEXT[],
                objective TEXT,
                first_seen TIMESTAMP WITH TIME ZONE,
                last_seen TIMESTAMP WITH TIME ZONE,
                active BOOLEAN DEFAULT TRUE,
                stix_id VARCHAR(255),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS feeds (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name VARCHAR(255) NOT NULL,
                url TEXT,
                feed_type VARCHAR(50) DEFAULT 'taxii',
                enabled BOOLEAN DEFAULT TRUE,
                last_ingestion TIMESTAMP WITH TIME ZONE,
                config JSONB DEFAULT '{}',
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS attack_mappings (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                ioc_id UUID REFERENCES iocs(id) ON DELETE CASCADE,
                technique_id VARCHAR(20),
                tactic VARCHAR(50),
                technique_name VARCHAR(255),
                confidence INTEGER CHECK (confidence >= 0 AND confidence <= 100),
                source VARCHAR(255) DEFAULT 'manual',
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                UNIQUE(ioc_id, technique_id)
            );

            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                hashed_password VARCHAR(255) NOT NULL,
                role VARCHAR(20) DEFAULT 'viewer',
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                last_login TIMESTAMP WITH TIME ZONE
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                username VARCHAR(50),
                action VARCHAR(50) NOT NULL,
                resource VARCHAR(50) NOT NULL,
                resource_id VARCHAR(100),
                details TEXT,
                ip_address VARCHAR(45),
                timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );

            CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
            CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
            CREATE INDEX IF NOT EXISTS idx_iocs_threat_level ON iocs(threat_level);
            CREATE INDEX IF NOT EXISTS idx_iocs_active ON iocs(active);
            CREATE INDEX IF NOT EXISTS idx_actors_name ON threat_actors(name);
            CREATE INDEX IF NOT EXISTS idx_malware_name ON malware(name);
            CREATE INDEX IF NOT EXISTS idx_campaigns_name ON campaigns(name);
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(username);
        """)


async def close_db() -> None:
    """Close database connection pool."""
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


async def init_security_db() -> None:
    """Initialize security tables (users, audit_logs).
    Now handled by Alembic migrations — this is a no-op for backward compatibility."""
