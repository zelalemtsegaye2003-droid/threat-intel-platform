from __future__ import annotations

from neo4j import AsyncGraphDatabase

from app.config import get_settings

async def init_schema():
    """Initialize Neo4j schema with constraints and indexes."""
    settings = get_settings()
    driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password),
    )
    
    async with driver.session() as session:
        # Create constraints
        await session.run("""
            CREATE CONSTRAINT ioc_id_unique IF NOT EXISTS
            FOR (i:IOC) REQUIRE i.id IS UNIQUE
        """)
        
        await session.run("""
            CREATE CONSTRAINT actor_id_unique IF NOT EXISTS
            FOR (a:Actor) REQUIRE a.id IS UNIQUE
        """)
        
        await session.run("""
            CREATE CONSTRAINT malware_id_unique IF NOT EXISTS
            FOR (m:Malware) REQUIRE m.id IS UNIQUE
        """)
        
        await session.run("""
            CREATE CONSTRAINT campaign_id_unique IF NOT EXISTS
            FOR (c:Campaign) REQUIRE c.id IS UNIQUE
        """)
        
        # Create indexes
        await session.run("""
            CREATE INDEX ioc_value IF NOT EXISTS
            FOR (i:IOC) ON (i.value)
        """)
        
        await session.run("""
            CREATE INDEX ioc_type IF NOT EXISTS
            FOR (i:IOC) ON (i.type)
        """)
        
        await session.run("""
            CREATE INDEX actor_name IF NOT EXISTS
            FOR (a:Actor) ON (a.name)
        """)
    
    await driver.close()
    print("Neo4j schema initialized successfully")
