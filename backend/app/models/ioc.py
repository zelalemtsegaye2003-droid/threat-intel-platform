from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, Field
from typing import Optional, Any


# ========================
# Database IOC Models
# ========================

class IOCDB(BaseModel):
    """Database schema for IOC storage."""

    id: UUID = Field(default_factory=uuid4)
    type: str
    value: str
    threat_level: str = "medium"
    confidence: int = Field(75, ge=0, le=100)
    source: str = "manual"
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    active: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)
    stix_id: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


# ========================
# Threat Actor DB Models
# ========================

class ActorDB(BaseModel):
    """Database schema for Threat Actors."""

    id: UUID = Field(default_factory=uuid4)
    name: str
    aliases: list[str] = Field(default_factory=list)
    actor_types: list[str] = Field(default_factory=list)
    sophistication: Optional[str] = None
    resource_level: Optional[str] = None
    goals: list[str] = Field(default_factory=list)
    motivation: Optional[str] = None
    description: Optional[str] = None
    stix_id: Optional[str] = None
    active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


# ========================
# Malware DB Models
# ========================

class MalwareDB(BaseModel):
    """Database schema for Malware families."""

    id: UUID = Field(default_factory=uuid4)
    name: str
    aliases: list[str] = Field(default_factory=list)
    malware_types: list[str] = Field(default_factory=list)
    is_family: bool = False
    description: Optional[str] = None
    stix_id: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


# ========================
# Campaign DB Models
# ========================

class CampaignDB(BaseModel):
    """Database schema for Campaigns."""

    id: UUID = Field(default_factory=uuid4)
    name: str
    description: Optional[str] = None
    campaign_types: list[str] = Field(default_factory=list)
    objective: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    active: bool = True
    stix_id: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


# ========================
# Feed Models
# ========================

class FeedDB(BaseModel):
    """Database schema for External Feeds."""

    id: UUID = Field(default_factory=uuid4)
    name: str
    url: Optional[str] = None
    feed_type: str = "taxii"  # taxii, rss, api, csv
    enabled: bool = True
    last_ingestion: Optional[datetime] = None
    config: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)


# ========================
# ATT&CK Mapping Models
# ========================

class AttackMappingDB(BaseModel):
    """Database schema for MITRE ATT&CK mappings."""

    id: UUID = Field(default_factory=uuid4)
    ioc_id: UUID
    technique_id: str  # T1059, T1105, etc.
    tactic: str  # initial-access, execution, persistence, etc.
    technique_name: Optional[str] = None
    confidence: int = Field(75, ge=0, le=100)
    source: str = "manual"
    created_at: datetime = Field(default_factory=datetime.utcnow())
