from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ========================
# STIX 2.1 Base Models
# ========================

class STIXObject(BaseModel):
    """Base class for all STIX 2.1 objects."""

    type: str
    id: str = Field(..., pattern=r"^[\w]+--[\da-fA-F]{8}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{12}$")
    created: datetime = Field(default_factory=datetime.utcnow)
    modified: datetime = Field(default_factory=datetime.utcnow)
    name: Optional[str] = None
    description: Optional[str] = None
    labels: list[str] = Field(default_factory=list)
    external_references: list[dict[str, Any]] = Field(default_factory=list)

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat().replace("+00:00", "Z")
        }


class Identity(STIXObject):
    """STIX 2.1 Identity object."""

    type: str = "identity"
    identity_class: str = "individual"  # individual, group, organization, class, unknown
    sectors: Optional[list[str]] = None
    contact_information: Optional[str] = None


class MarkingDefinition(BaseModel):
    """STIX 2.1 Marking Definition."""

    type: str = "marking-definition"
    id: str
    created: datetime = Field(default_factory=datetime.utcnow)
    definition_type: str = "statement"
    definition: dict[str, str] = {"statement": "Copyright 2026"}


# ========================
# IOC / Indicator Models
# ========================

class Indicator(STIXObject):
    """STIX 2.1 Indicator object."""

    type: str = "indicator"
    pattern: str  # STIX pattern: [ipv4-addr:value = '198.51.100.0/24']
    pattern_type: str = "stix"  # stix, pcre
    valid_from: datetime = Field(default_factory=datetime.utcnow)
    valid_until: Optional[datetime] = None
    kill_chain_phases: list[dict[str, str]] = Field(default_factory=list)
    confidence: Optional[int] = Field(None, ge=0, le=100)
    indicator_types: list[str] = Field(default_factory=list)


class ObservedData(STIXObject):
    """STIX 2.1 Observed Data object."""

    type: str = "observed-data"
    first_observed: datetime
    last_observed: datetime
    number_observed: int = 1
    objects: dict[str, dict[str, Any]]  # STIX Cyber-observable Objects


# ========================
# Threat Actor Models
# ========================

class ThreatActor(STIXObject):
    """STIX 2.1 Threat Actor object."""

    type: str = "threat-actor"
    threat_actor_types: list[str] = Field(default_factory=list)
    sophistication: Optional[str] = None
    resource_level: Optional[str] = None
    goals: list[str] = Field(default_factory=list)
    methodology: Optional[str] = None
    aliases: list[str] = Field(default_factory=list)


# ========================
# Malware Models
# ========================

class Malware(STIXObject):
    """STIX 2.1 Malware object."""

    type: str = "malware"
    malware_types: list[str] = Field(default_factory=list)
    is_family: bool = False
    aliases: list[str] = Field(default_factory=list)
    kill_chain_phases: list[dict[str, str]] = Field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


# ========================
# Campaign Models
# ========================

class Campaign(STIXObject):
    """STIX 2.1 Campaign object."""

    type: str = "campaign"
    campaign_types: list[str] = Field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    objective: Optional[str] = None


# ========================
# Relationship Model
# ========================

class Relationship(BaseModel):
    """STIX 2.1 Relationship object."""

    type: str = "relationship"
    id: str = Field(..., pattern=r"^relationship--[\da-fA-F]{8}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{12}$")
    created: datetime = Field(default_factory=datetime.utcnow)
    modified: datetime = Field(default_factory=datetime.utcnow)
    relationship_type: str  # uses, indicates, targets, attributed-to, etc.
    description: Optional[str] = None
    source_ref: str  # STIX ID of source object
    target_ref: str  # STIX ID of target object


# ========================
# Bundle (Container)
# ========================

class Bundle(BaseModel):
    """STIX 2.1 Bundle - container for multiple STIX objects."""

    type: str = "bundle"
    id: str = Field(default_factory=lambda: f"bundle--{uuid4()}")
    objects: list[dict[str, Any]] = Field(default_factory=list)


# ========================
# Internal Database Models (Pydantic)
# ========================

class IOCBase(BaseModel):
    """Internal IOC model for database storage."""

    type: str  # ipv4, ipv6, domain, url, hash-md5, hash-sha1, hash-sha256, email
    value: str
    threat_level: str = "medium"  # low, medium, high, critical
    confidence: int = Field(75, ge=0, le=100)
    source: str = "manual"
    active: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)
    stix_id: Optional[str] = None
    attack_mappings: list[dict[str, Any]] = Field(default_factory=list)


class IOCreate(IOCBase):
    """Model for creating a new IOC."""
    pass


class IOCUpdate(BaseModel):
    """Model for updating an IOC."""
    threat_level: Optional[str] = None
    confidence: Optional[int] = Field(None, ge=0, le=100)
    active: Optional[bool] = None
    metadata: Optional[dict[str, Any]] = None


class IOCResponse(IOCBase):
    """Model for IOC response with ID."""
    id: UUID
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


# ========================
# STIX Pattern Helpers
# ========================

def create_ipv4_pattern(ip: str) -> str:
    """Create STIX pattern for IPv4 address."""
    return f"[ipv4-addr:value = '{ip}']"


def create_domain_pattern(domain: str) -> str:
    """Create STIX pattern for domain name."""
    return f"[domain-name:value = '{domain}']"


def create_url_pattern(url: str) -> str:
    """Create STIX pattern for URL."""
    return f"[url:value = '{url}']"


def create_hash_pattern(hash_value: str, hash_type: str = "sha256") -> str:
    """Create STIX pattern for file hash."""
    hash_type_map = {
        "md5": "MD5",
        "sha1": "SHA-1",
        "sha256": "SHA-256",
        "sha512": "SHA-512",
    }
    stix_hash = hash_type_map.get(hash_type.lower(), "SHA-256")
    return f"[file:hashes.'{stix_hash}' = '{hash_value}']"


def generate_stix_id(object_type: str) -> str:
    """Generate a valid STIX 2.1 ID."""
    type_map = {
        "indicator": "indicator",
        "malware": "malware",
        "threat-actor": "threat-actor",
        "campaign": "campaign",
        "relationship": "relationship",
        "identity": "identity",
        "observed-data": "observed-data",
    }
    stix_type = type_map.get(object_type, object_type)
    return f"{stix_type}--{uuid4()}"
