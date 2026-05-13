from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.endpoints import (
    iocs,
    actors,
    malware,
    campaigns,
    feeds,
    search,
    taxii,
    stix,
    analysis,
    dashboard,
)

api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(iocs.router, prefix="/iocs", tags=["IOCs"])
api_router.include_router(actors.router, prefix="/actors", tags=["Threat Actors"])
api_router.include_router(malware.router, prefix="/malware", tags=["Malware"])
api_router.include_router(campaigns.router, prefix="/campaigns", tags=["Campaigns"])
api_router.include_router(feeds.router, prefix="/feeds", tags=["Feeds"])
api_router.include_router(search.router, prefix="/search", tags=["Search"])
api_router.include_router(taxii.router, prefix="/taxii", tags=["TAXII 2.x"])
api_router.include_router(stix.router, prefix="/stix", tags=["STIX 2.1"])
api_router.include_router(analysis.router, prefix="/analysis", tags=["Analysis"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])