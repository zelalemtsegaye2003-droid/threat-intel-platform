from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()

from app.api.v1.endpoints import iocs, actors, malware, campaigns

__all__ = ["router"]
