from __future__ import annotations

from pydantic import BaseModel, Field
from typing import Generic, TypeVar, Optional, Any
from datetime import datetime


DataT = TypeVar("DataT")


class ResponseBase(BaseModel):
    """Base response model."""

    success: bool = True
    message: str = "Operation successful"
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class DataResponse(ResponseBase, Generic[DataT]):
    """Generic data response."""

    data: Optional[DataT] = None


class ListResponse(ResponseBase):
    """Generic list response."""

    data: list[Any] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    page_size: int = 50
    total_pages: int = 1


class ErrorResponse(ResponseBase):
    """Error response."""

    success: bool = False
    error_code: Optional[str] = None
    details: Optional[Any] = None


# ========================
# Pagination
# ========================

class PaginationParams(BaseModel):
    """Pagination parameters."""

    page: int = Field(1, ge=1)
    page_size: int = Field(50, ge=1, le=100)
    sort_by: str = "created_at"
    sort_order: str = "desc"  # asc, desc


# ========================
# Search
# ========================

class SearchQuery(BaseModel):
    """Search query model."""

    query: str
    filters: dict[str, Any] = Field(default_factory=dict)
    limit: int = Field(20, ge=1, le=50)
    offset: int = Field(0, ge=0)


class SemanticSearchQuery(BaseModel):
    """Semantic vector search query."""

    query: str
    collection: str = "ioc_embeddings"
    limit: int = Field(10, ge=1, le=50)
    score_threshold: float = Field(0.7, ge=0.0, le=1.0)


# ========================
# Feed Ingestion
# ========================

class FeedIngestRequest(BaseModel):
    """Feed ingestion request."""

    feed_id: str
    force: bool = False


class FeedIngestResponse(ResponseBase):
    """Feed ingestion response."""

    data: dict[str, Any] = {
        "feed_id": "",
        "status": "pending",
        "iocs_added": 0,
        "iocs_updated": 0,
        "errors": [],
    }
