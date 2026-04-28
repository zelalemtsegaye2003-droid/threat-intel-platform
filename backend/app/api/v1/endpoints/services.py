from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from typing import Any

from app.services import (
    EnhancedEnrichmentService,
    LLMAnalysisService,
    EnhancedAttackMapper,
    DeduplicationService,
)
from app.services.correlation import CorrelationEngine
from app.models.response import DataResponse

router = APIRouter()


@router.get("/status")
async def service_status():
    """Get status of all services."""
    return {
        "success": True,
        "data": {
            "enrichment": "EnhancedEnrichmentService available",
            "llm": "LLMAnalysisService available (Ollama)",
            "attack_mapper": "EnhancedAttackMapper with ATT&CK",
            "deduplication": "DeduplicationService available",
            "correlation": "CorrelationEngine with Neo4j graph",
        }
    }


@router.post("/test-enrichment")
async def test_enrichment(ioc: dict[str, Any]):
    """Test enrichment pipeline."""
    service = EnhancedEnrichmentService()
    result = await service.enrich_ioc(ioc)
    await service.close()
    
    return {
        "success": True,
        "message": "Enrichment test complete",
        "data": result,
    }


@router.post("/test-llm")
async def test_llm(prompt: str, max_tokens: int = 512):
    """Test LLM generation."""
    service = LLMAnalysisService()
    result = await service.ollama.generate(
        prompt=prompt,
        max_tokens=max_tokens,
    )
    await service.close()
    
    return {
        "success": True,
        "message": "LLM test complete",
        "data": {"response": result},
    }


@router.post("/test-attack-mapping")
async def test_attack_mapping(ioc: dict[str, Any]):
    """Test ATT&CK mapping."""
    mapper = EnhancedAttackMapper()
    techniques = await mapper.map_ioc_to_techniques(ioc)
    await mapper.close()
    
    return {
        "success": True,
        "message": f"Found {len(techniques)} technique mappings",
        "data": techniques,
    }


@router.post("/test-deduplication")
async def test_deduplication(
    value: str,
    ioc_type: str,
):
    """Test deduplication logic."""
    from app.db.postgres import get_db
    
    async with get_db() as conn:
        service = DeduplicationService()
        existing = await service.find_existing_ioc(conn, value, ioc_type)
        similar = await service.find_similar_iocs(conn, value)
        
        return {
            "success": True,
            "data": {
                "existing": dict(existing) if existing else None,
                "similar_count": len(similar),
                "similar": similar[:5],  # First 5
            }
        }
