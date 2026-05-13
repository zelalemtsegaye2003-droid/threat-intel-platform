from __future__ import annotations

import hashlib
import json
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from asyncpg import Connection

from app.db.postgres import get_db
from app.db.redis_db import cache_get, cache_set
from app.services import LLMAnalysisService, EnhancedAttackMapper
from app.models.response import DataResponse

router = APIRouter()


# Initialize services lazily to avoid import issues at module load
llm_svc = None
attack_mapper = None


def _ensure_services():
    """Lazily initialize services on first request."""
    global llm_svc, attack_mapper
    if llm_svc is None and LLMAnalysisService is not None:
        llm_svc = LLMAnalysisService()
    if attack_mapper is None and EnhancedAttackMapper is not None:
        attack_mapper = EnhancedAttackMapper()


def _cache_key(prefix: str, text: str) -> str:
    """Generate a deterministic cache key from prefix and text."""
    digest = hashlib.sha256(text.encode()).hexdigest()[:16]
    return f"analysis:{prefix}:{digest}"


@router.post("/analyze-text")
async def analyze_text(
    text: str,
    analysis_type: str = "general",
):
    """Analyze text using LLM."""
    _ensure_services()

    # Check cache first (cacheable for all analysis types)
    cache_key = _cache_key("analyze", f"{analysis_type}:{text[:500]}")
    cached = await cache_get(cache_key)
    if cached:
        try:
            return json.loads(cached)
        except (json.JSONDecodeError, TypeError):
            pass  # Fall through to recompute

    if analysis_type == "threat-report":
        result = await llm_svc.analyze_threat_report(text) if llm_svc else {"error": "LLM service unavailable"}
    else:
        result = await llm_svc.gemini.generate(
            prompt=text,
            system_prompt="You are a cybersecurity analyst. Provide a concise analysis."
        ) if llm_svc and hasattr(llm_svc, 'gemini') else {"error": "LLM service unavailable"}

    response = {
        "success": True,
        "data": {
            "analysis": result,
            "type": analysis_type,
        }
    }

    # Cache for 1 hour (analysis results are relatively static)
    await cache_set(cache_key, json.dumps(response), ttl=3600)
    return response


@router.post("/extract-iocs")
async def extract_iocs(
    text: str,
    min_confidence: int = 70,
):
    """Extract IOCs from text using Gemini."""
    _ensure_services()

    # Check cache first
    cache_key = _cache_key("iocs", f"{min_confidence}:{text[:500]}")
    cached = await cache_get(cache_key)
    if cached:
        try:
            return json.loads(cached)
        except (json.JSONDecodeError, TypeError):
            pass

    if not llm_svc or not hasattr(llm_svc, 'gemini') or not hasattr(llm_svc.gemini, 'extract_iocs_from_text'):
        response = {
            "success": True,
            "data": {"iocs": [], "total_found": 0, "after_filter": 0, "note": "LLM service unavailable"}
        }
    else:
        iocs = await llm_svc.gemini.extract_iocs_from_text(text)
        # Filter by confidence
        filtered = [ioc for ioc in iocs if ioc.get("confidence", 0) >= min_confidence]

        response = {
            "success": True,
            "data": {
                "iocs": filtered,
                "total_found": len(iocs),
                "after_filter": len(filtered),
            }
        }

    # Cache for 1 hour
    await cache_set(cache_key, json.dumps(response), ttl=3600)
    return response


@router.post("/generate-report")
async def generate_report(
    ioc_ids: list[str],
    conn: Connection = Depends(get_db),
):
    """Generate a threat report from IOCs."""
    # Check cache first
    cache_key = _cache_key("report", json.dumps(sorted(ioc_ids)))
    cached = await cache_get(cache_key)
    if cached:
        try:
            return json.loads(cached)
        except (json.JSONDecodeError, TypeError):
            pass

    # Fetch IOCs
    rows = await conn.fetch(
        "SELECT * FROM iocs WHERE id = ANY($1::uuid[])",
        ioc_ids,
    )

    if not rows:
        raise HTTPException(404, "No IOCs found")

    iocs = [dict(row) for row in rows]

    # Generate report using LLM
    if llm_svc:
        report = await llm_svc.generate_threat_brief(
            iocs,
            actor=None,
        )
    else:
        report = "LLM service unavailable"

    response = {
        "success": True,
        "data": {
            "report": report,
            "ioc_count": len(iocs),
        }
    }

    # Cache for 30 minutes (report content may change with new IOCs)
    await cache_set(cache_key, json.dumps(response), ttl=1800)
    return response


@router.post("/map-attack")
async def map_to_attack(
    text: str,
    use_llm: bool = True,
):
    """Map text or technique to MITRE ATT&CK."""
    _ensure_services()

    # Check cache first
    cache_key = _cache_key("attack", f"{use_llm}:{text[:500]}")
    cached = await cache_get(cache_key)
    if cached:
        try:
            return json.loads(cached)
        except (json.JSONDecodeError, TypeError):
            pass

    result = None
    if use_llm and attack_mapper and hasattr(attack_mapper, 'map_report_to_techniques'):
        result = await attack_mapper.map_report_to_techniques(text)

    response = {
        "success": True,
        "data": result or {"message": "No techniques mapped"}
    }

    # Cache for 1 hour (ATT&CK mappings are static)
    await cache_set(cache_key, json.dumps(response), ttl=3600)
    return response


@router.post("/upload-report")
async def upload_and_analyze(
    file: UploadFile = File(...),
    analysis_type: str = "threat-report",
):
    """Upload a file and analyze it."""
    _ensure_services()
    content = await file.read()

    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(400, "File must be valid UTF-8 text")

    # Check cache using file content hash
    content_hash = hashlib.sha256(text[:5000].encode()).hexdigest()[:16]
    cache_key = f"analysis:upload:{content_hash}:{analysis_type}"
    cached = await cache_get(cache_key)
    if cached:
        try:
            data = json.loads(cached)
            data["data"]["cached"] = True
            return data
        except (json.JSONDecodeError, TypeError):
            pass

    if analysis_type == "threat-report":
        result = await llm_svc.analyze_threat_report(text) if llm_svc else {"error": "LLM service unavailable"}
    else:
        result = await llm_svc.gemini.generate(prompt=text[:5000]) if llm_svc and hasattr(llm_svc, 'gemini') else {"error": "LLM service unavailable"}

    response = {
        "success": True,
        "data": {
            "filename": file.filename,
            "analysis": result,
        }
    }

    # Cache for 1 hour
    await cache_set(cache_key, json.dumps(response), ttl=3600)
    return response