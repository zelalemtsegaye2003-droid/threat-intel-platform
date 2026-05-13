from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse
from asyncpg import Connection
from typing import Any

from app.db.postgres import get_db
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


@router.post("/analyze-text")
async def analyze_text(
    text: str,
    analysis_type: str = "general",
):
    """Analyze text using LLM."""
    _ensure_services()
    if analysis_type == "threat-report":
        result = await llm_svc.analyze_threat_report(text) if llm_svc else {"error": "LLM service unavailable"}
    else:
        result = await llm_svc.gemini.generate(
            prompt=text,
            system_prompt="You are a cybersecurity analyst. Provide a concise analysis."
        ) if llm_svc and hasattr(llm_svc, 'gemini') else {"error": "LLM service unavailable"}

    return {
        "success": True,
        "data": {
            "analysis": result,
            "type": analysis_type,
        }
    }


@router.post("/extract-iocs")
async def extract_iocs(
    text: str,
    min_confidence: int = 70,
):
    """Extract IOCs from text using Gemini."""
    _ensure_services()
    if not llm_svc or not hasattr(llm_svc, 'gemini') or not hasattr(llm_svc.gemini, 'extract_iocs_from_text'):
        return {
            "success": True,
            "data": {"iocs": [], "total_found": 0, "after_filter": 0, "note": "LLM service unavailable"}
        }

    iocs = await llm_svc.gemini.extract_iocs_from_text(text)

    # Filter by confidence
    filtered = [ioc for ioc in iocs if ioc.get("confidence", 0) >= min_confidence]

    return {
        "success": True,
        "data": {
            "iocs": filtered,
            "total_found": len(iocs),
            "after_filter": len(filtered),
        }
    }


@router.post("/generate-report")
async def generate_report(
    ioc_ids: list[str],
    conn: Connection = Depends(get_db),
):
    """Generate a threat report from IOCs."""
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

    return {
        "success": True,
        "data": {
            "report": report,
            "ioc_count": len(iocs),
        }
    }


@router.post("/map-attack")
async def map_to_attack(
    text: str,
    use_llm: bool = True,
):
    """Map text or technique to MITRE ATT&CK."""
    _ensure_services()
    result = None
    if use_llm and attack_mapper and hasattr(attack_mapper, 'map_report_to_techniques'):
        result = await attack_mapper.map_report_to_techniques(text)

    return {
        "success": True,
        "data": result or {"message": "No techniques mapped"}
    }


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

    if analysis_type == "threat-report":
        result = await llm_svc.analyze_threat_report(text) if llm_svc else {"error": "LLM service unavailable"}
    else:
        result = await llm_svc.gemini.generate(prompt=text[:5000]) if llm_svc and hasattr(llm_svc, 'gemini') else {"error": "LLM service unavailable"}

    return {
        "success": True,
        "data": {
            "filename": file.filename,
            "analysis": result,
        }
    }