from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse
from asyncpg import Connection
from typing import Any

from app.db.postgres import get_db
from app.services import LLMAnalysisService, EnhancedAttackMapper
from app.models.response import DataResponse

router = APIRouter()

# Initialize services
llm_svc = LLMAnalysisService()
attack_mapper = EnhancedAttackMapper()


@router.post("/analyze-text")
async def analyze_text(
    text: str,
    analysis_type: str = "general",
):
    """Analyze text using LLM."""
    if analysis_type == "threat-report":
        result = await llm_svc.analyze_threat_report(text)
    else:
        result = await llm_svc.ollama.generate(
            prompt=text,
            system_prompt="You are a cybersecurity analyst. Provide a concise analysis."
        )
    
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
    """Extract IOCs from text using LLM."""
    iocs = await llm_svc.ollama.extract_iocs_from_text(text)
    
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
    report = await llm_svc.generate_threat_brief(
        iocs,
        actor=None,  # Could look up actor from graph
    )
    
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
    if use_llm:
        result = await attack_mapper.map_report_to_techniques(text)
    else:
        # Use rule-based mapping
        # This would need IOC data structure
        result = None
    
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
    content = await file.read()
    
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(400, "File must be valid UTF-8 text")
    
    if analysis_type == "threat-report":
        result = await llm_svc.analyze_threat_report(text)
    else:
        result = await llm_svc.ollama.generate(prompt=text[:5000])  # Limit length
    
    return {
        "success": True,
        "data": {
            "filename": file.filename,
            "analysis": result,
        }
    }
