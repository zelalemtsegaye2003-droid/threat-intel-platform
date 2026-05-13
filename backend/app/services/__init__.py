from __future__ import annotations

import structlog

logger = structlog.get_logger(__name__)

# Import what's available, degrade gracefully
__all__ = []

try:
    from app.services.deduplication import DeduplicationService
    __all__.append("DeduplicationService")
except ImportError as e:
    logger.warning("deduplication_unavailable", reason=str(e))

try:
    from app.services.correlation import CorrelationEngine
    __all__.append("CorrelationEngine")
except ImportError as e:
    logger.warning("correlation_unavailable", reason=str(e))

try:
    from app.services.enrichment import EnrichmentService, VectorService, AttackMapper, FeedIngestor
    __all__.extend(["EnrichmentService", "VectorService", "AttackMapper", "FeedIngestor"])
except ImportError as e:
    logger.warning("enrichment_unavailable", reason=str(e))

try:
    from app.services.llm_service import LLMAnalysisService, get_gemini_service
    __all__.extend(["LLMAnalysisService", "get_gemini_service"])
except ImportError as e:
    logger.warning("llm_service_unavailable", reason=str(e))
    LLMAnalysisService = None  # type: ignore
    get_gemini_service = None

try:
    from app.services.external_services import EnhancedEnrichmentService, VirusTotalService, ShodanService
    __all__.extend(["EnhancedEnrichmentService", "VirusTotalService", "ShodanService"])
except ImportError as e:
    logger.warning("external_services_unavailable", reason=str(e))

try:
    from app.services.attack_mapper import EnhancedAttackMapper
    __all__.append("EnhancedAttackMapper")
except ImportError as e:
    logger.warning("attack_mapper_unavailable", reason=str(e))
    EnhancedAttackMapper = None  # type: ignore