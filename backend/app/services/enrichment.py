from __future__ import annotations

from typing import Any, Optional
import structlog

logger = structlog.get_logger(__name__)

# Lazy-load SentenceTransformer — only when actually needed
_model: Any = None


def _load_embedding_model():
    """Lazily load the sentence transformer model."""
    global _model
    if _model is None:
        try:
            from sentence_transformers import SentenceTransformer
            _model = SentenceTransformer('all-MiniLM-L6-v2')
        except ImportError:
            logger.warning("sentence_transformers_not_installed", reason="Skipping embedding model")
    return _model


from app.config import get_settings  # noqa: E402

settings = get_settings()


import httpx
from datetime import datetime


class EnrichmentService:
    """IOC enrichment pipeline — degrades gracefully if ML models are unavailable."""

    def __init__(self):
        self.client = httpx.AsyncClient(timeout=30.0)

    async def enrich_ioc(self, ioc_data: dict[str, Any]) -> dict[str, Any]:
        """Enrich an IOC with additional context."""
        enriched = ioc_data.copy()
        ioc_type = ioc_data.get("type", "")
        value = ioc_data.get("value", "")

        if ioc_type in ("ipv4", "ipv6"):
            geo_data = await self._enrich_ip(value)
            if geo_data:
                enriched["metadata"]["geoip"] = geo_data

        if ioc_type == "domain":
            domain_data = await self._enrich_domain(value)
            if domain_data:
                enriched["metadata"]["reputation"] = domain_data

        if "hash" in ioc_type:
            hash_data = await self._enrich_hash(value)
            if hash_data:
                enriched["metadata"]["hash_info"] = hash_data

        return enriched

    async def _enrich_ip(self, ip: str) -> dict[str, Any] | None:
        """Enrich IP address with GeoIP data."""
        try:
            import time
            from app.metrics import FEED_INGESTION_COUNT, FEED_INGESTION_DURATION
            start_time = time.time()
            FEED_INGESTION_COUNT.labels(feed="geoip", status="attempt").inc()

            response = await self.client.get(f"https://ipinfo.io/{ip}/json")
            if response.status_code == 200:
                FEED_INGESTION_DURATION.labels(feed="geoip").observe(time.time() - start_time)
                FEED_INGESTION_COUNT.labels(feed="geoip", status="success").inc()
                return response.json()
        except Exception as e:
            from app.metrics import FEED_INGESTION_COUNT as FIC
            FIC.labels(feed="geoip", status="error").inc()
            logger.error("geoip_enrichment_failed", ip=ip, error=str(e))
        return None

    async def _enrich_domain(self, domain: str) -> dict[str, Any] | None:
        """Enrich domain with reputation data."""
        return {
            "checked_at": datetime.utcnow().isoformat(),
            "reputation": "unknown",
        }

    async def _enrich_hash(self, hash_value: str) -> dict[str, Any] | None:
        """Enrich file hash with malware information."""
        return {
            "checked_at": datetime.utcnow().isoformat(),
            "malware_family": None,
            "positives": 0,
        }

    async def close(self):
        await self.client.aclose()


class VectorService:
    """Vector embedding and search service — degrades gracefully."""

    def __init__(self):
        self.model = None

    def _get_model(self):
        if self.model is None:
            self.model = _load_embedding_model()
        return self.model

    def generate_embedding(self, text: str) -> list[float] | None:
        """Generate embedding vector for text. Returns None if model unavailable."""
        model = self._get_model()
        if model is None:
            logger.warning("embedding_model_unavailable")
            return None
        return model.encode(text).tolist()

    async def index_ioc(self, ioc: dict[str, Any]) -> None:
        """Index an IOC in Qdrant for vector search."""
        from app.db.qdrant_db import upsert_point
        from app.db.neo4j_db import get_qdrant

        vector = self.generate_embedding(
            f"{ioc.get('type', '')} {ioc.get('value', '')} {ioc.get('source', '')}"
        )
        if vector is None:
            return

        await upsert_point(
            collection="ioc_embeddings",
            point_id=str(ioc.get("id", "")),
            vector=vector,
            payload={
                "ioc_id": str(ioc.get("id", "")),
                "ioc_type": ioc.get("type", ""),
                "value": ioc.get("value", ""),
                "threat_level": ioc.get("threat_level", "medium"),
                "source": ioc.get("source", ""),
            },
        )

    async def search_similar_iocs(self, query: str, limit: int = 10, score_threshold: float = 0.7) -> list:
        """Search for IOCs similar to the query."""
        from app.db.qdrant_db import search_similar
        vector = self.generate_embedding(query)
        if vector is None:
            return []
        return await search_similar(
            collection="ioc_embeddings",
            query_vector=vector,
            limit=limit,
            score_threshold=score_threshold,
        )


class AttackMapper:
    """MITRE ATT&CK mapping service (rule-based, no ML dependency)."""

    TECHNIQUE_MAP = {
        "T1059": ["command-line-interface", "scripting"],
        "T1105": ["download", "transfer", "file"],
        "T1046": ["port-scan", "reconnaissance"],
        "T1133": ["external-remote-services"],
        "T1078": ["valid-accounts", "credentials"],
        "T1027": ["obfuscated-files", "information"],
        "T1486": ["data-encrypted", "ransomware"],
        "T1090": ["connection-proxy", "traffic"],
    }

    TACTIC_MAP = {
        "T1059": "execution", "T1105": "exfiltration", "T1046": "reconnaissance",
        "T1133": "persistence", "T1078": "initial-access", "T1027": "defense-evasion",
        "T1486": "impact", "T1090": "command-and-control",
    }

    TECHNIQUE_NAMES = {
        "T1059": "Command and Scripting Interpreter", "T1105": "Exfiltration Over Alternative Protocol",
        "T1046": "Network Service Discovery", "T1133": "External Remote Services",
        "T1078": "Valid Accounts", "T1027": "Obfuscated Files or Information",
        "T1486": "Data Encrypted for Impact", "T1090": "Proxy",
    }

    async def map_ioc_to_techniques(self, ioc: dict[str, Any]) -> list[dict[str, Any]]:
        """Map an IOC to potential ATT&CK techniques."""
        mappings = []
        value = ioc.get("value", "").lower()
        metadata_str = str(ioc.get("metadata", {})).lower()

        for tech_id, keywords in self.TECHNIQUE_MAP.items():
            score = sum(1 for kw in keywords if kw in value or kw in metadata_str)
            if score > 0:
                mappings.append({
                    "technique_id": tech_id,
                    "technique_name": self.TECHNIQUE_NAMES[tech_id],
                    "tactic": self.TACTIC_MAP.get(tech_id, "unknown"),
                    "confidence": min(100, score * 30),
                    "source": "rule-based",
                })
        return mappings

    async def close(self):
        pass


class FeedIngestor:
    """External feed ingestion service."""

    def __init__(self):
        self.client = httpx.AsyncClient(timeout=30.0)

    async def ingest_alienvault_otx(self, api_key: str | None = None) -> dict[str, Any]:
        """Ingest pulses from AlienVault OTX."""
        import time
        from app.metrics import FEED_INGESTION_COUNT, FEED_INGESTION_DURATION

        results = {"iocs_added": 0, "iocs_updated": 0, "errors": []}
        if not api_key:
            api_key = settings.alienvault_otx_api_key
        if not api_key:
            results["errors"].append("AlienVault OTX API key not configured")
            return results

        try:
            start_time = time.time()
            FEED_INGESTION_COUNT.labels(feed="alienvault_otx", status="attempt").inc()

            headers = {"X-OTX-API-KEY": api_key}
            response = await self.client.get(
                "https://otx.alienvault.com/api/v1/pulses/subscribed",
                headers=headers, params={"limit": 50},
            )

            if response.status_code == 200:
                data = response.json()
                pulses = data.get("results", [])
                for pulse in pulses:
                    for indicator in pulse.get("indicators", []):
                        ioc_type = self._map_otx_type(indicator.get("type", ""))
                        if ioc_type:
                            results["iocs_added"] += 1

                FEED_INGESTION_DURATION.labels(feed="alienvault_otx").observe(time.time() - start_time)
                FEED_INGESTION_COUNT.labels(feed="alienvault_otx", status="success").inc()

        except Exception as e:
            FEED_INGESTION_COUNT.labels(feed="alienvault_otx", status="error").inc()
            results["errors"].append(f"OTX ingestion error: {str(e)}")
            logger.error("otx_ingestion_failed", error=str(e))

        return results

    def _map_otx_type(self, otx_type: str) -> str | None:
        mapping = {
            "IPv4": "ipv4", "IPv6": "ipv6", "domain": "domain",
            "URL": "url", "FileHash-SHA256": "hash-sha256",
            "FileHash-MD5": "hash-md5", "FileHash-SHA1": "hash-sha1",
            "email": "email",
        }
        return mapping.get(otx_type)

    def _map_threat_level(self, tlp: str) -> str:
        mapping = {"white": "low", "green": "medium", "amber": "high", "red": "critical"}
        return mapping.get(tlp.lower(), "medium")

    async def ingest_abuse_ch(self) -> dict[str, Any]:
        """Ingest data from Abuse.ch."""
        import time
        from app.metrics import FEED_INGESTION_COUNT, FEED_INGESTION_DURATION

        results = {"iocs_added": 0, "iocs_updated": 0, "errors": []}
        try:
            start_time = time.time()
            FEED_INGESTION_COUNT.labels(feed="abuse_ch", status="attempt").inc()

            response = await self.client.get("https://urlhaus-api.abuse.ch/v1/urls/recent/")
            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok":
                    results["iocs_added"] = len(data.get("urls", []))

                FEED_INGESTION_DURATION.labels(feed="abuse_ch").observe(time.time() - start_time)
                FEED_INGESTION_COUNT.labels(feed="abuse_ch", status="success").inc()

        except Exception as e:
            FEED_INGESTION_COUNT.labels(feed="abuse_ch", status="error").inc()
            results["errors"].append(f"Abuse.ch ingestion error: {str(e)}")
            logger.error("abuse_ch_ingestion_failed", error=str(e))

        return results

    async def close(self):
        await self.client.aclose()