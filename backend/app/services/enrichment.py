from __future__ import annotations

from typing import Any, Optional
import httpx
import structlog
from datetime import datetime

from app.config import get_settings
from app.db.postgres import get_db
from app.db.neo4j_db import create_ioc_node, create_relationship
from app.db.qdrant_db import upsert_point
from sentence_transformers import SentenceTransformer

logger = structlog.get_logger(__name__)

settings = get_settings()

# Load embedding model (lazy loading)
_model: SentenceTransformer | None = None


def get_embedding_model() -> SentenceTransformer:
    """Get or load the sentence transformer model."""
    global _model
    if _model is None:
        _model = SentenceTransformer('all-MiniLM-L6-v2')
    return _model


class EnrichmentService:
    """IOC enrichment pipeline."""

    def __init__(self):
        self.client = httpx.AsyncClient(timeout=30.0)

    async def enrich_ioc(self, ioc_data: dict[str, Any]) -> dict[str, Any]:
        """Enrich an IOC with additional context."""
        enriched = ioc_data.copy()
        ioc_type = ioc_data.get("type", "")
        value = ioc_data.get("value", "")

        # GeoIP enrichment for IPs
        if ioc_type == "ipv4" or ioc_type == "ipv6":
            geo_data = await self._enrich_ip(value)
            if geo_data:
                enriched["metadata"]["geoip"] = geo_data

        # Domain reputation (placeholder)
        if ioc_type == "domain":
            domain_data = await self._enrich_domain(value)
            if domain_data:
                enriched["metadata"]["reputation"] = domain_data

        # Hash lookup (placeholder)
        if "hash" in ioc_type:
            hash_data = await self._enrich_hash(value)
            if hash_data:
                enriched["metadata"]["hash_info"] = hash_data

        return enriched

    async def _enrich_ip(self, ip: str) -> dict[str, Any] | None:
        """Enrich IP address with GeoIP data."""
        try:
            # Using ipinfo.io (free tier, no key needed for basic)
            response = await self.client.get(f"https://ipinfo.io/{ip}/json")
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.error("geoip_enrichment_failed", ip=ip, error=str(e))
        return None

    async def _enrich_domain(self, domain: str) -> dict[str, Any] | None:
        """Enrich domain with reputation data."""
        # Placeholder for VirusTotal, URLVoid, etc.
        return {
            "checked_at": datetime.utcnow().isoformat(),
            "reputation": "unknown",
        }

    async def _enrich_hash(self, hash_value: str) -> dict[str, Any] | None:
        """Enrich file hash with malware information."""
        # Placeholder for VirusTotal, Hybrid Analysis, etc.
        return {
            "checked_at": datetime.utcnow().isoformat(),
            "malware_family": None,
            "positives": 0,
        }

    async def close(self):
        await self.client.aclose()


class VectorService:
    """Vector embedding and search service."""

    def __init__(self):
        self.model = None

    def _get_model(self) -> SentenceTransformer:
        if self.model is None:
            self.model = get_embedding_model()
        return self.model

    def generate_embedding(self, text: str) -> list[float]:
        """Generate embedding vector for text."""
        model = self._get_model()
        return model.encode(text).tolist()

    async def index_ioc(self, ioc: dict[str, Any]) -> None:
        """Index an IOC in Qdrant for vector search."""
        from app.db.qdrant_db import get_qdrant

        client = await get_qdrant()

        # Create text representation for embedding
        text = f"{ioc.get('type', '')} {ioc.get('value', '')} {ioc.get('source', '')}"
        if ioc.get("metadata"):
            text += f" {str(ioc['metadata'])[:500]}"

        vector = self.generate_embedding(text)

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

    async def search_similar_iocs(
        self, query: str, limit: int = 10, score_threshold: float = 0.7
    ) -> list[dict]:
        """Search for IOCs similar to the query."""
        from app.db.qdrant_db import search_similar

        vector = self.generate_embedding(query)
        results = await search_similar(
            collection="ioc_embeddings",
            query_vector=vector,
            limit=limit,
            score_threshold=score_threshold,
        )
        return results


class AttackMapper:
    """MITRE ATT&CK mapping service."""

    # Simplified mapping of techniques to IOCs
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
        "T1059": "execution",
        "T1105": "exfiltration",
        "T1046": "reconnaissance",
        "T1133": "persistence",
        "T1078": "initial-access",
        "T1027": "defense-evasion",
        "T1486": "impact",
        "T1090": "command-and-control",
    }

    async def map_ioc_to_techniques(self, ioc: dict[str, Any]) -> list[dict[str, Any]]:
        """Map an IOC to potential ATT&CK techniques."""
        mappings = []
        value = ioc.get("value", "").lower()
        ioc_type = ioc.get("type", "")
        metadata_str = str(ioc.get("metadata", {})).lower()

        for technique_id, keywords in self.TECHNIQUE_MAP.items():
            score = 0
            for keyword in keywords:
                if keyword in value or keyword in metadata_str:
                    score += 1

            if score > 0:
                mappings.append({
                    "technique_id": technique_id,
                    "technique_name": self._get_technique_name(technique_id),
                    "tactic": self.TACTIC_MAP.get(technique_id, "unknown"),
                    "confidence": min(100, score * 30),
                    "source": "automated",
                })

        return mappings

    def _get_technique_name(self, technique_id: str) -> str:
        """Get technique name from ID."""
        names = {
            "T1059": "Command and Scripting Interpreter",
            "T1105": "Exfiltration Over Alternative Protocol",
            "T1046": "Network Service Discovery",
            "T1133": "External Remote Services",
            "T1078": "Valid Accounts",
            "T1027": "Obfuscated Files or Information",
            "T1486": "Data Encrypted for Impact",
            "T1090": "Proxy",
        }
        return names.get(technique_id, "Unknown Technique")


class FeedIngestor:
    """External feed ingestion service."""

    def __init__(self):
        self.client = httpx.AsyncClient(timeout=30.0)

    async def ingest_alienvault_otx(self, api_key: str | None = None) -> dict[str, Any]:
        """Ingest pulses from AlienVault OTX."""
        results = {"iocs_added": 0, "iocs_updated": 0, "errors": []}

        if not api_key:
            api_key = settings.alienvault_otx_api_key

        if not api_key:
            results["errors"].append("AlienVault OTX API key not configured")
            return results

        try:
            headers = {"X-OTX-API-KEY": api_key}
            response = await self.client.get(
                "https://otx.alienvault.com/api/v1/pulses/subscribed",
                headers=headers,
                params={"limit": 50},
            )

            if response.status_code != 200:
                results["errors"].append(f"OTX API error: {response.status_code}")
                return results

            data = response.json()
            pulses = data.get("results", [])

            for pulse in pulses:
                for indicator in pulse.get("indicators", []):
                    ioc_type = self._map_otx_type(indicator.get("type", ""))
                    if ioc_type:
                        ioc_data = {
                            "type": ioc_type,
                            "value": indicator.get("indicator", ""),
                            "threat_level": self._map_threat_level(pulse.get("TLP", "")),
                            "source": "alienvault_otx",
                            "metadata": {
                                "pulse_id": pulse.get("id", ""),
                                "pulse_name": pulse.get("name", ""),
                                "description": pulse.get("description", "")[:500],
                            },
                        }
                        # Process IOC (would save to DB in real implementation)
                        results["iocs_added"] += 1

        except Exception as e:
            results["errors"].append(f"OTX ingestion error: {str(e)}")

        return results

    def _map_otx_type(self, otx_type: str) -> str | None:
        """Map AlienVault OTX type to our IOC type."""
        mapping = {
            "IPv4": "ipv4",
            "IPv6": "ipv6",
            "domain": "domain",
            "URL": "url",
            "FileHash-SHA256": "hash-sha256",
            "FileHash-MD5": "hash-md5",
            "FileHash-SHA1": "hash-sha1",
            "email": "email",
        }
        return mapping.get(otx_type)

    def _map_threat_level(self, tlp: str) -> str:
        """Map TLP level to threat level."""
        mapping = {
            "white": "low",
            "green": "medium",
            "amber": "high",
            "red": "critical",
        }
        return mapping.get(tlp.lower(), "medium")

    async def ingest_abuse_ch(self) -> dict[str, Any]:
        """Ingest data from Abuse.ch."""
        results = {"iocs_added": 0, "iocs_updated": 0, "errors": []}

        try:
            # Example: URLhaus feed
            response = await self.client.get(
                "https://urlhaus-api.abuse.ch/v1/urls/recent/"
            )

            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok":
                    urls = data.get("urls", [])
                    for item in urls:
                        # Process malicious URLs
                        results["iocs_added"] += 1

        except Exception as e:
            results["errors"].append(f"Abuse.ch ingestion error: {str(e)}")

        return results

    async def close(self):
        await self.client.aclose()
