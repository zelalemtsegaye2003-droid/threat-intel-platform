from __future__ import annotations

from typing import Any, Optional
import httpx
from datetime import datetime

from app.config import get_settings
from app.services.enrichment import EnrichmentService

settings = get_settings()


class VirusTotalService:
    """VirusTotal API v3 integration."""

    def __init__(self):
        self.api_key = settings.virustotal_api_key
        self.client = httpx.AsyncClient(
            base_url="https://www.virustotal.com/vtapi/v3",
            timeout=30.0,
        )
        self._headers = {"x-apikey": self.api_key} if self.api_key else {}

    async def enrich_ip(self, ip: str) -> dict[str, Any] | None:
        """Get IP report from VirusTotal."""
        if not self.api_key:
            return None
        try:
            response = await self.client.get(f"/ip_addresses/{ip}", headers=self._headers)
            if response.status_code == 200:
                data = response.json()
                attrs = data.get("data", {}).get("attributes", {})
                return {
                    "reputation": attrs.get("reputation", 0),
                    "last_analysis_stats": attrs.get("last_analysis_stats", {}),
                    "country": attrs.get("country", ""),
                    "as_owner": attrs.get("as_owner", ""),
                    "network": attrs.get("network", ""),
                    "checked_at": datetime.utcnow().isoformat(),
                }
        except Exception as e:
            print(f"VirusTotal IP enrichment failed: {e}")
        return None

    async def enrich_domain(self, domain: str) -> dict[str, Any] | None:
        """Get domain report from VirusTotal."""
        if not self.api_key:
            return None
        try:
            response = await self.client.get(f"/domains/{domain}", headers=self._headers)
            if response.status_code == 200:
                data = response.json()
                attrs = data.get("data", {}).get("attributes", {})
                return {
                    "reputation": attrs.get("reputation", 0),
                    "last_analysis_stats": attrs.get("last_analysis_stats", {}),
                    "creation_date": attrs.get("creation_date"),
                    "registrar": attrs.get("registrar", ""),
                    "checked_at": datetime.utcnow().isoformat(),
                }
        except Exception as e:
            print(f"VirusTotal domain enrichment failed: {e}")
        return None

    async def enrich_url(self, url: str) -> dict[str, Any] | None:
        """Get URL report from VirusTotal."""
        if not self.api_key:
            return None
        try:
            # URL needs to be URL-encoded
            import urllib.parse
            encoded_url = urllib.parse.quote(url, safe="")
            response = await self.client.get(f"/urls/{encoded_url}", headers=self._headers)
            if response.status_code == 200:
                data = response.json()
                attrs = data.get("data", {}).get("attributes", {})
                return {
                    "last_analysis_stats": attrs.get("last_analysis_stats", {}),
                    "last_final_url": attrs.get("last_final_url", ""),
                    "checked_at": datetime.utcnow().isoformat(),
                }
        except Exception as e:
            print(f"VirusTotal URL enrichment failed: {e}")
        return None

    async def enrich_hash(self, file_hash: str) -> dict[str, Any] | None:
        """Get file hash report from VirusTotal."""
        if not self.api_key:
            return None
        try:
            response = await self.client.get(f"/files/{file_hash}", headers=self._headers)
            if response.status_code == 200:
                data = response.json()
                attrs = data.get("data", {}).get("attributes", {})
                return {
                    "meaningful_name": attrs.get("meaningful_name", ""),
                    "type_description": attrs.get("type_description", ""),
                    "size": attrs.get("size", 0),
                    "last_analysis_stats": attrs.get("last_analysis_stats", {}),
                    "md5": attrs.get("md5", ""),
                    "sha1": attrs.get("sha1", ""),
                    "sha256": attrs.get("sha256", ""),
                    "checked_at": datetime.utcnow().isoformat(),
                }
        except Exception as e:
            print(f"VirusTotal hash enrichment failed: {e}")
        return None

    async def close(self):
        await self.client.aclose()


class ShodanService:
    """Shodan API integration."""

    def __init__(self):
        self.api_key = settings.shodan_api_key
        self.client = httpx.AsyncClient(
            base_url="https://api.shodan.io",
            timeout=30.0,
        )

    async def search_host(self, ip: str) -> dict[str, Any] | None:
        """Search Shodan for host information."""
        if not self.api_key:
            return None
        try:
            response = await self.client.get(
                "/shodan/host",
                params={"key": self.api_key, "ip": ip, "minify": True},
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    "ports": data.get("ports", []),
                    "vulns": data.get("vulns", []),
                    "hostnames": data.get("hostnames", []),
                    "country_name": data.get("country_name", ""),
                    "org": data.get("org", ""),
                    "os": data.get("os", ""),
                    "last_update": data.get("last_update", ""),
                    "checked_at": datetime.utcnow().isoformat(),
                }
        except Exception as e:
            print(f"Shodan search failed: {e}")
        return None

    async def search_query(self, query: str, limit: int = 10) -> list[dict] | None:
        """Search Shodan with a query."""
        if not self.api_key:
            return None
        try:
            response = await self.client.get(
                "/shodan/host/search",
                params={"key": self.api_key, "query": query, "limit": limit},
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("matches", [])
        except Exception as e:
            print(f"Shodan query failed: {e}")
        return None

    async def close(self):
        await self.client.aclose()


# Enhanced EnrichmentService with VirusTotal and Shodan
class EnhancedEnrichmentService(EnrichmentService):
    """Enhanced enrichment with VirusTotal and Shodan."""

    def __init__(self):
        super().__init__()
        self.vt_service = VirusTotalService() if settings.virustotal_api_key else None
        self.shodan_service = ShodanService() if settings.shodan_api_key else None

    async def enrich_ioc(self, ioc_data: dict[str, Any]) -> dict[str, Any]:
        """Enrich an IOC with all available sources."""
        enriched = ioc_data.copy()
        ioc_type = ioc_data.get("type", "")
        value = ioc_data.get("value", "")

        # Base enrichment (GeoIP, etc.)
        enriched = await super().enrich_ioc(ioc_data)

        # VirusTotal enrichment
        if self.vt_service:
            if "ip" in ioc_type:
                vt_data = await self.vt_service.enrich_ip(value)
                if vt_data:
                    enriched["metadata"]["virustotal"] = vt_data
            elif ioc_type == "domain":
                vt_data = await self.vt_service.enrich_domain(value)
                if vt_data:
                    enriched["metadata"]["virustotal"] = vt_data
            elif ioc_type == "url":
                vt_data = await self.vt_service.enrich_url(value)
                if vt_data:
                    enriched["metadata"]["virustotal"] = vt_data
            elif "hash" in ioc_type:
                vt_data = await self.vt_service.enrich_hash(value)
                if vt_data:
                    enriched["metadata"]["virustotal"] = vt_data

        # Shodan enrichment (IP only)
        if self.shodan_service and "ip" in ioc_type:
            shodan_data = await self.shodan_service.search_host(value)
            if shodan_data:
                enriched["metadata"]["shodan"] = shodan_data

        return enriched

    async def close(self):
        await super().close()
        if self.vt_service:
            await self.vt_service.close()
        if self.shodan_service:
            await self.shodan_service.close()
