from __future__ import annotations

import structlog
from typing import Any
import httpx
from datetime import datetime

# Lazy-load GeminiService to avoid import-time failures
def _get_gemini_service():
    try:
        from app.services.llm_service import get_gemini_service
        return get_gemini_service()
    except Exception:
        return None

logger = structlog.get_logger(__name__)


class AttackTechnique:
    """MITRE ATT&CK technique representation."""

    def __init__(
        self,
        technique_id: str,
        name: str,
        tactic: str,
        description: str = "",
    ):
        self.technique_id = technique_id
        self.name = name
        self.tactic = tactic
        self.description = description


# MITRE ATT&CK Enterprise Techniques (simplified mapping)
# In production, you'd load these from official ATT&CK STIX data
ATTACK_TECHNIQUES = {
    # Reconnaissance
    "T1595": AttackTechnique("T1595", "Active Scanning", "reconnaissance"),
    "T1592": AttackTechnique("T1592", "Gather Victim Host Information", "reconnaissance"),
    # Initial Access
    "T1078": AttackTechnique("T1078", "Valid Accounts", "initial-access"),
    "T1133": AttackTechnique("T1133", "External Remote Services", "initial-access"),
    "T1566": AttackTechnique("T1566", "Phishing", "initial-access"),
    # Execution
    "T1059": AttackTechnique("T1059", "Command and Scripting Interpreter", "execution"),
    "T1203": AttackTechnique("T1203", "Exploitation for Client Execution", "execution"),
    # Persistence
    "T1136": AttackTechnique("T1136", "Create Account", "persistence"),
    "T1547": AttackTechnique("T1547", "Boot or Logon Autostart Execution", "persistence"),
    # Privilege Escalation
    "T1548": AttackTechnique("T1548", "Abuse Elevation Control Mechanism", "privilege-escalation"),
    "T1068": AttackTechnique("T1068", "Exploitation for Privilege Escalation", "privilege-escalation"),
    # Defense Evasion
    "T1027": AttackTechnique("T1027", "Obfuscated Files or Information", "defense-evasion"),
    "T1070": AttackTechnique("T1070", "Indicator Removal on Host", "defense-evasion"),
    "T1562": AttackTechnique("T1562", "Impair Defenses", "defense-evasion"),
    # Credential Access
    "T1110": AttackTechnique("T1110", "Brute Force", "credential-access"),
    "T1555": AttackTechnique("T1555", "Credentials from Password Stores", "credential-access"),
    # Discovery
    "T1046": AttackTechnique("T1046", "Network Service Discovery", "discovery"),
    "T1087": AttackTechnique("T1087", "Account Discovery", "discovery"),
    # Lateral Movement
    "T1021": AttackTechnique("T1021", "Remote Services", "lateral-movement"),
    "T1570": AttackTechnique("T1570", "Lateral Tool Transfer", "lateral-movement"),
    # Collection
    "T1557": AttackTechnique("T1557", "Adversary-in-the-Middle", "collection"),
    "T1560": AttackTechnique("T1560", "Archive Collected Data", "collection"),
    # Exfiltration
    "T1041": AttackTechnique("T1041", "Exfiltration Over C2 Channel", "exfiltration"),
    "T1105": AttackTechnique("T1105", "Ingress Tool Transfer", "exfiltration"),
    # Impact
    "T1486": AttackTechnique("T1486", "Data Encrypted for Impact", "impact"),
    "T1496": AttackTechnique("T1496", "Resource Hijacking", "impact"),
}


class EnhancedAttackMapper:
    """Enhanced MITRE ATT&CK mapping with Gemini assistance (degrades if LLM unavailable)."""

    def __init__(self):
        self.gemini = _get_gemini_service()
        self.techniques = ATTACK_TECHNIQUES

    async def map_ioc_to_techniques(self, ioc: dict[str, Any]) -> list[dict[str, Any]]:
        """Map an IOC to potential ATT&CK techniques."""
        mappings = []
        value = ioc.get("value", "").lower()
        ioc_type = ioc.get("type", "")
        metadata_str = str(ioc.get("metadata", {})).lower()

        # Rule-based mapping
        for tech_id, technique in self.techniques.items():
            score = 0
            # Check if technique keywords appear in IOC or metadata
            keywords = self._get_technique_keywords(tech_id)
            for keyword in keywords:
                if keyword in value or keyword in metadata_str:
                    score += 1

            if score > 0:
                mappings.append({
                    "technique_id": tech_id,
                    "technique_name": technique.name,
                    "tactic": technique.tactic,
                    "confidence": min(100, score * 30),
                    "source": "rule-based",
                })

        # LLM-enhanced mapping if we have context
        if ioc.get("metadata", {}).get("description"):
            llm_result = await self.gemini.map_to_attack(
                ioc.get("metadata", {}).get("description", "")
            )
            if llm_result and llm_result.get("technique_id") != "unknown":
                mappings.append({
                    "technique_id": llm_result.get("technique_id"),
                    "technique_name": llm_result.get("technique_name", ""),
                    "tactic": llm_result.get("tactic", ""),
                    "confidence": llm_result.get("confidence", 50),
                    "source": "gemini",
                })

        return mappings

    def _get_technique_keywords(self, technique_id: str) -> list[str]:
        """Get keywords associated with a technique."""
        keyword_map = {
            "T1595": ["scan", "port scan", "nmap", "recon"],
            "T1078": ["account", "login", "ssh", "rdp", "valid account"],
            "T1059": ["powershell", "cmd", "bash", "script", "command line"],
            "T1027": ["obfuscate", "encode", "base64", "encrypt"],
            "T1486": ["ransomware", "encrypt", ".locked", ".encrypted"],
            "T1105": ["exfil", "transfer", "upload", "c2"],
            "T1046": ["scan", "discover", "network", "port"],
            "T1110": ["brute", "password", "crack", "dictionary"],
        }
        return keyword_map.get(technique_id, [])

    async def map_report_to_techniques(self, report_text: str) -> list[dict[str, Any]]:
        """Map an entire threat report to ATT&CK techniques using Gemini."""
        result = await self.gemini.map_to_attack(report_text[:2000])  # Limit length
        if result and result.get("technique_id") != "unknown":
            return [result]
        return []

    async def get_technique_details(self, technique_id: str) -> dict[str, Any] | None:
        """Get details for a specific technique."""
        tech = self.techniques.get(technique_id)
        if tech:
            return {
                "id": tech.technique_id,
                "name": tech.name,
                "tactic": tech.tactic,
                "description": tech.description,
            }
        return None

    async def close(self):
        """Clean up resources."""
        await self.gemini.close()


# For production use: Load official ATT&CK data from MITRE
async def load_attack_data_from_url() -> dict[str, Any]:
    """Load ATT&CK data from MITRE's STIX distribution."""
    client = httpx.AsyncClient(timeout=60.0)
    try:
        # This would load the official ATT&CK STIX bundle
        # https://cti-taxii.mitre.org/stix/enterprise-attack
        response = await client.get(
            "https://cti-taxii.mitre.org/stix/enterprise-attack/attack-pattern"
        )
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        logger.error("attack_data_load_failed", error=str(e))
    finally:
        await client.aclose()
    return {}
