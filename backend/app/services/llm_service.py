from __future__ import annotations

from typing import Any, Optional
import httpx
from datetime import datetime
import json

from app.config import get_settings

settings = get_settings()


class OllamaService:
    """Local LLM integration via Ollama."""

    def __init__(self):
        self.base_url = settings.ollama_base_url
        self.model = settings.ollama_model
        self.client = httpx.AsyncClient(timeout=120.0)  # LLM can be slow

    async def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
    ) -> str | None:
        """Generate text using Ollama."""
        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                },
            }
            if system_prompt:
                payload["system"] = system_prompt

            response = await self.client.post(
                f"{self.base_url}/api/generate",
                json=payload,
            )

            if response.status_code == 200:
                data = response.json()
                return data.get("response", "").strip()
        except Exception as e:
            print(f"Ollama generation failed: {e}")
        return None

    async def chat(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.7,
    ) -> str | None:
        """Chat with Ollama using message format."""
        try:
            payload = {
                "model": self.model,
                "messages": messages,
                "stream": False,
                "options": {"temperature": temperature},
            }

            response = await self.client.post(
                f"{self.base_url}/api/chat",
                json=payload,
            )

            if response.status_code == 200:
                data = response.json()
                return data.get("message", {}).get("content", "").strip()
        except Exception as e:
            print(f"Ollama chat failed: {e}")
        return None

    async def extract_iocs_from_text(self, text: str) -> list[dict[str, Any]]:
        """Extract IOCs from threat report text using LLM."""
        system_prompt = """You are a cybersecurity analyst. Extract all Indicators of Compromise (IOCs) from the given text.
Return ONLY a valid JSON array of objects, each with: "type", "value", "context".
Types: ipv4, ipv6, domain, url, hash-md5, hash-sha1, hash-sha256, email.
If no IOCs found, return []."""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Extract IOCs from this text:\n\n{text}"},
        ]

        result = await self.chat(messages)

        if result:
            try:
                # Try to parse JSON
                # Clean up the response - sometimes LLMs add markdown
                cleaned = result.strip()
                if cleaned.startswith("```"):
                    cleaned = cleaned.split("```")[1]
                    if cleaned.startswith("json"):
                        cleaned = cleaned[4:]
                return json.loads(cleaned)
            except json.JSONDecodeError:
                print(f"Failed to parse LLM response as JSON: {result}")
        return []

    async def analyze_threat_report(self, report_text: str) -> dict[str, Any]:
        """Analyze a threat report and provide insights."""
        system_prompt = """You are an expert cybersecurity threat intelligence analyst.
Analyze the threat report and provide:
1. Executive summary (2-3 sentences)
2. Threat actor assessment (if identifiable)
3. TTPs (Tactics, Techniques, Procedures) mentioned
4. IOCs found (with severity if possible)
5. Recommended mitigations
Return as JSON with keys: summary, threat_actor, ttps, iocs, mitigations."""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Analyze this threat report:\n\n{report_text}"},
        ]

        result = await self.chat(messages, temperature=0.3)

        if result:
            try:
                cleaned = result.strip()
                if cleaned.startswith("```"):
                    cleaned = cleaned.split("```")[1]
                    if cleaned.startswith("json"):
                        cleaned = cleaned[4:]
                return json.loads(cleaned)
            except json.JSONDecodeError:
                # Return as plain text
                return {"summary": result, "raw": True}
        return {}

    async def map_to_attack(self, technique_description: str) -> dict[str, Any] | None:
        """Map a technique description to MITRE ATT&CK."""
        system_prompt = """You are a MITRE ATT&CK expert. Given a technique description, 
return the most likely ATT&CK technique ID and name in JSON format:
{"technique_id": "Txxxx", "technique_name": "...", "tactic": "...", "confidence": 0-100}
If unsure, return {"technique_id": "unknown", "confidence": 0}."""

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Map this: {technique_description}"},
        ]

        result = await self.chat(messages)

        if result:
            try:
                cleaned = result.strip()
                if cleaned.startswith("```"):
                    cleaned = cleaned.split("```")[1]
                return json.loads(cleaned)
            except json.JSONDecodeError:
                pass
        return None

    async def close(self):
        await self.client.aclose()


class LLMAnalysisService:
    """High-level LLM analysis service."""

    def __init__(self):
        self.ollama = OllamaService()

    async def analyze_ioc_context(self, ioc_value: str, context: str) -> dict[str, Any]:
        """Analyze the context around an IOC to determine threat level."""
        prompt = f"""Given this IOC: {ioc_value}
And this context: {context}

Assess the threat level (low/medium/high/critical) and provide reasoning.
Return JSON: {"threat_level": "...", "confidence": 0-100, "reasoning": "..."}"""

        result = await self.ollama.chat(
            [{"role": "user", "content": prompt}]
        )

        if result:
            try:
                return json.loads(result)
            except json.JSONDecodeError:
                return {"raw_response": result}
        return {}

    async def generate_threat_brief(self, iocs: list[dict], actor: str | None = None) -> str:
        """Generate a threat brief from a list of IOCs."""
        ioc_summary = "\n".join(
            [f"- {i.get('type', '')}: {i.get('value', '')} ({i.get('threat_level', 'unknown')})"
             for i in iocs[:20]]  # Limit to 20 IOCs
        )

        prompt = f"""Generate a concise threat brief based on these IOCs:
{ioc_summary}
{f'Attributed to: {actor}' if actor else ''}

Provide a 2-3 paragraph summary suitable for an analyst briefing."""

        result = await self.ollama.generate(prompt, temperature=0.5)
        return result or "Analysis unavailable"

    async def close(self):
        await self.ollama.close()
