from __future__ import annotations

import time
import os
from typing import Any
import structlog

from google import genai
from google.genai import types

from app.config import get_settings
from app.metrics import LLM_REQUEST_COUNT, LLM_LATENCY, LLM_ERROR_COUNT

logger = structlog.get_logger(__name__)


class GeminiService:
    """Google Gemini AI service for threat intelligence."""

    def __init__(self):
        self._settings = get_settings()
        self.model_name = self._settings.gemini_model
        self._client = None
    
    @property
    def client(self):
        """Lazy-load Gemini client."""
        if self._client is None:
            if self._settings.use_vertex_ai:
                # Use Vertex AI (Agent Platform) with ADC
                self._client = genai.Client(
                    vertexai=True,
                    project=self._settings.google_cloud_project,
                    location=self._settings.google_cloud_location,
                )
            elif self._settings.gemini_api_key:
                # Use express mode with API key
                self._client = genai.Client(api_key=self._settings.gemini_api_key)
            else:
                # Try ADC (Application Default Credentials)
                os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "true"
                if self._settings.google_cloud_project:
                    os.environ["GOOGLE_CLOUD_PROJECT"] = self._settings.google_cloud_project
                os.environ["GOOGLE_CLOUD_LOCATION"] = self._settings.google_cloud_location
                self._client = genai.Client()
        return self._client

    async def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        max_tokens: int = 2048,
        temperature: float = 0.7,
    ) -> str | None:
        """Generate text using Gemini."""
        try:
            start_time = time.time()
            LLM_REQUEST_COUNT.labels(model=self.model_name, operation="generate").inc()

            contents = [prompt]

            config = types.GenerateContentConfig(
                max_output_tokens=max_tokens,
                temperature=temperature,
            )

            if system_prompt:
                config.system_instruction = system_prompt

            response = self.client.models.generate_content(
                model=self.model_name,
                contents=contents,
                config=config,
            )

            LLM_LATENCY.labels(model=self.model_name, operation="generate").observe(time.time() - start_time)
            return response.text if response.text else None
        except Exception as e:
            LLM_ERROR_COUNT.labels(model=self.model_name, error_type=type(e).__name__).inc()
            logger.error("gemini_generate_error", error=str(e))
            return None

    async def chat(
        self,
        messages: list[dict],
        system_prompt: str | None = None,
        max_tokens: int = 2048,
    ) -> str | None:
        """Chat with Gemini using message history."""
        try:
            start_time = time.time()
            LLM_REQUEST_COUNT.labels(model=self.model_name, operation="chat").inc()

            # Convert messages to Gemini format
            contents = []
            for msg in messages:
                role = msg.get("role", "user")
                content = msg.get("content", "")
                if content:
                    contents.append(
                        types.Content(
                            role="user" if role == "user" else "model",
                            parts=[types.Part(text=content)],
                        )
                    )

            config = types.GenerateContentConfig(
                max_output_tokens=max_tokens,
            )

            if system_prompt:
                config.system_instruction = system_prompt

            response = self.client.models.generate_content(
                model=self.model_name,
                contents=contents,
                config=config,
            )

            LLM_LATENCY.labels(model=self.model_name, operation="chat").observe(time.time() - start_time)
            return response.text if response.text else None
        except Exception as e:
            LLM_ERROR_COUNT.labels(model=self.model_name, error_type=type(e).__name__).inc()
            logger.error("gemini_chat_error", error=str(e))
            return None

    async def extract_iocs_from_text(self, text: str) -> list[dict[str, Any]]:
        """Extract IOCs from text using Gemini."""
        try:
            prompt = f"""
Extract all Indicators of Compromise (IOCs) from the following text.
Return the results as a JSON array where each IOC has:
- "type": one of ip, domain, url, hash, email, file_name
- "value": the IOC value
- "confidence": confidence score 0-100

Text:
{text}

Return only the JSON array, no other text.
"""
            
            response_text = await self.generate(prompt, max_tokens=4096)
            
            if not response_text:
                return []
            
            # Parse JSON response
            import json
            # Clean up response - remove markdown code blocks if present
            cleaned = response_text.strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[7:]
            if cleaned.startswith("```"):
                cleaned = cleaned[3:]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            cleaned = cleaned.strip()
            
            iocs = json.loads(cleaned)
            return iocs if isinstance(iocs, list) else []
        except Exception as e:
            logger.error("gemini_ioc_extraction_error", error=str(e))
            return []

    async def map_to_attack(self, text: str) -> dict[str, Any] | None:
        """Map text to MITRE ATT&CK technique using Gemini."""
        try:
            prompt = f"""
Analyze the following text and identify the most relevant MITRE ATT&CK technique.
Return the result as a JSON object with:
- "technique_id": the ATT&CK technique ID (e.g., T1059)
- "technique_name": the technique name
- "tactic": the tactic (e.g., execution)
- "confidence": confidence score 0-100

Text:
{text}

Return only the JSON object, no other text. If no technique matches, return {{"technique_id": "unknown"}}.
"""
            
            response_text = await self.generate(prompt, max_tokens=1024)
            
            if not response_text:
                return None
            
            import json
            cleaned = response_text.strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[7:]
            if cleaned.startswith("```"):
                cleaned = cleaned[3:]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            cleaned = cleaned.strip()
            
            result = json.loads(cleaned)
            return result if isinstance(result, dict) else None
        except Exception as e:
            logger.error("gemini_attack_mapping_error", error=str(e))
            return None

    async def close(self):
        """Clean up resources."""
        pass


class LLMAnalysisService:
    """LLM analysis service using Google Gemini."""

    def __init__(self):
        self.gemini = GeminiService()

    async def analyze_threat_report(self, text: str) -> dict[str, Any] | None:
        """Analyze a threat report using Gemini."""
        try:
            prompt = f"""
Analyze the following threat report and provide:
1. A brief summary
2. Severity assessment (low, medium, high, critical)
3. Key IOCs found
4. Recommended actions

Report:
{text}

Return the analysis as a JSON object with keys: summary, severity, iocs, recommendations.
"""
            
            response_text = await self.gemini.generate(prompt, max_tokens=4096)
            
            if not response_text:
                return None
            
            import json
            cleaned = response_text.strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[7:]
            if cleaned.startswith("```"):
                cleaned = cleaned[3:]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            cleaned = cleaned.strip()
            
            result = json.loads(cleaned)
            return result if isinstance(result, dict) else None
        except Exception as e:
            logger.error("gemini_threat_analysis_error", error=str(e))
            return None

    async def generate_threat_brief(
        self,
        iocs: list[dict],
        actor: str | None = None,
    ) -> str | None:
        """Generate a threat brief from IOCs using Gemini."""
        try:
            iocs_text = "\n".join([
                f"- {ioc.get('type', 'unknown')}: {ioc.get('value', '')}"
                for ioc in iocs
            ])
            
            actor_text = f" attributed to {actor}" if actor else ""
            
            prompt = f"""
Generate a concise threat brief for the following IOCs{actor_text}:

{iocs_text}

Provide a professional threat intelligence summary.
"""
            
            return await self.gemini.generate(prompt, max_tokens=2048)
        except Exception as e:
            logger.error("gemini_threat_brief_error", error=str(e))
            return None

    async def close(self):
        """Clean up resources."""
        await self.gemini.close()
