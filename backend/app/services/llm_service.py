"""LLM Analysis Service — degrades gracefully if google-genai is not installed."""
from __future__ import annotations

import time
import os
from typing import Any
import structlog

from app.config import get_settings
from app.metrics import LLM_REQUEST_COUNT, LLM_LATENCY, LLM_ERROR_COUNT

logger = structlog.get_logger(__name__)


class _GeminiServicePlaceholder:
    """Placeholder when google-genai is not installed."""
    def __init__(self):
        self.model_name = "unavailable"
        self._available = False

    @property
    def client(self):
        raise RuntimeError("google-genai not installed. Run: pip install google-genai")

    async def generate(self, prompt, **kwargs):
        logger.warning("gemini_unavailable", reason="google-genai not installed")
        return None

    async def chat(self, messages, **kwargs):
        logger.warning("gemini_unavailable", reason="google-genai not installed")
        return None

    async def extract_iocs_from_text(self, text):
        return []

    async def map_to_attack(self, text):
        return None

    async def close(self):
        pass


def _create_gemini_service() -> Any:
    """Try to create real GeminiService, fall back to placeholder."""
    try:
        from google import genai
        from google.genai import types
    except ImportError:
        logger.warning("google_genai_not_installed")
        return _GeminiServicePlaceholder()

    class GeminiService:
        """Google Gemini AI service for threat intelligence."""

        def __init__(self):
            self._settings = get_settings()
            self.model_name = self._settings.gemini_model
            self._client = None

        @property
        def client(self):
            if self._client is None:
                try:
                    if self._settings.use_vertex_ai:
                        self._client = genai.Client(
                            vertexai=True,
                            project=self._settings.google_cloud_project,
                            location=self._settings.google_cloud_location,
                        )
                    elif self._settings.gemini_api_key:
                        self._client = genai.Client(api_key=self._settings.gemini_api_key)
                    else:
                        os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "true"
                        if self._settings.google_cloud_project:
                            os.environ["GOOGLE_CLOUD_PROJECT"] = self._settings.google_cloud_project
                        os.environ["GOOGLE_CLOUD_LOCATION"] = self._settings.google_cloud_location
                        self._client = genai.Client()
                except Exception as e:
                    logger.error("gemini_client_init_failed", error=str(e))
                    self._client = None
            return self._client

        async def generate(self, prompt, max_tokens=2048, temperature=0.7, system_prompt=None):
            try:
                if self._client is None:
                    return None
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
                    model=self.model_name, contents=contents, config=config,
                )
                LLM_LATENCY.labels(model=self.model_name, operation="generate").observe(time.time() - start_time)
                return response.text if response.text else None
            except Exception as e:
                LLM_ERROR_COUNT.labels(model=self.model_name, error_type=type(e).__name__).inc()
                logger.error("gemini_generate_error", error=str(e))
                return None

        async def chat(self, messages, max_tokens=2048, system_prompt=None):
            try:
                if self._client is None:
                    return None
                start_time = time.time()
                LLM_REQUEST_COUNT.labels(model=self.model_name, operation="chat").inc()

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

                config = types.GenerateContentConfig(max_output_tokens=max_tokens)
                if system_prompt:
                    config.system_instruction = system_prompt

                response = self.client.models.generate_content(
                    model=self.model_name, contents=contents, config=config,
                )
                LLM_LATENCY.labels(model=self.model_name, operation="chat").observe(time.time() - start_time)
                return response.text if response.text else None
            except Exception as e:
                LLM_ERROR_COUNT.labels(model=self.model_name, error_type=type(e).__name__).inc()
                logger.error("gemini_chat_error", error=str(e))
                return None

        async def extract_iocs_from_text(self, text):
            try:
                prompt = f"""Extract all IOCs from the following text.
Return JSON array with type, value, confidence.
Text: {text}"""
                response_text = await self.generate(prompt, max_tokens=4096)
                if not response_text:
                    return []
                import json
                cleaned = response_text.strip().strip("```json").strip("```").strip()
                return json.loads(cleaned) if isinstance(json.loads(cleaned), list) else []
            except Exception as e:
                logger.error("gemini_ioc_extract_error", error=str(e))
                return []

        async def map_to_attack(self, text):
            try:
                prompt = f"""Analyze text and identify MITRE ATT&CK technique.
Return JSON with technique_id, technique_name, tactic, confidence.
Text: {text}"""
                response_text = await self.generate(prompt, max_tokens=1024)
                if not response_text:
                    return None
                import json
                cleaned = response_text.strip().strip("```json").strip("```").strip()
                result = json.loads(cleaned)
                return result if isinstance(result, dict) else None
            except Exception as e:
                logger.error("gemini_attack_mapping_error", error=str(e))
                return None

        async def close(self):
            pass

    return GeminiService()


_gemini = None


def get_gemini_service() -> Any:
    global _gemini
    if _gemini is None:
        _gemini = _create_gemini_service()
    return _gemini


class LLMAnalysisService:
    """LLM analysis service using Google Gemini (or placeholder)."""

    def __init__(self):
        self.gemini = get_gemini_service()

    async def analyze_threat_report(self, text: str) -> dict[str, Any] | None:
        """Analyze a threat report using Gemini."""
        try:
            start_time = time.time()
            LLM_REQUEST_COUNT.labels(model=self.gemini.model_name, operation="analyze").inc()

            prompt = f"""Analyze the following threat report and provide:
1. A brief summary
2. Severity assessment (low, medium, high, critical)
3. Key IOCs found
4. Recommended actions

Report:
{text[:3000]}

Return JSON with keys: summary, severity, iocs, recommendations."""

            response_text = await self.gemini.generate(prompt, max_tokens=4096)
            LLM_LATENCY.labels(model=self.gemini.model_name, operation="analyze").observe(time.time() - start_time)

            if not response_text:
                return None

            import json
            cleaned = response_text.strip().strip("```json").strip("```").strip()
            result = json.loads(cleaned)
            return result if isinstance(result, dict) else None
        except Exception as e:
            LLM_ERROR_COUNT.labels(model=self.gemini.model_name, error_type=type(e).__name__).inc()
            logger.error("gemini_threat_analysis_error", error=str(e))
            return None

    async def generate_threat_brief(self, iocs: list[dict], actor: str | None = None) -> str | None:
        """Generate a threat brief from IOCs using Gemini."""
        try:
            iocs_text = "\n".join([f"- {ioc.get('type', 'unknown')}: {ioc.get('value', '')}" for ioc in iocs])
            actor_text = f" attributed to {actor}" if actor else ""

            prompt = f"""Generate a concise threat brief for the following IOCs{actor_text}:
{iocs_text}"""

            return await self.gemini.generate(prompt, max_tokens=2048)
        except Exception as e:
            logger.error("gemini_threat_brief_error", error=str(e))
            return None

    async def close(self):
        await self.gemini.close()