from __future__ import annotations

import os
from typing import Any

from google import genai
from google.genai import types

from app.config import get_settings


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
            
            return response.text if response.text else None
        except Exception as e:
            print(f"Gemini generate error: {e}")
            return None

    async def chat(
        self,
        messages: list[dict],
        system_prompt: str | None = None,
        max_tokens: int = 2048,
    ) -> str | None:
        """Chat with Gemini using message history."""
        try:
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
            
            return response.text if response.text else None
        except Exception as e:
            print(f"Gemini chat error: {e}")
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
            print(f"Gemini IOC extraction error: {e}")
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
            print(f"Gemini ATT&CK mapping error: {e}")
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
            print(f"Gemini threat analysis error: {e}")
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
            print(f"Gemini threat brief error: {e}")
            return None

    async def close(self):
        """Clean up resources."""
        await self.gemini.close()
