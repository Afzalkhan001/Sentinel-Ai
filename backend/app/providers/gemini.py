import time

import httpx

from ..config import settings
from .base import Completion, LLMProvider

DEFAULT_BASE = "https://generativelanguage.googleapis.com/v1beta"


class GeminiProvider(LLMProvider):
    async def complete(
        self,
        prompt: str,
        system: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 512,
    ) -> Completion:
        base = (self.base_url or DEFAULT_BASE).rstrip("/")
        url = f"{base}/models/{self.model_name}:generateContent?key={self.api_key}"
        payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": temperature, "maxOutputTokens": max_tokens},
        }
        if system:
            payload["systemInstruction"] = {"parts": [{"text": system}]}

        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=settings.request_timeout_s) as client:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
                data = resp.json()
            parts = data["candidates"][0]["content"]["parts"]
            text = "".join(p.get("text", "") for p in parts)
            return Completion(text=text, raw=data, latency_ms=int((time.perf_counter() - start) * 1000))
        except Exception as e:  # noqa: BLE001
            return Completion(text="", latency_ms=int((time.perf_counter() - start) * 1000), error=str(e))
