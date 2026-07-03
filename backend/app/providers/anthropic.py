import time

import httpx

from ..config import settings
from .base import Completion, LLMProvider

DEFAULT_BASE = "https://api.anthropic.com/v1"


class AnthropicProvider(LLMProvider):
    async def complete(
        self,
        prompt: str,
        system: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 512,
    ) -> Completion:
        base = (self.base_url or DEFAULT_BASE).rstrip("/")
        url = f"{base}/messages"
        headers = {
            "x-api-key": self.api_key or "",
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": self.model_name,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            payload["system"] = system

        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=settings.request_timeout_s) as client:
                resp = await client.post(url, json=payload, headers=headers)
                resp.raise_for_status()
                data = resp.json()
            text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
            return Completion(text=text, raw=data, latency_ms=int((time.perf_counter() - start) * 1000))
        except Exception as e:  # noqa: BLE001
            return Completion(text="", latency_ms=int((time.perf_counter() - start) * 1000), error=str(e))
