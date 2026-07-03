import asyncio
import time

import httpx

from ..config import settings
from .base import Completion, LLMProvider


class OpenAICompatibleProvider(LLMProvider):
    """Covers OpenAI, Groq, OpenRouter, DeepSeek, and Ollama.

    They all speak the /chat/completions schema; only base_url (and whether a
    key is required) differs. Ollama needs no API key.
    """

    async def complete(
        self,
        prompt: str,
        system: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 512,
    ) -> Completion:
        url = f"{(self.base_url or '').rstrip('/')}/chat/completions"
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": self.model_name,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        start = time.perf_counter()
        backoff = 1.0
        last_err = None
        async with httpx.AsyncClient(timeout=settings.request_timeout_s) as client:
            for attempt in range(4):
                try:
                    resp = await client.post(url, json=payload, headers=headers)
                    if resp.status_code == 429:
                        last_err = "rate limited (429)"
                        await asyncio.sleep(backoff)
                        backoff *= 2
                        continue
                    resp.raise_for_status()
                    data = resp.json()
                    text = data["choices"][0]["message"]["content"] or ""
                    latency = int((time.perf_counter() - start) * 1000)
                    return Completion(text=text, raw=data, latency_ms=latency)
                except httpx.HTTPStatusError as e:
                    body = e.response.text[:300] if e.response is not None else ""
                    last_err = f"HTTP {e.response.status_code}: {body}"
                    break
                except Exception as e:  # noqa: BLE001
                    last_err = str(e)
                    break

        latency = int((time.perf_counter() - start) * 1000)
        return Completion(text="", latency_ms=latency, error=last_err or "unknown error")
