import time

import httpx

from ..config import settings
from .base import Completion, LLMProvider

DEFAULT_BASE = "https://api-inference.huggingface.co/models"


class HuggingFaceProvider(LLMProvider):
    async def complete(
        self,
        prompt: str,
        system: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 512,
    ) -> Completion:
        base = (self.base_url or DEFAULT_BASE).rstrip("/")
        url = f"{base}/{self.model_name}"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        full_prompt = f"{system}\n\n{prompt}" if system else prompt
        payload = {
            "inputs": full_prompt,
            "parameters": {
                "temperature": max(temperature, 0.01),
                "max_new_tokens": max_tokens,
                "return_full_text": False,
            },
        }

        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=settings.request_timeout_s) as client:
                resp = await client.post(url, json=payload, headers=headers)
                resp.raise_for_status()
                data = resp.json()
            if isinstance(data, list) and data:
                text = data[0].get("generated_text", "")
            elif isinstance(data, dict):
                text = data.get("generated_text", "")
            else:
                text = str(data)
            return Completion(text=text, raw={"data": data}, latency_ms=int((time.perf_counter() - start) * 1000))
        except Exception as e:  # noqa: BLE001
            return Completion(text="", latency_ms=int((time.perf_counter() - start) * 1000), error=str(e))
