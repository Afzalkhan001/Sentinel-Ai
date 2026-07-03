import json
import time

import httpx

from ..config import settings
from .base import Completion, LLMProvider


def _dig(data, path: str):
    """Extract a nested value using dot-notation (supports numeric list indices).

    e.g. "choices.0.message.content" -> data["choices"][0]["message"]["content"]
    """
    if not path:
        return data
    cur = data
    for part in path.split("."):
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
        if cur is None:
            return None
    return cur


class CustomHTTPProvider(LLMProvider):
    """Generic adapter for testing a real deployed LLM app / chatbot endpoint.

    request_config = {
        "method": "POST",
        "headers": {"Authorization": "Bearer {{api_key}}"},
        "body_template": '{"messages":[{"role":"user","content":"{{prompt}}"}]}',
        "response_path": "choices.0.message.content"
    }

    {{prompt}} is substituted with the JSON-escaped attack text (must sit inside a
    JSON string in the template). {{api_key}} is substituted from the in-memory vault.
    """

    def __init__(self, model_name, api_key=None, base_url=None, request_config=None):
        super().__init__(model_name, api_key, base_url)
        self.cfg = request_config or {}

    async def complete(self, prompt, system=None, temperature=0.0, max_tokens=512) -> Completion:
        url = self.base_url or ""
        method = (self.cfg.get("method") or "POST").upper()
        response_path = self.cfg.get("response_path") or ""

        def sub_key(s: str) -> str:
            return (s or "").replace("{{api_key}}", self.api_key or "")

        headers = {k: sub_key(v) for k, v in (self.cfg.get("headers") or {}).items()}
        headers.setdefault("Content-Type", "application/json")

        # JSON-escape the prompt so quotes/newlines don't break the body template.
        esc_prompt = json.dumps(prompt)[1:-1]
        body_template = self.cfg.get("body_template") or '{"prompt": "{{prompt}}"}'
        body_str = sub_key(body_template).replace("{{prompt}}", esc_prompt)

        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=settings.request_timeout_s) as client:
                resp = await client.request(method, url, content=body_str.encode("utf-8"), headers=headers)
                resp.raise_for_status()
                try:
                    data = resp.json()
                except Exception:  # noqa: BLE001
                    # Non-JSON endpoint: treat raw text as the answer.
                    return Completion(text=resp.text, raw={}, latency_ms=int((time.perf_counter() - start) * 1000))

            extracted = _dig(data, response_path)
            if extracted is None:
                extracted = data  # fall back to the whole payload so the user can see it
            text = extracted if isinstance(extracted, str) else json.dumps(extracted)
            raw = data if isinstance(data, dict) else {"data": data}
            return Completion(text=text, raw=raw, latency_ms=int((time.perf_counter() - start) * 1000))
        except Exception as e:  # noqa: BLE001
            return Completion(text="", latency_ms=int((time.perf_counter() - start) * 1000), error=str(e))
