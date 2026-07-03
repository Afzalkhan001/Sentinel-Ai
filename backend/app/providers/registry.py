from ..config import settings
from .anthropic import AnthropicProvider
from .base import LLMProvider
from .custom_http import CustomHTTPProvider
from .gemini import GeminiProvider
from .huggingface import HuggingFaceProvider
from .openai_compatible import OpenAICompatibleProvider

# Default base URLs for OpenAI-compatible providers.
OPENAI_COMPATIBLE_BASES = {
    "openai": "https://api.openai.com/v1",
    "groq": settings.groq_base_url,
    "openrouter": "https://openrouter.ai/api/v1",
    "deepseek": "https://api.deepseek.com/v1",
    "ollama": "http://localhost:11434/v1",
}


def get_provider(
    provider: str,
    model_name: str,
    api_key: str | None,
    base_url: str | None = None,
    request_config: dict | None = None,
) -> LLMProvider:
    provider = (provider or "").lower()

    if provider in OPENAI_COMPATIBLE_BASES:
        resolved_base = base_url or OPENAI_COMPATIBLE_BASES[provider]
        return OpenAICompatibleProvider(model_name, api_key, resolved_base)
    if provider == "gemini":
        return GeminiProvider(model_name, api_key, base_url)
    if provider == "anthropic":
        return AnthropicProvider(model_name, api_key, base_url)
    if provider == "huggingface":
        return HuggingFaceProvider(model_name, api_key, base_url)
    if provider == "custom":
        return CustomHTTPProvider(model_name, api_key, base_url, request_config)

    raise ValueError(f"Unknown provider: {provider}")


SUPPORTED_PROVIDERS = list(OPENAI_COMPATIBLE_BASES.keys()) + ["gemini", "anthropic", "huggingface", "custom"]
