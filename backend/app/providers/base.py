from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class Completion:
    text: str
    raw: dict = field(default_factory=dict)
    latency_ms: int = 0
    error: str | None = None


class LLMProvider(ABC):
    """One interface every provider adapter conforms to."""

    def __init__(self, model_name: str, api_key: str | None = None, base_url: str | None = None):
        self.model_name = model_name
        self.api_key = api_key
        self.base_url = base_url

    @abstractmethod
    async def complete(
        self,
        prompt: str,
        system: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 512,
    ) -> Completion:
        """Send a single prompt, return a normalized Completion.

        Adapters MUST catch their own exceptions and return Completion(error=...)
        rather than raising, so one failing attack never aborts a whole run.
        """
        ...
