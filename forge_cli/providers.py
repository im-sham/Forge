from __future__ import annotations

from typing import Protocol


class LLMProvider(Protocol):
    """Protocol for LLM providers used by forge analyze."""

    def complete(self, prompt: str, max_tokens: int) -> str: ...


class AnthropicProvider:
    def __init__(self, model: str = "claude-sonnet-4-20250514"):
        try:
            import anthropic
        except ImportError:
            raise ImportError(
                "Anthropic SDK not installed. Run: pip install forge-cli[anthropic]"
            )
        self.client = anthropic.Anthropic()
        self.model = model

    def complete(self, prompt: str, max_tokens: int) -> str:
        message = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text


class OpenAIProvider:
    def __init__(self, model: str = "gpt-4o"):
        try:
            import openai
        except ImportError:
            raise ImportError(
                "OpenAI SDK not installed. Run: pip install forge-cli[openai]"
            )
        self.client = openai.OpenAI()
        self.model = model

    def complete(self, prompt: str, max_tokens: int) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message.content


_PROVIDERS = {
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
}


def get_provider(provider_name: str, model: str | None = None) -> LLMProvider:
    """Factory that returns the configured LLM provider."""
    cls = _PROVIDERS.get(provider_name)
    if cls is None:
        available = ", ".join(_PROVIDERS.keys())
        raise ValueError(f"Unknown provider '{provider_name}'. Available: {available}")

    if model:
        return cls(model=model)
    return cls()
