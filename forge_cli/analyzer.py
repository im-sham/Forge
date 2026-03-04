from __future__ import annotations

from forge_cli.providers import LLMProvider


def analyze_incidents(
    incidents_yaml: str,
    prompt_template: str,
    provider: LLMProvider,
    max_tokens: int = 4096,
) -> str:
    """Send incidents to an LLM for pattern analysis. Returns markdown report."""
    prompt = prompt_template.replace(
        "[INCIDENTS ARE INSERTED HERE AS YAML]",
        incidents_yaml,
    )

    return provider.complete(prompt, max_tokens)
