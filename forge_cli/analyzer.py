from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import yaml

from forge_cli.models import Incident
from forge_cli.providers import LLMProvider


def serialize_incidents_for_analysis(incidents: list[Incident]) -> str:
    """Serialize incidents to YAML for insertion into the analysis prompt."""
    return yaml.dump(
        [incident.to_dict() for incident in incidents],
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
    )


def render_analysis_prompt(prompt_template: str, incidents_yaml: str) -> str:
    """Insert serialized incident data into the analysis prompt template."""
    return prompt_template.replace(
        "[INCIDENTS ARE INSERTED HERE AS YAML]",
        incidents_yaml,
    )


def next_analysis_output_path(
    output_dir: Path,
    *,
    date_prefix: str | None = None,
    label: str = "analysis",
) -> Path:
    """Return the next non-conflicting dated output path inside the analysis directory."""
    output_dir.mkdir(parents=True, exist_ok=True)

    if date_prefix is None:
        date_prefix = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    base_path = output_dir / f"{date_prefix}-{label}.md"
    if not base_path.exists():
        return base_path

    seq = 2
    while True:
        candidate = output_dir / f"{date_prefix}-{label}-{seq}.md"
        if not candidate.exists():
            return candidate
        seq += 1


def analyze_incidents(
    incidents_yaml: str,
    prompt_template: str,
    provider: LLMProvider,
    max_tokens: int = 4096,
) -> str:
    """Send incidents to an LLM for pattern analysis. Returns markdown report."""
    prompt = render_analysis_prompt(prompt_template, incidents_yaml)

    return provider.complete(prompt, max_tokens)
