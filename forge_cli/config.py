from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class ForgeConfig:
    root: Path
    default_reporter: str = "sham"
    analysis_provider: str = "anthropic"
    analysis_model: str = "claude-sonnet-4-20250514"
    analysis_max_tokens: int = 4096
    projects: list[str] = field(
        default_factory=lambda: ["mila", "scalescore", "aegis", "sentinel", "ghost-sentry"]
    )
    platforms: list[str] = field(
        default_factory=lambda: [
            "claude-code", "claude-api", "cursor", "chatgpt", "codex", "copilot", "custom"
        ]
    )

    @property
    def incidents_dir(self) -> Path:
        return self.root / "incidents"

    @property
    def analysis_dir(self) -> Path:
        return self.root / "analysis"

    @property
    def templates_dir(self) -> Path:
        return self.root / "templates"

    @property
    def playbook_dir(self) -> Path:
        return self.root / "playbook"


def find_project_root(start: Path | None = None) -> Path | None:
    """Walk up from start directory looking for pyproject.toml to find the forge root."""
    current = (start or Path.cwd()).resolve()
    for directory in [current, *current.parents]:
        if (directory / "pyproject.toml").exists() and (directory / "forge_cli").is_dir():
            return directory
    return None


def load_config(root: Path | None = None) -> ForgeConfig:
    """Load forge configuration from config.yaml at the project root."""
    if root is None:
        root = find_project_root()
    if root is None:
        raise FileNotFoundError(
            "Could not find forge project root. "
            "Run forge from within the forge directory or a subdirectory."
        )

    config = ForgeConfig(root=root)

    config_path = root / "config.yaml"
    if config_path.exists():
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}

        config.default_reporter = data.get("default_reporter", config.default_reporter)
        config.projects = data.get("projects", config.projects)
        config.platforms = data.get("platforms", config.platforms)

        analysis = data.get("analysis", {})
        if analysis:
            config.analysis_provider = analysis.get("provider", config.analysis_provider)
            config.analysis_model = analysis.get("model", config.analysis_model)
            config.analysis_max_tokens = analysis.get("max_tokens", config.analysis_max_tokens)

    return config
