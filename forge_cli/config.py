from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path

import yaml


@dataclass
class ForgeConfig:
    root: Path
    data_root: Path | None = None
    default_reporter: str = "forge-user"
    organization_name: str = "your organization"
    analysis_provider: str = "anthropic"
    analysis_model: str = "claude-sonnet-4-20250514"
    analysis_max_tokens: int = 4096
    projects: list[str] = field(
        default_factory=lambda: [
            "support-agent",
            "research-assistant",
            "workflow-orchestrator",
            "governance-service",
            "sales-copilot",
        ]
    )
    platforms: list[str] = field(
        default_factory=lambda: [
            "claude-code", "claude-api", "cursor", "chatgpt", "codex", "copilot", "custom"
        ]
    )

    def __post_init__(self) -> None:
        self.root = self.root.expanduser().resolve()
        if self.data_root is None:
            self.data_root = self.root
        else:
            self.data_root = self.data_root.expanduser()
            if not self.data_root.is_absolute():
                self.data_root = (self.root / self.data_root).resolve()

    @property
    def incidents_dir(self) -> Path:
        return self.data_root / "incidents"

    @property
    def analysis_dir(self) -> Path:
        return self.data_root / "analysis"

    @property
    def templates_dir(self) -> Path:
        return self.root / "templates"

    @property
    def playbook_dir(self) -> Path:
        return self.data_root / "playbook"


def find_project_root(start: Path | None = None) -> Path | None:
    """Walk up from start directory looking for pyproject.toml to find the forge root."""
    current = (start or Path.cwd()).resolve()
    for directory in [current, *current.parents]:
        if (directory / "pyproject.toml").exists() and (directory / "forge_cli").is_dir():
            return directory
    return None


def _apply_config_values(config: ForgeConfig, data: dict) -> ForgeConfig:
    data_root = data.get("data_root")
    if data_root:
        config.data_root = Path(str(data_root)).expanduser()
        if not config.data_root.is_absolute():
            config.data_root = (config.root / config.data_root).resolve()

    config.default_reporter = data.get("default_reporter", config.default_reporter)
    config.organization_name = data.get("organization_name", config.organization_name)
    config.projects = data.get("projects", config.projects)
    config.platforms = data.get("platforms", config.platforms)

    analysis = data.get("analysis", {})
    if analysis:
        config.analysis_provider = analysis.get("provider", config.analysis_provider)
        config.analysis_model = analysis.get("model", config.analysis_model)
        config.analysis_max_tokens = analysis.get("max_tokens", config.analysis_max_tokens)

    return config


def load_config(root: Path | None = None) -> ForgeConfig:
    """Load forge configuration from config files and environment overrides."""
    if root is None:
        root = find_project_root()
    if root is None:
        raise FileNotFoundError(
            "Could not find forge project root. "
            "Run forge from within the forge directory or a subdirectory."
        )

    root = root.expanduser().resolve()
    config = ForgeConfig(root=root, data_root=root)

    for config_name in ("config.yaml", "config.local.yaml"):
        config_path = root / config_name
        if not config_path.exists():
            continue
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
        config = _apply_config_values(config, data)

    env_data_root = os.environ.get("FORGE_DATA_ROOT")
    if env_data_root:
        config.data_root = Path(env_data_root).expanduser()
        if not config.data_root.is_absolute():
            config.data_root = (config.root / config.data_root).resolve()

    return config
