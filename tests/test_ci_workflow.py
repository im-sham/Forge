from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
ACTION_REF = re.compile(r"^\s*-?\s*uses:\s+([^\s]+)@([^\s#]+)", re.MULTILINE)


def test_ci_workflow_has_dependency_security_gate() -> None:
    workflow = CI_WORKFLOW.read_text()

    assert "permissions:" in workflow
    assert "contents: read" in workflow
    assert "dependency-security:" in workflow
    assert "scripts/verify_dependency_artifacts.py --check-lock" in workflow
    assert "--require-hashes --no-deps -r requirements/dev.lock" in workflow
    assert "requirements/${surface}.lock" in workflow
    assert "--generate-sboms" in workflow
    assert "--validate-sboms" in workflow
    assert "--check-environment" in workflow
    assert '"${runtime_forge}" --help' in workflow
    assert "from forge_cli.mcp_server import forge_schema" in workflow
    assert "-m pip_audit" in workflow
    assert "--ignore-vuln" not in workflow
    assert 'pip install -e ".[dev]' not in workflow


def test_github_actions_are_pinned_to_commit_shas() -> None:
    external_actions = [
        (action, revision)
        for action, revision in ACTION_REF.findall(CI_WORKFLOW.read_text())
        if not action.startswith("./")
    ]

    assert external_actions
    assert all(re.fullmatch(r"[0-9a-f]{40}", revision) for _, revision in external_actions)


def test_dependabot_tracks_ci_and_python_updates() -> None:
    config = ROOT / ".github" / "dependabot.yml"

    assert config.exists()
    content = config.read_text()
    assert 'package-ecosystem: "github-actions"' in content
    assert 'package-ecosystem: "pip"' in content


def test_ci_exercises_all_declared_python_versions() -> None:
    workflow = CI_WORKFLOW.read_text()

    assert 'python-version: ["3.11", "3.12", "3.13"]' in workflow
    assert 'python-version: "3.14"' not in workflow
    assert "ubuntu-latest" in workflow
    assert "macos-latest" in workflow
    assert "windows-latest" in workflow
