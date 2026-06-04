from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
PYTHON_CONSTRAINTS = ROOT / "constraints.txt"
TAGGED_ACTION_REF = re.compile(r"uses:\s+[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@v\d+")


def test_ci_workflow_has_dependency_security_gate() -> None:
    workflow = CI_WORKFLOW.read_text()

    assert "permissions:" in workflow
    assert "contents: read" in workflow
    assert "dependency-security:" in workflow
    assert 'python -m pip install --upgrade "pip>=26.1"' in workflow
    assert "python -m pip install pip-audit" in workflow
    assert "python -m pip_audit --progress-spinner off -r constraints.txt" in workflow


def test_ci_installs_project_dependencies_with_python_constraints() -> None:
    workflow = CI_WORKFLOW.read_text()

    assert 'pip install -c constraints.txt -e ".[dev]"' in workflow
    assert 'python -m pip install -c constraints.txt -e ".[dev]"' in workflow


def test_python_constraints_pin_ci_dependency_set() -> None:
    assert PYTHON_CONSTRAINTS.exists()
    content = PYTHON_CONSTRAINTS.read_text()

    for package in ("typer", "rich", "pyyaml", "pytest", "ruff"):
        assert f"{package}==" in content.lower()

    unconstrained_lines = [
        line
        for line in content.splitlines()
        if line.strip() and not line.startswith("#") and "==" not in line
    ]
    assert unconstrained_lines == []


def test_github_actions_are_pinned_to_commit_shas() -> None:
    offenders = [
        line.strip()
        for line in CI_WORKFLOW.read_text().splitlines()
        if TAGGED_ACTION_REF.search(line)
    ]

    assert offenders == []


def test_dependabot_tracks_ci_and_python_updates() -> None:
    config = ROOT / ".github" / "dependabot.yml"

    assert config.exists()
    content = config.read_text()
    assert 'package-ecosystem: "github-actions"' in content
    assert 'package-ecosystem: "pip"' in content
