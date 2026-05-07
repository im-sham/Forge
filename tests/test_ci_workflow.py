from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def test_ci_workflow_has_dependency_security_gate() -> None:
    workflow = CI_WORKFLOW.read_text()

    assert "permissions:" in workflow
    assert "contents: read" in workflow
    assert "dependency-security:" in workflow
    assert 'python -m pip install --upgrade "pip>=26.1"' in workflow
    assert "python -m pip install pip-audit" in workflow
    assert "python -m pip_audit --progress-spinner off" in workflow
