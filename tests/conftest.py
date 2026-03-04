from __future__ import annotations

from pathlib import Path

import pytest


SAMPLE_INCIDENT_DATA = {
    "id": "2026-03-04-001",
    "timestamp": "2026-03-04T14:30:00Z",
    "reported_by": "sham",
    "project": "mila",
    "agent": "document-analyzer",
    "platform": "claude-code",
    "severity": "functional",
    "failure_type": "hallucination",
    "expected_behavior": "Agent should have extracted the three key metrics.",
    "actual_behavior": "Agent fabricated two of three metrics.",
    "context": "Document was a 47-page PDF.",
    "root_cause": "context_window_overflow",
    "immediate_fix": "Added page-specific extraction.",
    "systemic_takeaway": "Long documents need chunked extraction.",
    "tags": ["hallucination", "long-document"],
    "related_incidents": [],
    "playbook_entry": "",
}


@pytest.fixture
def tmp_incidents_dir(tmp_path: Path) -> Path:
    """Create a temporary incidents directory."""
    incidents = tmp_path / "incidents"
    incidents.mkdir()
    return incidents


@pytest.fixture
def sample_data() -> dict:
    return SAMPLE_INCIDENT_DATA.copy()
