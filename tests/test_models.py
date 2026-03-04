from forge_cli.models import FailureType, Incident, Severity


def test_severity_enum_values():
    assert Severity.COSMETIC.value == "cosmetic"
    assert Severity.FUNCTIONAL.value == "functional"
    assert Severity.SAFETY_CRITICAL.value == "safety-critical"


def test_failure_type_enum_count():
    assert len(FailureType) == 12


def test_incident_from_dict(sample_data):
    incident = Incident.from_dict(sample_data)
    assert incident.id == "2026-03-04-001"
    assert incident.project == "mila"
    assert incident.platform == "claude-code"
    assert incident.severity == "functional"
    assert incident.tags == ["hallucination", "long-document"]


def test_incident_to_dict_roundtrip(sample_data):
    incident = Incident.from_dict(sample_data)
    result = incident.to_dict()
    assert result["id"] == sample_data["id"]
    assert result["project"] == sample_data["project"]
    assert result["platform"] == "claude-code"
    assert result["tags"] == sample_data["tags"]


def test_incident_from_dict_missing_platform():
    """Backwards compat: incidents without platform field should load fine."""
    data = {
        "id": "2026-03-04-001",
        "timestamp": "2026-03-04T14:30:00Z",
        "reported_by": "sham",
        "project": "mila",
        "agent": "test-agent",
        "severity": "cosmetic",
        "failure_type": "other",
        "expected_behavior": "expected",
        "actual_behavior": "actual",
        "context": "",
        "root_cause": "",
        "immediate_fix": "",
        "systemic_takeaway": "",
    }
    incident = Incident.from_dict(data)
    assert incident.platform == ""
    assert incident.tags == []
    assert incident.related_incidents == []
    assert incident.playbook_entry == ""


def test_incident_free_text_project():
    """Project field accepts any string value (not enum-constrained)."""
    data = {
        "id": "2026-03-04-001",
        "timestamp": "2026-03-04T14:30:00Z",
        "reported_by": "sham",
        "project": "my-custom-project",
        "agent": "test-agent",
        "platform": "cursor",
        "severity": "functional",
        "failure_type": "hallucination",
        "expected_behavior": "expected",
        "actual_behavior": "actual",
        "context": "",
        "root_cause": "",
        "immediate_fix": "",
        "systemic_takeaway": "",
    }
    incident = Incident.from_dict(data)
    assert incident.project == "my-custom-project"
    assert incident.platform == "cursor"
