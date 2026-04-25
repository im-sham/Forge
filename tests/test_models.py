from forge_cli.models import (
    FORGE_DEFAULT_ENVIRONMENT_ID,
    FORGE_UNSCOPED_ORGANIZATION_ID,
    PROOFHOUSE_SHARED_CONTRACT_VERSION,
    FailureType,
    Incident,
    Severity,
)


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
    assert "workflow_ref" not in result
    assert "assessment_ref" not in result


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


def test_incident_ref_projection_preserves_boundary(sample_data):
    incident = Incident.from_dict(sample_data)
    ref = incident.to_ref()
    data = ref.to_dict()

    assert ref.ref_id == "incident:2026-03-04-001"
    assert ref.ref_type == "incident"
    assert ref.source_capability == "forge"
    assert ref.organization_id == FORGE_UNSCOPED_ORGANIZATION_ID
    assert ref.environment_id == FORGE_DEFAULT_ENVIRONMENT_ID
    assert ref.incident_id == sample_data["id"]
    assert ref.failure_type == "hallucination"
    assert ref.severity == "functional"
    assert ref.capability_area == "unknown"
    assert ref.lifecycle_stage == "unknown"
    assert ref.issue_class == "hallucination"
    assert ref.workflow_ref is None
    assert ref.assessment_ref is None
    assert "expected_behavior" not in data
    assert "actual_behavior" not in data


def test_incident_ref_projection_infers_proofhouse_axes(sample_data):
    data = sample_data.copy()
    data["project"] = "sentinel"
    data["tags"] = ["operational-learning", "use-approval", "redaction"]
    incident = Incident.from_dict(data)
    ref = incident.to_ref()

    assert ref.capability_area == "governance"
    assert ref.lifecycle_stage == "approval"
    assert ref.issue_class == "use_approval"


def test_incident_ref_envelope_shape(sample_data):
    incident = Incident.from_dict(sample_data)
    envelope = incident.to_ref_envelope()

    assert envelope["contract_version"] == PROOFHOUSE_SHARED_CONTRACT_VERSION
    assert envelope["contract_name"] == "IncidentRef"
    assert envelope["producer_capability"] == "forge"
    assert envelope["producer_system"] == "proofhouse-forge"
    assert envelope["canonical_owner"] == "forge"
    assert envelope["cache_policy"] == "summary_snapshot"
    assert envelope["ref"]["incident_id"] == sample_data["id"]
    assert envelope["ref"]["organization_id"] == FORGE_UNSCOPED_ORGANIZATION_ID
