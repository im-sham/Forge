from datetime import date
from pathlib import Path

from forge_cli.incident_store import (
    AmbiguousIncidentLookupError,
    DuplicateIncidentError,
    find_incident,
    find_incident_path,
    generate_id,
    list_incidents,
    load_incident,
    save_incident,
)
from forge_cli.models import Incident


def test_generate_id_first_of_day(tmp_incidents_dir):
    incident_id = generate_id(tmp_incidents_dir, date(2026, 3, 4))
    assert incident_id == "2026-03-04-001"


def test_generate_id_sequential(tmp_incidents_dir):
    # Create month dir and a fake first incident
    month_dir = tmp_incidents_dir / "2026-03"
    month_dir.mkdir()
    (month_dir / "2026-03-04-001.yml").write_text("id: '2026-03-04-001'")
    (month_dir / "2026-03-04-002.yml").write_text("id: '2026-03-04-002'")

    incident_id = generate_id(tmp_incidents_dir, date(2026, 3, 4))
    assert incident_id == "2026-03-04-003"


def test_save_and_load_roundtrip(tmp_incidents_dir, sample_data):
    incident = Incident.from_dict(sample_data)
    filepath = save_incident(incident, tmp_incidents_dir)

    assert filepath.exists()
    assert filepath.name == "2026-03-04-001.yml"
    assert filepath.parent.name == "2026-03"

    loaded = load_incident(filepath)
    assert loaded.id == incident.id
    assert loaded.project == incident.project
    assert loaded.platform == incident.platform
    assert loaded.severity == incident.severity
    assert loaded.failure_type == incident.failure_type
    assert loaded.tags == incident.tags


def test_save_creates_month_directory(tmp_incidents_dir, sample_data):
    incident = Incident.from_dict(sample_data)
    save_incident(incident, tmp_incidents_dir)
    assert (tmp_incidents_dir / "2026-03").is_dir()


def test_list_incidents_empty(tmp_incidents_dir):
    result = list_incidents(tmp_incidents_dir)
    assert result == []


def test_list_incidents_with_filter(tmp_incidents_dir, sample_data):
    incident = Incident.from_dict(sample_data)
    save_incident(incident, tmp_incidents_dir)

    # Match project
    result = list_incidents(tmp_incidents_dir, project="mila")
    assert len(result) == 1

    # No match
    result = list_incidents(tmp_incidents_dir, project="aegis")
    assert len(result) == 0


def test_list_incidents_severity_filter(tmp_incidents_dir, sample_data):
    incident = Incident.from_dict(sample_data)
    save_incident(incident, tmp_incidents_dir)

    result = list_incidents(tmp_incidents_dir, severity="functional")
    assert len(result) == 1

    result = list_incidents(tmp_incidents_dir, severity="safety-critical")
    assert len(result) == 0


def test_yaml_multiline_block_style(tmp_incidents_dir):
    data = {
        "id": "2026-03-04-001",
        "timestamp": "2026-03-04T14:30:00Z",
        "reported_by": "sham",
        "project": "mila",
        "agent": "test",
        "platform": "claude-code",
        "severity": "functional",
        "failure_type": "hallucination",
        "expected_behavior": "Line one.\nLine two.",
        "actual_behavior": "Single line.",
        "context": "",
        "root_cause": "",
        "immediate_fix": "",
        "systemic_takeaway": "",
    }
    incident = Incident.from_dict(data)
    filepath = save_incident(incident, tmp_incidents_dir)

    raw = filepath.read_text()
    # Multiline field should use block scalar style (|- strips trailing newline)
    assert "|-" in raw or "|\n" in raw
    assert "Line one." in raw
    assert "Line two." in raw


def test_find_incident_exact(tmp_incidents_dir, sample_data):
    incident = Incident.from_dict(sample_data)
    save_incident(incident, tmp_incidents_dir)

    found = find_incident(tmp_incidents_dir, "2026-03-04-001")
    assert found is not None
    assert found.id == "2026-03-04-001"


def test_find_incident_suffix(tmp_incidents_dir, sample_data):
    incident = Incident.from_dict(sample_data)
    save_incident(incident, tmp_incidents_dir)

    found = find_incident(tmp_incidents_dir, "001")
    assert found is not None
    assert found.id == "2026-03-04-001"


def test_find_incident_not_found(tmp_incidents_dir):
    found = find_incident(tmp_incidents_dir, "9999")
    assert found is None


def test_find_incident_path_returns_path(tmp_incidents_dir, sample_data):
    incident = Incident.from_dict(sample_data)
    saved = save_incident(incident, tmp_incidents_dir)

    path = find_incident_path(tmp_incidents_dir, "2026-03-04-001")
    assert path is not None
    assert path == saved


def test_find_incident_path_not_found(tmp_incidents_dir):
    path = find_incident_path(tmp_incidents_dir, "9999")
    assert path is None


def test_list_incidents_tag_filter(tmp_incidents_dir, sample_data):
    incident = Incident.from_dict(sample_data)
    save_incident(incident, tmp_incidents_dir)

    # sample_data has tags: ["hallucination", "long-document"]
    result = list_incidents(tmp_incidents_dir, tag="hallucination")
    assert len(result) == 1

    result = list_incidents(tmp_incidents_dir, tag="nonexistent-tag")
    assert len(result) == 0


def test_list_incidents_filters_structured_axes(tmp_incidents_dir, sample_data):
    first = sample_data.copy()
    first.update(
        {
            "issue_class": "rate_source_ambiguity",
            "capability_area": "workflow_context",
            "lifecycle_stage": "evidence_review",
            "workflow_archetype": "claims_hybrid_high_dollar_review",
            "blocked_use_class": "internal_eval",
        }
    )
    second = sample_data.copy()
    second.update(
        {
            "id": "2026-03-04-002",
            "issue_class": "redaction_miss",
            "capability_area": "governance",
            "lifecycle_stage": "redaction_review",
            "workflow_archetype": "document_operations",
            "blocked_use_class": "external_export",
        }
    )
    save_incident(Incident.from_dict(first), tmp_incidents_dir)
    save_incident(Incident.from_dict(second), tmp_incidents_dir)

    result = list_incidents(
        tmp_incidents_dir,
        issue_class="rate_source_ambiguity",
        capability_area="workflow_context",
        lifecycle_stage="evidence_review",
        workflow_archetype="claims_hybrid_high_dollar_review",
        blocked_use_class="internal_eval",
    )

    assert [incident.id for incident in result] == ["2026-03-04-001"]


def test_save_incident_rejects_duplicate_id(tmp_incidents_dir, sample_data):
    incident = Incident.from_dict(sample_data)
    save_incident(incident, tmp_incidents_dir)

    try:
        save_incident(incident, tmp_incidents_dir)
    except DuplicateIncidentError as exc:
        assert "2026-03-04-001" in str(exc)
    else:
        raise AssertionError("expected duplicate incident id to be rejected")


def test_find_incident_path_rejects_ambiguous_suffix(tmp_incidents_dir, sample_data):
    first = Incident.from_dict(sample_data)
    second_data = sample_data.copy()
    second_data["id"] = "2026-03-05-001"
    second_data["timestamp"] = "2026-03-05T14:30:00Z"
    save_incident(first, tmp_incidents_dir)
    save_incident(Incident.from_dict(second_data), tmp_incidents_dir)

    try:
        find_incident_path(tmp_incidents_dir, "001")
    except AmbiguousIncidentLookupError as exc:
        assert "2026-03-04-001" in str(exc)
        assert "2026-03-05-001" in str(exc)
    else:
        raise AssertionError("expected ambiguous suffix lookup to be rejected")


def test_document_operations_example_loads_as_structured_stub():
    fixture_path = (
        Path(__file__).parents[1]
        / "examples"
        / "document-operations"
        / "redaction-miss-incident.yml"
    )

    incident = load_incident(fixture_path)

    assert incident.project == "proofhouse-document-operations"
    assert incident.capability_area == "governance"
    assert incident.lifecycle_stage == "redaction_review"
    assert incident.issue_class == "redaction_miss"
    assert incident.workflow_archetype == "document_operations"
    assert incident.workflow_ref is not None
    assert incident.workflow_evidence_snapshot is not None
    assert incident.assessment_ref is not None
    assert incident.use_approval_ref is not None
    assert incident.workflow_ref["cache_policy"] == "ref_only"
    assert incident.asset_ref["cache_policy"] == "ref_only"


def test_claims_rate_source_example_roundtrips_to_valid_incident_ref():
    fixture_path = (
        Path(__file__).parents[1]
        / "examples"
        / "claims"
        / "rate-source-ambiguity-incident.yml"
    )

    incident = load_incident(fixture_path)
    result = incident.to_dict()
    envelope = incident.to_ref_envelope()
    ref = envelope["ref"]

    assert incident.project == "proofhouse-claims"
    assert incident.issue_class == "rate_source_ambiguity"
    assert incident.workflow_archetype == "claims_hybrid_high_dollar_review"
    assert incident.subject_type == "claim_review_packet"
    assert result["workflow_ref"]["cache_policy"] == "summary_snapshot"
    assert result["workflow_evidence_snapshot"]["cache_policy"] == "digest_snapshot"
    assert result["assessment_ref"]["cache_policy"] == "summary_snapshot"
    assert result["policy_decision_ref"]["cache_policy"] == "ref_only"
    assert result["use_approval_ref"]["cache_policy"] == "ref_only"
    assert ref["ref_id"] == "incident:example-claims-rate-source-ambiguity"
    assert ref["ref_type"] == "incident"
    assert ref["source_capability"] == "forge"
    assert ref["issue_class"] == "rate_source_ambiguity"
    assert "expected_behavior" not in ref
    assert "actual_behavior" not in ref


def test_claims_rate_source_example_is_pointer_and_summary_only():
    fixture_path = (
        Path(__file__).parents[1]
        / "examples"
        / "claims"
        / "rate-source-ambiguity-incident.yml"
    )
    raw = fixture_path.read_text().lower()
    incident = load_incident(fixture_path)

    forbidden_terms = [
        "member name",
        "patient name",
        "date of birth",
        "dob",
        "ssn",
        "837",
        "835",
        "turquoise live",
        "raw claim",
        "claim payload",
        "rate table row",
    ]

    assert incident.observed_state["boundary_note"].startswith("Forge stores only")
    assert all(term not in raw for term in forbidden_terms)
