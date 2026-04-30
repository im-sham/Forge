import pytest

from forge_cli.models import (
    FORGE_DEFAULT_ENVIRONMENT_ID,
    FORGE_UNSCOPED_ORGANIZATION_ID,
    PROOFHOUSE_REF_FIELDS,
    PROOFHOUSE_SHARED_CONTRACT_VERSION,
    FailureType,
    Incident,
    ISSUE_CLASS_VALUES,
    Severity,
    parse_observed_state,
    parse_pointer_value,
)
from forge_cli.schema_metadata import STRUCTURED_AXIS_METADATA


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
    assert incident.capability_area == ""
    assert incident.workflow_ref is None


def test_incident_to_dict_roundtrip(sample_data):
    incident = Incident.from_dict(sample_data)
    result = incident.to_dict()
    assert result["id"] == sample_data["id"]
    assert result["project"] == sample_data["project"]
    assert result["platform"] == "claude-code"
    assert result["tags"] == sample_data["tags"]
    assert "workflow_ref" not in result
    assert "assessment_ref" not in result
    assert "capability_area" not in result


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
    assert ref.workflow_archetype == ""
    assert ref.subject_type == ""
    assert ref.blocked_use_class == ""
    assert ref.workflow_ref is None
    assert ref.evidence_ref is None
    assert ref.workflow_evidence_snapshot is None
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
    assert ref.lifecycle_stage == "use_approval"
    assert ref.issue_class == "use_approval"


def test_claims_issue_classes_are_valid_structured_values():
    expected = {
        "phi_redaction_failure",
        "missing_claim_evidence",
        "rate_source_ambiguity",
        "contract_rate_mismatch",
        "allowed_amount_conflict",
        "approval_bypass",
        "downstream_export_mismatch",
        "savings_recognition_dispute",
    }

    assert expected.issubset(set(ISSUE_CLASS_VALUES))


def test_structured_axis_metadata_is_single_source_for_claims_axes():
    assert STRUCTURED_AXIS_METADATA["issue_class"].values is ISSUE_CLASS_VALUES
    assert STRUCTURED_AXIS_METADATA["capability_area"].description
    assert STRUCTURED_AXIS_METADATA["workflow_archetype"].description
    assert STRUCTURED_AXIS_METADATA["blocked_use_class"].values


def test_subject_ref_is_supported_as_pointer_only(sample_data):
    data = sample_data.copy()
    data["subject_ref"] = "subject:document-packet:synthetic-demo"

    incident = Incident.from_dict(data)
    ref = incident.to_ref()

    assert "subject_ref" in PROOFHOUSE_REF_FIELDS
    assert incident.subject_ref["ref_id"] == "subject:document-packet:synthetic-demo"
    assert incident.subject_ref["cache_policy"] == "ref_only"
    assert ref.subject_ref["ref_id"] == "subject:document-packet:synthetic-demo"


def test_pointer_refs_reject_obvious_raw_payload_keys():
    try:
        parse_pointer_value({"ref_id": "workflow:demo", "payload": {"claim": "raw"}}, "workflow_ref")
    except ValueError as exc:
        assert "payload" in str(exc)
    else:
        raise AssertionError("expected raw payload key to be rejected")


def test_pointer_refs_allow_digest_metadata():
    parsed = parse_pointer_value(
        {"ref_id": "workflow:demo", "payload_digest": "sha256:placeholder"},
        "workflow_ref",
    )

    assert parsed["payload_digest"] == "sha256:placeholder"


def test_observed_state_rejects_obvious_sensitive_keys():
    try:
        parse_observed_state({"state": "needs_review", "claim_text": "raw claim body"})
    except ValueError as exc:
        assert "claim_text" in str(exc)
    else:
        raise AssertionError("expected raw observed_state key to be rejected")


def test_observed_state_rejects_camel_case_raw_payload_keys():
    for raw_key in [
        "rawPayload",
        "claimText",
        "documentText",
        "dateOfBirth",
        "patientName",
        "memberName",
    ]:
        with pytest.raises(ValueError, match=raw_key):
            parse_observed_state({raw_key: "raw value"})


def test_observed_state_allows_boundary_safe_phi_status_keys():
    parsed = parse_observed_state(
        {
            "phi_redaction_status": "passed",
            "phi_boundary_state": "summary_only",
            "phi_packet_digest": "sha256:placeholder",
        }
    )

    assert parsed["phi_redaction_status"] == "passed"


def test_incident_ref_projection_infers_claims_issue_class_alias(sample_data):
    data = sample_data.copy()
    data.update(
        {
            "project": "proofhouse-claims",
            "agent": "claims-review-fixture",
            "tags": ["claims", "contract-rate-mismatch", "rate-source"],
        }
    )
    incident = Incident.from_dict(data)
    ref = incident.to_ref()

    assert ref.issue_class == "contract_rate_mismatch"


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


def test_structured_document_operations_incident_roundtrip(sample_data):
    data = sample_data.copy()
    data.update(
        {
            "capability_area": "governance",
            "lifecycle_stage": "redaction_review",
            "issue_class": "redaction_miss",
            "workflow_archetype": "document_operations",
            "subject_type": "document_packet",
            "blocked_use_class": "internal_eval",
            "observed_state": {"fixture_id": "document_ops_regulated_review_v0"},
            "workflow_ref": "workflow:document_ops_regulated_review_v0",
            "workflow_evidence_snapshot": {
                "ref_id": "workflow-evidence-snapshot:document_ops_regulated_review_v0:g1",
                "digest": "sha256:placeholder",
            },
            "assessment_ref": "assessment:document_ops_regulated_review_v0:g2",
            "policy_decision_ref": "policy-decision:document_ops_review_required:g2",
            "use_approval_ref": "use-approval:document_ops_internal_eval:g2",
            "asset_ref": "asset:document_ops_exception_packet:g2",
            "derivation_ref": "derivation:document_ops_exception_packet:g2",
            "transform_ref": "transform:redaction:document_ops_exception_packet:g2",
        }
    )

    incident = Incident.from_dict(data)
    result = incident.to_dict()
    ref = incident.to_ref()

    assert result["capability_area"] == "governance"
    assert result["issue_class"] == "redaction_miss"
    assert result["workflow_ref"]["ref_id"] == "workflow:document_ops_regulated_review_v0"
    assert result["workflow_ref"]["cache_policy"] == "ref_only"
    assert ref.capability_area == "governance"
    assert ref.lifecycle_stage == "redaction_review"
    assert ref.issue_class == "redaction_miss"
    assert ref.workflow_archetype == "document_operations"
    assert ref.subject_type == "document_packet"
    assert ref.blocked_use_class == "internal_eval"
    assert ref.workflow_ref["ref_id"] == "workflow:document_ops_regulated_review_v0"
    assert ref.workflow_evidence_snapshot["digest"] == "sha256:placeholder"
    assert ref.use_approval_ref["ref_id"] == "use-approval:document_ops_internal_eval:g2"
