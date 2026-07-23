from __future__ import annotations

import json
from dataclasses import fields
from pathlib import Path

import pytest
from typer.testing import CliRunner

from forge_cli.cli import app
from forge_cli.incident_store import save_incident
from forge_cli.models import Incident, IncidentRef


ENVELOPE_FIELDS = [
    "contract_version",
    "contract_name",
    "producer_capability",
    "producer_system",
    "canonical_owner",
    "issued_at",
    "cache_policy",
    "ref",
]

INCIDENT_REF_FIELDS = [
    "ref_id",
    "ref_type",
    "source_capability",
    "organization_id",
    "environment_id",
    "external_uri",
    "snapshot_id",
    "version",
    "created_at",
    "summary",
    "incident_id",
    "failure_type",
    "severity",
    "project",
    "agent",
    "platform",
    "capability_area",
    "lifecycle_stage",
    "issue_class",
    "workflow_archetype",
    "subject_type",
    "blocked_use_class",
    "observed_state",
    "tags",
    "related_incidents",
    "playbook_entry",
    "workflow_ref",
    "evidence_ref",
    "workflow_evidence_snapshot",
    "control_refs",
    "subject_ref",
    "assessment_ref",
    "policy_decision_ref",
    "use_approval_ref",
    "asset_ref",
    "derivation_ref",
    "transform_ref",
]


def _legacy_incident_data() -> dict[str, object]:
    return {
        "id": "2026-03-04-001",
        "timestamp": "2026-03-04T14:30:00Z",
        "reported_by": "legacy-reporter",
        "project": "legacy-project",
        "agent": "legacy-agent",
        "severity": "functional",
        "failure_type": "hallucination",
        "expected_behavior": "Use only cited facts.",
        "actual_behavior": "The answer included an unsupported summary.",
        "context": "Legacy incident without structured axes or refs.",
        "root_cause": "Source grounding was incomplete.",
        "immediate_fix": "Re-ran with explicit citations.",
        "systemic_takeaway": "Require source-grounded summaries.",
    }


def _expected_legacy_envelope() -> dict[str, object]:
    return {
        "contract_version": "proofhouse-shared-contracts/v0.1",
        "contract_name": "IncidentRef",
        "producer_capability": "forge",
        "producer_system": "proofhouse-forge",
        "canonical_owner": "forge",
        "issued_at": "2026-03-04T14:30:00Z",
        "cache_policy": "summary_snapshot",
        "ref": {
            "ref_id": "incident:2026-03-04-001",
            "ref_type": "incident",
            "source_capability": "forge",
            "organization_id": "unscoped",
            "environment_id": "default",
            "external_uri": "forge://incidents/2026-03-04-001",
            "snapshot_id": None,
            "version": None,
            "created_at": "2026-03-04T14:30:00Z",
            "summary": (
                "Forge incident 2026-03-04-001: functional hallucination "
                "in legacy-project/legacy-agent"
            ),
            "incident_id": "2026-03-04-001",
            "failure_type": "hallucination",
            "severity": "functional",
            "project": "legacy-project",
            "agent": "legacy-agent",
            "platform": "",
            "capability_area": "unknown",
            "lifecycle_stage": "unknown",
            "issue_class": "hallucination",
            "workflow_archetype": "",
            "subject_type": "",
            "blocked_use_class": "",
            "observed_state": None,
            "tags": [],
            "related_incidents": [],
            "playbook_entry": "",
            "workflow_ref": None,
            "evidence_ref": None,
            "workflow_evidence_snapshot": None,
            "control_refs": [],
            "subject_ref": None,
            "assessment_ref": None,
            "policy_decision_ref": None,
            "use_approval_ref": None,
            "asset_ref": None,
            "derivation_ref": None,
            "transform_ref": None,
        },
    }


def test_incident_ref_wire_and_envelope_field_inventory_is_exact() -> None:
    incident = Incident.from_dict(_legacy_incident_data())
    envelope = incident.to_ref_envelope()
    ref_payload = envelope["ref"]

    assert isinstance(ref_payload, dict)
    assert [field.name for field in fields(IncidentRef)] == INCIDENT_REF_FIELDS
    assert list(envelope) == ENVELOPE_FIELDS
    assert list(ref_payload) == INCIDENT_REF_FIELDS


def test_legacy_projection_is_deterministic_and_preserves_current_defaults() -> None:
    incident = Incident.from_dict(_legacy_incident_data())
    first = incident.to_ref_envelope()
    second = incident.to_ref_envelope()

    assert first == _expected_legacy_envelope()
    assert second == first
    assert json.dumps(second, separators=(",", ":")) == json.dumps(
        first, separators=(",", ":")
    )


def test_structured_projection_passes_summary_only_pointers_without_core_text() -> None:
    workflow_ref = {
        "ref_id": "workflow:synthetic-review",
        "ref_type": "workflow",
        "cache_policy": "ref_only",
        "digest": "sha256:synthetic",
        "summary": "Synthetic workflow pointer.",
    }
    data = _legacy_incident_data()
    data.update(
        {
            "capability_area": "governance",
            "lifecycle_stage": "use_approval",
            "issue_class": "approval_bypass",
            "workflow_archetype": "document_operations",
            "subject_type": "document_packet",
            "blocked_use_class": "internal_eval",
            "observed_state": {"review_status": "blocked", "fixture_id": "synthetic-review"},
            "workflow_ref": workflow_ref,
            "control_refs": ["control:synthetic-review"],
        }
    )

    ref = Incident.from_dict(data).to_ref().to_dict()

    assert ref["workflow_ref"] == workflow_ref
    assert ref["control_refs"] == [
        {
            "ref_id": "control:synthetic-review",
            "ref_type": "control",
            "cache_policy": "ref_only",
        }
    ]
    assert ref["observed_state"] == {
        "review_status": "blocked",
        "fixture_id": "synthetic-review",
    }
    for raw_incident_field in (
        "expected_behavior",
        "actual_behavior",
        "context",
        "root_cause",
        "immediate_fix",
        "systemic_takeaway",
    ):
        assert raw_incident_field not in ref


@pytest.mark.parametrize(
    ("field_name", "forbidden_value", "error_pattern"),
    [
        (
            "workflow_ref",
            {"ref_id": "workflow:synthetic-review", "raw_payload": {"text": "raw"}},
            "workflow_ref.*raw_payload",
        ),
        (
            "observed_state",
            {"review_status": "blocked", "document_text": "raw"},
            "observed_state.*document_text",
        ),
        (
            "context",
            '{"claim_text": "raw"}',
            "context.*claim_text",
        ),
    ],
)
def test_projection_inputs_reject_raw_payload_markers(
    field_name: str, forbidden_value: object, error_pattern: str
) -> None:
    data = _legacy_incident_data()
    data[field_name] = forbidden_value

    with pytest.raises(ValueError, match=error_pattern):
        _ = Incident.from_dict(data)


def test_cli_and_mcp_emit_the_same_incident_ref_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _ = pytest.importorskip("mcp")
    from forge_cli.mcp_server import forge_incident_ref

    data_root = tmp_path / "forge-data"
    incidents_dir = data_root / "incidents"
    incidents_dir.mkdir(parents=True)
    incident = Incident.from_dict(_legacy_incident_data())
    _ = save_incident(incident, incidents_dir)
    monkeypatch.setenv("FORGE_DATA_ROOT", str(data_root))

    cli_result = CliRunner().invoke(app, ["ref", "001", "--compact"])
    mcp_result = str(forge_incident_ref("001"))

    assert cli_result.exit_code == 0
    assert json.loads(cli_result.output) == incident.to_ref_envelope()
    assert json.loads(mcp_result) == incident.to_ref_envelope()
