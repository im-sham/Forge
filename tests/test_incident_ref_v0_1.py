from __future__ import annotations

import pytest

from forge_cli.incident_ref_v0_1 import (
    CanonicalIncidentIdentity,
    CanonicalWorkflowIdentity,
    ImmutableStatePin,
    build_strict_incident_ref_v0_1,
)
from forge_cli.models import Incident


def _incident() -> Incident:
    return Incident.from_dict(
        {
            "id": "inc_synthetic_001",
            "timestamp": "2026-07-23T11:30:00Z",
            "reported_by": "internal-test",
            "project": "must-not-escape",
            "agent": "must-not-escape",
            "platform": "must-not-escape",
            "severity": "functional",
            "failure_type": "integration_failure",
            "expected_behavior": "Summary-only synthetic test text.",
            "actual_behavior": "Summary-only synthetic test text.",
            "context": "Summary-only synthetic test text.",
            "root_cause": "Summary-only synthetic test text.",
            "immediate_fix": "Summary-only synthetic test text.",
            "systemic_takeaway": "Summary-only synthetic test text.",
            "tags": ["must-not-escape"],
        }
    )


def _incident_identity(*, second_state_id: str = "state:incident:1") -> CanonicalIncidentIdentity:
    return CanonicalIncidentIdentity(
        incident_id="inc_synthetic_001",
        snapshot=ImmutableStatePin("incident-snapshot-001", "state:incident:1"),
        version=ImmutableStatePin("1", second_state_id),
    )


def _workflow_identity(*, second_state_id: str = "state:workflow:1") -> CanonicalWorkflowIdentity:
    return CanonicalWorkflowIdentity(
        workflow_id="wf_synthetic_001",
        snapshot=ImmutableStatePin("workflow-snapshot-001", "state:workflow:1"),
        version=ImmutableStatePin("1", second_state_id),
    )


def test_strict_emitter_builds_closed_metadata_only_v0_1_envelope() -> None:
    envelope = build_strict_incident_ref_v0_1(
        _incident(),
        organization_id="proofhouse_internal",
        environment_id="internal_staging",
        issued_at="2026-07-23T12:00:00Z",
        incident_identity=_incident_identity(),
        workflow_identity=_workflow_identity(),
    )

    assert envelope == {
        "contract_version": "proofhouse-shared-contracts/v0.1",
        "contract_name": "IncidentRef",
        "producer_capability": "forge",
        "producer_system": "proofhouse-forge",
        "canonical_owner": "forge",
        "issued_at": "2026-07-23T12:00:00Z",
        "cache_policy": "summary_snapshot",
        "ref": {
            "ref_id": "incident:inc_synthetic_001",
            "ref_type": "incident",
            "source_capability": "forge",
            "organization_id": "proofhouse_internal",
            "environment_id": "internal_staging",
            "external_uri": "forge://incident/inc_synthetic_001",
            "snapshot_id": "incident-snapshot-001",
            "version": "1",
            "created_at": "2026-07-23T11:30:00Z",
            "summary": "Forge incident inc_synthetic_001: functional integration_failure",
            "incident_id": "inc_synthetic_001",
            "failure_type": "integration_failure",
            "severity": "functional",
            "workflow_ref": {
                "ref_id": "workflow:wf_synthetic_001",
                "ref_type": "workflow",
                "source_capability": "workflow_context",
                "organization_id": "proofhouse_internal",
                "environment_id": "internal_staging",
                "workflow_id": "wf_synthetic_001",
                "snapshot_id": "workflow-snapshot-001",
                "version": "1",
            },
        },
    }
    ref = envelope["ref"]
    for forbidden_field in (
        "expected_behavior",
        "actual_behavior",
        "context",
        "root_cause",
        "immediate_fix",
        "systemic_takeaway",
    ):
        assert forbidden_field not in ref
    assert "must-not-escape" not in str(envelope)


@pytest.mark.parametrize("field", ["organization_id", "environment_id"])
@pytest.mark.parametrize("value", ["", "default", "UNSCOPED", "tenant_default", "unknown"])
def test_strict_emitter_rejects_missing_or_placeholder_scope(field: str, value: str) -> None:
    arguments = {
        "organization_id": "proofhouse_internal",
        "environment_id": "internal_staging",
        "issued_at": "2026-07-23T12:00:00Z",
        "incident_identity": _incident_identity(),
        "workflow_identity": _workflow_identity(),
    }
    arguments[field] = value

    with pytest.raises(ValueError, match="explicit and non-placeholder"):
        build_strict_incident_ref_v0_1(_incident(), **arguments)


def test_strict_emitter_rejects_incident_identity_mismatch() -> None:
    identity = CanonicalIncidentIdentity(
        incident_id="inc_other",
        version=ImmutableStatePin("1", "state:incident:1"),
    )

    with pytest.raises(ValueError, match="incident identity"):
        build_strict_incident_ref_v0_1(
            _incident(),
            organization_id="proofhouse_internal",
            environment_id="internal_staging",
            issued_at="2026-07-23T12:00:00Z",
            incident_identity=identity,
            workflow_identity=_workflow_identity(),
        )


@pytest.mark.parametrize(
    "identity",
    [
        CanonicalIncidentIdentity(incident_id="inc_synthetic_001"),
        CanonicalWorkflowIdentity(workflow_id="wf_synthetic_001"),
    ],
)
def test_canonical_identity_requires_an_immutable_pin(
    identity: CanonicalIncidentIdentity | CanonicalWorkflowIdentity,
) -> None:
    with pytest.raises(ValueError, match="snapshot or version pin is required"):
        identity.validate()


@pytest.mark.parametrize("value", ["", "latest", "CURRENT", "2026-07-23T12:00:00Z"])
def test_immutable_state_pin_rejects_nonimmutable_values(value: str) -> None:
    with pytest.raises(ValueError, match="immutable pin"):
        ImmutableStatePin(value, "state:incident:1")


@pytest.mark.parametrize(
    "incident_identity,workflow_identity",
    [
        (_incident_identity(second_state_id="state:incident:2"), _workflow_identity()),
        (_incident_identity(), _workflow_identity(second_state_id="state:workflow:2")),
    ],
)
def test_strict_emitter_rejects_pins_from_different_states(
    incident_identity: CanonicalIncidentIdentity,
    workflow_identity: CanonicalWorkflowIdentity,
) -> None:
    with pytest.raises(ValueError, match="same immutable state"):
        build_strict_incident_ref_v0_1(
            _incident(),
            organization_id="proofhouse_internal",
            environment_id="internal_staging",
            issued_at="2026-07-23T12:00:00Z",
            incident_identity=incident_identity,
            workflow_identity=workflow_identity,
        )


def test_strict_emitter_omits_absent_optional_pins() -> None:
    envelope = build_strict_incident_ref_v0_1(
        _incident(),
        organization_id="proofhouse_internal",
        environment_id="internal_staging",
        issued_at="2026-07-23T12:00:00Z",
        incident_identity=CanonicalIncidentIdentity(
            incident_id="inc_synthetic_001",
            version=ImmutableStatePin("1", "state:incident:1"),
        ),
        workflow_identity=CanonicalWorkflowIdentity(
            workflow_id="wf_synthetic_001",
            snapshot=ImmutableStatePin("workflow-snapshot-001", "state:workflow:1"),
        ),
    )

    assert "snapshot_id" not in envelope["ref"]
    assert "version" not in envelope["ref"]["workflow_ref"]


@pytest.mark.parametrize(
    "issued_at",
    [
        "2026-99-99",
        "2026-07-23",
        "2026-07-23T12:00:00",
        "2026-07-23T12:00Z",
        "2026-07-23T12:00:00,5Z",
        "2026-07-23T12:00:00+0000",
        "2026-07-23T12:00:00+00:00:30",
    ],
)
def test_strict_emitter_rejects_malformed_issued_at(issued_at: str) -> None:
    with pytest.raises(ValueError, match="issued_at must be an RFC 3339"):
        build_strict_incident_ref_v0_1(
            _incident(),
            organization_id="proofhouse_internal",
            environment_id="internal_staging",
            issued_at=issued_at,
            incident_identity=_incident_identity(),
            workflow_identity=_workflow_identity(),
        )


def test_strict_emitter_rejects_malformed_incident_created_at() -> None:
    incident = _incident()
    incident.timestamp = "2026-99-99"

    with pytest.raises(ValueError, match="incident.timestamp must be an RFC 3339"):
        build_strict_incident_ref_v0_1(
            incident,
            organization_id="proofhouse_internal",
            environment_id="internal_staging",
            issued_at="2026-07-23T12:00:00Z",
            incident_identity=_incident_identity(),
            workflow_identity=_workflow_identity(),
        )


def test_strict_emitter_preserves_contract_valid_lowercase_t_and_z() -> None:
    incident = _incident()
    incident.timestamp = "2026-07-23t11:30:00z"

    envelope = build_strict_incident_ref_v0_1(
        incident,
        organization_id="proofhouse_internal",
        environment_id="internal_staging",
        issued_at="2026-07-23t12:00:00z",
        incident_identity=_incident_identity(),
        workflow_identity=_workflow_identity(),
    )

    assert envelope["issued_at"] == "2026-07-23t12:00:00z"
    assert envelope["ref"]["created_at"] == "2026-07-23t11:30:00z"


@pytest.mark.parametrize(
    ("field", "value", "error_pattern"),
    [
        ("failure_type", "not-canonical", "failure_type"),
        ("severity", "not-canonical", "severity"),
    ],
)
def test_strict_emitter_rejects_noncanonical_classification(
    field: str, value: str, error_pattern: str
) -> None:
    incident = _incident()
    setattr(incident, field, value)

    with pytest.raises(ValueError, match=error_pattern):
        build_strict_incident_ref_v0_1(
            incident,
            organization_id="proofhouse_internal",
            environment_id="internal_staging",
            issued_at="2026-07-23T12:00:00Z",
            incident_identity=_incident_identity(),
            workflow_identity=_workflow_identity(),
        )
