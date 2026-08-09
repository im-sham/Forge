from __future__ import annotations

import calendar
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from forge_cli.models import FORGE_PRODUCER_SYSTEM, PROOFHOUSE_SHARED_CONTRACT_VERSION, Incident
from forge_cli.incident_store import find_incident

_RFC3339_DATE_TIME = re.compile(
    r"^(?P<year>\d{4})-(?P<month>0[1-9]|1[0-2])-(?P<day>\d{2})"
    r"T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?"
    r"(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$",
    re.ASCII | re.IGNORECASE,
)
_IDENTITY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_PIN_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+-]*$")
_TIMESTAMP_PIN_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$",
    re.IGNORECASE,
)
_PLACEHOLDER_SCOPES = frozenset(
    {
        "default",
        "environment_default",
        "global",
        "n/a",
        "na",
        "none",
        "null",
        "org_default",
        "organization_default",
        "placeholder",
        "project",
        "project_default",
        "tenant_default",
        "unknown",
        "unscoped",
    }
)
_MUTABLE_PINS = frozenset({"current", "default", "head", "latest", "mutable"})
_FAILURE_TYPES = frozenset(
    {
        "hallucination",
        "tool_misuse",
        "scope_creep",
        "safety_boundary_violation",
        "performance_degradation",
        "context_loss",
        "confidence_miscalibration",
        "instruction_drift",
        "error_handling_failure",
        "integration_failure",
        "adversarial_vulnerability",
        "other",
    }
)
_SEVERITIES = frozenset({"cosmetic", "functional", "safety-critical"})


@dataclass(frozen=True, slots=True)
class ImmutableStatePin:
    """One opaque pin and its Forge-owned co-reference state identity."""

    value: str
    state_id: str

    def __post_init__(self) -> None:
        if (
            not self.value
            or len(self.value) > 256
            or _PIN_PATTERN.fullmatch(self.value) is None
            or self.value.lower() in _MUTABLE_PINS
            or _TIMESTAMP_PIN_PATTERN.fullmatch(self.value) is not None
        ):
            raise ValueError("immutable pin must be non-empty, well-formed, and immutable")
        _validate_identity(self.state_id, "state_id")


class _CanonicalIdentity(Protocol):
    @property
    def snapshot(self) -> ImmutableStatePin | None: ...

    @property
    def version(self) -> ImmutableStatePin | None: ...


@dataclass(frozen=True, slots=True)
class CanonicalIncidentIdentity:
    """Exact incident identity and Forge-owned immutable state pins."""

    incident_id: str
    snapshot: ImmutableStatePin | None = None
    version: ImmutableStatePin | None = None

    def validate(self) -> None:
        _validate_identity(self.incident_id, "incident_id")
        _validate_pins(self)


@dataclass(frozen=True, slots=True)
class CanonicalWorkflowIdentity:
    """Exact Workflow Context identity and immutable alignment state pins."""

    workflow_id: str
    snapshot: ImmutableStatePin | None = None
    version: ImmutableStatePin | None = None

    def validate(self) -> None:
        _validate_identity(self.workflow_id, "workflow_id")
        _validate_pins(self)


def _validate_identity(value: str, field_name: str) -> None:
    if not value or len(value) > 256 or _IDENTITY_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be an explicit well-formed identity")


def _validate_pins(identity: _CanonicalIdentity) -> None:
    if identity.snapshot is None and identity.version is None:
        raise ValueError("snapshot or version pin is required")
    if (
        identity.snapshot is not None
        and identity.version is not None
        and identity.snapshot.state_id != identity.version.state_id
    ):
        raise ValueError("snapshot and version pins must identify the same immutable state")


def _validate_scope(value: str, field_name: str) -> None:
    if (
        not value
        or len(value) > 256
        or _IDENTITY_PATTERN.fullmatch(value) is None
        or value.lower() in _PLACEHOLDER_SCOPES
    ):
        raise ValueError(f"{field_name} must be explicit and non-placeholder")


def _validate_date_time(value: str, field_name: str) -> None:
    match = _RFC3339_DATE_TIME.fullmatch(value)
    if match is None:
        raise ValueError(f"{field_name} must be an RFC 3339 date-time string")
    year, month, day = (int(match[name]) for name in ("year", "month", "day"))
    if year == 0 or not 1 <= day <= calendar.monthrange(year, month)[1]:
        raise ValueError(f"{field_name} must be an RFC 3339 date-time string")


def _emit_pins(identity: _CanonicalIdentity) -> dict[str, str]:
    pins: dict[str, str] = {}
    if identity.snapshot is not None:
        pins["snapshot_id"] = identity.snapshot.value
    if identity.version is not None:
        pins["version"] = identity.version.value
    return pins


def _optional_state_pin(
    value: str | None,
    state_id: str | None,
    field_name: str,
) -> ImmutableStatePin | None:
    if value is None and state_id is None:
        return None
    if value is None or state_id is None:
        raise ValueError(f"{field_name} requires both a pin and its state identity")
    return ImmutableStatePin(value=value, state_id=state_id)


def build_strict_incident_ref_v0_1_from_corpus(
    *,
    data_root: Path,
    incident_lookup: str,
    organization_id: str,
    environment_id: str,
    issued_at: str,
    incident_id: str,
    workflow_id: str,
    incident_snapshot_id: str | None = None,
    incident_snapshot_state_id: str | None = None,
    incident_version: str | None = None,
    incident_version_state_id: str | None = None,
    workflow_snapshot_id: str | None = None,
    workflow_snapshot_state_id: str | None = None,
    workflow_version: str | None = None,
    workflow_version_state_id: str | None = None,
) -> dict[str, object]:
    """Load one explicit local incident and emit its strict canonical V0.1 envelope."""
    incident = find_incident(data_root / "incidents", incident_lookup)
    if incident is None:
        raise ValueError("incident not found in explicit Forge corpus")

    incident_identity = CanonicalIncidentIdentity(
        incident_id=incident_id,
        snapshot=_optional_state_pin(
            incident_snapshot_id,
            incident_snapshot_state_id,
            "incident snapshot",
        ),
        version=_optional_state_pin(
            incident_version,
            incident_version_state_id,
            "incident version",
        ),
    )
    workflow_identity = CanonicalWorkflowIdentity(
        workflow_id=workflow_id,
        snapshot=_optional_state_pin(
            workflow_snapshot_id,
            workflow_snapshot_state_id,
            "workflow snapshot",
        ),
        version=_optional_state_pin(
            workflow_version,
            workflow_version_state_id,
            "workflow version",
        ),
    )
    return build_strict_incident_ref_v0_1(
        incident,
        organization_id=organization_id,
        environment_id=environment_id,
        issued_at=issued_at,
        incident_identity=incident_identity,
        workflow_identity=workflow_identity,
    )


def build_strict_incident_ref_v0_1(
    incident: Incident,
    *,
    organization_id: str,
    environment_id: str,
    issued_at: str,
    incident_identity: CanonicalIncidentIdentity,
    workflow_identity: CanonicalWorkflowIdentity,
) -> dict[str, object]:
    """Emit the strict canonical IncidentRef V0.1 wire from explicit immutable identities."""
    _validate_scope(organization_id, "organization_id")
    _validate_scope(environment_id, "environment_id")
    _validate_date_time(issued_at, "issued_at")
    _validate_date_time(incident.timestamp, "incident.timestamp")
    incident_identity.validate()
    workflow_identity.validate()
    if incident_identity.incident_id != incident.id:
        raise ValueError("canonical incident identity must equal the stored incident identity")
    if incident.failure_type not in _FAILURE_TYPES:
        raise ValueError("incident.failure_type is not canonical IncidentRef V0.1")
    if incident.severity not in _SEVERITIES:
        raise ValueError("incident.severity is not canonical IncidentRef V0.1")

    workflow_ref: dict[str, object] = {
        "ref_id": f"workflow:{workflow_identity.workflow_id}",
        "ref_type": "workflow",
        "source_capability": "workflow_context",
        "organization_id": organization_id,
        "environment_id": environment_id,
        "workflow_id": workflow_identity.workflow_id,
        **_emit_pins(workflow_identity),
    }
    ref: dict[str, object] = {
        "ref_id": f"incident:{incident.id}",
        "ref_type": "incident",
        "source_capability": "forge",
        "organization_id": organization_id,
        "environment_id": environment_id,
        "external_uri": f"forge://incident/{incident.id}",
        **_emit_pins(incident_identity),
        "created_at": incident.timestamp,
        "summary": f"Forge incident {incident.id}: {incident.severity} {incident.failure_type}",
        "incident_id": incident.id,
        "failure_type": incident.failure_type,
        "severity": incident.severity,
        "workflow_ref": workflow_ref,
    }
    return {
        "contract_version": PROOFHOUSE_SHARED_CONTRACT_VERSION,
        "contract_name": "IncidentRef",
        "producer_capability": "forge",
        "producer_system": FORGE_PRODUCER_SYSTEM,
        "canonical_owner": "forge",
        "issued_at": issued_at,
        "cache_policy": "summary_snapshot",
        "ref": ref,
    }
