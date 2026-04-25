from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


PROOFHOUSE_SHARED_CONTRACT_VERSION = "proofhouse-shared-contracts/v0.1"
FORGE_PRODUCER_SYSTEM = "proofhouse-forge"
FORGE_UNSCOPED_ORGANIZATION_ID = "unscoped"
FORGE_DEFAULT_ENVIRONMENT_ID = "default"

PROOFHOUSE_REF_FIELDS = [
    "workflow_ref",
    "assessment_ref",
    "policy_decision_ref",
    "asset_ref",
    "derivation_ref",
    "transform_ref",
    "use_approval_ref",
]

CAPABILITY_AREA_ALIASES = [
    (
        "governance",
        {
            "governance",
            "proofhouse-governance",
            "sentinel",
            "use-approval",
            "redaction",
            "export-control",
            "rights",
            "manifest",
        },
    ),
    (
        "readiness",
        {
            "readiness",
            "scalescore",
            "assessment",
            "suitability",
        },
    ),
    (
        "workflow_context",
        {
            "workflow-context",
            "workflow_context",
            "workflow",
            "opsorchestra",
        },
    ),
    (
        "operational_learning",
        {
            "operational-learning",
            "operational_learning",
        },
    ),
    (
        "forge",
        {
            "forge",
            "incident-memory",
            "incident_memory",
            "playbook",
        },
    ),
]

ISSUE_CLASS_ALIASES = [
    ("use_approval", {"use-approval", "use_approval"}),
    ("redaction", {"redaction", "redaction-review", "redaction_review"}),
    ("export_control", {"export-control", "export_control"}),
    ("rights", {"rights", "rights-review", "rights_review"}),
    ("provenance", {"provenance", "lineage"}),
    ("derivation_quality", {"derivation-quality", "derivation_quality"}),
    ("readiness_gap", {"readiness-gap", "readiness_gap"}),
    ("workflow_truth", {"workflow-truth", "workflow_truth"}),
]

LIFECYCLE_STAGE_ALIASES = [
    ("approval", {"approval", "use-approval", "use_approval"}),
    ("redaction_review", {"redaction", "redaction-review", "redaction_review"}),
    ("export", {"export", "export-control", "export_control"}),
    ("asset_derivation", {"derivation", "derivation-quality", "derivation_quality"}),
    ("assessment", {"assessment", "readiness", "suitability"}),
    ("evaluation", {"eval", "evaluation", "internal-eval", "internal_eval"}),
    ("training", {"training", "internal-training", "internal_training"}),
    ("capture", {"capture", "intake", "logging"}),
    ("runtime", {"runtime", "production"}),
    ("handoff", {"handoff", "escalation"}),
]


class Severity(str, Enum):
    COSMETIC = "cosmetic"
    FUNCTIONAL = "functional"
    SAFETY_CRITICAL = "safety-critical"


class FailureType(str, Enum):
    HALLUCINATION = "hallucination"
    TOOL_MISUSE = "tool_misuse"
    SCOPE_CREEP = "scope_creep"
    SAFETY_BOUNDARY_VIOLATION = "safety_boundary_violation"
    PERFORMANCE_DEGRADATION = "performance_degradation"
    CONTEXT_LOSS = "context_loss"
    CONFIDENCE_MISCALIBRATION = "confidence_miscalibration"
    INSTRUCTION_DRIFT = "instruction_drift"
    ERROR_HANDLING_FAILURE = "error_handling_failure"
    INTEGRATION_FAILURE = "integration_failure"
    ADVERSARIAL_VULNERABILITY = "adversarial_vulnerability"
    OTHER = "other"


def _normalized_tokens(incident: Incident) -> set[str]:
    raw_tokens = [
        incident.project,
        incident.agent,
        incident.platform,
        incident.failure_type,
        *incident.tags,
    ]
    return {
        token.strip().lower().replace("_", "-")
        for token in raw_tokens
        if token and token.strip()
    }


def _match_alias(tokens: set[str], aliases: list[tuple[str, set[str]]]) -> str | None:
    for value, candidates in aliases:
        if tokens.intersection(candidates):
            return value
    return None


# Ordered field names matching the YAML template layout
INCIDENT_FIELD_ORDER = [
    "id",
    "timestamp",
    "reported_by",
    "project",
    "agent",
    "platform",
    "severity",
    "failure_type",
    "expected_behavior",
    "actual_behavior",
    "context",
    "root_cause",
    "immediate_fix",
    "systemic_takeaway",
    "tags",
    "related_incidents",
    "playbook_entry",
]


@dataclass(frozen=True)
class IncidentRef:
    """Compact Forge-owned incident reference for Proofhouse consumers."""

    ref_id: str
    ref_type: str
    source_capability: str
    organization_id: str
    environment_id: str
    external_uri: str | None
    snapshot_id: str | None
    version: str | None
    created_at: str
    summary: str
    incident_id: str
    failure_type: str
    severity: str
    project: str
    agent: str
    platform: str
    capability_area: str
    lifecycle_stage: str
    issue_class: str
    tags: list[str]
    related_incidents: list[str]
    playbook_entry: str
    workflow_ref: dict[str, Any] | None = None
    assessment_ref: dict[str, Any] | None = None
    policy_decision_ref: dict[str, Any] | None = None
    asset_ref: dict[str, Any] | None = None
    derivation_ref: dict[str, Any] | None = None
    transform_ref: dict[str, Any] | None = None
    use_approval_ref: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Incident:
    id: str
    timestamp: str
    reported_by: str
    project: str
    agent: str
    platform: str
    severity: str
    failure_type: str
    expected_behavior: str
    actual_behavior: str
    context: str
    root_cause: str
    immediate_fix: str
    systemic_takeaway: str
    tags: list[str] = field(default_factory=list)
    related_incidents: list[str] = field(default_factory=list)
    playbook_entry: str = ""

    def to_dict(self) -> dict:
        """Convert to ordered dict matching the YAML template field order."""
        data = {}
        for key in INCIDENT_FIELD_ORDER:
            data[key] = getattr(self, key)
        return data

    def to_ref(self) -> IncidentRef:
        """Project this incident into a Proofhouse V0.1 IncidentRef."""
        return build_incident_ref(self)

    def to_ref_envelope(self) -> dict[str, Any]:
        """Project this incident into a Proofhouse V0.1 ref envelope."""
        return build_incident_ref_envelope(self)

    @classmethod
    def from_dict(cls, data: dict) -> Incident:
        """Create an Incident from a dict (e.g., parsed YAML)."""
        return cls(
            id=data.get("id", ""),
            timestamp=data.get("timestamp", ""),
            reported_by=data.get("reported_by", ""),
            project=data.get("project", ""),
            agent=data.get("agent", ""),
            platform=data.get("platform", "") or "",
            severity=data.get("severity", ""),
            failure_type=data.get("failure_type", ""),
            expected_behavior=data.get("expected_behavior", ""),
            actual_behavior=data.get("actual_behavior", ""),
            context=data.get("context", ""),
            root_cause=data.get("root_cause", ""),
            immediate_fix=data.get("immediate_fix", ""),
            systemic_takeaway=data.get("systemic_takeaway", ""),
            tags=data.get("tags", []) or [],
            related_incidents=data.get("related_incidents", []) or [],
            playbook_entry=data.get("playbook_entry", "") or "",
        )


def build_incident_ref(incident: Incident) -> IncidentRef:
    """Build a boundary-safe IncidentRef without changing YAML storage."""
    tokens = _normalized_tokens(incident)
    capability_area = _match_alias(tokens, CAPABILITY_AREA_ALIASES) or "unknown"
    lifecycle_stage = _match_alias(tokens, LIFECYCLE_STAGE_ALIASES) or "unknown"
    issue_class = _match_alias(tokens, ISSUE_CLASS_ALIASES) or incident.failure_type or "unknown"

    summary = (
        f"Forge incident {incident.id}: "
        f"{incident.severity or 'unclassified'} {incident.failure_type or 'failure'}"
    )
    if incident.project:
        summary = f"{summary} in {incident.project}"
    if incident.agent:
        summary = f"{summary}/{incident.agent}"

    return IncidentRef(
        ref_id=f"incident:{incident.id}",
        ref_type="incident",
        source_capability="forge",
        organization_id=FORGE_UNSCOPED_ORGANIZATION_ID,
        environment_id=FORGE_DEFAULT_ENVIRONMENT_ID,
        external_uri=f"forge://incidents/{incident.id}",
        snapshot_id=None,
        version=None,
        created_at=incident.timestamp,
        summary=summary,
        incident_id=incident.id,
        failure_type=incident.failure_type,
        severity=incident.severity,
        project=incident.project,
        agent=incident.agent,
        platform=incident.platform,
        capability_area=capability_area,
        lifecycle_stage=lifecycle_stage,
        issue_class=issue_class,
        tags=list(incident.tags),
        related_incidents=list(incident.related_incidents),
        playbook_entry=incident.playbook_entry,
    )


def build_incident_ref_envelope(incident: Incident) -> dict[str, Any]:
    """Wrap an IncidentRef in the Proofhouse shared-contract envelope."""
    return {
        "contract_version": PROOFHOUSE_SHARED_CONTRACT_VERSION,
        "contract_name": "IncidentRef",
        "producer_capability": "forge",
        "producer_system": FORGE_PRODUCER_SYSTEM,
        "canonical_owner": "forge",
        "issued_at": incident.timestamp,
        "cache_policy": "summary_snapshot",
        "ref": build_incident_ref(incident).to_dict(),
    }
