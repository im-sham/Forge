from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from forge_cli import schema_metadata


PROOFHOUSE_SHARED_CONTRACT_VERSION = "proofhouse-shared-contracts/v0.1"
FORGE_PRODUCER_SYSTEM = "proofhouse-forge"
FORGE_UNSCOPED_ORGANIZATION_ID = "unscoped"
FORGE_DEFAULT_ENVIRONMENT_ID = "default"

CAPABILITY_AREA_VALUES = schema_metadata.CAPABILITY_AREA_VALUES
ISSUE_CLASS_VALUES = schema_metadata.ISSUE_CLASS_VALUES
LIFECYCLE_STAGE_VALUES = schema_metadata.LIFECYCLE_STAGE_VALUES
WORKFLOW_ARCHETYPE_VALUES = schema_metadata.WORKFLOW_ARCHETYPE_VALUES
USE_CLASS_VALUES = schema_metadata.USE_CLASS_VALUES

PROOFHOUSE_REF_FIELDS = [
    "workflow_ref",
    "evidence_ref",
    "workflow_evidence_snapshot",
    "subject_ref",
    "assessment_ref",
    "policy_decision_ref",
    "use_approval_ref",
    "asset_ref",
    "derivation_ref",
    "transform_ref",
]

PROOFHOUSE_AXIS_FIELDS = [
    "capability_area",
    "lifecycle_stage",
    "issue_class",
    "workflow_archetype",
    "subject_type",
    "blocked_use_class",
]

PROOFHOUSE_OBSERVED_STATE_FIELD = "observed_state"

CORE_INCIDENT_FREE_TEXT_FIELDS = [
    "expected_behavior",
    "actual_behavior",
    "context",
    "root_cause",
    "immediate_fix",
    "systemic_takeaway",
]

OPTIONAL_INCIDENT_FIELD_ORDER = [
    *PROOFHOUSE_AXIS_FIELDS,
    PROOFHOUSE_OBSERVED_STATE_FIELD,
    *PROOFHOUSE_REF_FIELDS,
]

REF_TYPE_BY_FIELD = {
    "workflow_ref": "workflow",
    "evidence_ref": "evidence",
    "workflow_evidence_snapshot": "workflow_evidence_snapshot",
    "subject_ref": "subject",
    "assessment_ref": "assessment",
    "policy_decision_ref": "policy_decision",
    "use_approval_ref": "use_approval",
    "asset_ref": "asset",
    "derivation_ref": "derivation",
    "transform_ref": "transform",
}

FORBIDDEN_SUMMARY_KEY_PARTS = {
    "payload",
    "raw_payload",
    "source_payload",
    "document_text",
    "claim_text",
    "claim_payload",
    "raw_claim",
    "raw_claim_text",
    "source_document_text",
    "phi",
    "ssn",
    "dob",
    "date_of_birth",
    "member_id",
    "member_name",
    "patient_name",
    "authorization",
    "api_key",
    "secret",
    "credential",
    "credentials",
    "token",
    "access_token",
    "refresh_token",
    "bearer_token",
    "client_secret",
    "customer_data",
    "rate_table_row",
    "payment_payload",
}

SENSITIVE_SUMMARY_KEY_PREFIXES = (
    "phi_",
    "ssn_",
    "dob_",
    "date_of_birth_",
    "member_id_",
    "member_name_",
    "patient_name_",
    "authorization_",
    "api_key_",
    "secret_",
    "credential_",
    "credentials_",
    "token_",
    "access_token_",
    "refresh_token_",
    "bearer_token_",
    "client_secret_",
)

SAFE_SUMMARY_KEY_SUFFIXES = (
    "_class",
    "_decision",
    "_digest",
    "_id",
    "_label",
    "_mode",
    "_owner",
    "_policy",
    "_present",
    "_ref",
    "_ref_id",
    "_required",
    "_scope",
    "_state",
    "_status",
    "_summary",
    "_type",
)

CAMEL_CASE_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
KEY_LABEL_PATTERN = re.compile(r"[\"']?(?P<key>[A-Za-z][A-Za-z0-9_-]{1,80})[\"']?\s*[:=]")

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

LIFECYCLE_STAGE_ALIASES = [
    ("use_approval", {"approval", "use-approval", "use_approval"}),
    ("redaction_review", {"redaction", "redaction-review", "redaction_review"}),
    ("export", {"export", "export-control", "export_control"}),
    ("asset_derivation", {"derivation", "derivation-quality", "derivation_quality"}),
    ("transform", {"transform", "transform-failure", "transform_failure"}),
    ("document_review", {"document-review", "document_review", "document-operations"}),
    ("evidence_review", {"evidence-gap", "evidence_gap", "evidence"}),
    ("assessment", {"assessment", "readiness", "suitability"}),
    ("internal_eval", {"eval", "evaluation", "internal-eval", "internal_eval"}),
    ("internal_training", {"training", "internal-training", "internal_training"}),
    ("promotion", {"promotion", "promotion-failure", "promotion_failure"}),
    ("capture", {"capture", "intake", "logging"}),
    ("runtime", {"runtime", "production"}),
    ("handoff", {"handoff", "escalation"}),
]

ISSUE_CLASS_ALIASES = [
    ("redaction_miss", {"redaction-miss", "redaction_miss"}),
    ("rights_ambiguity", {"rights-ambiguity", "rights_ambiguity"}),
    ("promotion_failure", {"promotion-failure", "promotion_failure"}),
    ("export_control_failure", {"export-control-failure", "export_control_failure"}),
    ("transform_failure", {"transform-failure", "transform_failure"}),
    ("derivation_quality_failure", {"derivation-quality-failure", "derivation_quality_failure"}),
    ("evidence_gap", {"evidence-gap", "evidence_gap"}),
    ("escalation_miss", {"escalation-miss", "escalation_miss"}),
    ("reviewer_disagreement", {"reviewer-disagreement", "reviewer_disagreement"}),
    (
        "phi_redaction_failure",
        {"phi-redaction-failure", "phi_redaction_failure", "phi-redaction", "phi_redaction"},
    ),
    (
        "missing_claim_evidence",
        {"missing-claim-evidence", "missing_claim_evidence", "claim-evidence-gap"},
    ),
    (
        "contract_rate_mismatch",
        {"contract-rate-mismatch", "contract_rate_mismatch", "rate-mismatch"},
    ),
    (
        "rate_source_ambiguity",
        {"rate-source-ambiguity", "rate_source_ambiguity", "rate-source"},
    ),
    (
        "allowed_amount_conflict",
        {"allowed-amount-conflict", "allowed_amount_conflict", "allowed-amount"},
    ),
    ("approval_bypass", {"approval-bypass", "approval_bypass", "bypass"}),
    (
        "downstream_export_mismatch",
        {"downstream-export-mismatch", "downstream_export_mismatch", "export-mismatch"},
    ),
    (
        "savings_recognition_dispute",
        {"savings-recognition-dispute", "savings_recognition_dispute", "savings-dispute"},
    ),
    ("use_approval", {"use-approval", "use_approval"}),
    ("redaction_miss", {"redaction", "redaction-review", "redaction_review"}),
    ("export_control_failure", {"export-control", "export_control"}),
    ("rights_ambiguity", {"rights", "rights-review", "rights_review"}),
    ("provenance_gap", {"provenance", "lineage"}),
    ("derivation_quality_failure", {"derivation-quality", "derivation_quality"}),
    ("readiness_gap", {"readiness-gap", "readiness_gap"}),
    ("workflow_truth", {"workflow-truth", "workflow_truth"}),
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


def _has_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict, tuple, set)):
        return bool(value)
    return True


def _normalize_key(value: Any) -> str:
    normalized = CAMEL_CASE_BOUNDARY.sub("_", str(value).strip())
    return normalized.lower().replace("-", "_").replace(" ", "_")


def _is_forbidden_summary_key(normalized: str) -> bool:
    if normalized in FORBIDDEN_SUMMARY_KEY_PARTS:
        return True
    if normalized.startswith(SENSITIVE_SUMMARY_KEY_PREFIXES):
        return not normalized.endswith(SAFE_SUMMARY_KEY_SUFFIXES)
    return False


def _validate_summary_only_mapping(value: dict[str, Any], field_name: str) -> None:
    for key, nested_value in value.items():
        normalized = _normalize_key(key)
        if _is_forbidden_summary_key(normalized):
            raise ValueError(
                f"{field_name} contains forbidden raw/sensitive payload key '{key}'. "
                "Store pointer refs, ids, digests, labels, or short summaries only."
            )
        if isinstance(nested_value, dict):
            _validate_summary_only_mapping(nested_value, field_name)
        elif isinstance(nested_value, list):
            for item in nested_value:
                if isinstance(item, dict):
                    _validate_summary_only_mapping(item, field_name)


def _validate_summary_only_json_value(value: Any, field_name: str) -> None:
    if isinstance(value, dict):
        _validate_summary_only_mapping(value, field_name)
    elif isinstance(value, list):
        for item in value:
            _validate_summary_only_json_value(item, field_name)


def validate_summary_only_text(value: str, field_name: str) -> str:
    """Reject obvious raw payload labels in incident free-text fields."""
    if not value:
        return value
    stripped = value.strip()
    if stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            parsed = None
        if parsed is not None:
            _validate_summary_only_json_value(parsed, field_name)

    for match in KEY_LABEL_PATTERN.finditer(value):
        key = match.group("key")
        normalized = _normalize_key(key)
        if _is_forbidden_summary_key(normalized):
            raise ValueError(
                f"{field_name} contains forbidden raw/sensitive payload label '{key}'. "
                "Store pointer refs, ids, digests, labels, or short summaries only."
            )
    return value


def parse_pointer_value(value: Any, field_name: str) -> dict[str, Any] | None:
    """Parse a pointer ref from YAML data or CLI/MCP text input."""
    if value is None:
        return None
    if isinstance(value, dict):
        _validate_summary_only_mapping(value, field_name)
        return value or None
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        if stripped.startswith("{"):
            parsed = json.loads(stripped)
            if not isinstance(parsed, dict):
                raise ValueError(f"{field_name} must be a JSON object when JSON is supplied")
            _validate_summary_only_mapping(parsed, field_name)
            return parsed
        return {
            "ref_id": stripped,
            "ref_type": REF_TYPE_BY_FIELD.get(field_name, field_name),
            "cache_policy": "ref_only",
        }
    raise TypeError(f"{field_name} must be a mapping, JSON object string, string ref id, or empty")


def parse_observed_state(value: Any) -> dict[str, Any] | None:
    """Parse optional incident-local observed state without assuming canonical truth."""
    if value is None:
        return None
    if isinstance(value, dict):
        _validate_summary_only_mapping(value, "observed_state")
        return value or None
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        if stripped.startswith("{"):
            parsed = json.loads(stripped)
            if not isinstance(parsed, dict):
                raise ValueError("observed_state must be a JSON object when JSON is supplied")
            _validate_summary_only_mapping(parsed, "observed_state")
            return parsed
        return {"summary": stripped}
    raise TypeError("observed_state must be a mapping, JSON object string, string summary, or empty")


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
    workflow_archetype: str
    subject_type: str
    blocked_use_class: str
    observed_state: dict[str, Any] | None
    tags: list[str]
    related_incidents: list[str]
    playbook_entry: str
    workflow_ref: dict[str, Any] | None = None
    evidence_ref: dict[str, Any] | None = None
    workflow_evidence_snapshot: dict[str, Any] | None = None
    subject_ref: dict[str, Any] | None = None
    assessment_ref: dict[str, Any] | None = None
    policy_decision_ref: dict[str, Any] | None = None
    use_approval_ref: dict[str, Any] | None = None
    asset_ref: dict[str, Any] | None = None
    derivation_ref: dict[str, Any] | None = None
    transform_ref: dict[str, Any] | None = None

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
    capability_area: str = ""
    lifecycle_stage: str = ""
    issue_class: str = ""
    workflow_archetype: str = ""
    subject_type: str = ""
    blocked_use_class: str = ""
    observed_state: dict[str, Any] | None = None
    workflow_ref: dict[str, Any] | None = None
    evidence_ref: dict[str, Any] | None = None
    workflow_evidence_snapshot: dict[str, Any] | None = None
    subject_ref: dict[str, Any] | None = None
    assessment_ref: dict[str, Any] | None = None
    policy_decision_ref: dict[str, Any] | None = None
    use_approval_ref: dict[str, Any] | None = None
    asset_ref: dict[str, Any] | None = None
    derivation_ref: dict[str, Any] | None = None
    transform_ref: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        for field_name in CORE_INCIDENT_FREE_TEXT_FIELDS:
            validate_summary_only_text(getattr(self, field_name), field_name)

    def to_dict(self) -> dict:
        """Convert to ordered dict matching the YAML template field order."""
        data = {}
        for key in INCIDENT_FIELD_ORDER:
            data[key] = getattr(self, key)
        for key in OPTIONAL_INCIDENT_FIELD_ORDER:
            value = getattr(self, key)
            if _has_value(value):
                data[key] = value
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
            capability_area=data.get("capability_area", "") or "",
            lifecycle_stage=data.get("lifecycle_stage", "") or "",
            issue_class=data.get("issue_class", "") or "",
            workflow_archetype=data.get("workflow_archetype", "") or "",
            subject_type=data.get("subject_type", "") or "",
            blocked_use_class=data.get("blocked_use_class", "") or "",
            observed_state=parse_observed_state(data.get("observed_state")),
            workflow_ref=parse_pointer_value(data.get("workflow_ref"), "workflow_ref"),
            evidence_ref=parse_pointer_value(data.get("evidence_ref"), "evidence_ref"),
            workflow_evidence_snapshot=parse_pointer_value(
                data.get("workflow_evidence_snapshot"), "workflow_evidence_snapshot"
            ),
            subject_ref=parse_pointer_value(data.get("subject_ref"), "subject_ref"),
            assessment_ref=parse_pointer_value(data.get("assessment_ref"), "assessment_ref"),
            policy_decision_ref=parse_pointer_value(
                data.get("policy_decision_ref"), "policy_decision_ref"
            ),
            use_approval_ref=parse_pointer_value(data.get("use_approval_ref"), "use_approval_ref"),
            asset_ref=parse_pointer_value(data.get("asset_ref"), "asset_ref"),
            derivation_ref=parse_pointer_value(data.get("derivation_ref"), "derivation_ref"),
            transform_ref=parse_pointer_value(data.get("transform_ref"), "transform_ref"),
        )


def build_incident_ref(incident: Incident) -> IncidentRef:
    """Build a boundary-safe IncidentRef from stored or inferred incident fields."""
    tokens = _normalized_tokens(incident)
    capability_area = incident.capability_area or _match_alias(tokens, CAPABILITY_AREA_ALIASES) or "unknown"
    lifecycle_stage = incident.lifecycle_stage or _match_alias(tokens, LIFECYCLE_STAGE_ALIASES) or "unknown"
    issue_class = incident.issue_class or _match_alias(tokens, ISSUE_CLASS_ALIASES) or incident.failure_type or "unknown"

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
        workflow_archetype=incident.workflow_archetype,
        subject_type=incident.subject_type,
        blocked_use_class=incident.blocked_use_class,
        observed_state=incident.observed_state,
        tags=list(incident.tags),
        related_incidents=list(incident.related_incidents),
        playbook_entry=incident.playbook_entry,
        workflow_ref=incident.workflow_ref,
        evidence_ref=incident.evidence_ref,
        workflow_evidence_snapshot=incident.workflow_evidence_snapshot,
        subject_ref=incident.subject_ref,
        assessment_ref=incident.assessment_ref,
        policy_decision_ref=incident.policy_decision_ref,
        use_approval_ref=incident.use_approval_ref,
        asset_ref=incident.asset_ref,
        derivation_ref=incident.derivation_ref,
        transform_ref=incident.transform_ref,
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
