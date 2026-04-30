from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AxisMetadata:
    field_name: str
    description: str
    values: list[str]
    required: bool = False


CAPABILITY_AREA_VALUES = [
    "workflow_context",
    "readiness",
    "governance",
    "forge",
    "operational_learning",
    "analyst",
    "external_integration",
]

LIFECYCLE_STAGE_VALUES = [
    "capture",
    "document_review",
    "evidence_review",
    "assessment",
    "policy_decision",
    "redaction_review",
    "use_approval",
    "promotion",
    "asset_derivation",
    "transform",
    "internal_eval",
    "internal_training",
    "export",
    "escalation",
    "runtime",
    "handoff",
]

ISSUE_CLASS_VALUES = [
    "redaction_miss",
    "rights_ambiguity",
    "promotion_failure",
    "export_control_failure",
    "transform_failure",
    "derivation_quality_failure",
    "evidence_gap",
    "escalation_miss",
    "reviewer_disagreement",
    "phi_redaction_failure",
    "missing_claim_evidence",
    "rate_source_ambiguity",
    "contract_rate_mismatch",
    "allowed_amount_conflict",
    "approval_bypass",
    "downstream_export_mismatch",
    "savings_recognition_dispute",
    "use_approval",
    "provenance_gap",
    "readiness_gap",
    "workflow_truth",
    "other",
]

WORKFLOW_ARCHETYPE_VALUES = [
    "document_operations",
    "claims_hybrid_high_dollar_review",
    "other",
]

USE_CLASS_VALUES = [
    "evidence_only",
    "internal_eval",
    "internal_training",
    "policy_learning",
    "external_export",
]

STRUCTURED_AXIS_METADATA = {
    "issue_class": AxisMetadata(
        field_name="issue_class",
        description="Forge-owned failure or boundary issue class for incident-memory filtering.",
        values=ISSUE_CLASS_VALUES,
    ),
    "capability_area": AxisMetadata(
        field_name="capability_area",
        description="Proofhouse capability area involved in the incident; this is not ownership transfer.",
        values=CAPABILITY_AREA_VALUES,
    ),
    "lifecycle_stage": AxisMetadata(
        field_name="lifecycle_stage",
        description="Workflow or Operational Learning lifecycle stage where the failure appeared.",
        values=LIFECYCLE_STAGE_VALUES,
    ),
    "workflow_archetype": AxisMetadata(
        field_name="workflow_archetype",
        description="High-level workflow pattern label used for incident discovery.",
        values=WORKFLOW_ARCHETYPE_VALUES,
    ),
    "blocked_use_class": AxisMetadata(
        field_name="blocked_use_class",
        description="Use class affected by the incident; Forge records the issue but does not approve or block use.",
        values=USE_CLASS_VALUES,
    ),
}
