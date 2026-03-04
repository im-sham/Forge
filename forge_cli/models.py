from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


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
