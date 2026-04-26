"""Forge MCP Server — Expose forge tools via Model Context Protocol."""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from datetime import datetime, timezone

from forge_cli.config import load_config
from forge_cli.incident_store import (
    find_incident,
    generate_id,
    get_all_incidents,
    list_incidents,
    save_incident,
)
from forge_cli.models import (
    CAPABILITY_AREA_VALUES,
    ISSUE_CLASS_VALUES,
    LIFECYCLE_STAGE_VALUES,
    PROOFHOUSE_AXIS_FIELDS,
    PROOFHOUSE_REF_FIELDS,
    USE_CLASS_VALUES,
    FailureType,
    Incident,
    Severity,
    parse_observed_state,
    parse_pointer_value,
)

mcp = FastMCP("Forge", json_response=True)


def _incident_to_text(incident: Incident) -> str:
    """Format an incident as readable text."""
    lines = [
        f"ID: {incident.id}",
        f"Timestamp: {incident.timestamp}",
        f"Reporter: {incident.reported_by}",
        f"Project: {incident.project}",
        f"Agent: {incident.agent}",
        f"Platform: {incident.platform}",
        f"Severity: {incident.severity}",
        f"Failure Type: {incident.failure_type}",
        "",
        f"Expected: {incident.expected_behavior.strip()}",
        "",
        f"Actual: {incident.actual_behavior.strip()}",
    ]
    if incident.context.strip():
        lines += ["", f"Context: {incident.context.strip()}"]
    if incident.root_cause.strip():
        lines += ["", f"Root Cause: {incident.root_cause.strip()}"]
    if incident.immediate_fix.strip():
        lines += ["", f"Immediate Fix: {incident.immediate_fix.strip()}"]
    if incident.systemic_takeaway.strip():
        lines += ["", f"Systemic Takeaway: {incident.systemic_takeaway.strip()}"]
    if incident.tags:
        lines.append(f"\nTags: {', '.join(incident.tags)}")
    axes = [
        ("Capability Area", incident.capability_area),
        ("Lifecycle Stage", incident.lifecycle_stage),
        ("Issue Class", incident.issue_class),
        ("Workflow Archetype", incident.workflow_archetype),
        ("Subject Type", incident.subject_type),
        ("Blocked Use Class", incident.blocked_use_class),
    ]
    shown_axes = [f"{label}: {value}" for label, value in axes if value]
    if shown_axes:
        lines += ["", "Structured Axes:", *shown_axes]
    present_refs = [field_name for field_name in PROOFHOUSE_REF_FIELDS if getattr(incident, field_name)]
    if present_refs:
        lines += ["", f"Pointer Refs: {', '.join(present_refs)}"]
    if incident.related_incidents:
        lines.append(f"Related: {', '.join(incident.related_incidents)}")
    if incident.playbook_entry:
        lines.append(f"Playbook: {incident.playbook_entry}")
    return "\n".join(lines)


@mcp.tool()
def forge_log(
    project: str,
    agent: str,
    severity: str,
    failure_type: str,
    expected_behavior: str,
    actual_behavior: str,
    platform: str = "",
    context: str = "",
    root_cause: str = "",
    immediate_fix: str = "",
    systemic_takeaway: str = "",
    tags: str = "",
    related_incidents: str = "",
    reported_by: str = "",
    playbook_entry: str = "",
    capability_area: str = "",
    lifecycle_stage: str = "",
    issue_class: str = "",
    workflow_archetype: str = "",
    subject_type: str = "",
    blocked_use_class: str = "",
    observed_state: str = "",
    workflow_ref: str = "",
    evidence_ref: str = "",
    workflow_evidence_snapshot: str = "",
    assessment_ref: str = "",
    policy_decision_ref: str = "",
    use_approval_ref: str = "",
    asset_ref: str = "",
    derivation_ref: str = "",
    transform_ref: str = "",
) -> str:
    """Log a new forge incident. Creates a YAML file in the incidents directory.

    Args:
        project: Project name (e.g., "support-agent", "governance-service")
        agent: Agent or component that failed (e.g., "respond-node", "mcp-server")
        severity: Severity level — must be one of: cosmetic, functional, safety-critical
        failure_type: Failure category — must be one of: hallucination, tool_misuse, scope_creep, safety_boundary_violation, performance_degradation, context_loss, confidence_miscalibration, instruction_drift, error_handling_failure, integration_failure, adversarial_vulnerability, other
        expected_behavior: What the system should have done
        actual_behavior: What actually happened
        platform: AI tool/platform (e.g., "claude-code", "cursor", "chatgpt"). Defaults to empty.
        context: Additional context about when/where this occurred
        root_cause: Root cause if known
        immediate_fix: Fix applied or recommended
        systemic_takeaway: Broader lesson learned
        tags: Comma-separated tags (e.g., "silent-fallback,observability-gap")
        related_incidents: Comma-separated related incident IDs (e.g., "2026-03-04-001,2026-03-04-002")
        reported_by: Who reported this. Defaults to config default_reporter.
        playbook_entry: Optional playbook slug.
        capability_area: Optional structured Proofhouse capability area.
        lifecycle_stage: Optional structured lifecycle stage.
        issue_class: Optional structured issue class.
        workflow_archetype: Optional workflow archetype such as document_operations.
        subject_type: Optional subject class such as document_packet.
        blocked_use_class: Optional blocked use class such as internal_eval.
        observed_state: Optional incident-local JSON object or summary.
        workflow_ref: Optional WorkflowRef pointer as JSON object or ref id.
        evidence_ref: Optional EvidenceRef pointer as JSON object or ref id.
        workflow_evidence_snapshot: Optional WorkflowEvidenceSnapshot pointer as JSON object or id.
        assessment_ref: Optional AssessmentRef pointer as JSON object or ref id.
        policy_decision_ref: Optional PolicyDecisionRef pointer as JSON object or ref id.
        use_approval_ref: Optional UseApprovalRef pointer as JSON object or ref id.
        asset_ref: Optional AssetRef pointer as JSON object or ref id.
        derivation_ref: Optional DerivationRef pointer as JSON object or ref id.
        transform_ref: Optional TransformRef pointer as JSON object or ref id.
    """
    cfg = load_config()

    # Validate severity
    valid_severities = [s.value for s in Severity]
    if severity not in valid_severities:
        return f"Invalid severity '{severity}'. Must be one of: {', '.join(valid_severities)}"

    # Validate failure_type
    valid_types = [f.value for f in FailureType]
    if failure_type not in valid_types:
        return f"Invalid failure_type '{failure_type}'. Must be one of: {', '.join(valid_types)}"

    for field_name, value, choices in [
        ("capability_area", capability_area, CAPABILITY_AREA_VALUES),
        ("lifecycle_stage", lifecycle_stage, LIFECYCLE_STAGE_VALUES),
        ("issue_class", issue_class, ISSUE_CLASS_VALUES),
        ("blocked_use_class", blocked_use_class, USE_CLASS_VALUES),
    ]:
        if value and value not in choices:
            return f"Invalid {field_name} '{value}'. Must be one of: {', '.join(choices)}"

    try:
        pointer_refs = {
            "workflow_ref": parse_pointer_value(workflow_ref, "workflow_ref"),
            "evidence_ref": parse_pointer_value(evidence_ref, "evidence_ref"),
            "workflow_evidence_snapshot": parse_pointer_value(
                workflow_evidence_snapshot, "workflow_evidence_snapshot"
            ),
            "assessment_ref": parse_pointer_value(assessment_ref, "assessment_ref"),
            "policy_decision_ref": parse_pointer_value(policy_decision_ref, "policy_decision_ref"),
            "use_approval_ref": parse_pointer_value(use_approval_ref, "use_approval_ref"),
            "asset_ref": parse_pointer_value(asset_ref, "asset_ref"),
            "derivation_ref": parse_pointer_value(derivation_ref, "derivation_ref"),
            "transform_ref": parse_pointer_value(transform_ref, "transform_ref"),
        }
        observed = parse_observed_state(observed_state)
    except (TypeError, ValueError) as e:
        return str(e)

    now = datetime.now(timezone.utc)
    incident_id = generate_id(cfg.incidents_dir, now.date())

    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
    related_list = [r.strip() for r in related_incidents.split(",") if r.strip()] if related_incidents else []

    incident = Incident(
        id=incident_id,
        timestamp=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        reported_by=reported_by or cfg.default_reporter,
        project=project,
        agent=agent,
        platform=platform,
        severity=severity,
        failure_type=failure_type,
        expected_behavior=expected_behavior,
        actual_behavior=actual_behavior,
        context=context,
        root_cause=root_cause,
        immediate_fix=immediate_fix,
        systemic_takeaway=systemic_takeaway,
        tags=tag_list,
        related_incidents=related_list,
        playbook_entry=playbook_entry,
        capability_area=capability_area,
        lifecycle_stage=lifecycle_stage,
        issue_class=issue_class,
        workflow_archetype=workflow_archetype,
        subject_type=subject_type,
        blocked_use_class=blocked_use_class,
        observed_state=observed,
        **pointer_refs,
    )

    filepath = save_incident(incident, cfg.incidents_dir)
    return f"Incident logged: {incident_id}\nSaved to: {filepath}"


@mcp.tool()
def forge_list(
    project: str = "",
    severity: str = "",
    since: str = "",
    tag: str = "",
    limit: int = 10,
) -> str:
    """List forge incidents with optional filters.

    Args:
        project: Filter by project name (e.g., "support-agent", "governance-service")
        severity: Filter by severity (cosmetic, functional, safety-critical)
        since: Filter by date, showing incidents from this date onward (YYYY-MM-DD)
        tag: Filter by tag (e.g., "silent-fallback", "hallucination")
        limit: Maximum number of incidents to return (default 10)
    """
    cfg = load_config()
    incidents = list_incidents(
        cfg.incidents_dir,
        project=project or None,
        severity=severity or None,
        since=since or None,
        tag=tag or None,
        limit=limit,
    )

    if not incidents:
        return "No incidents found matching the given filters."

    results = []
    for inc in incidents:
        summary = (inc.actual_behavior or "").strip().split("\n")[0][:80]
        results.append(
            f"[{inc.id}] {inc.project}/{inc.platform} | {inc.severity} | {inc.failure_type} | {summary}"
        )

    return f"Found {len(incidents)} incident(s):\n\n" + "\n".join(results)


@mcp.tool()
def forge_show(incident_id: str) -> str:
    """Show full details of a single forge incident.

    Args:
        incident_id: Incident ID (e.g., "2026-03-04-001") or suffix (e.g., "001")
    """
    cfg = load_config()
    incident = find_incident(cfg.incidents_dir, incident_id)

    if incident is None:
        return f"No incident found matching '{incident_id}'."

    return _incident_to_text(incident)


@mcp.tool()
def forge_incident_ref(incident_id: str) -> str:
    """Return the Proofhouse IncidentRef projection for a single Forge incident.

    Args:
        incident_id: Incident ID (e.g., "2026-03-04-001") or suffix (e.g., "001")
    """
    cfg = load_config()
    incident = find_incident(cfg.incidents_dir, incident_id)

    if incident is None:
        return f"No incident found matching '{incident_id}'."

    return json.dumps(incident.to_ref_envelope(), indent=2)


@mcp.tool()
def forge_stats(
    project: str = "",
    severity: str = "",
) -> str:
    """Show aggregate statistics across forge incidents.

    Args:
        project: Filter by project name
        severity: Filter by severity level
    """
    from collections import Counter

    cfg = load_config()
    incidents = get_all_incidents(cfg.incidents_dir)

    if project:
        incidents = [i for i in incidents if i.project == project]
    if severity:
        incidents = [i for i in incidents if i.severity == severity]

    if not incidents:
        return "No incidents found."

    by_severity = Counter(i.severity for i in incidents)
    by_type = Counter(i.failure_type for i in incidents)
    by_project = Counter(i.project for i in incidents)
    by_platform = Counter(i.platform for i in incidents if i.platform)
    all_tags = Counter(tag for i in incidents for tag in i.tags)

    lines = [f"Total incidents: {len(incidents)}", ""]

    lines.append("By Severity:")
    for sev, count in by_severity.most_common():
        lines.append(f"  {sev}: {count}")

    lines.append("\nBy Project:")
    for proj, count in by_project.most_common():
        lines.append(f"  {proj}: {count}")

    lines.append("\nBy Failure Type:")
    for ft, count in by_type.most_common():
        lines.append(f"  {ft}: {count}")

    lines.append("\nBy Platform:")
    for plat, count in by_platform.most_common():
        lines.append(f"  {plat}: {count}")

    if all_tags:
        lines.append("\nTop Tags:")
        for tag, count in all_tags.most_common(10):
            lines.append(f"  {tag}: {count}")

    return "\n".join(lines)


@mcp.tool()
def forge_playbook_list() -> str:
    """List all playbook entries documenting recurring failure patterns."""
    cfg = load_config()
    playbook_dir = cfg.playbook_dir

    if not playbook_dir.exists():
        return "No playbook directory found."

    entries = sorted(playbook_dir.glob("*.md"))
    entries = [e for e in entries if e.stem != "index"]

    if not entries:
        return "No playbook entries yet. Entries are created when patterns have 3+ occurrences or safety-critical severity."

    results = []
    for entry in entries:
        name = entry.stem.replace("-", " ").title()
        results.append(f"- {name} ({entry.name})")

    return "Playbook entries:\n\n" + "\n".join(results)


@mcp.tool()
def forge_playbook_show(name: str) -> str:
    """Show a specific playbook entry by name.

    Args:
        name: Playbook entry name (e.g., "silent-fallback" or "hallucination"). Partial matches supported.
    """
    cfg = load_config()
    playbook_dir = cfg.playbook_dir

    if not playbook_dir.exists():
        return "Playbook directory not found."

    target = playbook_dir / f"{name}.md"
    if not target.exists():
        matches = [f for f in playbook_dir.glob("*.md") if name.lower() in f.stem.lower() and f.stem != "index"]
        if len(matches) == 1:
            target = matches[0]
        elif len(matches) > 1:
            return f"Ambiguous name '{name}'. Matches: {', '.join(m.stem for m in matches)}"
        else:
            return f"No playbook entry matching '{name}'."

    return target.read_text()


@mcp.tool()
def forge_schema() -> str:
    """Show the incident schema — available severity levels, failure types, and field names."""
    severities = [s.value for s in Severity]
    failure_types = [f.value for f in FailureType]

    return json.dumps(
        {
            "severity_levels": severities,
            "failure_types": failure_types,
            "fields": [
                "id", "timestamp", "reported_by", "project", "agent", "platform",
                "severity", "failure_type", "expected_behavior", "actual_behavior",
                "context", "root_cause", "immediate_fix", "systemic_takeaway",
                "tags", "related_incidents", "playbook_entry",
                "capability_area", "lifecycle_stage", "issue_class", "workflow_archetype",
                "subject_type", "blocked_use_class", "observed_state",
                "workflow_ref", "evidence_ref", "workflow_evidence_snapshot",
                "assessment_ref", "policy_decision_ref", "use_approval_ref",
                "asset_ref", "derivation_ref", "transform_ref",
            ],
            "structured_axis_fields": PROOFHOUSE_AXIS_FIELDS,
            "structured_axis_values": {
                "capability_area": CAPABILITY_AREA_VALUES,
                "lifecycle_stage": LIFECYCLE_STAGE_VALUES,
                "issue_class": ISSUE_CLASS_VALUES,
                "blocked_use_class": USE_CLASS_VALUES,
            },
            "emitted_refs": ["IncidentRef"],
            "incident_ref_fields": [
                "incident_id", "failure_type", "severity", "capability_area",
                "lifecycle_stage", "issue_class", "workflow_archetype", "subject_type",
                "blocked_use_class", "workflow_ref", "evidence_ref",
                "workflow_evidence_snapshot", "assessment_ref", "policy_decision_ref",
                "use_approval_ref", "asset_ref", "derivation_ref", "transform_ref",
                "playbook_entry",
            ],
            "pointer_ref_fields": PROOFHOUSE_REF_FIELDS,
            "compatibility": "Existing incident YAML can omit all structured axis and pointer fields.",
        },
        indent=2,
    )


if __name__ == "__main__":
    mcp.run()
