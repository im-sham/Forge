from __future__ import annotations

import json

import yaml
from typer.testing import CliRunner

from forge_cli.cli import app
from forge_cli.incident_store import save_incident
from forge_cli.models import Incident


def test_ref_command_prints_incident_ref(tmp_path, sample_data):
    data_root = tmp_path / "forge-data"
    incidents_dir = data_root / "incidents"
    incidents_dir.mkdir(parents=True)
    save_incident(Incident.from_dict(sample_data), incidents_dir)

    runner = CliRunner()
    result = runner.invoke(
        app,
        ["ref", "001", "--compact"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["contract_name"] == "IncidentRef"
    assert payload["ref"]["incident_id"] == sample_data["id"]


def test_log_command_accepts_structured_axes_and_pointer_refs(tmp_path):
    data_root = tmp_path / "forge-data"
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "log",
            "--project",
            "proofhouse-document-operations",
            "--agent",
            "document-review-fixture",
            "--platform",
            "codex",
            "--severity",
            "functional",
            "--type",
            "other",
            "--capability-area",
            "governance",
            "--lifecycle-stage",
            "redaction_review",
            "--issue-class",
            "redaction_miss",
            "--workflow-archetype",
            "document_operations",
            "--subject-type",
            "document_packet",
            "--blocked-use-class",
            "internal_eval",
            "--workflow-ref",
            "workflow:document_ops_regulated_review_v0",
            "--assessment-ref",
            "assessment:document_ops_regulated_review_v0:g2",
            "--use-approval-ref",
            "use-approval:document_ops_internal_eval:g2",
            "--playbook-entry",
            "document-review-redaction-miss",
        ],
        input=(
            "Expected behavior\n"
            "Actual behavior\n"
            "Context\n"
            "root-cause\n"
            "Immediate fix\n"
            "Systemic takeaway\n"
            "document-operations,redaction-miss\n"
            "y\n"
        ),
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code == 0
    saved = next((data_root / "incidents").rglob("*.yml"))
    incident = Incident.from_dict(yaml.safe_load(saved.read_text()))
    assert incident.capability_area == "governance"
    assert incident.issue_class == "redaction_miss"
    assert incident.workflow_ref["ref_id"] == "workflow:document_ops_regulated_review_v0"
    assert incident.use_approval_ref["ref_id"] == "use-approval:document_ops_internal_eval:g2"


def test_log_command_accepts_claims_issue_class(tmp_path):
    data_root = tmp_path / "forge-data"
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "log",
            "--project",
            "proofhouse-claims",
            "--agent",
            "claims-review-fixture",
            "--platform",
            "codex",
            "--severity",
            "functional",
            "--type",
            "integration_failure",
            "--capability-area",
            "workflow_context",
            "--lifecycle-stage",
            "evidence_review",
            "--issue-class",
            "rate_source_ambiguity",
            "--workflow-archetype",
            "claims_hybrid_high_dollar_review",
            "--subject-type",
            "claim_review_packet",
            "--blocked-use-class",
            "internal_eval",
            "--workflow-ref",
            "workflow:claims-hybrid-high-dollar-review-v0",
            "--assessment-ref",
            "assessment:claims-hybrid-high-dollar-review-v0:weak-candidate",
            "--playbook-entry",
            "claims-rate-source-ambiguity",
        ],
        input=(
            "Expected behavior\n"
            "Actual behavior\n"
            "Context\n"
            "root-cause\n"
            "Immediate fix\n"
            "Systemic takeaway\n"
            "claims,rate-source-ambiguity\n"
            "y\n"
        ),
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code == 0
    saved = next((data_root / "incidents").rglob("*.yml"))
    incident = Incident.from_dict(yaml.safe_load(saved.read_text()))
    assert incident.issue_class == "rate_source_ambiguity"
    assert incident.workflow_archetype == "claims_hybrid_high_dollar_review"
    assert incident.workflow_ref["ref_id"] == "workflow:claims-hybrid-high-dollar-review-v0"


def test_log_command_rejects_unknown_workflow_archetype(tmp_path):
    data_root = tmp_path / "forge-data"
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "log",
            "--project",
            "proofhouse-claims",
            "--agent",
            "claims-review-fixture",
            "--platform",
            "codex",
            "--severity",
            "functional",
            "--type",
            "integration_failure",
            "--workflow-archetype",
            "claims_custom_unreviewed",
        ],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code == 1
    assert "Invalid workflow_archetype" in result.output
    assert not list((data_root / "incidents").rglob("*.yml"))


def test_list_command_filters_structured_axes(tmp_path, sample_data):
    data_root = tmp_path / "forge-data"
    incidents_dir = data_root / "incidents"
    incidents_dir.mkdir(parents=True)
    claims_data = sample_data.copy()
    claims_data.update(
        {
            "issue_class": "rate_source_ambiguity",
            "capability_area": "workflow_context",
            "lifecycle_stage": "evidence_review",
            "workflow_archetype": "claims_hybrid_high_dollar_review",
            "blocked_use_class": "internal_eval",
        }
    )
    docs_data = sample_data.copy()
    docs_data.update(
        {
            "id": "2026-03-04-002",
            "issue_class": "redaction_miss",
            "capability_area": "governance",
            "lifecycle_stage": "redaction_review",
            "workflow_archetype": "document_operations",
            "blocked_use_class": "external_export",
        }
    )
    save_incident(Incident.from_dict(claims_data), incidents_dir)
    save_incident(Incident.from_dict(docs_data), incidents_dir)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "list",
            "--issue-class",
            "rate_source_ambiguity",
            "--capability-area",
            "workflow_context",
            "--lifecycle-stage",
            "evidence_review",
            "--workflow-archetype",
            "claims_hybrid_high_dollar_review",
            "--blocked-use-class",
            "internal_eval",
        ],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code == 0
    assert "2026-03-04-001" in result.output
    assert "2026-03-04-002" not in result.output


def test_log_command_accepts_subject_ref(tmp_path):
    data_root = tmp_path / "forge-data"
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "log",
            "--project",
            "proofhouse-document-operations",
            "--agent",
            "document-review-fixture",
            "--platform",
            "codex",
            "--severity",
            "functional",
            "--type",
            "other",
            "--subject-ref",
            "subject:document-packet:synthetic-demo",
        ],
        input=(
            "Expected behavior\n"
            "Actual behavior\n"
            "Context\n"
            "root-cause\n"
            "Immediate fix\n"
            "Systemic takeaway\n"
            "document-operations\n"
            "y\n"
        ),
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code == 0
    saved = next((data_root / "incidents").rglob("*.yml"))
    incident = Incident.from_dict(yaml.safe_load(saved.read_text()))
    assert incident.subject_ref["ref_id"] == "subject:document-packet:synthetic-demo"
