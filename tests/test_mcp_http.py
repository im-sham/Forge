import pytest


mcp = pytest.importorskip("mcp")

import json  # noqa: E402
import yaml  # noqa: E402

from forge_cli.incident_store import save_incident  # noqa: E402
from forge_cli.models import Incident  # noqa: E402
from forge_cli.mcp_server import forge_list, forge_log, forge_schema  # noqa: E402
from forge_cli.mcp_http import (  # noqa: E402
    MCPHTTPServerOptions,
    resolve_transport_security,
    validate_server_options,
)


def test_validate_server_options_allows_loopback_defaults():
    validate_server_options(MCPHTTPServerOptions())


def test_validate_server_options_rejects_remote_bind_without_opt_in():
    options = MCPHTTPServerOptions(host="0.0.0.0")

    with pytest.raises(ValueError, match="--allow-remote"):
        validate_server_options(options)


def test_validate_server_options_requires_explicit_dns_override_for_remote_bind():
    options = MCPHTTPServerOptions(host="0.0.0.0", allow_remote=True)

    with pytest.raises(ValueError, match="--disable-dns-rebinding-protection"):
        validate_server_options(options)


def test_resolve_transport_security_keeps_localhost_protection_enabled():
    security = resolve_transport_security(MCPHTTPServerOptions())

    assert security is not None
    assert security.enable_dns_rebinding_protection is True
    assert "127.0.0.1:*" in security.allowed_hosts


def test_resolve_transport_security_can_disable_protection_for_private_network_use():
    security = resolve_transport_security(
        MCPHTTPServerOptions(
            host="0.0.0.0",
            allow_remote=True,
            disable_dns_rebinding_protection=True,
        )
    )

    assert security is not None
    assert security.enable_dns_rebinding_protection is False


def test_forge_schema_exposes_centralized_structured_axis_metadata():
    schema = json.loads(forge_schema())

    assert "structured_axis_metadata" in schema
    assert schema["structured_axis_metadata"]["issue_class"]["values"]
    assert "subject_ref" in schema["pointer_ref_fields"]
    assert "subject_ref" in schema["incident_ref_fields"]


def test_forge_list_filters_structured_axes(tmp_path, monkeypatch, sample_data):
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
    monkeypatch.setenv("FORGE_DATA_ROOT", str(data_root))

    result = forge_list(
        issue_class="rate_source_ambiguity",
        capability_area="workflow_context",
        lifecycle_stage="evidence_review",
        workflow_archetype="claims_hybrid_high_dollar_review",
        blocked_use_class="internal_eval",
    )

    assert "2026-03-04-001" in result
    assert "2026-03-04-002" not in result


def test_forge_log_rejects_raw_payload_pointer_keys(tmp_path, monkeypatch):
    data_root = tmp_path / "forge-data"
    monkeypatch.setenv("FORGE_DATA_ROOT", str(data_root))

    result = forge_log(
        project="proofhouse-claims",
        agent="claims-review-fixture",
        severity="functional",
        failure_type="other",
        expected_behavior="Expected behavior",
        actual_behavior="Actual behavior",
        workflow_ref=json.dumps({"ref_id": "workflow:demo", "claim_text": "raw claim"}),
    )

    assert "claim_text" in result
    assert not list((data_root / "incidents").rglob("*.yml"))


def test_forge_log_rejects_unknown_workflow_archetype(tmp_path, monkeypatch):
    data_root = tmp_path / "forge-data"
    monkeypatch.setenv("FORGE_DATA_ROOT", str(data_root))

    result = forge_log(
        project="proofhouse-claims",
        agent="claims-review-fixture",
        severity="functional",
        failure_type="other",
        expected_behavior="Expected behavior",
        actual_behavior="Actual behavior",
        workflow_archetype="claims_custom_unreviewed",
    )

    assert "Invalid workflow_archetype" in result
    assert not list((data_root / "incidents").rglob("*.yml"))


def test_forge_log_accepts_subject_ref(tmp_path, monkeypatch):
    data_root = tmp_path / "forge-data"
    monkeypatch.setenv("FORGE_DATA_ROOT", str(data_root))

    result = forge_log(
        project="proofhouse-document-operations",
        agent="document-review-fixture",
        severity="functional",
        failure_type="other",
        expected_behavior="Expected behavior",
        actual_behavior="Actual behavior",
        subject_ref="subject:document-packet:synthetic-demo",
    )

    assert "Incident logged:" in result
    saved = next((data_root / "incidents").rglob("*.yml"))
    incident = Incident.from_dict(yaml.safe_load(saved.read_text()))
    assert incident.subject_ref["ref_id"] == "subject:document-packet:synthetic-demo"
