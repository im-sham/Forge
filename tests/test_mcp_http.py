import pytest


mcp = pytest.importorskip("mcp")

import json  # noqa: E402
import os  # noqa: E402
import yaml  # noqa: E402
from pathlib import Path  # noqa: E402
import time  # noqa: E402

from forge_cli.incident_store import DuplicateIncidentError, save_incident  # noqa: E402
from forge_cli.models import Incident  # noqa: E402
from forge_cli.mcp_server import (  # noqa: E402
    forge_incident_ref,
    forge_list,
    forge_log,
    forge_schema,
    forge_show,
    forge_stats,
)
from forge_cli.mcp_http import (  # noqa: E402
    MCPHTTPServerOptions,
    resolve_transport_security,
    validate_server_options,
)


def _minimal_mcp_log() -> str:
    return forge_log(
        project="project",
        agent="agent",
        platform="platform",
        severity="functional",
        failure_type="other",
        expected_behavior="Expected behavior",
        actual_behavior="Actual behavior",
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
    assert "control_refs" in schema["pointer_ref_fields"]
    assert "control_refs" in schema["incident_ref_fields"]


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


def test_mcp_list_and_stats_report_loaded_and_skipped_corrupt_files(
    tmp_path, monkeypatch, sample_data
):
    data_root = tmp_path / "forge-data"
    incidents_dir = data_root / "incidents"
    incidents_dir.mkdir(parents=True)
    save_incident(Incident.from_dict(sample_data), incidents_dir)
    corrupt_path = incidents_dir / "2026-03" / "2026-03-04-002.yml"
    corrupt_payload = "incident: [unterminated"
    corrupt_path.write_text(corrupt_payload)
    monkeypatch.setenv("FORGE_DATA_ROOT", str(data_root))

    list_result = forge_list()
    stats_result = forge_stats()

    for result in (list_result, stats_result):
        assert "Valid corpus incidents: 1" in result
        assert "Corrupt corpus files: 1" in result
        assert "Matched incidents: 1" in result
        assert "Returned incidents: 1" in result
        assert "2026-03/2026-03-04-002.yml" in result
        assert "YAMLError" in result
        assert str(data_root) not in result
    assert corrupt_path.read_text() == corrupt_payload


def test_mcp_diagnostics_preserve_established_list_and_stats_markers(
    tmp_path, monkeypatch, sample_data
):
    data_root = tmp_path / "forge-data"
    incidents_dir = data_root / "incidents"
    incidents_dir.mkdir(parents=True)
    save_incident(Incident.from_dict(sample_data), incidents_dir)
    monkeypatch.setenv("FORGE_DATA_ROOT", str(data_root))

    list_lines = forge_list().splitlines()
    stats_lines = forge_stats().splitlines()

    assert list_lines[0] == "Found 1 incident(s):"
    assert "Valid corpus incidents: 1" in list_lines[1:]
    assert stats_lines[0] == "Total incidents: 1"
    assert "Valid corpus incidents: 1" in stats_lines[1:]


def test_mcp_empty_marker_remains_first_and_missing_corpus_is_read_only(
    tmp_path, monkeypatch
):
    data_root = tmp_path / "forge-data"
    incidents_dir = data_root / "incidents"
    monkeypatch.setenv("FORGE_DATA_ROOT", str(data_root))

    list_result = forge_list()
    stats_result = forge_stats()

    assert list_result.splitlines()[0] == "No incidents found matching the given filters."
    assert stats_result.splitlines()[0] == "Total incidents: 0"
    assert "Valid corpus incidents: 0" in list_result
    assert "Valid corpus incidents: 0" in stats_result
    assert not incidents_dir.exists()


def test_mcp_list_zero_limit_reports_diagnostics_without_incidents(
    tmp_path, monkeypatch, sample_data
):
    data_root = tmp_path / "forge-data"
    incidents_dir = data_root / "incidents"
    incidents_dir.mkdir(parents=True)
    save_incident(Incident.from_dict(sample_data), incidents_dir)
    monkeypatch.setenv("FORGE_DATA_ROOT", str(data_root))

    result = forge_list(limit=0)

    assert "Valid corpus incidents: 1" in result
    assert "Matched incidents: 1" in result
    assert "Returned incidents: 0" in result
    assert sample_data["id"] not in result


def test_mcp_list_rejects_negative_limit(tmp_path, monkeypatch):
    monkeypatch.setenv("FORGE_DATA_ROOT", str(tmp_path / "forge-data"))

    result = forge_list(limit=-1)

    assert result == "Invalid limit: must be non-negative"


def test_mcp_list_and_stats_fail_closed_on_operational_scan_error(
    tmp_path, monkeypatch, sample_data
):
    data_root = tmp_path / "forge-data"
    corrupt_path = data_root / "incidents" / "2026-03" / "unsafe\nincident.yml"
    corrupt_path.parent.mkdir(parents=True)
    corrupt_path.write_text("incident: [unterminated")
    safe_corrupt = corrupt_path.with_name("corrupt.yml")
    safe_corrupt.write_text("incident: [unterminated")
    save_incident(
        Incident.from_dict(
            {
                **sample_data,
                "project": "secret-valid-project",
            }
        ),
        data_root / "incidents",
    )
    raw_message = f"raw traversal failure at {data_root}\nwith payload"

    real_stat = os.stat

    def fail_stat(path, *args, **kwargs):
        if path == corrupt_path.name:
            error = PermissionError(raw_message)
            error.filename = str(data_root / "incidents" / "unsafe\nroot")
            raise error
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr("forge_cli.incident_store.os.stat", fail_stat)
    monkeypatch.setenv("FORGE_DATA_ROOT", str(data_root))

    for result in (forge_list(), forge_stats()):
        assert result.splitlines()[0] == "Incident corpus scan incomplete."
        assert "Scan operational errors: 1" in result
        assert "PermissionError" in result
        assert "YAMLError" in result
        assert "Found " not in result
        assert sample_data["id"] not in result
        assert "secret-valid-project" not in result
        assert "Total incidents:" not in result
        assert "By Severity:" not in result
        assert "By Type:" not in result
        assert "By Project:" not in result
        assert "By Platform:" not in result
        assert "Top Tags:" not in result
        assert raw_message not in result
        assert str(data_root) not in result
        assert "\nroot" not in result
        assert "\nincident" not in result


@pytest.mark.parametrize("lookup", ["2026-03-04-001", "001"])
@pytest.mark.parametrize("lookup_tool", [forge_show, forge_incident_ref])
def test_mcp_lookup_reports_corrupt_requested_candidate(
    tmp_path, monkeypatch, lookup, lookup_tool
):
    data_root = tmp_path / "forge-data"
    candidate = data_root / "incidents" / "2026-03" / "2026-03-04-001.yml"
    candidate.parent.mkdir(parents=True)
    candidate.write_text("incident: [unterminated")
    monkeypatch.setenv("FORGE_DATA_ROOT", str(data_root))

    result = lookup_tool(lookup)

    assert "Requested incident candidate is corrupt" in result
    assert "No incident found" not in result
    assert str(data_root) not in result
    assert "Traceback" not in result


@pytest.mark.parametrize("lookup_tool", [forge_show, forge_incident_ref])
@pytest.mark.parametrize("lookup", ["2026-03-04-001", "001"])
def test_mcp_lookup_prioritizes_matching_corrupt_over_valid_candidate(
    tmp_path, monkeypatch, sample_data, lookup_tool, lookup
):
    data_root = tmp_path / "hostile-[root]\x1b"
    incidents_dir = data_root / "incidents"
    valid = save_incident(Incident.from_dict(sample_data), incidents_dir)
    corrupt = incidents_dir / "duplicate" / valid.name
    corrupt.parent.mkdir()
    corrupt.write_text("incident: [unterminated")
    monkeypatch.setenv("FORGE_DATA_ROOT", str(data_root))

    result = lookup_tool(lookup)

    assert "Requested incident candidate is corrupt" in result
    assert "duplicate/2026-03-04-001.yml" in result
    assert str(data_root) not in result
    assert "\x1b" not in result
    assert "Traceback" not in result


@pytest.mark.parametrize("lookup_tool", [forge_show, forge_incident_ref])
@pytest.mark.parametrize("lookup", ["2026-03-04-001", "001"])
def test_mcp_lookup_prioritizes_scan_error_over_matching_corruption_and_fallback(
    tmp_path, monkeypatch, sample_data, lookup_tool, lookup
):
    data_root = tmp_path / "hostile-[root]\x1b"
    incidents_dir = data_root / "incidents"
    valid = save_incident(Incident.from_dict(sample_data), incidents_dir)
    corrupt = incidents_dir / "duplicate" / valid.name
    corrupt.parent.mkdir()
    corrupt.write_text("incident: [unterminated")
    external = tmp_path / "external"
    external.mkdir()
    (incidents_dir / "unrelated").symlink_to(external, target_is_directory=True)
    monkeypatch.setenv("FORGE_DATA_ROOT", str(data_root))

    result = lookup_tool(lookup)

    assert "operationally incomplete" in result
    assert "unrelated: SymlinkRejectedError" in result
    assert "Requested incident candidate is corrupt" not in result
    assert "No incident found" not in result
    assert "duplicate/2026-03-04-001.yml" not in result
    assert str(data_root) not in result
    assert "\x1b" not in result
    assert "Traceback" not in result


@pytest.mark.parametrize("lookup_tool", [forge_show, forge_incident_ref])
def test_mcp_lookup_valid_exact_ignores_corrupt_suffix_candidate(
    tmp_path, monkeypatch, sample_data, lookup_tool
):
    data_root = tmp_path / "hostile-[root]\x1b"
    incidents_dir = data_root / "incidents"
    valid = save_incident(Incident.from_dict(sample_data), incidents_dir)
    corrupt_suffix = incidents_dir / "suffix" / f"prefix-{valid.name}"
    corrupt_suffix.parent.mkdir()
    corrupt_suffix.write_text("incident: [unterminated")
    monkeypatch.setenv("FORGE_DATA_ROOT", str(data_root))

    result = lookup_tool(valid.stem)

    assert sample_data["id"] in result
    assert "Requested incident candidate is corrupt" not in result
    assert f"prefix-{valid.name}" not in result
    assert str(data_root) not in result
    assert "\x1b" not in result
    assert "Traceback" not in result


@pytest.mark.parametrize("lookup_tool", [forge_show, forge_incident_ref])
@pytest.mark.parametrize("lookup", ["2026-03-04-001", "001"])
def test_mcp_lookup_prioritizes_inaccessible_nested_directory_over_valid_candidate(
    tmp_path, monkeypatch, sample_data, lookup_tool, lookup
):
    data_root = tmp_path / "hostile-[root]\x1b"
    incidents_dir = data_root / "incidents"
    save_incident(Incident.from_dict(sample_data), incidents_dir)
    (incidents_dir / "nested").mkdir()
    real_listdir = os.listdir
    calls = 0

    def fail_nested_listdir(directory_fd):
        nonlocal calls
        calls += 1
        if calls == 3:
            raise PermissionError(f"secret root {data_root}")
        return real_listdir(directory_fd)

    monkeypatch.setattr("forge_cli.incident_store.os.listdir", fail_nested_listdir)
    monkeypatch.setenv("FORGE_DATA_ROOT", str(data_root))

    result = lookup_tool(lookup)

    assert "operationally incomplete" in result
    assert "nested: PermissionError" in result
    assert str(data_root) not in result
    assert "\x1b" not in result
    assert "Traceback" not in result


@pytest.mark.parametrize("lookup_tool", [forge_show, forge_incident_ref])
@pytest.mark.parametrize("lookup", ["2026-03-04-001", "001"])
def test_mcp_lookup_prioritizes_symlinked_nested_directory_over_valid_candidate(
    tmp_path, monkeypatch, sample_data, lookup_tool, lookup
):
    data_root = tmp_path / "hostile-[root]\x1b"
    incidents_dir = data_root / "incidents"
    save_incident(Incident.from_dict(sample_data), incidents_dir)
    external = tmp_path / "external"
    external.mkdir()
    (incidents_dir / "nested").symlink_to(external, target_is_directory=True)
    monkeypatch.setenv("FORGE_DATA_ROOT", str(data_root))

    result = lookup_tool(lookup)

    assert "operationally incomplete" in result
    assert "nested: SymlinkRejectedError" in result
    assert str(data_root) not in result
    assert "\x1b" not in result
    assert "Traceback" not in result


@pytest.mark.parametrize("lookup_tool", [forge_show, forge_incident_ref])
@pytest.mark.parametrize("lookup", ["2026-03-04-001", "001"])
def test_mcp_lookup_rejects_multiple_valid_exact_candidates(
    tmp_path, monkeypatch, sample_data, lookup_tool, lookup
):
    data_root = tmp_path / "hostile-[root]\x1b"
    incidents_dir = data_root / "incidents"
    valid = save_incident(Incident.from_dict(sample_data), incidents_dir)
    duplicate = incidents_dir / "duplicate" / valid.name
    duplicate.parent.mkdir()
    duplicate.write_bytes(valid.read_bytes())
    monkeypatch.setenv("FORGE_DATA_ROOT", str(data_root))

    result = lookup_tool(lookup)

    assert "Ambiguous incident id" in result
    assert str(data_root) not in result
    assert "\x1b" not in result
    assert "Traceback" not in result


@pytest.mark.parametrize("lookup_tool", [forge_show, forge_incident_ref])
@pytest.mark.parametrize("nested_failure", [False, True])
def test_mcp_lookup_reports_operationally_incomplete_scan(
    tmp_path, monkeypatch, lookup_tool, nested_failure
):
    data_root = tmp_path / "forge-data"
    incidents_dir = data_root / "incidents"
    incidents_dir.mkdir(parents=True)
    if nested_failure:
        (incidents_dir / "nested").mkdir()
    raw_message = f"raw scan failure {data_root}\nsecret"
    real_listdir = os.listdir
    calls = 0

    def fail_listdir(directory_fd):
        nonlocal calls
        calls += 1
        if not nested_failure or calls == 2:
            raise PermissionError(raw_message)
        return real_listdir(directory_fd)

    monkeypatch.setattr("forge_cli.incident_store.os.listdir", fail_listdir)
    monkeypatch.setenv("FORGE_DATA_ROOT", str(data_root))

    result = lookup_tool("001")

    assert "operationally incomplete" in result
    assert "No incident found" not in result
    assert str(data_root) not in result
    assert raw_message not in result
    assert "Traceback" not in result


@pytest.mark.parametrize(
    ("incident_id", "timestamp", "include_timestamp"),
    [
        ("2026-02-30-001", "2026-02-28T12:00:00Z", True),
        ("legacy-malformed", "not-a-timestamp", True),
        ("legacy-empty", "", True),
        ("legacy-missing", None, False),
    ],
)
def test_mcp_scan_classifies_invalid_ordering_fields(
    tmp_path, monkeypatch, sample_data, incident_id, timestamp, include_timestamp
):
    data_root = tmp_path / "forge-data"
    candidate = data_root / "incidents" / "nested" / f"{incident_id}.yml"
    candidate.parent.mkdir(parents=True)
    payload = {**sample_data, "id": incident_id}
    if include_timestamp:
        payload["timestamp"] = timestamp
    else:
        payload.pop("timestamp", None)
    candidate.write_text(yaml.safe_dump(payload))
    monkeypatch.setenv("FORGE_DATA_ROOT", str(data_root))

    for result in (forge_list(), forge_stats()):
        assert "Corrupt corpus files: 1" in result
        assert f"nested/{incident_id}.yml: InvalidIncidentError" in result
        assert str(data_root) not in result


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


def test_forge_log_rejects_sensitive_core_free_text(tmp_path, monkeypatch):
    data_root = tmp_path / "forge-data"
    monkeypatch.setenv("FORGE_DATA_ROOT", str(data_root))

    result = forge_log(
        project="proofhouse-claims",
        agent="claims-review-fixture",
        severity="functional",
        failure_type="safety_boundary_violation",
        expected_behavior="Expected behavior",
        actual_behavior="Actual behavior",
        context='{"patient_name": "Synthetic Patient"}',
    )

    assert "context" in result
    assert "patient_name" in result
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


def test_forge_log_accepts_control_refs(tmp_path, monkeypatch):
    data_root = tmp_path / "forge-data"
    monkeypatch.setenv("FORGE_DATA_ROOT", str(data_root))

    result = forge_log(
        project="proofhouse-document-operations",
        agent="document-review-fixture",
        severity="functional",
        failure_type="other",
        expected_behavior="Expected behavior",
        actual_behavior="Actual behavior",
        control_refs=json.dumps(
            [
                "control:document_ops_redaction_required:g2",
                {
                    "ref_id": "control:document_ops_use_gate:g2",
                    "control_type": "use_gate",
                },
            ]
        ),
    )

    assert "Incident logged:" in result
    saved = next((data_root / "incidents").rglob("*.yml"))
    incident = Incident.from_dict(yaml.safe_load(saved.read_text()))
    assert [ref["ref_id"] for ref in incident.control_refs] == [
        "control:document_ops_redaction_required:g2",
        "control:document_ops_use_gate:g2",
    ]


def test_mcp_log_success_reports_only_id_and_safe_relative_path(
    tmp_path, monkeypatch
):
    data_root = tmp_path / "absolute-[hostile]\x1b-root"
    monkeypatch.setenv("FORGE_DATA_ROOT", str(data_root))

    result = _minimal_mcp_log()

    saved = next((data_root / "incidents").rglob("*.yml"))
    relative = saved.relative_to(data_root / "incidents").as_posix()
    assert f"Incident logged: {saved.stem}" in result
    assert f"Saved to: {relative}" in result
    assert str(data_root) not in result
    assert "\x1b" not in result
    assert "Traceback" not in result


@pytest.mark.parametrize(
    ("failure_scope", "exception_type", "classification"),
    [
        ("root", PermissionError, "PermissionError"),
        ("month", PermissionError, "PermissionError"),
        ("root", OSError, "OSError"),
    ],
)
def test_mcp_log_storage_failures_are_stable_and_do_not_leak_roots(
    tmp_path,
    monkeypatch,
    failure_scope,
    exception_type,
    classification,
):
    data_root = tmp_path / "absolute-[hostile]\x1b-root"
    incidents_dir = data_root / "incidents"
    real_open = __import__(
        "forge_cli.incident_store",
        fromlist=["_open_nofollow"],
    )._open_nofollow
    raw_message = f"raw storage failure at {data_root}\nsecret\x1b"

    def fail_open(path, *, directory=False, dir_fd=None):
        is_root = dir_fd is None and Path(path) == incidents_dir
        is_month = dir_fd is not None and directory
        if (failure_scope == "root" and is_root) or (
            failure_scope == "month" and is_month
        ):
            raise exception_type(raw_message)
        return real_open(path, directory=directory, dir_fd=dir_fd)

    monkeypatch.setattr("forge_cli.incident_store._open_nofollow", fail_open)
    monkeypatch.setenv("FORGE_DATA_ROOT", str(data_root))

    result = _minimal_mcp_log()

    assert result == f"Storage error: {classification}"
    assert raw_message not in result
    assert str(data_root) not in result
    assert "\x1b" not in result
    assert "Traceback" not in result


def test_mcp_log_rejects_symlinked_month_without_root_leakage(
    tmp_path, monkeypatch
):
    data_root = tmp_path / "absolute-[hostile]\x1b-root"
    incidents_dir = data_root / "incidents"
    incidents_dir.mkdir(parents=True)
    external = tmp_path / "external-month"
    external.mkdir()
    month = time.strftime("%Y-%m", time.gmtime())
    (incidents_dir / month).symlink_to(external, target_is_directory=True)
    monkeypatch.setenv("FORGE_DATA_ROOT", str(data_root))

    result = _minimal_mcp_log()

    assert result == "Storage error: UnsafeIncidentPathError"
    assert str(data_root) not in result
    assert "\x1b" not in result
    assert "Traceback" not in result
    assert list(external.iterdir()) == []


def test_mcp_log_preserves_duplicate_classification_without_raw_error(
    tmp_path, monkeypatch
):
    data_root = tmp_path / "absolute-[hostile]\x1b-root"

    def fail_duplicate(*_args, **_kwargs):
        raise DuplicateIncidentError(f"raw duplicate {data_root}\nsecret\x1b")

    monkeypatch.setattr(
        "forge_cli.mcp_server.save_generated_incident",
        fail_duplicate,
    )
    monkeypatch.setenv("FORGE_DATA_ROOT", str(data_root))

    result = _minimal_mcp_log()

    assert result == "Duplicate incident id"
    assert str(data_root) not in result
    assert "\x1b" not in result
    assert "Traceback" not in result
