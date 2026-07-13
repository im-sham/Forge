from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import time
import stat
import tempfile
import yaml
import pytest
from typer.testing import CliRunner

import forge_cli.incident_store as incident_store
from forge_cli.cli import app
from forge_cli.incident_store import DuplicateIncidentError, load_incident, save_incident
from forge_cli.models import Incident


def _file_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file()
    }


def _invoke_minimal_log(data_root: Path):
    return CliRunner().invoke(
        app,
        [
            "log",
            "--project",
            "project",
            "--agent",
            "agent",
            "--platform",
            "platform",
            "--severity",
            "functional",
            "--type",
            "other",
        ],
        input=(
            "Expected behavior\n"
            "Actual behavior\n"
            "\n"
            "\n"
            "\n"
            "\n"
            "\n"
            "y\n"
        ),
        env={"FORGE_DATA_ROOT": str(data_root)},
    )


def _prepare_incomplete_analysis_corpus(
    data_root: Path,
    sample_data: dict,
    failure_kind: str,
    monkeypatch,
) -> None:
    incidents_dir = data_root / "incidents"
    incidents_dir.mkdir(parents=True)
    save_incident(Incident.from_dict(sample_data), incidents_dir)
    candidate = incidents_dir / "2026-03" / "2026-03-04-002.yml"
    if failure_kind == "corrupt":
        candidate.write_text("incident: [unterminated")
        return

    candidate.write_text(
        yaml.safe_dump(
            {
                **sample_data,
                "id": "2026-03-04-002",
                "timestamp": "2026-03-04T15:30:00Z",
            }
        )
    )
    real_open_nofollow = incident_store._open_nofollow

    def fail_candidate_open(path, *, directory=False, dir_fd=None):
        if not directory and Path(path).name == candidate.name:
            raise PermissionError(f"secret root {data_root}")
        return real_open_nofollow(path, directory=directory, dir_fd=dir_fd)

    monkeypatch.setattr(incident_store, "_open_nofollow", fail_candidate_open)


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
            "--control-ref",
            "control:document_ops_redaction_required:g2",
            "--control-ref",
            "control:document_ops_use_gate:g2",
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
    assert "[allocated at save]" in result.output
    assert result.output.index("[allocated at save]") < result.output.index("Save this incident?")
    assert saved.stem in result.output
    incident = Incident.from_dict(yaml.safe_load(saved.read_text()))
    assert incident.capability_area == "governance"
    assert incident.issue_class == "redaction_miss"
    assert incident.workflow_ref["ref_id"] == "workflow:document_ops_regulated_review_v0"
    assert [ref["ref_id"] for ref in incident.control_refs] == [
        "control:document_ops_redaction_required:g2",
        "control:document_ops_use_gate:g2",
    ]
    assert incident.use_approval_ref["ref_id"] == "use-approval:document_ops_internal_eval:g2"


def test_log_success_reports_only_id_and_safe_relative_path(tmp_path):
    data_root = tmp_path / "absolute-[hostile]\x1b-root"

    result = _invoke_minimal_log(data_root)

    saved = next((data_root / "incidents").rglob("*.yml"))
    relative = saved.relative_to(data_root / "incidents").as_posix()
    assert result.exit_code == 0
    assert f"Saved incident {saved.stem}" in result.output
    assert f"Saved: {relative}" in result.output
    assert str(data_root) not in result.output
    assert "\x1b" not in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize(
    ("failure_scope", "exception_type", "classification"),
    [
        ("root", PermissionError, "PermissionError"),
        ("month", PermissionError, "PermissionError"),
        ("root", OSError, "OSError"),
    ],
)
def test_log_storage_failures_are_stable_and_do_not_leak_roots(
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

    result = _invoke_minimal_log(data_root)

    assert result.exit_code == 1
    assert f"Storage error: {classification}" in result.output
    assert raw_message not in result.output
    assert str(data_root) not in result.output
    assert "\x1b" not in result.output
    assert "Traceback" not in result.output


def test_log_rejects_symlinked_month_without_root_leakage(tmp_path):
    data_root = tmp_path / "absolute-[hostile]\x1b-root"
    incidents_dir = data_root / "incidents"
    incidents_dir.mkdir(parents=True)
    external = tmp_path / "external-month"
    external.mkdir()
    month = time.strftime("%Y-%m", time.gmtime())
    (incidents_dir / month).symlink_to(external, target_is_directory=True)

    result = _invoke_minimal_log(data_root)

    assert result.exit_code == 1
    assert "Storage error: UnsafeIncidentPathError" in result.output
    assert str(data_root) not in result.output
    assert "\x1b" not in result.output
    assert "Traceback" not in result.output
    assert list(external.iterdir()) == []


def test_log_preserves_duplicate_classification_without_raw_error(
    tmp_path, monkeypatch
):
    data_root = tmp_path / "absolute-[hostile]\x1b-root"

    def fail_duplicate(*_args, **_kwargs):
        raise DuplicateIncidentError(f"raw duplicate {data_root}\nsecret\x1b")

    monkeypatch.setattr(
        "forge_cli.cli.save_generated_incident",
        fail_duplicate,
    )

    result = _invoke_minimal_log(data_root)

    assert result.exit_code == 1
    assert "Duplicate incident id" in result.output
    assert str(data_root) not in result.output
    assert "\x1b" not in result.output
    assert "Traceback" not in result.output


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


def test_log_command_rejects_sensitive_core_free_text(tmp_path):
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
            "safety_boundary_violation",
        ],
        input=(
            "Expected behavior\n"
            "Actual behavior included source_payload: {\"claim_id\": \"synthetic\"}\n"
            "Context\n"
            "root-cause\n"
            "Immediate fix\n"
            "Systemic takeaway\n"
            "claims\n"
            "y\n"
        ),
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code == 1
    assert "actual_behavior" in result.output
    assert "source_payload" in result.output
    assert not list((data_root / "incidents").rglob("*.yml"))


def test_list_and_stats_report_loaded_and_skipped_corrupt_files(tmp_path, sample_data):
    data_root = tmp_path / "forge-data"
    incidents_dir = data_root / "incidents"
    incidents_dir.mkdir(parents=True)
    save_incident(Incident.from_dict(sample_data), incidents_dir)
    corrupt_path = incidents_dir / "2026-03" / "2026-03-04-002.yml"
    corrupt_payload = "incident: [unterminated"
    corrupt_path.write_text(corrupt_payload)
    runner = CliRunner()
    env = {"FORGE_DATA_ROOT": str(data_root)}

    list_result = runner.invoke(app, ["list"], env=env)
    stats_result = runner.invoke(app, ["stats"], env=env)

    for result in (list_result, stats_result):
        assert result.exit_code == 0
        assert "Valid corpus incidents: 1" in result.output
        assert "Corrupt corpus files: 1" in result.output
        assert "Matched incidents: 1" in result.output
        assert "Returned incidents: 1" in result.output
        assert "2026-03/2026-03-04-002.yml" in result.output
        assert "YAMLError" in result.output
        assert str(data_root) not in result.output
    assert corrupt_path.read_text() == corrupt_payload


def test_validate_strict_exits_nonzero_on_corruption(tmp_path):
    data_root = tmp_path / "forge-data"
    corrupt_path = data_root / "incidents" / "2026-03" / "2026-03-04-001.yml"
    corrupt_path.parent.mkdir(parents=True)
    corrupt_payload = "incident: [unterminated"
    corrupt_path.write_text(corrupt_payload)
    runner = CliRunner()
    env = {"FORGE_DATA_ROOT": str(data_root)}

    lenient_result = runner.invoke(app, ["validate"], env=env)
    strict_result = runner.invoke(app, ["validate", "--strict"], env=env)

    assert lenient_result.exit_code == 0
    assert strict_result.exit_code == 1
    assert "Corrupt corpus files: 1" in strict_result.output
    assert "2026-03/2026-03-04-001.yml" in strict_result.output
    assert str(data_root) not in strict_result.output
    assert corrupt_path.read_text() == corrupt_payload


def test_quarantine_defaults_to_zero_write_dry_run(tmp_path):
    data_root = tmp_path / "forge-data"
    corrupt_path = data_root / "incidents" / "2026-03" / "2026-03-04-001.yml"
    corrupt_path.parent.mkdir(parents=True)
    corrupt_payload = "incident: [unterminated"
    corrupt_path.write_text(corrupt_payload)
    before = {
        path.relative_to(data_root).as_posix(): path.read_bytes()
        for path in data_root.rglob("*")
        if path.is_file()
    }

    result = CliRunner().invoke(
        app,
        ["quarantine"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    after = {
        path.relative_to(data_root).as_posix(): path.read_bytes()
        for path in data_root.rglob("*")
        if path.is_file()
    }
    assert result.exit_code == 0
    assert "Quarantine preview: 1 corrupt file(s)" in result.output
    assert "2026-03/2026-03-04-001.yml" in result.output
    assert after == before


@pytest.mark.parametrize(
    ("command", "marker"),
    [
        ("repair", "Repair dry-run: 2 corrupt file(s)"),
        ("quarantine", "Quarantine dry-run: 2 corrupt file(s)"),
    ],
)
def test_maintenance_dry_run_reports_safe_candidates_without_writes(
    tmp_path, command, marker
):
    data_root = tmp_path / "absolute-[hostile]\x1b-root"
    first = data_root / "incidents" / "2026-03" / "first-[candidate]\x1b.yml"
    second = data_root / "incidents" / "nested" / "second.yml"
    first.parent.mkdir(parents=True)
    second.parent.mkdir(parents=True)
    first.write_bytes(b"incident: [unterminated\x00")
    second.write_bytes(b"\xff\xfe malformed")
    before_hashes = _file_hashes(data_root)
    before_count = len(before_hashes)

    result = CliRunner().invoke(
        app,
        [command, "--dry-run"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    after_hashes = _file_hashes(data_root)
    assert result.exit_code == 0
    assert marker in result.output
    assert "2026-03/first-[candidate]?.yml" in result.output
    assert "nested/second.yml" in result.output
    assert str(data_root) not in result.output
    assert "\x1b" not in result.output
    assert "Traceback" not in result.output
    assert len(after_hashes) == before_count
    assert after_hashes == before_hashes


@pytest.mark.parametrize("command", ["repair"])
def test_maintenance_rejects_apply_and_performs_zero_writes(tmp_path, command):
    data_root = tmp_path / "forge-data"
    corrupt_path = data_root / "incidents" / "2026-03" / "2026-03-04-001.yml"
    corrupt_path.parent.mkdir(parents=True)
    corrupt_payload = b"incident: [unterminated"
    corrupt_path.write_bytes(corrupt_payload)

    result = CliRunner().invoke(
        app,
        [command, "--apply"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code != 0
    assert corrupt_path.read_bytes() == corrupt_payload
    assert not (data_root / "quarantine").exists()


def test_quarantine_rejects_apply_with_dry_run_without_writes(tmp_path):
    data_root = tmp_path / "forge-data"
    corrupt_path = data_root / "incidents" / "2026-03" / "corrupt.yml"
    corrupt_path.parent.mkdir(parents=True)
    corrupt_payload = b"incident: [unterminated"
    corrupt_path.write_bytes(corrupt_payload)

    result = CliRunner().invoke(
        app,
        ["quarantine", "--apply", "--dry-run"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code != 0
    assert corrupt_path.read_bytes() == corrupt_payload
    assert not (data_root / "quarantine").exists()


def test_quarantine_apply_moves_only_freshly_corrupt_regular_files(
    tmp_path, sample_data
):
    data_root = tmp_path / "forge-data"
    incidents_dir = data_root / "incidents"
    incidents_dir.mkdir(parents=True)
    valid = Incident.from_dict(sample_data)
    valid_path = save_incident(valid, incidents_dir)
    corrupt_path = incidents_dir / "nested" / "hostile-[name]\x1b.yml"
    corrupt_path.parent.mkdir()
    corrupt_payload = b"\xff\xfe malformed incident bytes\n"
    corrupt_path.write_bytes(corrupt_payload)

    result = CliRunner().invoke(
        app,
        ["quarantine", "--apply"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    destination = data_root / "quarantine" / "nested" / corrupt_path.name
    assert result.exit_code == 0, result.output
    assert not corrupt_path.exists()
    assert destination.read_bytes() == corrupt_payload
    assert valid_path.exists()
    assert load_incident(valid_path).id == valid.id
    assert "Moved: nested/hostile-[name]?.yml" in result.output
    assert str(data_root) not in result.output
    assert "\x1b" not in result.output
    assert "Traceback" not in result.output


def test_quarantine_apply_fails_closed_before_writes_on_scan_error(
    tmp_path, monkeypatch
):
    data_root = tmp_path / "absolute-[root]\x1b"
    corrupt_path = data_root / "incidents" / "corrupt.yml"
    blocked_path = data_root / "incidents" / "blocked.yml"
    corrupt_path.parent.mkdir(parents=True)
    corrupt_path.write_text("incident: [unterminated")
    blocked_path.write_text("incident: [unterminated")
    real_open = incident_store._open_nofollow
    raw_message = f"blocked at {data_root} [bold]leak[/bold]"

    def fail_one(path, *, directory=False, dir_fd=None):
        if not directory and Path(path).name == blocked_path.name:
            raise PermissionError(raw_message)
        return real_open(path, directory=directory, dir_fd=dir_fd)

    monkeypatch.setattr(incident_store, "_open_nofollow", fail_one)

    result = CliRunner().invoke(
        app,
        ["quarantine", "--apply"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code != 0
    assert corrupt_path.exists()
    assert blocked_path.exists()
    assert not (data_root / "quarantine").exists()
    assert "PermissionError" in result.output
    assert raw_message not in result.output
    assert str(data_root) not in result.output
    assert "[bold]leak[/bold]" not in result.output
    assert "Traceback" not in result.output


def test_quarantine_apply_revalidates_source_after_scan(
    tmp_path, monkeypatch, sample_data
):
    data_root = tmp_path / "forge-data"
    corrupt_path = data_root / "incidents" / "candidate.yml"
    corrupt_path.parent.mkdir(parents=True)
    corrupt_path.write_text("incident: [unterminated")
    real_scan = incident_store.scan_incidents

    def mutate_after_scan(incidents_dir):
        result = real_scan(incidents_dir)
        corrupt_path.write_text(yaml.safe_dump(sample_data))
        return result

    monkeypatch.setattr(incident_store, "scan_incidents", mutate_after_scan)

    result = CliRunner().invoke(
        app,
        ["quarantine", "--apply"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code != 0
    assert load_incident(corrupt_path).id == sample_data["id"]
    assert not (data_root / "quarantine" / "candidate.yml").exists()
    assert "Failed: candidate.yml (SourceChangedError)" in result.output


def test_quarantine_no_replace_collision_at_syscall_preserves_both_files(
    tmp_path, monkeypatch
):
    data_root = tmp_path / "forge-data"
    source = data_root / "incidents" / "nested" / "candidate.yml"
    destination = data_root / "quarantine" / "nested" / "candidate.yml"
    source.parent.mkdir(parents=True)
    source_payload = b"incident: [unterminated"
    destination_payload = b"concurrent quarantine payload"
    source.write_bytes(source_payload)
    real_rename_noreplace = incident_store._rename_noreplace

    def collide_at_syscall(source_fd, source_name, destination_fd, destination_name):
        fd = os.open(
            destination_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=destination_fd,
        )
        try:
            os.write(fd, destination_payload)
        finally:
            os.close(fd)
        return real_rename_noreplace(
            source_fd, source_name, destination_fd, destination_name
        )

    monkeypatch.setattr(
        incident_store, "_rename_noreplace", collide_at_syscall
    )

    result = CliRunner().invoke(
        app,
        ["quarantine", "--apply"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code != 0
    assert source.read_bytes() == source_payload
    assert destination.read_bytes() == destination_payload
    assert "Failed: nested/candidate.yml (FileExistsError)" in result.output


def test_quarantine_apply_rejects_symlinked_destination_directory(tmp_path):
    data_root = tmp_path / "forge-data"
    corrupt_path = data_root / "incidents" / "nested" / "candidate.yml"
    external = tmp_path / "external"
    corrupt_path.parent.mkdir(parents=True)
    external.mkdir()
    corrupt_path.write_text("incident: [unterminated")
    quarantine = data_root / "quarantine"
    quarantine.mkdir()
    (quarantine / "nested").symlink_to(external, target_is_directory=True)

    result = CliRunner().invoke(
        app,
        ["quarantine", "--apply"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code != 0
    assert corrupt_path.exists()
    assert not (external / "candidate.yml").exists()
    assert "UnsafeIncidentPathError" in result.output


def test_quarantine_apply_rejects_symlinked_source_without_writes(tmp_path):
    data_root = tmp_path / "forge-data"
    incidents_dir = data_root / "incidents"
    incidents_dir.mkdir(parents=True)
    external = tmp_path / "external-corrupt.yml"
    payload = b"incident: [unterminated"
    external.write_bytes(payload)
    (incidents_dir / "candidate.yml").symlink_to(external)

    result = CliRunner().invoke(
        app,
        ["quarantine", "--apply"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code != 0
    assert external.read_bytes() == payload
    assert (incidents_dir / "candidate.yml").is_symlink()
    assert not (data_root / "quarantine").exists()
    assert "SymlinkRejectedError" in result.output
    assert str(external) not in result.output
    assert "Traceback" not in result.output


def test_quarantine_internal_move_rejects_traversal_before_writes(tmp_path):
    data_root = tmp_path / "forge-data"
    incidents_dir = data_root / "incidents"
    incidents_dir.mkdir(parents=True)
    outside = data_root / "outside.yml"
    payload = b"incident: [unterminated"
    outside.write_bytes(payload)

    with pytest.raises(incident_store.UnsafeIncidentPathError):
        incident_store._quarantine_one(incidents_dir, "../outside.yml")

    assert outside.read_bytes() == payload
    assert not (data_root / "quarantine").exists()


def test_quarantine_apply_ancestor_fsync_failure_keeps_source(
    tmp_path, monkeypatch
):
    data_root = tmp_path / "absolute-[root]\x1b"
    source = data_root / "incidents" / "candidate.yml"
    source.parent.mkdir(parents=True)
    payload = b"incident: [unterminated"
    source.write_bytes(payload)
    raw_message = f"fsync denied at {data_root} [bold]leak[/bold]"
    real_fsync = incident_store.os.fsync

    def fail_directory_fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise PermissionError(raw_message)
        return real_fsync(fd)

    monkeypatch.setattr(incident_store.os, "fsync", fail_directory_fsync)

    result = CliRunner().invoke(
        app,
        ["quarantine", "--apply"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code != 0
    assert source.read_bytes() == payload
    assert not (data_root / "quarantine" / "candidate.yml").exists()
    assert "Failed: candidate.yml (PermissionError)" in result.output
    assert raw_message not in result.output
    assert str(data_root) not in result.output
    assert "[bold]leak[/bold]" not in result.output
    assert "Traceback" not in result.output


def test_quarantine_apply_reports_safe_failure_after_an_earlier_move(
    tmp_path, monkeypatch
):
    data_root = tmp_path / "absolute-[root]\x1b"
    first = data_root / "incidents" / "a.yml"
    second = data_root / "incidents" / "b.yml"
    first.parent.mkdir(parents=True)
    first.write_bytes(b"first: [unterminated")
    second.write_bytes(b"second: [unterminated")
    real_rename_noreplace = incident_store._rename_noreplace
    raw_message = f"denied {data_root} [bold]leak[/bold]"

    def fail_second(source_fd, source_name, destination_fd, destination_name):
        if source_name == second.name:
            raise PermissionError(raw_message)
        return real_rename_noreplace(
            source_fd, source_name, destination_fd, destination_name
        )

    monkeypatch.setattr(incident_store, "_rename_noreplace", fail_second)

    result = CliRunner().invoke(
        app,
        ["quarantine", "--apply"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code != 0
    assert not first.exists()
    assert (data_root / "quarantine" / "a.yml").read_bytes() == b"first: [unterminated"
    assert second.read_bytes() == b"second: [unterminated"
    assert "Moved: a.yml" in result.output
    assert "Failed: b.yml (PermissionError)" in result.output
    assert raw_message not in result.output
    assert str(data_root) not in result.output
    assert "[bold]leak[/bold]" not in result.output
    assert "Traceback" not in result.output


def test_quarantine_source_replacement_at_syscall_is_restored_without_overwrite(
    tmp_path, monkeypatch
):
    data_root = tmp_path / "absolute-[root]\x1b"
    source = data_root / "incidents" / "candidate.yml"
    source.parent.mkdir(parents=True)
    corrupt_payload = b"incident: [unterminated"
    replacement_payload = b"replacement restored to source\n"
    source.write_bytes(corrupt_payload)
    real_rename_noreplace = incident_store._rename_noreplace
    calls = 0

    def replace_at_syscall(source_fd, source_name, destination_fd, destination_name):
        nonlocal calls
        calls += 1
        if calls == 1:
            os.unlink(source_name, dir_fd=source_fd)
            fd = os.open(
                source_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=source_fd,
            )
            try:
                os.write(fd, replacement_payload)
            finally:
                os.close(fd)
        return real_rename_noreplace(
            source_fd, source_name, destination_fd, destination_name
        )

    monkeypatch.setattr(incident_store, "_rename_noreplace", replace_at_syscall)

    result = CliRunner().invoke(
        app,
        ["quarantine", "--apply"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    destination = data_root / "quarantine" / source.name
    assert result.exit_code != 0
    assert calls == 2
    assert source.read_bytes() == replacement_payload
    assert not destination.exists()
    assert "Failed: candidate.yml (SourceChangedError)" in result.output
    assert str(data_root) not in result.output
    assert "Traceback" not in result.output


def test_quarantine_source_metadata_change_at_syscall_is_restored(
    tmp_path, monkeypatch
):
    data_root = tmp_path / "forge-data"
    source = data_root / "incidents" / "candidate.yml"
    source.parent.mkdir(parents=True)
    payload = b"incident: [unterminated"
    source.write_bytes(payload)
    real_rename_noreplace = incident_store._rename_noreplace
    calls = 0

    def mutate_metadata_at_syscall(
        source_fd, source_name, destination_fd, destination_name
    ):
        nonlocal calls
        calls += 1
        if calls == 1:
            os.chmod(source_name, 0o640, dir_fd=source_fd)
        return real_rename_noreplace(
            source_fd, source_name, destination_fd, destination_name
        )

    monkeypatch.setattr(
        incident_store, "_rename_noreplace", mutate_metadata_at_syscall
    )

    result = CliRunner().invoke(
        app,
        ["quarantine", "--apply"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    destination = data_root / "quarantine" / source.name
    assert result.exit_code != 0
    assert calls == 2
    assert source.read_bytes() == payload
    assert stat.S_IMODE(source.stat().st_mode) == 0o640
    assert not destination.exists()
    assert "Failed: candidate.yml (SourceChangedError)" in result.output


def test_quarantine_restore_collision_leaves_visible_recoverable_entry(
    tmp_path, monkeypatch
):
    data_root = tmp_path / "absolute-[root]\x1b"
    source = data_root / "incidents" / "candidate.yml"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"incident: [unterminated")
    replacement_payload = b"replacement moved at syscall\n"
    concurrent_payload = b"concurrent source entry\n"
    real_rename_noreplace = incident_store._rename_noreplace
    calls = 0

    def collide_during_restore(
        source_fd, source_name, destination_fd, destination_name
    ):
        nonlocal calls
        calls += 1
        if calls == 1:
            os.unlink(source_name, dir_fd=source_fd)
            fd = os.open(
                source_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=source_fd,
            )
            try:
                os.write(fd, replacement_payload)
            finally:
                os.close(fd)
        elif calls == 2:
            fd = os.open(
                destination_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=destination_fd,
            )
            try:
                os.write(fd, concurrent_payload)
            finally:
                os.close(fd)
        return real_rename_noreplace(
            source_fd, source_name, destination_fd, destination_name
        )

    monkeypatch.setattr(incident_store, "_rename_noreplace", collide_during_restore)

    result = CliRunner().invoke(
        app,
        ["quarantine", "--apply"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    destination = data_root / "quarantine" / source.name
    assert result.exit_code != 0
    assert calls == 2
    assert source.read_bytes() == concurrent_payload
    assert destination.read_bytes() == replacement_payload
    assert (
        "Partial move: candidate.yml (RecoverablePartialStateError)"
        in result.output
    )
    assert str(data_root) not in result.output
    assert "Traceback" not in result.output


def test_quarantine_without_native_noreplace_fails_closed_without_writes(
    tmp_path, monkeypatch
):
    data_root = tmp_path / "forge-data"
    source = data_root / "incidents" / "candidate.yml"
    source.parent.mkdir(parents=True)
    payload = b"incident: [unterminated"
    source.write_bytes(payload)
    monkeypatch.setattr(incident_store, "_NATIVE_RENAME_NOREPLACE", None)

    result = CliRunner().invoke(
        app,
        ["quarantine", "--apply"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code != 0
    assert source.read_bytes() == payload
    assert not (data_root / "quarantine").exists()
    assert "Failed: candidate.yml (UnsupportedOperation)" in result.output


@pytest.mark.parametrize(
    "failure_point",
    ["destination-stat", "destination-parent-fsync", "source-parent-fsync"],
)
def test_quarantine_post_move_failures_report_safe_partial_move(
    tmp_path, monkeypatch, failure_point
):
    data_root = tmp_path / "absolute-[root]\x1b"
    source = data_root / "incidents" / "candidate.yml"
    destination = data_root / "quarantine" / source.name
    source.parent.mkdir(parents=True)
    payload = b"incident: [unterminated"
    source.write_bytes(payload)
    real_rename_noreplace = incident_store._rename_noreplace
    real_stat = incident_store.os.stat
    real_fsync = incident_store.os.fsync
    moved = False
    source_parent_fd = None
    destination_parent_fd = None
    raw_message = f"post-move failure at {data_root} [bold]leak[/bold]"

    def record_move(source_fd, source_name, destination_fd, destination_name):
        nonlocal moved, source_parent_fd, destination_parent_fd
        result = real_rename_noreplace(
            source_fd, source_name, destination_fd, destination_name
        )
        moved = True
        source_parent_fd = source_fd
        destination_parent_fd = destination_fd
        return result

    def fail_destination_stat(path, *args, **kwargs):
        if (
            failure_point == "destination-stat"
            and moved
            and path == destination.name
            and kwargs.get("dir_fd") == destination_parent_fd
        ):
            raise PermissionError(raw_message)
        return real_stat(path, *args, **kwargs)

    def fail_parent_fsync(fd):
        if (
            moved
            and failure_point == "destination-parent-fsync"
            and fd == destination_parent_fd
        ):
            raise PermissionError(raw_message)
        if (
            moved
            and failure_point == "source-parent-fsync"
            and fd == source_parent_fd
        ):
            raise PermissionError(raw_message)
        return real_fsync(fd)

    monkeypatch.setattr(incident_store, "_rename_noreplace", record_move)
    monkeypatch.setattr(incident_store.os, "stat", fail_destination_stat)
    monkeypatch.setattr(incident_store.os, "fsync", fail_parent_fsync)

    result = CliRunner().invoke(
        app,
        ["quarantine", "--apply"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code != 0
    assert not source.exists()
    assert destination.read_bytes() == payload
    assert (
        "Partial move: candidate.yml (RecoverablePartialStateError)"
        in result.output
    )
    assert raw_message not in result.output
    assert str(data_root) not in result.output
    assert "[bold]leak[/bold]" not in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize(
    ("failed_restore_fsync", "move_back_collision"),
    [
        ("source", False),
        ("destination", False),
        ("source", True),
    ],
)
def test_quarantine_restore_durability_failure_leaves_safe_partial_state(
    tmp_path, monkeypatch, failed_restore_fsync, move_back_collision
):
    data_root = tmp_path / "absolute-[root]\x1b"
    source = data_root / "incidents" / "candidate.yml"
    destination = data_root / "quarantine" / source.name
    source.parent.mkdir(parents=True)
    source.write_bytes(b"incident: [unterminated")
    replacement_payload = b"replacement moved at syscall\n"
    concurrent_payload = b"concurrent quarantine entry\n"
    real_rename_noreplace = incident_store._rename_noreplace
    real_fsync = incident_store.os.fsync
    calls = 0
    source_parent_fd = None
    destination_parent_fd = None
    restore_started = False
    fsync_failed = False

    def inject_restore_failures(
        source_fd, source_name, destination_fd, destination_name
    ):
        nonlocal calls, source_parent_fd, destination_parent_fd, restore_started
        calls += 1
        if calls == 1:
            source_parent_fd = source_fd
            destination_parent_fd = destination_fd
            os.unlink(source_name, dir_fd=source_fd)
            fd = os.open(
                source_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=source_fd,
            )
            try:
                os.write(fd, replacement_payload)
            finally:
                os.close(fd)
        elif calls == 2:
            restore_started = True
        elif calls == 3 and move_back_collision:
            fd = os.open(
                destination_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=destination_fd,
            )
            try:
                os.write(fd, concurrent_payload)
            finally:
                os.close(fd)
        return real_rename_noreplace(
            source_fd, source_name, destination_fd, destination_name
        )

    def fail_restore_fsync(fd):
        nonlocal fsync_failed
        target_fd = (
            source_parent_fd
            if failed_restore_fsync == "source"
            else destination_parent_fd
        )
        if restore_started and not fsync_failed and fd == target_fd:
            fsync_failed = True
            raise PermissionError("restore durability failure")
        return real_fsync(fd)

    monkeypatch.setattr(
        incident_store, "_rename_noreplace", inject_restore_failures
    )
    monkeypatch.setattr(incident_store.os, "fsync", fail_restore_fsync)

    result = CliRunner().invoke(
        app,
        ["quarantine", "--apply"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code != 0
    assert calls == 3
    assert fsync_failed is True
    assert (
        "Partial move: candidate.yml (RecoverablePartialStateError)"
        in result.output
    )
    if move_back_collision:
        assert source.read_bytes() == replacement_payload
        assert destination.read_bytes() == concurrent_payload
    else:
        assert not source.exists()
        assert destination.read_bytes() == replacement_payload
    assert str(data_root) not in result.output
    assert "Traceback" not in result.output


def test_quarantine_directory_identity_mismatch_prevents_move(
    tmp_path, monkeypatch
):
    data_root = tmp_path / "forge-data"
    source = data_root / "incidents" / "candidate.yml"
    source.parent.mkdir(parents=True)
    payload = b"incident: [unterminated"
    source.write_bytes(payload)
    real_open_nofollow = incident_store._open_nofollow
    real_fstat = incident_store.os.fstat
    quarantine_fd = None
    move_called = False

    def record_quarantine_open(path, *, directory=False, dir_fd=None):
        nonlocal quarantine_fd
        fd = real_open_nofollow(path, directory=directory, dir_fd=dir_fd)
        if path == "quarantine" and directory:
            quarantine_fd = fd
        return fd

    def mismatch_opened_directory(fd):
        metadata = real_fstat(fd)
        if fd == quarantine_fd:
            return type(
                "MismatchedDirectoryMetadata",
                (),
                {"st_dev": metadata.st_dev, "st_ino": metadata.st_ino + 1},
            )()
        return metadata

    def reject_move(*_args, **_kwargs):
        nonlocal move_called
        move_called = True
        raise AssertionError("move must not run")

    monkeypatch.setattr(
        incident_store, "_open_nofollow", record_quarantine_open
    )
    monkeypatch.setattr(incident_store.os, "fstat", mismatch_opened_directory)
    monkeypatch.setattr(incident_store, "_rename_noreplace", reject_move)

    result = CliRunner().invoke(
        app,
        ["quarantine", "--apply"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code != 0
    assert source.read_bytes() == payload
    assert move_called is False
    assert not (data_root / "quarantine" / source.name).exists()
    assert "Failed: candidate.yml (UnsafeIncidentPathError)" in result.output


def test_quarantine_success_leaves_only_visible_destination(tmp_path):
    data_root = tmp_path / "forge-data"
    source = data_root / "incidents" / "nested" / "candidate.yml"
    destination = data_root / "quarantine" / "nested" / "candidate.yml"
    source.parent.mkdir(parents=True)
    payload = b"incident: [unterminated"
    source.write_bytes(payload)

    result = CliRunner().invoke(
        app,
        ["quarantine", "--apply"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code == 0, result.output
    assert not source.exists()
    assert destination.read_bytes() == payload
    quarantine_entries = sorted(
        path.relative_to(data_root / "quarantine").as_posix()
        for path in (data_root / "quarantine").rglob("*")
    )
    assert quarantine_entries == ["nested", "nested/candidate.yml"]
    assert not list((data_root / "quarantine").rglob(".forge-recovery-*"))


def test_quarantine_fsyncs_each_new_ancestor_before_descending(
    tmp_path, monkeypatch
):
    data_root = tmp_path / "forge-data"
    source = data_root / "incidents" / "nested" / "candidate.yml"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"incident: [unterminated")
    real_mkdir = incident_store.os.mkdir
    real_fsync = incident_store.os.fsync
    pending_parent_fds: list[int] = []
    events: list[tuple[str, str | int]] = []

    def record_mkdir(name, mode=0o777, *, dir_fd=None):
        result = real_mkdir(name, mode, dir_fd=dir_fd)
        if dir_fd is not None and name in {"quarantine", "nested"}:
            pending_parent_fds.append(dir_fd)
            events.append(("mkdir", name))
        return result

    def record_fsync(fd):
        if pending_parent_fds and fd == pending_parent_fds[0]:
            pending_parent_fds.pop(0)
            events.append(("fsync-parent", fd))
        return real_fsync(fd)

    monkeypatch.setattr(incident_store.os, "mkdir", record_mkdir)
    monkeypatch.setattr(incident_store.os, "fsync", record_fsync)

    result = CliRunner().invoke(
        app,
        ["quarantine", "--apply"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code == 0, result.output
    assert [event[0] for event in events[:4]] == [
        "mkdir",
        "fsync-parent",
        "mkdir",
        "fsync-parent",
    ]
    assert [event[1] for event in events[::2][:2]] == ["quarantine", "nested"]
    assert pending_parent_fds == []


def test_quarantine_nested_ancestry_fsync_failure_retains_source(
    tmp_path, monkeypatch
):
    data_root = tmp_path / "absolute-[root]\x1b"
    source = data_root / "incidents" / "nested" / "candidate.yml"
    destination = data_root / "quarantine" / "nested" / source.name
    source.parent.mkdir(parents=True)
    payload = b"incident: [unterminated"
    source.write_bytes(payload)
    real_mkdir = incident_store.os.mkdir
    real_fsync = incident_store.os.fsync
    nested_parent_fd: int | None = None
    raw_message = f"fsync denied at {data_root} [bold]leak[/bold]"

    def record_nested_mkdir(name, mode=0o777, *, dir_fd=None):
        nonlocal nested_parent_fd
        result = real_mkdir(name, mode, dir_fd=dir_fd)
        if name == "nested":
            nested_parent_fd = dir_fd
        return result

    def fail_nested_parent_fsync(fd):
        if nested_parent_fd is not None and fd == nested_parent_fd:
            raise PermissionError(raw_message)
        return real_fsync(fd)

    monkeypatch.setattr(incident_store.os, "mkdir", record_nested_mkdir)
    monkeypatch.setattr(incident_store.os, "fsync", fail_nested_parent_fsync)

    result = CliRunner().invoke(
        app,
        ["quarantine", "--apply"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code != 0
    assert source.read_bytes() == payload
    assert not destination.exists()
    assert "Failed: nested/candidate.yml (PermissionError)" in result.output
    assert raw_message not in result.output
    assert str(data_root) not in result.output
    assert "Traceback" not in result.output


def test_list_zero_limit_reports_counts_without_incidents(tmp_path, sample_data):
    data_root = tmp_path / "forge-data"
    incidents_dir = data_root / "incidents"
    incidents_dir.mkdir(parents=True)
    save_incident(Incident.from_dict(sample_data), incidents_dir)

    result = CliRunner().invoke(
        app,
        ["list", "--limit", "0"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code == 0
    assert "Valid corpus incidents: 1" in result.output
    assert "Matched incidents: 1" in result.output
    assert "Returned incidents: 0" in result.output
    assert sample_data["id"] not in result.output


def test_list_rejects_negative_limit(tmp_path):
    result = CliRunner().invoke(
        app,
        ["list", "--limit", "-1"],
        env={"FORGE_DATA_ROOT": str(tmp_path / "forge-data")},
    )

    assert result.exit_code != 0
    assert "limit must be non-negative" in result.output


def test_list_exits_nonzero_with_sanitized_scan_failure(
    tmp_path, monkeypatch
):
    data_root = tmp_path / "forge-data"
    corrupt_path = data_root / "incidents" / "2026-03" / "unsafe\nincident.yml"
    corrupt_path.parent.mkdir(parents=True)
    corrupt_path.write_text("incident: [unterminated")
    safe_corrupt = corrupt_path.with_name("corrupt.yml")
    safe_corrupt.write_text("incident: [unterminated")
    raw_message = f"raw traversal failure at {data_root}\nwith payload"

    real_stat = os.stat

    def fail_stat(path, *args, **kwargs):
        if path == corrupt_path.name:
            error = PermissionError(raw_message)
            error.filename = str(data_root / "incidents" / "unsafe\nroot")
            raise error
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr("forge_cli.incident_store.os.stat", fail_stat)

    result = CliRunner().invoke(
        app,
        ["list"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code == 1
    assert "Corrupt corpus files: 1" in result.output
    assert "Scan operational errors: 1" in result.output
    assert "PermissionError" in result.output
    assert "YAMLError" in result.output
    assert raw_message not in result.output
    assert str(data_root) not in result.output
    assert "\nroot" not in result.output
    assert "\nincident" not in result.output


@pytest.mark.parametrize(
    ("incident_id", "literal"),
    [
        ("[unterminated", "[unterminated"),
        ("[bold]markup[/bold]", "[bold]markup[/bold]"),
        ("\x1b[31mcontrol", "?[31mcontrol"),
    ],
)
def test_cli_errors_render_untrusted_ids_literally_without_controls(
    tmp_path, incident_id, literal
):
    data_root = tmp_path / "forge-data"

    result = CliRunner().invoke(
        app,
        ["show", incident_id],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code == 1
    assert literal in result.output
    assert "\x1b" not in result.output
    assert "Traceback" not in result.output


def test_cli_ambiguous_lookup_renders_markup_filenames_literally(
    tmp_path, sample_data
):
    data_root = tmp_path / "forge-data"
    incidents_dir = data_root / "incidents"
    first = Incident.from_dict(sample_data)
    second = Incident.from_dict(
        {
            **sample_data,
            "id": "2026-03-05-001",
            "timestamp": "2026-03-05T14:30:00Z",
        }
    )
    first_path = save_incident(first, incidents_dir)
    second_path = save_incident(second, incidents_dir)
    first_path.rename(first_path.with_name("first-[bold].yml"))
    second_path.rename(second_path.with_name("second-[bold].yml"))

    result = CliRunner().invoke(
        app,
        ["show", "[bold]"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code == 1
    assert "first-[bold]" in result.output
    assert "second-[bold]" in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize("command", ["show", "ref", "edit"])
@pytest.mark.parametrize("lookup", ["2026-03-04-001", "001"])
def test_cli_lookup_commands_cannot_follow_corpus_symlinks(
    tmp_path, sample_data, command, lookup
):
    data_root = tmp_path / "forge-data"
    incidents_dir = data_root / "incidents"
    external = tmp_path / "external"
    external_file = save_incident(Incident.from_dict(sample_data), external)
    month_dir = incidents_dir / "2026-03"
    month_dir.mkdir(parents=True)
    (month_dir / external_file.name).symlink_to(external_file)
    before = external_file.read_bytes()

    result = CliRunner().invoke(
        app,
        [command, lookup],
        env={
            "FORGE_DATA_ROOT": str(data_root),
            "EDITOR": "/usr/bin/false",
        },
    )

    assert result.exit_code == 1
    assert "operationally incomplete" in result.output
    assert external_file.read_bytes() == before
    assert "Traceback" not in result.output


@pytest.mark.parametrize("command", [["list"], ["stats"], ["validate", "--strict"]])
def test_cli_missing_incidents_directory_is_empty_and_read_only(tmp_path, command):
    data_root = tmp_path / "forge-data"
    incidents_dir = data_root / "incidents"

    result = CliRunner().invoke(
        app,
        command,
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code == 0
    assert "Valid corpus incidents: 0" in result.output
    assert "Corrupt corpus files: 0" in result.output
    assert not incidents_dir.exists()


def _editor_helper(tmp_path: Path, name: str, body: str) -> Path:
    editor = tmp_path / name
    editor.write_text(f"#!{sys.executable}\nimport os\nimport pathlib\nimport sys\nimport time\n{body}\n")
    editor.chmod(0o700)
    return editor


def _edit_fixture(tmp_path: Path, sample_data: dict) -> tuple[Path, Path, bytes]:
    data_root = tmp_path / "forge-data"
    incidents_dir = data_root / "incidents"
    saved = save_incident(Incident.from_dict(sample_data), incidents_dir)
    return data_root, saved, saved.read_bytes()


def _edited_payload(sample_data: dict) -> str:
    return yaml.safe_dump({**sample_data, "actual_behavior": "edited safely"})


def test_edit_uses_normal_stage_for_in_place_editor(tmp_path, sample_data):
    data_root, saved, original = _edit_fixture(tmp_path, sample_data)
    payload = _edited_payload(sample_data)
    editor = _editor_helper(
        tmp_path,
        "in-place-editor",
        f"path = pathlib.Path(sys.argv[1])\n"
        f"assert path.is_file()\n"
        f"assert not str(path).startswith('/dev/fd/')\n"
        f"path.write_text({payload!r})",
    )

    result = CliRunner().invoke(
        app,
        ["edit", sample_data["id"]],
        env={"FORGE_DATA_ROOT": str(data_root), "EDITOR": str(editor)},
    )

    assert result.exit_code == 0
    assert saved.read_bytes() != original
    assert load_incident(saved).actual_behavior == "edited safely"
    assert "/dev/fd/" not in result.output


def test_edit_accepts_atomic_save_editor(tmp_path, sample_data):
    data_root, saved, _original = _edit_fixture(tmp_path, sample_data)
    payload = _edited_payload(sample_data)
    editor = _editor_helper(
        tmp_path,
        "atomic-editor",
        f"path = pathlib.Path(sys.argv[1])\n"
        f"replacement = path.with_suffix('.new')\n"
        f"replacement.write_text({payload!r})\n"
        f"os.replace(replacement, path)",
    )

    result = CliRunner().invoke(
        app,
        ["edit", sample_data["id"]],
        env={"FORGE_DATA_ROOT": str(data_root), "EDITOR": str(editor)},
    )

    assert result.exit_code == 0
    assert load_incident(saved).actual_behavior == "edited safely"


@pytest.mark.parametrize(
    ("name", "body", "expected"),
    [
        (
            "failing-editor",
            "pathlib.Path(sys.argv[1]).write_text('changed stage')\nsys.exit(7)",
            "Editor exited with an error.",
        ),
        (
            "invalid-editor",
            "pathlib.Path(sys.argv[1]).write_text('incident: [unterminated')",
            "Edited file has invalid YAML.",
        ),
    ],
)
def test_edit_failure_or_invalid_stage_preserves_product_bytes(
    tmp_path, sample_data, name, body, expected, monkeypatch
):
    stage_root = tmp_path / "stages"
    stage_root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(stage_root))
    data_root, saved, original = _edit_fixture(tmp_path, sample_data)
    editor = _editor_helper(tmp_path, name, body)

    result = CliRunner().invoke(
        app,
        ["edit", sample_data["id"]],
        env={"FORGE_DATA_ROOT": str(data_root), "EDITOR": str(editor)},
    )

    assert result.exit_code == 1
    assert expected in result.output
    assert saved.read_bytes() == original
    assert "Traceback" not in result.output
    assert str(data_root) not in result.output
    assert list(stage_root.iterdir()) == []


@pytest.mark.parametrize(
    "failure_point",
    [
        "root-reopen",
        "parent-reopen",
        "stage-create",
        "stage-validation-open",
        "publication-create",
        "publication-write",
        "file-fsync",
        "replace",
        "directory-fsync",
        "directory-fsync-after-replace",
        "cleanup",
    ],
)
def test_edit_operational_storage_errors_are_sanitized_and_preserve_original(
    tmp_path, sample_data, monkeypatch, failure_point
):
    stage_root = tmp_path / "stages"
    stage_root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(stage_root))
    data_root = tmp_path / "absolute-[root]\x1b"
    incidents_dir = data_root / "incidents"
    saved = save_incident(Incident.from_dict(sample_data), incidents_dir)
    original = saved.read_bytes()
    payload = _edited_payload(sample_data)
    editor = _editor_helper(
        tmp_path,
        "storage-error-editor",
        f"pathlib.Path(sys.argv[1]).write_text({payload!r})",
    )
    raw_primary = f"primary failure at {data_root} [bold]leak[/bold]"
    raw_cleanup = f"cleanup failure at {data_root} [italic]leak[/italic]"
    expected_type = "PermissionError"

    if failure_point == "root-reopen":
        real_open_nofollow = incident_store._open_nofollow
        root_opens = 0

        def fail_root_reopen(path, *, directory=False, dir_fd=None):
            nonlocal root_opens
            if directory and Path(path) == incidents_dir and dir_fd is None:
                root_opens += 1
                if root_opens == 2:
                    raise PermissionError(raw_primary)
            return real_open_nofollow(path, directory=directory, dir_fd=dir_fd)

        monkeypatch.setattr(incident_store, "_open_nofollow", fail_root_reopen)
    elif failure_point == "parent-reopen":
        monkeypatch.setattr(
            incident_store,
            "_open_incident_parent",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                PermissionError(raw_primary)
            ),
        )
    elif failure_point == "stage-create":
        monkeypatch.setattr(
            incident_store,
            "_create_stage",
            lambda _original: (_ for _ in ()).throw(PermissionError(raw_primary)),
        )
    elif failure_point == "stage-validation-open":
        real_open_nofollow = incident_store._open_nofollow

        def fail_stage_validation_open(path, *, directory=False, dir_fd=None):
            if (
                not directory
                and dir_fd is None
                and Path(path).name == "incident.yml"
                and stage_root in Path(path).parents
            ):
                raise PermissionError(raw_primary)
            return real_open_nofollow(path, directory=directory, dir_fd=dir_fd)

        monkeypatch.setattr(
            incident_store, "_open_nofollow", fail_stage_validation_open
        )
    elif failure_point == "publication-create":
        real_open = incident_store.os.open

        def fail_publication_open(path, flags, *args, **kwargs):
            if isinstance(path, str) and path.startswith(f".{saved.name}."):
                raise PermissionError(raw_primary)
            return real_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(incident_store.os, "open", fail_publication_open)
    elif failure_point in {"publication-write", "cleanup"}:
        monkeypatch.setattr(
            incident_store,
            "_write_all",
            lambda *_args: (_ for _ in ()).throw(PermissionError(raw_primary)),
        )
        if failure_point == "cleanup":
            real_unlink = incident_store.os.unlink

            def fail_publication_cleanup(path, *args, **kwargs):
                if isinstance(path, str) and path.startswith(f".{saved.name}."):
                    raise OSError(raw_cleanup)
                return real_unlink(path, *args, **kwargs)

            monkeypatch.setattr(
                incident_store.os, "unlink", fail_publication_cleanup
            )
    elif failure_point == "file-fsync":
        real_fsync = incident_store.os.fsync
        file_fsyncs = 0

        def fail_publication_file_fsync(fd):
            nonlocal file_fsyncs
            if stat.S_ISREG(os.fstat(fd).st_mode):
                file_fsyncs += 1
                if file_fsyncs == 2:
                    raise PermissionError(raw_primary)
            return real_fsync(fd)

        monkeypatch.setattr(incident_store.os, "fsync", fail_publication_file_fsync)
    elif failure_point == "replace":
        monkeypatch.setattr(
            incident_store.os,
            "replace",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                PermissionError(raw_primary)
            ),
        )
    elif failure_point in {"directory-fsync", "directory-fsync-after-replace"}:
        real_fsync = incident_store.os.fsync
        directory_fsyncs = 0

        def fail_directory_fsync(fd):
            nonlocal directory_fsyncs
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                directory_fsyncs += 1
                target_call = (
                    2 if failure_point == "directory-fsync-after-replace" else 1
                )
                if directory_fsyncs == target_call:
                    raise PermissionError(raw_primary)
            return real_fsync(fd)

        monkeypatch.setattr(incident_store.os, "fsync", fail_directory_fsync)

    result = CliRunner().invoke(
        app,
        ["edit", sample_data["id"]],
        env={"FORGE_DATA_ROOT": str(data_root), "EDITOR": str(editor)},
    )

    assert result.exit_code == 1
    assert f"Storage error: {expected_type}" in result.output
    if failure_point in {"cleanup", "directory-fsync"}:
        assert (
            "Recoverable partial state: RecoverablePartialStateError"
            in result.output
        )
    assert saved.read_bytes() == original
    assert raw_primary not in result.output
    assert raw_cleanup not in result.output
    assert str(data_root) not in result.output
    assert "[bold]leak[/bold]" not in result.output
    assert "[italic]leak[/italic]" not in result.output
    assert "Traceback" not in result.output
    publication_temps = list(saved.parent.glob(f".{saved.name}.*.tmp"))
    if failure_point == "cleanup":
        assert len(publication_temps) == 1
    else:
        assert publication_temps == []
    backups = list(saved.parent.glob(f".{saved.name}.*.bak"))
    if failure_point == "directory-fsync":
        assert len(backups) == 1
        assert backups[0].read_bytes() == original
    else:
        assert backups == []
    assert list(stage_root.iterdir()) == []


@pytest.mark.parametrize("cleanup_kind", ["stage", "directory-fd"])
@pytest.mark.parametrize("primary_fails", [False, True])
def test_edit_session_cleanup_failure_composes_with_primary_storage_error(
    tmp_path, sample_data, monkeypatch, cleanup_kind, primary_fails
):
    data_root, saved, original = _edit_fixture(tmp_path, sample_data)
    editor = _editor_helper(
        tmp_path,
        "session-cleanup-failure-editor",
        f"pathlib.Path(sys.argv[1]).write_text({_edited_payload(sample_data)!r})",
    )
    raw_primary = f"primary failure at {data_root} [bold]primary[/bold]"
    raw_cleanup = f"cleanup failure at {data_root} [italic]cleanup[/italic]"

    if primary_fails:
        monkeypatch.setattr(
            incident_store,
            "_write_all",
            lambda *_args: (_ for _ in ()).throw(PermissionError(raw_primary)),
        )

    if cleanup_kind == "stage":
        real_cleanup = tempfile.TemporaryDirectory.cleanup

        def cleanup_then_fail(stage_dir):
            real_cleanup(stage_dir)
            raise PermissionError(raw_cleanup)

        monkeypatch.setattr(
            tempfile.TemporaryDirectory, "cleanup", cleanup_then_fail
        )
    else:
        real_open_parent = incident_store._open_incident_parent
        real_close = incident_store.os.close
        session_directory_fd = None

        def record_session_directory(*args, **kwargs):
            nonlocal session_directory_fd
            result = real_open_parent(*args, **kwargs)
            session_directory_fd = result[0]
            return result

        def close_then_fail(fd):
            if fd == session_directory_fd:
                real_close(fd)
                raise PermissionError(raw_cleanup)
            return real_close(fd)

        monkeypatch.setattr(
            incident_store, "_open_incident_parent", record_session_directory
        )
        monkeypatch.setattr(incident_store.os, "close", close_then_fail)

    result = CliRunner().invoke(
        app,
        ["edit", sample_data["id"]],
        env={"FORGE_DATA_ROOT": str(data_root), "EDITOR": str(editor)},
    )

    assert result.exit_code == 1
    assert "Storage error: PermissionError" in result.output
    assert "Recoverable partial state: RecoverablePartialStateError" in result.output
    if primary_fails:
        assert saved.read_bytes() == original
    else:
        assert load_incident(saved).actual_behavior == "edited safely"
    assert raw_primary not in result.output
    assert raw_cleanup not in result.output
    assert str(data_root) not in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize("cleanup_failure", ["unlink", "fsync"])
def test_edit_replace_and_backup_cleanup_failure_preserves_primary_and_recovery(
    tmp_path, sample_data, monkeypatch, cleanup_failure
):
    data_root = tmp_path / "absolute-[root]\x1b"
    incidents_dir = data_root / "incidents"
    saved = save_incident(Incident.from_dict(sample_data), incidents_dir)
    original = saved.read_bytes()
    editor = _editor_helper(
        tmp_path,
        "combined-publication-failure-editor",
        f"pathlib.Path(sys.argv[1]).write_text({_edited_payload(sample_data)!r})",
    )
    real_replace = incident_store.os.replace
    real_unlink = incident_store.os.unlink
    real_fsync = incident_store.os.fsync
    directory_fsyncs = 0
    primary_message = f"publication failed at {data_root} [bold]primary[/bold]"
    cleanup_message = f"cleanup failed at {data_root} [italic]cleanup[/italic]"

    def fail_publication_replace(source, destination, *args, **kwargs):
        if isinstance(source, str) and source.endswith(".tmp"):
            raise PermissionError(primary_message)
        return real_replace(source, destination, *args, **kwargs)

    def fail_backup_cleanup(path, *args, **kwargs):
        if (
            cleanup_failure == "unlink"
            and isinstance(path, str)
            and path.endswith(".bak")
        ):
            raise OSError(cleanup_message)
        return real_unlink(path, *args, **kwargs)

    def fail_backup_cleanup_fsync(fd):
        nonlocal directory_fsyncs
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            directory_fsyncs += 1
            if cleanup_failure == "fsync" and directory_fsyncs == 2:
                raise OSError(cleanup_message)
        return real_fsync(fd)

    monkeypatch.setattr(incident_store.os, "replace", fail_publication_replace)
    monkeypatch.setattr(incident_store.os, "unlink", fail_backup_cleanup)
    monkeypatch.setattr(incident_store.os, "fsync", fail_backup_cleanup_fsync)

    result = CliRunner().invoke(
        app,
        ["edit", sample_data["id"]],
        env={"FORGE_DATA_ROOT": str(data_root), "EDITOR": str(editor)},
    )

    assert result.exit_code == 1
    assert "Storage error: PermissionError" in result.output
    assert "Recoverable partial state: RecoverablePartialStateError" in result.output
    assert saved.read_bytes() == original
    backups = list(saved.parent.glob(f".{saved.name}.*.bak"))
    assert len(backups) == 1
    assert backups[0].read_bytes() == original
    assert primary_message not in result.output
    assert cleanup_message not in result.output
    assert str(data_root) not in result.output
    assert "[bold]primary[/bold]" not in result.output
    assert "[italic]cleanup[/italic]" not in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_edit_rollback_replace_failure_preserves_original_recovery_link(
    tmp_path, sample_data, monkeypatch, cleanup_fails
):
    data_root = tmp_path / "absolute-[root]\x1b"
    incidents_dir = data_root / "incidents"
    saved = save_incident(Incident.from_dict(sample_data), incidents_dir)
    original = saved.read_bytes()
    editor = _editor_helper(
        tmp_path,
        "rollback-failure-editor",
        f"pathlib.Path(sys.argv[1]).write_text({_edited_payload(sample_data)!r})",
    )
    real_fsync = incident_store.os.fsync
    real_replace = incident_store.os.replace
    real_unlink = incident_store.os.unlink
    directory_fsyncs = 0
    replaces = 0
    raw_publication = f"publication fsync failed at {data_root} [bold]leak[/bold]"
    raw_rollback = f"rollback failed at {data_root} [italic]leak[/italic]"
    raw_cleanup = f"cleanup failed at {data_root} [underline]leak[/underline]"

    def fail_publication_directory_fsync(fd):
        nonlocal directory_fsyncs
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            directory_fsyncs += 1
            if directory_fsyncs == 2:
                raise PermissionError(raw_publication)
        return real_fsync(fd)

    def fail_rollback_replace(src, dst, *args, **kwargs):
        nonlocal replaces
        replaces += 1
        if replaces == 2:
            raise OSError(raw_rollback)
        return real_replace(src, dst, *args, **kwargs)

    def maybe_fail_backup_cleanup(path, *args, **kwargs):
        if cleanup_fails and isinstance(path, str) and path.endswith(".bak"):
            raise OSError(raw_cleanup)
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(incident_store.os, "fsync", fail_publication_directory_fsync)
    monkeypatch.setattr(incident_store.os, "replace", fail_rollback_replace)
    monkeypatch.setattr(incident_store.os, "unlink", maybe_fail_backup_cleanup)

    result = CliRunner().invoke(
        app,
        ["edit", sample_data["id"]],
        env={"FORGE_DATA_ROOT": str(data_root), "EDITOR": str(editor)},
    )

    backups = list(saved.parent.glob(f".{saved.name}.*.bak"))
    assert result.exit_code != 0
    assert len(backups) == 1
    assert backups[0].read_bytes() == original
    assert "Storage error: PermissionError" in result.output
    assert "Recoverable partial state: RecoverablePartialStateError" in result.output
    assert raw_publication not in result.output
    assert raw_rollback not in result.output
    assert raw_cleanup not in result.output
    assert str(data_root) not in result.output
    assert "Traceback" not in result.output


def test_edit_backup_unlink_failure_reports_recoverable_partial_state(
    tmp_path, sample_data, monkeypatch
):
    data_root = tmp_path / "absolute-[root]\x1b"
    incidents_dir = data_root / "incidents"
    saved = save_incident(Incident.from_dict(sample_data), incidents_dir)
    original = saved.read_bytes()
    editor = _editor_helper(
        tmp_path,
        "backup-unlink-failure-editor",
        f"pathlib.Path(sys.argv[1]).write_text({_edited_payload(sample_data)!r})",
    )
    real_unlink = incident_store.os.unlink
    raw_message = f"backup unlink failed at {data_root} [bold]leak[/bold]"

    def fail_backup_unlink(path, *args, **kwargs):
        if isinstance(path, str) and path.endswith(".bak"):
            raise PermissionError(raw_message)
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(incident_store.os, "unlink", fail_backup_unlink)

    result = CliRunner().invoke(
        app,
        ["edit", sample_data["id"]],
        env={"FORGE_DATA_ROOT": str(data_root), "EDITOR": str(editor)},
    )

    backups = list(saved.parent.glob(f".{saved.name}.*.bak"))
    assert result.exit_code != 0
    assert load_incident(saved).actual_behavior == "edited safely"
    assert len(backups) == 1
    assert backups[0].read_bytes() == original
    assert "Storage error: PermissionError" in result.output
    assert "Recoverable partial state: RecoverablePartialStateError" in result.output
    assert raw_message not in result.output
    assert str(data_root) not in result.output
    assert "Traceback" not in result.output


def test_edit_backup_unlink_directory_fsync_failure_reports_partial_state(
    tmp_path, sample_data, monkeypatch
):
    data_root = tmp_path / "absolute-[root]\x1b"
    incidents_dir = data_root / "incidents"
    saved = save_incident(Incident.from_dict(sample_data), incidents_dir)
    editor = _editor_helper(
        tmp_path,
        "backup-fsync-failure-editor",
        f"pathlib.Path(sys.argv[1]).write_text({_edited_payload(sample_data)!r})",
    )
    real_fsync = incident_store.os.fsync
    directory_fsyncs = 0
    raw_message = f"backup cleanup fsync failed at {data_root} [bold]leak[/bold]"

    def fail_backup_cleanup_fsync(fd):
        nonlocal directory_fsyncs
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            directory_fsyncs += 1
            if directory_fsyncs == 3:
                raise PermissionError(raw_message)
        return real_fsync(fd)

    monkeypatch.setattr(incident_store.os, "fsync", fail_backup_cleanup_fsync)

    result = CliRunner().invoke(
        app,
        ["edit", sample_data["id"]],
        env={"FORGE_DATA_ROOT": str(data_root), "EDITOR": str(editor)},
    )

    assert result.exit_code != 0
    assert load_incident(saved).actual_behavior == "edited safely"
    assert not list(saved.parent.glob(f".{saved.name}.*.bak"))
    assert "Storage error: PermissionError" in result.output
    assert "Recoverable partial state: RecoverablePartialStateError" in result.output
    assert raw_message not in result.output
    assert str(data_root) not in result.output
    assert "Traceback" not in result.output


def test_edit_early_return_descendant_can_only_modify_stage(tmp_path, sample_data):
    data_root, saved, original = _edit_fixture(tmp_path, sample_data)
    editor = _editor_helper(
        tmp_path,
        "early-return-editor",
        "path = sys.argv[1]\n"
        "if os.fork() == 0:\n"
        "    time.sleep(0.3)\n"
        "    pathlib.Path(path).write_text('late descendant write')\n"
        "    os._exit(0)",
    )

    result = CliRunner().invoke(
        app,
        ["edit", sample_data["id"]],
        env={"FORGE_DATA_ROOT": str(data_root), "EDITOR": str(editor)},
    )
    time.sleep(0.5)

    assert result.exit_code == 0
    assert saved.read_bytes() == original


def test_edit_rejects_target_replacement_conflict(tmp_path, sample_data):
    data_root, saved, original = _edit_fixture(tmp_path, sample_data)
    replacement = b"external replacement\n"
    payload = _edited_payload(sample_data)
    editor = _editor_helper(
        tmp_path,
        "replacement-editor",
        f"target = pathlib.Path(os.environ['FORGE_TEST_TARGET'])\n"
        f"other = target.with_suffix('.replacement')\n"
        f"other.write_bytes({replacement!r})\n"
        f"os.replace(other, target)\n"
        f"pathlib.Path(sys.argv[1]).write_text({payload!r})",
    )

    result = CliRunner().invoke(
        app,
        ["edit", sample_data["id"]],
        env={
            "FORGE_DATA_ROOT": str(data_root),
            "EDITOR": str(editor),
            "FORGE_TEST_TARGET": str(saved),
        },
    )

    assert result.exit_code == 1
    assert "changed while the editor was open" in result.output
    assert saved.read_bytes() == replacement
    assert saved.read_bytes() != original


def test_edit_rejects_symlink_replacement_without_touching_external(
    tmp_path, sample_data
):
    data_root, saved, _original = _edit_fixture(tmp_path, sample_data)
    external = tmp_path / "external.yml"
    external.write_bytes(b"external remains unchanged\n")
    before = external.read_bytes()
    editor = _editor_helper(
        tmp_path,
        "symlink-editor",
        "target = pathlib.Path(os.environ['FORGE_TEST_TARGET'])\n"
        "target.unlink()\n"
        "target.symlink_to(pathlib.Path(os.environ['FORGE_TEST_EXTERNAL']))",
    )

    result = CliRunner().invoke(
        app,
        ["edit", sample_data["id"]],
        env={
            "FORGE_DATA_ROOT": str(data_root),
            "EDITOR": str(editor),
            "FORGE_TEST_TARGET": str(saved),
            "FORGE_TEST_EXTERNAL": str(external),
        },
    )

    assert result.exit_code == 1
    assert "Cannot safely edit incident" in result.output
    assert saved.is_symlink()
    assert external.read_bytes() == before


def test_edit_breaks_existing_hard_links(tmp_path, sample_data):
    data_root, saved, original = _edit_fixture(tmp_path, sample_data)
    linked = tmp_path / "external-hard-link.yml"
    os.link(saved, linked)
    payload = _edited_payload(sample_data)
    editor = _editor_helper(
        tmp_path,
        "hard-link-editor",
        f"pathlib.Path(sys.argv[1]).write_text({payload!r})",
    )

    result = CliRunner().invoke(
        app,
        ["edit", sample_data["id"]],
        env={"FORGE_DATA_ROOT": str(data_root), "EDITOR": str(editor)},
    )

    assert result.exit_code == 0
    assert linked.read_bytes() == original
    assert saved.read_bytes() != original
    assert os.stat(saved).st_ino != os.stat(linked).st_ino


@pytest.mark.parametrize("command", ["show", "ref", "edit"])
@pytest.mark.parametrize("lookup", ["2026-03-04-001", "001"])
def test_cli_lookup_reports_corrupt_requested_candidate(
    tmp_path, command, lookup
):
    data_root = tmp_path / "forge-data"
    candidate = data_root / "incidents" / "2026-03" / "2026-03-04-001.yml"
    candidate.parent.mkdir(parents=True)
    candidate.write_text("incident: [unterminated")

    result = CliRunner().invoke(
        app,
        [command, lookup],
        env={"FORGE_DATA_ROOT": str(data_root), "EDITOR": "/usr/bin/false"},
    )

    assert result.exit_code == 1
    assert "Requested incident candidate is corrupt" in result.output
    assert "No incident found" not in result.output
    assert str(data_root) not in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize("command", ["show", "ref", "edit"])
@pytest.mark.parametrize("lookup", ["2026-03-04-001", "001"])
def test_cli_lookup_prioritizes_matching_corrupt_over_valid_candidate(
    tmp_path, sample_data, command, lookup
):
    data_root = tmp_path / "hostile-[root]\x1b"
    incidents_dir = data_root / "incidents"
    valid = save_incident(Incident.from_dict(sample_data), incidents_dir)
    corrupt = incidents_dir / "duplicate" / valid.name
    corrupt.parent.mkdir()
    corrupt.write_text("incident: [unterminated")

    result = CliRunner().invoke(
        app,
        [command, lookup],
        env={"FORGE_DATA_ROOT": str(data_root), "EDITOR": "/usr/bin/false"},
    )

    assert result.exit_code == 1
    assert "Requested incident candidate is corrupt" in result.output
    assert "duplicate/2026-03-04-001.yml" in result.output
    assert str(data_root) not in result.output
    assert "\x1b" not in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize("command", ["show", "ref", "edit"])
@pytest.mark.parametrize("lookup", ["2026-03-04-001", "001"])
def test_cli_lookup_prioritizes_scan_error_over_matching_corruption_and_fallback(
    tmp_path, sample_data, command, lookup
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

    result = CliRunner().invoke(
        app,
        [command, lookup],
        env={"FORGE_DATA_ROOT": str(data_root), "EDITOR": "/usr/bin/false"},
    )

    assert result.exit_code == 1
    assert "operationally incomplete" in result.output
    assert "unrelated:" in result.output
    assert "SymlinkRejectedError" in result.output
    assert "Requested incident candidate is corrupt" not in result.output
    assert "No incident found" not in result.output
    assert "duplicate/2026-03-04-001.yml" not in result.output
    assert str(data_root) not in result.output
    assert "\x1b" not in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize("command", ["show", "ref", "edit"])
def test_cli_lookup_valid_exact_ignores_corrupt_suffix_candidate(
    tmp_path, sample_data, command
):
    data_root = tmp_path / "hostile-[root]\x1b"
    incidents_dir = data_root / "incidents"
    valid = save_incident(Incident.from_dict(sample_data), incidents_dir)
    corrupt_suffix = incidents_dir / "suffix" / f"prefix-{valid.name}"
    corrupt_suffix.parent.mkdir()
    corrupt_suffix.write_text("incident: [unterminated")

    result = CliRunner().invoke(
        app,
        [command, valid.stem],
        env={"FORGE_DATA_ROOT": str(data_root), "EDITOR": "/usr/bin/true"},
    )

    assert result.exit_code == 0
    assert sample_data["id"] in result.output
    assert "Requested incident candidate is corrupt" not in result.output
    assert f"prefix-{valid.name}" not in result.output
    assert str(data_root) not in result.output
    assert "\x1b" not in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize("command", ["show", "ref", "edit"])
@pytest.mark.parametrize("lookup", ["2026-03-04-001", "001"])
def test_cli_lookup_prioritizes_inaccessible_nested_directory_over_valid_candidate(
    tmp_path, sample_data, monkeypatch, command, lookup
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
    result = CliRunner().invoke(
        app,
        [command, lookup],
        env={"FORGE_DATA_ROOT": str(data_root), "EDITOR": "/usr/bin/false"},
    )

    assert result.exit_code == 1
    assert "operationally incomplete" in result.output
    assert "nested: PermissionError" in result.output
    assert str(data_root) not in result.output
    assert "\x1b" not in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize("command", ["show", "ref", "edit"])
@pytest.mark.parametrize("lookup", ["2026-03-04-001", "001"])
def test_cli_lookup_prioritizes_symlinked_nested_directory_over_valid_candidate(
    tmp_path, sample_data, command, lookup
):
    data_root = tmp_path / "hostile-[root]\x1b"
    incidents_dir = data_root / "incidents"
    save_incident(Incident.from_dict(sample_data), incidents_dir)
    external = tmp_path / "external"
    external.mkdir()
    (incidents_dir / "nested").symlink_to(external, target_is_directory=True)

    result = CliRunner().invoke(
        app,
        [command, lookup],
        env={"FORGE_DATA_ROOT": str(data_root), "EDITOR": "/usr/bin/false"},
    )

    assert result.exit_code == 1
    assert "operationally incomplete" in result.output
    assert "nested: SymlinkRejectedError" in result.output
    assert str(data_root) not in result.output
    assert "\x1b" not in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize("command", ["show", "ref", "edit"])
@pytest.mark.parametrize("lookup", ["2026-03-04-001", "001"])
def test_cli_lookup_rejects_multiple_valid_exact_candidates(
    tmp_path, sample_data, command, lookup
):
    data_root = tmp_path / "hostile-[root]\x1b"
    incidents_dir = data_root / "incidents"
    valid = save_incident(Incident.from_dict(sample_data), incidents_dir)
    duplicate = incidents_dir / "duplicate" / valid.name
    duplicate.parent.mkdir()
    duplicate.write_bytes(valid.read_bytes())

    result = CliRunner().invoke(
        app,
        [command, lookup],
        env={"FORGE_DATA_ROOT": str(data_root), "EDITOR": "/usr/bin/false"},
    )

    assert result.exit_code == 1
    assert "Ambiguous incident id" in result.output
    assert str(data_root) not in result.output
    assert "\x1b" not in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize("command", ["show", "ref", "edit"])
@pytest.mark.parametrize("nested_failure", [False, True])
def test_cli_lookup_reports_operationally_incomplete_scan(
    tmp_path, monkeypatch, command, nested_failure
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
    result = CliRunner().invoke(
        app,
        [command, "001"],
        env={"FORGE_DATA_ROOT": str(data_root), "EDITOR": "/usr/bin/false"},
    )

    assert result.exit_code == 1
    assert "operationally incomplete" in result.output
    assert "No incident found" not in result.output
    assert str(data_root) not in result.output
    assert raw_message not in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize("command", [["list"], ["stats"]])
@pytest.mark.parametrize(
    ("incident_id", "timestamp", "include_timestamp"),
    [
        ("2026-02-30-001", "2026-02-28T12:00:00Z", True),
        ("legacy-malformed", "not-a-timestamp", True),
        ("legacy-empty", "", True),
        ("legacy-missing", None, False),
    ],
)
def test_cli_scan_commands_classify_invalid_ordering_fields(
    tmp_path, sample_data, command, incident_id, timestamp, include_timestamp
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

    result = CliRunner().invoke(
        app,
        command,
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code == 0
    assert "Corrupt corpus files: 1" in result.output
    assert f"nested/{incident_id}.yml: InvalidIncidentError" in result.output
    assert str(data_root) not in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize("valid", [True, False])
def test_edit_output_is_literal_control_safe_and_root_relative(
    tmp_path, sample_data, valid
):
    data_root = tmp_path / "forge-[root]\x1b\n-data"
    incidents_dir = data_root / "incidents"
    saved = save_incident(Incident.from_dict(sample_data), incidents_dir)
    hostile = saved.with_name("unsafe-[file]\x1b\n\r-001.yml")
    saved.rename(hostile)
    payload = _edited_payload(sample_data)
    body = (
        f"pathlib.Path(sys.argv[1]).write_text({payload!r})"
        if valid
        else "pathlib.Path(sys.argv[1]).write_text('incident: [unterminated')"
    )
    editor = _editor_helper(tmp_path, "editor-[name]\x1b\n\r", body)

    result = CliRunner().invoke(
        app,
        ["edit", "001"],
        env={"FORGE_DATA_ROOT": str(data_root), "EDITOR": str(editor)},
    )

    assert result.exit_code == (0 if valid else 1)
    assert "unsafe-[file]???-001.yml" in result.output
    assert "[name]???" in result.output
    assert "\x1b" not in result.output
    assert "\r" not in result.output
    assert str(data_root) not in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize("mutation", ["disappear", "same-inode-content"])
def test_edit_rejects_target_disappearance_or_content_conflict(
    tmp_path, sample_data, mutation
):
    data_root, saved, original = _edit_fixture(tmp_path, sample_data)
    payload = _edited_payload(sample_data)
    mutation_code = (
        "target.unlink()"
        if mutation == "disappear"
        else "target.write_bytes(target.read_bytes() + b'external change\\n')"
    )
    editor = _editor_helper(
        tmp_path,
        f"{mutation}-editor",
        "target = pathlib.Path(os.environ['FORGE_TEST_TARGET'])\n"
        f"{mutation_code}\n"
        f"pathlib.Path(sys.argv[1]).write_text({payload!r})",
    )

    result = CliRunner().invoke(
        app,
        ["edit", sample_data["id"]],
        env={
            "FORGE_DATA_ROOT": str(data_root),
            "EDITOR": str(editor),
            "FORGE_TEST_TARGET": str(saved),
        },
    )

    assert result.exit_code == 1
    assert "changed while the editor was open" in result.output
    if mutation == "disappear":
        assert not saved.exists()
    else:
        assert saved.read_bytes() == original + b"external change\n"
        assert not list(saved.parent.glob(f".{saved.name}.*.tmp"))


@pytest.mark.parametrize("failure_kind", ["corrupt", "scan-error"])
def test_analyze_prepare_only_fails_before_creating_artifact_on_incomplete_corpus(
    tmp_path, sample_data, monkeypatch, failure_kind
):
    data_root = tmp_path / "forge-data"
    _prepare_incomplete_analysis_corpus(
        data_root, sample_data, failure_kind, monkeypatch
    )

    result = CliRunner().invoke(
        app,
        ["analyze", "--prepare-only"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code == 1
    assert "Valid corpus incidents: 1" in result.output
    assert (
        f"Corrupt corpus files: {1 if failure_kind == 'corrupt' else 0}"
        in result.output
    )
    assert (
        f"Scan operational errors: {1 if failure_kind == 'scan-error' else 0}"
        in result.output
    )
    assert not (data_root / "analysis").exists()
    assert str(data_root) not in result.output


@pytest.mark.parametrize("failure_kind", ["corrupt", "scan-error"])
def test_analyze_provider_path_fails_before_provider_call_on_incomplete_corpus(
    tmp_path, sample_data, monkeypatch, failure_kind
):
    data_root = tmp_path / "forge-data"
    _prepare_incomplete_analysis_corpus(
        data_root, sample_data, failure_kind, monkeypatch
    )
    provider_calls = 0

    def fail_get_provider(*_args, **_kwargs):
        nonlocal provider_calls
        provider_calls += 1
        raise AssertionError("provider must not be resolved")

    monkeypatch.setattr("forge_cli.providers.get_provider", fail_get_provider)

    result = CliRunner().invoke(
        app,
        ["analyze", "--provider", "openai"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code == 1
    assert provider_calls == 0
    assert "Valid corpus incidents: 1" in result.output
    assert "Incident corpus is incomplete; analysis was not started." in result.output
    assert not (data_root / "analysis").exists()


def test_analyze_missing_corpus_is_successful_empty_read_only_result(tmp_path):
    data_root = tmp_path / "missing-forge-data"

    result = CliRunner().invoke(
        app,
        ["analyze", "--prepare-only"],
        env={"FORGE_DATA_ROOT": str(data_root)},
    )

    assert result.exit_code == 0
    assert "No incidents to analyze." in result.output
    assert not data_root.exists()
