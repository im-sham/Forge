from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Callable

from click import unstyle
import pytest
from typer.testing import CliRunner

from forge_cli.cli import app

ROOT = Path(__file__).resolve().parents[1]
INCIDENT_FIXTURE = ROOT / "examples/document-operations/redaction-miss-incident.yml"
EXPECTED_FIXTURE = ROOT / "examples/document-operations/incident-ref-v0.1.expected.json"


def _corpus(tmp_path: Path) -> Path:
    data_root = tmp_path / "forge-data"
    incidents_dir = data_root / "incidents"
    incidents_dir.mkdir(parents=True)
    shutil.copyfile(
        INCIDENT_FIXTURE,
        incidents_dir / "example-document-ops-redaction-miss.yml",
    )
    return data_root


def _file_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file()
    }


def _replace_option(args: list[str], option: str, value: str) -> list[str]:
    changed = list(args)
    changed[changed.index(option) + 1] = value
    return changed


def _without_options(args: list[str], *options: str) -> list[str]:
    changed = list(args)
    for option in options:
        index = changed.index(option)
        del changed[index : index + 2]
    return changed


def _canonical_args(data_root: Path) -> list[str]:
    return [
        "canonical-ref-v0-1",
        "--data-root",
        str(data_root),
        "--incident-lookup",
        "example-document-ops-redaction-miss",
        "--organization-id",
        "proofhouse-demo",
        "--environment-id",
        "internal-demo",
        "--issued-at",
        "2026-04-27T12:02:00+00:00",
        "--incident-id",
        "example-document-ops-redaction-miss",
        "--incident-snapshot-id",
        "incident-snapshot:example-document-ops-redaction-miss:g1",
        "--incident-snapshot-state-id",
        "state:incident:example-document-ops-redaction-miss:g1",
        "--workflow-id",
        "document_ops_regulated_review_v0",
        "--workflow-snapshot-id",
        "snapshot:document_ops_regulated_review_v0:g10-governance-preflight",
        "--workflow-snapshot-state-id",
        "state:workflow:document_ops_regulated_review_v0:g10-governance-preflight",
    ]


def test_canonical_ref_v0_1_emits_exact_accepted_document_operations_fixture(
    tmp_path: Path,
) -> None:
    data_root = _corpus(tmp_path)
    before = _file_hashes(data_root)

    result = CliRunner().invoke(
        app,
        _canonical_args(data_root),
        env={"FORGE_DATA_ROOT": str(tmp_path / "ignored-corpus")},
    )

    assert result.exit_code == 0
    assert result.stderr == ""
    expected = json.loads(EXPECTED_FIXTURE.read_text(encoding="utf-8"))
    assert json.loads(result.stdout) == expected
    assert result.stdout.count("\n") == 1
    assert "Candidate internal-eval assets" not in result.stdout
    assert "missing_redaction_transform_ref_before_eval_handoff" not in result.stdout
    assert _file_hashes(data_root) == before


@pytest.mark.parametrize(
    ("mutate", "error_text"),
    [
        (
            lambda args: _without_options(
                args,
                "--incident-snapshot-id",
                "--incident-snapshot-state-id",
            ),
            "snapshot or version pin is required",
        ),
        (
            lambda args: _without_options(args, "--incident-snapshot-state-id"),
            "incident snapshot requires both a pin and its state identity",
        ),
        (
            lambda args: _replace_option(args, "--incident-snapshot-id", "latest"),
            "immutable pin must be non-empty, well-formed, and immutable",
        ),
        (
            lambda args: (
                args
                + [
                    "--workflow-version",
                    "1",
                    "--workflow-version-state-id",
                    "state:workflow:different",
                ]
            ),
            "snapshot and version pins must identify the same immutable state",
        ),
        (
            lambda args: _replace_option(args, "--incident-id", "other-incident"),
            "canonical incident identity must equal the stored incident identity",
        ),
        (
            lambda args: _replace_option(args, "--workflow-id", "workflow/latest"),
            "workflow_id must be an explicit well-formed identity",
        ),
    ],
)
def test_canonical_ref_v0_1_fails_closed_with_stderr_only(
    tmp_path: Path,
    mutate: Callable[[list[str]], list[str]],
    error_text: str,
) -> None:
    data_root = _corpus(tmp_path)
    before = _file_hashes(data_root)
    args = mutate(_canonical_args(data_root))

    result = CliRunner().invoke(app, args)

    assert result.exit_code != 0
    assert result.stdout == ""
    assert error_text in result.stderr
    assert "Candidate internal-eval assets" not in result.stderr
    assert _file_hashes(data_root) == before


def test_canonical_ref_v0_1_requires_explicit_data_root() -> None:
    result = CliRunner().invoke(app, ["canonical-ref-v0-1"])

    assert result.exit_code != 0
    assert result.stdout == ""
    assert "Missing option '--data-root'." in unstyle(result.stderr)


def test_mcp_canonical_ref_v0_1_reuses_exact_typed_boundary(tmp_path: Path) -> None:
    _ = pytest.importorskip("mcp")
    from forge_cli.mcp_server import forge_canonical_incident_ref_v0_1

    data_root = _corpus(tmp_path)
    before = _file_hashes(data_root)

    result = str(
        forge_canonical_incident_ref_v0_1(
            data_root=str(data_root),
            incident_lookup="example-document-ops-redaction-miss",
            organization_id="proofhouse-demo",
            environment_id="internal-demo",
            issued_at="2026-04-27T12:02:00+00:00",
            incident_id="example-document-ops-redaction-miss",
            workflow_id="document_ops_regulated_review_v0",
            incident_snapshot_id="incident-snapshot:example-document-ops-redaction-miss:g1",
            incident_snapshot_state_id=("state:incident:example-document-ops-redaction-miss:g1"),
            workflow_snapshot_id=(
                "snapshot:document_ops_regulated_review_v0:g10-governance-preflight"
            ),
            workflow_snapshot_state_id=(
                "state:workflow:document_ops_regulated_review_v0:g10-governance-preflight"
            ),
        )
    )

    expected = json.loads(EXPECTED_FIXTURE.read_text(encoding="utf-8"))
    assert json.loads(result) == expected
    assert _file_hashes(data_root) == before
