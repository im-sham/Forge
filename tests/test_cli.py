from __future__ import annotations

import json

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
