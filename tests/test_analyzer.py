from pathlib import Path

from forge_cli.analyzer import (
    next_analysis_output_path,
    render_analysis_prompt,
    serialize_incidents_for_analysis,
)
from forge_cli.models import Incident


def test_serialize_incidents_for_analysis_preserves_field_order(sample_data):
    incident = Incident.from_dict(sample_data)

    rendered = serialize_incidents_for_analysis([incident])

    assert "id: 2026-03-04-001" in rendered
    assert "timestamp: '2026-03-04T14:30:00Z'" in rendered
    assert rendered.index("id: 2026-03-04-001") < rendered.index("timestamp: '2026-03-04T14:30:00Z'")
    assert rendered.index("project: mila") < rendered.index("agent: document-analyzer")
    assert "tags:" in rendered


def test_render_analysis_prompt_substitutes_incident_yaml():
    prompt_template = "Header\n\n[INCIDENTS ARE INSERTED HERE AS YAML]\n\nFooter"
    incidents_yaml = "- id: 2026-03-04-001\n  project: mila\n"

    rendered = render_analysis_prompt(prompt_template, incidents_yaml)

    assert "[INCIDENTS ARE INSERTED HERE AS YAML]" not in rendered
    assert incidents_yaml in rendered
    assert rendered.startswith("Header")
    assert rendered.endswith("Footer")


def test_next_analysis_output_path_uses_sequence_when_needed(tmp_path):
    first = next_analysis_output_path(tmp_path, date_prefix="2026-03-28")
    assert first == tmp_path / "2026-03-28-analysis.md"

    first.write_text("# analysis", encoding="utf-8")

    second = next_analysis_output_path(tmp_path, date_prefix="2026-03-28")
    assert second == tmp_path / "2026-03-28-analysis-2.md"


def test_next_analysis_output_path_supports_alternate_labels(tmp_path):
    output = next_analysis_output_path(
        tmp_path,
        date_prefix="2026-03-28",
        label="analysis-input",
    )

    assert output == Path(tmp_path) / "2026-03-28-analysis-input.md"
