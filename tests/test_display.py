from io import StringIO

import pytest
from rich.console import Console

import forge_cli.display as display
from forge_cli.models import Incident


def _capture_console(monkeypatch) -> StringIO:
    output = StringIO()
    monkeypatch.setattr(
        display,
        "console",
        Console(file=output, force_terminal=False, color_system=None, width=500),
    )
    return output


def _unsafe_incident(sample_data) -> Incident:
    incident = Incident.from_dict(sample_data)
    incident.id = "[bold]id[/bold]\x1b\r"
    incident.timestamp = "[bold]timestamp[/bold]\x1b\r"
    incident.reported_by = "[bold]reporter[/bold]\x1b\r"
    incident.project = "[bold]project[/bold]\x1b\r"
    incident.agent = "[bold]agent[/bold]\x1b\r"
    incident.platform = "[bold]platform[/bold]\x1b\r"
    incident.severity = "[bold]severity[/bold]\x1b\r"
    incident.failure_type = "[bold]type[/bold]\x1b\r"
    incident.expected_behavior = "[bold]expected[/bold]\nsecond\x1b\r"
    incident.actual_behavior = "[bold]actual[/bold]\nsecond\x1b\r"
    incident.context = "[bold]context[/bold]\nsecond\x1b\r"
    incident.root_cause = "[bold]cause[/bold]\nsecond\x1b\r"
    incident.immediate_fix = "[bold]fix[/bold]\nsecond\x1b\r"
    incident.systemic_takeaway = "[bold]takeaway[/bold]\nsecond\x1b\r"
    incident.tags = ["[bold]tag[/bold]\x1b\r"]
    incident.capability_area = "[bold]capability[/bold]\x1b\r"
    incident.lifecycle_stage = "[bold]lifecycle[/bold]\x1b\r"
    incident.issue_class = "[bold]issue[/bold]\x1b\r"
    incident.workflow_archetype = "[bold]workflow[/bold]\x1b\r"
    incident.subject_type = "[bold]subject[/bold]\x1b\r"
    incident.blocked_use_class = "[bold]blocked[/bold]\x1b\r"
    incident.observed_state = {
        "[bold]state-key[/bold]\x1b\r": "[bold]state-value[/bold]\x1b\r"
    }
    incident.related_incidents = ["[bold]related[/bold]\x1b\r"]
    incident.playbook_entry = "[bold]playbook[/bold]\x1b\r"
    incident.workflow_ref = {"ref_id": "workflow:1"}
    return incident


def _assert_literal_safe(rendered: str, *labels: str) -> None:
    for label in labels:
        assert f"[bold]{label}[/bold]??" in rendered
    assert "\x1b" not in rendered
    assert "\r" not in rendered


@pytest.mark.parametrize(
    "printer_name",
    ["print_info", "print_success", "print_warning", "print_error"],
)
def test_message_printers_render_untrusted_text_literally_without_controls(
    monkeypatch, printer_name
):
    output = StringIO()
    monkeypatch.setattr(
        display,
        "console",
        Console(file=output, force_terminal=False, color_system=None, width=200),
    )
    message = "[bold]literal[/bold] unmatched[\x1b\n\r"

    getattr(display, printer_name)(message)

    rendered = output.getvalue()
    assert "[bold]literal[/bold] unmatched[???" in rendered
    assert "\x1b" not in rendered
    assert "\r" not in rendered
    assert rendered.count("\n") == 1


def test_display_incident_panel_renders_fields_tags_axes_and_multiline_literally(
    monkeypatch, sample_data
):
    output = _capture_console(monkeypatch)
    incident = _unsafe_incident(sample_data)

    display.display_incident_panel(incident)

    rendered = output.getvalue()
    _assert_literal_safe(
        rendered,
        "id",
        "project",
        "agent",
        "platform",
        "severity",
        "type",
        "tag",
        "capability",
        "lifecycle",
        "issue",
        "workflow",
    )
    assert "[bold]actual[/bold]" in rendered
    assert "[bold]expected[/bold]" in rendered
    assert "second?" in rendered


def test_display_incident_detail_renders_title_and_every_corpus_field_literally(
    monkeypatch, sample_data
):
    output = _capture_console(monkeypatch)
    incident = _unsafe_incident(sample_data)

    display.display_incident_detail(incident)

    rendered = output.getvalue()
    _assert_literal_safe(
        rendered,
        "id",
        "timestamp",
        "reporter",
        "project",
        "agent",
        "platform",
        "severity",
        "type",
        "tag",
        "capability",
        "lifecycle",
        "issue",
        "workflow",
        "subject",
        "blocked",
        "state-key",
        "state-value",
        "related",
        "playbook",
    )
    for label in ["expected", "actual", "context", "cause", "fix", "takeaway"]:
        assert f"[bold]{label}[/bold]" in rendered
    assert "[bold]id[/bold]??" in rendered.splitlines()[0]
    assert "second?" in rendered
    assert "workflow_ref" in rendered


def test_display_incident_table_renders_all_corpus_cells_literally(
    monkeypatch, sample_data
):
    output = _capture_console(monkeypatch)
    incident = _unsafe_incident(sample_data)

    display.display_incident_table([incident])

    rendered = output.getvalue()
    _assert_literal_safe(
        rendered,
        "id",
        "project",
        "platform",
        "severity",
        "type",
    )
    assert "[bold]actual[/bold]" in rendered


def test_display_stats_renders_all_corpus_cells_literally(
    monkeypatch, sample_data
):
    output = _capture_console(monkeypatch)
    incident = _unsafe_incident(sample_data)
    incident.timestamp = "[date]\x1b\r"

    display.display_stats([incident])

    rendered = output.getvalue()
    _assert_literal_safe(
        rendered,
        "project",
        "platform",
        "severity",
        "type",
        "tag",
        "issue",
        "capability",
    )
    assert "[date]??" in rendered
