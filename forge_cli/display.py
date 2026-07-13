from __future__ import annotations

from collections import Counter

from rich.console import Console
from rich.columns import Columns
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from forge_cli.models import PROOFHOUSE_REF_FIELDS, Incident

console = Console()


def severity_color(severity: str) -> str:
    return {
        "cosmetic": "dim",
        "functional": "yellow",
        "safety-critical": "bold red",
    }.get(severity, "white")


def _safe_string(value: object) -> str:
    return "".join(
        character if character.isprintable() else "?" for character in str(value)
    )


def _literal_text(value: object, style: str | None = None) -> Text:
    return Text(_safe_string(value), style=style)


def _literal_multiline_text(value: object, style: str | None = None) -> Text:
    safe = "\n".join(_safe_string(line) for line in str(value).split("\n"))
    return Text(safe, style=style)


def _append_field(
    content: Text,
    label: str,
    value: object,
    *,
    width: int,
    label_style: str = "cyan bold",
    value_style: str | None = None,
) -> None:
    if content:
        content.append("\n")
    content.append(Text(f"{label + ':':<{width}}", style=label_style))
    content.append(_literal_multiline_text(value, value_style))


def display_incident_table(incidents: list[Incident], total: int | None = None) -> None:
    """Display a Rich table of incidents."""
    if not incidents:
        console.print(Text("No incidents found.", style="dim"))
        return

    table = Table(
        title=Text("Forge Incidents"),
        show_lines=False,
        padding=(0, 1),
    )
    table.add_column(Text("ID"), style="cyan", no_wrap=True)
    table.add_column(Text("Project"), style="blue")
    table.add_column(Text("Platform"), style="dim cyan")
    table.add_column(Text("Severity"), no_wrap=True)
    table.add_column(Text("Type"), style="magenta")
    table.add_column(Text("Summary"))

    for inc in incidents:
        sev_style = severity_color(inc.severity)
        summary = (inc.actual_behavior or "").strip().split("\n")[0][:60]
        table.add_row(
            _literal_text(inc.id),
            _literal_text(inc.project),
            _literal_text(inc.platform or ""),
            _literal_text(inc.severity, sev_style),
            _literal_text(inc.failure_type),
            _literal_text(summary),
        )

    console.print(table)

    shown = len(incidents)
    if total and total > shown:
        console.print(
            Text(f"Showing {shown} of {total} incidents", style="dim")
        )


def display_incident_panel(incident: Incident) -> None:
    """Display a Rich panel summarizing a logged incident."""
    shown_id = incident.id or "[allocated at save]"
    content = Text()
    for label, value, value_style in [
        ("ID", shown_id, None),
        ("Project", incident.project, None),
        ("Agent", incident.agent, None),
        ("Platform", incident.platform or "", None),
        ("Severity", incident.severity, severity_color(incident.severity)),
        ("Type", incident.failure_type, None),
    ]:
        _append_field(
            content,
            label,
            value,
            width=12,
            label_style="cyan",
            value_style=value_style,
        )

    content.append("\n")
    _append_field(
        content,
        "Expected",
        incident.expected_behavior.strip()[:80],
        width=12,
        label_style="cyan",
    )
    _append_field(
        content,
        "Actual",
        incident.actual_behavior.strip()[:80],
        width=12,
        label_style="cyan",
    )
    if incident.tags:
        _append_field(
            content,
            "Tags",
            ", ".join(incident.tags),
            width=12,
            label_style="cyan",
        )
    axes = [
        value
        for value in [
            incident.capability_area,
            incident.lifecycle_stage,
            incident.issue_class,
            incident.workflow_archetype,
        ]
        if value
    ]
    if axes:
        _append_field(
            content,
            "Axes",
            ", ".join(axes),
            width=12,
            label_style="cyan",
        )

    console.print(
        Panel(
            content,
            title=Text("Incident Captured"),
            border_style="green",
        )
    )


def display_incident_detail(incident: Incident) -> None:
    """Display full incident details in a Rich panel."""
    content = Text()
    for label, value, value_style in [
        ("ID", incident.id, None),
        ("Timestamp", incident.timestamp, None),
        ("Reported by", incident.reported_by, None),
        ("Project", incident.project, None),
        ("Agent", incident.agent, None),
        ("Platform", incident.platform, None),
        ("Severity", incident.severity, severity_color(incident.severity)),
        ("Failure type", incident.failure_type, None),
    ]:
        _append_field(
            content,
            label,
            value,
            width=16,
            value_style=value_style,
        )

    for label, value in [
        ("Expected", incident.expected_behavior),
        ("Actual", incident.actual_behavior),
        ("Context", incident.context),
        ("Root cause", incident.root_cause),
        ("Immediate fix", incident.immediate_fix),
        ("Systemic takeaway", incident.systemic_takeaway),
    ]:
        text = (value or "").strip()
        if text:
            content.append("\n\n")
            content.append(Text(f"{label}:", style="cyan bold"))
            for line in text.split("\n"):
                content.append("\n  ")
                content.append(_literal_text(line))

    if incident.tags:
        content.append("\n\n")
        content.append(Text(f"{'Tags:':<16}", style="cyan bold"))
        content.append(_literal_text(", ".join(incident.tags)))

    axes = [
        ("Capability area", incident.capability_area),
        ("Lifecycle stage", incident.lifecycle_stage),
        ("Issue class", incident.issue_class),
        ("Workflow archetype", incident.workflow_archetype),
        ("Subject type", incident.subject_type),
        ("Blocked use class", incident.blocked_use_class),
    ]
    shown_axes = [(label, value) for label, value in axes if value]
    if shown_axes:
        content.append("\n\n")
        content.append(Text("Structured axes:", style="cyan bold"))
        for label, value in shown_axes:
            content.append(f"\n  {label}: ")
            content.append(_literal_text(value))

    if incident.observed_state:
        content.append("\n\n")
        content.append(Text("Observed state:", style="cyan bold"))
        for key, value in incident.observed_state.items():
            content.append("\n  ")
            content.append(_literal_text(key))
            content.append(": ")
            content.append(_literal_text(value))

    present_refs = [
        field_name
        for field_name in PROOFHOUSE_REF_FIELDS
        if getattr(incident, field_name)
    ]
    if present_refs:
        content.append("\n\n")
        content.append(Text(f"{'Pointer refs:':<16}", style="cyan bold"))
        content.append(_literal_text(", ".join(present_refs)))
    if incident.related_incidents:
        content.append("\n")
        content.append(Text(f"{'Related:':<16}", style="cyan bold"))
        content.append(_literal_text(", ".join(incident.related_incidents)))
    if incident.playbook_entry:
        content.append("\n")
        content.append(Text(f"{'Playbook:':<16}", style="cyan bold"))
        content.append(_literal_text(incident.playbook_entry))

    title = Text("Incident ")
    title.append(_literal_text(incident.id))
    console.print(Panel(content, title=title, border_style="cyan"))


def print_success(msg: str) -> None:
    console.print(_literal_text(msg, "green"))


def print_warning(msg: str) -> None:
    console.print(_literal_text(msg, "yellow"))


def print_error(msg: str) -> None:
    text = Text("Error:", style="bold red")
    text.append(" ")
    text.append(_literal_text(msg, "red"))
    console.print(text)


def print_info(msg: str) -> None:
    console.print(_literal_text(msg, "dim"))


def _counter_table(title: str, counter: Counter, color: str = "cyan") -> Table:
    """Build a small Rich table from a Counter."""
    table = Table(
        title=Text(title),
        show_lines=False,
        padding=(0, 1),
        expand=True,
    )
    table.add_column(Text("Value"), style=color)
    table.add_column(Text("Count"), justify="right", style="bold")
    for value, count in counter.most_common():
        table.add_row(
            _literal_text(value or "(empty)"),
            _literal_text(count),
        )
    return table


def display_stats(incidents: list[Incident]) -> None:
    """Display aggregate statistics for a list of incidents."""
    if not incidents:
        console.print(Text("No incidents to summarize.", style="dim"))
        return

    total = len(incidents)
    by_severity = Counter(i.severity for i in incidents)
    by_type = Counter(i.failure_type for i in incidents)
    by_project = Counter(i.project for i in incidents)
    by_platform = Counter(i.platform for i in incidents if i.platform)
    all_tags = Counter(tag for i in incidents for tag in i.tags)
    by_issue_class = Counter(i.issue_class for i in incidents if i.issue_class)
    by_capability_area = Counter(
        i.capability_area for i in incidents if i.capability_area
    )

    timestamps = sorted(i.timestamp for i in incidents if i.timestamp)
    date_range = ""
    if timestamps:
        first = timestamps[0][:10]
        last = timestamps[-1][:10]
        date_range = f"{first} to {last}" if first != last else first

    header = Text("Total incidents:", style="bold")
    header.append(f" {total}")
    if date_range:
        header.append("\n")
        header.append(Text("Date range:", style="bold"))
        header.append(" ")
        header.append(_literal_text(date_range))
    console.print(
        Panel(
            header,
            title=Text("Forge Stats"),
            border_style="cyan",
        )
    )
    console.print()

    sev_table = Table(
        title=Text("By Severity"),
        show_lines=False,
        padding=(0, 1),
        expand=True,
    )
    sev_table.add_column(Text("Severity"))
    sev_table.add_column(Text("Count"), justify="right", style="bold")
    for sev, count in by_severity.most_common():
        sev_table.add_row(
            _literal_text(sev, severity_color(sev)),
            _literal_text(count),
        )

    proj_table = _counter_table("By Project", by_project, color="blue")
    console.print(Columns([sev_table, proj_table], equal=True))
    console.print()

    type_table = _counter_table("By Failure Type", by_type, color="magenta")
    plat_table = _counter_table("By Platform", by_platform, color="dim cyan")
    console.print(Columns([type_table, plat_table], equal=True))

    if by_issue_class or by_capability_area:
        console.print()
        issue_table = _counter_table(
            "By Issue Class",
            by_issue_class,
            color="yellow",
        )
        capability_table = _counter_table(
            "By Capability Area",
            by_capability_area,
            color="cyan",
        )
        console.print(Columns([issue_table, capability_table], equal=True))

    if all_tags:
        console.print()
        tag_table = Table(
            title=Text("Top Tags"),
            show_lines=False,
            padding=(0, 1),
        )
        tag_table.add_column(Text("Tag"), style="green")
        tag_table.add_column(Text("Count"), justify="right", style="bold")
        for tag, count in all_tags.most_common(10):
            tag_table.add_row(_literal_text(tag), _literal_text(count))
        console.print(tag_table)
