from __future__ import annotations

from collections import Counter

from rich.console import Console
from rich.columns import Columns
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from forge_cli.models import Incident

console = Console()


def severity_color(severity: str) -> str:
    return {
        "cosmetic": "dim",
        "functional": "yellow",
        "safety-critical": "bold red",
    }.get(severity, "white")


def display_incident_table(incidents: list[Incident], total: int | None = None) -> None:
    """Display a Rich table of incidents."""
    if not incidents:
        console.print("[dim]No incidents found.[/dim]")
        return

    table = Table(title="Forge Incidents", show_lines=False, padding=(0, 1))
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Project", style="blue")
    table.add_column("Platform", style="dim cyan")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Type", style="magenta")
    table.add_column("Summary")

    for inc in incidents:
        sev_style = severity_color(inc.severity)
        summary = (inc.actual_behavior or "").strip().split("\n")[0][:60]

        table.add_row(
            inc.id,
            inc.project,
            inc.platform or "",
            Text(inc.severity, style=sev_style),
            inc.failure_type,
            summary,
        )

    console.print(table)

    shown = len(incidents)
    if total and total > shown:
        console.print(f"[dim]Showing {shown} of {total} incidents[/dim]")


def display_incident_panel(incident: Incident) -> None:
    """Display a Rich panel summarizing a logged incident."""
    lines = [
        f"[cyan]ID:[/cyan]         {incident.id}",
        f"[cyan]Project:[/cyan]    {incident.project}",
        f"[cyan]Agent:[/cyan]      {incident.agent}",
        f"[cyan]Platform:[/cyan]   {incident.platform}",
        f"[cyan]Severity:[/cyan]   [{severity_color(incident.severity)}]{incident.severity}[/]",
        f"[cyan]Type:[/cyan]       {incident.failure_type}",
        "",
        f"[cyan]Expected:[/cyan]   {incident.expected_behavior.strip()[:80]}",
        f"[cyan]Actual:[/cyan]     {incident.actual_behavior.strip()[:80]}",
    ]
    if incident.tags:
        lines.append(f"[cyan]Tags:[/cyan]       {', '.join(incident.tags)}")
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
        lines.append(f"[cyan]Axes:[/cyan]       {', '.join(axes)}")

    content = "\n".join(lines)
    console.print(Panel(content, title="Incident Captured", border_style="green"))


def display_incident_detail(incident: Incident) -> None:
    """Display full incident details in a Rich panel."""
    sev_style = severity_color(incident.severity)

    lines = [
        f"[cyan bold]ID:[/]            {incident.id}",
        f"[cyan bold]Timestamp:[/]     {incident.timestamp}",
        f"[cyan bold]Reported by:[/]   {incident.reported_by}",
        "",
        f"[cyan bold]Project:[/]       {incident.project}",
        f"[cyan bold]Agent:[/]         {incident.agent}",
        f"[cyan bold]Platform:[/]      {incident.platform}",
        f"[cyan bold]Severity:[/]      [{sev_style}]{incident.severity}[/]",
        f"[cyan bold]Failure type:[/]  {incident.failure_type}",
    ]

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
            lines.append("")
            lines.append(f"[cyan bold]{label}:[/]")
            for line in text.split("\n"):
                lines.append(f"  {line}")

    if incident.tags:
        lines.append("")
        lines.append(f"[cyan bold]Tags:[/]          {', '.join(incident.tags)}")
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
        lines.append("")
        lines.append("[cyan bold]Structured axes:[/]")
        for label, value in shown_axes:
            lines.append(f"  {label}: {value}")
    if incident.observed_state:
        lines.append("")
        lines.append("[cyan bold]Observed state:[/]")
        for key, value in incident.observed_state.items():
            lines.append(f"  {key}: {value}")
    present_refs = [
        field_name
        for field_name in [
            "workflow_ref",
            "evidence_ref",
            "workflow_evidence_snapshot",
            "assessment_ref",
            "policy_decision_ref",
            "use_approval_ref",
            "asset_ref",
            "derivation_ref",
            "transform_ref",
        ]
        if getattr(incident, field_name)
    ]
    if present_refs:
        lines.append("")
        lines.append(f"[cyan bold]Pointer refs:[/]    {', '.join(present_refs)}")
    if incident.related_incidents:
        lines.append(f"[cyan bold]Related:[/]       {', '.join(incident.related_incidents)}")
    if incident.playbook_entry:
        lines.append(f"[cyan bold]Playbook:[/]      {incident.playbook_entry}")

    content = "\n".join(lines)
    console.print(Panel(content, title=f"Incident {incident.id}", border_style="cyan"))


def print_success(msg: str) -> None:
    console.print(f"[green]{msg}[/green]")


def print_error(msg: str) -> None:
    console.print(f"[bold red]Error:[/bold red] {msg}")


def print_info(msg: str) -> None:
    console.print(f"[dim]{msg}[/dim]")


def _counter_table(title: str, counter: Counter, color: str = "cyan") -> Table:
    """Build a small Rich table from a Counter."""
    table = Table(title=title, show_lines=False, padding=(0, 1), expand=True)
    table.add_column("Value", style=color)
    table.add_column("Count", justify="right", style="bold")
    for value, count in counter.most_common():
        table.add_row(value or "(empty)", str(count))
    return table


def display_stats(incidents: list[Incident]) -> None:
    """Display aggregate statistics for a list of incidents."""
    if not incidents:
        console.print("[dim]No incidents to summarize.[/dim]")
        return

    total = len(incidents)
    by_severity = Counter(i.severity for i in incidents)
    by_type = Counter(i.failure_type for i in incidents)
    by_project = Counter(i.project for i in incidents)
    by_platform = Counter(i.platform for i in incidents if i.platform)
    all_tags = Counter(tag for i in incidents for tag in i.tags)

    # Date range
    timestamps = sorted(i.timestamp for i in incidents if i.timestamp)
    date_range = ""
    if timestamps:
        first = timestamps[0][:10]
        last = timestamps[-1][:10]
        date_range = f"{first} to {last}" if first != last else first

    # Header
    header_lines = [f"[bold]Total incidents:[/bold] {total}"]
    if date_range:
        header_lines.append(f"[bold]Date range:[/bold] {date_range}")
    console.print(Panel("\n".join(header_lines), title="Forge Stats", border_style="cyan"))
    console.print()

    # Severity & project side by side
    sev_table = Table(title="By Severity", show_lines=False, padding=(0, 1), expand=True)
    sev_table.add_column("Severity")
    sev_table.add_column("Count", justify="right", style="bold")
    for sev, count in by_severity.most_common():
        sev_table.add_row(Text(sev, style=severity_color(sev)), str(count))

    proj_table = _counter_table("By Project", by_project, color="blue")

    console.print(Columns([sev_table, proj_table], equal=True))
    console.print()

    # Type & platform side by side
    type_table = _counter_table("By Failure Type", by_type, color="magenta")
    plat_table = _counter_table("By Platform", by_platform, color="dim cyan")

    console.print(Columns([type_table, plat_table], equal=True))

    # Top tags
    if all_tags:
        console.print()
        tag_table = Table(title="Top Tags", show_lines=False, padding=(0, 1))
        tag_table.add_column("Tag", style="green")
        tag_table.add_column("Count", justify="right", style="bold")
        for tag, count in all_tags.most_common(10):
            tag_table.add_row(tag, str(count))
        console.print(tag_table)
