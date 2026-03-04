from __future__ import annotations

import os
import subprocess
import tempfile
from datetime import datetime, timezone
from typing import Optional

import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.status import Status
from rich.table import Table

from forge_cli.config import load_config
from forge_cli.display import (
    display_incident_detail,
    display_incident_panel,
    display_incident_table,
    display_stats,
    print_error,
    print_info,
    print_success,
)
from forge_cli.incident_store import (
    find_incident,
    generate_id,
    get_all_incidents,
    list_incidents,
    save_incident,
)
from forge_cli.models import FailureType, Incident, Severity

app = typer.Typer(
    name="forge",
    help="USMI Labs — AI agent failure mode tracking and analysis",
    no_args_is_help=True,
)
console = Console()


def _prompt_choice(prompt_text: str, choices: list[str], default: str | None = None) -> str:
    """Prompt the user to pick from a list of valid choices."""
    choices_display = " | ".join(choices)
    while True:
        hint = f" [{default}]" if default else ""
        value = typer.prompt(f"{prompt_text} ({choices_display}){hint}", default=default or "")
        value = value.strip()
        if value in choices:
            return value
        typer.echo(f"  Invalid choice. Must be one of: {choices_display}")


def _prompt_suggested(prompt_text: str, suggestions: list[str]) -> str:
    """Prompt for free-text input, showing suggestions. Any value accepted."""
    hint = ", ".join(suggestions)
    value = typer.prompt(f"{prompt_text} (suggestions: {hint})")
    return value.strip()


def _prompt_text(prompt_text: str, required: bool = True) -> str:
    """Prompt for text input. Type 'edit' to open $EDITOR for multiline."""
    value = typer.prompt(f"{prompt_text} (or 'edit' for $EDITOR)", default="" if not required else ...)
    if value.strip().lower() == "edit":
        return _open_editor()
    return value.strip()


def _open_editor() -> str:
    """Open $EDITOR on a temp file and return its contents."""
    editor = os.environ.get("EDITOR", "vi")
    with tempfile.NamedTemporaryFile(suffix=".md", mode="w", delete=False) as f:
        f.write("# Enter text below. Save and close to continue.\n")
        tmppath = f.name

    try:
        subprocess.run([editor, tmppath], check=True)
        with open(tmppath) as f:
            lines = f.readlines()
        # Strip the instruction comment
        text = "".join(line for line in lines if not line.startswith("# Enter text"))
        return text.strip()
    finally:
        os.unlink(tmppath)


@app.command()
def log(
    project: Optional[str] = typer.Option(None, "--project", "-p", help="Project name"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Severity level"),
    failure_type: Optional[str] = typer.Option(None, "--type", "-t", help="Failure type"),
    agent: Optional[str] = typer.Option(None, "--agent", "-a", help="Agent or component name"),
    platform: Optional[str] = typer.Option(None, "--platform", "-P", help="AI tool/platform"),
) -> None:
    """Log a new incident. Prompts interactively for missing fields."""
    try:
        cfg = load_config()
    except FileNotFoundError as e:
        print_error(str(e))
        raise typer.Exit(1)

    severity_choices = [s.value for s in Severity]
    failure_choices = [f.value for f in FailureType]

    console.print("[bold]Forge — Log New Incident[/bold]\n")

    # Classification
    if not project:
        project = _prompt_suggested("Project", cfg.projects)

    if not agent:
        agent = typer.prompt("Agent/component")

    if not platform:
        platform = _prompt_suggested("Platform", cfg.platforms)

    if not severity:
        severity = _prompt_choice("Severity", severity_choices)
    elif severity not in severity_choices:
        print_error(
            f"Invalid severity '{severity}'. Must be one of: {', '.join(severity_choices)}"
        )
        raise typer.Exit(1)

    if not failure_type:
        failure_type = _prompt_choice("Failure type", failure_choices)
    elif failure_type not in failure_choices:
        print_error(
            f"Invalid failure type '{failure_type}'. Must be one of: {', '.join(failure_choices)}"
        )
        raise typer.Exit(1)

    # What happened
    expected = _prompt_text("Expected behavior")
    actual = _prompt_text("Actual behavior")
    context = _prompt_text("Context", required=False) or ""

    # Resolution
    root_cause = typer.prompt("Root cause", default="")
    fix = _prompt_text("Immediate fix", required=False) or ""
    takeaway = _prompt_text("Systemic takeaway", required=False) or ""

    # Metadata
    tags_input = typer.prompt("Tags (comma-separated)", default="")
    tags = [t.strip() for t in tags_input.split(",") if t.strip()]

    # Build incident
    now = datetime.now(timezone.utc)
    incident_id = generate_id(cfg.incidents_dir, now.date())

    incident = Incident(
        id=incident_id,
        timestamp=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        reported_by=cfg.default_reporter,
        project=project,
        agent=agent,
        platform=platform,
        severity=severity,
        failure_type=failure_type,
        expected_behavior=expected,
        actual_behavior=actual,
        context=context,
        root_cause=root_cause,
        immediate_fix=fix,
        systemic_takeaway=takeaway,
        tags=tags,
    )

    # Confirm
    console.print()
    display_incident_panel(incident)
    console.print()

    if not typer.confirm("Save this incident?", default=True):
        print_info("Incident discarded.")
        raise typer.Exit(0)

    filepath = save_incident(incident, cfg.incidents_dir)
    print_success(f"Saved: {filepath}")


@app.command("list")
def list_cmd(
    project: Optional[str] = typer.Option(None, "--project", "-p", help="Filter by project"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by severity"),
    since: Optional[str] = typer.Option(None, "--since", help="Filter by date (YYYY-MM-DD)"),
    limit: int = typer.Option(10, "--limit", "-n", help="Max incidents to show"),
) -> None:
    """List recent incidents with optional filters."""
    try:
        cfg = load_config()
    except FileNotFoundError as e:
        print_error(str(e))
        raise typer.Exit(1)

    incidents = list_incidents(
        cfg.incidents_dir,
        project=project,
        severity=severity,
        since=since,
        limit=limit,
    )

    display_incident_table(incidents)


@app.command()
def show(
    incident_id: str = typer.Argument(help="Incident ID (e.g., '2026-03-04-001' or '001')"),
) -> None:
    """Show full details of a single incident."""
    try:
        cfg = load_config()
    except FileNotFoundError as e:
        print_error(str(e))
        raise typer.Exit(1)

    incident = find_incident(cfg.incidents_dir, incident_id)
    if incident is None:
        print_error(f"No incident found matching '{incident_id}'.")
        raise typer.Exit(1)

    display_incident_detail(incident)


@app.command()
def analyze(
    since: Optional[str] = typer.Option(None, "--since", help="Analyze incidents since date"),
    full: bool = typer.Option(False, "--full", help="Re-analyze all incidents"),
    provider: Optional[str] = typer.Option(None, "--provider", help="LLM provider (anthropic|openai)"),
) -> None:
    """Run LLM pattern analysis on incidents."""
    try:
        cfg = load_config()
    except FileNotFoundError as e:
        print_error(str(e))
        raise typer.Exit(1)

    from forge_cli.analyzer import analyze_incidents
    from forge_cli.providers import get_provider

    # Load incidents
    all_incidents = get_all_incidents(cfg.incidents_dir)

    if not full and since:
        all_incidents = [i for i in all_incidents if i.timestamp >= since]

    if not all_incidents:
        print_info("No incidents to analyze.")
        raise typer.Exit(0)

    # Load prompt template
    prompt_path = cfg.templates_dir / "analysis-prompt.md"
    if not prompt_path.exists():
        print_error(f"Analysis prompt template not found: {prompt_path}")
        raise typer.Exit(1)

    prompt_template = prompt_path.read_text()

    # Serialize incidents to YAML for the prompt
    incidents_yaml = yaml.dump(
        [i.to_dict() for i in all_incidents],
        default_flow_style=False,
        allow_unicode=True,
    )

    # Resolve provider
    provider_name = provider or cfg.analysis_provider
    try:
        llm = get_provider(provider_name, model=cfg.analysis_model)
    except (ValueError, ImportError) as e:
        print_error(str(e))
        raise typer.Exit(1)

    console.print(f"[bold]Analyzing {len(all_incidents)} incidents via {provider_name}...[/bold]\n")

    with Status(f"[bold cyan]Sending to {provider_name} for analysis...", console=console):
        try:
            report = analyze_incidents(
                incidents_yaml=incidents_yaml,
                prompt_template=prompt_template,
                provider=llm,
                max_tokens=cfg.analysis_max_tokens,
            )
        except Exception as e:
            print_error(f"Analysis failed: {e}")
            raise typer.Exit(1)

    # Save report
    cfg.analysis_dir.mkdir(parents=True, exist_ok=True)
    report_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    report_path = cfg.analysis_dir / f"{report_date}-analysis.md"

    # Avoid overwriting — append sequence if needed
    if report_path.exists():
        seq = 2
        while report_path.exists():
            report_path = cfg.analysis_dir / f"{report_date}-analysis-{seq}.md"
            seq += 1

    report_path.write_text(report)
    print_success(f"Analysis saved: {report_path}")

    # Show first few lines as a preview
    preview_lines = report.split("\n")[:10]
    console.print()
    for line in preview_lines:
        console.print(f"  {line}")
    if len(report.split("\n")) > 10:
        print_info(f"  ... ({len(report.split(chr(10)))} lines total)")


@app.command()
def stats(
    project: Optional[str] = typer.Option(None, "--project", "-p", help="Filter by project"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by severity"),
    since: Optional[str] = typer.Option(None, "--since", help="Filter by date (YYYY-MM-DD)"),
) -> None:
    """Show summary statistics across all incidents."""
    try:
        cfg = load_config()
    except FileNotFoundError as e:
        print_error(str(e))
        raise typer.Exit(1)

    incidents = get_all_incidents(cfg.incidents_dir)

    if project:
        incidents = [i for i in incidents if i.project == project]
    if severity:
        incidents = [i for i in incidents if i.severity == severity]
    if since:
        incidents = [i for i in incidents if i.timestamp >= since]

    display_stats(incidents)


# --- Playbook subcommand ---

playbook_app = typer.Typer(
    name="playbook",
    help="View and manage failure mode playbook entries",
    invoke_without_command=True,
)
app.add_typer(playbook_app, name="playbook")


@playbook_app.callback(invoke_without_command=True)
def playbook_list(ctx: typer.Context) -> None:
    """List all playbook entries."""
    if ctx.invoked_subcommand is not None:
        return

    try:
        cfg = load_config()
    except FileNotFoundError as e:
        print_error(str(e))
        raise typer.Exit(1)

    playbook_dir = cfg.playbook_dir
    if not playbook_dir.exists():
        print_info("No playbook directory found.")
        raise typer.Exit(0)

    entries = sorted(playbook_dir.glob("*.md"))
    # Exclude index.md from the listing
    entries = [e for e in entries if e.stem != "index"]

    if not entries:
        print_info("No playbook entries yet. Run `forge analyze` to generate entries from incident patterns.")
        return

    table = Table(title="Forge Playbook", show_lines=False, padding=(0, 1))
    table.add_column("Entry", style="cyan")
    table.add_column("File", style="dim")

    for entry in entries:
        # Use stem as the display name, replace hyphens with spaces and title-case
        name = entry.stem.replace("-", " ").title()
        table.add_row(name, entry.name)

    console.print(table)
    print_info(f"\nUse `forge playbook show <name>` to view an entry.")


@playbook_app.command()
def show(
    name: str = typer.Argument(help="Playbook entry name (e.g., 'silent-fallback' or 'hallucination')"),
) -> None:
    """Show a specific playbook entry."""
    try:
        cfg = load_config()
    except FileNotFoundError as e:
        print_error(str(e))
        raise typer.Exit(1)

    playbook_dir = cfg.playbook_dir
    if not playbook_dir.exists():
        print_error("Playbook directory not found.")
        raise typer.Exit(1)

    # Try exact match first, then partial match
    target = playbook_dir / f"{name}.md"
    if not target.exists():
        # Search for partial match
        matches = [f for f in playbook_dir.glob("*.md") if name.lower() in f.stem.lower() and f.stem != "index"]
        if len(matches) == 1:
            target = matches[0]
        elif len(matches) > 1:
            print_error(f"Ambiguous name '{name}'. Matches: {', '.join(m.stem for m in matches)}")
            raise typer.Exit(1)
        else:
            print_error(f"No playbook entry matching '{name}'.")
            raise typer.Exit(1)

    content = target.read_text()
    console.print(Panel(content, title=target.stem.replace("-", " ").title(), border_style="cyan"))
