from __future__ import annotations

import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from typing import Optional

import typer
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
    AmbiguousIncidentLookupError,
    DuplicateIncidentError,
    find_incident,
    find_incident_path,
    generate_id,
    get_all_incidents,
    list_incidents,
    load_incident,
    save_incident,
)
from forge_cli.models import (
    CAPABILITY_AREA_VALUES,
    ISSUE_CLASS_VALUES,
    LIFECYCLE_STAGE_VALUES,
    PROOFHOUSE_REF_FIELDS,
    USE_CLASS_VALUES,
    WORKFLOW_ARCHETYPE_VALUES,
    FailureType,
    Incident,
    Severity,
    parse_observed_state,
    parse_pointer_value,
)
from forge_cli.analyzer import (
    analyze_incidents,
    next_analysis_output_path,
    render_analysis_prompt,
    serialize_incidents_for_analysis,
)

app = typer.Typer(
    name="forge",
    help="Git-native incident tracking and pattern analysis for AI agents",
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


def _validate_optional_choice(field_name: str, value: str | None, choices: list[str]) -> str:
    if not value:
        return ""
    if value not in choices:
        print_error(f"Invalid {field_name} '{value}'. Must be one of: {', '.join(choices)}")
        raise typer.Exit(1)
    return value


def _parse_optional_ref(field_name: str, value: str | None) -> dict | None:
    try:
        return parse_pointer_value(value, field_name)
    except (TypeError, ValueError) as e:
        print_error(str(e))
        raise typer.Exit(1)


def _parse_optional_observed_state(value: str | None) -> dict | None:
    try:
        return parse_observed_state(value)
    except (TypeError, ValueError) as e:
        print_error(str(e))
        raise typer.Exit(1)


@app.command()
def log(
    project: Optional[str] = typer.Option(None, "--project", "-p", help="Project name"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Severity level"),
    failure_type: Optional[str] = typer.Option(None, "--type", "-t", help="Failure type"),
    agent: Optional[str] = typer.Option(None, "--agent", "-a", help="Agent or component name"),
    platform: Optional[str] = typer.Option(None, "--platform", "-P", help="AI tool/platform"),
    capability_area: Optional[str] = typer.Option(
        None,
        "--capability-area",
        help="Proofhouse owner area involved in the incident",
    ),
    lifecycle_stage: Optional[str] = typer.Option(
        None,
        "--lifecycle-stage",
        help="Proofhouse lifecycle stage involved in the incident",
    ),
    issue_class: Optional[str] = typer.Option(
        None,
        "--issue-class",
        help="Structured issue class, for example redaction_miss or rights_ambiguity",
    ),
    workflow_archetype: Optional[str] = typer.Option(
        None,
        "--workflow-archetype",
        help="Workflow archetype, for example document_operations",
    ),
    subject_type: Optional[str] = typer.Option(
        None,
        "--subject-type",
        help="Subject class, for example document_packet",
    ),
    blocked_use_class: Optional[str] = typer.Option(
        None,
        "--blocked-use-class",
        help="Use class blocked by the incident, if any",
    ),
    observed_state: Optional[str] = typer.Option(
        None,
        "--observed-state",
        help="Incident-local JSON object or summary; do not copy canonical state",
    ),
    workflow_ref: Optional[str] = typer.Option(
        None,
        "--workflow-ref",
        help="WorkflowRef pointer as JSON object or ref id",
    ),
    evidence_ref: Optional[str] = typer.Option(
        None,
        "--evidence-ref",
        help="EvidenceRef pointer as JSON object or ref id",
    ),
    workflow_evidence_snapshot: Optional[str] = typer.Option(
        None,
        "--workflow-evidence-snapshot",
        help="WorkflowEvidenceSnapshot pointer as JSON object or snapshot id",
    ),
    subject_ref: Optional[str] = typer.Option(
        None,
        "--subject-ref",
        help="SubjectRef pointer as JSON object or ref id",
    ),
    assessment_ref: Optional[str] = typer.Option(
        None,
        "--assessment-ref",
        help="AssessmentRef pointer as JSON object or ref id",
    ),
    policy_decision_ref: Optional[str] = typer.Option(
        None,
        "--policy-decision-ref",
        help="PolicyDecisionRef pointer as JSON object or ref id",
    ),
    use_approval_ref: Optional[str] = typer.Option(
        None,
        "--use-approval-ref",
        help="UseApprovalRef pointer as JSON object or ref id",
    ),
    asset_ref: Optional[str] = typer.Option(
        None,
        "--asset-ref",
        help="AssetRef pointer as JSON object or ref id",
    ),
    derivation_ref: Optional[str] = typer.Option(
        None,
        "--derivation-ref",
        help="DerivationRef pointer as JSON object or ref id",
    ),
    transform_ref: Optional[str] = typer.Option(
        None,
        "--transform-ref",
        help="TransformRef pointer as JSON object or ref id",
    ),
    playbook_entry: Optional[str] = typer.Option(
        None,
        "--playbook-entry",
        help="Known playbook entry slug",
    ),
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

    capability_area = _validate_optional_choice(
        "capability_area", capability_area, CAPABILITY_AREA_VALUES
    )
    lifecycle_stage = _validate_optional_choice(
        "lifecycle_stage", lifecycle_stage, LIFECYCLE_STAGE_VALUES
    )
    issue_class = _validate_optional_choice("issue_class", issue_class, ISSUE_CLASS_VALUES)
    workflow_archetype = _validate_optional_choice(
        "workflow_archetype", workflow_archetype, WORKFLOW_ARCHETYPE_VALUES
    )
    blocked_use_class = _validate_optional_choice(
        "blocked_use_class", blocked_use_class, USE_CLASS_VALUES
    )

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

    pointer_refs = {
        field_name: _parse_optional_ref(field_name, value)
        for field_name, value in {
            "workflow_ref": workflow_ref,
            "evidence_ref": evidence_ref,
            "workflow_evidence_snapshot": workflow_evidence_snapshot,
            "subject_ref": subject_ref,
            "assessment_ref": assessment_ref,
            "policy_decision_ref": policy_decision_ref,
            "use_approval_ref": use_approval_ref,
            "asset_ref": asset_ref,
            "derivation_ref": derivation_ref,
            "transform_ref": transform_ref,
        }.items()
        if field_name in PROOFHOUSE_REF_FIELDS
    }

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
        playbook_entry=playbook_entry or "",
        capability_area=capability_area,
        lifecycle_stage=lifecycle_stage,
        issue_class=issue_class,
        workflow_archetype=workflow_archetype or "",
        subject_type=subject_type or "",
        blocked_use_class=blocked_use_class,
        observed_state=_parse_optional_observed_state(observed_state),
        **pointer_refs,
    )

    # Confirm
    console.print()
    display_incident_panel(incident)
    console.print()

    if not typer.confirm("Save this incident?", default=True):
        print_info("Incident discarded.")
        raise typer.Exit(0)

    try:
        filepath = save_incident(incident, cfg.incidents_dir)
    except DuplicateIncidentError as e:
        print_error(str(e))
        raise typer.Exit(1)
    print_success(f"Saved: {filepath}")


@app.command("list")
def list_cmd(
    project: Optional[str] = typer.Option(None, "--project", "-p", help="Filter by project"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by severity"),
    since: Optional[str] = typer.Option(None, "--since", help="Filter by date (YYYY-MM-DD)"),
    tag: Optional[str] = typer.Option(None, "--tag", "-T", help="Filter by tag"),
    issue_class: Optional[str] = typer.Option(None, "--issue-class", help="Filter by issue class"),
    capability_area: Optional[str] = typer.Option(
        None, "--capability-area", help="Filter by capability area"
    ),
    lifecycle_stage: Optional[str] = typer.Option(
        None, "--lifecycle-stage", help="Filter by lifecycle stage"
    ),
    workflow_archetype: Optional[str] = typer.Option(
        None, "--workflow-archetype", help="Filter by workflow archetype"
    ),
    blocked_use_class: Optional[str] = typer.Option(
        None, "--blocked-use-class", help="Filter by blocked use class"
    ),
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
        tag=tag,
        issue_class=issue_class,
        capability_area=capability_area,
        lifecycle_stage=lifecycle_stage,
        workflow_archetype=workflow_archetype,
        blocked_use_class=blocked_use_class,
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

    try:
        incident = find_incident(cfg.incidents_dir, incident_id)
    except AmbiguousIncidentLookupError as e:
        print_error(str(e))
        raise typer.Exit(1)
    if incident is None:
        print_error(f"No incident found matching '{incident_id}'.")
        raise typer.Exit(1)

    display_incident_detail(incident)


@app.command("ref")
def ref_cmd(
    incident_id: str = typer.Argument(help="Incident ID (e.g., '2026-03-04-001' or '001')"),
    compact: bool = typer.Option(False, "--compact", help="Print single-line JSON"),
) -> None:
    """Print the Proofhouse IncidentRef projection for a single incident."""
    try:
        cfg = load_config()
    except FileNotFoundError as e:
        print_error(str(e))
        raise typer.Exit(1)

    try:
        incident = find_incident(cfg.incidents_dir, incident_id)
    except AmbiguousIncidentLookupError as e:
        print_error(str(e))
        raise typer.Exit(1)
    if incident is None:
        print_error(f"No incident found matching '{incident_id}'.")
        raise typer.Exit(1)

    indent = None if compact else 2
    typer.echo(json.dumps(incident.to_ref_envelope(), indent=indent))


@app.command()
def edit(
    incident_id: str = typer.Argument(help="Incident ID (e.g., '2026-03-04-001' or '001')"),
) -> None:
    """Open an incident in $EDITOR for modification."""
    try:
        cfg = load_config()
    except FileNotFoundError as e:
        print_error(str(e))
        raise typer.Exit(1)

    try:
        path = find_incident_path(cfg.incidents_dir, incident_id)
    except AmbiguousIncidentLookupError as e:
        print_error(str(e))
        raise typer.Exit(1)
    if path is None:
        print_error(f"No incident found matching '{incident_id}'.")
        raise typer.Exit(1)

    editor = os.environ.get("EDITOR", "vi")
    console.print(f"[bold]Opening {path.name} in {editor}...[/bold]")

    try:
        subprocess.run([editor, str(path)], check=True)
    except subprocess.CalledProcessError:
        print_error("Editor exited with an error.")
        raise typer.Exit(1)

    # Validate the edited file still parses
    try:
        updated = load_incident(path)
    except Exception as e:
        print_error(f"Edited file has invalid YAML: {e}")
        print_info(f"File is at: {path}")
        raise typer.Exit(1)

    display_incident_detail(updated)
    print_success(f"Updated: {path}")


@app.command()
def analyze(
    since: Optional[str] = typer.Option(None, "--since", help="Analyze incidents since date"),
    full: bool = typer.Option(False, "--full", help="Re-analyze all incidents"),
    provider: Optional[str] = typer.Option(None, "--provider", help="LLM provider (anthropic|openai)"),
    prepare_only: bool = typer.Option(
        False,
        "--prepare-only",
        help="Save the rendered analysis input without calling an LLM",
    ),
) -> None:
    """Run LLM pattern analysis on incidents."""
    try:
        cfg = load_config()
    except FileNotFoundError as e:
        print_error(str(e))
        raise typer.Exit(1)

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
    incidents_yaml = serialize_incidents_for_analysis(all_incidents)
    rendered_prompt = render_analysis_prompt(
        prompt_template,
        incidents_yaml,
        organization_name=cfg.organization_name,
    )

    report_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if prepare_only:
        prompt_path = next_analysis_output_path(
            cfg.analysis_dir,
            date_prefix=report_date,
            label="analysis-input",
        )
        prompt_path.write_text(rendered_prompt)
        print_success(f"Analysis input saved: {prompt_path}")
        print_info(
            f"Prepared {len(all_incidents)} incident(s) from {cfg.incidents_dir} for manual review or use with your preferred LLM."
        )
        raise typer.Exit(0)

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
                organization_name=cfg.organization_name,
            )
        except Exception as e:
            print_error(f"Analysis failed: {e}")
            raise typer.Exit(1)

    # Save report
    report_path = next_analysis_output_path(cfg.analysis_dir, date_prefix=report_date)
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
    issue_class: Optional[str] = typer.Option(None, "--issue-class", help="Filter by issue class"),
    capability_area: Optional[str] = typer.Option(
        None, "--capability-area", help="Filter by capability area"
    ),
    lifecycle_stage: Optional[str] = typer.Option(
        None, "--lifecycle-stage", help="Filter by lifecycle stage"
    ),
    workflow_archetype: Optional[str] = typer.Option(
        None, "--workflow-archetype", help="Filter by workflow archetype"
    ),
    blocked_use_class: Optional[str] = typer.Option(
        None, "--blocked-use-class", help="Filter by blocked use class"
    ),
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
    if issue_class:
        incidents = [i for i in incidents if i.issue_class == issue_class]
    if capability_area:
        incidents = [i for i in incidents if i.capability_area == capability_area]
    if lifecycle_stage:
        incidents = [i for i in incidents if i.lifecycle_stage == lifecycle_stage]
    if workflow_archetype:
        incidents = [i for i in incidents if i.workflow_archetype == workflow_archetype]
    if blocked_use_class:
        incidents = [i for i in incidents if i.blocked_use_class == blocked_use_class]

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
    print_info("\nUse `forge playbook show <name>` to view an entry.")


@playbook_app.command("show")
def playbook_show(
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


# --- MCP subcommand ---

mcp_app = typer.Typer(
    name="mcp",
    help="Run Forge over MCP transports",
)
app.add_typer(mcp_app, name="mcp")


@mcp_app.command("serve")
def mcp_serve(
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help="Bind host. Defaults to loopback for local-only access.",
    ),
    port: int = typer.Option(
        8765,
        "--port",
        help="Bind port for the Streamable HTTP server.",
    ),
    allow_remote: bool = typer.Option(
        False,
        "--allow-remote",
        help="Allow binding to a non-loopback host on a trusted network.",
    ),
    disable_dns_rebinding_protection: bool = typer.Option(
        False,
        "--disable-dns-rebinding-protection",
        help="Disable DNS rebinding protection for trusted private-network deployments.",
    ),
) -> None:
    """Serve Forge over MCP Streamable HTTP."""
    try:
        from forge_cli.mcp_http import (
            MCPHTTPServerOptions,
            serve_mcp_http,
            validate_server_options,
        )
    except ImportError as e:
        print_error(
            f"{e}. Install MCP server dependencies with `pip install -e \".[mcp]\"`."
        )
        raise typer.Exit(1)

    options = MCPHTTPServerOptions(
        host=host,
        port=port,
        allow_remote=allow_remote,
        disable_dns_rebinding_protection=disable_dns_rebinding_protection,
    )

    try:
        validate_server_options(options)
        if disable_dns_rebinding_protection:
            print_info(
                "DNS rebinding protection is disabled. Only do this on a network you explicitly trust."
            )
        print_info(f"Starting Forge MCP HTTP server on http://{host}:{port}/mcp")
        serve_mcp_http(options)
    except ValueError as e:
        print_error(str(e))
        raise typer.Exit(1)
