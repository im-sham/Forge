from __future__ import annotations

from datetime import date, datetime
import os
from pathlib import Path
import tempfile

import yaml

from forge_cli.models import Incident


# --- Custom YAML dumper that uses block scalars for multiline strings ---


class _BlockDumper(yaml.Dumper):
    pass


def _str_representer(dumper: yaml.Dumper, data: str) -> yaml.ScalarNode:
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


def _ordered_dict_representer(dumper: yaml.Dumper, data: dict) -> yaml.MappingNode:
    """Preserve insertion order of dict keys."""
    return dumper.represent_mapping("tag:yaml.org,2002:map", data.items())


_BlockDumper.add_representer(str, _str_representer)
_BlockDumper.add_representer(dict, _ordered_dict_representer)


# --- ID generation ---


class DuplicateIncidentError(FileExistsError):
    """Raised when saving would overwrite an existing incident file."""


class AmbiguousIncidentLookupError(LookupError):
    """Raised when a suffix lookup matches multiple incidents."""


def generate_id(incidents_dir: Path, incident_date: date | None = None) -> str:
    """Generate the next incident ID for the given date (YYYY-MM-DD-NNN)."""
    if incident_date is None:
        incident_date = date.today()

    month_dir = incidents_dir / incident_date.strftime("%Y-%m")
    prefix = incident_date.strftime("%Y-%m-%d")

    if month_dir.exists():
        existing = sorted(month_dir.glob(f"{prefix}-*.yml"))
        if existing:
            last_seq = int(existing[-1].stem.split("-")[-1])
            return f"{prefix}-{last_seq + 1:03d}"

    return f"{prefix}-001"


# --- File I/O ---


def save_incident(incident: Incident, incidents_dir: Path) -> Path:
    """Write an incident as a YAML file. Returns the file path."""
    incident_date = datetime.fromisoformat(incident.timestamp).date()
    month_dir = incidents_dir / incident_date.strftime("%Y-%m")
    month_dir.mkdir(parents=True, exist_ok=True)

    filepath = month_dir / f"{incident.id}.yml"

    data = incident.to_dict()

    if filepath.exists():
        raise DuplicateIncidentError(f"Incident id already exists: {incident.id}")

    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            dir=month_dir,
            prefix=f".{incident.id}.",
            suffix=".tmp",
            delete=False,
        ) as f:
            tmp_path = Path(f.name)
            yaml.dump(data, f, Dumper=_BlockDumper, default_flow_style=False, allow_unicode=True)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(tmp_path, filepath)
        except FileExistsError as exc:
            raise DuplicateIncidentError(f"Incident id already exists: {incident.id}") from exc
    finally:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink()

    return filepath


def load_incident(path: Path) -> Incident:
    """Load a single incident from a YAML file."""
    with open(path) as f:
        data = yaml.safe_load(f)
    return Incident.from_dict(data)


def list_incidents(
    incidents_dir: Path,
    project: str | None = None,
    severity: str | None = None,
    since: str | None = None,
    tag: str | None = None,
    issue_class: str | None = None,
    capability_area: str | None = None,
    lifecycle_stage: str | None = None,
    workflow_archetype: str | None = None,
    blocked_use_class: str | None = None,
    limit: int = 10,
) -> list[Incident]:
    """List incidents with optional filtering, most recent first."""
    all_files = sorted(incidents_dir.rglob("*.yml"), reverse=True)

    # Exclude template-like files (e.g., .gitkeep won't match *.yml)
    incidents: list[Incident] = []
    for filepath in all_files:
        try:
            incident = load_incident(filepath)
        except Exception:
            continue

        if project and incident.project != project:
            continue
        if severity and incident.severity != severity:
            continue
        if since and incident.timestamp < since:
            continue
        if tag and tag not in incident.tags:
            continue
        if issue_class and incident.issue_class != issue_class:
            continue
        if capability_area and incident.capability_area != capability_area:
            continue
        if lifecycle_stage and incident.lifecycle_stage != lifecycle_stage:
            continue
        if workflow_archetype and incident.workflow_archetype != workflow_archetype:
            continue
        if blocked_use_class and incident.blocked_use_class != blocked_use_class:
            continue

        incidents.append(incident)
        if len(incidents) >= limit:
            break

    return incidents


def find_incident_path(incidents_dir: Path, incident_id: str) -> Path | None:
    """Find the file path for an incident by ID (exact or suffix match)."""
    parts = incident_id.split("-")
    if len(parts) >= 3:
        month_prefix = f"{parts[0]}-{parts[1]}"
        exact_path = incidents_dir / month_prefix / f"{incident_id}.yml"
        if exact_path.exists():
            return exact_path

    matches = sorted(filepath for filepath in incidents_dir.rglob("*.yml") if filepath.stem.endswith(incident_id))
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        ids = ", ".join(match.stem for match in matches)
        raise AmbiguousIncidentLookupError(f"Ambiguous incident id '{incident_id}'. Matches: {ids}")

    return None


def find_incident(incidents_dir: Path, incident_id: str) -> Incident | None:
    """Find an incident by ID (exact or suffix match)."""
    path = find_incident_path(incidents_dir, incident_id)
    if path is None:
        return None
    try:
        return load_incident(path)
    except Exception:
        return None


def get_all_incidents(incidents_dir: Path) -> list[Incident]:
    """Load all incidents, oldest first (for analysis)."""
    all_files = sorted(incidents_dir.rglob("*.yml"))
    incidents: list[Incident] = []
    for filepath in all_files:
        try:
            incidents.append(load_incident(filepath))
        except Exception:
            continue
    return incidents
