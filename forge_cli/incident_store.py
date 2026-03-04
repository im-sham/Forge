from __future__ import annotations

from datetime import date, datetime
from pathlib import Path

import yaml

from forge_cli.models import INCIDENT_FIELD_ORDER, Incident


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

    # Build ordered dict matching template field layout
    data = {}
    for key in INCIDENT_FIELD_ORDER:
        data[key] = getattr(incident, key)

    with open(filepath, "w") as f:
        yaml.dump(data, f, Dumper=_BlockDumper, default_flow_style=False, allow_unicode=True)

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

        incidents.append(incident)
        if len(incidents) >= limit:
            break

    return incidents


def find_incident(incidents_dir: Path, incident_id: str) -> Incident | None:
    """Find an incident by ID (exact or suffix match)."""
    # Try exact match first: derive path from ID (e.g., 2026-03-04-001 -> 2026-03/2026-03-04-001.yml)
    parts = incident_id.split("-")
    if len(parts) >= 3:
        month_prefix = f"{parts[0]}-{parts[1]}"
        exact_path = incidents_dir / month_prefix / f"{incident_id}.yml"
        if exact_path.exists():
            return load_incident(exact_path)

    # Fallback: search all files for suffix match (e.g., "001" matches "2026-03-04-001")
    for filepath in incidents_dir.rglob("*.yml"):
        if incident_id in filepath.stem:
            try:
                return load_incident(filepath)
            except Exception:
                continue

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
