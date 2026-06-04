from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, datetime
import fcntl
import json
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


INCIDENT_INDEX_VERSION = 1
INCIDENT_INDEX_FILENAME = ".forge_incident_index.json"
INCIDENT_INDEX_LOCK_FILENAME = ".forge_incident_index.lock"


@dataclass(frozen=True)
class IncidentIndexEntry:
    id: str
    timestamp: str
    project: str
    severity: str
    failure_type: str
    platform: str
    tags: list[str]
    path: str
    issue_class: str = ""
    capability_area: str = ""
    lifecycle_stage: str = ""
    workflow_archetype: str = ""
    blocked_use_class: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> IncidentIndexEntry:
        return cls(
            id=str(data.get("id", "")),
            timestamp=str(data.get("timestamp", "")),
            project=str(data.get("project", "")),
            severity=str(data.get("severity", "")),
            failure_type=str(data.get("failure_type", "")),
            platform=str(data.get("platform", "")),
            tags=list(data.get("tags", []) or []),
            path=str(data.get("path", "")),
            issue_class=str(data.get("issue_class", "")),
            capability_area=str(data.get("capability_area", "")),
            lifecycle_stage=str(data.get("lifecycle_stage", "")),
            workflow_archetype=str(data.get("workflow_archetype", "")),
            blocked_use_class=str(data.get("blocked_use_class", "")),
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "project": self.project,
            "severity": self.severity,
            "failure_type": self.failure_type,
            "platform": self.platform,
            "tags": self.tags,
            "path": self.path,
            "issue_class": self.issue_class,
            "capability_area": self.capability_area,
            "lifecycle_stage": self.lifecycle_stage,
            "workflow_archetype": self.workflow_archetype,
            "blocked_use_class": self.blocked_use_class,
        }

    def to_incident_summary(self) -> Incident:
        return Incident(
            id=self.id,
            timestamp=self.timestamp,
            reported_by="",
            project=self.project,
            agent="",
            platform=self.platform,
            severity=self.severity,
            failure_type=self.failure_type,
            expected_behavior="",
            actual_behavior="",
            context="",
            root_cause="",
            immediate_fix="",
            systemic_takeaway="",
            tags=list(self.tags),
            issue_class=self.issue_class,
            capability_area=self.capability_area,
            lifecycle_stage=self.lifecycle_stage,
            workflow_archetype=self.workflow_archetype,
            blocked_use_class=self.blocked_use_class,
        )


@dataclass(frozen=True)
class IncidentStats:
    total: int
    by_severity: dict[str, int]
    by_type: dict[str, int]
    by_project: dict[str, int]
    by_platform: dict[str, int]
    by_issue_class: dict[str, int]
    by_capability_area: dict[str, int]
    by_tag: dict[str, int]


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

    _upsert_index_entry(incidents_dir, _entry_from_incident(incident, filepath, incidents_dir))
    return filepath


def save_generated_incident(
    incident: Incident,
    incidents_dir: Path,
    *,
    max_attempts: int = 1000,
) -> Path:
    """Assign a dated incident ID and save, retrying on concurrent duplicates."""
    incident_date = datetime.fromisoformat(
        incident.timestamp.replace("Z", "+00:00")
    ).date()
    for _ in range(max_attempts):
        incident.id = generate_id(incidents_dir, incident_date)
        try:
            return save_incident(incident, incidents_dir)
        except DuplicateIncidentError:
            continue
    raise DuplicateIncidentError(
        f"Could not allocate unique incident id for date {incident_date.isoformat()}"
    )


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
    entries = _filter_index_entries(
        _index_entries(incidents_dir),
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
    incidents: list[Incident] = []
    for entry in entries:
        filepath = incidents_dir / entry.path
        try:
            incident = load_incident(filepath)
        except Exception:
            continue
        incidents.append(incident)

    return incidents


def find_incident_path(incidents_dir: Path, incident_id: str) -> Path | None:
    """Find the file path for an incident by ID (exact or suffix match)."""
    parts = incident_id.split("-")
    if len(parts) >= 3:
        month_prefix = f"{parts[0]}-{parts[1]}"
        exact_path = incidents_dir / month_prefix / f"{incident_id}.yml"
        if exact_path.exists():
            return exact_path

    matches = [
        incidents_dir / entry.path
        for entry in _index_entries(incidents_dir)
        if entry.id.endswith(incident_id)
    ]
    matches = sorted(path for path in matches if path.exists())
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


def list_incident_summaries(
    incidents_dir: Path,
    project: str | None = None,
    severity: str | None = None,
    since: str | None = None,
    issue_class: str | None = None,
    capability_area: str | None = None,
    lifecycle_stage: str | None = None,
    workflow_archetype: str | None = None,
    blocked_use_class: str | None = None,
) -> list[Incident]:
    """Return index-backed summary incidents for aggregate displays."""
    return [
        entry.to_incident_summary()
        for entry in _filter_index_entries(
            _index_entries(incidents_dir),
            project=project,
            severity=severity,
            since=since,
            issue_class=issue_class,
            capability_area=capability_area,
            lifecycle_stage=lifecycle_stage,
            workflow_archetype=workflow_archetype,
            blocked_use_class=blocked_use_class,
            limit=None,
        )
    ]


def get_incident_stats(
    incidents_dir: Path,
    project: str | None = None,
    severity: str | None = None,
    issue_class: str | None = None,
    capability_area: str | None = None,
) -> IncidentStats:
    """Aggregate incident stats from the compact incident index."""
    entries = _filter_index_entries(
        _index_entries(incidents_dir),
        project=project,
        severity=severity,
        issue_class=issue_class,
        capability_area=capability_area,
        limit=None,
    )
    return IncidentStats(
        total=len(entries),
        by_severity=_sorted_counter(entry.severity for entry in entries if entry.severity),
        by_type=_sorted_counter(entry.failure_type for entry in entries if entry.failure_type),
        by_project=_sorted_counter(entry.project for entry in entries if entry.project),
        by_platform=_sorted_counter(entry.platform for entry in entries if entry.platform),
        by_issue_class=_sorted_counter(
            entry.issue_class for entry in entries if entry.issue_class
        ),
        by_capability_area=_sorted_counter(
            entry.capability_area for entry in entries if entry.capability_area
        ),
        by_tag=_sorted_counter(tag for entry in entries for tag in entry.tags),
    )


def rebuild_incident_index(incidents_dir: Path) -> list[IncidentIndexEntry]:
    with _locked_index(incidents_dir):
        return _rebuild_incident_index_unlocked(incidents_dir)


def _rebuild_incident_index_unlocked(incidents_dir: Path) -> list[IncidentIndexEntry]:
    entries: list[IncidentIndexEntry] = []
    for filepath in sorted(incidents_dir.rglob("*.yml")):
        try:
            incident = load_incident(filepath)
        except Exception:
            continue
        entries.append(_entry_from_incident(incident, filepath, incidents_dir))
    entries = _sort_index_entries(entries)
    _write_index(incidents_dir, entries)
    return entries


def _index_entries(incidents_dir: Path) -> list[IncidentIndexEntry]:
    loaded = _load_index(incidents_dir)
    if loaded is not None:
        return loaded
    return rebuild_incident_index(incidents_dir)


def _index_path(incidents_dir: Path) -> Path:
    return incidents_dir / INCIDENT_INDEX_FILENAME


def _load_index(incidents_dir: Path) -> list[IncidentIndexEntry] | None:
    path = _index_path(incidents_dir)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("version") != INCIDENT_INDEX_VERSION:
            return None
        entries = [IncidentIndexEntry.from_dict(item) for item in payload.get("entries", [])]
    except Exception:
        return None
    return _sort_index_entries(entries)


def _write_index(incidents_dir: Path, entries: list[IncidentIndexEntry]) -> None:
    incidents_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": INCIDENT_INDEX_VERSION,
        "entries": [entry.to_dict() for entry in _sort_index_entries(entries)],
    }
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            dir=incidents_dir,
            prefix=f".{INCIDENT_INDEX_FILENAME}.",
            suffix=".tmp",
            delete=False,
            encoding="utf-8",
        ) as f:
            tmp_path = Path(f.name)
            json.dump(payload, f, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, _index_path(incidents_dir))
        _fsync_directory(incidents_dir)
    finally:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink()


def _upsert_index_entry(incidents_dir: Path, entry: IncidentIndexEntry) -> None:
    with _locked_index(incidents_dir):
        entries = _load_index(incidents_dir)
        if entries is None:
            entries = _rebuild_incident_index_unlocked(incidents_dir)
        entries = [existing for existing in entries if existing.id != entry.id]
        entries.append(entry)
        _write_index(incidents_dir, entries)


def _entry_from_incident(
    incident: Incident, filepath: Path, incidents_dir: Path
) -> IncidentIndexEntry:
    return IncidentIndexEntry(
        id=incident.id,
        timestamp=incident.timestamp,
        project=incident.project,
        severity=incident.severity,
        failure_type=incident.failure_type,
        platform=incident.platform,
        tags=list(incident.tags),
        path=str(filepath.relative_to(incidents_dir)),
        issue_class=incident.issue_class,
        capability_area=incident.capability_area,
        lifecycle_stage=incident.lifecycle_stage,
        workflow_archetype=incident.workflow_archetype,
        blocked_use_class=incident.blocked_use_class,
    )


def _filter_index_entries(
    entries: list[IncidentIndexEntry],
    *,
    project: str | None = None,
    severity: str | None = None,
    since: str | None = None,
    tag: str | None = None,
    issue_class: str | None = None,
    capability_area: str | None = None,
    lifecycle_stage: str | None = None,
    workflow_archetype: str | None = None,
    blocked_use_class: str | None = None,
    limit: int | None = 10,
) -> list[IncidentIndexEntry]:
    filtered: list[IncidentIndexEntry] = []
    for entry in _sort_index_entries(entries):
        if project and entry.project != project:
            continue
        if severity and entry.severity != severity:
            continue
        if since and entry.timestamp < since:
            continue
        if tag and tag not in entry.tags:
            continue
        if issue_class and entry.issue_class != issue_class:
            continue
        if capability_area and entry.capability_area != capability_area:
            continue
        if lifecycle_stage and entry.lifecycle_stage != lifecycle_stage:
            continue
        if workflow_archetype and entry.workflow_archetype != workflow_archetype:
            continue
        if blocked_use_class and entry.blocked_use_class != blocked_use_class:
            continue
        filtered.append(entry)
        if limit is not None and len(filtered) >= limit:
            break
    return filtered


def _sort_index_entries(entries: list[IncidentIndexEntry]) -> list[IncidentIndexEntry]:
    return sorted(entries, key=lambda entry: (entry.timestamp, entry.id), reverse=True)


def _sorted_counter(values) -> dict[str, int]:
    counter = Counter(values)
    return dict(counter.most_common())


def _fsync_directory(path: Path) -> None:
    try:
        directory_fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(directory_fd)
    except OSError:
        return
    finally:
        os.close(directory_fd)


@contextmanager
def _locked_index(incidents_dir: Path):
    incidents_dir.mkdir(parents=True, exist_ok=True)
    lock_path = incidents_dir / INCIDENT_INDEX_LOCK_FILENAME
    with lock_path.open("a+", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
