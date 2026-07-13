from __future__ import annotations
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass, field
import errno

from datetime import date, datetime
import os
from pathlib import Path
import re
import secrets
import stat
import sys
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


class UnsafeIncidentPathError(OSError):
    """Raised when no-follow access cannot safely open an incident path."""


class IncidentLookupCorruptError(LookupError):
    """Raised when the requested exact or suffix candidate is corrupt."""


class IncidentLookupIncompleteError(LookupError):
    """Raised when operational scan errors prevent a reliable lookup."""


class IncidentEditConflictError(OSError):
    """Raised when the corpus target changed during a staged edit."""


class InvalidIncidentEditError(ValueError):
    """Raised when an editor stage is unsafe or does not contain a valid incident."""


class AtomicRenameUnsupportedError(OSError):
    """Raised when the platform lacks a safe atomic no-replace rename."""


class QuarantineSourceChangedError(OSError):
    """Raised when a quarantine candidate is no longer freshly corrupt."""

class RecoverablePartialStateError(OSError):
    """Indicates recovery state remains after an incomplete operation."""

    def __init__(
        self,
        *,
        primary_error: OSError | None = None,
        moved: bool = False,
    ) -> None:
        super().__init__()
        if (
            isinstance(primary_error, RecoverablePartialStateError)
            and primary_error.primary_error is not None
        ):
            primary_error = primary_error.primary_error
        self.primary_error = primary_error
        self.moved = moved


@dataclass(frozen=True)
class IncidentLoadError:
    """Safe diagnostic for an incident file that could not be loaded."""

    path: str
    error_type: str
    _relative_path: str | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class IncidentScanResult:
    """Incident results with explicit corpus, match, return, and error scopes."""

    incidents: tuple[Incident, ...]
    errors: tuple[IncidentLoadError, ...]
    scan_errors: tuple[IncidentLoadError, ...]
    valid_corpus_count: int
    matched_count: int

    @property
    def corrupt_corpus_count(self) -> int:
        return len(self.errors)

    @property
    def returned_count(self) -> int:
        return len(self.incidents)


@dataclass(frozen=True)
class QuarantineResult:
    """Sanitized result of an explicit corrupt-file quarantine operation."""

    scan: IncidentScanResult
    moved: tuple[str, ...] = ()
    partial: tuple[str, ...] = ()
    failures: tuple[IncidentLoadError, ...] = ()


def generate_id(incidents_dir: Path, incident_date: date | None = None) -> str:
    """Read the next dated ID without creating corpus directories."""
    if incident_date is None:
        incident_date = date.today()
    month_name = incident_date.strftime("%Y-%m")
    prefix = incident_date.strftime("%Y-%m-%d")
    pattern = re.compile(rf"{re.escape(prefix)}-(\d{{3,}})\.yml")
    maximum = 0
    try:
        root_fd = _open_nofollow(incidents_dir, directory=True)
    except FileNotFoundError:
        return f"{prefix}-001"
    try:
        try:
            month_fd = _open_nofollow(month_name, directory=True, dir_fd=root_fd)
        except FileNotFoundError:
            return f"{prefix}-001"
        try:
            for name in os.listdir(month_fd):
                match = pattern.fullmatch(name)
                if match:
                    maximum = max(maximum, int(match.group(1)))
        finally:
            os.close(month_fd)
    finally:
        os.close(root_fd)
    return f"{prefix}-{maximum + 1:03d}"


# --- File I/O ---


def save_incident(incident: Incident, incidents_dir: Path) -> Path:
    """Atomically publish an incident through verified directory descriptors."""
    incident_date = datetime.fromisoformat(incident.timestamp).date()
    month_name = incident_date.strftime("%Y-%m")
    target_name = f"{incident.id}.yml"
    if Path(target_name).name != target_name or target_name in {".", ".."}:
        raise ValueError("Incident id is not safe for a corpus filename")
    incidents_dir.mkdir(parents=True, exist_ok=True)
    root_fd = _open_nofollow(incidents_dir, directory=True)
    month_fd: int | None = None
    temporary_name: str | None = None
    temporary_fd: int | None = None
    try:
        try:
            month_fd = _open_nofollow(month_name, directory=True, dir_fd=root_fd)
        except FileNotFoundError:
            try:
                os.mkdir(month_name, 0o755, dir_fd=root_fd)
            except FileExistsError:
                pass
            month_fd = _open_nofollow(month_name, directory=True, dir_fd=root_fd)

        payload = yaml.dump(
            incident.to_dict(),
            Dumper=_BlockDumper,
            default_flow_style=False,
            allow_unicode=True,
        ).encode()
        for _ in range(100):
            candidate = f".{incident.id}.{secrets.token_hex(8)}.tmp"
            try:
                temporary_fd = os.open(
                    candidate,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=month_fd,
                )
            except FileExistsError:
                continue
            temporary_name = candidate
            break
        if temporary_fd is None or temporary_name is None:
            raise FileExistsError("Could not create an incident publication file")
        _write_all(temporary_fd, payload)
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = None
        try:
            os.link(
                temporary_name,
                target_name,
                src_dir_fd=month_fd,
                dst_dir_fd=month_fd,
                follow_symlinks=False,
            )
        except FileExistsError as exc:
            raise DuplicateIncidentError(
                f"Incident id already exists: {incident.id}"
            ) from exc
        os.fsync(month_fd)
    finally:
        if temporary_fd is not None:
            os.close(temporary_fd)
        if temporary_name is not None and month_fd is not None:
            try:
                os.unlink(temporary_name, dir_fd=month_fd)
            except FileNotFoundError:
                pass
        if month_fd is not None:
            os.close(month_fd)
        os.close(root_fd)
    return incidents_dir / month_name / target_name


def save_generated_incident(
    incident: Incident,
    incidents_dir: Path,
    *,
    max_attempts: int = 100,
) -> Path:
    """Assign a human-readable dated ID and save with bounded collision retries."""
    if max_attempts <= 0:
        raise ValueError("max_attempts must be positive")
    incident_date = datetime.fromisoformat(incident.timestamp.replace("Z", "+00:00")).date()
    for _ in range(max_attempts):
        incident.id = generate_id(incidents_dir, incident_date)
        try:
            return save_incident(incident, incidents_dir)
        except DuplicateIncidentError:
            continue
    raise DuplicateIncidentError(
        f"Could not allocate a unique incident id for {incident_date.isoformat()} "
        f"after {max_attempts} attempts"
    )


def _require_nofollow_flags(*, directory: bool = False) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise UnsafeIncidentPathError(
            "Safe incident access requires POSIX O_NOFOLLOW support"
        )
    flags = os.O_RDONLY | nofollow
    if directory:
        directory_flag = getattr(os, "O_DIRECTORY", 0)
        if not directory_flag:
            raise UnsafeIncidentPathError(
                "Safe incident access requires POSIX O_DIRECTORY support"
            )
        flags |= directory_flag
    else:
        flags |= getattr(os, "O_NONBLOCK", 0)
    return flags


def _open_nofollow(
    path: str | os.PathLike[str],
    *,
    directory: bool = False,
    dir_fd: int | None = None,
) -> int:
    flags = _require_nofollow_flags(directory=directory)
    try:
        fd = os.open(path, flags, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.EMLINK} or (
            directory and exc.errno == errno.ENOTDIR
        ):
            raise UnsafeIncidentPathError(
                "Incident directory path is a symlink or non-directory"
            ) from exc
        raise
    mode = os.fstat(fd).st_mode
    expected = stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)
    if not expected:
        os.close(fd)
        kind = "directory" if directory else "regular file"
        raise UnsafeIncidentPathError(f"Incident path is not a {kind}")
    return fd


def _load_incident_fd(fd: int) -> Incident:
    with os.fdopen(os.dup(fd)) as file:
        data = yaml.safe_load(file)
    return Incident.from_dict(data)


def load_open_incident(fd: int) -> Incident:
    """Load an already-open incident descriptor from its current contents."""
    os.lseek(fd, 0, os.SEEK_SET)
    return _load_incident_fd(fd)


def load_incident(path: Path) -> Incident:
    """Load one regular incident file without following its final symlink."""
    fd = _open_nofollow(path)
    try:
        return _load_incident_fd(fd)
    finally:
        os.close(fd)


def _safe_text(value: str) -> str:
    return "".join(character if character.isprintable() else "?" for character in value)


def _safe_relative_path(path: str | os.PathLike[str], incidents_dir: Path) -> str:
    candidate = Path(path)
    try:
        relative = candidate.relative_to(incidents_dir)
    except ValueError:
        relative = Path(candidate.name)
    return _safe_text(relative.as_posix() or ".")


def safe_incident_relative_path(
    path: str | os.PathLike[str],
    incidents_dir: Path,
) -> str:
    """Return a printable incidents-root-relative path without exposing the root."""
    return _safe_relative_path(path, incidents_dir)


def _safe_error_type(exc: BaseException) -> str:
    if isinstance(exc, AtomicRenameUnsupportedError):
        return "UnsupportedOperation"
    if isinstance(exc, UnsafeIncidentPathError):
        return "UnsafeIncidentPathError"
    if isinstance(exc, QuarantineSourceChangedError):
        return "SourceChangedError"
    if isinstance(exc, RecoverablePartialStateError):
        return "RecoverablePartialStateError"
    if isinstance(exc, PermissionError):
        return "PermissionError"
    if isinstance(exc, FileNotFoundError):
        return "FileNotFoundError"
    if isinstance(exc, FileExistsError):
        return "FileExistsError"
    if isinstance(exc, IsADirectoryError):
        return "IsADirectoryError"
    if isinstance(exc, NotADirectoryError):
        return "NotADirectoryError"
    if isinstance(exc, yaml.YAMLError):
        return "YAMLError"
    if isinstance(exc, OSError):
        return "OSError"
    return "InvalidIncidentError"


def safe_storage_error_type(exc: OSError) -> str:
    """Classify a storage error without exposing its message or filename."""
    if (
        isinstance(exc, RecoverablePartialStateError)
        and exc.primary_error is not None
    ):
        return _safe_error_type(exc.primary_error)
    return _safe_error_type(exc)


def storage_error_has_recoverable_partial_state(exc: OSError) -> bool:
    """Return whether an operation left recoverable partial storage state."""
    return isinstance(exc, RecoverablePartialStateError)


@dataclass(frozen=True)
class _IncidentEntry:
    incident: Incident
    relative_path: str
    order_key: tuple


@dataclass(frozen=True)
class _IncidentLookupResult:
    entry: _IncidentEntry | None
    errors: tuple[IncidentLoadError, ...]
    scan_errors: tuple[IncidentLoadError, ...]


_CANONICAL_ID = re.compile(
    r"^(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})-(?P<sequence>\d{3,})$"
)


def _incident_order_key(incident: Incident, relative_path: str) -> tuple:
    """Validate and order canonical IDs or legacy timestamps deterministically."""
    match = _CANONICAL_ID.fullmatch(incident.id)
    if match:
        canonical_date = date(
            int(match["year"]),
            int(match["month"]),
            int(match["day"]),
        )
        return (
            canonical_date,
            0,
            int(match["sequence"]),
            relative_path,
        )
    timestamp = datetime.fromisoformat(incident.timestamp.replace("Z", "+00:00"))
    return (
        timestamp.date(),
        1,
        timestamp.isoformat(),
        relative_path,
    )


def _symlink_error(relative_path: Path) -> IncidentLoadError:
    return IncidentLoadError(
        path=_safe_text(relative_path.as_posix()),
        error_type="SymlinkRejectedError",
    )


def _scan_incident_entries(
    incidents_dir: Path,
) -> tuple[list[_IncidentEntry], list[IncidentLoadError], list[IncidentLoadError]]:
    entries: list[_IncidentEntry] = []
    errors: list[IncidentLoadError] = []
    scan_errors: list[IncidentLoadError] = []

    try:
        root_fd = _open_nofollow(incidents_dir, directory=True)
    except FileNotFoundError:
        return entries, errors, scan_errors
    except Exception as exc:
        scan_errors.append(
            IncidentLoadError(
                path=".",
                error_type=_safe_error_type(exc),
            )
        )
        return entries, errors, scan_errors

    def visit(directory_fd: int, relative_root: Path) -> None:
        try:
            names = sorted(os.listdir(directory_fd))
        except OSError as exc:
            scan_errors.append(
                IncidentLoadError(
                    path=_safe_text(relative_root.as_posix() or "."),
                    error_type=_safe_error_type(exc),
                )
            )
            return

        for name in names:
            relative_path = relative_root / name
            try:
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                scan_errors.append(
                    IncidentLoadError(
                        path=_safe_text(relative_path.as_posix()),
                        error_type=_safe_error_type(exc),
                    )
                )
                continue
            if stat.S_ISLNK(metadata.st_mode):
                scan_errors.append(_symlink_error(relative_path))
                continue
            if stat.S_ISDIR(metadata.st_mode):
                try:
                    child_fd = _open_nofollow(
                        name,
                        directory=True,
                        dir_fd=directory_fd,
                    )
                except UnsafeIncidentPathError:
                    scan_errors.append(_symlink_error(relative_path))
                    continue
                except OSError as exc:
                    scan_errors.append(
                        IncidentLoadError(
                            path=_safe_text(relative_path.as_posix()),
                            error_type=_safe_error_type(exc),
                        )
                    )
                    continue
                try:
                    visit(child_fd, relative_path)
                finally:
                    os.close(child_fd)
                continue
            if Path(name).suffix != ".yml":
                continue
            if not stat.S_ISREG(metadata.st_mode):
                scan_errors.append(
                    IncidentLoadError(
                        path=_safe_text(relative_path.as_posix()),
                        error_type="UnsafeFileTypeError",
                    )
                )
                continue
            try:
                file_fd = _open_nofollow(name, dir_fd=directory_fd)
            except UnsafeIncidentPathError:
                scan_errors.append(_symlink_error(relative_path))
                continue
            except OSError as exc:
                scan_errors.append(
                    IncidentLoadError(
                        path=_safe_text(relative_path.as_posix()),
                        error_type=_safe_error_type(exc),
                    )
                )
                continue
            try:
                try:
                    content = _read_fd_bytes(file_fd)
                except OSError as exc:
                    scan_errors.append(
                        IncidentLoadError(
                            path=_safe_text(relative_path.as_posix()),
                            error_type=_safe_error_type(exc),
                        )
                    )
                    continue
                try:
                    data = yaml.safe_load(content.decode("utf-8"))
                    incident = Incident.from_dict(data)
                    relative_text = relative_path.as_posix()
                    order_key = _incident_order_key(incident, relative_text)
                except Exception as exc:
                    errors.append(
                        IncidentLoadError(
                            path=_safe_text(relative_path.as_posix()),
                            error_type=_safe_error_type(exc),
                            _relative_path=relative_path.as_posix(),
                        )
                    )
                else:
                    entries.append(
                        _IncidentEntry(
                            incident=incident,
                            relative_path=relative_text,
                            order_key=order_key,
                        )
                    )
            finally:
                os.close(file_fd)

    try:
        visit(root_fd, Path())
    finally:
        os.close(root_fd)
    entries.sort(key=lambda entry: entry.order_key)
    return entries, errors, scan_errors


def scan_incidents(incidents_dir: Path) -> IncidentScanResult:
    """Load an oldest-first corpus without writes or symlink traversal."""
    entries, errors, scan_errors = _scan_incident_entries(incidents_dir)
    loaded = tuple(entry.incident for entry in entries)
    return IncidentScanResult(
        incidents=loaded,
        errors=tuple(errors),
        scan_errors=tuple(scan_errors),
        valid_corpus_count=len(loaded),
        matched_count=len(loaded),
    )


def _close_quietly(fd: int | None) -> None:
    if fd is None:
        return
    try:
        os.close(fd)
    except OSError:
        pass


def _open_or_create_directory(name: str, parent_fd: int) -> int:
    if name in {"", ".", ".."} or "/" in name:
        raise UnsafeIncidentPathError("Unsafe quarantine directory component")
    created_metadata: os.stat_result | None = None
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        created_metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        os.fsync(parent_fd)
    except FileExistsError:
        pass

    directory_fd = _open_nofollow(name, directory=True, dir_fd=parent_fd)
    try:
        opened_metadata = os.fstat(directory_fd)
        current_metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        opened_identity = (opened_metadata.st_dev, opened_metadata.st_ino)
        if (
            opened_identity != (current_metadata.st_dev, current_metadata.st_ino)
            or (
                created_metadata is not None
                and opened_identity
                != (created_metadata.st_dev, created_metadata.st_ino)
            )
        ):
            raise UnsafeIncidentPathError(
                "Quarantine directory changed while it was opened"
            )
        return directory_fd
    except BaseException:
        _close_quietly(directory_fd)
        raise


def _open_quarantine_parent(incidents_dir: Path, relative_path: str) -> tuple[int, str]:
    relative = Path(relative_path)
    parts = relative.parts
    if (
        relative.is_absolute()
        or not parts
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise UnsafeIncidentPathError("Unsafe quarantine relative path")
    root_fd = _open_nofollow(incidents_dir.parent, directory=True)
    quarantine_fd: int | None = None
    try:
        quarantine_fd = _open_or_create_directory("quarantine", root_fd)
        for part in parts[:-1]:
            child_fd = _open_or_create_directory(part, quarantine_fd)
            _close_quietly(quarantine_fd)
            quarantine_fd = child_fd
        return quarantine_fd, parts[-1]
    except BaseException:
        _close_quietly(quarantine_fd)
        raise
    finally:
        _close_quietly(root_fd)


def _require_fresh_corrupt_file(
    source_name: str,
    source_parent_fd: int,
) -> tuple[int, os.stat_result, bytes]:
    source_fd = _open_nofollow(source_name, dir_fd=source_parent_fd)
    try:
        before = os.fstat(source_fd)
        content = _read_fd_bytes(source_fd)
        after = os.fstat(source_fd)
        if _stable_metadata(before) != _stable_metadata(after):
            raise QuarantineSourceChangedError()
        try:
            data = yaml.safe_load(content.decode("utf-8"))
            incident = Incident.from_dict(data)
            _incident_order_key(incident, source_name)
        except Exception:
            return source_fd, after, content
    except BaseException:
        _close_quietly(source_fd)
        raise
    _close_quietly(source_fd)
    raise QuarantineSourceChangedError()


def _load_native_rename_noreplace():
    try:
        libc = ctypes.CDLL(None, use_errno=True)
    except OSError:
        return None

    if sys.platform == "darwin":
        function = getattr(libc, "renameatx_np", None)
        flag = 0x00000004  # RENAME_EXCL
    elif sys.platform.startswith("linux"):
        function = getattr(libc, "renameat2", None)
        flag = 0x00000001  # RENAME_NOREPLACE
    else:
        return None
    if function is None:
        return None

    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int

    def rename_noreplace(
        source_parent_fd: int,
        source_name: str,
        destination_parent_fd: int,
        destination_name: str,
    ) -> None:
        ctypes.set_errno(0)
        result = function(
            source_parent_fd,
            os.fsencode(source_name),
            destination_parent_fd,
            os.fsencode(destination_name),
            flag,
        )
        if result == 0:
            return
        error_number = ctypes.get_errno()
        if error_number in {
            errno.ENOSYS,
            errno.EINVAL,
            errno.ENOTSUP,
            errno.EOPNOTSUPP,
        }:
            raise AtomicRenameUnsupportedError()
        raise OSError(error_number, os.strerror(error_number))

    return rename_noreplace


_NATIVE_RENAME_NOREPLACE = _load_native_rename_noreplace()


def _rename_noreplace(
    source_parent_fd: int,
    source_name: str,
    destination_parent_fd: int,
    destination_name: str,
) -> None:
    native_rename = _NATIVE_RENAME_NOREPLACE
    if native_rename is None:
        raise AtomicRenameUnsupportedError()
    native_rename(
        source_parent_fd,
        source_name,
        destination_parent_fd,
        destination_name,
    )


def _restore_changed_quarantine_source(
    source_parent_fd: int,
    source_name: str,
    destination_parent_fd: int,
    destination_name: str,
) -> None:
    source_changed = QuarantineSourceChangedError()
    try:
        _rename_noreplace(
            destination_parent_fd,
            destination_name,
            source_parent_fd,
            source_name,
        )
    except OSError as restore_error:
        raise RecoverablePartialStateError(
            primary_error=source_changed,
            moved=True,
        ) from restore_error
    try:
        os.fsync(source_parent_fd)
        os.fsync(destination_parent_fd)
    except OSError as durability_error:
        try:
            _rename_noreplace(
                source_parent_fd,
                source_name,
                destination_parent_fd,
                destination_name,
            )
        except OSError:
            pass
        raise RecoverablePartialStateError(
            primary_error=source_changed,
            moved=True,
        ) from durability_error
    raise source_changed


def _quarantine_one(incidents_dir: Path, relative_path: str) -> None:
    if _NATIVE_RENAME_NOREPLACE is None:
        raise AtomicRenameUnsupportedError()

    source_parent_fd: int | None = None
    destination_parent_fd: int | None = None
    source_fd: int | None = None
    moved = False
    try:
        source_parent_fd, source_name = _open_incident_parent(
            incidents_dir, relative_path
        )
        source_fd, source_metadata, source_content = _require_fresh_corrupt_file(
            source_name, source_parent_fd
        )
        expected_metadata = _quarantine_metadata(source_metadata)
        destination_parent_fd, destination_name = _open_quarantine_parent(
            incidents_dir, relative_path
        )
        _rename_noreplace(
            source_parent_fd,
            source_name,
            destination_parent_fd,
            destination_name,
        )
        moved = True
        try:
            destination_metadata = os.stat(
                destination_name,
                dir_fd=destination_parent_fd,
                follow_symlinks=False,
            )
            if (
                _quarantine_metadata(destination_metadata) != expected_metadata
                or _read_fd_bytes(source_fd) != source_content
            ):
                _restore_changed_quarantine_source(
                    source_parent_fd,
                    source_name,
                    destination_parent_fd,
                    destination_name,
                )
            os.fsync(destination_parent_fd)
            os.fsync(source_parent_fd)
        except QuarantineSourceChangedError:
            raise
        except RecoverablePartialStateError:
            raise
        except OSError as exc:
            raise RecoverablePartialStateError(
                primary_error=exc,
                moved=True,
            ) from exc
    except QuarantineSourceChangedError:
        raise
    except AtomicRenameUnsupportedError:
        raise
    except RecoverablePartialStateError:
        raise
    except OSError as exc:
        if moved:
            raise RecoverablePartialStateError(
                primary_error=exc,
                moved=True,
            ) from exc
        raise
    finally:
        _close_quietly(source_fd)
        _close_quietly(destination_parent_fd)
        _close_quietly(source_parent_fd)


def quarantine_corrupt_incidents(incidents_dir: Path) -> QuarantineResult:
    """Move freshly revalidated corrupt regular files into a sibling quarantine."""
    scan = scan_incidents(incidents_dir)
    if scan.scan_errors:
        return QuarantineResult(scan=scan)

    moved: list[str] = []
    partial: list[str] = []
    failures: list[IncidentLoadError] = []
    for candidate in scan.errors:
        relative_path = candidate._relative_path
        if relative_path is None:
            failures.append(
                IncidentLoadError(candidate.path, "UnsafeIncidentPathError")
            )
            continue
        try:
            _quarantine_one(incidents_dir, relative_path)
        except OSError as exc:
            if isinstance(exc, RecoverablePartialStateError) and exc.moved:
                partial.append(candidate.path)
            failures.append(
                IncidentLoadError(candidate.path, _safe_error_type(exc))
            )
        else:
            moved.append(candidate.path)
    return QuarantineResult(
        scan=scan,
        moved=tuple(moved),
        partial=tuple(partial),
        failures=tuple(failures),
    )


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
    return list(
        list_incidents_result(
            incidents_dir,
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
        ).incidents
    )


def list_incidents_result(
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
    limit: int | None = 10,
) -> IncidentScanResult:
    """List newest-first incidents with diagnostics for every skipped file."""
    if limit is not None and limit < 0:
        raise ValueError("limit must be non-negative")
    scan = scan_incidents(incidents_dir)
    incidents = [
        incident
        for incident in reversed(scan.incidents)
        if (not project or incident.project == project)
        and (not severity or incident.severity == severity)
        and (not since or incident.timestamp >= since)
        and (not tag or tag in incident.tags)
        and (not issue_class or incident.issue_class == issue_class)
        and (not capability_area or incident.capability_area == capability_area)
        and (not lifecycle_stage or incident.lifecycle_stage == lifecycle_stage)
        and (not workflow_archetype or incident.workflow_archetype == workflow_archetype)
        and (not blocked_use_class or incident.blocked_use_class == blocked_use_class)
    ]
    matched_count = len(incidents)
    if limit is not None:
        incidents = incidents[:limit]
    return IncidentScanResult(
        incidents=tuple(incidents),
        errors=scan.errors,
        scan_errors=scan.scan_errors,
        valid_corpus_count=scan.valid_corpus_count,
        matched_count=matched_count,
    )


def _lookup_result(
    incidents_dir: Path,
    incident_id: str,
) -> _IncidentLookupResult:
    entries, errors, scan_errors = _scan_incident_entries(incidents_dir)
    if scan_errors:
        details = ", ".join(
            f"{error.path}: {error.error_type}" for error in scan_errors
        )
        raise IncidentLookupIncompleteError(
            f"Incident lookup is operationally incomplete: {details}"
        )
    exact_entries = [
        entry
        for entry in entries
        if Path(entry.relative_path).stem == incident_id
    ]
    exact_errors = tuple(
        error for error in errors if Path(error.path).stem == incident_id
    )
    if exact_entries or exact_errors:
        matches = exact_entries
        requested_errors = exact_errors
    else:
        matches = [
            entry
            for entry in entries
            if Path(entry.relative_path).stem.endswith(incident_id)
        ]
        requested_errors = tuple(
            error
            for error in errors
            if Path(error.path).stem.endswith(incident_id)
        )
    if requested_errors:
        details = ", ".join(
            f"{error.path}: {error.error_type}" for error in requested_errors
        )
        raise IncidentLookupCorruptError(
            f"Requested incident candidate is corrupt: {details}"
        )
    if len(matches) == 1:
        return _IncidentLookupResult(matches[0], tuple(errors), tuple(scan_errors))
    if len(matches) > 1:
        ids = ", ".join(
            _safe_text(Path(match.relative_path).stem)
            for match in matches
        )
        safe_id = _safe_text(incident_id)
        raise AmbiguousIncidentLookupError(
            f"Ambiguous incident id '{safe_id}'. Matches: {ids}"
        )
    return _IncidentLookupResult(None, tuple(errors), tuple(scan_errors))


def _lookup_entry(
    incidents_dir: Path,
    incident_id: str,
) -> _IncidentEntry | None:
    return _lookup_result(incidents_dir, incident_id).entry


def find_incident_path(incidents_dir: Path, incident_id: str) -> Path | None:
    """Return an advisory path; callers needing guarantees must reopen no-follow."""
    entry = _lookup_entry(incidents_dir, incident_id)
    if entry is None:
        return None
    return incidents_dir / entry.relative_path


def find_incident(incidents_dir: Path, incident_id: str) -> Incident | None:
    """Find an incident from the no-follow scan snapshot."""
    entry = _lookup_entry(incidents_dir, incident_id)
    return entry.incident if entry is not None else None


def _read_fd_bytes(fd: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _stable_metadata(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _quarantine_metadata(metadata: os.stat_result) -> tuple[int, ...]:
    """Return identity and content metadata that rename does not update."""
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _open_incident_parent(incidents_dir: Path, relative_path: str) -> tuple[int, str]:
    parts = Path(relative_path).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise UnsafeIncidentPathError("Incident path is not a safe relative path")
    directory_fd = _open_nofollow(incidents_dir, directory=True)
    try:
        for part in parts[:-1]:
            child_fd = _open_nofollow(part, directory=True, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = child_fd
        return directory_fd, parts[-1]
    except BaseException:
        os.close(directory_fd)
        raise


def _read_stable_regular_file(name: str, directory_fd: int) -> tuple[bytes, os.stat_result]:
    fd = _open_nofollow(name, dir_fd=directory_fd)
    try:
        before = os.fstat(fd)
        content = _read_fd_bytes(fd)
        after = os.fstat(fd)
        if _stable_metadata(before) != _stable_metadata(after):
            raise IncidentEditConflictError(
                "Incident changed while it was being read"
            )
        return content, after
    finally:
        os.close(fd)


def _create_stage(original: bytes) -> tuple[tempfile.TemporaryDirectory[str], Path]:
    stage_dir = tempfile.TemporaryDirectory(prefix="forge-edit-")
    stage_path = Path(stage_dir.name) / "incident.yml"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(stage_path, flags, 0o600)
    try:
        view = memoryview(original)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    except BaseException:
        _close_quietly(fd)
        try:
            stage_dir.cleanup()
        except OSError:
            pass
        raise
    try:
        os.close(fd)
    except OSError:
        try:
            stage_dir.cleanup()
        except OSError:
            pass
        raise
    return stage_dir, stage_path


def _validated_stage(stage_path: Path) -> tuple[bytes, Incident]:
    try:
        fd = _open_nofollow(stage_path)
    except (UnsafeIncidentPathError, FileNotFoundError) as exc:
        raise InvalidIncidentEditError("Edited file is not a safe regular file") from exc
    try:
        before = os.fstat(fd)
        content = _read_fd_bytes(fd)
        after = os.fstat(fd)
        if _stable_metadata(before) != _stable_metadata(after):
            raise InvalidIncidentEditError("Edited file changed while it was read")
    finally:
        os.close(fd)
    try:
        incident = Incident.from_dict(yaml.safe_load(content))
    except Exception as exc:
        raise InvalidIncidentEditError("Edited file has invalid YAML") from exc
    return content, incident


def _write_all(fd: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(fd, view)
        view = view[written:]


@dataclass
class IncidentEditSession:
    """Isolated edit stage with bounded pre-publication conflict detection.

    Publication fails if the target's descriptor identity, metadata, or bytes differ
    from the captured snapshot. POSIX has no compare-and-swap rename, so an external
    replacement in the final recheck-to-rename interval cannot be detected atomically.
    The replacement itself is descriptor-relative and atomic within the verified
    parent directory; the old inode is never mutated.
    """

    relative_path: str
    stage_path: Path
    _directory_fd: int
    _target_name: str
    _original: bytes
    _original_metadata: tuple[int, ...]

    def _verify_target_unchanged(self) -> None:
        try:
            content, metadata = _read_stable_regular_file(
                self._target_name, self._directory_fd
            )
        except UnsafeIncidentPathError:
            raise
        except OSError as exc:
            raise IncidentEditConflictError(
                "Incident changed while the editor was open"
            ) from exc
        if (
            _stable_metadata(metadata) != self._original_metadata
            or content != self._original
        ):
            raise IncidentEditConflictError(
                "Incident changed while the editor was open"
            )

    def publish(self) -> Incident:
        content, incident = _validated_stage(self.stage_path)
        self._verify_target_unchanged()
        temporary_name: str | None = None
        temporary_fd: int | None = None
        backup_name: str | None = None
        primary_error: OSError | None = None
        try:
            for _ in range(100):
                candidate = f".{self._target_name}.{secrets.token_hex(8)}.tmp"
                try:
                    temporary_fd = os.open(
                        candidate,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o600,
                        dir_fd=self._directory_fd,
                    )
                except FileExistsError:
                    continue
                temporary_name = candidate
                break
            if temporary_fd is None or temporary_name is None:
                raise FileExistsError("Could not create an edit publication file")
            _write_all(temporary_fd, content)
            os.fsync(temporary_fd)
            os.close(temporary_fd)
            temporary_fd = None
            self._verify_target_unchanged()
            for _ in range(100):
                candidate = f".{self._target_name}.{secrets.token_hex(8)}.bak"
                try:
                    os.link(
                        self._target_name,
                        candidate,
                        src_dir_fd=self._directory_fd,
                        dst_dir_fd=self._directory_fd,
                        follow_symlinks=False,
                    )
                except FileExistsError:
                    continue
                backup_name = candidate
                break
            if backup_name is None:
                raise FileExistsError("Could not create an edit rollback link")
            try:
                os.fsync(self._directory_fd)
            except OSError as exc:
                raise RecoverablePartialStateError(primary_error=exc) from exc

            try:
                os.replace(
                    temporary_name,
                    self._target_name,
                    src_dir_fd=self._directory_fd,
                    dst_dir_fd=self._directory_fd,
                )
            except OSError as publication_error:
                try:
                    os.unlink(backup_name, dir_fd=self._directory_fd)
                except OSError as cleanup_error:
                    raise RecoverablePartialStateError(
                        primary_error=publication_error
                    ) from cleanup_error
                try:
                    os.fsync(self._directory_fd)
                except OSError as cleanup_error:
                    try:
                        os.link(
                            self._target_name,
                            backup_name,
                            src_dir_fd=self._directory_fd,
                            dst_dir_fd=self._directory_fd,
                            follow_symlinks=False,
                        )
                    except OSError:
                        pass
                    raise RecoverablePartialStateError(
                        primary_error=publication_error
                    ) from cleanup_error
                backup_name = None
                raise publication_error
            temporary_name = None

            try:
                os.fsync(self._directory_fd)
            except OSError as publication_error:
                try:
                    os.replace(
                        backup_name,
                        self._target_name,
                        src_dir_fd=self._directory_fd,
                        dst_dir_fd=self._directory_fd,
                    )
                except OSError as rollback_error:
                    raise RecoverablePartialStateError(
                        primary_error=publication_error
                    ) from rollback_error
                backup_name = None
                try:
                    os.fsync(self._directory_fd)
                except OSError as rollback_fsync_error:
                    raise RecoverablePartialStateError(
                        primary_error=publication_error
                    ) from rollback_fsync_error
                raise publication_error

            try:
                os.unlink(backup_name, dir_fd=self._directory_fd)
            except OSError as cleanup_error:
                raise RecoverablePartialStateError(
                    primary_error=cleanup_error
                ) from cleanup_error
            backup_name = None
            try:
                os.fsync(self._directory_fd)
            except OSError as cleanup_fsync_error:
                raise RecoverablePartialStateError(
                    primary_error=cleanup_fsync_error
                ) from cleanup_fsync_error
            return incident
        except OSError as exc:
            primary_error = exc
            raise
        finally:
            cleanup_error: OSError | None = None
            if temporary_fd is not None:
                try:
                    os.close(temporary_fd)
                except OSError as exc:
                    cleanup_error = exc
            if temporary_name is not None:
                try:
                    os.unlink(temporary_name, dir_fd=self._directory_fd)
                except OSError as exc:
                    if cleanup_error is None:
                        cleanup_error = exc
            if cleanup_error is not None:
                raise RecoverablePartialStateError(
                    primary_error=primary_error or cleanup_error
                ) from cleanup_error


@contextmanager
def stage_incident_for_edit(incidents_dir: Path, incident_id: str):
    """Yield an isolated regular-file stage; never yield a product descriptor."""
    entry = _lookup_entry(incidents_dir, incident_id)
    if entry is None:
        yield None
        return
    directory_fd, target_name = _open_incident_parent(
        incidents_dir, entry.relative_path
    )
    stage_dir: tempfile.TemporaryDirectory[str] | None = None
    primary_error: BaseException | None = None
    try:
        original, metadata = _read_stable_regular_file(target_name, directory_fd)
        stage_dir, stage_path = _create_stage(original)
        yield IncidentEditSession(
            relative_path=entry.relative_path,
            stage_path=stage_path,
            _directory_fd=directory_fd,
            _target_name=target_name,
            _original=original,
            _original_metadata=_stable_metadata(metadata),
        )
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        cleanup_error: OSError | None = None
        if stage_dir is not None:
            try:
                stage_dir.cleanup()
            except OSError as exc:
                cleanup_error = exc
        try:
            os.close(directory_fd)
        except OSError as exc:
            if cleanup_error is None:
                cleanup_error = exc
        if cleanup_error is not None and (
            primary_error is None or isinstance(primary_error, OSError)
        ):
            storage_error = (
                primary_error if isinstance(primary_error, OSError) else cleanup_error
            )
            raise RecoverablePartialStateError(
                primary_error=storage_error
            ) from cleanup_error


def get_all_incidents(incidents_dir: Path) -> list[Incident]:
    """Load all valid incidents, oldest first (for analysis)."""
    return list(scan_incidents(incidents_dir).incidents)
