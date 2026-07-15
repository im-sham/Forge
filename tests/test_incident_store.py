from concurrent.futures import ProcessPoolExecutor
from datetime import date
import errno
import multiprocessing
import os
from pathlib import Path

import yaml
import pytest
import forge_cli.incident_store as incident_store

from forge_cli.incident_store import (
    AmbiguousIncidentLookupError,
    DuplicateIncidentError,
    IncidentLookupCorruptError,
    IncidentLookupIncompleteError,
    UnsafeIncidentPathError,
    find_incident,
    find_incident_path,
    generate_id,
    get_all_incidents,
    list_incidents,
    list_incidents_result,
    load_incident,
    stage_incident_for_edit,
    save_generated_incident,
    save_incident,
    scan_incidents,
)
from forge_cli.models import Incident


class _FakeNativeRename:
    def __init__(self, result=0):
        self.result = result
        self.calls = []
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        self.calls.append(args)
        return self.result


class _FakeLibc:
    pass


@pytest.mark.parametrize(
    ("platform", "symbol", "expected_flag"),
    [
        ("darwin", "renameatx_np", 0x00000004),
        ("linux", "renameat2", 0x00000001),
    ],
)
def test_native_noreplace_loader_selects_exact_symbol_and_flag(
    monkeypatch, platform, symbol, expected_flag
):
    native = _FakeNativeRename()
    libc = _FakeLibc()
    setattr(libc, symbol, native)
    monkeypatch.setattr(incident_store.sys, "platform", platform)
    monkeypatch.setattr(
        incident_store.ctypes, "CDLL", lambda *_args, **_kwargs: libc
    )

    rename_noreplace = incident_store._load_native_rename_noreplace()

    assert rename_noreplace is not None
    rename_noreplace(11, "source", 22, "destination")
    assert native.calls == [
        (11, b"source", 22, b"destination", expected_flag)
    ]


@pytest.mark.parametrize("platform", ["darwin", "linux"])
def test_native_noreplace_loader_fails_closed_without_platform_symbol(
    monkeypatch, platform
):
    monkeypatch.setattr(incident_store.sys, "platform", platform)
    monkeypatch.setattr(
        incident_store.ctypes, "CDLL", lambda *_args, **_kwargs: _FakeLibc()
    )

    assert incident_store._load_native_rename_noreplace() is None


def test_native_noreplace_loader_skips_libc_on_windows(monkeypatch):
    monkeypatch.setattr(incident_store.sys, "platform", "win32")

    def fail_if_called(*_args, **_kwargs):
        pytest.fail("ctypes.CDLL must not be called on unsupported platforms")

    monkeypatch.setattr(incident_store.ctypes, "CDLL", fail_if_called)

    assert incident_store._load_native_rename_noreplace() is None


@pytest.mark.parametrize(
    "error_number",
    [
        errno.ENOSYS,
        errno.EINVAL,
        errno.ENOTSUP,
        errno.EOPNOTSUPP,
    ],
)
def test_native_noreplace_maps_unsupported_errno(
    monkeypatch, error_number
):
    native = _FakeNativeRename(result=-1)
    libc = _FakeLibc()
    libc.renameatx_np = native
    monkeypatch.setattr(incident_store.sys, "platform", "darwin")
    monkeypatch.setattr(
        incident_store.ctypes, "CDLL", lambda *_args, **_kwargs: libc
    )
    monkeypatch.setattr(incident_store.ctypes, "get_errno", lambda: error_number)
    rename_noreplace = incident_store._load_native_rename_noreplace()

    assert rename_noreplace is not None
    with pytest.raises(incident_store.AtomicRenameUnsupportedError):
        rename_noreplace(11, "source", 22, "destination")


@pytest.mark.parametrize(
    ("error_number", "expected_error"),
    [
        (errno.EEXIST, FileExistsError),
        (errno.EACCES, PermissionError),
        (errno.EIO, OSError),
    ],
)
def test_native_noreplace_preserves_supported_errno_classification(
    monkeypatch, error_number, expected_error
):
    native = _FakeNativeRename(result=-1)
    libc = _FakeLibc()
    libc.renameat2 = native
    monkeypatch.setattr(incident_store.sys, "platform", "linux")
    monkeypatch.setattr(
        incident_store.ctypes, "CDLL", lambda *_args, **_kwargs: libc
    )
    monkeypatch.setattr(incident_store.ctypes, "get_errno", lambda: error_number)
    rename_noreplace = incident_store._load_native_rename_noreplace()

    assert rename_noreplace is not None
    with pytest.raises(expected_error):
        rename_noreplace(11, "source", 22, "destination")


def _save_generated_worker(incidents_dir: str, sample_data: dict) -> tuple[str, str]:
    incident = Incident.from_dict(sample_data)
    path = save_generated_incident(incident, Path(incidents_dir))
    return incident.id, str(path)


def test_generate_id_first_of_day(tmp_incidents_dir):
    incident_id = generate_id(tmp_incidents_dir, date(2026, 3, 4))
    assert incident_id == "2026-03-04-001"


def test_generate_id_sequential(tmp_incidents_dir):
    # Create month dir and a fake first incident
    month_dir = tmp_incidents_dir / "2026-03"
    month_dir.mkdir()
    (month_dir / "2026-03-04-001.yml").write_text("id: '2026-03-04-001'")
    (month_dir / "2026-03-04-002.yml").write_text("id: '2026-03-04-002'")

    incident_id = generate_id(tmp_incidents_dir, date(2026, 3, 4))
    assert incident_id == "2026-03-04-003"


def test_generate_id_transitions_from_998_through_1000(tmp_incidents_dir):
    month_dir = tmp_incidents_dir / "2026-03"
    month_dir.mkdir()
    (month_dir / "2026-03-04-998.yml").touch()
    assert generate_id(tmp_incidents_dir, date(2026, 3, 4)) == "2026-03-04-999"

    (month_dir / "2026-03-04-999.yml").touch()
    assert generate_id(tmp_incidents_dir, date(2026, 3, 4)) == "2026-03-04-1000"

    (month_dir / "2026-03-04-1000.yml").touch()
    assert generate_id(tmp_incidents_dir, date(2026, 3, 4)) == "2026-03-04-1001"


def test_generate_id_uses_numeric_max_across_boundaries_and_gaps(tmp_incidents_dir):
    month_dir = tmp_incidents_dir / "2026-03"
    month_dir.mkdir()
    for sequence in (998, 999, 1000, 1002):
        (month_dir / f"2026-03-04-{sequence:03d}.yml").touch()

    assert generate_id(tmp_incidents_dir, date(2026, 3, 4)) == "2026-03-04-1003"


def test_generate_id_ignores_nonconforming_neighboring_filenames(tmp_incidents_dir):
    month_dir = tmp_incidents_dir / "2026-03"
    month_dir.mkdir()
    (month_dir / "2026-03-04-007.yml").touch()
    (month_dir / "2026-03-04-invalid.yml").touch()
    (month_dir / "2026-03-04-999-copy.yml").touch()
    (month_dir / "prefix-2026-03-04-999.yml").touch()

    assert generate_id(tmp_incidents_dir, date(2026, 3, 4)) == "2026-03-04-008"


@pytest.mark.parametrize("max_attempts", [0, -1])
def test_save_generated_incident_rejects_nonpositive_max_attempts(
    tmp_incidents_dir, sample_data, max_attempts
):
    incident = Incident.from_dict({**sample_data, "id": ""})

    with pytest.raises(ValueError, match="max_attempts must be positive"):
        save_generated_incident(
            incident,
            tmp_incidents_dir,
            max_attempts=max_attempts,
        )

    assert not list(tmp_incidents_dir.rglob("*.yml"))


def test_save_generated_incident_retries_first_publication_collision(
    tmp_incidents_dir, sample_data, monkeypatch
):
    incident = Incident.from_dict({**sample_data, "id": ""})
    real_save = save_incident
    attempts = 0

    def collide_once(candidate, incidents_dir):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise DuplicateIncidentError("deterministic collision")
        return real_save(candidate, incidents_dir)

    monkeypatch.setattr("forge_cli.incident_store.save_incident", collide_once)

    path = save_generated_incident(incident, tmp_incidents_dir, max_attempts=2)

    assert attempts == 2
    assert path.exists()
    assert incident.id == "2026-03-04-001"


def test_save_generated_incident_exhausts_bounded_collision_retries(
    tmp_incidents_dir, sample_data, monkeypatch
):
    incident = Incident.from_dict({**sample_data, "id": ""})
    attempts = 0

    def always_collide(_candidate, _incidents_dir):
        nonlocal attempts
        attempts += 1
        raise DuplicateIncidentError("deterministic collision")

    monkeypatch.setattr("forge_cli.incident_store.save_incident", always_collide)

    with pytest.raises(DuplicateIncidentError, match="after 3 attempts"):
        save_generated_incident(incident, tmp_incidents_dir, max_attempts=3)

    assert attempts == 3
    assert not list(tmp_incidents_dir.rglob("*.yml"))


def test_save_and_load_roundtrip(tmp_incidents_dir, sample_data):
    incident = Incident.from_dict(sample_data)
    filepath = save_incident(incident, tmp_incidents_dir)

    assert filepath.exists()
    assert filepath.name == "2026-03-04-001.yml"
    assert filepath.parent.name == "2026-03"

    loaded = load_incident(filepath)
    assert loaded.id == incident.id
    assert loaded.project == incident.project
    assert loaded.platform == incident.platform
    assert loaded.severity == incident.severity
    assert loaded.failure_type == incident.failure_type
    assert loaded.tags == incident.tags


def test_save_creates_month_directory(tmp_incidents_dir, sample_data):
    incident = Incident.from_dict(sample_data)
    save_incident(incident, tmp_incidents_dir)
    assert (tmp_incidents_dir / "2026-03").is_dir()


def test_list_incidents_empty(tmp_incidents_dir):
    result = list_incidents(tmp_incidents_dir)
    assert result == []


def test_list_incidents_with_filter(tmp_incidents_dir, sample_data):
    incident = Incident.from_dict(sample_data)
    save_incident(incident, tmp_incidents_dir)

    # Match project
    result = list_incidents(tmp_incidents_dir, project="mila")
    assert len(result) == 1

    # No match
    result = list_incidents(tmp_incidents_dir, project="aegis")
    assert len(result) == 0


def test_list_incidents_severity_filter(tmp_incidents_dir, sample_data):
    incident = Incident.from_dict(sample_data)
    save_incident(incident, tmp_incidents_dir)

    result = list_incidents(tmp_incidents_dir, severity="functional")
    assert len(result) == 1

    result = list_incidents(tmp_incidents_dir, severity="safety-critical")
    assert len(result) == 0


def test_missing_incidents_directory_is_an_empty_read_only_corpus(tmp_path):
    incidents_dir = tmp_path / "missing-incidents"

    scan = scan_incidents(incidents_dir)

    assert scan.incidents == ()
    assert scan.errors == ()
    assert scan.scan_errors == ()
    assert list_incidents(incidents_dir) == []
    assert get_all_incidents(incidents_dir) == []
    assert not incidents_dir.exists()


def test_scan_incidents_reports_corruption_without_modifying_source(
    tmp_incidents_dir, sample_data
):
    save_incident(Incident.from_dict(sample_data), tmp_incidents_dir)
    corrupt_path = tmp_incidents_dir / "2026-03" / "2026-03-04-002.yml"
    corrupt_payload = b"incident: [unterminated"
    corrupt_path.write_bytes(corrupt_payload)

    result = scan_incidents(tmp_incidents_dir)

    assert [incident.id for incident in result.incidents] == ["2026-03-04-001"]
    assert result.valid_corpus_count == 1
    assert result.corrupt_corpus_count == 1
    assert result.errors[0].path == "2026-03/2026-03-04-002.yml"
    assert result.errors[0].error_type == "YAMLError"
    assert corrupt_path.read_bytes() == corrupt_payload


def test_list_result_distinguishes_corpus_matches_and_returned_count(
    tmp_incidents_dir, sample_data
):
    first = Incident.from_dict(sample_data)
    second = Incident.from_dict(
        {
            **sample_data,
            "id": "2026-03-04-002",
            "project": "other-project",
        }
    )
    third = Incident.from_dict(
        {
            **sample_data,
            "id": "2026-03-04-003",
            "timestamp": "2026-03-04T16:30:00Z",
        }
    )
    for incident in (first, second, third):
        save_incident(incident, tmp_incidents_dir)
    corrupt_path = tmp_incidents_dir / "2026-03" / "2026-03-04-004.yml"
    corrupt_path.write_text("incident: [unterminated")

    result = list_incidents_result(
        tmp_incidents_dir,
        project=sample_data["project"],
        limit=1,
    )

    assert result.valid_corpus_count == 3
    assert result.corrupt_corpus_count == 1
    assert result.matched_count == 2
    assert result.returned_count == 1


def test_list_result_zero_limit_keeps_corpus_diagnostics(tmp_incidents_dir, sample_data):
    save_incident(Incident.from_dict(sample_data), tmp_incidents_dir)
    corrupt_path = tmp_incidents_dir / "2026-03" / "2026-03-04-002.yml"
    corrupt_path.write_text("incident: [unterminated")

    result = list_incidents_result(tmp_incidents_dir, limit=0)

    assert result.incidents == ()
    assert result.valid_corpus_count == 1
    assert result.corrupt_corpus_count == 1
    assert result.matched_count == 1
    assert result.returned_count == 0
    assert list_incidents(tmp_incidents_dir, limit=0) == []


@pytest.mark.parametrize("list_function", [list_incidents, list_incidents_result])
def test_store_list_functions_reject_negative_limit(
    tmp_incidents_dir, list_function
):
    with pytest.raises(ValueError, match="limit must be non-negative"):
        list_function(tmp_incidents_dir, limit=-1)


def test_scan_does_not_follow_directory_symlinks(tmp_incidents_dir, sample_data):
    external = tmp_incidents_dir.parent / "external"
    save_incident(Incident.from_dict(sample_data), external)
    linked = tmp_incidents_dir / "linked"
    linked.symlink_to(external, target_is_directory=True)

    result = scan_incidents(tmp_incidents_dir)

    assert result.incidents == ()
    assert result.valid_corpus_count == 0
    assert result.corrupt_corpus_count == 0



def test_scan_rejects_file_and_directory_symlinks(tmp_incidents_dir, sample_data):
    external = tmp_incidents_dir.parent / "external"
    external_file = save_incident(Incident.from_dict(sample_data), external)
    month_dir = tmp_incidents_dir / "2026-03"
    month_dir.mkdir()
    file_link = month_dir / external_file.name
    file_link.symlink_to(external_file)
    directory_link = tmp_incidents_dir / "linked"
    directory_link.symlink_to(external, target_is_directory=True)

    result = scan_incidents(tmp_incidents_dir)

    assert result.incidents == ()
    assert [(error.path, error.error_type) for error in result.scan_errors] == [
        ("2026-03/2026-03-04-001.yml", "SymlinkRejectedError"),
        ("linked", "SymlinkRejectedError"),
    ]


@pytest.mark.parametrize("lookup", ["2026-03-04-001", "001"])
def test_exact_and_suffix_lookup_reject_file_symlinks(
    tmp_incidents_dir, sample_data, lookup
):
    external = tmp_incidents_dir.parent / "external"
    external_file = save_incident(Incident.from_dict(sample_data), external)
    month_dir = tmp_incidents_dir / "2026-03"
    month_dir.mkdir()
    (month_dir / external_file.name).symlink_to(external_file)

    for lookup_function in (find_incident_path, find_incident):
        with pytest.raises(IncidentLookupIncompleteError, match="operationally incomplete"):
            lookup_function(tmp_incidents_dir, lookup)


@pytest.mark.parametrize("lookup", ["2026-03-04-001", "001"])
def test_exact_and_suffix_lookup_reject_symlink_directories(
    tmp_incidents_dir, sample_data, lookup
):
    external = tmp_incidents_dir.parent / "external"
    save_incident(Incident.from_dict(sample_data), external)
    (tmp_incidents_dir / "2026-03").symlink_to(
        external / "2026-03", target_is_directory=True
    )

    for lookup_function in (find_incident_path, find_incident):
        with pytest.raises(IncidentLookupIncompleteError, match="operationally incomplete"):
            lookup_function(tmp_incidents_dir, lookup)


def test_lookup_rejects_symlink_replacement_at_safe_open_seam(
    tmp_incidents_dir, sample_data, monkeypatch
):
    saved = save_incident(Incident.from_dict(sample_data), tmp_incidents_dir)
    external = tmp_incidents_dir.parent / "replacement.yml"
    external.write_text(saved.read_text())
    real_open = os.open
    replaced = False

    def replace_before_file_open(path, flags, *args, **kwargs):
        nonlocal replaced
        if Path(path) == saved and kwargs.get("dir_fd") is None and not replaced:
            replaced = True
            saved.unlink()
            saved.symlink_to(external)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr("forge_cli.incident_store.os.open", replace_before_file_open)

    with pytest.raises(UnsafeIncidentPathError, match="symlink"):
        load_incident(saved)

    assert replaced is True
    assert external.exists()

def test_edit_stage_rejects_symlink_replacement_after_lookup(
    tmp_incidents_dir, sample_data, monkeypatch
):
    saved = save_incident(Incident.from_dict(sample_data), tmp_incidents_dir)
    external = tmp_incidents_dir.parent / "replacement.yml"
    external.write_text(saved.read_text())
    real_open = os.open
    file_opens = 0

    def replace_after_lookup(path, flags, *args, **kwargs):
        nonlocal file_opens
        if path == saved.name and kwargs.get("dir_fd") is not None:
            file_opens += 1
            if file_opens == 2:
                saved.unlink()
                saved.symlink_to(external)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr("forge_cli.incident_store.os.open", replace_after_lookup)

    with pytest.raises(UnsafeIncidentPathError, match="symlink"):
        with stage_incident_for_edit(tmp_incidents_dir, "001"):
            pass

    assert file_opens == 2
    assert external.exists()


def test_edit_stage_nonblocking_open_rejects_fifo_replacement(
    tmp_incidents_dir, sample_data, monkeypatch
):
    saved = save_incident(Incident.from_dict(sample_data), tmp_incidents_dir)
    real_open = os.open
    file_opens = 0

    def replace_with_fifo(path, flags, *args, **kwargs):
        nonlocal file_opens
        if path == saved.name and kwargs.get("dir_fd") is not None:
            file_opens += 1
            if file_opens == 2:
                saved.unlink()
                os.mkfifo(saved)
                assert flags & os.O_NONBLOCK
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr("forge_cli.incident_store.os.open", replace_with_fifo)

    with pytest.raises(UnsafeIncidentPathError, match="regular file"):
        with stage_incident_for_edit(tmp_incidents_dir, "001"):
            pass

    assert file_opens == 2


def test_no_follow_unavailable_has_clear_error_contract(
    tmp_incidents_dir, sample_data, monkeypatch
):
    saved = save_incident(Incident.from_dict(sample_data), tmp_incidents_dir)
    monkeypatch.setattr(os, "O_NOFOLLOW", 0)

    result = scan_incidents(tmp_incidents_dir)

    assert result.incidents == ()
    assert result.scan_errors[0].error_type == "UnsafeIncidentPathError"
    with pytest.raises(
        UnsafeIncidentPathError,
        match="requires POSIX O_NOFOLLOW support",
    ):
        load_incident(saved)


def test_scan_routes_read_oserror_after_open_to_scan_errors(
    tmp_incidents_dir, monkeypatch
):
    unsafe_name = "2026-03-04-\n001.yml"
    candidate = tmp_incidents_dir / "2026-03" / unsafe_name
    candidate.parent.mkdir()
    candidate.touch()
    raw_message = f"raw failure at {tmp_incidents_dir}\nwith payload"

    def fail_read(_fd, _size):
        raise OSError(raw_message)

    monkeypatch.setattr("forge_cli.incident_store.os.read", fail_read)

    result = scan_incidents(tmp_incidents_dir)
    rendered = (
        f"{result.scan_errors[0].path}: {result.scan_errors[0].error_type}"
    )

    assert result.errors == ()
    assert result.scan_errors[0].error_type == "OSError"
    assert "\n" not in rendered
    assert raw_message not in rendered
    assert str(tmp_incidents_dir) not in rendered


def test_scan_routes_regular_file_open_permission_error_to_scan_errors(
    tmp_incidents_dir, sample_data, monkeypatch
):
    saved = save_incident(Incident.from_dict(sample_data), tmp_incidents_dir)
    real_open_nofollow = __import__(
        "forge_cli.incident_store", fromlist=["_open_nofollow"]
    )._open_nofollow

    def fail_regular_file_open(path, *, directory=False, dir_fd=None):
        if not directory and Path(path).name == saved.name:
            raise PermissionError(f"secret root {tmp_incidents_dir}")
        return real_open_nofollow(path, directory=directory, dir_fd=dir_fd)

    monkeypatch.setattr(
        "forge_cli.incident_store._open_nofollow", fail_regular_file_open
    )

    result = scan_incidents(tmp_incidents_dir)

    assert result.errors == ()
    assert [(error.path, error.error_type) for error in result.scan_errors] == [
        ("2026-03/2026-03-04-001.yml", "PermissionError")
    ]


@pytest.mark.parametrize("lookup_function", [find_incident, find_incident_path])
def test_lookup_fails_closed_when_unrelated_yaml_cannot_be_opened(
    tmp_incidents_dir, sample_data, monkeypatch, lookup_function
):
    requested = save_incident(Incident.from_dict(sample_data), tmp_incidents_dir)
    unrelated = save_incident(
        Incident.from_dict(
            {
                **sample_data,
                "id": "2026-03-04-002",
                "timestamp": "2026-03-04T15:30:00Z",
            }
        ),
        tmp_incidents_dir,
    )
    real_open_nofollow = __import__(
        "forge_cli.incident_store", fromlist=["_open_nofollow"]
    )._open_nofollow

    def fail_unrelated_open(path, *, directory=False, dir_fd=None):
        if not directory and Path(path).name == unrelated.name:
            raise PermissionError(f"secret root {tmp_incidents_dir}")
        return real_open_nofollow(path, directory=directory, dir_fd=dir_fd)

    monkeypatch.setattr(
        "forge_cli.incident_store._open_nofollow", fail_unrelated_open
    )

    with pytest.raises(IncidentLookupIncompleteError) as exc_info:
        lookup_function(tmp_incidents_dir, requested.stem)

    message = str(exc_info.value)
    assert f"2026-03/{unrelated.name}: PermissionError" in message
    assert str(tmp_incidents_dir) not in message


@pytest.mark.parametrize("lookup", ["2026-03-04-001", "001"])
@pytest.mark.parametrize("lookup_function", [find_incident, find_incident_path])
def test_lookup_fails_closed_for_unreadable_exact_and_suffix_candidates(
    tmp_incidents_dir, sample_data, monkeypatch, lookup, lookup_function
):
    saved = save_incident(Incident.from_dict(sample_data), tmp_incidents_dir)
    real_open_nofollow = __import__(
        "forge_cli.incident_store", fromlist=["_open_nofollow"]
    )._open_nofollow

    def fail_candidate_open(path, *, directory=False, dir_fd=None):
        if not directory and Path(path).name == saved.name:
            raise PermissionError(f"secret root {tmp_incidents_dir}")
        return real_open_nofollow(path, directory=directory, dir_fd=dir_fd)

    monkeypatch.setattr(
        "forge_cli.incident_store._open_nofollow", fail_candidate_open
    )

    with pytest.raises(IncidentLookupIncompleteError) as exc_info:
        lookup_function(tmp_incidents_dir, lookup)

    message = str(exc_info.value)
    assert f"2026-03/{saved.name}: PermissionError" in message
    assert str(tmp_incidents_dir) not in message


def test_scan_sanitizes_traversal_failures(tmp_incidents_dir, monkeypatch):
    raw_message = f"raw traversal failure at {tmp_incidents_dir}\nwith payload"

    real_listdir = os.listdir

    def fail_root_list(directory_fd):
        if directory_fd >= 0:
            error = PermissionError(raw_message)
            error.filename = str(tmp_incidents_dir / "unsafe\npath")
            raise error
        return real_listdir(directory_fd)

    monkeypatch.setattr("forge_cli.incident_store.os.listdir", fail_root_list)

    result = scan_incidents(tmp_incidents_dir)
    rendered = f"{result.scan_errors[0].path}: {result.scan_errors[0].error_type}"

    assert result.scan_errors[0].error_type == "PermissionError"
    assert "\n" not in rendered
    assert raw_message not in rendered
    assert str(tmp_incidents_dir) not in rendered


def test_ambiguous_lookup_sanitizes_markup_and_control_characters(
    tmp_incidents_dir, sample_data
):
    first = Incident.from_dict(sample_data)
    second = Incident.from_dict(
        {
            **sample_data,
            "id": "2026-03-05-001",
            "timestamp": "2026-03-05T14:30:00Z",
        }
    )
    first_path = save_incident(first, tmp_incidents_dir)
    second_path = save_incident(second, tmp_incidents_dir)
    first_markup = first_path.with_name("first-[bold]\x1b-001.yml")
    second_markup = second_path.with_name("second-[bold]\x1b-001.yml")
    first_path.rename(first_markup)
    second_path.rename(second_markup)

    with pytest.raises(AmbiguousIncidentLookupError) as exc_info:
        find_incident_path(tmp_incidents_dir, "001")

    message = str(exc_info.value)
    assert "[bold]" in message
    assert "\x1b" not in message
    assert "first-[bold]?-001" in message
    assert "second-[bold]?-001" in message


def test_scan_preview_performs_zero_writes(tmp_incidents_dir):
    corrupt_path = tmp_incidents_dir / "2026-03" / "2026-03-04-001.yml"
    corrupt_path.parent.mkdir()
    corrupt_path.write_bytes(b"incident: [unterminated")
    before = {
        path.relative_to(tmp_incidents_dir).as_posix(): path.read_bytes()
        for path in tmp_incidents_dir.rglob("*")
        if path.is_file()
    }

    result = scan_incidents(tmp_incidents_dir)

    after = {
        path.relative_to(tmp_incidents_dir).as_posix(): path.read_bytes()
        for path in tmp_incidents_dir.rglob("*")
        if path.is_file()
    }
    assert [candidate.path for candidate in result.errors] == [
        "2026-03/2026-03-04-001.yml"
    ]
    assert after == before


def test_save_generated_incident_is_unique_across_processes(
    tmp_incidents_dir, sample_data
):
    worker_data = sample_data.copy()
    worker_data["id"] = ""
    context = multiprocessing.get_context("spawn")

    with ProcessPoolExecutor(max_workers=4, mp_context=context) as executor:
        results = list(
            executor.map(
                _save_generated_worker,
                [str(tmp_incidents_dir)] * 8,
                [worker_data] * 8,
            )
        )

    incident_ids = [incident_id for incident_id, _ in results]
    saved_paths = [Path(path) for _, path in results]
    assert len(set(incident_ids)) == 8
    assert len(list(tmp_incidents_dir.rglob("*.yml"))) == 8
    assert all(path.exists() for path in saved_paths)
    for incident_id in incident_ids:
        assert find_incident(tmp_incidents_dir, incident_id).id == incident_id
        suffix = incident_id.rsplit("-", 1)[-1]
        assert find_incident(tmp_incidents_dir, suffix).id == incident_id


def test_incident_ordering_is_canonical_numeric_then_legacy_timestamp_and_path(
    tmp_incidents_dir, sample_data
):
    canonical = [
        ("2025-12-31-001", "2025-12-31T23:59:59Z"),
        ("2026-01-01-998", "2099-01-01T00:00:00Z"),
        ("2026-01-01-999", "2000-01-01T00:00:00Z"),
        ("2026-01-01-1000", "2000-01-01T00:00:00Z"),
        ("2026-01-01-1001", "2000-01-01T00:00:00Z"),
        ("2026-02-01-001", "2000-01-01T00:00:00Z"),
    ]
    for incident_id, timestamp in canonical:
        save_incident(
            Incident.from_dict(
                {**sample_data, "id": incident_id, "timestamp": timestamp}
            ),
            tmp_incidents_dir,
        )

    legacy_root = tmp_incidents_dir / "legacy-root.yml"
    legacy_nested = tmp_incidents_dir / "nested" / "legacy-nested.yml"
    legacy_nested.parent.mkdir()
    legacy_data = {
        **sample_data,
        "id": "legacy-root",
        "timestamp": "2026-01-15T12:00:00Z",
    }
    legacy_root.write_text(yaml.safe_dump(legacy_data))
    legacy_nested.write_text(
        yaml.safe_dump({**legacy_data, "id": "legacy-nested"})
    )

    oldest_first = [incident.id for incident in get_all_incidents(tmp_incidents_dir)]
    newest_first = [incident.id for incident in list_incidents(tmp_incidents_dir, limit=20)]

    assert oldest_first == [
        "2025-12-31-001",
        "2026-01-01-998",
        "2026-01-01-999",
        "2026-01-01-1000",
        "2026-01-01-1001",
        "legacy-root",
        "legacy-nested",
        "2026-02-01-001",
    ]
    assert newest_first == list(reversed(oldest_first))


@pytest.mark.parametrize(
    ("incident_id", "timestamp", "include_timestamp"),
    [
        ("2026-02-30-001", "2026-02-28T12:00:00Z", True),
        ("legacy-malformed", "not-a-timestamp", True),
        ("legacy-empty", "", True),
        ("legacy-missing", None, False),
    ],
)
def test_scan_classifies_invalid_ordering_fields_per_file(
    tmp_incidents_dir, sample_data, incident_id, timestamp, include_timestamp
):
    candidate = tmp_incidents_dir / "nested" / f"{incident_id}.yml"
    candidate.parent.mkdir()
    payload = {**sample_data, "id": incident_id}
    if include_timestamp:
        payload["timestamp"] = timestamp
    else:
        payload.pop("timestamp", None)
    candidate.write_text(yaml.safe_dump(payload))

    scan = scan_incidents(tmp_incidents_dir)
    listed = list_incidents_result(tmp_incidents_dir)

    assert scan.incidents == ()
    assert listed.incidents == ()
    assert [(error.path, error.error_type) for error in scan.errors] == [
        (f"nested/{incident_id}.yml", "InvalidIncidentError")
    ]
    assert scan.scan_errors == ()


@pytest.mark.parametrize("lookup", ["2026-03-04-001", "001"])
def test_lookup_distinguishes_corrupt_requested_candidate(
    tmp_incidents_dir, lookup
):
    candidate = tmp_incidents_dir / "2026-03" / "2026-03-04-001.yml"
    candidate.parent.mkdir()
    candidate.write_text("incident: [unterminated")

    with pytest.raises(IncidentLookupCorruptError) as exc_info:
        find_incident(tmp_incidents_dir, lookup)

    message = str(exc_info.value)
    assert "requested incident candidate is corrupt" in message.lower()
    assert "2026-03/2026-03-04-001.yml" in message
    assert str(tmp_incidents_dir) not in message


@pytest.mark.parametrize("lookup", ["2026-03-04-001", "001"])
@pytest.mark.parametrize("lookup_function", [find_incident, find_incident_path])
def test_lookup_prioritizes_matching_corrupt_candidate_over_valid_candidate(
    tmp_incidents_dir, sample_data, lookup, lookup_function
):
    valid = save_incident(Incident.from_dict(sample_data), tmp_incidents_dir)
    corrupt = tmp_incidents_dir / "duplicate" / valid.name
    corrupt.parent.mkdir()
    corrupt.write_text("incident: [unterminated")

    with pytest.raises(IncidentLookupCorruptError) as exc_info:
        lookup_function(tmp_incidents_dir, lookup)

    message = str(exc_info.value)
    assert "duplicate/2026-03-04-001.yml" in message
    assert str(tmp_incidents_dir) not in message


@pytest.mark.parametrize("lookup", ["2026-03-04-001", "001"])
@pytest.mark.parametrize("lookup_function", [find_incident, find_incident_path])
def test_lookup_prioritizes_scan_error_over_matching_corruption_and_valid_fallback(
    tmp_incidents_dir, sample_data, lookup, lookup_function
):
    valid = save_incident(Incident.from_dict(sample_data), tmp_incidents_dir)
    corrupt = tmp_incidents_dir / "duplicate" / valid.name
    corrupt.parent.mkdir()
    corrupt.write_text("incident: [unterminated")
    external = tmp_incidents_dir.parent / "external"
    external.mkdir()
    (tmp_incidents_dir / "unrelated").symlink_to(
        external, target_is_directory=True
    )

    with pytest.raises(IncidentLookupIncompleteError) as exc_info:
        lookup_function(tmp_incidents_dir, lookup)

    message = str(exc_info.value)
    assert "unrelated: SymlinkRejectedError" in message
    assert "Requested incident candidate is corrupt" not in message
    assert "duplicate/2026-03-04-001.yml" not in message
    assert str(tmp_incidents_dir) not in message


@pytest.mark.parametrize("lookup_function", [find_incident, find_incident_path])
def test_lookup_valid_exact_ignores_corrupt_suffix_candidate(
    tmp_incidents_dir, sample_data, lookup_function
):
    valid = save_incident(Incident.from_dict(sample_data), tmp_incidents_dir)
    corrupt_suffix = (
        tmp_incidents_dir / "suffix" / f"prefix-{valid.name}"
    )
    corrupt_suffix.parent.mkdir()
    corrupt_suffix.write_text("incident: [unterminated")

    result = lookup_function(tmp_incidents_dir, valid.stem)

    if lookup_function is find_incident:
        assert result is not None
        assert result.id == sample_data["id"]
    else:
        assert result == valid


@pytest.mark.parametrize("lookup_function", [find_incident, find_incident_path])
def test_lookup_corrupt_exact_ignores_valid_suffix_candidate(
    tmp_incidents_dir, sample_data, lookup_function
):
    valid_suffix = save_incident(Incident.from_dict(sample_data), tmp_incidents_dir)
    valid_suffix.rename(valid_suffix.with_name(f"prefix-{valid_suffix.name}"))
    corrupt_exact = (
        tmp_incidents_dir / "exact" / f"{sample_data['id']}.yml"
    )
    corrupt_exact.parent.mkdir()
    corrupt_exact.write_text("incident: [unterminated")

    with pytest.raises(IncidentLookupCorruptError) as exc_info:
        lookup_function(tmp_incidents_dir, sample_data["id"])

    message = str(exc_info.value)
    assert f"exact/{sample_data['id']}.yml: YAMLError" in message
    assert f"prefix-{sample_data['id']}.yml" not in message
    assert str(tmp_incidents_dir) not in message


@pytest.mark.parametrize("lookup", ["2026-03-04-001", "001"])
@pytest.mark.parametrize("lookup_function", [find_incident, find_incident_path])
def test_lookup_prioritizes_inaccessible_nested_directory_over_valid_candidate(
    tmp_incidents_dir, sample_data, monkeypatch, lookup, lookup_function
):
    save_incident(Incident.from_dict(sample_data), tmp_incidents_dir)
    (tmp_incidents_dir / "nested").mkdir()
    real_listdir = os.listdir
    calls = 0

    def fail_nested_listdir(directory_fd):
        nonlocal calls
        calls += 1
        if calls == 3:
            raise PermissionError(f"secret root {tmp_incidents_dir}")
        return real_listdir(directory_fd)

    monkeypatch.setattr("forge_cli.incident_store.os.listdir", fail_nested_listdir)

    with pytest.raises(IncidentLookupIncompleteError) as exc_info:
        lookup_function(tmp_incidents_dir, lookup)

    message = str(exc_info.value)
    assert "nested: PermissionError" in message
    assert str(tmp_incidents_dir) not in message


@pytest.mark.parametrize("lookup", ["2026-03-04-001", "001"])
@pytest.mark.parametrize("lookup_function", [find_incident, find_incident_path])
def test_lookup_prioritizes_symlinked_nested_directory_over_valid_candidate(
    tmp_incidents_dir, sample_data, lookup, lookup_function
):
    save_incident(Incident.from_dict(sample_data), tmp_incidents_dir)
    external = tmp_incidents_dir.parent / "external"
    external.mkdir()
    (tmp_incidents_dir / "nested").symlink_to(external, target_is_directory=True)

    with pytest.raises(IncidentLookupIncompleteError) as exc_info:
        lookup_function(tmp_incidents_dir, lookup)

    message = str(exc_info.value)
    assert "nested: SymlinkRejectedError" in message
    assert str(tmp_incidents_dir) not in message


@pytest.mark.parametrize("lookup", ["2026-03-04-001", "001"])
@pytest.mark.parametrize("lookup_function", [find_incident, find_incident_path])
def test_lookup_rejects_multiple_valid_exact_candidates(
    tmp_incidents_dir, sample_data, lookup, lookup_function
):
    valid = save_incident(Incident.from_dict(sample_data), tmp_incidents_dir)
    duplicate = tmp_incidents_dir / "duplicate" / valid.name
    duplicate.parent.mkdir()
    duplicate.write_bytes(valid.read_bytes())

    with pytest.raises(AmbiguousIncidentLookupError) as exc_info:
        lookup_function(tmp_incidents_dir, lookup)

    message = str(exc_info.value)
    assert "Ambiguous incident id" in message
    assert str(tmp_incidents_dir) not in message


def test_lookup_distinguishes_operationally_incomplete_root_scan(
    tmp_incidents_dir, monkeypatch
):
    raw_message = f"cannot scan {tmp_incidents_dir}\nsecret"

    def fail_listdir(_directory_fd):
        raise PermissionError(raw_message)

    monkeypatch.setattr("forge_cli.incident_store.os.listdir", fail_listdir)

    with pytest.raises(IncidentLookupIncompleteError) as exc_info:
        find_incident(tmp_incidents_dir, "001")

    message = str(exc_info.value)
    assert "operationally incomplete" in message.lower()
    assert str(tmp_incidents_dir) not in message
    assert raw_message not in message
    assert "\n" not in message


def test_lookup_distinguishes_operationally_incomplete_nested_scan(
    tmp_incidents_dir, monkeypatch
):
    nested = tmp_incidents_dir / "nested"
    nested.mkdir()
    real_listdir = os.listdir
    calls = 0

    def fail_nested_listdir(directory_fd):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise PermissionError("nested raw failure")
        return real_listdir(directory_fd)

    monkeypatch.setattr("forge_cli.incident_store.os.listdir", fail_nested_listdir)

    with pytest.raises(IncidentLookupIncompleteError) as exc_info:
        find_incident_path(tmp_incidents_dir, "001")

    assert "nested: PermissionError" in str(exc_info.value)


def test_clean_lookup_not_found_remains_none(tmp_incidents_dir):
    assert find_incident(tmp_incidents_dir, "missing") is None
    assert find_incident_path(tmp_incidents_dir, "missing") is None


def test_yaml_multiline_block_style(tmp_incidents_dir):
    data = {
        "id": "2026-03-04-001",
        "timestamp": "2026-03-04T14:30:00Z",
        "reported_by": "sham",
        "project": "mila",
        "agent": "test",
        "platform": "claude-code",
        "severity": "functional",
        "failure_type": "hallucination",
        "expected_behavior": "Line one.\nLine two.",
        "actual_behavior": "Single line.",
        "context": "",
        "root_cause": "",
        "immediate_fix": "",
        "systemic_takeaway": "",
    }
    incident = Incident.from_dict(data)
    filepath = save_incident(incident, tmp_incidents_dir)

    raw = filepath.read_text()
    # Multiline field should use block scalar style (|- strips trailing newline)
    assert "|-" in raw or "|\n" in raw
    assert "Line one." in raw
    assert "Line two." in raw


def test_find_incident_exact(tmp_incidents_dir, sample_data):
    incident = Incident.from_dict(sample_data)
    save_incident(incident, tmp_incidents_dir)

    found = find_incident(tmp_incidents_dir, "2026-03-04-001")
    assert found is not None
    assert found.id == "2026-03-04-001"


def test_find_incident_suffix(tmp_incidents_dir, sample_data):
    incident = Incident.from_dict(sample_data)
    save_incident(incident, tmp_incidents_dir)

    found = find_incident(tmp_incidents_dir, "001")
    assert found is not None
    assert found.id == "2026-03-04-001"


def test_find_incident_not_found(tmp_incidents_dir):
    found = find_incident(tmp_incidents_dir, "9999")
    assert found is None


def test_find_incident_path_returns_path(tmp_incidents_dir, sample_data):
    incident = Incident.from_dict(sample_data)
    saved = save_incident(incident, tmp_incidents_dir)

    path = find_incident_path(tmp_incidents_dir, "2026-03-04-001")
    assert path is not None
    assert path == saved


def test_find_incident_path_not_found(tmp_incidents_dir):
    path = find_incident_path(tmp_incidents_dir, "9999")
    assert path is None


def test_list_incidents_tag_filter(tmp_incidents_dir, sample_data):
    incident = Incident.from_dict(sample_data)
    save_incident(incident, tmp_incidents_dir)

    # sample_data has tags: ["hallucination", "long-document"]
    result = list_incidents(tmp_incidents_dir, tag="hallucination")
    assert len(result) == 1

    result = list_incidents(tmp_incidents_dir, tag="nonexistent-tag")
    assert len(result) == 0


def test_list_incidents_filters_structured_axes(tmp_incidents_dir, sample_data):
    first = sample_data.copy()
    first.update(
        {
            "issue_class": "rate_source_ambiguity",
            "capability_area": "workflow_context",
            "lifecycle_stage": "evidence_review",
            "workflow_archetype": "claims_hybrid_high_dollar_review",
            "blocked_use_class": "internal_eval",
        }
    )
    second = sample_data.copy()
    second.update(
        {
            "id": "2026-03-04-002",
            "issue_class": "redaction_miss",
            "capability_area": "governance",
            "lifecycle_stage": "redaction_review",
            "workflow_archetype": "document_operations",
            "blocked_use_class": "external_export",
        }
    )
    save_incident(Incident.from_dict(first), tmp_incidents_dir)
    save_incident(Incident.from_dict(second), tmp_incidents_dir)

    result = list_incidents(
        tmp_incidents_dir,
        issue_class="rate_source_ambiguity",
        capability_area="workflow_context",
        lifecycle_stage="evidence_review",
        workflow_archetype="claims_hybrid_high_dollar_review",
        blocked_use_class="internal_eval",
    )

    assert [incident.id for incident in result] == ["2026-03-04-001"]


def test_save_incident_rejects_duplicate_id(tmp_incidents_dir, sample_data):
    incident = Incident.from_dict(sample_data)
    save_incident(incident, tmp_incidents_dir)

    try:
        save_incident(incident, tmp_incidents_dir)
    except DuplicateIncidentError as exc:
        assert "2026-03-04-001" in str(exc)
    else:
        raise AssertionError("expected duplicate incident id to be rejected")


def test_find_incident_path_rejects_ambiguous_suffix(tmp_incidents_dir, sample_data):
    first = Incident.from_dict(sample_data)
    second_data = sample_data.copy()
    second_data["id"] = "2026-03-05-001"
    second_data["timestamp"] = "2026-03-05T14:30:00Z"
    save_incident(first, tmp_incidents_dir)
    save_incident(Incident.from_dict(second_data), tmp_incidents_dir)

    try:
        find_incident_path(tmp_incidents_dir, "001")
    except AmbiguousIncidentLookupError as exc:
        assert "2026-03-04-001" in str(exc)
        assert "2026-03-05-001" in str(exc)
    else:
        raise AssertionError("expected ambiguous suffix lookup to be rejected")


def test_document_operations_example_loads_as_structured_stub():
    fixture_path = (
        Path(__file__).parents[1]
        / "examples"
        / "document-operations"
        / "redaction-miss-incident.yml"
    )

    incident = load_incident(fixture_path)

    assert incident.project == "proofhouse-document-operations"
    assert incident.capability_area == "governance"
    assert incident.lifecycle_stage == "redaction_review"
    assert incident.issue_class == "redaction_miss"
    assert incident.workflow_archetype == "document_operations"
    assert incident.workflow_ref is not None
    assert incident.workflow_evidence_snapshot is not None
    assert incident.assessment_ref is not None
    assert incident.use_approval_ref is not None
    assert incident.workflow_ref["cache_policy"] == "ref_only"
    assert incident.asset_ref["cache_policy"] == "ref_only"


def test_claims_rate_source_example_roundtrips_to_valid_incident_ref():
    fixture_path = (
        Path(__file__).parents[1]
        / "examples"
        / "claims"
        / "rate-source-ambiguity-incident.yml"
    )

    incident = load_incident(fixture_path)
    result = incident.to_dict()
    envelope = incident.to_ref_envelope()
    ref = envelope["ref"]

    assert incident.project == "proofhouse-claims"
    assert incident.issue_class == "rate_source_ambiguity"
    assert incident.workflow_archetype == "claims_hybrid_high_dollar_review"
    assert incident.subject_type == "claim_review_packet"
    assert result["workflow_ref"]["cache_policy"] == "summary_snapshot"
    assert result["workflow_evidence_snapshot"]["cache_policy"] == "digest_snapshot"
    assert result["assessment_ref"]["cache_policy"] == "summary_snapshot"
    assert result["policy_decision_ref"]["cache_policy"] == "ref_only"
    assert result["use_approval_ref"]["cache_policy"] == "ref_only"
    assert ref["ref_id"] == "incident:example-claims-rate-source-ambiguity"
    assert ref["ref_type"] == "incident"
    assert ref["source_capability"] == "forge"
    assert ref["issue_class"] == "rate_source_ambiguity"
    assert "expected_behavior" not in ref
    assert "actual_behavior" not in ref


def test_claims_rate_source_example_is_pointer_and_summary_only():
    fixture_path = (
        Path(__file__).parents[1]
        / "examples"
        / "claims"
        / "rate-source-ambiguity-incident.yml"
    )
    raw = fixture_path.read_text().lower()
    incident = load_incident(fixture_path)

    forbidden_terms = [
        "member name",
        "patient name",
        "date of birth",
        "dob",
        "ssn",
        "837",
        "835",
        "turquoise live",
        "raw claim",
        "claim payload",
        "rate table row",
    ]

    assert incident.observed_state["boundary_note"].startswith("Forge stores only")
    assert all(term not in raw for term in forbidden_terms)


def test_generated_write_rejects_symlinked_month_directory(
    tmp_incidents_dir, sample_data
):
    external = tmp_incidents_dir.parent / "external-month"
    external.mkdir()
    before = tuple(external.iterdir())
    (tmp_incidents_dir / "2026-03").symlink_to(external, target_is_directory=True)
    incident = Incident.from_dict({**sample_data, "id": ""})

    with pytest.raises(UnsafeIncidentPathError, match="symlink"):
        save_generated_incident(incident, tmp_incidents_dir)

    assert tuple(external.iterdir()) == before
    assert (tmp_incidents_dir / "2026-03").is_symlink()


def test_generate_id_rejects_symlinked_month_without_writes(
    tmp_incidents_dir
):
    external = tmp_incidents_dir.parent / "external-id-month"
    external.mkdir()
    (tmp_incidents_dir / "2026-03").symlink_to(external, target_is_directory=True)

    with pytest.raises(UnsafeIncidentPathError, match="symlink"):
        generate_id(tmp_incidents_dir, date(2026, 3, 4))

    assert tuple(external.iterdir()) == ()


def test_duplicate_save_cleans_descriptor_relative_temp_files(
    tmp_incidents_dir, sample_data
):
    incident = Incident.from_dict(sample_data)
    saved = save_incident(incident, tmp_incidents_dir)
    original = saved.read_bytes()

    with pytest.raises(DuplicateIncidentError):
        save_incident(incident, tmp_incidents_dir)

    assert saved.read_bytes() == original
    assert [
        path.name
        for path in saved.parent.iterdir()
        if path.name.startswith(f".{incident.id}.")
    ] == []
