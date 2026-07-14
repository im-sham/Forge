from __future__ import annotations

import json
from datetime import date
from pathlib import Path
import zipfile

import pytest

from scripts.verify_dependency_artifacts import (
    ADVISORY_EXCEPTIONS,
    DEPLOYABLE_SURFACES,
    DependencyArtifactError,
    _read_normalized_text,
    active_lock_entries,
    dependency_sbom,
    lock_path,
    parse_lock,
    validate_advisory_exceptions,
    validate_packaged_resources,
    validate_surface_separation,
)


def _write_test_wheel(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "forge_cli-0.1.0.dist-info/METADATA",
            "Metadata-Version: 2.4\nName: forge-cli\nVersion: 0.1.0\n",
        )
    return path


def test_all_dependency_locks_are_exact_and_hash_locked() -> None:
    for surface in (*DEPLOYABLE_SURFACES, "dev", "build", "audit-tools"):
        assert parse_lock(lock_path(surface))


def test_optional_surfaces_do_not_contaminate_core() -> None:
    validate_surface_separation()


def test_packaged_analysis_prompt_matches_checkout_source() -> None:
    validate_packaged_resources()


def test_lock_text_comparison_normalizes_platform_newlines(tmp_path: Path) -> None:
    lf = tmp_path / "lf.lock"
    crlf = tmp_path / "crlf.lock"
    lf.write_bytes(b"package==1.0 \\\n    --hash=sha256:abc\n")
    crlf.write_bytes(b"package==1.0 \\\r\n    --hash=sha256:abc\r\n")

    assert _read_normalized_text(lf) == _read_normalized_text(crlf)


def test_sboms_are_deterministic_and_match_each_surface(tmp_path: Path) -> None:
    wheel = _write_test_wheel(tmp_path / "forge_cli-0.1.0-py3-none-any.whl")
    for surface in DEPLOYABLE_SURFACES:
        first = json.dumps(dependency_sbom(surface, wheel), sort_keys=True)
        second = json.dumps(dependency_sbom(surface, wheel), sort_keys=True)
        assert first == second
        document = json.loads(first)
        components = {component["name"]: component["version"] for component in document["components"]}
        assert components == {
            name: version
            for name, (version, _marker) in active_lock_entries(lock_path(surface)).items()
        }
        assert document["metadata"]["component"]["properties"][0]["value"] == surface
        assert document["metadata"]["component"]["hashes"][0]["content"]


def test_sbom_identity_changes_with_wheel_bytes(tmp_path: Path) -> None:
    first_wheel = _write_test_wheel(tmp_path / "forge_cli-0.1.0-py3-none-any.whl")
    second_wheel = tmp_path / "forge_cli-0.1.0-2-py3-none-any.whl"
    with zipfile.ZipFile(second_wheel, "w") as archive:
        archive.writestr(
            "forge_cli-0.1.0.dist-info/METADATA",
            "Metadata-Version: 2.4\nName: forge-cli\nVersion: 0.1.0\n",
        )
        archive.writestr("forge_cli/build-marker.txt", "different wheel bytes")

    first = dependency_sbom("core", first_wheel)
    second = dependency_sbom("core", second_wheel)

    assert first["serialNumber"] != second["serialNumber"]
    assert (
        first["metadata"]["component"]["hashes"]
        != second["metadata"]["component"]["hashes"]
    )


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"owner": "   "}, "missing fields"),
        ({"owner": 7}, "missing fields"),
        ({"id": "not-an-advisory"}, "invalid advisory id"),
        ({"affected_surface": "unknown"}, "unknown affected surface"),
        ({"package": "not-in-lock"}, "absent from core.lock"),
    ],
)
def test_advisory_registry_rejects_malformed_entries(
    tmp_path: Path, changes: dict[str, object], message: str
) -> None:
    registry = tmp_path / "exceptions.json"
    exception = {
        "id": "CVE-2026-12345",
        "package": "typer",
        "owner": "team:forge",
        "rationale": "fixture",
        "affected_surface": "core",
        "compensating_control": "fixture",
        "expires": "2026-07-15",
    }
    exception.update(changes)
    registry.write_text(
        json.dumps({"schema_version": 1, "exceptions": [exception]}),
        encoding="utf-8",
    )

    with pytest.raises(DependencyArtifactError, match=message):
        validate_advisory_exceptions(registry, today=date(2026, 7, 14))


def test_advisory_registry_rejects_canonicalized_duplicates(tmp_path: Path) -> None:
    registry = tmp_path / "exceptions.json"
    base = {
        "id": "CVE-2026-12345",
        "package": "typer",
        "owner": "team:forge",
        "rationale": "fixture",
        "affected_surface": "core",
        "compensating_control": "fixture",
        "expires": "2026-07-15",
    }
    duplicate = {**base, "id": "cve-2026-12345", "package": "Typer"}
    registry.write_text(
        json.dumps({"schema_version": 1, "exceptions": [base, duplicate]}),
        encoding="utf-8",
    )

    with pytest.raises(DependencyArtifactError, match="Duplicate"):
        validate_advisory_exceptions(registry, today=date(2026, 7, 14))


def test_advisory_registry_is_valid_and_current() -> None:
    validate_advisory_exceptions(ADVISORY_EXCEPTIONS, today=date(2026, 7, 14))


def test_advisory_registry_rejects_expired_entries(tmp_path: Path) -> None:
    registry = tmp_path / "exceptions.json"
    registry.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "exceptions": [
                    {
                        "id": "CVE-2000-0001",
                        "package": "typer",
                        "owner": "security@example.invalid",
                        "rationale": "fixture",
                        "affected_surface": "core",
                        "compensating_control": "fixture",
                        "expires": "2026-07-13",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(DependencyArtifactError, match="expired"):
        validate_advisory_exceptions(registry, today=date(2026, 7, 14))
