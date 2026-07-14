#!/usr/bin/env python3
"""Generate and verify Forge dependency locks and deterministic SBOMs."""

from __future__ import annotations

import argparse
from email.parser import BytesParser
from email.policy import default as email_policy
import importlib.metadata
import json
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
import zipfile
from collections.abc import Sequence
from datetime import date
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = ROOT / "requirements"
ADVISORY_EXCEPTIONS = ROOT / "docs" / "security" / "dependency-advisory-exceptions.json"
SOURCE_ANALYSIS_PROMPT = ROOT / "templates" / "analysis-prompt.md"
PACKAGED_ANALYSIS_PROMPT = ROOT / "forge_cli" / "resources" / "analysis-prompt.md"
UV_VERSION = "0.11.28"
PIN_PATTERN = re.compile(
    r"^([A-Za-z0-9_.-]+)==([^ ;\\]+)(?:\s*;\s*(.*?))?\s*\\?$"
)
PROJECT_VERSION_PATTERN = re.compile(r'^version\s*=\s*"([^"]+)"$', re.MULTILINE)
ADVISORY_ID_PATTERN = re.compile(
    r"^(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|PYSEC-\d{4}-\d+)$",
    re.IGNORECASE,
)
OWNER_PATTERN = re.compile(
    r"^(?:@[A-Za-z0-9][A-Za-z0-9_.-]*|"
    r"[A-Za-z0-9][A-Za-z0-9_.+:-]*(?:@[A-Za-z0-9.-]+)?)$"
)
REQUIRED_EXCEPTION_FIELDS = {
    "id",
    "package",
    "owner",
    "rationale",
    "affected_surface",
    "compensating_control",
    "expires",
}
SURFACE_EXPORTS: dict[str, tuple[str, ...]] = {
    "core": ("--no-default-groups",),
    "mcp": ("--no-default-groups", "--extra", "mcp"),
    "anthropic": ("--no-default-groups", "--extra", "anthropic"),
    "openai": ("--no-default-groups", "--extra", "openai"),
    "dev": ("--no-default-groups", "--extra", "dev", "--extra", "mcp"),
    "build": ("--only-group", "build"),
    "audit-tools": ("--only-group", "audit"),
}
DEPLOYABLE_SURFACES = ("core", "mcp", "anthropic", "openai")
DIRECT_DEPENDENCIES: dict[str, set[str]] = {
    "core": {"typer", "rich", "pyyaml"},
    "mcp": {"typer", "rich", "pyyaml", "mcp", "uvicorn"},
    "anthropic": {"typer", "rich", "pyyaml", "anthropic"},
    "openai": {"typer", "rich", "pyyaml", "openai"},
}
ENVIRONMENT_TOOLING = {"forge-cli", "pip", "setuptools", "wheel"}


class DependencyArtifactError(RuntimeError):
    """Raised when a dependency artifact is missing, stale, or invalid."""


def canonicalize_name(name: str) -> str:
    """Normalize a Python distribution name according to PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower()


def lock_path(surface: str) -> Path:
    """Return the committed lock path for a known surface."""
    if surface not in SURFACE_EXPORTS:
        raise DependencyArtifactError(f"Unknown dependency surface: {surface}")
    return REQUIREMENTS / f"{surface}.lock"


def _run(command: Sequence[str]) -> None:
    subprocess.run(command, cwd=ROOT, check=True)


def _read_normalized_text(path: Path) -> str:
    """Read UTF-8 text with platform checkout newlines normalized."""
    return path.read_text(encoding="utf-8")


def check_uv_version() -> None:
    """Require the exact resolver/exporter version that owns committed lock content."""
    if shutil.which("uv") is None:
        raise DependencyArtifactError(f"uv {UV_VERSION} is required")
    result = subprocess.run(
        ["uv", "--version"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    actual = result.stdout.strip().split()
    if actual[:2] != ["uv", UV_VERSION]:
        rendered = result.stdout.strip() or result.stderr.strip() or "unknown"
        raise DependencyArtifactError(
            f"uv {UV_VERSION} is required; found {rendered}"
        )


def _uv_export_command(output: Path, surface: str) -> list[str]:
    return [
        "uv",
        "--quiet",
        "export",
        "--frozen",
        "--format",
        "requirements.txt",
        "--no-emit-project",
        "--no-header",
        "--no-annotate",
        "--output-file",
        str(output),
        *SURFACE_EXPORTS[surface],
    ]


def validate_packaged_resources() -> None:
    """Fail when an installed-wheel resource drifts from its checkout source."""
    try:
        source = SOURCE_ANALYSIS_PROMPT.read_bytes()
        packaged = PACKAGED_ANALYSIS_PROMPT.read_bytes()
    except FileNotFoundError as error:
        raise DependencyArtifactError(
            f"Missing packaged resource input: {error.filename}"
        ) from error
    if source != packaged:
        raise DependencyArtifactError(
            "forge_cli/resources/analysis-prompt.md has drifted from "
            "templates/analysis-prompt.md"
        )


def parse_lock_entries(path: Path) -> dict[str, tuple[str, str | None]]:
    """Read exact distribution pins and optional PEP 508 markers from an export."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as error:
        raise DependencyArtifactError(f"Missing dependency lock: {path}") from error

    pins: dict[str, tuple[str, str | None]] = {}
    entries = re.split(r"\n(?=[A-Za-z0-9_.-]+==)", text.strip()) if text.strip() else []
    for entry in entries:
        first_line = entry.splitlines()[0]
        match = PIN_PATTERN.match(first_line)
        if match is None:
            raise DependencyArtifactError(f"Unparseable lock entry in {path}: {first_line}")
        name = canonicalize_name(match.group(1))
        if name in pins:
            raise DependencyArtifactError(f"Duplicate distribution {name} in {path}")
        if "--hash=sha256:" not in entry:
            raise DependencyArtifactError(f"Distribution {name} is not hash locked in {path}")
        marker = match.group(3).strip() if match.group(3) else None
        pins[name] = (match.group(2), marker)
    if not pins:
        raise DependencyArtifactError(f"Dependency lock is empty: {path}")
    return pins


def parse_lock(path: Path) -> dict[str, str]:
    """Read exact distribution name/version pins from a uv requirements export."""
    return {name: entry[0] for name, entry in parse_lock_entries(path).items()}


def validate_advisory_exceptions(path: Path, *, today: date | None = None) -> None:
    """Require every advisory disposition to be owned, explicit, and unexpired."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as error:
        raise DependencyArtifactError(f"Invalid advisory exception file: {path}") from error
    if document.get("schema_version") != 1 or not isinstance(document.get("exceptions"), list):
        raise DependencyArtifactError(
            "Advisory exceptions require schema_version 1 and an exceptions list"
        )

    current_date = today or date.today()
    seen: set[tuple[str, str, str]] = set()
    for index, exception in enumerate(document["exceptions"]):
        if not isinstance(exception, dict):
            raise DependencyArtifactError(f"Advisory exception {index} must be an object")
        missing = REQUIRED_EXCEPTION_FIELDS - exception.keys()
        invalid_strings = {
            field
            for field in REQUIRED_EXCEPTION_FIELDS
            if field in exception
            and (not isinstance(exception[field], str) or not exception[field].strip())
        }
        if missing or invalid_strings:
            fields = ", ".join(sorted(missing | invalid_strings))
            raise DependencyArtifactError(
                f"Advisory exception {index} has missing fields: {fields}"
            )

        advisory_id = exception["id"].strip().upper()
        package = canonicalize_name(exception["package"].strip())
        owner = exception["owner"].strip()
        surface = exception["affected_surface"].strip()
        if ADVISORY_ID_PATTERN.fullmatch(advisory_id) is None:
            raise DependencyArtifactError(
                f"Advisory exception {index} has an invalid advisory id"
            )
        if OWNER_PATTERN.fullmatch(owner) is None:
            raise DependencyArtifactError(
                f"Advisory exception {advisory_id} has an invalid owner"
            )
        if surface not in DEPLOYABLE_SURFACES:
            raise DependencyArtifactError(
                f"Advisory exception {advisory_id} has an unknown affected surface"
            )
        if package not in parse_lock(lock_path(surface)):
            raise DependencyArtifactError(
                f"Advisory exception {advisory_id} package is absent from {surface}.lock"
            )

        identity = (package, advisory_id, surface)
        if identity in seen:
            raise DependencyArtifactError(
                f"Duplicate advisory exception for {package} {advisory_id} on {surface}"
            )
        seen.add(identity)
        try:
            expires = date.fromisoformat(exception["expires"].strip())
        except ValueError as error:
            raise DependencyArtifactError(
                f"Advisory exception {identity[1]} has an invalid expiry"
            ) from error
        if expires < current_date:
            raise DependencyArtifactError(
                f"Advisory exception {identity[1]} expired on {expires.isoformat()}"
            )


def validate_surface_separation() -> None:
    """Prove optional deployable surfaces do not contaminate the core lock."""
    locks = {surface: parse_lock(lock_path(surface)) for surface in SURFACE_EXPORTS}
    core = locks["core"]
    for surface in DEPLOYABLE_SURFACES[1:]:
        missing_or_changed = {
            name
            for name, version in core.items()
            if locks[surface].get(name) != version
        }
        if missing_or_changed:
            raise DependencyArtifactError(
                f"{surface}.lock does not preserve core pins: {sorted(missing_or_changed)}"
            )

    required_only = {
        "mcp": {"mcp", "uvicorn"},
        "anthropic": {"anthropic"},
        "openai": {"openai"},
    }
    for surface, required in required_only.items():
        absent = required - locks[surface].keys()
        leaked = required & core.keys()
        if absent:
            raise DependencyArtifactError(
                f"{surface}.lock is missing its optional distributions: {sorted(absent)}"
            )
        if leaked:
            raise DependencyArtifactError(
                f"core.lock is contaminated by {surface}: {sorted(leaked)}"
            )

    for package, owner in (("mcp", "mcp"), ("anthropic", "anthropic"), ("openai", "openai")):
        contaminated = [
            surface
            for surface in DEPLOYABLE_SURFACES
            if surface not in {"core", owner} and package in locks[surface]
        ]
        if contaminated:
            raise DependencyArtifactError(
                f"Optional package {package} leaked into: {', '.join(contaminated)}"
            )

    if locks["mcp"].items() - locks["dev"].items():
        raise DependencyArtifactError("dev.lock must include the MCP surface exercised by tests")


def generate_locks() -> None:
    """Resolve the universal lock and export every exact install surface."""
    validate_packaged_resources()
    check_uv_version()
    REQUIREMENTS.mkdir(parents=True, exist_ok=True)
    _run(["uv", "--quiet", "lock"])
    for surface in SURFACE_EXPORTS:
        _run(_uv_export_command(lock_path(surface), surface))
    validate_surface_separation()
    validate_advisory_exceptions(ADVISORY_EXCEPTIONS)


def check_locks() -> None:
    """Fail if project metadata, uv.lock, or any exact export has drifted."""
    validate_packaged_resources()
    check_uv_version()
    _run(["uv", "--quiet", "lock", "--check"])
    for surface in SURFACE_EXPORTS:
        parse_lock(lock_path(surface))
    with tempfile.TemporaryDirectory(prefix="forge-dependency-lock-") as temporary:
        temporary_dir = Path(temporary)
        for surface in SURFACE_EXPORTS:
            candidate = temporary_dir / lock_path(surface).name
            _run(_uv_export_command(candidate, surface))
            # Git may materialize committed LF text as CRLF on Windows, while
            # uv writes LF. Compare normalized UTF-8 content so the drift gate
            # remains strict about pins, hashes, and markers without treating
            # checkout newline policy as dependency drift.
            if _read_normalized_text(candidate) != _read_normalized_text(
                lock_path(surface)
            ):
                raise DependencyArtifactError(
                    f"{lock_path(surface).relative_to(ROOT)} has drifted; regenerate with "
                    "python scripts/verify_dependency_artifacts.py --generate"
                )
    validate_surface_separation()
    validate_advisory_exceptions(ADVISORY_EXCEPTIONS)


def project_version() -> str:
    """Read the local project version without importing build tooling."""
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = PROJECT_VERSION_PATTERN.search(text)
    if match is None:
        raise DependencyArtifactError("Unable to read project version from pyproject.toml")
    return match.group(1)


def active_lock_entries(path: Path) -> dict[str, tuple[str, str | None]]:
    """Return the exact lock entries active for the current Python target."""
    try:
        from packaging.markers import Marker
    except ImportError:
        from pip._vendor.packaging.markers import Marker

    return {
        name: entry
        for name, entry in parse_lock_entries(path).items()
        if entry[1] is None or Marker(entry[1]).evaluate()
    }


def wheel_artifact_identity(path: Path) -> tuple[str, str]:
    """Validate the built Forge wheel and return its filename and SHA-256."""
    try:
        digest = sha256(path.read_bytes()).hexdigest()
        with zipfile.ZipFile(path) as archive:
            metadata_paths = [
                name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
            ]
            if len(metadata_paths) != 1:
                raise DependencyArtifactError(
                    f"Wheel must contain exactly one METADATA file: {path}"
                )
            metadata = BytesParser(policy=email_policy).parsebytes(
                archive.read(metadata_paths[0])
            )
    except (FileNotFoundError, zipfile.BadZipFile) as error:
        raise DependencyArtifactError(f"Invalid Forge wheel: {path}") from error
    if canonicalize_name(metadata.get("Name", "")) != "forge-cli":
        raise DependencyArtifactError(f"Wheel is not forge-cli: {path}")
    if metadata.get("Version") != project_version():
        raise DependencyArtifactError(f"Wheel version does not match pyproject.toml: {path}")
    return path.name, digest


def dependency_sbom(surface: str, wheel: Path) -> dict[str, object]:
    """Build a deterministic artifact-bound CycloneDX inventory for one target."""
    if surface not in DEPLOYABLE_SURFACES:
        raise DependencyArtifactError(f"SBOM surface is not deployable: {surface}")
    lock = lock_path(surface)
    entries = active_lock_entries(lock)
    pins = {name: entry[0] for name, entry in entries.items()}
    version = project_version()
    wheel_filename, wheel_digest = wheel_artifact_identity(wheel)
    root_ref = f"pkg:pypi/forge-cli@{version}"
    components = []
    for name, package_version in sorted(pins.items()):
        component: dict[str, object] = {
            "bom-ref": f"pkg:pypi/{name}@{package_version}",
            "name": name,
            "purl": f"pkg:pypi/{name}@{package_version}",
            "type": "library",
            "version": package_version,
        }
        marker = entries[name][1]
        if marker:
            component["properties"] = [{"name": "usmi:pep508-marker", "value": marker}]
        components.append(component)
    lock_digest = sha256(lock.read_bytes()).hexdigest()
    target = (
        f"{platform.python_implementation().lower()}-{platform.python_version()}-"
        f"{sys.platform}-{platform.machine().lower()}"
    )
    serial = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"forge-cli:{version}:{surface}:{lock_digest}:{wheel_digest}:{target}",
    )
    direct_refs = [
        f"pkg:pypi/{name}@{pins[name]}"
        for name in sorted(DIRECT_DEPENDENCIES[surface])
        if name in pins
    ]
    return {
        "bomFormat": "CycloneDX",
        "components": components,
        "dependencies": [{"dependsOn": direct_refs, "ref": root_ref}],
        "metadata": {
            "component": {
                "bom-ref": root_ref,
                "hashes": [{"alg": "SHA-256", "content": wheel_digest}],
                "name": "forge-cli",
                "properties": [
                    {"name": "usmi:dependency-surface", "value": surface},
                    {"name": "usmi:lock-sha256", "value": lock_digest},
                    {"name": "usmi:python-target", "value": target},
                    {"name": "usmi:wheel-filename", "value": wheel_filename},
                ],
                "purl": root_ref,
                "type": "application",
                "version": version,
            }
        },
        "serialNumber": f"urn:uuid:{serial}",
        "specVersion": "1.6",
        "version": 1,
    }


def generate_sboms(output_directory: Path, wheel: Path) -> None:
    """Write byte-stable CycloneDX inventories for every deployable surface."""
    output_directory.mkdir(parents=True, exist_ok=True)
    for surface in DEPLOYABLE_SURFACES:
        output = output_directory / f"forge-{surface}.cdx.json"
        output.write_text(
            json.dumps(dependency_sbom(surface, wheel), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def validate_sboms(input_directory: Path) -> None:
    """Strictly validate every generated CycloneDX document against schema 1.6."""
    try:
        from cyclonedx.schema import SchemaVersion
        from cyclonedx.validation.json import JsonStrictValidator
    except ImportError as error:
        raise DependencyArtifactError(
            "CycloneDX JSON validation requires the exact audit-tools lock"
        ) from error

    paths = sorted(input_directory.glob("forge-*.cdx.json"))
    expected_names = {f"forge-{surface}.cdx.json" for surface in DEPLOYABLE_SURFACES}
    if {path.name for path in paths} != expected_names:
        raise DependencyArtifactError(
            f"SBOM set does not match deployable surfaces: {[path.name for path in paths]}"
        )
    validator = JsonStrictValidator(SchemaVersion.V1_6)
    for path in paths:
        errors = validator.validate_str(path.read_text(encoding="utf-8"), all_errors=True)
        if errors is not None:
            raise DependencyArtifactError(f"Invalid CycloneDX SBOM {path}: {list(errors)}")


def check_environment(surface: str) -> None:
    """Require installed distributions to equal one lock plus explicit bootstrap tools."""
    expected = {
        name: version
        for name, (version, _marker) in active_lock_entries(lock_path(surface)).items()
    }
    actual = {
        canonicalize_name(distribution.metadata["Name"]): distribution.version
        for distribution in importlib.metadata.distributions()
        if distribution.metadata.get("Name")
    }
    unexpected = set(actual) - set(expected) - ENVIRONMENT_TOOLING
    missing = set(expected) - set(actual)
    changed = {
        name for name in set(expected) & set(actual) if expected[name] != actual[name]
    }
    if unexpected or missing or changed:
        details = []
        if missing:
            details.append(f"missing={sorted(missing)}")
        if unexpected:
            details.append(f"unexpected={sorted(unexpected)}")
        if changed:
            details.append(
                "changed="
                + str(sorted(f"{name}:{expected[name]}!={actual[name]}" for name in changed))
            )
        raise DependencyArtifactError(
            f"Installed environment does not match {surface}.lock: " + "; ".join(details)
        )


def main(argv: Sequence[str] | None = None) -> int:
    """Run dependency artifact generation or verification."""
    parser = argparse.ArgumentParser(description=__doc__)
    operations = parser.add_mutually_exclusive_group(required=True)
    operations.add_argument("--generate", action="store_true")
    operations.add_argument("--check-lock", action="store_true")
    operations.add_argument("--generate-sboms", type=Path)
    operations.add_argument("--validate-sboms", type=Path)
    operations.add_argument("--check-environment", choices=SURFACE_EXPORTS)
    parser.add_argument("--wheel", type=Path)
    arguments = parser.parse_args(argv)

    try:
        if arguments.generate:
            generate_locks()
        elif arguments.check_lock:
            check_locks()
        elif arguments.generate_sboms is not None:
            if arguments.wheel is None:
                raise DependencyArtifactError("--generate-sboms requires --wheel")
            generate_sboms(arguments.generate_sboms, arguments.wheel)
        elif arguments.validate_sboms is not None:
            validate_sboms(arguments.validate_sboms)
        else:
            check_environment(arguments.check_environment)
    except (DependencyArtifactError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"error: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
