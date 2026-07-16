#!/usr/bin/env python3
"""Enforce Forge's versioned critical typing policy and monotonic debt baseline."""

from __future__ import annotations

import argparse
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import TypeAlias, cast


ROOT = Path(__file__).resolve().parents[1]
POLICY_VERSION = 1
BASELINE_PATH = "typing/mypy-baseline-v1.json"
CRITICAL_SURFACES = (
    "forge_cli/models.py",
    "forge_cli/incident_store.py",
)
MYPY_ARGS = (
    "--check-untyped-defs",
    "--no-implicit-optional",
    "--warn-redundant-casts",
    "--warn-unused-ignores",
    "--show-error-codes",
    "--output=json",
    "--no-error-summary",
    "--no-pretty",
    "--no-incremental",
)
SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
DiagnosticKey: TypeAlias = tuple[str, str, str]
DiagnosticCounts: TypeAlias = Counter[DiagnosticKey]
Runner = Callable[..., subprocess.CompletedProcess[str]]


class TypeGateError(RuntimeError):
    """Raised when the type gate cannot prove the requested invariant."""


def diagnostic_counts(diagnostics: Iterable[object]) -> DiagnosticCounts:
    """Count stable diagnostic keys while excluding source positions and hints."""
    counts: DiagnosticCounts = Counter()
    for diagnostic in diagnostics:
        if not isinstance(diagnostic, Mapping):
            raise TypeGateError("each mypy diagnostic must be a JSON object")
        diagnostic_map = cast(Mapping[str, object], diagnostic)
        path = diagnostic_map.get("file")
        code = diagnostic_map.get("code")
        message = diagnostic_map.get("message")
        if (
            not isinstance(path, str)
            or not path
            or not isinstance(code, str)
            or not code
            or not isinstance(message, str)
            or not message
        ):
            raise TypeGateError(
                "each mypy diagnostic requires non-empty file, code, and message"
            )
        counts[(path, code, message)] += 1
    return counts


def _parse_mypy_output(output: str) -> DiagnosticCounts:
    diagnostics: list[object] = []
    for line_number, line in enumerate(output.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            diagnostics.append(cast(object, json.loads(line)))
        except json.JSONDecodeError as exc:
            raise TypeGateError(
                f"invalid mypy JSON output on line {line_number}: {exc.msg}"
            ) from exc
    return diagnostic_counts(diagnostics)


def collect_mypy_diagnostics(
    paths: Sequence[str],
    *,
    run: Runner = subprocess.run,
) -> DiagnosticCounts:
    """Run the selected JSON mypy policy and return normalized diagnostic counts."""
    try:
        result = run(
            [sys.executable, "-m", "mypy", *MYPY_ARGS, *paths],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise TypeGateError(f"mypy execution failed: {exc}") from exc
    if result.returncode not in {0, 1}:
        detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic output"
        raise TypeGateError(f"mypy execution failed ({result.returncode}): {detail}")
    if result.stderr.strip():
        raise TypeGateError(f"mypy wrote unexpected stderr: {result.stderr.strip()}")
    try:
        diagnostics = _parse_mypy_output(result.stdout)
    except TypeGateError as exc:
        if result.returncode == 1:
            raise TypeGateError(
                f"mypy exited 1 without parseable JSON diagnostics: {exc}"
            ) from exc
        raise
    if result.returncode == 1 and not diagnostics:
        raise TypeGateError("mypy exited 1 without parseable JSON diagnostics")
    return diagnostics


def parse_baseline(text: str) -> DiagnosticCounts:
    """Parse one versioned JSON baseline into stable diagnostic counts."""
    try:
        payload = cast(object, json.loads(text))
    except json.JSONDecodeError as exc:
        raise TypeGateError(f"baseline is not valid JSON: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise TypeGateError("baseline must be a version 1 JSON object")
    payload_map = cast(dict[str, object], payload)
    if type(payload_map.get("version")) is not int or payload_map["version"] != POLICY_VERSION:
        raise TypeGateError("baseline must be a version 1 JSON object")
    diagnostics = payload_map.get("diagnostics")
    if not isinstance(diagnostics, list):
        raise TypeGateError("baseline diagnostics must be a JSON list")
    return diagnostic_counts(cast(list[object], diagnostics))


def render_baseline(diagnostics: DiagnosticCounts) -> str:
    """Render deterministic versioned JSON containing only stable diagnostic keys."""
    entries = [
        {"file": path, "code": code, "message": message}
        for (path, code, message), count in sorted(diagnostics.items())
        for _ in range(count)
    ]
    return json.dumps(
        {"version": POLICY_VERSION, "diagnostics": entries},
        indent=2,
        sort_keys=True,
    ) + "\n"


def _format_counter(diagnostics: DiagnosticCounts) -> str:
    rendered: list[str] = []
    for (path, code, message), count in sorted(diagnostics.items()):
        diagnostic = f"{path}: [{code}] {message}"
        rendered.append(f"{count}x {diagnostic}" if count > 1 else diagnostic)
    return "\n".join(rendered) or "<none>"


def validate_candidate_baseline(
    current: DiagnosticCounts,
    candidate: DiagnosticCounts,
    trusted: DiagnosticCounts | None,
) -> None:
    """Require an exact current baseline that cannot exceed trusted-base debt."""
    if current != candidate:
        missing = candidate - current
        added = current - candidate
        raise TypeGateError(
            "\n".join(
                (
                    "candidate baseline does not exactly match current diagnostics",
                    f"stale/inflated entries:\n{_format_counter(missing)}",
                    f"unbaselined entries:\n{_format_counter(added)}",
                )
            )
        )
    if trusted is not None:
        growth = candidate - trusted
        if growth:
            raise TypeGateError(
                "candidate baseline exceeds trusted base diagnostic counts\n"
                + f"growth:\n{_format_counter(growth)}"
            )


def _run_git(run: Runner, arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
    try:
        return run(
            ["git", *arguments],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise TypeGateError(f"git execution failed: {exc}") from exc


def load_trusted_baseline(
    base_sha: str,
    *,
    run: Runner = subprocess.run,
) -> DiagnosticCounts | None:
    """Load the baseline from a proven git tree, or prove it is absent for bootstrap."""
    if SHA_PATTERN.fullmatch(base_sha) is None:
        raise TypeGateError("base SHA must be a full 40-character lowercase hexadecimal SHA")

    tree = _run_git(run, ("cat-file", "-e", f"{base_sha}^{{tree}}"))
    if tree.returncode != 0:
        detail = tree.stderr.strip() or "unknown git error"
        raise TypeGateError(f"trusted base tree lookup failed for {base_sha}: {detail}")

    listing = _run_git(run, ("ls-tree", "-z", "--full-tree", base_sha, "--", BASELINE_PATH))
    if listing.returncode != 0:
        raise TypeGateError(
            f"trusted base path lookup failed: {listing.stderr.strip() or 'unknown git error'}"
        )
    entries = [entry for entry in listing.stdout.split("\0") if entry]
    if not entries:
        return None
    if len(entries) != 1 or "\t" not in entries[0]:
        raise TypeGateError("trusted base path lookup returned malformed content")
    _, path = entries[0].split("\t", 1)
    if path != BASELINE_PATH:
        raise TypeGateError(f"trusted base path lookup returned unexpected path: {path}")

    shown = _run_git(run, ("show", f"{base_sha}:{BASELINE_PATH}"))
    if shown.returncode != 0:
        detail = shown.stderr.strip() or "unknown git error"
        raise TypeGateError(
            f"trusted base baseline content retrieval failed: {detail}"
        )
    return parse_baseline(shown.stdout)


def verify_type_gate(base_sha: str) -> tuple[int, int]:
    """Run the blocking critical check and the monotonic repository debt check."""
    critical = collect_mypy_diagnostics(CRITICAL_SURFACES)
    if critical:
        raise TypeGateError(
            f"critical-surface mypy policy failed\n{_format_counter(critical)}"
        )

    current = collect_mypy_diagnostics(("forge_cli",))
    candidate_path = ROOT / BASELINE_PATH
    try:
        candidate = parse_baseline(candidate_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise TypeGateError(f"candidate baseline read failed: {exc}") from exc
    trusted = load_trusted_baseline(base_sha)
    validate_candidate_baseline(current, candidate, trusted)
    return sum(critical.values()), sum(current.values())


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--base", required=True, help="full trusted PR or push base SHA")
    args = parser.parse_args(argv)
    base_sha = cast(str, args.base)
    try:
        critical_count, debt_count = verify_type_gate(base_sha)
    except TypeGateError as exc:
        print(f"type gate failed: {exc}", file=sys.stderr)
        return 1
    message = (
        f"Forge mypy policy v{POLICY_VERSION}: critical diagnostics={critical_count}; "
        f"repository debt diagnostics={debt_count}"
    )
    print(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
