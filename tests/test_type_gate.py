from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import subprocess

import pytest

from scripts.verify_type_gate import (
    BASELINE_PATH,
    CRITICAL_SURFACES,
    MYPY_ARGS,
    POLICY_VERSION,
    TypeGateError,
    collect_mypy_diagnostics,
    diagnostic_counts,
    load_trusted_baseline,
    parse_baseline,
    render_baseline,
    validate_candidate_baseline,
)


ROOT = Path(__file__).resolve().parents[1]
DiagnosticKey = tuple[str, str, str]


def _diagnostic(
    *,
    path: str = "forge_cli/example.py",
    code: str = "assignment",
    message: str = "incompatible assignment",
    line: int = 1,
    column: int = 0,
) -> dict[str, object]:
    return {
        "file": path,
        "line": line,
        "column": column,
        "message": message,
        "hint": None,
        "code": code,
        "severity": "error",
    }


def _key(
    *,
    path: str = "forge_cli/example.py",
    code: str = "assignment",
    message: str = "incompatible assignment",
) -> DiagnosticKey:
    return (path, code, message)


def test_policy_is_versioned_and_wired_to_exact_critical_surfaces() -> None:
    assert POLICY_VERSION == 1
    assert BASELINE_PATH == "typing/mypy-baseline-v1.json"
    assert CRITICAL_SURFACES == (
        "forge_cli/models.py",
        "forge_cli/incident_store.py",
    )
    assert MYPY_ARGS == (
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

    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "fetch-depth: 0" in workflow
    assert "github.event.pull_request.base.sha" in workflow
    assert "github.event.before" in workflow
    assert "python scripts/verify_type_gate.py --base" in workflow


def test_actual_mypy_policy_rejects_wrong_return(tmp_path: Path) -> None:
    module = tmp_path / "wrong_return.py"
    module.write_text("def wrong() -> str:\n    return 1\n", encoding="utf-8")

    diagnostics = collect_mypy_diagnostics((str(module),))

    assert any("Incompatible return value type" in key[2] for key in diagnostics)
    assert any(key[1] == "return-value" for key in diagnostics)


def test_line_and_column_movement_does_not_change_normalized_diagnostics() -> None:
    before = _diagnostic(line=10, column=4)
    after = _diagnostic(line=200, column=19)

    assert diagnostic_counts([before]) == diagnostic_counts([after])


def test_rendered_baseline_contains_only_versioned_stable_keys() -> None:
    diagnostic = _key()

    payload = json.loads(render_baseline(Counter({diagnostic: 1})))

    assert payload == {
        "diagnostics": [
            {
                "code": "assignment",
                "file": "forge_cli/example.py",
                "message": "incompatible assignment",
            }
        ],
        "version": 1,
    }


def test_candidate_baseline_rejects_stale_diagnostics() -> None:
    candidate = Counter({_key(): 1})

    with pytest.raises(TypeGateError, match="does not exactly match"):
        validate_candidate_baseline(Counter(), candidate, candidate)


def test_candidate_baseline_rejects_replaced_diagnostic_without_count_growth() -> None:
    original = _key(message="old assignment")
    replacement = _key(code="return-value", message="wrong return")

    with pytest.raises(TypeGateError, match="does not exactly match"):
        validate_candidate_baseline(
            Counter({replacement: 1}),
            Counter({original: 1}),
            Counter({original: 1}),
        )


def test_candidate_baseline_rejects_inflation() -> None:
    diagnostic = _key()

    with pytest.raises(TypeGateError, match="does not exactly match"):
        validate_candidate_baseline(
            Counter({diagnostic: 1}),
            Counter({diagnostic: 2}),
            Counter({diagnostic: 2}),
        )


def test_trusted_base_subset_comparison_counts_duplicates() -> None:
    diagnostic = _key()

    with pytest.raises(TypeGateError, match="exceeds trusted base"):
        validate_candidate_baseline(
            Counter({diagnostic: 2}),
            Counter({diagnostic: 2}),
            Counter({diagnostic: 1}),
        )


def test_baseline_parser_preserves_duplicate_counts() -> None:
    diagnostic = _diagnostic()
    text = json.dumps({"version": 1, "diagnostics": [diagnostic, diagnostic]})

    assert parse_baseline(text) == Counter({_key(): 2})


@pytest.mark.parametrize(
    "text",
    [
        "{",
        "[]",
        json.dumps({"version": 2, "diagnostics": []}),
        json.dumps({"version": 1, "diagnostics": {}}),
    ],
)
def test_malformed_baseline_json_fails_closed(text: str) -> None:
    with pytest.raises(TypeGateError):
        parse_baseline(text)


@pytest.mark.parametrize("field", ["file", "code", "message"])
@pytest.mark.parametrize("value", ["", None])
def test_empty_or_missing_required_diagnostic_fields_fail_closed(
    field: str,
    value: object,
) -> None:
    diagnostic = _diagnostic()
    diagnostic[field] = value
    text = json.dumps({"version": 1, "diagnostics": [diagnostic]})

    with pytest.raises(TypeGateError, match="non-empty file, code, and message"):
        parse_baseline(text)


@pytest.mark.parametrize("stdout", ["", "not-json\n"])
def test_mypy_exit_one_without_parseable_diagnostics_fails_closed(stdout: str) -> None:
    def run(command, **kwargs):
        return subprocess.CompletedProcess(command, 1, stdout, "")

    with pytest.raises(TypeGateError, match="without parseable JSON diagnostics"):
        collect_mypy_diagnostics(("forge_cli",), run=run)


def _git_runner(
    *,
    tree_returncode: int = 0,
    listing_returncode: int = 0,
    tree_output: str = "",
    show_returncode: int = 0,
    show_output: str = '{"version": 1, "diagnostics": []}\n',
):
    def run(command, **kwargs):
        if command[1:3] == ["cat-file", "-e"]:
            return subprocess.CompletedProcess(command, tree_returncode, "", "bad tree")
        if command[1] == "ls-tree":
            return subprocess.CompletedProcess(command, listing_returncode, tree_output, "bad listing")
        if command[1] == "show":
            return subprocess.CompletedProcess(command, show_returncode, show_output, "bad show")
        raise AssertionError(f"unexpected command: {command}")

    return run


def test_invalid_base_sha_fails_closed() -> None:
    with pytest.raises(TypeGateError, match="full 40-character"):
        load_trusted_baseline("not-a-sha", run=_git_runner())


def test_invalid_base_tree_fails_closed() -> None:
    with pytest.raises(TypeGateError, match="tree lookup failed"):
        load_trusted_baseline("a" * 40, run=_git_runner(tree_returncode=1))


def test_base_path_lookup_failure_fails_closed() -> None:
    with pytest.raises(TypeGateError, match="path lookup failed"):
        load_trusted_baseline("a" * 40, run=_git_runner(listing_returncode=1))


def test_missing_base_baseline_bootstraps_only_after_successful_tree_lookup() -> None:
    assert load_trusted_baseline("a" * 40, run=_git_runner(tree_output="")) is None


def test_base_baseline_show_failure_fails_closed() -> None:
    tree_output = f"100644 blob {'b' * 40}\t{BASELINE_PATH}\0"

    with pytest.raises(TypeGateError, match="content retrieval failed"):
        load_trusted_baseline(
            "a" * 40,
            run=_git_runner(tree_output=tree_output, show_returncode=1),
        )


def test_malformed_trusted_baseline_fails_closed() -> None:
    tree_output = f"100644 blob {'b' * 40}\t{BASELINE_PATH}\0"

    with pytest.raises(TypeGateError):
        load_trusted_baseline(
            "a" * 40,
            run=_git_runner(tree_output=tree_output, show_output="{"),
        )
