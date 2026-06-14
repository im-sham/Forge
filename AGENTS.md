# Agent Guide

Forge is the Proofhouse incident-memory and failure-pattern learning layer. Read
this before changing code, tests, integrations, or docs.

## Product Boundary

Forge owns:

- incident records
- incident severity and failure classification
- recurring failure patterns
- playbook entries
- incident-memory feedback to other Proofhouse capabilities

Forge does not own Workflow Context truth, Readiness scores, Governance rights
or approvals, Operational Learning asset derivation, promotion state, or
training/eval bundle contents.

Suite boundaries:

- Workflow Context owns canonical workflow truth, traces, source evidence, and
  operational context.
- Readiness owns readiness scoring, trust-gap diagnosis, remediation priorities,
  and Operational Learning suitability.
- Governance owns rights, redaction review, use approvals, export control,
  manifests, and audit-grade evidence.
- Operational Learning owns asset derivation, package work, and promotion state.

Forge may point to those records. It should not copy their canonical state.

## Data Handling

- Keep incidents pointer/ref-first when they relate to Proofhouse workflow
  evidence, Governance use control, or Operational Learning promotion/transform
  paths.
- Do not paste raw customer data, regulated personal data, credentials, source
  documents, training/eval source material, rights records, approval records, or
  export manifests into incident YAML.
- Core free-text fields are summary-only: `expected_behavior`,
  `actual_behavior`, `context`, `root_cause`, `immediate_fix`, and
  `systemic_takeaway`.
- Tags are discovery aids, not the structured contract. Prefer explicit axes
  such as `capability_area`, `lifecycle_stage`, `issue_class`,
  `workflow_archetype`, `subject_type`, and `blocked_use_class` when an incident
  touches Proofhouse boundaries.
- The code repo can be public while real incident data stays private. Keep live
  incident corpora outside the checkout through `FORGE_DATA_ROOT` or
  `config.local.yaml`.

## Implementation Seams

- `forge_cli/models.py` defines incident fields, validation, and `IncidentRef`
  projection behavior.
- `forge_cli/incident_store.py` owns ID allocation, YAML persistence, lookup,
  listing, and stats helpers.
- `forge_cli/cli.py` owns Typer CLI commands.
- `forge_cli/mcp_server.py`, `forge_cli/mcp_http.py`, and `forge_cli/mcp_sse.py`
  own MCP surfaces.
- `forge_cli/analyzer.py`, `forge_cli/providers.py`, and
  `templates/analysis-prompt.md` shape analysis flows.
- `integrations/codex/SKILL.md` is the Codex integration guidance for logging
  incidents.
- `tests/` covers CLI, model, store, stats, MCP, config, and analysis behavior.

## Development Workflow

- Prefer narrow PRs scoped to one command, model contract, storage behavior, or
  integration surface.
- Add or update tests before changing implementation behavior.
- Preserve backward compatibility for existing incident YAML. New Proofhouse
  axes and refs should remain optional unless a migration plan exists.
- Keep local-only MCP defaults safe. Remote bind flags must remain explicit and
  suitable only for trusted private-network setups.
- Do not make Forge responsible for upstream redaction, DLP, PHI
  classification, use approval, export approval, or workflow truth.

Useful local commands:

```bash
PYTHONPATH=. python -m ruff check .
PYTHONPATH=. python -m pytest
PYTHONPATH=. python -m compileall forge_cli tests
git diff --check
```

Use the project virtualenv when available. In this workspace that is usually:

```bash
PYTHONPATH=. /Users/shamimrehman/Projects/USMI/forge/.venv/bin/python -m pytest
```
