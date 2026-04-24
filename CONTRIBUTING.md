# Contributing to Forge

Thanks for contributing to Forge.

## Before You Open A PR

- open an issue or discussion for larger changes
- keep pull requests focused and easy to review
- avoid bundling unrelated refactors with behavior changes

## Local Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,mcp]"
```

## Checks

Run these before opening a pull request:

```bash
ruff check forge_cli/ tests/
pytest tests/ -v
```

## Data Hygiene

Forge is designed so code can be public while incident data stays private.

Please do not commit:

- real incident corpora
- internal analysis outputs
- customer data
- regulated personal data
- training/eval source material
- rights, redaction, use-approval, or export manifests copied from Governance
- local `config.local.yaml` files
- machine-specific settings

If you need sample incidents or playbook entries for a change, use sanitized examples only.

## Pull Request Guidance

- describe the user-facing impact
- call out any schema or CLI contract changes
- add or update tests when behavior changes
- update README or integration docs if setup or usage changes

## Licensing

By submitting a contribution, you agree that your contribution will be licensed under the Apache-2.0 license used by this repository.
