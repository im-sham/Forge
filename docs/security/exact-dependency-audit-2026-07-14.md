# Exact Dependency Audit

Date: 2026-07-14
Scope: Forge CLI, MCP server, Anthropic analysis, and OpenAI analysis install sets

## Resolution boundary

`pyproject.toml` remains the lower-bound package declaration and explicitly
supports Python 3.11 through 3.13. `uv.lock` is the universal application
resolution. The generated `requirements/*.lock` files are hash-locked exports:

| Lock | Purpose | Deployable |
| --- | --- | --- |
| `core.lock` | CLI and local incident store | Yes |
| `mcp.lock` | Core plus local MCP server | Yes |
| `anthropic.lock` | Core plus Anthropic analysis provider | Yes |
| `openai.lock` | Core plus OpenAI analysis provider | Yes |
| `dev.lock` | Tests, lint, and the MCP surface exercised by tests | No |
| `build.lock` | Exact isolated wheel construction | No |
| `audit-tools.lock` | Exact security-audit tooling | No |

The repository has no Dockerfile, hosted service manifest, or other container
artifact. The built Python wheel plus one selected runtime lock and an external
`FORGE_DATA_ROOT` is therefore the deployable artifact boundary; this work does
not invent a container claim. The installed package bundles its default
analysis prompt and can run without a source checkout. A checkout-local
`templates/` directory remains an intentional development override.

Regenerate and verify all artifacts with pinned `uv 0.11.28`:

```bash
python scripts/verify_dependency_artifacts.py --generate
python scripts/verify_dependency_artifacts.py --check-lock
```

CI builds the wheel in a no-pip virtual environment containing exactly
`build.lock`, then installs each deployable lock into a clean environment that
retains `pip` only as explicit bootstrap tooling, with hashes and no dependency
resolution. It installs the wheel with `--no-deps`, runs `uv pip check`, and
verifies the installed distribution set in both directions. On supported Linux
and macOS data-store runtimes, behavioral smoke runs from outside the checkout
against an external data root: a CLI corpus read, an MCP log/list round trip,
packaged-template analysis preparation, and offline provider construction.
Forge's fail-closed incident store requires POSIX path and rename primitives, so
Windows is an install, import, CLI-help, MCP-schema, provider, dependency-audit,
and marker-coverage target rather than a supported data-store runtime.
Production parity and advisory audits are matrixed on Python 3.11, 3.12, and
3.13 across Linux, macOS, and Windows so active PEP 508 marker branches are
exercised. Full tests run on Python 3.11, 3.12, and 3.13 from the exact
development lock. MCP dependencies are deliberately present in `dev.lock` so
MCP tests cannot silently skip.

## Audit disposition

Local `pip-audit 2.10.1` verification on macOS/Python 3.13 on 2026-07-14
reported no known vulnerabilities in the active subset of any of the four
exact deployment sets. The hosted matrix is the acceptance evidence for all
declared target combinations, including Windows-only packages; it remains
pending until this draft branch runs in GitHub. CI uses no advisory ignore flags
and audits optional surfaces separately so provider or MCP dependencies cannot
contaminate the core result.

Any future exception must be recorded in
`dependency-advisory-exceptions.json` with advisory ID, package, owner,
rationale, affected surface, compensating control, and expiry. Lock validation
rejects missing, duplicate, malformed, or expired entries. The registry is
currently empty.

## SBOM and rollback

Each concrete Python/platform target emits a deterministic CycloneDX 1.6
inventory for every deployment lock. Each inventory includes the Forge wheel as
the root application, its filename and SHA-256, the active exact name/version
set, the dependency-surface name, the Python target, and the universal lock
SHA-256. Direct root dependencies are modeled without falsely declaring every
transitive package to be a direct dependency. CI generates each inventory twice,
byte-compares it, and validates it against the strict CycloneDX 1.6 JSON schema
before upload. These are language-package inventories; they do not claim
operating-system or container coverage because Forge has no container artifact.

The pre-remediation repository had no committed application lock or retained
immutable wheel digest. `requirements/rollback/pre-wp-ri-05.json` records the
accepted source commit and tree that reconstruct the previous resolver
behavior, but it cannot retroactively satisfy the master spec's prior-lock/image
retention criterion. That one criterion remains `requires-human-disposition`;
it is not presented as complete. CI retains each new target's wheel, locks, and
audit/SBOM evidence for 90 days, but this repository does not claim durable
registry publication or production deployment.
