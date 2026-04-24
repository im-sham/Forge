# Forge

Git-native incident tracking and pattern analysis for AI agents.

Forge helps teams capture agent failures as structured YAML incidents, analyze recurring patterns, and build institutional memory across tools, teams, and providers.

Built by [USMI Labs](https://usmi.ai).

## Why Forge

- Local-first incident tracking in plain YAML
- Works across Claude, Codex, Cursor, ChatGPT, Copilot, and custom agents
- CLI for logging, browsing, and analysis
- MCP server for agent-native workflows
- Supports private data roots outside the code repo
- Keeps schemas and tooling reusable even when incident data stays private

## Install

```bash
git clone https://github.com/im-sham/Forge.git
cd Forge
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,mcp]"
```

## Quick Start

```bash
# Log an incident interactively
forge log

# List recent incidents
forge list

# Inspect one incident from the list
forge show <incident-id>

# Review aggregate patterns
forge stats

# Prepare a rendered analysis prompt without calling an LLM
forge analyze --prepare-only
```

## Public Code, Private Data

Forge is designed so the code can be public while your live incident corpus stays private.

The repo ships with empty `incidents/`, `playbook/`, and `analysis/` directories by default. For real usage, point Forge at an external data root:

```bash
cp config.local.example.yaml config.local.yaml
```

```yaml
data_root: "~/Library/Application Support/Forge/default"
```

Or set:

```bash
export FORGE_DATA_ROOT="$HOME/Library/Application Support/Forge/default"
```

Forge will read `incidents/`, `playbook/`, and `analysis/` from that external path while keeping templates, code, tests, and integrations in the repo.

You can also set an `organization_name` in `config.yaml` or `config.local.yaml` to personalize analysis prompts and generated analysis-input files.

## CLI Commands

| Command | Description |
|---------|-------------|
| `forge log` | Log a new incident with interactive prompts |
| `forge list` | List incidents with `--project`, `--severity`, `--since`, `--tag`, and `--limit` filters |
| `forge show <id>` | Show full details of one incident; suffix matches like `forge show 001` work |
| `forge edit <id>` | Open an incident in your editor |
| `forge stats` | Show aggregate counts by severity, type, project, platform, and tags |
| `forge playbook` | List playbook entries |
| `forge playbook show <name>` | Show one playbook entry |
| `forge analyze` | Run LLM-backed pattern analysis |
| `forge analyze --prepare-only` | Save the fully rendered analysis input without calling an LLM |
| `forge mcp serve` | Run Forge as a Streamable HTTP MCP server with local-only defaults |

## MCP Server

Forge exposes tools over the [Model Context Protocol](https://modelcontextprotocol.io) so agent tools can log and query incidents directly.

Available tools:

- `forge_log`
- `forge_list`
- `forge_show`
- `forge_stats`
- `forge_playbook_list`
- `forge_playbook_show`
- `forge_schema`

### Local stdio MCP

Use stdio when the MCP client runs on the same machine as Forge.

### Claude Code

The repo includes a generic `.mcp.json`. After installing dependencies, open the repo in Claude Code and the Forge server can be auto-discovered from the workspace.

### Claude Desktop

Add an MCP server entry like this:

```json
{
  "mcpServers": {
    "forge": {
      "command": "/absolute/path/to/Forge/.venv/bin/python3",
      "args": ["-m", "forge_cli.mcp_server"],
      "cwd": "/absolute/path/to/Forge"
    }
  }
}
```

### Codex

See [integrations/codex/README.md](integrations/codex/README.md) for Codex setup and the Forge skill.

### Streamable HTTP MCP

Use HTTP when a remote agent or another machine needs to talk to Forge over MCP.

Local-only default:

```bash
forge mcp serve
```

This starts Forge on `http://127.0.0.1:8765/mcp` with DNS rebinding protection enabled.

Trusted private-network example:

```bash
forge mcp serve \
  --host 0.0.0.0 \
  --port 8765 \
  --allow-remote \
  --disable-dns-rebinding-protection
```

The remote bind flags are intentionally explicit. They are meant for trusted private-network setups such as Tailscale, not for public internet exposure.

## Incident Schema

Each incident is a YAML file in `incidents/YYYY-MM/` with structured fields covering:

- classification: `project`, `agent`, `platform`, `severity`, `failure_type`
- event details: `expected_behavior`, `actual_behavior`, `context`
- resolution: `root_cause`, `immediate_fix`, `systemic_takeaway`
- metadata: `tags`, `related_incidents`, `playbook_entry`

### Severity Levels

| Level | Meaning |
|-------|---------|
| `cosmetic` | Minor formatting or UX issue |
| `functional` | Wrong output, broken workflow, or failed task |
| `safety-critical` | Harmful output, data leak, or unauthorized action |

### Failure Types

`hallucination`, `tool_misuse`, `scope_creep`, `safety_boundary_violation`, `performance_degradation`, `context_loss`, `confidence_miscalibration`, `instruction_drift`, `error_handling_failure`, `integration_failure`, `adversarial_vulnerability`, `other`

## Analysis Modes

### API-backed analysis

```bash
pip install -e ".[anthropic]"   # or .[openai]
export ANTHROPIC_API_KEY=sk-...
forge analyze
```

### Prepare-only analysis

If you want to inspect or paste the analysis input into another tool yourself:

```bash
forge analyze --prepare-only
```

This writes a dated `analysis-input` file into the active Forge data root.

## Development

```bash
pip install -e ".[dev,mcp]"
ruff check forge_cli/ tests/
pytest tests/ -v
```

## Project Structure

```text
forge/
├── forge_cli/
├── integrations/
├── templates/
├── incidents/          # empty by default; live data can stay external
├── playbook/           # empty by default; live data can stay external
├── analysis/           # empty by default; live data can stay external
├── tests/
├── .github/workflows/
├── config.yaml
├── config.local.example.yaml
└── SPEC.md
```

## Documentation

- [SPEC.md](SPEC.md) - original design specification
- [integrations/codex/README.md](integrations/codex/README.md) - Codex setup
- [CONTRIBUTING.md](CONTRIBUTING.md) - contribution workflow
- [SECURITY.md](SECURITY.md) - security reporting

## License

Apache-2.0. See [LICENSE](LICENSE).
