# Forge

AI agent failure mode tracking and analysis. Git-native, platform-agnostic, model-agnostic.

Built by [USMI Labs](https://usmachineintelligence.com).

## What it does

Forge captures AI agent failures as structured YAML incidents, analyzes patterns across projects, and builds a playbook of recurring failure modes. Works with any AI tool (Claude, Cursor, ChatGPT, Codex, custom agents) and any LLM provider for analysis (Anthropic, OpenAI).

## Quick start

```bash
# Clone and install
git clone https://github.com/im-sham/Forge.git
cd Forge
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Log an incident
forge log

# List recent incidents
forge list

# View full details
forge show 2026-03-04-001

# Stats dashboard
forge stats

# View playbook
forge playbook
forge playbook show silent-fallback
```

## CLI commands

| Command | Description |
|---------|-------------|
| `forge log` | Log a new incident (interactive prompts) |
| `forge list` | List incidents with `--project`, `--severity`, `--since`, `--limit` filters |
| `forge show <id>` | Full details of one incident (supports suffix match: `forge show 001`) |
| `forge stats` | Aggregate stats by severity, type, project, platform, tags |
| `forge playbook` | List playbook entries |
| `forge playbook show <name>` | Show a specific playbook entry (partial match supported) |
| `forge analyze` | Run LLM pattern analysis (requires API key) |

## MCP server

Forge exposes 7 tools via the [Model Context Protocol](https://modelcontextprotocol.io) for use from Claude Code, Claude Desktop, or any MCP client.

**Tools:** `forge_log`, `forge_list`, `forge_show`, `forge_stats`, `forge_playbook_list`, `forge_playbook_show`, `forge_schema`

### Claude Code

The `.mcp.json` in the repo auto-configures the server. Just open a Claude Code session in the forge directory.

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "forge": {
      "command": "/path/to/forge/.venv/bin/python3",
      "args": ["-m", "forge_cli.mcp_server"],
      "cwd": "/path/to/forge"
    }
  }
}
```

## Incident schema

Each incident is a YAML file in `incidents/YYYY-MM/` with 17 structured fields:

- **Classification:** project, agent, platform, severity, failure_type
- **What happened:** expected_behavior, actual_behavior, context
- **Resolution:** root_cause, immediate_fix, systemic_takeaway
- **Metadata:** tags, related_incidents, playbook_entry

### Severity levels

| Level | Meaning |
|-------|---------|
| `cosmetic` | Wrong formatting, minor UX issue |
| `functional` | Wrong output, failed task, broken workflow |
| `safety-critical` | Harmful output, data leak, unauthorized action |

### Failure types

`hallucination`, `tool_misuse`, `scope_creep`, `safety_boundary_violation`, `performance_degradation`, `context_loss`, `confidence_miscalibration`, `instruction_drift`, `error_handling_failure`, `integration_failure`, `adversarial_vulnerability`, `other`

## Analysis

Forge supports two analysis modes:

**API-based:** `forge analyze` sends incidents to an LLM for pattern analysis. Supports `--provider anthropic|openai`.

```bash
# Install provider SDK
pip install -e ".[anthropic]"  # or .[openai]

# Set API key
export ANTHROPIC_API_KEY=sk-...

# Run analysis
forge analyze
```

**Claude Code slash command:** Use `/forge-analyze` in Claude Code for API-free analysis within the conversation.

## Project structure

```
forge/
├── forge_cli/           # Python package
│   ├── cli.py           # Typer CLI (log, list, show, analyze, stats, playbook)
│   ├── mcp_server.py    # MCP server (7 tools)
│   ├── models.py        # Incident dataclass, enums, field ordering
│   ├── config.py        # Config loading, project root discovery
│   ├── incident_store.py # YAML file I/O, ID generation, filtering
│   ├── display.py       # Rich formatting (tables, panels, stats)
│   ├── analyzer.py      # LLM analysis orchestration
│   └── providers.py     # LLM provider protocol (Anthropic, OpenAI)
├── incidents/           # YAML incident files by month
├── playbook/            # Markdown playbook entries
├── analysis/            # LLM-generated pattern reports
├── templates/           # Incident template, analysis prompt
├── tests/               # 25 pytest tests
├── config.yaml          # Project configuration
└── SPEC.md              # Original design specification
```

## License

Internal USMI Labs project. See [SPEC.md](SPEC.md) for design specification and roadmap.
