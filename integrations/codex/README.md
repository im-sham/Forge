# Forge + Codex Integration

Connect Forge to OpenAI Codex CLI so incidents can be logged from Codex sessions alongside Claude Code.

## Setup

### 1. Add Forge MCP server to Codex config

Add to `~/.codex/config.toml`:

```toml
[mcp_servers.forge]
command = "/Users/shamimrehman/Projects/USMI/forge/.venv/bin/python3"
args = ["-m", "forge_cli.mcp_server"]
cwd = "/Users/shamimrehman/Projects/USMI/forge"
```

This makes `forge_log`, `forge_list`, `forge_show`, `forge_stats`, `forge_playbook_list`, `forge_playbook_show`, and `forge_schema` available as tools in every Codex session.

### 2. Install the Forge skill

Copy (or symlink) the skill directory into your Codex skills location:

```bash
# Option A: Symlink
ln -s /Users/shamimrehman/Projects/USMI/forge/integrations/codex \
      ~/.codex/skills/forge-incident-tracker

# Option B: Register in config.toml
```

Add to `~/.codex/config.toml`:

```toml
[[skills.config]]
path = "/Users/shamimrehman/Projects/USMI/forge/integrations/codex/SKILL.md"
enabled = true
```

### 3. Verify

Start a Codex session and try:

```
$forge-incident-tracker list all forge incidents
```

Or just describe a failure — the skill's implicit invocation will activate when it detects AI agent failure language.

## How it works

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│  Codex CLI   │────▶│  Forge MCP   │────▶│  YAML files  │
│  (platform:  │     │  Server      │     │  in git repo │
│   codex)     │     │  (stdio)     │     │              │
└─────────────┘     └──────────────┘     └──────────────┘
                                                │
                           Same incident store as:
                                                │
┌─────────────┐     ┌──────────────┐            │
│ Claude Code  │────▶│  Forge MCP   │────────────┘
│  (platform:  │     │  Server      │
│  claude-code)│     │  (stdio)     │
└─────────────┘     └──────────────┘
```

Both tools write to the same `incidents/` directory. `forge stats` aggregates across all platforms. The `platform` field distinguishes where each incident was captured.

## Usage from Codex

**Log an incident:**
> "Log a forge incident: the mila respond-node hallucinated an API endpoint"

**Check stats:**
> "Show me forge stats"

**View playbook:**
> "Show the forge playbook entry for silent fallback"

**List recent incidents:**
> "List all safety-critical forge incidents"

The skill handles mapping natural language to the correct MCP tool calls.
