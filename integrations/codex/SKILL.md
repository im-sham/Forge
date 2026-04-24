---
name: forge-incident-tracker
description: >
  Use this skill when you encounter an AI agent failure, error, or unexpected behavior
  during development. Also use when the user asks to "log a forge incident", "track this
  failure", "report this bug to forge", or mentions forge incident logging. Do NOT use
  for general bug tracking or non-AI-agent issues.
---

# Forge Incident Tracker

You have access to the Forge failure mode tracking system via MCP tools. Use these tools
to log and query AI agent incidents.

Forge owns incident memory and recurring failure-pattern learning. It does not own Workflow Context truth, Readiness scoring, Governance approval state, rights decisions, redaction review, export eligibility, or training/eval asset derivation.

## Available MCP Tools

- `forge_log` — Log a new incident (creates a YAML file)
- `forge_list` — List incidents with filters (project, severity, since, limit)
- `forge_show` — Show full details of one incident (by ID or suffix)
- `forge_stats` — Aggregate statistics across all incidents
- `forge_playbook_list` — List documented failure mode patterns
- `forge_playbook_show` — Show a specific playbook entry
- `forge_schema` — Get valid severity levels, failure types, and field names

## When to Log an Incident

Log a forge incident when any of these occur during your work:

1. An AI agent produces incorrect output (hallucination, wrong tool use)
2. An agent ignores instructions or drifts from its system prompt
3. An error handler silently swallows failures instead of surfacing them
4. An agent acts outside its defined scope
5. A safety boundary is crossed (data leak, unauthorized action)
6. Integration with external tools fails in an unexpected way
7. The user explicitly asks you to log a failure

## How to Log

When logging, always set `platform: "codex"` to identify this was captured from Codex.
Use `forge_schema` first if you need to check valid severity levels or failure types.

Required fields: `project`, `agent`, `severity`, `failure_type`, `expected_behavior`, `actual_behavior`

Recommended fields: `platform`, `context`, `root_cause`, `tags`

When logging Proofhouse-related incidents, use pointer-style context and tags instead of copying sensitive source material. Suitable tags include `workflow-context`, `readiness`, `governance`, `operational-learning`, `redaction`, and `use-approval`. Do not paste raw customer data, regulated personal data, credentials, or training/eval source material into Forge.

Example:
```
forge_log(
  project="support-agent",
  agent="respond-node",
  severity="functional",
  failure_type="hallucination",
  platform="codex",
  expected_behavior="Agent should have returned the correct API endpoint",
  actual_behavior="Agent fabricated a non-existent endpoint /api/v3/sync",
  context="Found during code review of agent/routes.py",
  tags="hallucination,api-endpoint"
)
```

## Querying Incidents

Use `forge_list`, `forge_show`, and `forge_stats` to help the user understand
patterns across their incidents. When showing results, highlight:

- Recurring failure types
- Safety-critical incidents that need attention
- Related incidents that form a pattern
- Playbook entries that offer prevention guidance
- Which owning capability should receive the handoff when the issue involves Workflow Context, Readiness, Governance, or Forge itself
