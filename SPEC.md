# Forge System Spec
## Failure Modes & Learnings System

> Historical note: this is Forge's original internal design specification from March 2026.
> The current public setup and usage guidance lives in `README.md`. Some examples below
> still reference early USMI project names because they reflect Forge's first deployment context.

**Created:** March 2, 2026
**Status:** Ready to build v0
**Owner:** Sham Rehman
**Environment:** Code (build immediately)

---

## Purpose

Forge is USMI's internal system for capturing, analyzing, and systematizing AI agent failure modes across all active projects (Mila, Scalescore, Aegis, and future products). It serves three functions:

1. **Operational:** Makes our current projects more reliable by capturing and learning from failures
2. **Content:** Generates the real-world data that powers Sham's public positioning (blog posts, playbook, conference talks)
3. **Product:** Becomes the seed dataset and foundational architecture for Sentinel's incident capture and analysis features

Forge is the engine that feeds everything else. It should be the first thing built.

---

## Design Principles

- **Capture is frictionless.** If it takes more than 60 seconds to log an incident, people won't do it. The system must minimize friction to the point where capturing a failure is easier than ignoring it.
- **Structure over freeform.** Every incident follows the same schema. This enables pattern analysis, taxonomy building, and eventual productization. Freeform notes are supplementary, not primary.
- **Git-native.** Incidents are YAML files in a git repo. This gives us versioning, collaboration, diffing, and zero infrastructure to start. No database needed for v0.
- **Claude-powered analysis.** Pattern detection and playbook generation use Claude, not custom ML. We're dogfooding our own thesis that AI augments human operational judgment.
- **Progressive sophistication.** v0 is CLI + YAML + Claude + Markdown. v1 adds a web interface. v2 adds real-time ingestion. Each version should work independently — we don't need v2 to get value from v0.

---

## Architecture

### v0: Minimum Viable System (Build This Week)

```
┌─────────────────────┐
│   Incident occurs    │
│   in any USMI        │
│   project            │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐     ┌─────────────────────┐
│   CLI Tool           │────►│   YAML file written  │
│   `forge log`        │     │   to git repo        │
│                      │     │   incidents/          │
│   Interactive prompts│     │     YYYY-MM-DD/       │
│   for structured     │     │       incident-001.yml│
│   fields             │     └─────────────────────┘
└─────────────────────┘
                                      │
                              ┌───────┘  (weekly/bi-weekly)
                              ▼
                    ┌─────────────────────┐
                    │   Analysis Script    │
                    │   `forge analyze`    │
                    │                      │
                    │   Reads all incidents│
                    │   Sends to Claude    │
                    │   Gets pattern report│
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Outputs:           │
                    │   - Pattern report   │
                    │   - Playbook updates │
                    │   - Severity trends  │
                    └─────────────────────┘
```

**Components:**
- `forge` — Python CLI tool (Click or Typer)
- `incidents/` — Directory of YAML incident files, organized by date
- `playbook/` — Markdown playbook files, one per failure mode pattern
- `analysis/` — Claude-generated pattern reports
- `schema.yaml` — Incident schema definition

### v1: Web Interface (Build when v0 has 50+ incidents)

- Simple FastAPI + HTMX web interface for logging and browsing incidents
- Dashboard showing incident trends, severity distribution, project breakdown
- Search and filter across all incidents
- Playbook viewer with linked incidents

### v2: Real-Time Ingestion (Build alongside Sentinel)

- Webhook/API endpoint that receives events from production agent systems
- Automated incident detection based on behavioral baselines
- Integration with Mila, Scalescore, and Aegis telemetry
- This version becomes the core of Sentinel's incident engine

---

## Incident Schema

```yaml
# incident-YYYY-MM-DD-NNN.yml

id: "2026-03-02-001"                    # Auto-generated: date + sequence
timestamp: "2026-03-02T14:30:00Z"       # When the incident occurred
reported_by: "sham"                      # Who logged this

# Classification
project: "mila"                          # Which USMI project: mila | scalescore | aegis | sentinel | other
agent: "document-analyzer"               # Which specific agent or component
severity: "functional"                   # cosmetic | functional | safety-critical
                                         #   cosmetic: wrong formatting, minor UX issue
                                         #   functional: wrong output, failed task, broken workflow
                                         #   safety-critical: harmful output, data leak, unauthorized action

# What happened
failure_type: "hallucination"            # Taxonomy (see below)
expected_behavior: |
  Agent should have extracted the three key financial metrics
  from the uploaded Q3 report and presented them in a summary.
actual_behavior: |
  Agent fabricated two of three metrics. The revenue figure was
  correct but the margin and growth rate were hallucinated.
  Confidence was stated as high despite fabrication.
context: |
  Document was a 47-page PDF. The relevant metrics were on page 31
  in a table. Agent appeared to process the document but may have
  lost context by page 31.

# Resolution
root_cause: "context_window_overflow"     # Best understanding of why this happened
immediate_fix: |
  Added page-specific extraction with explicit page references.
  Agent now extracts from targeted pages rather than full document.
systemic_takeaway: |
  Long documents need chunked extraction with verification.
  Agent confidence calibration is poor — high confidence on
  fabricated data is a recurring pattern across projects.

# Metadata
tags:
  - "hallucination"
  - "confidence-calibration"
  - "long-document"
  - "financial-data"
related_incidents: []                     # IDs of related incidents
playbook_entry: ""                        # Link to relevant playbook entry once created
```

### Failure Type Taxonomy

Start with these categories. Expand as patterns emerge.

| Type | Description | Example |
|------|-------------|---------|
| `hallucination` | Agent generates factually incorrect information | Fabricated metrics, invented citations |
| `tool_misuse` | Agent uses a tool incorrectly or inappropriately | Wrong API called, malformed parameters |
| `scope_creep` | Agent acts outside its defined boundaries | Answering questions outside its domain, taking unauthorized actions |
| `safety_boundary_violation` | Agent crosses a safety or ethical boundary | Generating harmful content, leaking private data |
| `performance_degradation` | Agent output quality drops without obvious cause | Increasingly poor responses over conversation length |
| `context_loss` | Agent loses track of relevant context | Forgetting earlier instructions, contradicting prior statements |
| `confidence_miscalibration` | Agent expresses inappropriate confidence levels | High confidence on wrong answers, low confidence on correct ones |
| `instruction_drift` | Agent gradually deviates from its system prompt or instructions | Personality changes, ignoring guardrails over time |
| `error_handling_failure` | Agent fails to gracefully handle errors or edge cases | Crashes, loops, or produces garbage on unexpected input |
| `integration_failure` | Failure in agent's interaction with external systems | API timeouts not handled, malformed responses from tools |
| `adversarial_vulnerability` | Agent susceptible to prompt injection or manipulation | Following instructions from untrusted content |
| `other` | Doesn't fit existing categories (flag for taxonomy review) | — |

---

## Claude Analysis Prompt

This is the prompt used for periodic pattern analysis. Run weekly or bi-weekly via `forge analyze`.

```markdown
You are an AI safety analyst reviewing incident reports from USMI Labs'
AI agent systems. Your job is to identify patterns, assess systemic risks,
and recommend both immediate mitigations and architectural improvements.

## Incident Data

[INCIDENTS ARE INSERTED HERE AS YAML]

## Analysis Required

Please provide:

### 1. Pattern Identification
- What recurring failure modes do you see?
- Are any failure types increasing in frequency or severity?
- Are specific projects or agents disproportionately affected?

### 2. Root Cause Analysis
- What are the underlying systemic causes behind the patterns?
- Are there shared architectural weaknesses across projects?
- Which root causes, if addressed, would prevent the most incidents?

### 3. Risk Assessment
- Rate each identified pattern: LOW / MEDIUM / HIGH / CRITICAL
- Which patterns pose the greatest risk if they occur in production
  with real users or in regulated contexts?
- Are there any patterns that suggest emerging risks not yet realized?

### 4. Recommendations
For each identified pattern, provide:
- **Detection method:** How to catch this failure mode early
- **Prevention method:** Architectural or design changes to prevent it
- **Monitoring suggestion:** What to watch for ongoing
- **Guardrail specification:** What technical control would prevent this

### 5. Playbook Updates
- Which existing playbook entries need updating based on new data?
- What new playbook entries should be created?
- Provide draft content for any new entries.

### 6. Trend Analysis
- Compare to previous analysis periods if available
- Are we improving, stable, or degrading on key failure modes?
- What does the trend suggest about our overall safety posture?

## Output Format

Structure your response as:
1. Executive Summary (3-5 sentences)
2. Pattern Details (one section per pattern)
3. Risk Matrix (table format)
4. Prioritized Recommendations (numbered, highest impact first)
5. Playbook Updates (specific content for each)
6. Trend Analysis (if prior data available)
```

---

## CLI Tool Specification

### Commands

```bash
# Log a new incident (interactive)
forge log
# Prompts for: project, agent, severity, failure_type, expected, actual, context, root_cause, fix, takeaway, tags

# Log with pre-filled fields (for scripting or quick capture)
forge log --project mila --severity functional --type hallucination

# List recent incidents
forge list                    # Last 10 incidents
forge list --project mila     # Filter by project
forge list --severity safety-critical  # Filter by severity
forge list --since 2026-03-01 # Filter by date

# Run Claude analysis
forge analyze                 # Analyze all unanalyzed incidents
forge analyze --since 2026-03-01  # Analyze incidents since date
forge analyze --full          # Re-analyze everything

# View/update playbook
forge playbook                # List all playbook entries
forge playbook show hallucination  # Show specific entry

# Stats
forge stats                   # Summary: counts by type, severity, project, trend
```

### File Structure

```
forge/
├── forge.py                  # CLI tool
├── schema.yaml               # Incident schema definition
├── config.yaml               # Configuration (Claude model, paths, etc.)
├── incidents/
│   ├── 2026-03/
│   │   ├── 2026-03-02-001.yml
│   │   ├── 2026-03-02-002.yml
│   │   └── ...
│   └── 2026-04/
│       └── ...
├── analysis/
│   ├── 2026-03-15-weekly.md
│   ├── 2026-03-29-weekly.md
│   └── ...
├── playbook/
│   ├── index.md              # Playbook table of contents
│   ├── hallucination.md
│   ├── tool-misuse.md
│   ├── scope-creep.md
│   └── ...
└── templates/
    ├── incident.yml          # Blank incident template
    └── analysis-prompt.md    # Claude analysis prompt template
```

---

## Implementation Plan

### This Week (v0 — Get Capturing)
1. Create the forge directory structure in the USMI project folder
2. Build `forge.py` CLI with `log`, `list`, and `analyze` commands
3. Create the incident schema template
4. Log the first 3-5 incidents from memory (recent failures across Mila, Scalescore, Aegis)
5. Run first Claude analysis

### Week 2-3 (v0 Refinement)
6. Add `stats` and `playbook` commands
7. Refine the taxonomy based on actual incidents logged
8. Write first playbook entries based on analysis
9. Establish capture habit: log every failure as it happens

### Month 2 (v0 → v1 Transition)
10. Assess: do we have 30+ incidents? Is the taxonomy stable?
11. If yes: build simple web interface (FastAPI + HTMX)
12. Add search, filtering, and dashboarding
13. First public blog post derived from Forge data

### Month 3+ (v1 → v2 Planning)
14. Design real-time ingestion API
15. Plan integration hooks for Mila, Scalescore, Aegis
16. This is where Forge starts becoming Sentinel's incident engine

---

## Connection to Sentinel

Forge is Sentinel's R&D lab. Specifically:

| Forge Component | Becomes Sentinel Feature |
|----------------|------------------------|
| Incident schema | Customer incident capture API |
| Failure taxonomy | Standardized classification for enterprise use |
| Claude analysis prompt | Automated pattern detection engine |
| Playbook entries | Customer-facing response protocols |
| CLI tool | Sentinel SDK for developer integration |
| Web interface (v1) | Sentinel dashboard |
| Real-time ingestion (v2) | Sentinel's core monitoring pipeline |

Every line of code written for Forge has a second life in Sentinel. Nothing is throwaway.

---

*Take this spec into Claude Code. Build v0 this week. Start capturing immediately.*
