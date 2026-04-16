---
description: Analyze forge incidents for patterns — no API key needed
---

Resolve the active Forge paths first:

1. Load Forge config from the repo root using `forge_cli.config.load_config()`.
2. Use `cfg.incidents_dir` as the source of truth for incidents.
3. Use `cfg.templates_dir / "analysis-prompt.md"` for the prompt template.
4. Save the finished report into `cfg.analysis_dir`.

This matters because Forge may be configured with an external `data_root` via `config.local.yaml` or `FORGE_DATA_ROOT`. Do not assume the repo-local `incidents/` or `analysis/` directories contain the live data.

Read all YAML incident files from `cfg.incidents_dir` (recursively find all `.yml` files). Then read the analysis prompt template from `cfg.templates_dir / "analysis-prompt.md"`.

Substitute the full YAML content of all incidents into the template where it says `[INCIDENTS ARE INSERTED HERE AS YAML]`.

Perform the analysis exactly as described in the prompt template. Your analysis should cover:
1. Pattern identification
2. Root cause analysis
3. Risk assessment
4. Recommendations
5. Playbook updates
6. Trend analysis

If no incident files exist in `cfg.incidents_dir`, stop and say there is nothing to analyze.

After completing the analysis, save the full report as a markdown file at `cfg.analysis_dir / "YYYY-MM-DD-analysis.md"` using today's date. If that file already exists, append a sequence number (for example, `YYYY-MM-DD-analysis-2.md`). Create `cfg.analysis_dir` first if it does not exist.

Print a summary of the key findings after saving.
