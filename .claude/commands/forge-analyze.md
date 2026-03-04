---
description: Analyze forge incidents for patterns — no API key needed
---

Read all YAML incident files from the `incidents/` directory (recursively find all `.yml` files). Then read the analysis prompt template from `templates/analysis-prompt.md`.

Substitute the full YAML content of all incidents into the template where it says `[INCIDENTS ARE INSERTED HERE AS YAML]`.

Perform the analysis exactly as described in the prompt template. Your analysis should cover:
1. Pattern identification
2. Root cause analysis
3. Risk assessment
4. Recommendations
5. Playbook updates
6. Trend analysis

After completing the analysis, save the full report as a markdown file at `analysis/YYYY-MM-DD-analysis.md` (using today's date). If that file already exists, append a sequence number (e.g., `analysis/YYYY-MM-DD-analysis-2.md`).

Print a summary of the key findings after saving.
