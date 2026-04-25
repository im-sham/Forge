# Forge Contract Guide

**Status:** Active local guide  
**Suite contract:** `proofhouse-shared-contracts/v0.1`

Forge owns incident-memory truth and failure-pattern learning for Proofhouse.

## Canonical Ownership

Forge owns:

- incident records
- incident severity and failure classification
- recurring failure patterns
- playbook entries
- incident-memory feedback to other capabilities

Forge does not own:

- Workflow Context canonical workflow truth
- Readiness scoring truth
- Governance rights, redaction, use approval, export, or manifest truth
- Operational Learning asset derivation, promotion state, or training/eval bundle contents

## Shared Refs This Repo Should Consume

Forge incidents may point to:

- `WorkflowRef`
- `SubjectRef`
- `AssessmentRef`
- `PolicyDecisionRef`
- `AssetRef`
- `DerivationRef`
- `TransformRef`
- `UseApprovalRef`

Pointers should be summaries or IDs only. Do not copy raw source material, customer data, regulated personal data, rights records, approval records, export manifests, or training/eval source material into Forge.

## Shared Refs This Repo Should Emit

### `IncidentRef`

The current YAML schema is minimal and tag-based. V0.1 `IncidentRef` is implemented as a compatibility projection over existing incidents before changing the underlying storage format.

Current projection:

- `incident_id`
- `failure_type`
- `severity`
- `capability_area`
- `lifecycle_stage`
- `issue_class`
- `workflow_ref`
- `assessment_ref`
- `policy_decision_ref`
- `asset_ref`
- `derivation_ref`
- `transform_ref`
- `use_approval_ref`
- `playbook_entry`

Current implementation:

- `forge_cli/models.py` builds `IncidentRef` and the V0.1 shared envelope from existing incident fields.
- `forge ref <incident-id>` prints the projection as JSON for CLI consumers.
- `forge_incident_ref` exposes the same projection to MCP clients.
- Existing YAML incident files are not rewritten and do not gain new required fields.
- Forge local data does not currently carry tenant or environment metadata, so the projection emits `organization_id: "unscoped"` and `environment_id: "default"` until structured metadata exists.

## Current Implementation Seams

- `forge_cli/models.py` defines the current incident dataclass and field order.
- `forge_cli/mcp_server.py` exposes incident logging and query tools.
- `templates/analysis-prompt.md` shapes failure-pattern analysis.
- `integrations/codex/SKILL.md` defines Codex logging guidance.

## V0.1 Implementation Rule

Keep `failure_type` as the mechanism-level classification. Add Operational Learning axes as separate fields or compatibility projections rather than overloading `tags`.

## Pointer Tags Until Structured Fields Exist

Use tags like:

- `workflow-context`
- `readiness`
- `governance`
- `operational-learning`
- `redaction`
- `use-approval`
- `export-control`
- `derivation-quality`

Tags are a bridge, not the final contract.
