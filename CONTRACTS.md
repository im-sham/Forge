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
- `EvidenceRef`
- `WorkflowEvidenceSnapshot`
- `SubjectRef`
- `AssessmentRef`
- `PolicyDecisionRef`
- `UseApprovalRef`
- `AssetRef`
- `DerivationRef`
- `TransformRef`

Pointers should be summaries or IDs only. Do not copy raw source material, customer data, regulated personal data, rights records, approval records, export manifests, or training/eval source material into Forge.

## Structured Incident Axes

Forge keeps `failure_type` as the mechanism-level classification and stores Proofhouse / document-operations learning as optional axes:

- `capability_area`
- `lifecycle_stage`
- `issue_class`
- `workflow_archetype`
- `subject_type`
- `blocked_use_class`
- `observed_state`

The first document-operations issue classes are:

- `redaction_miss`
- `rights_ambiguity`
- `promotion_failure`
- `export_control_failure`
- `transform_failure`
- `derivation_quality_failure`
- `evidence_gap`
- `escalation_miss`
- `reviewer_disagreement`

Claims-specific issue classes are:

- `phi_redaction_failure`
- `missing_claim_evidence`
- `rate_source_ambiguity`
- `contract_rate_mismatch`
- `allowed_amount_conflict`
- `approval_bypass`
- `downstream_export_mismatch`
- `savings_recognition_dispute`

Existing incident YAML can omit every structured axis and pointer field. New incidents should use these fields when the incident touches Proofhouse workflow evidence, Governance use control, or Operational Learning promotion/transform paths.

## Shared Refs This Repo Should Emit

### `IncidentRef`

The YAML schema preserves the original minimal incident fields and adds optional V0.1 structured axes / pointer refs for Proofhouse incidents. V0.1 `IncidentRef` remains a compatibility projection over both old and new YAML shapes.

Projection fields:

- `incident_id`
- `failure_type`
- `severity`
- `capability_area`
- `lifecycle_stage`
- `issue_class`
- `workflow_archetype`
- `subject_type`
- `blocked_use_class`
- `workflow_ref`
- `evidence_ref`
- `workflow_evidence_snapshot`
- `subject_ref`
- `assessment_ref`
- `policy_decision_ref`
- `use_approval_ref`
- `asset_ref`
- `derivation_ref`
- `transform_ref`
- `playbook_entry`

Current implementation:

- `forge_cli/models.py` builds `IncidentRef` and the V0.1 shared envelope from incident fields.
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

## Pointer Tags As Discovery Aids

Use tags like:

- `workflow-context`
- `readiness`
- `governance`
- `operational-learning`
- `redaction`
- `use-approval`
- `export-control`
- `derivation-quality`
- `claims`
- `rate-source-ambiguity`
- `contract-rate-mismatch`
- `approval-bypass`
- `savings-recognition-dispute`

Tags are secondary discovery aids, not the structured contract. The sanitized document-operations stub at `examples/document-operations/redaction-miss-incident.yml` shows the preferred structured pattern.
The sanitized claims stub at `examples/claims/rate-source-ambiguity-incident.yml` shows the same pointer/ref-summary posture for claims review failures. It must not store PHI, real claim data, source payloads, licensed rate extracts, payment payloads, source writeback state, or approval truth.
