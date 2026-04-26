# Document Review Redaction Miss

## Pattern

A document-operations incident involves a candidate eval, training, policy-learning, or export handoff where redaction review is missing, stale, ambiguous, or not linked through a dereferenceable `TransformRef` / `UseApprovalRef`.

## Detection

- Incident has `workflow_archetype: document_operations`.
- Incident has `issue_class: redaction_miss`.
- `blocked_use_class` is `internal_eval`, `internal_training`, `policy_learning`, or `external_export`.
- The incident has `WorkflowRef` and `WorkflowEvidenceSnapshot` pointers, but the redaction `TransformRef` or Governance `UseApprovalRef` pointer is missing, stale, or non-dereferenceable.

## Prevention

- Require pointer validation before any Operational Learning handoff.
- Fail closed when redaction review, rights, provenance, asset, derivation, or transform refs are absent.
- Keep source documents and source asset payloads out of Forge. Store incident classification, summaries, and refs only.
- Route redaction and approval remediation to Governance and Operational Learning; Forge owns the incident memory and recurrence pattern.

## Response Protocol

1. Record the incident with structured axes: `capability_area`, `lifecycle_stage`, `issue_class`, `workflow_archetype`, `subject_type`, and `blocked_use_class`.
2. Attach pointer-style refs only: `WorkflowRef`, `WorkflowEvidenceSnapshot` or `EvidenceRef`, `AssessmentRef`, `PolicyDecisionRef`, `UseApprovalRef`, and any relevant `AssetRef`, `DerivationRef`, or `TransformRef`.
3. Confirm the attempted use class is blocked until the owning Governance and Operational Learning systems provide valid refs.
4. Add the pattern to analysis if recurrence appears across workflows, agents, or document families.

## Boundary

Forge records that the redaction miss happened and how it recurred. Forge does not own workflow truth, readiness score truth, rights approvals, redaction state, export manifests, source documents, or Operational Learning asset payloads.
