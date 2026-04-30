# Claims Rate Source Ambiguity

## Pattern

A claims review incident involves a high-dollar or exception claim where packet,
line, or review summaries exist, but the contract/rate source pointer is
missing, ambiguous, stale, unlicensed, or not tied to a reviewed method before
internal eval, downstream handoff, audit export, or savings recognition.

## Detection

- Incident has `workflow_archetype: claims_hybrid_high_dollar_review`.
- Incident has `issue_class: rate_source_ambiguity`, `contract_rate_mismatch`,
  `allowed_amount_conflict`, or `missing_claim_evidence`.
- `observed_state` names the affected evidence class, but source detail remains
  a summary or digest.
- `WorkflowRef` / `WorkflowEvidenceSnapshot` exists, while the rate-source
  evidence summary, method, source version, or licensed-access posture is
  missing or unreviewed.
- Governance `PolicyDecisionRef` or `UseApprovalRef` is incomplete, denied, or
  review-required for the attempted use.

## Prevention

- Require Workflow Context to emit reviewed evidence summaries and digests for
  claim packet, claim line, and contract/rate source classes before proof check.
- Require Readiness to interpret rate-source traceability as a suitability
  blocker or trust gap, not as an approval.
- Require Governance to keep internal eval, export, downstream action, and
  savings-recognition paths fail-closed until the proper reviews and approvals
  exist.
- Keep Forge records to incident axes, summaries, and refs. Do not copy raw claim
  facts, protected data, rate extracts, payment details, source documents, or
  canonical decision state.

## Response Protocol

1. Record structured axes: `capability_area`, `lifecycle_stage`, `issue_class`,
   `workflow_archetype`, `subject_type`, and `blocked_use_class`.
2. Attach pointer-style refs only: `WorkflowRef`, `WorkflowEvidenceSnapshot` or
   `EvidenceRef`, `AssessmentRef`, `PolicyDecisionRef`, `UseApprovalRef`, and
   any relevant `AssetRef`, `DerivationRef`, or `TransformRef`.
3. Route workflow/source evidence gaps to Workflow Context.
4. Route suitability and trust-gap interpretation to Readiness.
5. Route approvals, redaction, use, export, action, and audit readback to
   Governance.
6. Keep recurrence, pattern memory, and playbook updates in Forge.

## Boundary

Forge records that the claims failure happened and how it recurs. Forge does not
own workflow truth, source connector truth, Readiness scoring truth, Governance
approval truth, redaction state, export/action approval, audit readback, asset
generation, training approval, policy-learning approval, production automation,
or source writeback.
