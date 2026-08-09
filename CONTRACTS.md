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
- `ControlRef`
- `SubjectRef`
- `AssessmentRef`
- `PolicyDecisionRef`
- `UseApprovalRef`
- `AssetRef`
- `DerivationRef`
- `TransformRef`

Pointers should be summaries or IDs only. Do not copy raw source material, customer data, regulated personal data, rights records, approval records, export manifests, or training/eval source material into Forge.

Core incident free-text fields are also summary-only: `expected_behavior`, `actual_behavior`, `context`, `root_cause`, `immediate_fix`, and `systemic_takeaway` should contain short incident summaries, synthetic fixture descriptions, refs, IDs, digests, and remediation notes only. Forge rejects obvious raw/sensitive payload indicators in those fields, including payload-shaped JSON and labels such as `payload`, `raw_payload`, `source_payload`, `document_text`, `claim_text`, `payment_payload`, `phi`, `ssn`, `dob`, `member_id`, `patient_name`, `authorization`, `api_key`, `secret`, and credential or token variants. This is boundary hygiene, not DLP or PHI classification.

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

### Legacy noncanonical `IncidentRef` compatibility projection

The characterized 37-field projection remains available for one release over old and new YAML shapes. It is not canonical IncidentRef V0.1.

Legacy envelope field order:

1. `contract_version`
2. `contract_name`
3. `producer_capability`
4. `producer_system`
5. `canonical_owner`
6. `issued_at`
7. `cache_policy`
8. `ref`

Legacy `ref` field order:

1. `ref_id`
2. `ref_type`
3. `source_capability`
4. `organization_id`
5. `environment_id`
6. `external_uri`
7. `snapshot_id`
8. `version`
9. `created_at`
10. `summary`
11. `incident_id`
12. `failure_type`
13. `severity`
14. `project`
15. `agent`
16. `platform`
17. `capability_area`
18. `lifecycle_stage`
19. `issue_class`
20. `workflow_archetype`
21. `subject_type`
22. `blocked_use_class`
23. `observed_state`
24. `tags`
25. `related_incidents`
26. `playbook_entry`
27. `workflow_ref`
28. `evidence_ref`
29. `workflow_evidence_snapshot`
30. `control_refs`
31. `subject_ref`
32. `assessment_ref`
33. `policy_decision_ref`
34. `use_approval_ref`
35. `asset_ref`
36. `derivation_ref`
37. `transform_ref`

Characterized legacy behavior:

- `forge_cli/models.py` deterministically builds the legacy noncanonical envelope from one loaded incident; it performs no write or external lookup.
- Envelope constants are `contract_name: "IncidentRef"`, `producer_capability: "forge"`, `producer_system: "proofhouse-forge"`, `canonical_owner: "forge"`, and `cache_policy: "summary_snapshot"`.
- Forge local data has no structured tenant or environment metadata. Every projection therefore emits the compatibility sentinels `organization_id: "unscoped"` and `environment_id: "default"`; `project` is not treated as tenant scope.
- Legacy YAML may omit `platform`, tags, related incidents, playbook data, every structured axis, observed state, and every pointer. Missing scalar values remain empty strings; missing maps are `null`; missing lists are empty. Compatibility inference uses `"unknown"` for absent capability/lifecycle values and falls back to `failure_type` for `issue_class`.
- Structured axes override compatibility inference. Pointer mappings and summary-only observed state pass through the projection, while string refs are normalized to ref-only mappings. Core incident free text is not emitted.
- Pointer maps, observed-state maps, and core free-text fields reject obvious raw/sensitive payload markers before projection. This is boundary hygiene, not DLP, PHI classification, rights approval, or workflow-truth validation.
- `forge ref <incident-id>` and `forge_incident_ref` are legacy noncanonical surfaces that load through the same incident lookup and serialize byte-identical envelopes.
- Existing YAML is not rewritten and gains no required fields.

`tests/test_incident_ref_characterization.py` freezes the exact inventories, deprecated aliases, and these behaviors as executable drift evidence. Run it with:

```bash
PYTHONPATH=. python -m pytest tests/test_incident_ref_characterization.py -q
```

This compatibility surface does not satisfy or claim canonical IncidentRef V0.1 conformance.

### Strict canonical `IncidentRef` V0.1 producer

`forge_cli.incident_ref_v0_1.build_strict_incident_ref_v0_1` is the canonical producer API. `build_strict_incident_ref_v0_1_from_corpus` is the shared typed, read-only local interface used by `forge canonical-ref-v0-1` and `forge_canonical_incident_ref_v0_1`. Both local surfaces require an explicit corpus root, lookup, non-placeholder organization and environment scope, issue time, exact incident and workflow identities, and at least one immutable pin plus state identity for each identity. They do not consult config, environment corpus defaults, project names, tags, current time, or mutable state. `ImmutableStatePin.state_id` is Forge-owned producer evidence used only to reject snapshot/version pairs that do not co-reference the same immutable state; it is never emitted and does not require opaque pin strings to be equal.

Canonical output is closed and metadata-only. It derives incident identity, creation time, severity, and failure classification from the loaded Forge incident, constructs a bounded classification-only summary, and excludes all raw incident free text, project/agent/platform metadata, tags, diagnostics, authority, and broad linked refs. Missing optional pins are omitted rather than serialized as `null`.

Parity is pinned to accepted Contracts protected main `79caef37cd62b290e7643c6dd2599a2217f74e48` (tree `945446de73b2460b553cb9607f327ea1d4768a86`), schema SHA-256 `a05484880cb08236c33200d3ff0a5984f240db795ad01f077aa14588667d026a`, corpus-index SHA-256 `9753aaee774f6bd69fd594bb1ba9307374128f5c06a2c19a0625fa06103aff7d`, artifact-digests SHA-256 `519ceb37fd1244e0ac1c73eecc8ad9c3ce717e18ec1fff1a46cd0ccafef57638`, generated Python binding SHA-256 `d5f87f94240d59ffeecccd2c8348e83d8807ab8ecc96c3c08955237418aad9f3`, and provenance SHA-256 `ae36a2617d35761a2cba61b1a6bae6887d0700a39f546d321a2306f78245b7cc`. `scripts/vendor_incident_ref_contract.py` regenerates and verifies the exact minimum binding/corpus material from a clean detached checkout. `tests/test_incident_ref_v0_1_parity.py` proves all 88 positive and negative cases through the unmodified generated semantic validator.

The deterministic document-operations expected output at
`examples/document-operations/incident-ref-v0.1.expected.json` is copied
exactly from the accepted consumer fixture
`im-sham/opsorchestra@3e9804144270f17bbfdb62507fd16ad10b2533c2`,
`data/demo_sets/document_ops/regulated_document_review_workflow.json` blob
`5371742934f729686c532d1ff161a348acd6a2d0`. Focused tests invoke the Forge
CLI and MCP surfaces against the repo-owned sanitized source incident, assert
exact envelope parity, and assert that the corpus bytes do not change.

Contracts publication is complete. These producer interfaces authorize no runtime-data migration, deployment, production use, external use, customer data, rights/use decision, export, product gate, or work-package closure.

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
