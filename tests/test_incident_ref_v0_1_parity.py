from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from forge_cli.incident_ref_v0_1 import (
    CanonicalIncidentIdentity,
    CanonicalWorkflowIdentity,
    ImmutableStatePin,
    build_strict_incident_ref_v0_1,
)
from forge_cli.models import Incident
from tests.contracts.incident_ref_v0_1_binding import IncidentRefEnvelope

ROOT = Path(__file__).resolve().parents[1]
BUNDLE_PATH = ROOT / "tests/contracts/incident_ref_v0_1_contract.json"
BINDING_PATH = ROOT / "tests/contracts/incident_ref_v0_1_binding.py"
VENDOR_SCRIPT = ROOT / "scripts/vendor_incident_ref_contract.py"
CONTRACT_COMMIT = "79caef37cd62b290e7643c6dd2599a2217f74e48"
CONTRACT_TREE = "945446de73b2460b553cb9607f327ea1d4768a86"
CONTRACT_BASE = "eacf66786685bec2762585238db9af5cd56449e4"
SCHEMA_SHA256 = "a05484880cb08236c33200d3ff0a5984f240db795ad01f077aa14588667d026a"
CORPUS_INDEX_SHA256 = "9753aaee774f6bd69fd594bb1ba9307374128f5c06a2c19a0625fa06103aff7d"
ARTIFACT_DIGESTS_SHA256 = "519ceb37fd1244e0ac1c73eecc8ad9c3ce717e18ec1fff1a46cd0ccafef57638"
BINDING_SHA256 = "d5f87f94240d59ffeecccd2c8348e83d8807ab8ecc96c3c08955237418aad9f3"
PROVENANCE_SHA256 = "ae36a2617d35761a2cba61b1a6bae6887d0700a39f546d321a2306f78245b7cc"


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _bundle() -> dict[str, object]:
    return json.loads(BUNDLE_PATH.read_text(encoding="utf-8"))


def test_vendored_protected_main_pins_and_bytes_are_exact() -> None:
    bundle = _bundle()
    assert bundle["contracts_commit"] == CONTRACT_COMMIT
    assert bundle["contracts_base"] == CONTRACT_BASE
    assert bundle["contracts_tree"] == CONTRACT_TREE
    assert _sha256_text(str(bundle["schema"])) == SCHEMA_SHA256
    assert _sha256_text(str(bundle["corpus_index"])) == CORPUS_INDEX_SHA256
    assert _sha256_text(str(bundle["artifact_digests"])) == ARTIFACT_DIGESTS_SHA256
    assert _sha256_text(str(bundle["provenance"])) == PROVENANCE_SHA256

    digests = json.loads(str(bundle["artifact_digests"]))["artifacts"]
    assert hashlib.sha256(BINDING_PATH.read_bytes()).hexdigest() == BINDING_SHA256
    assert BINDING_SHA256 == digests["bindings/python/incident_ref.py"]
    corpus_files = bundle["corpus_files"]
    assert isinstance(corpus_files, dict)
    for filename, content in corpus_files.items():
        path = f"contracts/incident-ref/v0.1/fixtures/corpus/{filename}"
        assert _sha256_text(str(content)) == digests[path]


def test_exact_88_case_protected_main_corpus_matches_semantic_validator() -> None:
    bundle = _bundle()
    index = json.loads(str(bundle["corpus_index"]))
    corpus_files = bundle["corpus_files"]
    assert isinstance(corpus_files, dict)
    assert len(index["cases"]) == 88
    assert len(corpus_files) == 88

    outcomes: list[bool] = []
    for case in index["cases"]:
        try:
            IncidentRefEnvelope.model_validate_json(corpus_files[case["file"]])
        except ValidationError:
            actual_valid = False
        else:
            actual_valid = True
        assert actual_valid is case["expected_valid"], case["name"]
        outcomes.append(actual_valid)

    assert outcomes.count(True) == 20
    assert outcomes.count(False) == 68


def test_portable_binding_rejects_malformed_issued_at_without_optional_helper() -> None:
    bundle = _bundle()
    corpus_files = bundle["corpus_files"]
    assert isinstance(corpus_files, dict)

    with pytest.raises(ValidationError):
        IncidentRefEnvelope.model_validate_json(
            corpus_files["invalid-malformed-issued-at.json"]
        )


def test_strict_forge_emitter_lowercase_t_z_is_accepted_by_contract_binding() -> None:
    incident = Incident.from_dict(
        {
            "id": "inc_synthetic_001",
            "timestamp": "2026-07-23t11:30:00z",
            "reported_by": "internal-test",
            "project": "internal-test",
            "agent": "internal-test",
            "platform": "internal-test",
            "severity": "functional",
            "failure_type": "integration_failure",
            "expected_behavior": "Synthetic summary-only text.",
            "actual_behavior": "Synthetic summary-only text.",
            "context": "Synthetic summary-only text.",
            "root_cause": "Synthetic summary-only text.",
            "immediate_fix": "Synthetic summary-only text.",
            "systemic_takeaway": "Synthetic summary-only text.",
        }
    )
    envelope = build_strict_incident_ref_v0_1(
        incident,
        organization_id="proofhouse_internal",
        environment_id="internal_staging",
        issued_at="2026-07-23t12:00:00z",
        incident_identity=CanonicalIncidentIdentity(
            incident_id=incident.id,
            snapshot=ImmutableStatePin("incident-snapshot-001", "state:incident:1"),
            version=ImmutableStatePin("1", "state:incident:1"),
        ),
        workflow_identity=CanonicalWorkflowIdentity(
            workflow_id="wf_synthetic_001",
            snapshot=ImmutableStatePin("workflow-snapshot-001", "state:workflow:1"),
            version=ImmutableStatePin("1", "state:workflow:1"),
        ),
    )

    parsed = IncidentRefEnvelope.model_validate(envelope)
    assert parsed.ref.incident_id == incident.id
    assert parsed.ref.workflow_ref.workflow_id == "wf_synthetic_001"
    assert parsed.issued_at == "2026-07-23t12:00:00z"
    assert parsed.ref.created_at == "2026-07-23t11:30:00z"


def test_vendor_script_is_pinned_for_reproducible_refresh() -> None:
    source = VENDOR_SCRIPT.read_text(encoding="utf-8")
    assert CONTRACT_COMMIT in source
    assert CONTRACT_TREE in source
    assert SCHEMA_SHA256 in source
    assert CORPUS_INDEX_SHA256 in source
    assert ARTIFACT_DIGESTS_SHA256 in source
    assert BINDING_SHA256 in source
    assert PROVENANCE_SHA256 in source
