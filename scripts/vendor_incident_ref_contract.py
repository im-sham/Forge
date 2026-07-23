#!/usr/bin/env python3
"""Vendor exact minimum IncidentRef V0.1 protected-main contract material."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "tests/contracts/incident_ref_v0_1_contract.json"
BINDING_OUTPUT = ROOT / "tests/contracts/incident_ref_v0_1_binding.py"
CONTRACT_COMMIT = "79caef37cd62b290e7643c6dd2599a2217f74e48"
CONTRACT_TREE = "945446de73b2460b553cb9607f327ea1d4768a86"
CONTRACT_BASE = "eacf66786685bec2762585238db9af5cd56449e4"
SCHEMA_SHA256 = "a05484880cb08236c33200d3ff0a5984f240db795ad01f077aa14588667d026a"
CORPUS_INDEX_SHA256 = "9753aaee774f6bd69fd594bb1ba9307374128f5c06a2c19a0625fa06103aff7d"
ARTIFACT_DIGESTS_SHA256 = "519ceb37fd1244e0ac1c73eecc8ad9c3ce717e18ec1fff1a46cd0ccafef57638"
BINDING_SHA256 = "d5f87f94240d59ffeecccd2c8348e83d8807ab8ecc96c3c08955237418aad9f3"
PROVENANCE_SHA256 = "ae36a2617d35761a2cba61b1a6bae6887d0700a39f546d321a2306f78245b7cc"
BASE = Path("contracts/incident-ref/v0.1")
SCHEMA = BASE / "schema.json"
CORPUS = BASE / "fixtures/corpus"
DIGESTS = BASE / "artifact-digests.json"
PROVENANCE = BASE / "provenance.json"
BINDING = Path("bindings/python/incident_ref.py")


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _require_digest(source: Path, relative: Path, expected: str) -> bytes:
    content = (source / relative).read_bytes()
    actual = _sha256(content)
    if actual != expected:
        raise ValueError(f"{relative} digest mismatch: {actual}")
    return content


def _git(source: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=source,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def build_bundle(source: Path) -> tuple[bytes, bytes]:
    head = _git(source, "rev-parse", "HEAD")
    if head != CONTRACT_COMMIT:
        raise ValueError(f"Contracts checkout must be {CONTRACT_COMMIT}, found {head}")
    tree = _git(source, "rev-parse", "HEAD^{tree}")
    if tree != CONTRACT_TREE:
        raise ValueError(f"Contracts tree must be {CONTRACT_TREE}, found {tree}")
    base = _git(source, "merge-base", "HEAD", CONTRACT_BASE)
    if base != CONTRACT_BASE:
        raise ValueError(f"Contracts base must be {CONTRACT_BASE}, found {base}")

    schema = _require_digest(source, SCHEMA, SCHEMA_SHA256)
    index = _require_digest(source, CORPUS / "index.json", CORPUS_INDEX_SHA256)
    digest_document = _require_digest(source, DIGESTS, ARTIFACT_DIGESTS_SHA256)
    provenance = _require_digest(source, PROVENANCE, PROVENANCE_SHA256)
    artifact_digests = json.loads(digest_document)["artifacts"]
    corpus_index = json.loads(index)
    files: dict[str, str] = {}
    for case in corpus_index["cases"]:
        relative = CORPUS / case["file"]
        content = (source / relative).read_bytes()
        expected = artifact_digests[relative.as_posix()]
        if _sha256(content) != expected:
            raise ValueError(f"{relative} does not match artifact-digests.json")
        files[case["file"]] = content.decode("utf-8")

    binding = _require_digest(source, BINDING, BINDING_SHA256)
    if _sha256(binding) != artifact_digests[BINDING.as_posix()]:
        raise ValueError("Python binding does not match artifact-digests.json")
    bundle = {
        "artifact_digests": digest_document.decode("utf-8"),
        "contracts_base": CONTRACT_BASE,
        "contracts_commit": CONTRACT_COMMIT,
        "contracts_tree": CONTRACT_TREE,
        "corpus_files": files,
        "corpus_index": index.decode("utf-8"),
        "schema": schema.decode("utf-8"),
        "provenance": provenance.decode("utf-8"),
    }
    serialized = (json.dumps(bundle, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return serialized, binding


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    bundle, binding = build_bundle(args.source.resolve())
    if args.check:
        stale = []
        if not OUTPUT.exists() or OUTPUT.read_bytes() != bundle:
            stale.append(str(OUTPUT.relative_to(ROOT)))
        if not BINDING_OUTPUT.exists() or BINDING_OUTPUT.read_bytes() != binding:
            stale.append(str(BINDING_OUTPUT.relative_to(ROOT)))
        if stale:
            raise SystemExit(f"stale IncidentRef contract material: {', '.join(stale)}")
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_bytes(bundle)
    BINDING_OUTPUT.write_bytes(binding)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
