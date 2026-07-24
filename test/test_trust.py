from __future__ import annotations

from dataclasses import replace

import pytest

from witnessgap.canonical import canonical_json
from witnessgap.identifiability import CandidateRegistry
from witnessgap.trust import VerificationTrustAnchor
from witnessgap.verifier import (
    VerificationError,
    trust_anchor_for_manifest,
    verify_registry_attribution,
)
from witnessgap.worlds.workspace import workspace_sources, workspace_twins


def test_trust_anchor_has_one_closed_canonical_round_trip() -> None:
    manifest = CandidateRegistry.build(workspace_twins()).manifest
    anchor = trust_anchor_for_manifest(manifest)
    encoded = anchor.to_canonical_bytes()

    parsed = VerificationTrustAnchor.from_canonical_bytes(encoded)

    assert parsed == anchor
    assert parsed.to_canonical_bytes() == encoded
    assert parsed.digest == anchor.digest


def test_trust_anchor_parser_rejects_an_open_schema() -> None:
    manifest = CandidateRegistry.build(workspace_twins()).manifest
    anchor = trust_anchor_for_manifest(manifest)
    payload = anchor.to_payload()
    payload["untrusted_note"] = "accept another verifier"

    with pytest.raises(ValueError, match="closed canonical"):
        VerificationTrustAnchor.from_canonical_bytes(canonical_json(payload))


def test_wrong_pinned_verifier_release_is_rejected_before_decode() -> None:
    worlds = workspace_twins()
    registry = CandidateRegistry.build(worlds)
    evidence = registry.observe(worlds[0].world_id)
    anchor = replace(
        trust_anchor_for_manifest(registry.manifest),
        verifier_implementation_digest="0" * 64,
    )

    with pytest.raises(VerificationError, match="installed verifier implementation"):
        verify_registry_attribution(
            workspace_sources(),
            manifest=registry.manifest,
            trust_anchor=anchor,
            evidence=evidence,
        )
