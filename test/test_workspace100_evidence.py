from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest

from witnessgap.canonical import JsonValue, canonical_json
from witnessgap.identifiability import (
    CandidateRegistry,
    UnknownReason,
    VerdictKind,
)
from witnessgap.workspace100.evidence import (
    PARTICIPANT_CLAIM_FORMAT,
    PUBLIC_EVIDENCE_FORMAT,
    ParticipantClaim,
    PublicEvidenceEnvelope,
)
from witnessgap.worlds.workspace import workspace_twins


def _full_evidence_envelope() -> PublicEvidenceEnvelope:
    worlds = workspace_twins()
    registry = CandidateRegistry.build(worlds)
    evidence = registry.observe(
        worlds[0].world_id,
        probes=("draft_store_epoch",),
        interventions=(("refresh_draft_store",),),
    )
    return PublicEvidenceEnvelope(evidence)


def test_public_envelope_round_trips_without_routing_or_truth_identifiers() -> None:
    envelope = _full_evidence_envelope()
    encoded = envelope.to_canonical_bytes()
    payload = envelope.to_payload()

    parsed = PublicEvidenceEnvelope.from_canonical_bytes(encoded)

    assert parsed == envelope
    assert parsed.evidence_digest == envelope.evidence.digest
    assert parsed.to_canonical_bytes() == encoded
    assert payload["format"] == PUBLIC_EVIDENCE_FORMAT
    for forbidden in (
        "case_id",
        "evidence_digest",
        "episode_id",
        "pair_id",
        "split",
        "target",
        "template_id",
        "view",
        "witness",
    ):
        assert forbidden not in payload
        assert f'"{forbidden}"'.encode() not in encoded


def test_public_envelope_rejects_open_noncanonical_and_forged_records() -> None:
    envelope = _full_evidence_envelope()
    payload = envelope.to_payload()
    payload["case_id"] = "forged_case"

    with pytest.raises(ValueError, match="unknown or missing"):
        PublicEvidenceEnvelope.from_canonical_bytes(canonical_json(payload))
    with pytest.raises(ValueError, match="canonical JSON"):
        PublicEvidenceEnvelope.from_canonical_bytes(envelope.to_canonical_bytes().rstrip(b"\n"))

    forged_hex = envelope.to_payload()
    forged_hex["public_trace_hex"] = "AA"
    with pytest.raises(ValueError, match="lowercase even-length hex"):
        PublicEvidenceEnvelope.from_canonical_bytes(canonical_json(forged_hex))


def test_public_envelope_rejects_duplicate_keys_and_size_overflow() -> None:
    envelope = _full_evidence_envelope()
    duplicate = envelope.to_canonical_bytes().replace(
        b'"format":',
        b'"format":"duplicate","format":',
        1,
    )

    with pytest.raises(ValueError, match="canonical JSON"):
        PublicEvidenceEnvelope.from_canonical_bytes(duplicate)
    with pytest.raises(ValueError, match="byte bounds"):
        PublicEvidenceEnvelope.from_canonical_bytes(b"x" * ((1 << 18) + 1))


@pytest.mark.parametrize(
    "claim",
    [
        ParticipantClaim(
            kind=VerdictKind.IDENTIFIED_SINGLETON,
            target_family=(("environment",),),
            minimal_witnesses=(("refresh_draft_store",),),
        ),
        ParticipantClaim(
            kind=VerdictKind.NOT_IDENTIFIABLE,
            unknown_reason=UnknownReason.AMBIGUOUS_WORLDS,
        ),
    ],
)
def test_participant_claim_closed_union_round_trips_without_any_binding_id(
    claim: ParticipantClaim,
) -> None:
    encoded = claim.to_canonical_bytes()

    parsed = ParticipantClaim.from_canonical_bytes(encoded)

    assert parsed == claim
    assert parsed.digest == claim.digest
    assert parsed.to_canonical_bytes() == encoded
    assert claim.to_payload()["format"] == PARTICIPANT_CLAIM_FORMAT
    for forbidden in (
        "case_id",
        "evidence_digest",
        "episode_id",
        "method_id",
        "pair_id",
        "view",
    ):
        assert forbidden.encode() not in encoded


def test_claim_schema_keeps_wrong_predictions_syntactically_expressible() -> None:
    wrong = ParticipantClaim(
        kind=VerdictKind.IDENTIFIED_SINGLETON,
        target_family=(("wrong_target",),),
        minimal_witnesses=(("wrong_intervention",),),
    )

    assert ParticipantClaim.from_canonical_bytes(wrong.to_canonical_bytes()) == wrong


def test_claim_schema_rejects_incoherent_unions_and_unsorted_witnesses() -> None:
    with pytest.raises(ValueError, match="cannot contain a target"):
        ParticipantClaim(
            kind=VerdictKind.NOT_IDENTIFIABLE,
            target_family=(("environment",),),
            unknown_reason=UnknownReason.AMBIGUOUS_WORLDS,
        )
    with pytest.raises(ValueError, match="unique and sorted"):
        ParticipantClaim(
            kind=VerdictKind.IDENTIFIED_SINGLETON,
            target_family=(("environment",),),
            minimal_witnesses=(("z_atom", "a_atom"),),
        )
    with pytest.raises(ValueError, match="outside the frozen protocol"):
        ParticipantClaim(
            kind=VerdictKind.IDENTIFIED_COMPOUND,
            target_family=(("environment",),),
            minimal_witnesses=(("refresh_draft_store",),),
        )


def test_claim_parser_rejects_ids_open_fields_and_noncanonical_values() -> None:
    claim = ParticipantClaim(
        kind=VerdictKind.NOT_IDENTIFIABLE,
        unknown_reason=UnknownReason.AMBIGUOUS_WORLDS,
    )
    open_payload = claim.to_payload()
    open_payload["evidence_digest"] = "0" * 64

    with pytest.raises(ValueError, match="unknown or missing"):
        ParticipantClaim.from_canonical_bytes(canonical_json(open_payload))
    with pytest.raises(ValueError, match="canonical JSON"):
        ParticipantClaim.from_canonical_bytes(claim.to_canonical_bytes().rstrip(b"\n"))
    with pytest.raises(TypeError, match="exact bytes"):
        ParticipantClaim.from_canonical_bytes(cast(bytes, bytearray(claim.to_canonical_bytes())))


def test_claim_revalidates_post_init_mutation() -> None:
    claim = ParticipantClaim(
        kind=VerdictKind.IDENTIFIED_SINGLETON,
        target_family=(("environment",),),
        minimal_witnesses=(("refresh_draft_store",),),
    )
    object.__setattr__(claim, "minimal_witnesses", (("z_atom", "a_atom"),))

    with pytest.raises(ValueError, match="unique and sorted"):
        claim.to_canonical_bytes()


def test_claim_parser_rejects_open_target_container_types() -> None:
    claim = ParticipantClaim(
        kind=VerdictKind.IDENTIFIED_SINGLETON,
        target_family=(("environment",),),
        minimal_witnesses=(("refresh_draft_store",),),
    )

    with pytest.raises(TypeError, match="exact VerdictKind"):
        replace(claim, kind=cast(VerdictKind, "identified_singleton"))


def test_public_envelope_payload_remains_canonical_json_data() -> None:
    payload: JsonValue = _full_evidence_envelope().to_payload()

    assert canonical_json(payload).endswith(b"\n")
