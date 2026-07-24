"""Participant wire records for Workspace-100 evaluation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import cast

from witnessgap.canonical import JsonValue, canonical_digest, canonical_json
from witnessgap.identifiability import (
    Evidence,
    InterventionObservation,
    ProbeObservation,
    UnknownReason,
    VerdictKind,
)
from witnessgap.model import Outcome, TargetFamily, Witness
from witnessgap.workspace100.records import PROTOCOL_ID

PUBLIC_EVIDENCE_FORMAT = "witnessgap.workspace100-evidence-envelope.v1"
PARTICIPANT_CLAIM_FORMAT = "witnessgap.workspace100-claim.v1"

_MAX_EVIDENCE_BYTES = 1 << 18
_MAX_CLAIM_BYTES = 1 << 14
_MAX_WITNESS_ATOMS = 12
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{0,95}$")


@dataclass(frozen=True, slots=True)
class PublicEvidenceEnvelope:
    """The only request bytes delivered to a participant worker."""

    evidence: Evidence

    def __post_init__(self) -> None:
        if type(self.evidence) is not Evidence:
            raise TypeError("public envelope evidence must be an exact Evidence")
        self.evidence.validate()

    @property
    def evidence_digest(self) -> str:
        """Trusted-parent binding; deliberately absent from worker bytes."""

        return self.evidence.digest

    def to_payload(self) -> dict[str, JsonValue]:
        self.evidence.validate()
        return {
            "coverage_manifest_digest": self.evidence.coverage_manifest_digest,
            "format": PUBLIC_EVIDENCE_FORMAT,
            "intervention_observations": tuple(
                {
                    "interventions": observation.interventions,
                    "outcome": observation.outcome.value,
                    "public_trace_hex": observation.public_trace.hex(),
                }
                for observation in self.evidence.intervention_observations
            ),
            "outcome": self.evidence.outcome.value,
            "probes": tuple(
                {
                    "name": observation.name,
                    "value_hex": observation.value.hex(),
                }
                for observation in self.evidence.probes
            ),
            "protocol_id": PROTOCOL_ID,
            "public_trace_hex": self.evidence.public_trace.hex(),
            "registry_digest": self.evidence.registry_digest,
        }

    def to_canonical_bytes(self) -> bytes:
        payload = canonical_json(self.to_payload())
        if len(payload) > _MAX_EVIDENCE_BYTES:
            raise ValueError(f"public evidence exceeds the {_MAX_EVIDENCE_BYTES}-byte limit")
        return payload

    @classmethod
    def from_canonical_bytes(cls, payload: bytes) -> PublicEvidenceEnvelope:
        raw = _canonical_object(
            payload,
            label="public evidence",
            maximum_bytes=_MAX_EVIDENCE_BYTES,
        )
        expected_fields = {
            "coverage_manifest_digest",
            "format",
            "intervention_observations",
            "outcome",
            "probes",
            "protocol_id",
            "public_trace_hex",
            "registry_digest",
        }
        if set(raw) != expected_fields:
            raise ValueError("public evidence contains unknown or missing fields")
        if raw["format"] != PUBLIC_EVIDENCE_FORMAT:
            raise ValueError("public evidence format is unsupported")
        if raw["protocol_id"] != PROTOCOL_ID:
            raise ValueError("public evidence protocol is unsupported")
        probes_raw = raw["probes"]
        if type(probes_raw) is not list:
            raise ValueError("public evidence probes must be a JSON array")
        probes: list[ProbeObservation] = []
        for item in probes_raw:
            if type(item) is not dict or set(item) != {"name", "value_hex"}:
                raise ValueError("public evidence probe contains unknown or missing fields")
            probe = cast(dict[str, object], item)
            probes.append(
                ProbeObservation(
                    name=_required_string(probe, "name"),
                    value=_required_hex_bytes(probe, "value_hex"),
                )
            )
        observations_raw = raw["intervention_observations"]
        if type(observations_raw) is not list:
            raise ValueError("public evidence intervention observations must be a JSON array")
        observations: list[InterventionObservation] = []
        for item in observations_raw:
            if type(item) is not dict or set(item) != {
                "interventions",
                "outcome",
                "public_trace_hex",
            }:
                raise ValueError("public evidence intervention contains unknown or missing fields")
            observation = cast(dict[str, object], item)
            observations.append(
                InterventionObservation(
                    interventions=_required_string_tuple(
                        observation,
                        "interventions",
                    ),
                    public_trace=_required_hex_bytes(
                        observation,
                        "public_trace_hex",
                    ),
                    outcome=_required_outcome(observation, "outcome"),
                )
            )
        envelope = cls(
            Evidence(
                registry_digest=_required_string(raw, "registry_digest"),
                coverage_manifest_digest=_required_string(
                    raw,
                    "coverage_manifest_digest",
                ),
                public_trace=_required_hex_bytes(raw, "public_trace_hex"),
                outcome=_required_outcome(raw, "outcome"),
                probes=tuple(probes),
                intervention_observations=tuple(observations),
            )
        )
        if envelope.to_canonical_bytes() != payload:
            raise ValueError("public evidence failed canonical round-trip")
        return envelope


@dataclass(frozen=True, slots=True)
class ParticipantClaim:
    """One ID-free prediction returned by a participant worker."""

    kind: VerdictKind
    target_family: TargetFamily | None = None
    minimal_witnesses: tuple[Witness, ...] | None = None
    unknown_reason: UnknownReason | None = None

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if type(self.kind) is not VerdictKind:
            raise TypeError("participant claim kind must be an exact VerdictKind")
        if self.kind is VerdictKind.IDENTIFIED_SINGLETON:
            if self.unknown_reason is not None:
                raise ValueError("identified claim cannot contain an unknown reason")
            _validate_singleton_target(self.target_family)
            _validate_single_witness(self.minimal_witnesses)
            return
        if self.kind is VerdictKind.NOT_IDENTIFIABLE:
            if type(self.unknown_reason) is not UnknownReason:
                raise TypeError("not-identifiable claim requires an exact UnknownReason")
            if self.target_family is not None or self.minimal_witnesses is not None:
                raise ValueError("not-identifiable claim cannot contain a target or witness")
            return
        raise ValueError("Workspace-100 claim kind is outside the frozen protocol")

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        if self.kind is VerdictKind.IDENTIFIED_SINGLETON:
            return {
                "format": PARTICIPANT_CLAIM_FORMAT,
                "kind": self.kind.value,
                "minimal_witnesses": self.minimal_witnesses,
                "protocol_id": PROTOCOL_ID,
                "target_family": self.target_family,
            }
        return {
            "format": PARTICIPANT_CLAIM_FORMAT,
            "kind": self.kind.value,
            "protocol_id": PROTOCOL_ID,
            "unknown_reason": cast(UnknownReason, self.unknown_reason).value,
        }

    def to_canonical_bytes(self) -> bytes:
        payload = canonical_json(self.to_payload())
        if len(payload) > _MAX_CLAIM_BYTES:
            raise ValueError(f"participant claim exceeds the {_MAX_CLAIM_BYTES}-byte limit")
        return payload

    @classmethod
    def from_canonical_bytes(cls, payload: bytes) -> ParticipantClaim:
        raw = _canonical_object(
            payload,
            label="participant claim",
            maximum_bytes=_MAX_CLAIM_BYTES,
        )
        if raw.get("format") != PARTICIPANT_CLAIM_FORMAT:
            raise ValueError("participant claim format is unsupported")
        if raw.get("protocol_id") != PROTOCOL_ID:
            raise ValueError("participant claim protocol is unsupported")
        try:
            kind = VerdictKind(_required_string(raw, "kind"))
        except ValueError as error:
            raise ValueError("participant claim kind is unsupported") from error
        if kind is VerdictKind.IDENTIFIED_SINGLETON:
            if set(raw) != {
                "format",
                "kind",
                "minimal_witnesses",
                "protocol_id",
                "target_family",
            }:
                raise ValueError("identified claim contains unknown or missing fields")
            claim = cls(
                kind=kind,
                target_family=_required_nested_strings(raw, "target_family"),
                minimal_witnesses=_required_nested_strings(
                    raw,
                    "minimal_witnesses",
                ),
            )
        elif kind is VerdictKind.NOT_IDENTIFIABLE:
            if set(raw) != {
                "format",
                "kind",
                "protocol_id",
                "unknown_reason",
            }:
                raise ValueError("not-identifiable claim contains unknown or missing fields")
            try:
                reason = UnknownReason(_required_string(raw, "unknown_reason"))
            except ValueError as error:
                raise ValueError("participant claim unknown reason is unsupported") from error
            claim = cls(kind=kind, unknown_reason=reason)
        else:
            raise ValueError("Workspace-100 claim kind is outside the frozen protocol")
        if claim.to_canonical_bytes() != payload:
            raise ValueError("participant claim failed canonical round-trip")
        return claim

    @property
    def digest(self) -> str:
        return canonical_digest(PARTICIPANT_CLAIM_FORMAT, self.to_payload())


def _validate_singleton_target(target_family: object) -> None:
    if (
        type(target_family) is not tuple
        or len(target_family) != 1
        or type(target_family[0]) is not tuple
        or len(target_family[0]) != 1
    ):
        raise ValueError("identified claim target_family must contain one singleton target")
    target = target_family[0][0]
    _require_identifier(target, field="claim target")


def _validate_single_witness(witnesses: object) -> None:
    if (
        type(witnesses) is not tuple
        or len(witnesses) != 1
        or type(witnesses[0]) is not tuple
        or not witnesses[0]
        or len(witnesses[0]) > _MAX_WITNESS_ATOMS
    ):
        raise ValueError("identified claim must contain one non-empty bounded witness")
    witness = witnesses[0]
    if tuple(sorted(set(witness))) != witness:
        raise ValueError("claim witness atoms must be unique and sorted")
    for atom in witness:
        _require_identifier(atom, field="claim witness atom")


def _canonical_object(
    payload: bytes,
    *,
    label: str,
    maximum_bytes: int,
) -> dict[str, object]:
    if type(payload) is not bytes:
        raise TypeError(f"{label} payload must be exact bytes")
    if not payload or len(payload) > maximum_bytes:
        raise ValueError(f"{label} payload exceeds its byte bounds")
    try:
        raw: object = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from error
    try:
        canonical = type(raw) is dict and canonical_json(cast(JsonValue, raw)) == payload
    except (TypeError, UnicodeEncodeError, RecursionError) as error:
        raise ValueError(f"{label} contains unsupported JSON values") from error
    if not canonical:
        raise ValueError(f"{label} is not one canonical JSON object")
    return cast(dict[str, object], raw)


def _required_string(raw: dict[str, object], field: str) -> str:
    value = raw.get(field)
    if type(value) is not str:
        raise ValueError(f"{field} must be a string")
    return value


def _required_string_tuple(raw: dict[str, object], field: str) -> tuple[str, ...]:
    value = raw.get(field)
    if type(value) is not list or any(type(item) is not str for item in value):
        raise ValueError(f"{field} must be an array of strings")
    return tuple(cast(list[str], value))


def _required_nested_strings(
    raw: dict[str, object],
    field: str,
) -> tuple[tuple[str, ...], ...]:
    value = raw.get(field)
    if type(value) is not list:
        raise ValueError(f"{field} must be an array of string arrays")
    result: list[tuple[str, ...]] = []
    for item in value:
        if type(item) is not list or any(type(entry) is not str for entry in item):
            raise ValueError(f"{field} must be an array of string arrays")
        result.append(tuple(cast(list[str], item)))
    return tuple(result)


def _required_hex_bytes(raw: dict[str, object], field: str) -> bytes:
    value = _required_string(raw, field)
    if (
        len(value) % 2
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} must be lowercase even-length hex")
    return bytes.fromhex(value)


def _required_outcome(raw: dict[str, object], field: str) -> Outcome:
    try:
        return Outcome(_required_string(raw, field))
    except ValueError as error:
        raise ValueError(f"{field} has an unsupported outcome") from error


def _require_identifier(value: object, *, field: str) -> None:
    if type(value) is not str or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{field} must be a normalized identifier")
