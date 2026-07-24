"""External trust-anchor records for attribution verification."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import cast

from witnessgap.canonical import JsonValue, canonical_digest, canonical_json

_TRUST_ANCHOR_FORMAT = "witnessgap.verification-trust-anchor.v1"
_SHA256_HEX_LENGTH = 64


@dataclass(frozen=True, slots=True)
class VerificationTrustAnchor:
    """Digests that a verifier operator must pin independently of a claim."""

    registry_digest: str
    adapter_implementation_digest: str
    verifier_implementation_digest: str

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        for field, value in (
            ("registry_digest", self.registry_digest),
            ("adapter_implementation_digest", self.adapter_implementation_digest),
            ("verifier_implementation_digest", self.verifier_implementation_digest),
        ):
            if not _is_sha256(value):
                raise ValueError(f"{field} must be a lowercase SHA-256 digest")

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "adapter_implementation_digest": self.adapter_implementation_digest,
            "format": _TRUST_ANCHOR_FORMAT,
            "registry_digest": self.registry_digest,
            "verifier_implementation_digest": self.verifier_implementation_digest,
        }

    def to_canonical_bytes(self) -> bytes:
        return canonical_json(self.to_payload())

    @classmethod
    def from_canonical_bytes(cls, payload: bytes) -> VerificationTrustAnchor:
        if type(payload) is not bytes:
            raise TypeError("trust anchor payload must be exact bytes")
        try:
            raw: object = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("trust anchor is not valid UTF-8 JSON") from error
        if (
            type(raw) is not dict
            or canonical_json(cast(JsonValue, raw)) != payload
            or set(raw)
            != {
                "adapter_implementation_digest",
                "format",
                "registry_digest",
                "verifier_implementation_digest",
            }
        ):
            raise ValueError("trust anchor is not one closed canonical JSON object")
        if raw["format"] != _TRUST_ANCHOR_FORMAT:
            raise ValueError("trust anchor format is unsupported")
        fields = (
            raw["registry_digest"],
            raw["adapter_implementation_digest"],
            raw["verifier_implementation_digest"],
        )
        if any(type(value) is not str for value in fields):
            raise ValueError("trust anchor digest fields must be strings")
        anchor = cls(
            registry_digest=cast(str, fields[0]),
            adapter_implementation_digest=cast(str, fields[1]),
            verifier_implementation_digest=cast(str, fields[2]),
        )
        if anchor.to_canonical_bytes() != payload:
            raise ValueError("trust anchor failed canonical round-trip")
        return anchor

    @property
    def digest(self) -> str:
        return canonical_digest(_TRUST_ANCHOR_FORMAT, self.to_payload())


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == _SHA256_HEX_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )
