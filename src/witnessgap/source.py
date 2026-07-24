"""Content-addressed source bundles for sealed benchmark completions."""

from __future__ import annotations

from dataclasses import dataclass

from witnessgap.canonical import tagged_digest

_COMMITMENT_SALT_BYTES = 32
_MAX_SOURCE_BYTES = 1 << 20


@dataclass(frozen=True, slots=True)
class SealedWorldSource:
    """Immutable bytes used to reconstruct one hidden world completion.

    The salt prevents a small authored completion family from being recovered
    by hashing every plausible source record. It is part of the verifier input,
    not secret key material.
    """

    source_bytes: bytes
    commitment_salt: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.source_bytes, bytes):
            raise TypeError("source_bytes must be bytes")
        if not self.source_bytes:
            raise ValueError("source_bytes cannot be empty")
        if len(self.source_bytes) > _MAX_SOURCE_BYTES:
            raise ValueError(f"source_bytes cannot exceed {_MAX_SOURCE_BYTES} bytes")
        if not isinstance(self.commitment_salt, bytes):
            raise TypeError("commitment_salt must be bytes")
        if len(self.commitment_salt) != _COMMITMENT_SALT_BYTES:
            raise ValueError(f"commitment_salt must contain {_COMMITMENT_SALT_BYTES} bytes")

    @property
    def snapshot_digest(self) -> str:
        """Digest of the exact decoder input, excluding the privacy salt."""

        return tagged_digest("witnessgap.source-snapshot.v1", self.source_bytes)

    @property
    def completion_commitment(self) -> str:
        """Salted commitment to the exact decoder input."""

        return tagged_digest(
            "witnessgap.world-completion.v2",
            self.commitment_salt + self.source_bytes,
        )
