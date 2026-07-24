"""Content-addressed source bundles for sealed benchmark completions."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from witnessgap.canonical import JsonValue, canonical_digest, tagged_digest
from witnessgap.model import ExecutionArtifact, ExecutionRunner, InterventionAtom, Outcome

_COMMITMENT_SALT_BYTES = 32
_MAX_SOURCE_BYTES = 1 << 20
_PACKAGE_ROOT = Path(__file__).resolve().parent


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
        self.validate()

    def validate(self) -> None:
        """Recheck an opening after crossing an untrusted runtime boundary."""

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

        self.validate()
        return tagged_digest("witnessgap.source-snapshot.v1", self.source_bytes)

    @property
    def completion_commitment(self) -> str:
        """Salted commitment to the exact decoder input."""

        self.validate()
        return tagged_digest(
            "witnessgap.world-completion.v2",
            self.commitment_salt + self.source_bytes,
        )


class DecodedWorld(Protocol):
    """Trusted runtime reconstructed from one sealed source opening."""

    @property
    def world_id(self) -> str: ...

    @property
    def task_schema_id(self) -> str: ...

    @property
    def task_id(self) -> str: ...

    @property
    def source_format_id(self) -> str: ...

    @property
    def adapter_id(self) -> str: ...

    @property
    def adapter_implementation_digest(self) -> str: ...

    @property
    def atoms(self) -> tuple[InterventionAtom, ...]: ...

    @property
    def probe_names(self) -> tuple[str, ...]: ...

    @property
    def declared_state_channels(self) -> tuple[str, ...]: ...

    @property
    def completion_commitment(self) -> str: ...

    @property
    def source_snapshot_digest(self) -> str: ...

    @property
    def intervention_contract_digest(self) -> str: ...

    @property
    def probe_contract_digest(self) -> str: ...

    @property
    def runner_contract_digest(self) -> str: ...

    @property
    def artifact_validator_contract_digest(self) -> str: ...

    @property
    def success_oracle_contract_digest(self) -> str: ...

    @property
    def state_access_contract_digest(self) -> str: ...

    def probe(self, name: str) -> bytes: ...

    def fresh_runner(self) -> ExecutionRunner: ...

    def validate_artifact(self, artifact: ExecutionArtifact) -> Outcome: ...


class WorldSourceAdapter(Protocol):
    """Trusted decoder selected by the verifier, never supplied by a claim."""

    @property
    def adapter_id(self) -> str: ...

    @property
    def source_format_id(self) -> str: ...

    @property
    def implementation_digest(self) -> str: ...

    def decode(self, source: SealedWorldSource) -> DecodedWorld: ...


def package_implementation_digest(
    domain: str,
    relative_paths: tuple[str, ...],
) -> str:
    """Digest exact installed source files that implement one trusted adapter."""

    if not relative_paths or tuple(sorted(set(relative_paths))) != relative_paths:
        raise ValueError("implementation paths must be non-empty, unique, and sorted")
    entries: list[JsonValue] = []
    for relative_path in relative_paths:
        path = Path(relative_path)
        if path.is_absolute() or ".." in path.parts or path.as_posix() != relative_path:
            raise ValueError(f"invalid package implementation path: {relative_path!r}")
        resolved = (_PACKAGE_ROOT / path).resolve()
        if not resolved.is_relative_to(_PACKAGE_ROOT) or not resolved.is_file():
            raise ValueError(f"package implementation file does not exist: {relative_path!r}")
        entries.append(
            {
                "content_digest": tagged_digest(
                    "witnessgap.implementation-file.v1",
                    resolved.read_bytes(),
                ),
                "path": relative_path,
            }
        )
    payload: dict[str, JsonValue] = {
        "files": tuple(entries),
        "format": "witnessgap.implementation-bundle.v1",
    }
    return canonical_digest(domain, payload)
