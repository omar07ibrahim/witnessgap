"""Finite world and replay types used by the benchmark core."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SHA256_HEX_LENGTH = 64


def _require_identifier(value: str, *, field: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{field} must match {_IDENTIFIER.pattern!r}: {value!r}")


class Outcome(StrEnum):
    """Terminal result exposed by a benchmark world's success oracle."""

    FAILURE = "failure"
    SUCCESS = "success"


@dataclass(frozen=True, order=True, slots=True)
class InterventionAtom:
    """One task-owned repair operation.

    ``name`` identifies the concrete operation. ``target`` identifies the
    normalized causal site used when comparing witness families.
    """

    name: str
    target: str

    def __post_init__(self) -> None:
        _require_identifier(self.name, field="atom name")
        _require_identifier(self.target, field="atom target")


@dataclass(frozen=True, slots=True)
class ReplayResult:
    """Canonical public output and state provenance from one replay."""

    public_trace: bytes
    outcome: Outcome
    state_reads: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.public_trace, bytes):
            raise TypeError("public_trace must be bytes")
        if not isinstance(self.outcome, Outcome):
            raise TypeError("outcome must be an Outcome")
        if not isinstance(self.state_reads, tuple):
            raise TypeError("state_reads must be a tuple")
        for channel in self.state_reads:
            _require_identifier(channel, field="state channel")
        if tuple(sorted(set(self.state_reads))) != self.state_reads:
            raise ValueError("state_reads must be unique and sorted")


@dataclass(frozen=True, slots=True)
class StateRead:
    """One ordered, runner-recorded read from declared world state."""

    sequence: int
    channel: str
    value_digest: str

    def __post_init__(self) -> None:
        if self.sequence < 0:
            raise ValueError("state-read sequence cannot be negative")
        _require_identifier(self.channel, field="state channel")
        if len(self.value_digest) != _SHA256_HEX_LENGTH or any(
            character not in "0123456789abcdef" for character in self.value_digest
        ):
            raise ValueError("state-read value_digest must be lowercase SHA-256")


@dataclass(frozen=True, slots=True)
class ExecutionArtifact:
    """Raw runner output evaluated later by a separate success oracle."""

    source_snapshot_digest: str
    public_trace: bytes
    terminal_state: bytes
    state_read_log: tuple[StateRead, ...]
    intervention_log: tuple[str, ...]

    def __post_init__(self) -> None:
        if len(self.source_snapshot_digest) != _SHA256_HEX_LENGTH or any(
            character not in "0123456789abcdef" for character in self.source_snapshot_digest
        ):
            raise ValueError("source_snapshot_digest must be lowercase SHA-256")
        if not isinstance(self.public_trace, bytes) or not isinstance(self.terminal_state, bytes):
            raise TypeError("execution trace and terminal state must be bytes")
        sequences = tuple(read.sequence for read in self.state_read_log)
        if sequences != tuple(range(len(self.state_read_log))):
            raise ValueError("state-read sequence must be contiguous and start at zero")
        if self.intervention_log != tuple(sorted(set(self.intervention_log))):
            raise ValueError("intervention_log must be unique and sorted")


class ExecutionRunner(Protocol):
    """A fresh, single-snapshot runner used by the independent verifier."""

    def run(self, interventions: frozenset[str]) -> ExecutionArtifact:
        """Execute exactly one intervention subset."""


class FiniteWorld(Protocol):
    """A deterministic world with a finite intervention panel."""

    @property
    def world_id(self) -> str:
        """Stable identifier for the sealed world completion."""

    @property
    def atoms(self) -> tuple[InterventionAtom, ...]:
        """Complete intervention algebra for this world."""

    def replay(self, interventions: frozenset[str]) -> ReplayResult:
        """Replay from the canonical snapshot with the named atoms applied."""


Witness = tuple[str, ...]
TargetSet = tuple[str, ...]
TargetFamily = tuple[TargetSet, ...]


def normalize_witness(names: frozenset[str] | set[str] | tuple[str, ...]) -> Witness:
    """Return the canonical representation of an intervention set."""

    return tuple(sorted(names))
