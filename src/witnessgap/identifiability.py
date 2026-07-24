"""Compatibility-set reasoning for finite benchmark worlds."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from witnessgap.model import FiniteWorld, Outcome, TargetFamily, Witness
from witnessgap.oracle import RepairPanel, enumerate_repair_panel


class ProbeWorld(FiniteWorld, Protocol):
    """A finite world that exposes task-authored diagnostic probes."""

    @property
    def probe_names(self) -> tuple[str, ...]:
        """Complete names of probes that the benchmark may reveal."""

    def probe(self, name: str) -> bytes:
        """Return the canonical public observation for one probe."""


@dataclass(frozen=True, order=True, slots=True)
class ProbeObservation:
    name: str
    value: bytes


@dataclass(frozen=True, order=True, slots=True)
class InterventionObservation:
    """Public result of one bounded repair query."""

    interventions: Witness
    public_trace: bytes
    outcome: Outcome


@dataclass(frozen=True, slots=True)
class Evidence:
    """Evidence visible to an attribution method."""

    public_trace: bytes
    outcome: Outcome
    probes: tuple[ProbeObservation, ...] = ()
    intervention_observations: tuple[InterventionObservation, ...] = ()

    def __post_init__(self) -> None:
        probe_names = tuple(item.name for item in self.probes)
        if tuple(sorted(set(probe_names))) != probe_names:
            raise ValueError("probe observations must be unique and sorted by name")
        intervention_sets = tuple(item.interventions for item in self.intervention_observations)
        if any(not item or item != tuple(sorted(set(item))) for item in intervention_sets):
            raise ValueError("intervention queries must be non-empty sorted sets")
        if tuple(sorted(set(intervention_sets))) != intervention_sets:
            raise ValueError("intervention observations must be unique and sorted")


@dataclass(frozen=True, slots=True)
class WorldCandidate:
    """One sealed world completion and its exhaustive causal profile."""

    panel: RepairPanel
    baseline: Evidence
    probe_observations: tuple[ProbeObservation, ...]

    @property
    def world_id(self) -> str:
        return self.panel.world_id


class VerdictKind(StrEnum):
    IDENTIFIED_SINGLETON = "identified_singleton"
    IDENTIFIED_COMPOUND = "identified_compound"
    IDENTIFIED_EQUIVALENCE_CLASS = "identified_equivalence_class"
    NOT_IDENTIFIABLE = "not_identifiable"


class UnknownReason(StrEnum):
    AMBIGUOUS_WORLDS = "ambiguous_worlds"
    BUDGET_EXHAUSTED = "budget_exhausted"


@dataclass(frozen=True, slots=True)
class AmbiguityWitness:
    """Two compatible completions with incompatible causal profiles."""

    left_world_id: str
    left_target_family: TargetFamily
    right_world_id: str
    right_target_family: TargetFamily


@dataclass(frozen=True, slots=True)
class AttributionVerdict:
    kind: VerdictKind
    compatible_world_ids: tuple[str, ...]
    target_family: TargetFamily | None = None
    unknown_reason: UnknownReason | None = None
    ambiguity: AmbiguityWitness | None = None


class RegistryError(ValueError):
    """Raised when the finite candidate registry is malformed."""


class EvidenceMismatchError(LookupError):
    """Raised when no registered world can produce the supplied evidence."""


@dataclass(frozen=True, slots=True)
class CandidateRegistry:
    """A finite hypothesis family used to judge identifiability."""

    candidates: tuple[WorldCandidate, ...]

    @classmethod
    def build(cls, worlds: Iterable[ProbeWorld]) -> CandidateRegistry:
        candidates: list[WorldCandidate] = []
        for world in worlds:
            panel = enumerate_repair_panel(world)
            baseline_receipt = panel.receipt_for(())
            if tuple(sorted(set(world.probe_names))) != world.probe_names:
                raise RegistryError(f"{world.world_id}: probe names must be unique and sorted")
            probes = tuple(
                ProbeObservation(name=name, value=world.probe(name)) for name in world.probe_names
            )
            candidates.append(
                WorldCandidate(
                    panel=panel,
                    baseline=Evidence(
                        public_trace=baseline_receipt.result.public_trace,
                        outcome=baseline_receipt.result.outcome,
                    ),
                    probe_observations=probes,
                )
            )

        world_ids = tuple(candidate.world_id for candidate in candidates)
        if not candidates:
            raise RegistryError("candidate registry cannot be empty")
        if len(set(world_ids)) != len(world_ids):
            raise RegistryError("candidate world IDs must be unique")
        if world_ids != tuple(sorted(world_ids)):
            raise RegistryError("candidate worlds must be sorted by world ID")
        return cls(candidates=tuple(candidates))

    def observe(
        self,
        world_id: str,
        *,
        probes: Iterable[str] = (),
        interventions: Iterable[Witness] = (),
    ) -> Evidence:
        """Construct the evidence view for a sealed world and probe panel."""

        candidate = self._candidate(world_id)
        requested = tuple(probes)
        if tuple(sorted(set(requested))) != requested:
            raise ValueError("requested probes must be unique and sorted")
        available = {item.name: item.value for item in candidate.probe_observations}
        try:
            observations = tuple(
                ProbeObservation(name=name, value=available[name]) for name in requested
            )
        except KeyError as error:
            raise KeyError(f"{world_id}: unknown probe {error.args[0]!r}") from error

        requested_interventions = tuple(interventions)
        if any(not item or item != tuple(sorted(set(item))) for item in requested_interventions):
            raise ValueError("requested interventions must be non-empty sorted sets")
        if tuple(sorted(set(requested_interventions))) != requested_interventions:
            raise ValueError("requested interventions must be unique and sorted")
        try:
            intervention_observations = tuple(
                InterventionObservation(
                    interventions=item,
                    public_trace=candidate.panel.receipt_for(item).result.public_trace,
                    outcome=candidate.panel.receipt_for(item).result.outcome,
                )
                for item in requested_interventions
            )
        except KeyError as error:
            raise KeyError(f"{world_id}: unknown intervention subset {error.args[0]!r}") from error
        return Evidence(
            public_trace=candidate.baseline.public_trace,
            outcome=candidate.baseline.outcome,
            probes=observations,
            intervention_observations=intervention_observations,
        )

    def attribute(self, evidence: Evidence) -> AttributionVerdict:
        """Return the strongest causal verdict licensed by ``evidence``."""

        compatible = tuple(
            candidate for candidate in self.candidates if _is_compatible(candidate, evidence)
        )
        if not compatible:
            raise EvidenceMismatchError("no registered world completion matches the evidence")

        world_ids = tuple(candidate.world_id for candidate in compatible)
        profiles = {candidate.panel.target_family for candidate in compatible}
        if len(profiles) > 1:
            left = compatible[0]
            right = next(
                candidate
                for candidate in compatible[1:]
                if candidate.panel.target_family != left.panel.target_family
            )
            return AttributionVerdict(
                kind=VerdictKind.NOT_IDENTIFIABLE,
                compatible_world_ids=world_ids,
                unknown_reason=UnknownReason.AMBIGUOUS_WORLDS,
                ambiguity=AmbiguityWitness(
                    left_world_id=left.world_id,
                    left_target_family=left.panel.target_family,
                    right_world_id=right.world_id,
                    right_target_family=right.panel.target_family,
                ),
            )

        profile = profiles.pop()
        if not profile:
            return AttributionVerdict(
                kind=VerdictKind.NOT_IDENTIFIABLE,
                compatible_world_ids=world_ids,
                unknown_reason=UnknownReason.BUDGET_EXHAUSTED,
            )
        kind = (
            VerdictKind.IDENTIFIED_SINGLETON
            if len(profile) == 1 and len(profile[0]) == 1
            else VerdictKind.IDENTIFIED_COMPOUND
            if len(profile) == 1
            else VerdictKind.IDENTIFIED_EQUIVALENCE_CLASS
        )
        return AttributionVerdict(
            kind=kind,
            compatible_world_ids=world_ids,
            target_family=profile,
        )

    def _candidate(self, world_id: str) -> WorldCandidate:
        for candidate in self.candidates:
            if candidate.world_id == world_id:
                return candidate
        raise KeyError(world_id)


def _is_compatible(candidate: WorldCandidate, evidence: Evidence) -> bool:
    if candidate.baseline != Evidence(
        public_trace=evidence.public_trace,
        outcome=evidence.outcome,
    ):
        return False
    available = {item.name: item.value for item in candidate.probe_observations}
    if not all(available.get(item.name) == item.value for item in evidence.probes):
        return False
    for observation in evidence.intervention_observations:
        try:
            result = candidate.panel.receipt_for(observation.interventions).result
        except KeyError:
            return False
        if (result.public_trace, result.outcome) != (
            observation.public_trace,
            observation.outcome,
        ):
            return False
    return True
