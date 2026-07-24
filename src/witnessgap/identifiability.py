"""Compatibility-set reasoning for finite benchmark worlds."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from witnessgap.canonical import JsonValue, canonical_digest
from witnessgap.model import FiniteWorld, InterventionAtom, Outcome, TargetFamily, Witness
from witnessgap.oracle import RepairPanel, enumerate_repair_panel

_REGISTRY_FORMAT = "witnessgap.registry.v1"
_SHA256_HEX_LENGTH = 64


class ProbeWorld(FiniteWorld, Protocol):
    """A finite world that exposes task-authored diagnostic probes."""

    @property
    def task_schema_id(self) -> str:
        """Shared schema identity for the complete candidate family."""

    @property
    def task_id(self) -> str:
        """Shared public task identity for the complete candidate family."""

    @property
    def declared_state_channels(self) -> tuple[str, ...]:
        """Public state-channel coverage declaration."""

    @property
    def completion_commitment(self) -> str:
        """Commitment to the sealed completion source."""

    @property
    def intervention_contract_digest(self) -> str:
        """Commitment to the shared intervention semantics."""

    @property
    def probe_contract_digest(self) -> str:
        """Commitment to the shared probe semantics."""

    @property
    def runner_contract_digest(self) -> str:
        """Commitment to deterministic execution semantics."""

    @property
    def success_oracle_contract_digest(self) -> str:
        """Commitment to terminal success semantics."""

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

    registry_digest: str
    coverage_manifest_digest: str
    public_trace: bytes
    outcome: Outcome
    probes: tuple[ProbeObservation, ...] = ()
    intervention_observations: tuple[InterventionObservation, ...] = ()

    def __post_init__(self) -> None:
        if not _is_sha256(self.registry_digest):
            raise ValueError("registry_digest must be a lowercase SHA-256 digest")
        if not _is_sha256(self.coverage_manifest_digest):
            raise ValueError("coverage_manifest_digest must be a lowercase SHA-256 digest")
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
    completion_commitment: str
    baseline: Evidence
    probe_observations: tuple[ProbeObservation, ...]

    @property
    def world_id(self) -> str:
        return self.panel.world_id


class VerdictKind(StrEnum):
    IDENTIFIED_SINGLETON = "identified_singleton"
    IDENTIFIED_COMPOUND = "identified_compound"
    ALTERNATIVE_MINIMAL_REPAIRS = "alternative_minimal_repairs"
    EFFECT_ONLY = "effect_only"
    NOT_IDENTIFIABLE = "not_identifiable"


class UnknownReason(StrEnum):
    AMBIGUOUS_WORLDS = "ambiguous_worlds"
    BUDGET_EXHAUSTED = "budget_exhausted"
    INTERVENTION_UNFULFILLED = "intervention_unfulfilled"
    MISSING_STATE = "missing_state"
    NO_REPAIR_IN_DECLARED_ALGEBRA = "no_repair_in_declared_algebra"
    REPLAY_DIVERGED = "replay_diverged"


@dataclass(frozen=True, slots=True)
class AmbiguityWitness:
    """Two compatible completions with incompatible causal profiles."""

    left_world_id: str
    left_target_family: TargetFamily
    right_world_id: str
    right_target_family: TargetFamily


@dataclass(frozen=True, slots=True)
class AttributionVerdict:
    registry_digest: str
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
class RegistryManifest:
    """Public commitment to one declared finite hypothesis family."""

    task_schema_id: str
    task_id: str
    atoms: tuple[InterventionAtom, ...]
    intervention_contract_digest: str
    probe_names: tuple[str, ...]
    probe_contract_digest: str
    runner_contract_digest: str
    success_oracle_contract_digest: str
    declared_state_channels: tuple[str, ...]
    candidate_commitments: tuple[str, ...]

    @property
    def coverage_digest(self) -> str:
        payload: dict[str, JsonValue] = {
            "declared_state_channels": self.declared_state_channels,
            "format": "witnessgap.coverage-manifest.v1",
            "task_schema_id": self.task_schema_id,
        }
        return canonical_digest("witnessgap.coverage-manifest.v1", payload)

    @property
    def digest(self) -> str:
        payload: dict[str, JsonValue] = {
            "atoms": tuple({"name": atom.name, "target": atom.target} for atom in self.atoms),
            "candidate_commitments": self.candidate_commitments,
            "coverage_manifest_digest": self.coverage_digest,
            "format": _REGISTRY_FORMAT,
            "intervention_contract_digest": self.intervention_contract_digest,
            "probe_names": self.probe_names,
            "probe_contract_digest": self.probe_contract_digest,
            "runner_contract_digest": self.runner_contract_digest,
            "success_oracle_contract_digest": self.success_oracle_contract_digest,
            "task_id": self.task_id,
            "task_schema_id": self.task_schema_id,
        }
        return canonical_digest(_REGISTRY_FORMAT, payload)


@dataclass(frozen=True, slots=True)
class CandidateRegistry:
    """A finite hypothesis family used to judge identifiability."""

    manifest: RegistryManifest
    candidates: tuple[WorldCandidate, ...]

    @classmethod
    def build(cls, worlds: Iterable[ProbeWorld]) -> CandidateRegistry:
        world_family = tuple(worlds)
        reference = _validate_world_family(world_family)
        commitments = [world.completion_commitment for world in world_family]
        panels = [_validated_panel(world) for world in world_family]

        if len(set(commitments)) != len(commitments):
            raise RegistryError("candidate completion commitments must be unique")

        manifest = RegistryManifest(
            task_schema_id=reference.task_schema_id,
            task_id=reference.task_id,
            atoms=reference.atoms,
            intervention_contract_digest=reference.intervention_contract_digest,
            probe_names=reference.probe_names,
            probe_contract_digest=reference.probe_contract_digest,
            runner_contract_digest=reference.runner_contract_digest,
            success_oracle_contract_digest=reference.success_oracle_contract_digest,
            declared_state_channels=reference.declared_state_channels,
            candidate_commitments=tuple(sorted(commitments)),
        )
        candidates: list[WorldCandidate] = []
        for world, panel in zip(world_family, panels, strict=True):
            baseline_receipt = panel.receipt_for(())
            probes = tuple(
                ProbeObservation(name=name, value=world.probe(name)) for name in world.probe_names
            )
            candidates.append(
                WorldCandidate(
                    panel=panel,
                    completion_commitment=world.completion_commitment,
                    baseline=Evidence(
                        registry_digest=manifest.digest,
                        coverage_manifest_digest=manifest.coverage_digest,
                        public_trace=baseline_receipt.result.public_trace,
                        outcome=baseline_receipt.result.outcome,
                    ),
                    probe_observations=probes,
                )
            )
        return cls(manifest=manifest, candidates=tuple(candidates))

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
            registry_digest=self.manifest.digest,
            coverage_manifest_digest=self.manifest.coverage_digest,
            public_trace=candidate.baseline.public_trace,
            outcome=candidate.baseline.outcome,
            probes=observations,
            intervention_observations=intervention_observations,
        )

    def attribute(self, evidence: Evidence) -> AttributionVerdict:
        """Return the strongest causal verdict licensed by ``evidence``."""

        if (
            evidence.registry_digest != self.manifest.digest
            or evidence.coverage_manifest_digest != self.manifest.coverage_digest
        ):
            raise EvidenceMismatchError("evidence is not bound to this registry manifest")
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
                registry_digest=self.manifest.digest,
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
                registry_digest=self.manifest.digest,
                kind=VerdictKind.NOT_IDENTIFIABLE,
                compatible_world_ids=world_ids,
                unknown_reason=UnknownReason.NO_REPAIR_IN_DECLARED_ALGEBRA,
            )
        kind = (
            VerdictKind.IDENTIFIED_SINGLETON
            if len(profile) == 1 and len(profile[0]) == 1
            else VerdictKind.IDENTIFIED_COMPOUND
            if len(profile) == 1
            else VerdictKind.ALTERNATIVE_MINIMAL_REPAIRS
        )
        return AttributionVerdict(
            registry_digest=self.manifest.digest,
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
    if (candidate.baseline.public_trace, candidate.baseline.outcome) != (
        evidence.public_trace,
        evidence.outcome,
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


def _validate_world_family(worlds: tuple[ProbeWorld, ...]) -> ProbeWorld:
    if not worlds:
        raise RegistryError("candidate registry cannot be empty")

    world_ids = tuple(world.world_id for world in worlds)
    if len(set(world_ids)) != len(world_ids):
        raise RegistryError("candidate world IDs must be unique")
    if world_ids != tuple(sorted(world_ids)):
        raise RegistryError("candidate worlds must be sorted by world ID")

    reference = worlds[0]
    if not reference.task_schema_id or not reference.task_id:
        raise RegistryError("task schema and task IDs cannot be empty")
    reference_contract = _family_contract(reference)
    for world in worlds:
        if tuple(sorted(set(world.probe_names))) != world.probe_names:
            raise RegistryError(f"{world.world_id}: probe names must be unique and sorted")
        if tuple(sorted(set(world.declared_state_channels))) != world.declared_state_channels:
            raise RegistryError(
                f"{world.world_id}: declared state channels must be unique and sorted"
            )
        if _family_contract(world) != reference_contract:
            raise RegistryError(
                f"{world.world_id}: candidates must share one task, atom, "
                "probe, and coverage contract"
            )
        if not _is_sha256(world.completion_commitment):
            raise RegistryError(
                f"{world.world_id}: completion commitment must be a lowercase SHA-256 digest"
            )
        contract_digests = (
            world.intervention_contract_digest,
            world.probe_contract_digest,
            world.runner_contract_digest,
            world.success_oracle_contract_digest,
        )
        if not all(_is_sha256(digest) for digest in contract_digests):
            raise RegistryError(
                f"{world.world_id}: contract commitments must be lowercase SHA-256 digests"
            )
    return reference


def _family_contract(world: ProbeWorld) -> tuple[object, ...]:
    return (
        world.task_schema_id,
        world.task_id,
        world.atoms,
        world.intervention_contract_digest,
        world.probe_names,
        world.probe_contract_digest,
        world.runner_contract_digest,
        world.success_oracle_contract_digest,
        world.declared_state_channels,
    )


def _validated_panel(world: ProbeWorld) -> RepairPanel:
    panel = enumerate_repair_panel(world)
    undeclared_reads = {
        channel
        for receipt in panel.receipts
        for channel in receipt.result.state_reads
        if channel not in world.declared_state_channels
    }
    if undeclared_reads:
        raise RegistryError(
            f"{world.world_id}: replay read undeclared state channels {sorted(undeclared_reads)!r}"
        )
    return panel


def _is_sha256(value: str) -> bool:
    return len(value) == _SHA256_HEX_LENGTH and all(
        character in "0123456789abcdef" for character in value
    )
