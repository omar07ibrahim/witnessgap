"""Compatibility-set reasoning for finite benchmark worlds."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol, cast

from witnessgap.canonical import JsonValue, canonical_digest, canonical_json
from witnessgap.model import FiniteWorld, InterventionAtom, Outcome, TargetFamily, Witness

if TYPE_CHECKING:
    from witnessgap.oracle import RepairPanel

_REGISTRY_FORMAT = "witnessgap.registry.v2"
_SHA256_HEX_LENGTH = 64
_MAX_REGISTRY_ATOMS = 12
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_FORMAT_ID = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")


class ProbeWorld(FiniteWorld, Protocol):
    """A finite world that exposes task-authored diagnostic probes."""

    @property
    def task_schema_id(self) -> str:
        """Shared schema identity for the complete candidate family."""

    @property
    def task_id(self) -> str:
        """Shared public task identity for the complete candidate family."""

    @property
    def source_format_id(self) -> str:
        """Versioned closed schema decoded for every replay."""

    @property
    def adapter_id(self) -> str:
        """Identifier resolved through the verifier's trusted adapter registry."""

    @property
    def adapter_implementation_digest(self) -> str:
        """Digest of the installed source bundle implementing world semantics."""

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
    def artifact_validator_contract_digest(self) -> str:
        """Commitment to whole-artifact consistency checks."""

    @property
    def success_oracle_contract_digest(self) -> str:
        """Commitment to terminal success semantics."""

    @property
    def state_access_contract_digest(self) -> str:
        """Commitment to the state-recording interface."""

    @property
    def probe_names(self) -> tuple[str, ...]:
        """Complete names of probes that the benchmark may reveal."""

    def probe(self, name: str) -> bytes:
        """Return the canonical public observation for one probe."""


@dataclass(frozen=True, order=True, slots=True)
class ProbeObservation:
    name: str
    value: bytes

    def __post_init__(self) -> None:
        _require_identifier(self.name, field="probe name")
        if type(self.value) is not bytes:
            raise TypeError("probe value must be exact bytes")


@dataclass(frozen=True, order=True, slots=True)
class InterventionObservation:
    """Public result of one bounded repair query."""

    interventions: Witness
    public_trace: bytes
    outcome: Outcome

    def __post_init__(self) -> None:
        _validate_intervention_set(self.interventions)
        if type(self.public_trace) is not bytes:
            raise TypeError("intervention public_trace must be exact bytes")
        if type(self.outcome) is not Outcome:
            raise TypeError("intervention outcome must be an exact Outcome")


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
        self.validate()

    def validate(self) -> None:
        """Validate nested evidence again at an untrusted API boundary."""

        _validate_evidence_header(self)
        _validate_probe_observations(self.probes)
        _validate_intervention_observations(self.intervention_observations)


def _validate_evidence_header(evidence: Evidence) -> None:
    if not _is_sha256(evidence.registry_digest):
        raise ValueError("registry_digest must be a lowercase SHA-256 digest")
    if not _is_sha256(evidence.coverage_manifest_digest):
        raise ValueError("coverage_manifest_digest must be a lowercase SHA-256 digest")
    if type(evidence.public_trace) is not bytes:
        raise TypeError("evidence public_trace must be exact bytes")
    if type(evidence.outcome) is not Outcome:
        raise TypeError("evidence outcome must be an exact Outcome")


def _validate_probe_observations(probes: object) -> None:
    if type(probes) is not tuple or any(
        type(observation) is not ProbeObservation for observation in probes
    ):
        raise TypeError("probes must be a tuple of exact ProbeObservation values")
    typed_probes = cast(tuple[ProbeObservation, ...], probes)
    for observation in typed_probes:
        _require_identifier(observation.name, field="probe name")
        if type(observation.value) is not bytes:
            raise TypeError("probe value must be exact bytes")
    probe_names = tuple(observation.name for observation in typed_probes)
    if tuple(sorted(set(probe_names))) != probe_names:
        raise ValueError("probe observations must be unique and sorted by name")


def _validate_intervention_observations(observations: object) -> None:
    if type(observations) is not tuple or any(
        type(observation) is not InterventionObservation for observation in observations
    ):
        raise TypeError(
            "intervention_observations must contain exact InterventionObservation values"
        )
    typed_observations = cast(tuple[InterventionObservation, ...], observations)
    for observation in typed_observations:
        _validate_intervention_set(observation.interventions)
        if type(observation.public_trace) is not bytes:
            raise TypeError("intervention public_trace must be exact bytes")
        if type(observation.outcome) is not Outcome:
            raise TypeError("intervention outcome must be an exact Outcome")
    intervention_sets = tuple(observation.interventions for observation in typed_observations)
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
    source_format_id: str
    adapter_id: str
    adapter_implementation_digest: str
    atoms: tuple[InterventionAtom, ...]
    intervention_contract_digest: str
    probe_names: tuple[str, ...]
    probe_contract_digest: str
    runner_contract_digest: str
    artifact_validator_contract_digest: str
    success_oracle_contract_digest: str
    state_access_contract_digest: str
    declared_state_channels: tuple[str, ...]
    candidate_commitments: tuple[str, ...]

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        """Validate the complete public manifest at every trust boundary."""

        _require_identifier(
            self.task_schema_id,
            field="task_schema_id",
            error_type=RegistryError,
        )
        _require_identifier(
            self.task_id,
            field="task_id",
            error_type=RegistryError,
        )
        _require_format_id(
            self.source_format_id,
            field="source_format_id",
            error_type=RegistryError,
        )
        _require_identifier(
            self.adapter_id,
            field="adapter_id",
            error_type=RegistryError,
        )
        if type(self.atoms) is not tuple or any(
            type(atom) is not InterventionAtom for atom in self.atoms
        ):
            raise RegistryError("atoms must contain exact InterventionAtom values")
        if not self.atoms:
            raise RegistryError("registry intervention algebra cannot be empty")
        if len(self.atoms) > _MAX_REGISTRY_ATOMS:
            raise RegistryError(
                f"registry intervention algebra cannot exceed {_MAX_REGISTRY_ATOMS} atoms"
            )
        for atom in self.atoms:
            _require_identifier(
                atom.name,
                field="atom name",
                error_type=RegistryError,
            )
            _require_identifier(
                atom.target,
                field="atom target",
                error_type=RegistryError,
            )
        if tuple(sorted(self.atoms, key=lambda atom: (atom.name, atom.target))) != self.atoms:
            raise RegistryError("registry atoms must be sorted")
        atom_names = tuple(atom.name for atom in self.atoms)
        if len(set(atom_names)) != len(atom_names):
            raise RegistryError("registry atom names must be unique")
        _validate_identifier_tuple(self.probe_names, field="probe_names")
        _validate_identifier_tuple(
            self.declared_state_channels,
            field="declared_state_channels",
        )
        digests = (
            self.adapter_implementation_digest,
            self.intervention_contract_digest,
            self.probe_contract_digest,
            self.runner_contract_digest,
            self.artifact_validator_contract_digest,
            self.success_oracle_contract_digest,
            self.state_access_contract_digest,
        )
        if not all(_is_sha256(digest) for digest in digests):
            raise RegistryError("manifest contract fields must be lowercase SHA-256 digests")
        if (
            type(self.candidate_commitments) is not tuple
            or not self.candidate_commitments
            or any(type(commitment) is not str for commitment in self.candidate_commitments)
            or tuple(sorted(set(self.candidate_commitments))) != self.candidate_commitments
            or not all(_is_sha256(digest) for digest in self.candidate_commitments)
        ):
            raise RegistryError(
                "candidate_commitments must be non-empty, unique, sorted SHA-256 digests"
            )

    @property
    def coverage_digest(self) -> str:
        self.validate()
        payload: dict[str, JsonValue] = {
            "declared_state_channels": self.declared_state_channels,
            "format": "witnessgap.coverage-manifest.v2",
            "state_access_contract_digest": self.state_access_contract_digest,
            "task_schema_id": self.task_schema_id,
        }
        return canonical_digest("witnessgap.coverage-manifest.v2", payload)

    def to_payload(self) -> dict[str, JsonValue]:
        """Return the one closed JSON representation covered by the digest."""

        self.validate()
        return {
            "adapter_id": self.adapter_id,
            "adapter_implementation_digest": self.adapter_implementation_digest,
            "atoms": tuple({"name": atom.name, "target": atom.target} for atom in self.atoms),
            "artifact_validator_contract_digest": self.artifact_validator_contract_digest,
            "candidate_commitments": self.candidate_commitments,
            "coverage_manifest_digest": self.coverage_digest,
            "declared_state_channels": self.declared_state_channels,
            "format": _REGISTRY_FORMAT,
            "intervention_contract_digest": self.intervention_contract_digest,
            "probe_names": self.probe_names,
            "probe_contract_digest": self.probe_contract_digest,
            "runner_contract_digest": self.runner_contract_digest,
            "source_format_id": self.source_format_id,
            "state_access_contract_digest": self.state_access_contract_digest,
            "success_oracle_contract_digest": self.success_oracle_contract_digest,
            "task_id": self.task_id,
            "task_schema_id": self.task_schema_id,
        }

    def to_canonical_bytes(self) -> bytes:
        """Serialize the closed manifest for storage or independent review."""

        return canonical_json(self.to_payload())

    @classmethod
    def from_canonical_bytes(cls, payload: bytes) -> RegistryManifest:
        """Parse a canonical manifest while rejecting open or ambiguous schemas."""

        raw = _canonical_object(payload, label="registry manifest")
        expected_fields = {
            "adapter_id",
            "adapter_implementation_digest",
            "atoms",
            "artifact_validator_contract_digest",
            "candidate_commitments",
            "coverage_manifest_digest",
            "declared_state_channels",
            "format",
            "intervention_contract_digest",
            "probe_names",
            "probe_contract_digest",
            "runner_contract_digest",
            "source_format_id",
            "state_access_contract_digest",
            "success_oracle_contract_digest",
            "task_id",
            "task_schema_id",
        }
        if set(raw) != expected_fields:
            raise RegistryError("registry manifest contains unknown or missing fields")
        if raw["format"] != _REGISTRY_FORMAT:
            raise RegistryError("registry manifest format is unsupported")
        atoms_raw = raw["atoms"]
        if type(atoms_raw) is not list:
            raise RegistryError("registry atoms must be a JSON array")
        atoms: list[InterventionAtom] = []
        for raw_atom in atoms_raw:
            if type(raw_atom) is not dict or set(raw_atom) != {"name", "target"}:
                raise RegistryError("registry atom contains unknown or missing fields")
            name = raw_atom["name"]
            target = raw_atom["target"]
            if type(name) is not str or type(target) is not str:
                raise RegistryError("registry atom fields must be strings")
            atoms.append(InterventionAtom(name=name, target=target))
        manifest = cls(
            task_schema_id=_required_string(raw, "task_schema_id"),
            task_id=_required_string(raw, "task_id"),
            source_format_id=_required_string(raw, "source_format_id"),
            adapter_id=_required_string(raw, "adapter_id"),
            adapter_implementation_digest=_required_string(
                raw,
                "adapter_implementation_digest",
            ),
            atoms=tuple(atoms),
            intervention_contract_digest=_required_string(
                raw,
                "intervention_contract_digest",
            ),
            probe_names=_required_string_tuple(raw, "probe_names"),
            probe_contract_digest=_required_string(raw, "probe_contract_digest"),
            runner_contract_digest=_required_string(raw, "runner_contract_digest"),
            artifact_validator_contract_digest=_required_string(
                raw,
                "artifact_validator_contract_digest",
            ),
            success_oracle_contract_digest=_required_string(
                raw,
                "success_oracle_contract_digest",
            ),
            state_access_contract_digest=_required_string(
                raw,
                "state_access_contract_digest",
            ),
            declared_state_channels=_required_string_tuple(
                raw,
                "declared_state_channels",
            ),
            candidate_commitments=_required_string_tuple(
                raw,
                "candidate_commitments",
            ),
        )
        if _required_string(raw, "coverage_manifest_digest") != manifest.coverage_digest:
            raise RegistryError("coverage manifest digest contradicts its inline declaration")
        if manifest.to_canonical_bytes() != payload:
            raise RegistryError("registry manifest failed canonical round-trip")
        return manifest

    @property
    def digest(self) -> str:
        return canonical_digest(_REGISTRY_FORMAT, self.to_payload())


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
            source_format_id=reference.source_format_id,
            adapter_id=reference.adapter_id,
            adapter_implementation_digest=reference.adapter_implementation_digest,
            atoms=reference.atoms,
            intervention_contract_digest=reference.intervention_contract_digest,
            probe_names=reference.probe_names,
            probe_contract_digest=reference.probe_contract_digest,
            runner_contract_digest=reference.runner_contract_digest,
            artifact_validator_contract_digest=reference.artifact_validator_contract_digest,
            success_oracle_contract_digest=reference.success_oracle_contract_digest,
            state_access_contract_digest=reference.state_access_contract_digest,
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
            world.adapter_implementation_digest,
            world.intervention_contract_digest,
            world.probe_contract_digest,
            world.runner_contract_digest,
            world.artifact_validator_contract_digest,
            world.success_oracle_contract_digest,
            world.state_access_contract_digest,
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
        world.source_format_id,
        world.adapter_id,
        world.adapter_implementation_digest,
        world.atoms,
        world.intervention_contract_digest,
        world.probe_names,
        world.probe_contract_digest,
        world.runner_contract_digest,
        world.artifact_validator_contract_digest,
        world.success_oracle_contract_digest,
        world.state_access_contract_digest,
        world.declared_state_channels,
    )


def _validated_panel(world: ProbeWorld) -> RepairPanel:
    # Keep the search oracle outside verifier-only import and trust paths.
    from witnessgap.oracle import enumerate_repair_panel  # noqa: PLC0415

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


def _validate_intervention_set(interventions: object) -> None:
    if (
        type(interventions) is not tuple
        or not interventions
        or any(type(name) is not str for name in interventions)
        or tuple(sorted(set(interventions))) != interventions
    ):
        raise ValueError("interventions must be a non-empty sorted tuple of unique names")
    for name in interventions:
        _require_identifier(name, field="intervention name")


def _validate_identifier_tuple(values: object, *, field: str) -> None:
    if (
        type(values) is not tuple
        or any(type(value) is not str for value in values)
        or tuple(sorted(set(values))) != values
    ):
        raise RegistryError(f"{field} must be a unique sorted tuple of identifiers")
    for value in values:
        _require_identifier(value, field=field, error_type=RegistryError)


def _require_identifier(
    value: object,
    *,
    field: str,
    error_type: type[ValueError] = ValueError,
) -> None:
    if type(value) is not str or not _IDENTIFIER.fullmatch(value):
        raise error_type(f"{field} must match {_IDENTIFIER.pattern!r}: {value!r}")


def _require_format_id(
    value: object,
    *,
    field: str,
    error_type: type[ValueError] = ValueError,
) -> None:
    if type(value) is not str or not _FORMAT_ID.fullmatch(value):
        raise error_type(f"{field} must match {_FORMAT_ID.pattern!r}: {value!r}")


def _canonical_object(payload: bytes, *, label: str) -> dict[str, object]:
    if type(payload) is not bytes:
        raise RegistryError(f"{label} must be exact bytes")
    try:
        value: object = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RegistryError(f"{label} is not valid UTF-8 JSON") from error
    try:
        is_canonical = type(value) is dict and canonical_json(cast(JsonValue, value)) == payload
    except TypeError as error:
        raise RegistryError(f"{label} contains unsupported JSON values") from error
    if not is_canonical:
        raise RegistryError(f"{label} is not canonical JSON")
    return cast(dict[str, object], value)


def _required_string(raw: dict[str, object], field: str) -> str:
    value = raw[field]
    if type(value) is not str:
        raise RegistryError(f"registry field {field!r} must be a string")
    return value


def _required_string_tuple(raw: dict[str, object], field: str) -> tuple[str, ...]:
    value = raw[field]
    if type(value) is not list or any(type(item) is not str for item in value):
        raise RegistryError(f"registry field {field!r} must be an array of strings")
    return tuple(cast(list[str], value))


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == _SHA256_HEX_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )
