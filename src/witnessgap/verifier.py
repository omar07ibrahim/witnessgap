"""Independent finite-family verifier for attribution claims.

This module deliberately does not import the search oracle or its cached
``RepairPanel`` labels. It rebuilds every intervention panel from fresh runner
snapshots and evaluates terminal artifacts through each world's success oracle.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from witnessgap.canonical import JsonValue, canonical_digest, tagged_digest
from witnessgap.identifiability import (
    Evidence,
    RegistryManifest,
    UnknownReason,
    VerdictKind,
)
from witnessgap.model import (
    ExecutionArtifact,
    ExecutionRunner,
    Outcome,
    TargetFamily,
    Witness,
)

VERIFIER_MAX_ATOMS = 12


class VerifiableWorld(Protocol):
    """World source needed by the independent verifier."""

    @property
    def world_id(self) -> str: ...

    @property
    def task_schema_id(self) -> str: ...

    @property
    def task_id(self) -> str: ...

    @property
    def atoms(self) -> tuple[object, ...]: ...

    @property
    def probe_names(self) -> tuple[str, ...]: ...

    @property
    def declared_state_channels(self) -> tuple[str, ...]: ...

    @property
    def completion_commitment(self) -> str: ...

    @property
    def intervention_contract_digest(self) -> str: ...

    @property
    def probe_contract_digest(self) -> str: ...

    @property
    def runner_contract_digest(self) -> str: ...

    @property
    def success_oracle_contract_digest(self) -> str: ...

    def probe(self, name: str) -> bytes: ...

    def fresh_runner(self) -> ExecutionRunner: ...

    def evaluate_terminal(self, terminal_state: bytes) -> Outcome: ...


class VerificationError(ValueError):
    """Raised when source artifacts cannot support a trusted verdict."""


@dataclass(frozen=True, slots=True)
class VerifiedReceipt:
    """One independently replayed intervention subset."""

    interventions: Witness
    artifact: ExecutionArtifact
    outcome: Outcome

    @property
    def digest(self) -> str:
        state_reads: tuple[JsonValue, ...] = tuple(
            {
                "channel": read.channel,
                "sequence": read.sequence,
                "value_digest": read.value_digest,
            }
            for read in self.artifact.state_read_log
        )
        payload: dict[str, JsonValue] = {
            "format": "witnessgap.replay-receipt.v1",
            "intervention_log_digest": canonical_digest(
                "witnessgap.intervention-log.v1",
                self.artifact.intervention_log,
            ),
            "interventions": self.interventions,
            "outcome": self.outcome.value,
            "public_trace_digest": tagged_digest(
                "witnessgap.public-trace.v1",
                self.artifact.public_trace,
            ),
            "source_snapshot_digest": self.artifact.source_snapshot_digest,
            "state_read_log_digest": canonical_digest(
                "witnessgap.state-read-log.v1",
                state_reads,
            ),
            "terminal_state_digest": tagged_digest(
                "witnessgap.terminal-state.v1",
                self.artifact.terminal_state,
            ),
        }
        return canonical_digest("witnessgap.replay-receipt.v1", payload)


@dataclass(frozen=True, slots=True)
class VerifiedPanel:
    """Full independently derived panel for one sealed completion."""

    completion_commitment: str
    runner_contract_digest: str
    success_oracle_contract_digest: str
    atom_names: tuple[str, ...]
    receipts: tuple[VerifiedReceipt, ...]
    minimal_witnesses: tuple[Witness, ...]
    target_family: TargetFamily

    def receipt_for(self, interventions: Witness) -> VerifiedReceipt:
        for receipt in self.receipts:
            if receipt.interventions == interventions:
                return receipt
        raise KeyError(interventions)

    @property
    def digest(self) -> str:
        payload: dict[str, JsonValue] = {
            "atom_names": self.atom_names,
            "completion_commitment": self.completion_commitment,
            "format": "witnessgap.verified-panel.v1",
            "minimal_witnesses": self.minimal_witnesses,
            "receipt_digests": tuple(receipt.digest for receipt in self.receipts),
            "runner_contract_digest": self.runner_contract_digest,
            "success_oracle_contract_digest": self.success_oracle_contract_digest,
            "target_family": self.target_family,
        }
        return canonical_digest("witnessgap.verified-panel.v1", payload)


@dataclass(frozen=True, slots=True)
class VerifiedAttribution:
    """Verdict derived solely through the independent verification path."""

    registry_digest: str
    evidence_digest: str
    proof_root: str
    kind: VerdictKind
    compatible_completion_commitments: tuple[str, ...]
    target_family: TargetFamily | None = None
    unknown_reason: UnknownReason | None = None
    ambiguity_commitments: tuple[str, str] | None = None


def verify_registry_attribution(
    worlds: tuple[VerifiableWorld, ...],
    *,
    manifest: RegistryManifest,
    trusted_registry_digest: str,
    evidence: Evidence,
) -> VerifiedAttribution:
    """Rebuild the committed family and derive the strongest valid verdict."""

    if manifest.digest != trusted_registry_digest:
        raise VerificationError("registry manifest does not match the trusted digest")
    if (
        evidence.registry_digest != trusted_registry_digest
        or evidence.coverage_manifest_digest != manifest.coverage_digest
    ):
        raise VerificationError("evidence is not bound to the trusted registry")

    ordered_worlds = tuple(sorted(worlds, key=lambda world: world.completion_commitment))
    commitments = tuple(world.completion_commitment for world in ordered_worlds)
    if len(set(commitments)) != len(commitments):
        raise VerificationError("world sources contain duplicate completion commitments")
    if commitments != manifest.candidate_commitments:
        raise VerificationError("world sources do not exhaust the committed completion family")

    panels: list[VerifiedPanel] = []
    compatible_indexes: list[int] = []
    for index, world in enumerate(ordered_worlds):
        _verify_declaration(world, manifest)
        panel = verify_world_panel(world, manifest=manifest)
        panels.append(panel)
        if _matches_evidence(world, panel, evidence):
            compatible_indexes.append(index)

    if not compatible_indexes:
        raise VerificationError("no committed completion reproduces the supplied evidence")

    compatible = tuple(panels[index] for index in compatible_indexes)
    compatibility = tuple(index in compatible_indexes for index in range(len(panels)))
    proof_root = _proof_root(tuple(panels), compatibility)
    profiles = {panel.target_family for panel in compatible}
    compatible_commitments = tuple(panel.completion_commitment for panel in compatible)
    verified_evidence_digest = evidence_digest(evidence)

    if len(profiles) > 1:
        left = compatible[0]
        right = next(panel for panel in compatible[1:] if panel.target_family != left.target_family)
        return VerifiedAttribution(
            registry_digest=trusted_registry_digest,
            evidence_digest=verified_evidence_digest,
            proof_root=proof_root,
            kind=VerdictKind.NOT_IDENTIFIABLE,
            compatible_completion_commitments=compatible_commitments,
            unknown_reason=UnknownReason.AMBIGUOUS_WORLDS,
            ambiguity_commitments=(
                left.completion_commitment,
                right.completion_commitment,
            ),
        )

    profile = profiles.pop()
    if not profile:
        return VerifiedAttribution(
            registry_digest=trusted_registry_digest,
            evidence_digest=verified_evidence_digest,
            proof_root=proof_root,
            kind=VerdictKind.NOT_IDENTIFIABLE,
            compatible_completion_commitments=compatible_commitments,
            unknown_reason=UnknownReason.NO_REPAIR_IN_DECLARED_ALGEBRA,
        )
    if len(profile) > 1:
        kind = VerdictKind.ALTERNATIVE_MINIMAL_REPAIRS
    elif len(profile[0]) > 1:
        kind = VerdictKind.IDENTIFIED_COMPOUND
    else:
        kind = VerdictKind.IDENTIFIED_SINGLETON
    return VerifiedAttribution(
        registry_digest=trusted_registry_digest,
        evidence_digest=verified_evidence_digest,
        proof_root=proof_root,
        kind=kind,
        compatible_completion_commitments=compatible_commitments,
        target_family=profile,
    )


def verify_world_panel(
    world: VerifiableWorld,
    *,
    manifest: RegistryManifest,
) -> VerifiedPanel:
    """Replay all subsets from fresh snapshots and derive the causal profile."""

    _verify_declaration(world, manifest)
    atom_names = tuple(atom.name for atom in manifest.atoms)
    if len(atom_names) > VERIFIER_MAX_ATOMS:
        raise VerificationError(
            f"intervention algebra exceeds the verifier's {VERIFIER_MAX_ATOMS}-atom bound"
        )

    masks = sorted(
        range(1 << len(atom_names)),
        key=lambda mask: (mask.bit_count(), _witness_for_mask(mask, atom_names)),
    )
    receipts: list[VerifiedReceipt] = []
    successful_masks: set[int] = set()
    for mask in masks:
        witness = _witness_for_mask(mask, atom_names)
        interventions = frozenset(witness)
        first = _execute_fresh(world, interventions)
        second = _execute_fresh(world, interventions)
        if first != second:
            raise VerificationError(
                f"{world.completion_commitment}: fresh replays diverged for {witness!r}"
            )
        if first.intervention_log != witness:
            raise VerificationError(
                f"{world.completion_commitment}: intervention log does not fulfil {witness!r}"
            )
        undeclared = {
            read.channel
            for read in first.state_read_log
            if read.channel not in manifest.declared_state_channels
        }
        if undeclared:
            raise VerificationError(
                f"{world.completion_commitment}: runner read undeclared channels "
                f"{sorted(undeclared)!r}"
            )
        outcome = _evaluate(world, first)
        receipt = VerifiedReceipt(
            interventions=witness,
            artifact=first,
            outcome=outcome,
        )
        receipts.append(receipt)
        if outcome is Outcome.SUCCESS:
            successful_masks.add(mask)

    if receipts[0].outcome is not Outcome.FAILURE:
        raise VerificationError("the unmodified benchmark episode must fail")

    minimal_masks = tuple(
        mask
        for mask in masks
        if mask in successful_masks
        and not any(other != mask and other & mask == other for other in successful_masks)
    )
    minimal_witnesses = tuple(_witness_for_mask(mask, atom_names) for mask in minimal_masks)
    targets = {atom.name: atom.target for atom in manifest.atoms}
    projected = {frozenset(targets[name] for name in witness) for witness in minimal_witnesses}
    target_antichain = {
        target_set for target_set in projected if not any(other < target_set for other in projected)
    }
    target_family = tuple(sorted(tuple(sorted(target_set)) for target_set in target_antichain))

    _verify_declaration(world, manifest)
    return VerifiedPanel(
        completion_commitment=world.completion_commitment,
        runner_contract_digest=manifest.runner_contract_digest,
        success_oracle_contract_digest=manifest.success_oracle_contract_digest,
        atom_names=atom_names,
        receipts=tuple(receipts),
        minimal_witnesses=minimal_witnesses,
        target_family=target_family,
    )


def evidence_digest(evidence: Evidence) -> str:
    """Commit to exactly the evidence exposed to an attribution method."""

    probes: tuple[JsonValue, ...] = tuple(
        {
            "name": observation.name,
            "value_digest": tagged_digest(
                "witnessgap.probe-value.v1",
                observation.value,
            ),
        }
        for observation in evidence.probes
    )
    interventions: tuple[JsonValue, ...] = tuple(
        {
            "interventions": observation.interventions,
            "outcome": observation.outcome.value,
            "public_trace_digest": tagged_digest(
                "witnessgap.public-trace.v1",
                observation.public_trace,
            ),
        }
        for observation in evidence.intervention_observations
    )
    payload: dict[str, JsonValue] = {
        "coverage_manifest_digest": evidence.coverage_manifest_digest,
        "format": "witnessgap.evidence.v1",
        "intervention_observations": interventions,
        "outcome": evidence.outcome.value,
        "probes": probes,
        "public_trace_digest": tagged_digest(
            "witnessgap.public-trace.v1",
            evidence.public_trace,
        ),
        "registry_digest": evidence.registry_digest,
    }
    return canonical_digest("witnessgap.evidence.v1", payload)


def _execute_fresh(
    world: VerifiableWorld,
    interventions: frozenset[str],
) -> ExecutionArtifact:
    try:
        runner = world.fresh_runner()
        return runner.run(interventions)
    except (RuntimeError, TypeError, ValueError) as error:
        raise VerificationError(f"{world.completion_commitment}: fresh replay failed") from error


def _evaluate(world: VerifiableWorld, artifact: ExecutionArtifact) -> Outcome:
    try:
        outcome = world.evaluate_terminal(artifact.terminal_state)
    except (TypeError, ValueError) as error:
        raise VerificationError(
            f"{world.completion_commitment}: success oracle rejected terminal state"
        ) from error
    if not isinstance(outcome, Outcome):
        raise VerificationError("success oracle returned an invalid outcome")
    return outcome


def _verify_declaration(world: VerifiableWorld, manifest: RegistryManifest) -> None:
    declaration = (
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
    expected = (
        manifest.task_schema_id,
        manifest.task_id,
        manifest.atoms,
        manifest.intervention_contract_digest,
        manifest.probe_names,
        manifest.probe_contract_digest,
        manifest.runner_contract_digest,
        manifest.success_oracle_contract_digest,
        manifest.declared_state_channels,
    )
    if declaration != expected:
        raise VerificationError(
            f"{world.completion_commitment}: source declaration differs from the manifest"
        )
    if world.completion_commitment not in manifest.candidate_commitments:
        raise VerificationError("world completion is not committed by the manifest")


def _matches_evidence(
    world: VerifiableWorld,
    panel: VerifiedPanel,
    evidence: Evidence,
) -> bool:
    baseline = panel.receipt_for(())
    if (baseline.artifact.public_trace, baseline.outcome) != (
        evidence.public_trace,
        evidence.outcome,
    ):
        return False
    for probe_observation in evidence.probes:
        try:
            value = world.probe(probe_observation.name)
        except KeyError:
            return False
        if value != probe_observation.value:
            return False
    for intervention_observation in evidence.intervention_observations:
        try:
            receipt = panel.receipt_for(intervention_observation.interventions)
        except KeyError:
            return False
        if (receipt.artifact.public_trace, receipt.outcome) != (
            intervention_observation.public_trace,
            intervention_observation.outcome,
        ):
            return False
    return True


def _witness_for_mask(mask: int, atom_names: tuple[str, ...]) -> Witness:
    return tuple(name for index, name in enumerate(atom_names) if mask & (1 << index))


def _proof_root(
    panels: tuple[VerifiedPanel, ...],
    compatibility: tuple[bool, ...],
) -> str:
    entries: tuple[JsonValue, ...] = tuple(
        {
            "compatible": is_compatible,
            "completion_commitment": panel.completion_commitment,
            "panel_digest": panel.digest,
        }
        for panel, is_compatible in zip(panels, compatibility, strict=True)
    )
    return canonical_digest(
        "witnessgap.verification-proof.v1",
        {
            "entries": entries,
            "format": "witnessgap.verification-proof.v1",
        },
    )
