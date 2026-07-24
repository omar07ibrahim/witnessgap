"""Independent finite-family verifier for attribution claims.

This module deliberately does not import the search oracle or its cached
``RepairPanel`` labels. It resolves a trusted adapter internally, reconstructs
every replay from committed source bytes, and validates complete artifacts.
"""

from __future__ import annotations

from dataclasses import dataclass

from witnessgap.adapters import TrustedAdapterError, resolve_trusted_adapter
from witnessgap.canonical import JsonValue, canonical_digest, tagged_digest
from witnessgap.identifiability import (
    Evidence,
    RegistryManifest,
    UnknownReason,
    VerdictKind,
)
from witnessgap.model import (
    ExecutionArtifact,
    Outcome,
    TargetFamily,
    Witness,
)
from witnessgap.source import (
    DecodedWorld,
    SealedWorldSource,
    WorldSourceAdapter,
)

VERIFIER_MAX_ATOMS = 12


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
    source_snapshot_digest: str
    adapter_implementation_digest: str
    runner_contract_digest: str
    artifact_validator_contract_digest: str
    success_oracle_contract_digest: str
    state_access_contract_digest: str
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
            "adapter_implementation_digest": self.adapter_implementation_digest,
            "atom_names": self.atom_names,
            "artifact_validator_contract_digest": self.artifact_validator_contract_digest,
            "completion_commitment": self.completion_commitment,
            "format": "witnessgap.verified-panel.v1",
            "minimal_witnesses": self.minimal_witnesses,
            "receipt_digests": tuple(receipt.digest for receipt in self.receipts),
            "runner_contract_digest": self.runner_contract_digest,
            "source_snapshot_digest": self.source_snapshot_digest,
            "state_access_contract_digest": self.state_access_contract_digest,
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


def verify_registry_attribution(  # noqa: PLR0912
    sources: tuple[SealedWorldSource, ...],
    *,
    manifest: RegistryManifest,
    trusted_registry_digest: str,
    evidence: Evidence,
) -> VerifiedAttribution:
    """Rebuild the committed family from source openings and derive a verdict."""

    _validate_source_openings(sources)
    if manifest.digest != trusted_registry_digest:
        raise VerificationError("registry manifest does not match the trusted digest")
    if (
        evidence.registry_digest != trusted_registry_digest
        or evidence.coverage_manifest_digest != manifest.coverage_digest
    ):
        raise VerificationError("evidence is not bound to the trusted registry")
    _preflight_evidence(evidence, manifest)

    try:
        adapter = resolve_trusted_adapter(
            manifest.adapter_id,
            expected_implementation_digest=manifest.adapter_implementation_digest,
        )
    except TrustedAdapterError as error:
        raise VerificationError(str(error)) from error
    if adapter.source_format_id != manifest.source_format_id:
        raise VerificationError("trusted adapter source format differs from the manifest")

    ordered_sources = tuple(sorted(sources, key=lambda source: source.completion_commitment))
    commitments = tuple(source.completion_commitment for source in ordered_sources)
    if len(set(commitments)) != len(commitments):
        raise VerificationError("source openings contain duplicate completion commitments")
    if commitments != manifest.candidate_commitments:
        raise VerificationError("source openings do not exhaust the committed completion family")

    panels: list[VerifiedPanel] = []
    compatible_indexes: list[int] = []
    for index, source in enumerate(ordered_sources):
        panel = _verify_source_panel(source, adapter=adapter, manifest=manifest)
        panels.append(panel)
        if _matches_evidence(source, adapter, panel, evidence, manifest):
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


def verify_source_panel(
    source: SealedWorldSource,
    *,
    manifest: RegistryManifest,
) -> VerifiedPanel:
    """Verify one panel with the adapter trusted by this release."""

    if type(source) is not SealedWorldSource:
        raise VerificationError("source must be an exact SealedWorldSource")
    try:
        adapter = resolve_trusted_adapter(
            manifest.adapter_id,
            expected_implementation_digest=manifest.adapter_implementation_digest,
        )
    except TrustedAdapterError as error:
        raise VerificationError(str(error)) from error
    return _verify_source_panel(source, adapter=adapter, manifest=manifest)


def _verify_source_panel(
    source: SealedWorldSource,
    *,
    adapter: WorldSourceAdapter,
    manifest: RegistryManifest,
) -> VerifiedPanel:
    """Decode and replay every subset twice from the same immutable source."""

    _decode_source(source, adapter, manifest)
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
        first, first_outcome = _execute_fresh(source, adapter, manifest, interventions)
        second, second_outcome = _execute_fresh(source, adapter, manifest, interventions)
        if first != second:
            raise VerificationError(
                f"{source.completion_commitment}: fresh replays diverged for {witness!r}"
            )
        if first_outcome is not second_outcome:
            raise VerificationError(
                f"{source.completion_commitment}: artifact outcomes diverged for {witness!r}"
            )
        if first.intervention_log != witness:
            raise VerificationError(
                f"{source.completion_commitment}: intervention log does not fulfil {witness!r}"
            )
        undeclared = {
            read.channel
            for read in first.state_read_log
            if read.channel not in manifest.declared_state_channels
        }
        if undeclared:
            raise VerificationError(
                f"{source.completion_commitment}: runner read undeclared channels "
                f"{sorted(undeclared)!r}"
            )
        receipt = VerifiedReceipt(
            interventions=witness,
            artifact=first,
            outcome=first_outcome,
        )
        receipts.append(receipt)
        if first_outcome is Outcome.SUCCESS:
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

    _decode_source(source, adapter, manifest)
    return VerifiedPanel(
        completion_commitment=source.completion_commitment,
        source_snapshot_digest=source.snapshot_digest,
        adapter_implementation_digest=manifest.adapter_implementation_digest,
        runner_contract_digest=manifest.runner_contract_digest,
        artifact_validator_contract_digest=manifest.artifact_validator_contract_digest,
        success_oracle_contract_digest=manifest.success_oracle_contract_digest,
        state_access_contract_digest=manifest.state_access_contract_digest,
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
    source: SealedWorldSource,
    adapter: WorldSourceAdapter,
    manifest: RegistryManifest,
    interventions: frozenset[str],
) -> tuple[ExecutionArtifact, Outcome]:
    world = _decode_source(source, adapter, manifest)
    try:
        runner = world.fresh_runner()
        artifact = runner.run(interventions)
    except (RuntimeError, TypeError, ValueError) as error:
        raise VerificationError(f"{source.completion_commitment}: fresh replay failed") from error
    if artifact.source_snapshot_digest != source.snapshot_digest:
        raise VerificationError(
            f"{source.completion_commitment}: replay reports a different source snapshot"
        )
    try:
        outcome = world.validate_artifact(artifact)
    except (TypeError, ValueError) as error:
        raise VerificationError(
            f"{source.completion_commitment}: artifact validator rejected replay"
        ) from error
    if not isinstance(outcome, Outcome):
        raise VerificationError("artifact validator returned an invalid outcome")
    return artifact, outcome


def _decode_source(
    source: SealedWorldSource,
    adapter: WorldSourceAdapter,
    manifest: RegistryManifest,
) -> DecodedWorld:
    try:
        world = adapter.decode(source)
    except (TypeError, ValueError) as error:
        raise VerificationError(
            f"{source.completion_commitment}: trusted adapter rejected source opening"
        ) from error
    _verify_declaration(world, source, adapter, manifest)
    return world


def _verify_declaration(
    world: DecodedWorld,
    source: SealedWorldSource,
    adapter: WorldSourceAdapter,
    manifest: RegistryManifest,
) -> None:
    declaration = (
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
    expected = (
        manifest.task_schema_id,
        manifest.task_id,
        manifest.source_format_id,
        manifest.adapter_id,
        manifest.adapter_implementation_digest,
        manifest.atoms,
        manifest.intervention_contract_digest,
        manifest.probe_names,
        manifest.probe_contract_digest,
        manifest.runner_contract_digest,
        manifest.artifact_validator_contract_digest,
        manifest.success_oracle_contract_digest,
        manifest.state_access_contract_digest,
        manifest.declared_state_channels,
    )
    if declaration != expected:
        raise VerificationError(
            f"{source.completion_commitment}: decoded source declaration differs from the manifest"
        )
    if (
        world.completion_commitment != source.completion_commitment
        or world.source_snapshot_digest != source.snapshot_digest
    ):
        raise VerificationError("decoded world identity differs from the source opening")
    if source.completion_commitment not in manifest.candidate_commitments:
        raise VerificationError("source completion is not committed by the manifest")
    if (
        adapter.adapter_id != manifest.adapter_id
        or adapter.source_format_id != manifest.source_format_id
        or adapter.implementation_digest != manifest.adapter_implementation_digest
    ):
        raise VerificationError("trusted adapter identity differs from the manifest")


def _matches_evidence(
    source: SealedWorldSource,
    adapter: WorldSourceAdapter,
    panel: VerifiedPanel,
    evidence: Evidence,
    manifest: RegistryManifest,
) -> bool:
    baseline = panel.receipt_for(())
    if (baseline.artifact.public_trace, baseline.outcome) != (
        evidence.public_trace,
        evidence.outcome,
    ):
        return False
    for probe_observation in evidence.probes:
        first = _probe_fresh(source, adapter, manifest, probe_observation.name)
        second = _probe_fresh(source, adapter, manifest, probe_observation.name)
        if first != second:
            raise VerificationError(
                f"{source.completion_commitment}: probe diverged across fresh source decodes"
            )
        if first != probe_observation.value:
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


def _probe_fresh(
    source: SealedWorldSource,
    adapter: WorldSourceAdapter,
    manifest: RegistryManifest,
    name: str,
) -> bytes:
    world = _decode_source(source, adapter, manifest)
    try:
        value = world.probe(name)
    except KeyError as error:
        raise VerificationError(
            f"{source.completion_commitment}: declared probe is unavailable"
        ) from error
    if not isinstance(value, bytes):
        raise VerificationError("probe returned a non-bytes observation")
    return value


def _preflight_evidence(evidence: Evidence, manifest: RegistryManifest) -> None:
    undeclared_probes = {
        observation.name
        for observation in evidence.probes
        if observation.name not in manifest.probe_names
    }
    if undeclared_probes:
        raise VerificationError(
            f"evidence requests undeclared probes: {sorted(undeclared_probes)!r}"
        )
    atom_names = {atom.name for atom in manifest.atoms}
    undeclared_interventions = {
        name
        for observation in evidence.intervention_observations
        for name in observation.interventions
        if name not in atom_names
    }
    if undeclared_interventions:
        raise VerificationError(
            f"evidence requests undeclared interventions: {sorted(undeclared_interventions)!r}"
        )


def _validate_source_openings(sources: object) -> None:
    if not isinstance(sources, tuple):
        raise VerificationError("source openings must be supplied as a tuple")
    if any(type(source) is not SealedWorldSource for source in sources):
        raise VerificationError("every source opening must be an exact SealedWorldSource")


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
