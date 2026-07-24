"""Independent finite-family verifier for attribution claims.

This module deliberately does not import the search oracle or its cached
``RepairPanel`` labels. It resolves a trusted adapter internally, reconstructs
every replay from committed source bytes, and validates complete artifacts.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import cast

from witnessgap.adapters import TrustedAdapterError, resolve_trusted_adapter
from witnessgap.canonical import JsonValue, canonical_digest, canonical_json, tagged_digest
from witnessgap.identifiability import (
    Evidence,
    InterventionObservation,
    ProbeObservation,
    RegistryError,
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
    package_implementation_digest,
)
from witnessgap.trust import VerificationTrustAnchor

VERIFIER_MAX_ATOMS = 12
_CERTIFICATE_FORMAT = "witnessgap.attribution-certificate.v1"
_SHA256_HEX_LENGTH = 64
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_PAIR_SIZE = 2
_MIN_ALTERNATIVES = 2
_VERIFIER_IMPLEMENTATION_PATHS = (
    "__init__.py",
    "adapters.py",
    "canonical.py",
    "identifiability.py",
    "model.py",
    "source.py",
    "trust.py",
    "verifier.py",
)


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
class VerifiedProbeReceipt:
    """One probe value reproduced through two fresh source decodes."""

    completion_commitment: str
    source_snapshot_digest: str
    adapter_implementation_digest: str
    probe_contract_digest: str
    name: str
    value: bytes

    def __post_init__(self) -> None:
        for field, digest in (
            ("completion_commitment", self.completion_commitment),
            ("source_snapshot_digest", self.source_snapshot_digest),
            ("adapter_implementation_digest", self.adapter_implementation_digest),
            ("probe_contract_digest", self.probe_contract_digest),
        ):
            if not _is_sha256(digest):
                raise ValueError(f"{field} must be a lowercase SHA-256 digest")
        if type(self.name) is not str or not _IDENTIFIER.fullmatch(self.name):
            raise ValueError("probe receipt name must be an identifier")
        if type(self.value) is not bytes:
            raise TypeError("probe receipt value must be exact bytes")

    @property
    def digest(self) -> str:
        payload: dict[str, JsonValue] = {
            "adapter_implementation_digest": self.adapter_implementation_digest,
            "completion_commitment": self.completion_commitment,
            "format": "witnessgap.verified-probe-receipt.v1",
            "name": self.name,
            "probe_contract_digest": self.probe_contract_digest,
            "source_snapshot_digest": self.source_snapshot_digest,
            "value_digest": tagged_digest(
                "witnessgap.probe-value.v1",
                self.value,
            ),
        }
        return canonical_digest("witnessgap.verified-probe-receipt.v1", payload)


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
    adapter_implementation_digest: str
    verifier_implementation_digest: str
    trust_anchor_digest: str
    panel_root: str
    proof_root: str
    kind: VerdictKind
    compatible_completion_commitments: tuple[str, ...]
    target_family: TargetFamily | None = None
    unknown_reason: UnknownReason | None = None
    ambiguity_commitments: tuple[str, str] | None = None

    def __post_init__(self) -> None:
        _validate_verified_attribution(self)

    def to_canonical_bytes(self) -> bytes:
        """Serialize a closed, self-checking certificate record."""

        _validate_verified_attribution(self)
        payload = _certificate_proof_payload(self)
        payload["proof_root"] = self.proof_root
        return canonical_json(payload)

    @classmethod
    def from_canonical_bytes(cls, payload: bytes) -> VerifiedAttribution:
        """Parse a certificate record and recompute its internal proof root."""

        return _parse_attribution_certificate(payload)


@dataclass(frozen=True, slots=True)
class _AttributionBody:
    registry_digest: str
    evidence_digest: str
    adapter_implementation_digest: str
    trust_anchor_digest: str
    panel_root: str
    kind: VerdictKind
    compatible_completion_commitments: tuple[str, ...]
    target_family: TargetFamily | None = None
    unknown_reason: UnknownReason | None = None
    ambiguity_commitments: tuple[str, str] | None = None


@dataclass(frozen=True, slots=True)
class _CertificateFields:
    registry_digest: str
    evidence_digest: str
    adapter_implementation_digest: str
    verifier_implementation_digest: str
    trust_anchor_digest: str
    panel_root: str
    kind: VerdictKind
    compatible_completion_commitments: tuple[str, ...]
    target_family: TargetFamily | None
    unknown_reason: UnknownReason | None
    ambiguity_commitments: tuple[str, str] | None


def verify_registry_attribution(  # noqa: PLR0912
    sources: tuple[SealedWorldSource, ...],
    *,
    manifest: RegistryManifest,
    trust_anchor: VerificationTrustAnchor,
    evidence: Evidence,
) -> VerifiedAttribution:
    """Rebuild the committed family from source openings and derive a verdict."""

    sources = _normalize_source_openings(sources)
    trust_anchor = _normalize_trust_anchor(trust_anchor)
    manifest = _normalize_manifest(manifest)
    evidence = _normalize_evidence(evidence)
    if manifest.digest != trust_anchor.registry_digest:
        raise VerificationError("registry manifest does not match the trust anchor")
    if manifest.adapter_implementation_digest != trust_anchor.adapter_implementation_digest:
        raise VerificationError("registry adapter does not match the trust anchor")
    if (
        evidence.registry_digest != trust_anchor.registry_digest
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
    panel_root = _panel_root(tuple(panels), compatibility)
    profiles = {panel.target_family for panel in compatible}
    compatible_commitments = tuple(panel.completion_commitment for panel in compatible)
    verified_evidence_digest = evidence_digest(evidence)

    if len(profiles) > 1:
        left = compatible[0]
        right = next(panel for panel in compatible[1:] if panel.target_family != left.target_family)
        return _finalize_attribution(
            _AttributionBody(
                registry_digest=trust_anchor.registry_digest,
                evidence_digest=verified_evidence_digest,
                adapter_implementation_digest=manifest.adapter_implementation_digest,
                trust_anchor_digest=trust_anchor.digest,
                panel_root=panel_root,
                kind=VerdictKind.NOT_IDENTIFIABLE,
                compatible_completion_commitments=compatible_commitments,
                unknown_reason=UnknownReason.AMBIGUOUS_WORLDS,
                ambiguity_commitments=(
                    left.completion_commitment,
                    right.completion_commitment,
                ),
            ),
        )

    profile = profiles.pop()
    if not profile:
        return _finalize_attribution(
            _AttributionBody(
                registry_digest=trust_anchor.registry_digest,
                evidence_digest=verified_evidence_digest,
                adapter_implementation_digest=manifest.adapter_implementation_digest,
                trust_anchor_digest=trust_anchor.digest,
                panel_root=panel_root,
                kind=VerdictKind.NOT_IDENTIFIABLE,
                compatible_completion_commitments=compatible_commitments,
                unknown_reason=UnknownReason.NO_REPAIR_IN_DECLARED_ALGEBRA,
            )
        )
    if len(profile) > 1:
        kind = VerdictKind.ALTERNATIVE_MINIMAL_REPAIRS
    elif len(profile[0]) > 1:
        kind = VerdictKind.IDENTIFIED_COMPOUND
    else:
        kind = VerdictKind.IDENTIFIED_SINGLETON
    return _finalize_attribution(
        _AttributionBody(
            registry_digest=trust_anchor.registry_digest,
            evidence_digest=verified_evidence_digest,
            adapter_implementation_digest=manifest.adapter_implementation_digest,
            trust_anchor_digest=trust_anchor.digest,
            panel_root=panel_root,
            kind=kind,
            compatible_completion_commitments=compatible_commitments,
            target_family=profile,
        )
    )


def verify_source_panel(
    source: SealedWorldSource,
    *,
    manifest: RegistryManifest,
) -> VerifiedPanel:
    """Verify one panel with the adapter trusted by this release."""

    source = _normalize_source_opening(source)
    manifest = _normalize_manifest(manifest)
    try:
        adapter = resolve_trusted_adapter(
            manifest.adapter_id,
            expected_implementation_digest=manifest.adapter_implementation_digest,
        )
    except TrustedAdapterError as error:
        raise VerificationError(str(error)) from error
    return _verify_source_panel(source, adapter=adapter, manifest=manifest)


def verify_source_probe(
    source: SealedWorldSource,
    *,
    manifest: RegistryManifest,
    name: str,
) -> VerifiedProbeReceipt:
    """Verify one declared probe through two independently decoded worlds."""

    source = _normalize_source_opening(source)
    manifest = _normalize_manifest(manifest)
    if type(name) is not str or name not in manifest.probe_names:
        raise VerificationError(f"probe is not declared by the manifest: {name!r}")
    try:
        adapter = resolve_trusted_adapter(
            manifest.adapter_id,
            expected_implementation_digest=manifest.adapter_implementation_digest,
        )
    except TrustedAdapterError as error:
        raise VerificationError(str(error)) from error
    if adapter.source_format_id != manifest.source_format_id:
        raise VerificationError("trusted adapter source format differs from the manifest")
    first = _probe_fresh(source, adapter, manifest, name)
    second = _probe_fresh(source, adapter, manifest, name)
    if first != second:
        raise VerificationError(
            f"{source.completion_commitment}: probe diverged across fresh source decodes"
        )
    return VerifiedProbeReceipt(
        completion_commitment=source.completion_commitment,
        source_snapshot_digest=source.snapshot_digest,
        adapter_implementation_digest=manifest.adapter_implementation_digest,
        probe_contract_digest=manifest.probe_contract_digest,
        name=name,
        value=first,
    )


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

    return evidence.digest


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
    if type(artifact) is not ExecutionArtifact:
        raise VerificationError("runner returned a non-ExecutionArtifact value")
    try:
        artifact.validate()
    except (TypeError, ValueError) as error:
        raise VerificationError("runner returned a malformed execution artifact") from error
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


def _normalize_manifest(manifest: object) -> RegistryManifest:
    if type(manifest) is not RegistryManifest:
        raise VerificationError("manifest must be an exact RegistryManifest")
    try:
        manifest.validate()
        encoded = manifest.to_canonical_bytes()
        parsed = RegistryManifest.from_canonical_bytes(encoded)
    except (RegistryError, TypeError, ValueError) as error:
        raise VerificationError("registry manifest failed closed-schema validation") from error
    if parsed != manifest or parsed.to_canonical_bytes() != encoded:
        raise VerificationError("registry manifest failed canonical round-trip")
    return parsed


def _normalize_trust_anchor(anchor: object) -> VerificationTrustAnchor:
    if type(anchor) is not VerificationTrustAnchor:
        raise VerificationError("trust anchor must be an exact VerificationTrustAnchor")
    try:
        anchor.validate()
        encoded = anchor.to_canonical_bytes()
        parsed = VerificationTrustAnchor.from_canonical_bytes(encoded)
    except (TypeError, ValueError) as error:
        raise VerificationError("trust anchor failed closed-schema validation") from error
    if parsed != anchor or parsed.to_canonical_bytes() != encoded:
        raise VerificationError("trust anchor failed canonical round-trip")
    if anchor.verifier_implementation_digest != verifier_implementation_digest():
        raise VerificationError("installed verifier implementation differs from the trust anchor")
    return parsed


def _normalize_evidence(evidence: object) -> Evidence:
    if type(evidence) is not Evidence:
        raise VerificationError("evidence must be an exact Evidence value")
    try:
        evidence.validate()
    except (TypeError, ValueError) as error:
        raise VerificationError("evidence failed nested runtime validation") from error
    return Evidence(
        registry_digest=evidence.registry_digest,
        coverage_manifest_digest=evidence.coverage_manifest_digest,
        public_trace=evidence.public_trace,
        outcome=evidence.outcome,
        probes=tuple(
            ProbeObservation(name=observation.name, value=observation.value)
            for observation in evidence.probes
        ),
        intervention_observations=tuple(
            InterventionObservation(
                interventions=tuple(observation.interventions),
                public_trace=observation.public_trace,
                outcome=observation.outcome,
            )
            for observation in evidence.intervention_observations
        ),
    )


def _normalize_source_opening(source: object) -> SealedWorldSource:
    if type(source) is not SealedWorldSource:
        raise VerificationError("source must be an exact SealedWorldSource")
    try:
        source.validate()
    except (TypeError, ValueError) as error:
        raise VerificationError("source opening failed runtime validation") from error
    return SealedWorldSource(
        source_bytes=source.source_bytes,
        commitment_salt=source.commitment_salt,
    )


def _normalize_source_openings(sources: object) -> tuple[SealedWorldSource, ...]:
    if type(sources) is not tuple:
        raise VerificationError("source openings must be supplied as an exact tuple")
    if any(type(source) is not SealedWorldSource for source in sources):
        raise VerificationError("every source opening must be an exact SealedWorldSource")
    return tuple(_normalize_source_opening(source) for source in sources)


def _witness_for_mask(mask: int, atom_names: tuple[str, ...]) -> Witness:
    return tuple(name for index, name in enumerate(atom_names) if mask & (1 << index))


def _finalize_attribution(body: _AttributionBody) -> VerifiedAttribution:
    verifier_digest = verifier_implementation_digest()
    payload = _certificate_payload(
        _CertificateFields(
            registry_digest=body.registry_digest,
            evidence_digest=body.evidence_digest,
            adapter_implementation_digest=body.adapter_implementation_digest,
            verifier_implementation_digest=verifier_digest,
            trust_anchor_digest=body.trust_anchor_digest,
            panel_root=body.panel_root,
            kind=body.kind,
            compatible_completion_commitments=body.compatible_completion_commitments,
            target_family=body.target_family,
            unknown_reason=body.unknown_reason,
            ambiguity_commitments=body.ambiguity_commitments,
        )
    )
    proof_root = canonical_digest(_CERTIFICATE_FORMAT, payload)
    return VerifiedAttribution(
        registry_digest=body.registry_digest,
        evidence_digest=body.evidence_digest,
        adapter_implementation_digest=body.adapter_implementation_digest,
        verifier_implementation_digest=verifier_digest,
        trust_anchor_digest=body.trust_anchor_digest,
        panel_root=body.panel_root,
        proof_root=proof_root,
        kind=body.kind,
        compatible_completion_commitments=body.compatible_completion_commitments,
        target_family=body.target_family,
        unknown_reason=body.unknown_reason,
        ambiguity_commitments=body.ambiguity_commitments,
    )


def _certificate_payload(fields: _CertificateFields) -> dict[str, JsonValue]:
    return {
        "adapter_implementation_digest": fields.adapter_implementation_digest,
        "ambiguity_commitments": fields.ambiguity_commitments,
        "compatible_completion_commitments": fields.compatible_completion_commitments,
        "evidence_digest": fields.evidence_digest,
        "format": _CERTIFICATE_FORMAT,
        "kind": fields.kind.value,
        "panel_root": fields.panel_root,
        "registry_digest": fields.registry_digest,
        "target_family": fields.target_family,
        "trust_anchor_digest": fields.trust_anchor_digest,
        "unknown_reason": (
            fields.unknown_reason.value if fields.unknown_reason is not None else None
        ),
        "verifier_implementation_digest": fields.verifier_implementation_digest,
    }


def _certificate_proof_payload(
    certificate: VerifiedAttribution,
) -> dict[str, JsonValue]:
    return _certificate_payload(
        _CertificateFields(
            registry_digest=certificate.registry_digest,
            evidence_digest=certificate.evidence_digest,
            adapter_implementation_digest=certificate.adapter_implementation_digest,
            verifier_implementation_digest=certificate.verifier_implementation_digest,
            trust_anchor_digest=certificate.trust_anchor_digest,
            panel_root=certificate.panel_root,
            kind=certificate.kind,
            compatible_completion_commitments=(certificate.compatible_completion_commitments),
            target_family=certificate.target_family,
            unknown_reason=certificate.unknown_reason,
            ambiguity_commitments=certificate.ambiguity_commitments,
        )
    )


def verify_attribution_certificate(
    payload: bytes,
    *,
    trust_anchor: VerificationTrustAnchor,
    expected_proof_root: str,
) -> VerifiedAttribution:
    """Verify a serialized record against independently pinned digests.

    This checks record integrity and release binding. Re-establishing replay
    semantics still requires ``verify_registry_attribution`` and source
    openings.
    """

    anchor = _normalize_trust_anchor(trust_anchor)
    if not _is_sha256(expected_proof_root):
        raise VerificationError("expected proof root must be a lowercase SHA-256 digest")
    certificate = VerifiedAttribution.from_canonical_bytes(payload)
    if certificate.proof_root != expected_proof_root:
        raise VerificationError("certificate does not match the expected proof root")
    if (
        certificate.registry_digest != anchor.registry_digest
        or certificate.adapter_implementation_digest != anchor.adapter_implementation_digest
        or certificate.verifier_implementation_digest != anchor.verifier_implementation_digest
        or certificate.trust_anchor_digest != anchor.digest
    ):
        raise VerificationError("certificate does not match the external trust anchor")
    return certificate


def _validate_verified_attribution(certificate: VerifiedAttribution) -> None:
    digest_fields = (
        certificate.registry_digest,
        certificate.evidence_digest,
        certificate.adapter_implementation_digest,
        certificate.verifier_implementation_digest,
        certificate.trust_anchor_digest,
        certificate.panel_root,
        certificate.proof_root,
    )
    if not all(_is_sha256(value) for value in digest_fields):
        raise ValueError("certificate digest fields must be lowercase SHA-256")
    if type(certificate.kind) is not VerdictKind:
        raise TypeError("certificate kind must be an exact VerdictKind")
    _validate_commitment_tuple(certificate.compatible_completion_commitments)
    _validate_certificate_targets(certificate.target_family)
    if (
        certificate.unknown_reason is not None
        and type(certificate.unknown_reason) is not UnknownReason
    ):
        raise TypeError("certificate unknown_reason must be an exact UnknownReason")
    _validate_ambiguity_commitments(certificate.ambiguity_commitments)
    _validate_verdict_shape(certificate)
    expected_root = canonical_digest(
        _CERTIFICATE_FORMAT,
        _certificate_proof_payload(certificate),
    )
    if certificate.proof_root != expected_root:
        raise ValueError("certificate proof root contradicts its fields")


def _validate_commitment_tuple(commitments: object) -> None:
    if (
        type(commitments) is not tuple
        or not commitments
        or any(not _is_sha256(value) for value in commitments)
        or tuple(sorted(set(commitments))) != commitments
    ):
        raise ValueError("compatible completion commitments must be non-empty, unique, and sorted")


def _validate_certificate_targets(target_family: object) -> None:
    if target_family is None:
        return
    if type(target_family) is not tuple or not target_family:
        raise ValueError("certificate target_family must be a non-empty exact tuple")
    for target_set in target_family:
        if (
            type(target_set) is not tuple
            or not target_set
            or any(
                type(target) is not str or not _IDENTIFIER.fullmatch(target)
                for target in target_set
            )
            or tuple(sorted(set(target_set))) != target_set
        ):
            raise ValueError("certificate target sets must be unique sorted identifiers")
    if tuple(sorted(set(target_family))) != target_family:
        raise ValueError("certificate target_family must be unique and sorted")


def _validate_ambiguity_commitments(commitments: object) -> None:
    if commitments is None:
        return
    if (
        type(commitments) is not tuple
        or len(commitments) != _PAIR_SIZE
        or any(not _is_sha256(value) for value in commitments)
        or commitments[0] >= commitments[1]
    ):
        raise ValueError("ambiguity commitments must be two distinct sorted SHA-256 digests")


def _validate_verdict_shape(certificate: VerifiedAttribution) -> None:
    if certificate.kind is VerdictKind.NOT_IDENTIFIABLE:
        if certificate.target_family is not None or certificate.unknown_reason is None:
            raise ValueError("not_identifiable requires one reason and no target family")
        needs_pair = certificate.unknown_reason is UnknownReason.AMBIGUOUS_WORLDS
        if needs_pair != (certificate.ambiguity_commitments is not None):
            raise ValueError("ambiguous-world verdicts require exactly one ambiguity pair")
        if needs_pair:
            _validate_ambiguous_verdict_shape(certificate)
        return
    if certificate.kind is VerdictKind.EFFECT_ONLY:
        if (
            certificate.target_family is not None
            or certificate.unknown_reason is not None
            or certificate.ambiguity_commitments is not None
        ):
            raise ValueError("effect_only cannot contain target or unknown fields")
        return
    if (
        certificate.target_family is None
        or certificate.unknown_reason is not None
        or certificate.ambiguity_commitments is not None
    ):
        raise ValueError("identified verdicts require targets and no unknown fields")
    family = certificate.target_family
    if certificate.kind is VerdictKind.IDENTIFIED_SINGLETON and not (
        len(family) == 1 and len(family[0]) == 1
    ):
        raise ValueError("identified_singleton requires one singleton target set")
    if certificate.kind is VerdictKind.IDENTIFIED_COMPOUND and not (
        len(family) == 1 and len(family[0]) > 1
    ):
        raise ValueError("identified_compound requires one multi-target set")
    if certificate.kind is VerdictKind.ALTERNATIVE_MINIMAL_REPAIRS:
        _validate_alternative_repairs(family)


def _validate_ambiguous_verdict_shape(certificate: VerifiedAttribution) -> None:
    if len(certificate.compatible_completion_commitments) < _PAIR_SIZE:
        raise ValueError("ambiguous-world verdicts require at least two compatible completions")
    ambiguity_commitments = certificate.ambiguity_commitments
    if ambiguity_commitments is None or not set(ambiguity_commitments).issubset(
        certificate.compatible_completion_commitments
    ):
        raise ValueError("ambiguity commitments must be a subset of compatible completions")


def _validate_alternative_repairs(family: TargetFamily) -> None:
    if len(family) < _MIN_ALTERNATIVES:
        raise ValueError("alternative_minimal_repairs requires multiple target sets")
    target_sets = tuple(frozenset(target_set) for target_set in family)
    if any(
        left < right or right < left
        for index, left in enumerate(target_sets)
        for right in target_sets[index + 1 :]
    ):
        raise ValueError("alternative_minimal_repairs target family must be an antichain")


def _parse_attribution_certificate(payload: bytes) -> VerifiedAttribution:
    if type(payload) is not bytes:
        raise TypeError("certificate payload must be exact bytes")
    try:
        raw: object = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("certificate is not valid UTF-8 JSON") from error
    expected_fields = {
        "adapter_implementation_digest",
        "ambiguity_commitments",
        "compatible_completion_commitments",
        "evidence_digest",
        "format",
        "kind",
        "panel_root",
        "proof_root",
        "registry_digest",
        "target_family",
        "trust_anchor_digest",
        "unknown_reason",
        "verifier_implementation_digest",
    }
    try:
        canonical = type(raw) is dict and canonical_json(cast(JsonValue, raw)) == payload
    except TypeError as error:
        raise ValueError("certificate contains unsupported JSON values") from error
    if not canonical or set(cast(dict[str, object], raw)) != expected_fields:
        raise ValueError("certificate is not one closed canonical JSON object")
    value = cast(dict[str, object], raw)
    if value["format"] != _CERTIFICATE_FORMAT:
        raise ValueError("certificate format is unsupported")
    try:
        kind = VerdictKind(_certificate_string(value, "kind"))
    except ValueError as error:
        raise ValueError("certificate kind is unsupported") from error
    unknown_raw = value["unknown_reason"]
    try:
        unknown_reason = (
            None
            if unknown_raw is None
            else UnknownReason(_exact_string(unknown_raw, field="unknown_reason"))
        )
    except ValueError as error:
        raise ValueError("certificate unknown reason is unsupported") from error
    certificate = VerifiedAttribution(
        registry_digest=_certificate_string(value, "registry_digest"),
        evidence_digest=_certificate_string(value, "evidence_digest"),
        adapter_implementation_digest=_certificate_string(
            value,
            "adapter_implementation_digest",
        ),
        verifier_implementation_digest=_certificate_string(
            value,
            "verifier_implementation_digest",
        ),
        trust_anchor_digest=_certificate_string(value, "trust_anchor_digest"),
        panel_root=_certificate_string(value, "panel_root"),
        proof_root=_certificate_string(value, "proof_root"),
        kind=kind,
        compatible_completion_commitments=_string_tuple(
            value["compatible_completion_commitments"],
            field="compatible_completion_commitments",
        ),
        target_family=_target_family(value["target_family"]),
        unknown_reason=unknown_reason,
        ambiguity_commitments=_ambiguity_pair(value["ambiguity_commitments"]),
    )
    if certificate.to_canonical_bytes() != payload:
        raise ValueError("certificate failed canonical round-trip")
    return certificate


def _certificate_string(raw: dict[str, object], field: str) -> str:
    return _exact_string(raw[field], field=field)


def _exact_string(value: object, *, field: str) -> str:
    if type(value) is not str:
        raise ValueError(f"certificate field {field!r} must be a string")
    return value


def _string_tuple(value: object, *, field: str) -> tuple[str, ...]:
    if type(value) is not list or any(type(item) is not str for item in value):
        raise ValueError(f"certificate field {field!r} must be an array of strings")
    return tuple(cast(list[str], value))


def _target_family(value: object) -> TargetFamily | None:
    if value is None:
        return None
    if type(value) is not list or any(type(item) is not list for item in value):
        raise ValueError("certificate target_family must be an array of arrays")
    return tuple(
        _string_tuple(target_set, field="target_family") for target_set in cast(list[object], value)
    )


def _ambiguity_pair(value: object) -> tuple[str, str] | None:
    if value is None:
        return None
    pair = _string_tuple(value, field="ambiguity_commitments")
    if len(pair) != _PAIR_SIZE:
        raise ValueError("certificate ambiguity_commitments must contain two values")
    return pair[0], pair[1]


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == _SHA256_HEX_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def verifier_implementation_digest() -> str:
    """Digest the exact installed modules that implement certificate checks."""

    return package_implementation_digest(
        "witnessgap.verifier-implementation.v1",
        _VERIFIER_IMPLEMENTATION_PATHS,
    )


def trust_anchor_for_manifest(manifest: RegistryManifest) -> VerificationTrustAnchor:
    """Author an anchor for external review; verification never creates its own."""

    manifest = _normalize_manifest(manifest)
    try:
        resolve_trusted_adapter(
            manifest.adapter_id,
            expected_implementation_digest=manifest.adapter_implementation_digest,
        )
    except TrustedAdapterError as error:
        raise VerificationError(str(error)) from error
    return VerificationTrustAnchor(
        registry_digest=manifest.digest,
        adapter_implementation_digest=manifest.adapter_implementation_digest,
        verifier_implementation_digest=verifier_implementation_digest(),
    )


def _panel_root(
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
