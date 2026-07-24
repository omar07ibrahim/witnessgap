"""Verified materials used to author Workspace-100 public evidence views."""

from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations

from witnessgap.canonical import JsonValue, canonical_digest
from witnessgap.identifiability import RegistryManifest
from witnessgap.model import ExecutionArtifact, Outcome, TargetFamily, Witness
from witnessgap.verifier import (
    VerifiedPanel,
    VerifiedProbeReceipt,
    VerifiedReceipt,
    verify_source_panel,
    verify_source_probe,
)
from witnessgap.workspace100.catalog import TEMPLATES
from witnessgap.workspace100.generation import (
    GeneratedPair,
    Workspace100Corpus,
)
from witnessgap.workspace100.records import PROTOCOL_ID, Split, TemplateId, TemplateRecord
from witnessgap.workspace100.runtime import (
    Workspace100World,
    workspace100_pair_worlds,
)

_PAIR_COUNT = 50
_PAIR_SIZE = 2
_COMPLETION_COUNT = 100
_PROBES_PER_COMPLETION = 2
_ID_DIGEST_CHARACTERS = 24
_SHA256_HEX_LENGTH = 64


@dataclass(frozen=True, slots=True)
class VerifiedCompletionMaterial:
    """Verifier-owned panel and probes for one opaque episode."""

    episode_id: str
    panel: VerifiedPanel
    probes: tuple[VerifiedProbeReceipt, ...]

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if type(self.panel) is not VerifiedPanel:
            raise TypeError("verified material panel must be exact")
        expected_episode_id = _opaque_id(
            "wge",
            self.panel.completion_commitment,
        )
        if type(self.episode_id) is not str or self.episode_id != expected_episode_id:
            raise ValueError("verified material episode_id contradicts its completion")
        if (
            type(self.probes) is not tuple
            or len(self.probes) != _PROBES_PER_COMPLETION
            or any(type(receipt) is not VerifiedProbeReceipt for receipt in self.probes)
        ):
            raise TypeError("verified material must contain two exact probe receipts")
        probe_names = tuple(receipt.name for receipt in self.probes)
        if tuple(sorted(set(probe_names))) != probe_names:
            raise ValueError("verified material probes must be unique and sorted")
        for receipt in self.probes:
            _validate_probe_receipt(receipt)
            if (
                receipt.completion_commitment != self.panel.completion_commitment
                or receipt.source_snapshot_digest != self.panel.source_snapshot_digest
                or receipt.adapter_implementation_digest != self.panel.adapter_implementation_digest
            ):
                raise ValueError("verified probe receipt belongs to a different completion panel")

    def probe_for(self, name: str) -> VerifiedProbeReceipt:
        for receipt in self.probes:
            if receipt.name == name:
                return receipt
        raise KeyError(name)


@dataclass(frozen=True, slots=True)
class VerifiedPairMaterial:
    """All independently checked data needed to author one twin pair's views."""

    pair_id: str
    task_id: str
    template_id: TemplateId
    split: Split
    manifest: RegistryManifest
    completions: tuple[VerifiedCompletionMaterial, VerifiedCompletionMaterial]

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        _validate_pair_metadata(self)
        if (
            type(self.completions) is not tuple
            or len(self.completions) != _PAIR_SIZE
            or any(
                type(material) is not VerifiedCompletionMaterial for material in self.completions
            )
        ):
            raise TypeError("verified pair must contain two exact completion materials")
        for material in self.completions:
            material.validate()
            _validate_panel(material.panel, self.manifest)
            if tuple(receipt.name for receipt in material.probes) != self.manifest.probe_names:
                raise ValueError("verified pair probes differ from its manifest")
            if any(
                receipt.probe_contract_digest != self.manifest.probe_contract_digest
                for receipt in material.probes
            ):
                raise ValueError("verified pair probe contract differs from its manifest")
        commitments = tuple(material.panel.completion_commitment for material in self.completions)
        if commitments != self.manifest.candidate_commitments:
            raise ValueError("verified pair panels differ from its candidate manifest")
        if tuple(sorted(set(commitments))) != commitments:
            raise ValueError("verified pair completion materials must be unique and sorted")
        expected_pair_id = _pair_id(commitments)
        if type(self.pair_id) is not str or self.pair_id != expected_pair_id:
            raise ValueError("verified pair_id contradicts its completion commitments")
        episode_ids = tuple(material.episode_id for material in self.completions)
        if len(set(episode_ids)) != len(episode_ids):
            raise ValueError("verified pair episode IDs must be unique")


def verify_workspace100_materials(
    corpus: Workspace100Corpus,
) -> tuple[VerifiedPairMaterial, ...]:
    """Build panels and probe receipts without using search-time candidates."""

    if type(corpus) is not Workspace100Corpus:
        raise TypeError("verified view generation requires an exact Workspace100Corpus")
    corpus.validate()
    materials = tuple(_verify_pair_material(pair) for pair in corpus.pairs)
    if len(materials) != _PAIR_COUNT:
        raise ValueError(f"Workspace-100 must produce exactly {_PAIR_COUNT} pair materials")
    completion_count = sum(len(material.completions) for material in materials)
    if completion_count != _COMPLETION_COUNT:
        raise ValueError(
            f"Workspace-100 must produce exactly {_COMPLETION_COUNT} completion materials"
        )
    _validate_material_collection(corpus, materials)
    return materials


def _verify_pair_material(pair: GeneratedPair) -> VerifiedPairMaterial:
    worlds = workspace100_pair_worlds(pair)
    manifest = _manifest_for_worlds(worlds)
    completions: list[VerifiedCompletionMaterial] = []
    sources = {completion.completion_commitment: completion for completion in pair.completions}
    for world in worlds:
        completion = sources[world.completion_commitment]
        panel = verify_source_panel(
            completion.source,
            manifest=manifest,
        )
        probes = tuple(
            verify_source_probe(
                completion.source,
                manifest=manifest,
                name=name,
            )
            for name in manifest.probe_names
        )
        completions.append(
            VerifiedCompletionMaterial(
                episode_id=completion.episode_id,
                panel=panel,
                probes=probes,
            )
        )
    return VerifiedPairMaterial(
        pair_id=pair.pair_id,
        task_id=pair.task_id,
        template_id=pair.template_id,
        split=pair.split,
        manifest=manifest,
        completions=(completions[0], completions[1]),
    )


def _manifest_for_worlds(
    worlds: tuple[Workspace100World, Workspace100World],
) -> RegistryManifest:
    first, second = worlds
    if _world_declaration(first) != _world_declaration(second):
        raise ValueError("Workspace-100 twins do not share one runtime declaration")
    commitments = tuple(world.completion_commitment for world in worlds)
    if tuple(sorted(set(commitments))) != commitments:
        raise ValueError("Workspace-100 twins must be unique and commitment ordered")
    return RegistryManifest(
        task_schema_id=first.task_schema_id,
        task_id=first.task_id,
        source_format_id=first.source_format_id,
        adapter_id=first.adapter_id,
        adapter_implementation_digest=first.adapter_implementation_digest,
        atoms=first.atoms,
        intervention_contract_digest=first.intervention_contract_digest,
        probe_names=first.probe_names,
        probe_contract_digest=first.probe_contract_digest,
        runner_contract_digest=first.runner_contract_digest,
        artifact_validator_contract_digest=first.artifact_validator_contract_digest,
        success_oracle_contract_digest=first.success_oracle_contract_digest,
        state_access_contract_digest=first.state_access_contract_digest,
        declared_state_channels=first.declared_state_channels,
        candidate_commitments=commitments,
    )


def _world_declaration(world: Workspace100World) -> tuple[object, ...]:
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


def _validate_pair_metadata(material: VerifiedPairMaterial) -> None:
    if type(material.template_id) is not TemplateId:
        raise TypeError("verified pair template_id must be exact")
    if type(material.split) is not Split:
        raise TypeError("verified pair split must be exact")
    if type(material.manifest) is not RegistryManifest:
        raise TypeError("verified pair manifest must be exact")
    material.manifest.validate()
    if (
        type(material.task_id) is not str
        or not _is_opaque_id(material.task_id, "wgt")
        or material.task_id != material.manifest.task_id
    ):
        raise ValueError("verified pair task_id contradicts its manifest")
    template = _template_for(material.template_id)
    if material.split is not template.split:
        raise ValueError("verified pair split contradicts its frozen template")
    _validate_manifest_template(material.manifest, template)


def _validate_material_collection(
    corpus: Workspace100Corpus,
    materials: tuple[VerifiedPairMaterial, ...],
) -> None:
    for pair, material in zip(corpus.pairs, materials, strict=True):
        material.validate()
        if (
            material.pair_id,
            material.task_id,
            material.template_id,
            material.split,
        ) != (
            pair.pair_id,
            pair.task_id,
            pair.template_id,
            pair.split,
        ):
            raise ValueError("verified pair metadata differs from its authored pair")
        for completion, verified in zip(
            pair.completions,
            material.completions,
            strict=True,
        ):
            if (
                verified.episode_id != completion.episode_id
                or verified.panel.completion_commitment != completion.completion_commitment
                or verified.panel.source_snapshot_digest != completion.source.snapshot_digest
            ):
                raise ValueError("verified completion identity differs from its authored source")

    pair_ids = tuple(material.pair_id for material in materials)
    task_ids = tuple(material.task_id for material in materials)
    completions = tuple(completion for material in materials for completion in material.completions)
    unique_fields = {
        "pair IDs": pair_ids,
        "task IDs": task_ids,
        "episode IDs": tuple(completion.episode_id for completion in completions),
        "completion commitments": tuple(
            completion.panel.completion_commitment for completion in completions
        ),
        "source snapshots": tuple(
            completion.panel.source_snapshot_digest for completion in completions
        ),
    }
    for label, values in unique_fields.items():
        if len(set(values)) != len(values):
            raise ValueError(f"verified material collection contains duplicate {label}")
    if (
        sum(len(completion.probes) for completion in completions)
        != _COMPLETION_COUNT * _PROBES_PER_COMPLETION
    ):
        raise ValueError("verified material collection has the wrong probe count")
    if sum(len(completion.panel.receipts) for completion in completions) != _COMPLETION_COUNT * (
        1 << _PAIR_SIZE
    ):
        raise ValueError("verified material collection has the wrong replay count")


def _validate_manifest_template(
    manifest: RegistryManifest,
    template: TemplateRecord,
) -> None:
    expected_atom_names = tuple(sorted((template.refresh_atom, template.repair_atom)))
    expected_probe_names = tuple(sorted((template.epoch_probe, "workspace_owner")))
    if (
        manifest.task_schema_id != template.task_schema_id
        or tuple(atom.name for atom in manifest.atoms) != expected_atom_names
        or manifest.probe_names != expected_probe_names
    ):
        raise ValueError("verified pair manifest contradicts its frozen template")


def _validate_panel(
    panel: VerifiedPanel,
    manifest: RegistryManifest,
) -> None:
    expected_contracts = (
        manifest.adapter_implementation_digest,
        manifest.runner_contract_digest,
        manifest.artifact_validator_contract_digest,
        manifest.success_oracle_contract_digest,
        manifest.state_access_contract_digest,
    )
    panel_contracts = (
        panel.adapter_implementation_digest,
        panel.runner_contract_digest,
        panel.artifact_validator_contract_digest,
        panel.success_oracle_contract_digest,
        panel.state_access_contract_digest,
    )
    if panel_contracts != expected_contracts:
        raise ValueError("verified panel contracts differ from its manifest")
    if (
        not _is_sha256(panel.completion_commitment)
        or panel.completion_commitment not in manifest.candidate_commitments
        or not _is_sha256(panel.source_snapshot_digest)
    ):
        raise ValueError("verified panel identity is malformed or uncommitted")
    atom_names = tuple(atom.name for atom in manifest.atoms)
    if panel.atom_names != atom_names:
        raise ValueError("verified panel atoms differ from its manifest")

    expected_subsets = _intervention_subsets(atom_names)
    if (
        type(panel.receipts) is not tuple
        or len(panel.receipts) != len(expected_subsets)
        or any(type(receipt) is not VerifiedReceipt for receipt in panel.receipts)
    ):
        raise TypeError("verified panel must contain the complete exact receipt lattice")
    if tuple(receipt.interventions for receipt in panel.receipts) != expected_subsets:
        raise ValueError("verified panel receipts do not exhaust the intervention lattice")
    for receipt in panel.receipts:
        _validate_panel_receipt(
            receipt,
            source_snapshot_digest=panel.source_snapshot_digest,
            declared_state_channels=manifest.declared_state_channels,
        )
    if panel.receipts[0].outcome is not Outcome.FAILURE:
        raise ValueError("verified panel baseline must fail")

    minimal_witnesses = _minimal_successful_witnesses(panel.receipts)
    if panel.minimal_witnesses != minimal_witnesses:
        raise ValueError("verified panel minimal witnesses contradict its receipts")
    target_family = _target_family(minimal_witnesses, manifest)
    if panel.target_family != target_family:
        raise ValueError("verified panel target family contradicts its receipts")


def _validate_panel_receipt(
    receipt: VerifiedReceipt,
    *,
    source_snapshot_digest: str,
    declared_state_channels: tuple[str, ...],
) -> None:
    if type(receipt.interventions) is not tuple:
        raise TypeError("verified receipt interventions must be an exact tuple")
    if type(receipt.artifact) is not ExecutionArtifact:
        raise TypeError("verified receipt artifact must be exact")
    receipt.artifact.validate()
    if type(receipt.outcome) is not Outcome:
        raise TypeError("verified receipt outcome must be exact")
    if (
        receipt.artifact.source_snapshot_digest != source_snapshot_digest
        or receipt.artifact.intervention_log != receipt.interventions
    ):
        raise ValueError("verified receipt artifact contradicts its panel binding")
    if any(read.channel not in declared_state_channels for read in receipt.artifact.state_read_log):
        raise ValueError("verified receipt reads an undeclared state channel")


def _validate_probe_receipt(receipt: VerifiedProbeReceipt) -> None:
    for digest in (
        receipt.completion_commitment,
        receipt.source_snapshot_digest,
        receipt.adapter_implementation_digest,
        receipt.probe_contract_digest,
    ):
        if not _is_sha256(digest):
            raise ValueError("verified probe receipt contains a malformed digest")
    if type(receipt.name) is not str or type(receipt.value) is not bytes:
        raise TypeError("verified probe receipt name and value must be exact")


def _intervention_subsets(atom_names: tuple[str, ...]) -> tuple[Witness, ...]:
    return tuple(
        subset for size in range(len(atom_names) + 1) for subset in combinations(atom_names, size)
    )


def _minimal_successful_witnesses(
    receipts: tuple[VerifiedReceipt, ...],
) -> tuple[Witness, ...]:
    successful = tuple(
        receipt.interventions for receipt in receipts if receipt.outcome is Outcome.SUCCESS
    )
    return tuple(
        witness
        for witness in successful
        if not any(other != witness and set(other).issubset(witness) for other in successful)
    )


def _target_family(
    witnesses: tuple[Witness, ...],
    manifest: RegistryManifest,
) -> TargetFamily:
    targets = {atom.name: atom.target for atom in manifest.atoms}
    projected = {frozenset(targets[name] for name in witness) for witness in witnesses}
    antichain = {
        target_set for target_set in projected if not any(other < target_set for other in projected)
    }
    return tuple(sorted(tuple(sorted(target_set)) for target_set in antichain))


def _template_for(template_id: TemplateId) -> TemplateRecord:
    try:
        return next(template for template in TEMPLATES if template.template_id is template_id)
    except StopIteration as error:
        raise ValueError("verified pair names an unknown frozen template") from error


def _pair_id(commitments: tuple[str, ...]) -> str:
    payload: dict[str, JsonValue] = {
        "completion_commitments": commitments,
        "format": "witnessgap.workspace100-pair.v1",
        "protocol_id": PROTOCOL_ID,
    }
    digest = canonical_digest("witnessgap.workspace100-pair.v1", payload)
    return _opaque_id("wgp", digest)


def _opaque_id(prefix: str, digest: str) -> str:
    return f"{prefix}_{digest[:_ID_DIGEST_CHARACTERS]}"


def _is_opaque_id(value: str, prefix: str) -> bool:
    expected_length = len(prefix) + 1 + _ID_DIGEST_CHARACTERS
    return (
        len(value) == expected_length
        and value.startswith(f"{prefix}_")
        and all(character in "0123456789abcdef" for character in value[len(prefix) + 1 :])
    )


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == _SHA256_HEX_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )
