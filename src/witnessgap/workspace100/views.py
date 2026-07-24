"""Verified materials used to author Workspace-100 public evidence views."""

from __future__ import annotations

from dataclasses import dataclass

from witnessgap.identifiability import RegistryManifest
from witnessgap.verifier import (
    VerifiedPanel,
    VerifiedProbeReceipt,
    verify_source_panel,
    verify_source_probe,
)
from witnessgap.workspace100.generation import (
    GeneratedPair,
    Workspace100Corpus,
)
from witnessgap.workspace100.records import Split, TemplateId
from witnessgap.workspace100.runtime import (
    Workspace100World,
    workspace100_pair_worlds,
)

_PAIR_COUNT = 50
_PAIR_SIZE = 2
_COMPLETION_COUNT = 100
_PROBES_PER_COMPLETION = 2


@dataclass(frozen=True, slots=True)
class VerifiedCompletionMaterial:
    """Verifier-owned panel and probes for one opaque episode."""

    episode_id: str
    panel: VerifiedPanel
    probes: tuple[VerifiedProbeReceipt, ...]

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if type(self.episode_id) is not str or not self.episode_id.startswith("wge_"):
            raise ValueError("verified material episode_id must be opaque")
        if type(self.panel) is not VerifiedPanel:
            raise TypeError("verified material panel must be exact")
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
        if type(self.pair_id) is not str or not self.pair_id.startswith("wgp_"):
            raise ValueError("verified pair_id must be opaque")
        if type(self.task_id) is not str or self.task_id != self.manifest.task_id:
            raise ValueError("verified pair task_id contradicts its manifest")
        if type(self.template_id) is not TemplateId:
            raise TypeError("verified pair template_id must be exact")
        if type(self.split) is not Split:
            raise TypeError("verified pair split must be exact")
        if type(self.manifest) is not RegistryManifest:
            raise TypeError("verified pair manifest must be exact")
        self.manifest.validate()
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
