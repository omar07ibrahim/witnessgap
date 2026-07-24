"""Verified materials used to author Workspace-100 public evidence views."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum
from itertools import combinations
from typing import cast

from witnessgap.canonical import JsonValue, canonical_digest
from witnessgap.identifiability import (
    Evidence,
    InterventionObservation,
    ProbeObservation,
    RegistryManifest,
)
from witnessgap.model import ExecutionArtifact, Outcome, TargetFamily, Witness
from witnessgap.verifier import (
    VerifiedPanel,
    VerifiedProbeReceipt,
    VerifiedReceipt,
    verify_source_panel,
    verify_source_probe,
)
from witnessgap.workspace100.catalog import TEMPLATES
from witnessgap.workspace100.evidence import PublicEvidenceEnvelope
from witnessgap.workspace100.generation import (
    GeneratedPair,
    Workspace100Corpus,
)
from witnessgap.workspace100.records import (
    PROTOCOL_ID,
    SOURCE_FORMAT_ID,
    Split,
    TemplateId,
    TemplateRecord,
)
from witnessgap.workspace100.runtime import (
    WORKSPACE100_ADAPTER_ID,
    Workspace100World,
    workspace100_pair_worlds,
)

_PAIR_COUNT = 50
_PAIR_SIZE = 2
_COMPLETION_COUNT = 100
_PROBES_PER_COMPLETION = 2
_ID_DIGEST_CHARACTERS = 24
_SHA256_HEX_LENGTH = 64
_ASSIGNMENT_COUNT = 400
_EVIDENCE_CASE_COUNT = 300
_CASES_PER_TEMPLATE = 60
_ASSIGNMENTS_PER_EPISODE = 4
_ASSIGNMENTS_PER_PAIR = 8
_UNIQUE_CASES_PER_PAIR = 6


class ViewKind(StrEnum):
    """Frozen participant-evidence views in protocol order."""

    TRACE_ONLY = "trace_only"
    OWNER_PROBE = "owner_probe"
    EPOCH_PROBE = "epoch_probe"
    REFRESH_RECEIPT = "refresh_receipt"


_VIEW_ORDER = tuple(ViewKind)
_VIEW_RANK = {view: index for index, view in enumerate(_VIEW_ORDER)}
_TEMPLATE_RANK = {template_id: index for index, template_id in enumerate(TemplateId)}
_EXPECTED_CASES_BY_VIEW = {
    ViewKind.TRACE_ONLY: 50,
    ViewKind.OWNER_PROBE: 50,
    ViewKind.EPOCH_PROBE: 100,
    ViewKind.REFRESH_RECEIPT: 100,
}
_EXPECTED_CASES_BY_SPLIT = {
    Split.DEVELOPMENT: 120,
    Split.VALIDATION: 60,
    Split.TEST: 120,
}
_ENVIRONMENT_TARGET_FAMILY: TargetFamily = (("environment",),)
_POLICY_TARGET_FAMILY: TargetFamily = (("policy",),)
_FORBIDDEN_PUBLIC_LABELS = (
    b"causal_target",
    b"completion_side",
    b"current",
    b"environment",
    b"policy",
    b"resolver_aligned",
    b"selector_aligned",
    b"stale",
    b"target_label",
)
_FORBIDDEN_PUBLIC_KEYS = {
    b"case_id",
    b"completion_commitment",
    b"evidence_digest",
    b"episode_id",
    b"minimal_witnesses",
    b"pair_id",
    b"source_snapshot_digest",
    b"split",
    b"target_family",
    b"template_id",
    b"view",
}
_MAX_LEAK_SCAN_DEPTH = 16


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


@dataclass(frozen=True, slots=True)
class _CompletionRoute:
    """Private binding from one completion to its four evidence digests."""

    episode_id: str
    completion_commitment: str
    source_snapshot_digest: str
    evidence_digests: tuple[tuple[ViewKind, str], ...]

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if not _is_sha256(self.completion_commitment) or not _is_sha256(
            self.source_snapshot_digest
        ):
            raise ValueError("completion route commitments must be SHA-256 digests")
        expected_episode_id = _opaque_id("wge", self.completion_commitment)
        if type(self.episode_id) is not str or self.episode_id != expected_episode_id:
            raise ValueError("completion route episode contradicts its commitment")
        if (
            type(self.evidence_digests) is not tuple
            or len(self.evidence_digests) != len(_VIEW_ORDER)
            or any(
                type(binding) is not tuple
                or len(binding) != _PAIR_SIZE
                or type(binding[0]) is not ViewKind
                or not _is_sha256(binding[1])
                for binding in self.evidence_digests
            )
        ):
            raise TypeError("completion route must bind four exact evidence digests")
        if tuple(view for view, _digest in self.evidence_digests) != _VIEW_ORDER:
            raise ValueError("completion route evidence views are not in protocol order")
        digests = tuple(digest for _view, digest in self.evidence_digests)
        if len(set(digests)) != len(digests):
            raise ValueError("completion route evidence digests must be unique")

    def evidence_digest_for(self, view: ViewKind) -> str:
        for candidate, digest in self.evidence_digests:
            if candidate is view:
                return digest
        raise KeyError(view)

    def root_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "completion_commitment": self.completion_commitment,
            "episode_id": self.episode_id,
            "evidence_digests": tuple(
                {"digest": digest, "view": view.value} for view, digest in self.evidence_digests
            ),
            "format": "witnessgap.workspace100-completion-route.v1",
            "source_snapshot_digest": self.source_snapshot_digest,
        }


@dataclass(frozen=True, slots=True)
class _PairRoute:
    """Private manifest binding scheduler IDs to one verified registry."""

    pair_id: str
    template_id: TemplateId
    split: Split
    manifest: RegistryManifest
    completions: tuple[_CompletionRoute, _CompletionRoute]

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if type(self.template_id) is not TemplateId:
            raise TypeError("pair route template_id must be exact")
        if type(self.split) is not Split:
            raise TypeError("pair route split must be exact")
        if type(self.manifest) is not RegistryManifest:
            raise TypeError("pair route manifest must be exact")
        self.manifest.validate()
        template = _template_for(self.template_id)
        if self.split is not template.split:
            raise ValueError("pair route split contradicts its template")
        _validate_manifest_template(self.manifest, template)
        if (
            type(self.completions) is not tuple
            or len(self.completions) != _PAIR_SIZE
            or any(type(completion) is not _CompletionRoute for completion in self.completions)
        ):
            raise TypeError("pair route must contain two exact completion routes")
        for completion in self.completions:
            completion.validate()
        commitments = tuple(completion.completion_commitment for completion in self.completions)
        if commitments != self.manifest.candidate_commitments:
            raise ValueError("pair route completions contradict its manifest")
        if len(set(self.source_snapshot_digests)) != _PAIR_SIZE:
            raise ValueError("pair route source snapshots must be unique")
        expected_pair_id = _pair_id(commitments)
        if type(self.pair_id) is not str or self.pair_id != expected_pair_id:
            raise ValueError("pair route ID contradicts candidate commitments")

    @property
    def task_id(self) -> str:
        return self.manifest.task_id

    @property
    def episode_ids(self) -> tuple[str, str]:
        return (
            self.completions[0].episode_id,
            self.completions[1].episode_id,
        )

    @property
    def source_snapshot_digests(self) -> tuple[str, str]:
        return (
            self.completions[0].source_snapshot_digest,
            self.completions[1].source_snapshot_digest,
        )

    def root_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "completions": tuple(completion.root_payload() for completion in self.completions),
            "format": "witnessgap.workspace100-pair-route.v1",
            "manifest": self.manifest.to_payload(),
            "pair_id": self.pair_id,
            "split": self.split.value,
            "template_id": self.template_id.value,
        }


@dataclass(frozen=True, slots=True)
class _EvidenceAssignment:
    """Trusted-parent routing for one episode-to-view projection."""

    pair_id: str
    task_id: str
    episode_id: str
    template_id: TemplateId
    split: Split
    view: ViewKind
    evidence_digest: str

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        for field, value, prefix in (
            ("pair_id", self.pair_id, "wgp"),
            ("task_id", self.task_id, "wgt"),
            ("episode_id", self.episode_id, "wge"),
        ):
            if type(value) is not str or not _is_opaque_id(value, prefix):
                raise ValueError(f"evidence assignment {field} must be opaque")
        if type(self.template_id) is not TemplateId:
            raise TypeError("evidence assignment template_id must be exact")
        if type(self.split) is not Split:
            raise TypeError("evidence assignment split must be exact")
        if self.split is not _template_for(self.template_id).split:
            raise ValueError("evidence assignment split contradicts its template")
        if type(self.view) is not ViewKind:
            raise TypeError("evidence assignment view must be exact")
        if not _is_sha256(self.evidence_digest):
            raise ValueError("evidence assignment digest must be lowercase SHA-256")

    def root_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "episode_id": self.episode_id,
            "evidence_digest": self.evidence_digest,
            "format": "witnessgap.workspace100-evidence-assignment.v1",
            "pair_id": self.pair_id,
            "split": self.split.value,
            "task_id": self.task_id,
            "template_id": self.template_id.value,
            "view": self.view.value,
        }


@dataclass(frozen=True, slots=True)
class PublicEvidenceCase:
    """One unique evidence record; only ``worker_bytes`` enter a worker."""

    template_id: TemplateId
    split: Split
    view: ViewKind
    envelope: PublicEvidenceEnvelope

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if type(self.template_id) is not TemplateId:
            raise TypeError("public evidence case template_id must be exact")
        if type(self.split) is not Split:
            raise TypeError("public evidence case split must be exact")
        if self.split is not _template_for(self.template_id).split:
            raise ValueError("public evidence case split contradicts its template")
        if type(self.view) is not ViewKind:
            raise TypeError("public evidence case view must be exact")
        if type(self.envelope) is not PublicEvidenceEnvelope:
            raise TypeError("public evidence case envelope must be exact")
        self.envelope.evidence.validate()
        _validate_case_view(self)
        worker_bytes = self.envelope.to_canonical_bytes()
        if PublicEvidenceEnvelope.from_canonical_bytes(worker_bytes) != self.envelope:
            raise ValueError("public evidence case envelope failed its closed round-trip")

    @property
    def evidence_digest(self) -> str:
        return self.envelope.evidence_digest

    @property
    def worker_bytes(self) -> bytes:
        """Return the complete and only participant-visible request."""

        self.validate()
        return self.envelope.to_canonical_bytes()

    def root_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "evidence": self.envelope.to_payload(),
            "evidence_digest": self.evidence_digest,
            "format": "witnessgap.workspace100-evidence-case.v1",
            "split": self.split.value,
            "template_id": self.template_id.value,
            "view": self.view.value,
        }


@dataclass(frozen=True, slots=True)
class Workspace100ProjectionRoots:
    """One validated snapshot of the three public projection roots."""

    assignment_root: str
    evidence_root: str
    projection_root: str

    def __post_init__(self) -> None:
        for field, value in (
            ("assignment_root", self.assignment_root),
            ("evidence_root", self.evidence_root),
            ("projection_root", self.projection_root),
        ):
            if not _is_sha256(value):
                raise ValueError(f"projection {field} must be lowercase SHA-256")
        if self.projection_root != _projection_root(
            self.assignment_root,
            self.evidence_root,
        ):
            raise ValueError("projection root contradicts assignment and evidence roots")


@dataclass(frozen=True, slots=True)
class Workspace100EvidenceViews:
    """Deterministic 400-to-300 projection in root order, never run order.

    Registry commitments are stable within a pair. A later scheduler must give
    exactly one ``PublicEvidenceCase.worker_bytes`` value to a fresh isolated
    worker and must not expose this tuple's canonical position or metadata.
    """

    _routes: tuple[_PairRoute, ...]
    _assignments: tuple[_EvidenceAssignment, ...]
    cases: tuple[PublicEvidenceCase, ...]

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        _validate_evidence_view_types(self)
        for route in self._routes:
            route.validate()
        for assignment in self._assignments:
            assignment.validate()
        for case in self.cases:
            case.validate()
        _validate_evidence_view_order(self)
        _validate_evidence_view_join(self)
        _validate_evidence_view_counts(self)
        _validate_no_private_leaks(self)

    @property
    def assignment_count(self) -> int:
        return len(self._assignments)

    @property
    def case_count(self) -> int:
        return len(self.cases)

    @property
    def assignment_root(self) -> str:
        self.validate()
        return _assignment_root(self)

    @property
    def evidence_root(self) -> str:
        self.validate()
        return _evidence_root(self)

    @property
    def projection_root(self) -> str:
        """Bind routing and evidence roots without defining execution order."""

        self.validate()
        return _projection_root(
            _assignment_root(self),
            _evidence_root(self),
        )


def workspace100_projection_roots(
    views: Workspace100EvidenceViews,
) -> Workspace100ProjectionRoots:
    """Validate once and capture all roots without repeating the leak scan."""

    if type(views) is not Workspace100EvidenceViews:
        raise TypeError("projection roots require exact Workspace100EvidenceViews")
    views.validate()
    assignment_root = _assignment_root(views)
    evidence_root = _evidence_root(views)
    return Workspace100ProjectionRoots(
        assignment_root=assignment_root,
        evidence_root=evidence_root,
        projection_root=_projection_root(assignment_root, evidence_root),
    )


def _projection_root(
    assignment_root: str,
    evidence_root: str,
) -> str:
    payload: dict[str, JsonValue] = {
        "assignment_root": assignment_root,
        "evidence_root": evidence_root,
        "format": "witnessgap.workspace100-evidence-projection.v1",
        "protocol_id": PROTOCOL_ID,
    }
    return canonical_digest(
        "witnessgap.workspace100-evidence-projection.v1",
        payload,
    )


def _assignment_root(views: Workspace100EvidenceViews) -> str:
    payload: dict[str, JsonValue] = {
        "assignments": tuple(assignment.root_payload() for assignment in views._assignments),
        "format": "witnessgap.workspace100-assignment-set.v1",
        "protocol_id": PROTOCOL_ID,
        "routes": tuple(route.root_payload() for route in views._routes),
    }
    return canonical_digest("witnessgap.workspace100-assignment-set.v1", payload)


def _evidence_root(views: Workspace100EvidenceViews) -> str:
    payload: dict[str, JsonValue] = {
        "cases": tuple(case.root_payload() for case in views.cases),
        "format": "witnessgap.workspace100-evidence-set.v1",
        "protocol_id": PROTOCOL_ID,
    }
    return canonical_digest("witnessgap.workspace100-evidence-set.v1", payload)


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


def build_workspace100_evidence_views(
    corpus: Workspace100Corpus,
) -> Workspace100EvidenceViews:
    """Verify the corpus and project only receipt-backed participant evidence."""

    return _project_verified_materials(verify_workspace100_materials(corpus))


def _project_verified_materials(
    materials: tuple[VerifiedPairMaterial, ...],
) -> Workspace100EvidenceViews:
    if (
        type(materials) is not tuple
        or len(materials) != _PAIR_COUNT
        or any(type(material) is not VerifiedPairMaterial for material in materials)
    ):
        raise TypeError("evidence projection requires 50 exact verified pair materials")

    ordered_materials = tuple(sorted(materials, key=_material_sort_key))
    _validate_projection_materials(ordered_materials)
    routes: list[_PairRoute] = []
    assignments: list[_EvidenceAssignment] = []
    case_bindings: dict[
        str,
        tuple[PublicEvidenceCase, str, str, bytes],
    ] = {}
    for material in ordered_materials:
        completion_routes: list[_CompletionRoute] = []
        for completion in material.completions:
            evidence_digests: list[tuple[ViewKind, str]] = []
            for view in _VIEW_ORDER:
                envelope = _project_evidence(material, completion, view)
                case = PublicEvidenceCase(
                    template_id=material.template_id,
                    split=material.split,
                    view=view,
                    envelope=envelope,
                )
                assignment = _EvidenceAssignment(
                    pair_id=material.pair_id,
                    task_id=material.task_id,
                    episode_id=completion.episode_id,
                    template_id=material.template_id,
                    split=material.split,
                    view=view,
                    evidence_digest=case.evidence_digest,
                )
                assignments.append(assignment)
                binding = (
                    case,
                    material.pair_id,
                    material.task_id,
                    case.worker_bytes,
                )
                existing = case_bindings.get(case.evidence_digest)
                if existing is None:
                    case_bindings[case.evidence_digest] = binding
                elif existing != binding:
                    raise ValueError(
                        "evidence digest collides across unequal views or routing groups"
                    )
                evidence_digests.append((view, case.evidence_digest))
            completion_routes.append(
                _CompletionRoute(
                    episode_id=completion.episode_id,
                    completion_commitment=completion.panel.completion_commitment,
                    source_snapshot_digest=completion.panel.source_snapshot_digest,
                    evidence_digests=tuple(evidence_digests),
                )
            )
        routes.append(
            _PairRoute(
                pair_id=material.pair_id,
                template_id=material.template_id,
                split=material.split,
                manifest=material.manifest,
                completions=(completion_routes[0], completion_routes[1]),
            )
        )

    return Workspace100EvidenceViews(
        _routes=tuple(routes),
        _assignments=tuple(sorted(assignments, key=_assignment_sort_key)),
        cases=tuple(
            sorted(
                (binding[0] for binding in case_bindings.values()),
                key=_case_sort_key,
            )
        ),
    )


def _project_evidence(
    material: VerifiedPairMaterial,
    completion: VerifiedCompletionMaterial,
    view: ViewKind,
) -> PublicEvidenceEnvelope:
    baseline = completion.panel.receipt_for(())
    probes: tuple[ProbeObservation, ...] = ()
    interventions: tuple[InterventionObservation, ...] = ()
    if view is ViewKind.OWNER_PROBE:
        owner = completion.probe_for("workspace_owner")
        probes = (ProbeObservation(name=owner.name, value=owner.value),)
    elif view is ViewKind.EPOCH_PROBE:
        epoch_name = _epoch_probe_name(material.manifest)
        epoch = completion.probe_for(epoch_name)
        probes = (ProbeObservation(name=epoch.name, value=epoch.value),)
    elif view is ViewKind.REFRESH_RECEIPT:
        refresh_atom = _atom_for_target(material.manifest, "environment")
        receipt = completion.panel.receipt_for((refresh_atom,))
        interventions = (
            InterventionObservation(
                interventions=receipt.interventions,
                public_trace=receipt.artifact.public_trace,
                outcome=receipt.outcome,
            ),
        )
    elif view is not ViewKind.TRACE_ONLY:
        raise ValueError("evidence view is outside the frozen protocol")

    return PublicEvidenceEnvelope(
        Evidence(
            registry_digest=material.manifest.digest,
            coverage_manifest_digest=material.manifest.coverage_digest,
            public_trace=baseline.artifact.public_trace,
            outcome=baseline.outcome,
            probes=probes,
            intervention_observations=interventions,
        )
    )


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


def _validate_projection_materials(
    materials: tuple[VerifiedPairMaterial, ...],
) -> None:
    pair_ids: set[str] = set()
    task_ids: set[str] = set()
    episode_ids: set[str] = set()
    completion_commitments: set[str] = set()
    source_snapshots: set[str] = set()
    template_counts: Counter[TemplateId] = Counter()
    split_counts: Counter[Split] = Counter()
    for material in materials:
        material.validate()
        _validate_twin_material(material)
        if material.pair_id in pair_ids or material.task_id in task_ids:
            raise ValueError("evidence projection contains a duplicate pair or task")
        pair_ids.add(material.pair_id)
        task_ids.add(material.task_id)
        template_counts[material.template_id] += 1
        split_counts[material.split] += 1
        for completion in material.completions:
            if (
                completion.episode_id in episode_ids
                or completion.panel.completion_commitment in completion_commitments
                or completion.panel.source_snapshot_digest in source_snapshots
            ):
                raise ValueError("evidence projection contains a duplicate completion")
            episode_ids.add(completion.episode_id)
            completion_commitments.add(completion.panel.completion_commitment)
            source_snapshots.add(completion.panel.source_snapshot_digest)

    if template_counts != Counter(dict.fromkeys(TemplateId, 10)):
        raise ValueError("evidence projection does not contain ten pairs per template")
    if split_counts != Counter(
        {
            Split.DEVELOPMENT: 20,
            Split.VALIDATION: 10,
            Split.TEST: 20,
        }
    ):
        raise ValueError("evidence projection does not preserve the frozen grouped split")
    if (
        len(pair_ids) != _PAIR_COUNT
        or len(task_ids) != _PAIR_COUNT
        or len(episode_ids) != _COMPLETION_COUNT
        or len(completion_commitments) != _COMPLETION_COUNT
        or len(source_snapshots) != _COMPLETION_COUNT
    ):
        raise ValueError("evidence projection material cardinality is invalid")


def _validate_twin_material(material: VerifiedPairMaterial) -> None:
    left, right = material.completions
    left_baseline = left.panel.receipt_for(())
    right_baseline = right.panel.receipt_for(())
    if (
        left_baseline.outcome is not Outcome.FAILURE
        or right_baseline.outcome is not Outcome.FAILURE
        or left_baseline.artifact.public_trace != right_baseline.artifact.public_trace
    ):
        raise ValueError("causal twins must have one byte-identical failing baseline")

    owner_name = "workspace_owner"
    epoch_name = _epoch_probe_name(material.manifest)
    if left.probe_for(owner_name).value != right.probe_for(owner_name).value:
        raise ValueError("causal twins must share the neutral owner probe")
    if left.probe_for(epoch_name).value == right.probe_for(epoch_name).value:
        raise ValueError("causal twins must differ on the informative epoch probe")

    target_families = {
        left.panel.target_family,
        right.panel.target_family,
    }
    if target_families != {
        _ENVIRONMENT_TARGET_FAMILY,
        _POLICY_TARGET_FAMILY,
    }:
        raise ValueError("causal twins must balance environment and policy targets")

    refresh_atom = _atom_for_target(material.manifest, "environment")
    repair_atom = _atom_for_target(material.manifest, "policy")
    for completion in material.completions:
        target = completion.panel.target_family
        expected_witness = (
            (refresh_atom,) if target == _ENVIRONMENT_TARGET_FAMILY else (repair_atom,)
        )
        if completion.panel.minimal_witnesses != (expected_witness,):
            raise ValueError("causal twin target contradicts its minimal witness")
        refresh_outcome = completion.panel.receipt_for((refresh_atom,)).outcome
        repair_outcome = completion.panel.receipt_for((repair_atom,)).outcome
        expected_refresh = (
            Outcome.SUCCESS if target == _ENVIRONMENT_TARGET_FAMILY else Outcome.FAILURE
        )
        expected_repair = (
            Outcome.FAILURE if target == _ENVIRONMENT_TARGET_FAMILY else Outcome.SUCCESS
        )
        if (
            refresh_outcome is not expected_refresh
            or repair_outcome is not expected_repair
            or completion.panel.receipt_for(tuple(sorted((refresh_atom, repair_atom)))).outcome
            is not Outcome.SUCCESS
        ):
            raise ValueError("causal twin intervention matrix is invalid")


def _validate_case_view(case: PublicEvidenceCase) -> None:
    evidence = case.envelope.evidence
    template = _template_for(case.template_id)
    if evidence.outcome is not Outcome.FAILURE:
        raise ValueError("public evidence case baseline must fail")
    if case.view is ViewKind.TRACE_ONLY:
        expected_probes: tuple[ProbeObservation, ...] = ()
        expected_interventions: tuple[InterventionObservation, ...] = ()
    elif case.view is ViewKind.OWNER_PROBE:
        expected_probes = evidence.probes
        expected_interventions = ()
        if len(expected_probes) != 1 or expected_probes[0].name != "workspace_owner":
            raise ValueError("owner-probe case must expose only workspace_owner")
    elif case.view is ViewKind.EPOCH_PROBE:
        expected_probes = evidence.probes
        expected_interventions = ()
        if len(expected_probes) != 1 or expected_probes[0].name != template.epoch_probe:
            raise ValueError("epoch-probe case must expose only its template epoch")
    elif case.view is ViewKind.REFRESH_RECEIPT:
        expected_probes = ()
        expected_interventions = evidence.intervention_observations
        if len(expected_interventions) != 1 or expected_interventions[0].interventions != (
            template.refresh_atom,
        ):
            raise ValueError("refresh-receipt case must expose only its refresh atom")
    else:
        raise ValueError("public evidence case view is outside the frozen protocol")
    if (
        evidence.probes != expected_probes
        or evidence.intervention_observations != expected_interventions
    ):
        raise ValueError("public evidence case contains observations outside its view")


def _validate_evidence_view_types(views: Workspace100EvidenceViews) -> None:
    if (
        type(views._routes) is not tuple
        or len(views._routes) != _PAIR_COUNT
        or any(type(route) is not _PairRoute for route in views._routes)
    ):
        raise TypeError("Workspace-100 views require 50 exact pair routes")
    if (
        type(views._assignments) is not tuple
        or len(views._assignments) != _ASSIGNMENT_COUNT
        or any(type(assignment) is not _EvidenceAssignment for assignment in views._assignments)
    ):
        raise TypeError("Workspace-100 views require 400 exact assignments")
    if (
        type(views.cases) is not tuple
        or len(views.cases) != _EVIDENCE_CASE_COUNT
        or any(type(case) is not PublicEvidenceCase for case in views.cases)
    ):
        raise TypeError("Workspace-100 views require 300 exact evidence cases")


def _validate_evidence_view_order(views: Workspace100EvidenceViews) -> None:
    if views._routes != tuple(sorted(views._routes, key=_route_sort_key)):
        raise ValueError("Workspace-100 pair routes are not in canonical order")
    if views._assignments != tuple(sorted(views._assignments, key=_assignment_sort_key)):
        raise ValueError("Workspace-100 assignments are not in canonical order")
    if views.cases != tuple(sorted(views.cases, key=_case_sort_key)):
        raise ValueError("Workspace-100 evidence cases are not in canonical order")


def _validate_evidence_view_join(views: Workspace100EvidenceViews) -> None:
    cases_by_digest = _evidence_case_index(views)
    routes_by_pair, episode_routes = _routing_indexes(views)
    (
        routing_by_digest,
        assignments_by_digest,
        assignments_by_episode,
    ) = _assignment_join_indexes(
        views,
        cases_by_digest=cases_by_digest,
        routes_by_pair=routes_by_pair,
        episode_routes=episode_routes,
    )
    _validate_case_assignment_multiplicity(
        cases_by_digest,
        routing_by_digest=routing_by_digest,
        assignments_by_digest=assignments_by_digest,
    )
    _validate_episode_assignments(
        episode_routes,
        assignments_by_episode=assignments_by_episode,
    )


def _evidence_case_index(
    views: Workspace100EvidenceViews,
) -> dict[str, PublicEvidenceCase]:
    cases_by_digest = {case.evidence_digest: case for case in views.cases}
    if len(cases_by_digest) != len(views.cases):
        raise ValueError("Workspace-100 evidence cases contain duplicate digests")
    return cases_by_digest


def _routing_indexes(
    views: Workspace100EvidenceViews,
) -> tuple[
    dict[str, _PairRoute],
    dict[str, tuple[_PairRoute, _CompletionRoute]],
]:
    routes_by_pair = {route.pair_id: route for route in views._routes}
    routes_by_task = {route.task_id: route for route in views._routes}
    if len(routes_by_pair) != _PAIR_COUNT or len(routes_by_task) != _PAIR_COUNT:
        raise ValueError("Workspace-100 pair and task routing must be bijective")
    episode_routes: dict[str, tuple[_PairRoute, _CompletionRoute]] = {}
    for route in views._routes:
        for completion in route.completions:
            if completion.episode_id in episode_routes:
                raise ValueError("one episode appears in more than one pair route")
            episode_routes[completion.episode_id] = (route, completion)
    if len(episode_routes) != _COMPLETION_COUNT:
        raise ValueError("Workspace-100 pair routes must bind 100 unique episodes")
    return routes_by_pair, episode_routes


def _assignment_join_indexes(
    views: Workspace100EvidenceViews,
    *,
    cases_by_digest: dict[str, PublicEvidenceCase],
    routes_by_pair: dict[str, _PairRoute],
    episode_routes: dict[str, tuple[_PairRoute, _CompletionRoute]],
) -> tuple[
    defaultdict[str, set[tuple[str, str]]],
    Counter[str],
    defaultdict[str, list[_EvidenceAssignment]],
]:
    routing_by_digest: defaultdict[str, set[tuple[str, str]]] = defaultdict(set)
    assignment_keys: set[tuple[str, ViewKind]] = set()
    assignments_by_digest: Counter[str] = Counter()
    assignments_by_episode: defaultdict[str, list[_EvidenceAssignment]] = defaultdict(list)
    for assignment in views._assignments:
        case = cases_by_digest.get(assignment.evidence_digest)
        if case is None:
            raise ValueError("evidence assignment has no matching unique case")
        assignment_route = routes_by_pair.get(assignment.pair_id)
        episode_route = episode_routes.get(assignment.episode_id)
        if (
            assignment_route is None
            or episode_route is None
            or episode_route[0] is not assignment_route
        ):
            raise ValueError("evidence assignment contradicts its pair route")
        completion_route = episode_route[1]
        if (
            assignment.task_id != assignment_route.task_id
            or assignment.template_id is not assignment_route.template_id
            or assignment.split is not assignment_route.split
            or assignment.template_id is not case.template_id
            or assignment.split is not case.split
            or assignment.view is not case.view
        ):
            raise ValueError("evidence assignment metadata contradicts its route or case")
        if (
            case.envelope.evidence.registry_digest != assignment_route.manifest.digest
            or case.envelope.evidence.coverage_manifest_digest
            != assignment_route.manifest.coverage_digest
        ):
            raise ValueError("evidence case contradicts its routed registry")
        if completion_route.evidence_digest_for(assignment.view) != assignment.evidence_digest:
            raise ValueError("evidence assignment contradicts its completion route")
        routing_by_digest[assignment.evidence_digest].add((assignment.pair_id, assignment.task_id))
        key = (assignment.episode_id, assignment.view)
        if key in assignment_keys:
            raise ValueError("Workspace-100 contains a duplicate evidence assignment")
        assignment_keys.add(key)
        assignments_by_digest[assignment.evidence_digest] += 1
        assignments_by_episode[assignment.episode_id].append(assignment)
    return routing_by_digest, assignments_by_digest, assignments_by_episode


def _validate_case_assignment_multiplicity(
    cases_by_digest: dict[str, PublicEvidenceCase],
    *,
    routing_by_digest: defaultdict[str, set[tuple[str, str]]],
    assignments_by_digest: Counter[str],
) -> None:
    for digest, case in cases_by_digest.items():
        if len(routing_by_digest[digest]) != 1:
            raise ValueError("one evidence digest crosses pair or task routing groups")
        expected_assignments = (
            _PAIR_SIZE if case.view in {ViewKind.TRACE_ONLY, ViewKind.OWNER_PROBE} else 1
        )
        if assignments_by_digest[digest] != expected_assignments:
            raise ValueError("evidence case has the wrong assignment multiplicity")


def _validate_episode_assignments(
    episode_routes: dict[str, tuple[_PairRoute, _CompletionRoute]],
    *,
    assignments_by_episode: defaultdict[str, list[_EvidenceAssignment]],
) -> None:
    for episode_id, (route, _completion) in episode_routes.items():
        assignments = assignments_by_episode[episode_id]
        if (
            len(assignments) != _ASSIGNMENTS_PER_EPISODE
            or {assignment.view for assignment in assignments} != set(ViewKind)
            or any(
                (
                    assignment.pair_id,
                    assignment.task_id,
                    assignment.template_id,
                    assignment.split,
                )
                != (
                    route.pair_id,
                    route.task_id,
                    route.template_id,
                    route.split,
                )
                for assignment in assignments
            )
        ):
            raise ValueError("every routed episode must have one assignment for every view")


def _validate_evidence_view_counts(views: Workspace100EvidenceViews) -> None:
    assignment_view_counts = Counter(assignment.view for assignment in views._assignments)
    if assignment_view_counts != Counter(dict.fromkeys(ViewKind, 100)):
        raise ValueError("Workspace-100 must assign 100 episodes to every view")
    if Counter(case.view for case in views.cases) != Counter(_EXPECTED_CASES_BY_VIEW):
        raise ValueError("Workspace-100 unique-case view denominators are invalid")
    if Counter(case.template_id for case in views.cases) != Counter(
        dict.fromkeys(TemplateId, _CASES_PER_TEMPLATE)
    ):
        raise ValueError("Workspace-100 must contain 60 cases per template")
    if Counter(case.split for case in views.cases) != Counter(_EXPECTED_CASES_BY_SPLIT):
        raise ValueError("Workspace-100 unique-case split denominators are invalid")
    template_view_counts = Counter((case.template_id, case.view) for case in views.cases)
    expected_template_view_counts = Counter(
        {
            (template_id, view): (10 if view in {ViewKind.TRACE_ONLY, ViewKind.OWNER_PROBE} else 20)
            for template_id in TemplateId
            for view in ViewKind
        }
    )
    if template_view_counts != expected_template_view_counts:
        raise ValueError("Workspace-100 template-by-view denominators are invalid")

    episode_counts = Counter(assignment.episode_id for assignment in views._assignments)
    if len(episode_counts) != _COMPLETION_COUNT or set(episode_counts.values()) != {
        _ASSIGNMENTS_PER_EPISODE
    }:
        raise ValueError("every Workspace-100 episode must have four assignments")
    pair_counts = Counter(assignment.pair_id for assignment in views._assignments)
    if len(pair_counts) != _PAIR_COUNT or set(pair_counts.values()) != {_ASSIGNMENTS_PER_PAIR}:
        raise ValueError("every Workspace-100 pair must have eight assignments")
    digests_by_pair: defaultdict[str, set[str]] = defaultdict(set)
    for assignment in views._assignments:
        digests_by_pair[assignment.pair_id].add(assignment.evidence_digest)
    if any(len(digests) != _UNIQUE_CASES_PER_PAIR for digests in digests_by_pair.values()):
        raise ValueError("every Workspace-100 pair must project to six unique cases")


def _validate_no_private_leaks(views: Workspace100EvidenceViews) -> None:
    private_markers = tuple(
        marker.encode()
        for route in views._routes
        for marker in (
            route.pair_id,
            route.task_id,
            *route.episode_ids,
            *route.manifest.candidate_commitments,
            *route.source_snapshot_digests,
        )
    )
    for case in views.cases:
        for fragment, is_key in _visible_fragments(cast(object, case.envelope.to_payload())):
            folded = fragment.lower()
            if any(marker in fragment for marker in private_markers):
                raise ValueError("participant evidence contains a private routing value")
            if any(label in folded for label in _FORBIDDEN_PUBLIC_LABELS):
                raise ValueError("participant evidence contains a target or side label")
            if is_key and folded in _FORBIDDEN_PUBLIC_KEYS:
                raise ValueError("participant evidence contains a private field name")


def _visible_fragments(
    value: object,
    *,
    depth: int = 0,
) -> Iterator[tuple[bytes, bool]]:
    if depth > _MAX_LEAK_SCAN_DEPTH:
        raise ValueError("participant evidence exceeds the leak-scan depth bound")
    if type(value) is dict:
        for key, nested in cast(dict[object, object], value).items():
            key_bytes = str(key).encode()
            yield key_bytes, True
            if str(key).endswith("_hex") and type(nested) is str:
                try:
                    decoded = bytes.fromhex(nested)
                except ValueError as error:
                    raise ValueError(
                        "participant evidence contains invalid encoded bytes"
                    ) from error
                yield decoded, False
                yield from _decoded_json_fragments(decoded, depth=depth + 1)
            yield from _visible_fragments(nested, depth=depth + 1)
    elif type(value) in {tuple, list}:
        for nested in cast(tuple[object, ...] | list[object], value):
            yield from _visible_fragments(nested, depth=depth + 1)
    elif type(value) is str:
        yield value.encode(), False


def _decoded_json_fragments(
    payload: bytes,
    *,
    depth: int,
) -> Iterator[tuple[bytes, bool]]:
    try:
        decoded: object = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return
    except RecursionError as error:
        raise ValueError("participant evidence exceeds the decoded JSON depth bound") from error
    if type(decoded) in {dict, list}:
        yield from _visible_fragments(decoded, depth=depth)


def _epoch_probe_name(manifest: RegistryManifest) -> str:
    epoch_names = tuple(name for name in manifest.probe_names if name != "workspace_owner")
    if len(epoch_names) != 1 or "workspace_owner" not in manifest.probe_names:
        raise ValueError("Workspace-100 manifest must declare owner and epoch probes")
    return epoch_names[0]


def _atom_for_target(manifest: RegistryManifest, target: str) -> str:
    names = tuple(atom.name for atom in manifest.atoms if atom.target == target)
    if len(names) != 1:
        raise ValueError(f"Workspace-100 manifest must declare one {target} atom")
    return names[0]


def _route_sort_key(route: _PairRoute) -> tuple[int, str, str]:
    return (
        _TEMPLATE_RANK[route.template_id],
        route.task_id,
        route.pair_id,
    )


def _material_sort_key(
    material: VerifiedPairMaterial,
) -> tuple[int, str, str]:
    return (
        _TEMPLATE_RANK[material.template_id],
        material.task_id,
        material.pair_id,
    )


def _assignment_sort_key(
    assignment: _EvidenceAssignment,
) -> tuple[int, str, str, str, int, str]:
    return (
        _TEMPLATE_RANK[assignment.template_id],
        assignment.task_id,
        assignment.pair_id,
        assignment.episode_id,
        _VIEW_RANK[assignment.view],
        assignment.evidence_digest,
    )


def _case_sort_key(
    case: PublicEvidenceCase,
) -> tuple[int, int, str]:
    return (
        _VIEW_RANK[case.view],
        _TEMPLATE_RANK[case.template_id],
        case.evidence_digest,
    )


def _validate_manifest_template(
    manifest: RegistryManifest,
    template: TemplateRecord,
) -> None:
    expected_atoms = tuple(
        sorted(
            (
                (template.refresh_atom, "environment"),
                (template.repair_atom, "policy"),
            )
        )
    )
    expected_probe_names = tuple(sorted((template.epoch_probe, "workspace_owner")))
    expected_state_channels = tuple(sorted((template.selection_channel, template.resolver_channel)))
    if (
        manifest.task_schema_id != template.task_schema_id
        or not _is_opaque_id(manifest.task_id, "wgt")
        or manifest.source_format_id != SOURCE_FORMAT_ID
        or manifest.adapter_id != WORKSPACE100_ADAPTER_ID
        or tuple((atom.name, atom.target) for atom in manifest.atoms) != expected_atoms
        or manifest.probe_names != expected_probe_names
        or manifest.declared_state_channels != expected_state_channels
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
