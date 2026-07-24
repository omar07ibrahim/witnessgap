"""Private release truth for the Workspace-100 evaluation corpus.

Truth records live on the evaluator side of the protocol.  They bind public
evidence to independently pinned registries and sealed-source provenance, but
they are never part of a participant request.
"""

from __future__ import annotations

from dataclasses import dataclass

from witnessgap.canonical import JsonValue, canonical_digest
from witnessgap.identifiability import RegistryManifest
from witnessgap.trust import VerificationTrustAnchor
from witnessgap.workspace100.catalog import TEMPLATES
from witnessgap.workspace100.generation import GeneratedPair
from witnessgap.workspace100.records import (
    PROTOCOL_ID,
    SOURCE_FORMAT_ID,
    Split,
    TemplateId,
    TemplateRecord,
)
from witnessgap.workspace100.runtime import WORKSPACE100_ADAPTER_ID
from witnessgap.workspace100.views import ViewKind
from witnessgap.workspace100.views import _PairRoute as _EvidencePairRoute

_PAIR_SIZE = 2
_ID_DIGEST_CHARACTERS = 24
_SHA256_HEX_LENGTH = 64
_VIEW_ORDER = tuple(ViewKind)
_TRUTH_SOURCE_FORMAT = "witnessgap.workspace100-truth-source.v1"
_TRUTH_ROUTE_FORMAT = "witnessgap.workspace100-truth-route.v1"


@dataclass(frozen=True, slots=True)
class _TruthSourceBinding:
    """Private provenance and evidence routing for one sealed completion."""

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
            raise ValueError("truth source provenance must contain SHA-256 digests")
        if self.episode_id != _opaque_id("wge", self.completion_commitment):
            raise ValueError("truth source episode contradicts its completion commitment")
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
            raise TypeError("truth source must bind four exact evidence digests")
        if tuple(view for view, _digest in self.evidence_digests) != _VIEW_ORDER:
            raise ValueError("truth source evidence views are not in protocol order")
        if len({digest for _view, digest in self.evidence_digests}) != len(_VIEW_ORDER):
            raise ValueError("truth source evidence digests must be unique")

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
            "format": _TRUTH_SOURCE_FORMAT,
            "source_snapshot_digest": self.source_snapshot_digest,
        }


@dataclass(frozen=True, slots=True)
class _TruthPairRoute:
    """One externally anchored registry and its two exact source bindings."""

    pair_id: str
    task_id: str
    template_id: TemplateId
    split: Split
    manifest: RegistryManifest
    trust_anchor: VerificationTrustAnchor
    sources: tuple[_TruthSourceBinding, _TruthSourceBinding]

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if type(self.template_id) is not TemplateId:
            raise TypeError("truth route template_id must be exact")
        if type(self.split) is not Split:
            raise TypeError("truth route split must be exact")
        if type(self.manifest) is not RegistryManifest:
            raise TypeError("truth route manifest must be exact")
        if type(self.trust_anchor) is not VerificationTrustAnchor:
            raise TypeError("truth route trust anchor must be exact")
        _validate_manifest_round_trip(self.manifest)
        _validate_anchor_round_trip(self.trust_anchor)
        _validate_truth_route_identity(self)
        _validate_truth_route_sources(self)

    @property
    def digest(self) -> str:
        return canonical_digest(_TRUTH_ROUTE_FORMAT, self.root_payload())

    def root_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "format": _TRUTH_ROUTE_FORMAT,
            "manifest": self.manifest.to_payload(),
            "pair_id": self.pair_id,
            "protocol_id": PROTOCOL_ID,
            "sources": tuple(source.root_payload() for source in self.sources),
            "split": self.split.value,
            "task_id": self.task_id,
            "template_id": self.template_id.value,
            "trust_anchor": self.trust_anchor.to_payload(),
        }


def _validate_truth_route_identity(route: _TruthPairRoute) -> None:
    template = _template_for(route.template_id)
    if route.split is not template.split:
        raise ValueError("truth route split contradicts its frozen template")
    _validate_manifest_template(route.manifest, template)
    if (
        type(route.task_id) is not str
        or not _is_opaque_id(route.task_id, "wgt")
        or route.task_id != route.manifest.task_id
    ):
        raise ValueError("truth route task_id contradicts its manifest")
    if (
        route.trust_anchor.registry_digest != route.manifest.digest
        or route.trust_anchor.adapter_implementation_digest
        != route.manifest.adapter_implementation_digest
    ):
        raise ValueError("truth route anchor contradicts its registry manifest")


def _validate_truth_route_sources(route: _TruthPairRoute) -> None:
    if (
        type(route.sources) is not tuple
        or len(route.sources) != _PAIR_SIZE
        or any(type(source) is not _TruthSourceBinding for source in route.sources)
    ):
        raise TypeError("truth route must contain two exact source bindings")
    for source in route.sources:
        source.validate()
    commitments = tuple(source.completion_commitment for source in route.sources)
    if commitments != route.manifest.candidate_commitments:
        raise ValueError("truth route sources contradict its candidate manifest")
    if tuple(sorted(set(commitments))) != commitments:
        raise ValueError("truth route sources must be unique and commitment ordered")
    if len({source.episode_id for source in route.sources}) != _PAIR_SIZE:
        raise ValueError("truth route episode IDs must be unique")
    if len({source.source_snapshot_digest for source in route.sources}) != _PAIR_SIZE:
        raise ValueError("truth route source snapshots must be unique")
    if route.pair_id != _pair_id(commitments):
        raise ValueError("truth route pair_id contradicts its candidate commitments")


def _author_truth_route(
    pair: GeneratedPair,
    evidence_route: _EvidencePairRoute,
    trust_anchor: VerificationTrustAnchor,
) -> _TruthPairRoute:
    """Join one authored pair to its verified evidence route and external anchor."""

    if type(pair) is not GeneratedPair:
        raise TypeError("truth route authoring requires an exact GeneratedPair")
    if type(evidence_route) is not _EvidencePairRoute:
        raise TypeError("truth route authoring requires an exact evidence route")
    if type(trust_anchor) is not VerificationTrustAnchor:
        raise TypeError("truth route authoring requires an exact trust anchor")
    pair.validate()
    evidence_route.validate()
    if (
        pair.pair_id,
        pair.task_id,
        pair.template_id,
        pair.split,
    ) != (
        evidence_route.pair_id,
        evidence_route.task_id,
        evidence_route.template_id,
        evidence_route.split,
    ):
        raise ValueError("authored pair metadata contradicts its evidence route")

    sources: list[_TruthSourceBinding] = []
    for completion, routed in zip(
        pair.completions,
        evidence_route.completions,
        strict=True,
    ):
        if (
            completion.episode_id != routed.episode_id
            or completion.completion_commitment != routed.completion_commitment
            or completion.source.snapshot_digest != routed.source_snapshot_digest
        ):
            raise ValueError("authored source provenance contradicts its evidence route")
        sources.append(
            _TruthSourceBinding(
                episode_id=completion.episode_id,
                completion_commitment=completion.completion_commitment,
                source_snapshot_digest=completion.source.snapshot_digest,
                evidence_digests=routed.evidence_digests,
            )
        )
    return _TruthPairRoute(
        pair_id=pair.pair_id,
        task_id=pair.task_id,
        template_id=pair.template_id,
        split=pair.split,
        manifest=evidence_route.manifest,
        trust_anchor=trust_anchor,
        sources=(sources[0], sources[1]),
    )


def _validate_manifest_round_trip(manifest: RegistryManifest) -> None:
    try:
        manifest.validate()
        encoded = manifest.to_canonical_bytes()
        parsed = RegistryManifest.from_canonical_bytes(encoded)
    except (TypeError, ValueError) as error:
        raise ValueError("truth route manifest failed closed-schema validation") from error
    if parsed != manifest or parsed.to_canonical_bytes() != encoded:
        raise ValueError("truth route manifest failed canonical round-trip")


def _validate_anchor_round_trip(anchor: VerificationTrustAnchor) -> None:
    try:
        anchor.validate()
        encoded = anchor.to_canonical_bytes()
        parsed = VerificationTrustAnchor.from_canonical_bytes(encoded)
    except (TypeError, ValueError) as error:
        raise ValueError("truth route anchor failed closed-schema validation") from error
    if parsed != anchor or parsed.to_canonical_bytes() != encoded:
        raise ValueError("truth route anchor failed canonical round-trip")


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
    expected_probes = tuple(sorted((template.epoch_probe, "workspace_owner")))
    expected_channels = tuple(sorted((template.selection_channel, template.resolver_channel)))
    if (
        manifest.task_schema_id != template.task_schema_id
        or manifest.source_format_id != SOURCE_FORMAT_ID
        or manifest.adapter_id != WORKSPACE100_ADAPTER_ID
        or tuple((atom.name, atom.target) for atom in manifest.atoms) != expected_atoms
        or manifest.probe_names != expected_probes
        or manifest.declared_state_channels != expected_channels
    ):
        raise ValueError("truth route manifest contradicts its frozen template")


def _template_for(template_id: TemplateId) -> TemplateRecord:
    try:
        return next(template for template in TEMPLATES if template.template_id is template_id)
    except StopIteration as error:
        raise ValueError("truth route names an unknown frozen template") from error


def _pair_id(commitments: tuple[str, ...]) -> str:
    payload: dict[str, JsonValue] = {
        "completion_commitments": commitments,
        "format": "witnessgap.workspace100-pair.v1",
        "protocol_id": PROTOCOL_ID,
    }
    return _opaque_id(
        "wgp",
        canonical_digest("witnessgap.workspace100-pair.v1", payload),
    )


def _opaque_id(prefix: str, digest: str) -> str:
    return f"{prefix}_{digest[:_ID_DIGEST_CHARACTERS]}"


def _is_opaque_id(value: object, prefix: str) -> bool:
    if type(value) is not str:
        return False
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
