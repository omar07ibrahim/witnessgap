"""Private release truth for the Workspace-100 evaluation corpus.

Truth records live on the evaluator side of the protocol.  They bind public
evidence to independently pinned registries and sealed-source provenance, but
they are never part of a participant request.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import cast

from witnessgap.canonical import JsonValue, canonical_digest, canonical_json
from witnessgap.identifiability import (
    RegistryManifest,
    UnknownReason,
    VerdictKind,
)
from witnessgap.model import TargetFamily, Witness
from witnessgap.trust import VerificationTrustAnchor
from witnessgap.verifier import (
    VerifiedAttribution,
    VerifiedPanel,
    verifier_implementation_digest,
    verify_attribution_certificate,
    verify_registry_attributions,
    verify_source_panel,
)
from witnessgap.workspace100 import views as views_module
from witnessgap.workspace100.catalog import TEMPLATES
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
from witnessgap.workspace100.runtime import WORKSPACE100_ADAPTER_ID
from witnessgap.workspace100.views import (
    PublicEvidenceCase,
    ViewKind,
    Workspace100EvidenceViews,
    _EvidenceAssignment,
)
from witnessgap.workspace100.views import (
    _CompletionRoute as _EvidenceCompletionRoute,
)
from witnessgap.workspace100.views import _PairRoute as _EvidencePairRoute

_PAIR_COUNT = 50
_PAIR_SIZE = 2
_SOURCE_COUNT = 100
_CASE_COUNT = 300
_CASES_PER_PAIR = 6
_CASES_PER_TEMPLATE = 60
_PANEL_ROOT_COUNT = 150
_PANEL_ROOTS_PER_PAIR = 3
_ID_DIGEST_CHARACTERS = 24
_SHA256_HEX_LENGTH = 64
_VIEW_ORDER = tuple(ViewKind)
_VIEW_RANK = {view: index for index, view in enumerate(_VIEW_ORDER)}
_TEMPLATE_RANK = {template_id: index for index, template_id in enumerate(TemplateId)}
_AMBIGUOUS_VIEWS = frozenset((ViewKind.TRACE_ONLY, ViewKind.OWNER_PROBE))
_DECISIVE_VIEWS = frozenset((ViewKind.EPOCH_PROBE, ViewKind.REFRESH_RECEIPT))
_EXPECTED_CASES_BY_VIEW = Counter(
    {
        ViewKind.TRACE_ONLY: 50,
        ViewKind.OWNER_PROBE: 50,
        ViewKind.EPOCH_PROBE: 100,
        ViewKind.REFRESH_RECEIPT: 100,
    }
)
_EXPECTED_CASES_BY_SPLIT = Counter(
    {
        Split.DEVELOPMENT: 120,
        Split.VALIDATION: 60,
        Split.TEST: 120,
    }
)
_ENVIRONMENT_TARGET: TargetFamily = (("environment",),)
_POLICY_TARGET: TargetFamily = (("policy",),)
_TRUTH_SOURCE_FORMAT = "witnessgap.workspace100-truth-source.v1"
_TRUTH_ROUTE_FORMAT = "witnessgap.workspace100-truth-route.v1"
_TRUTH_ROUTE_SET_FORMAT = "witnessgap.workspace100-truth-route-set.v1"
_TRUTH_CASE_FORMAT = "witnessgap.workspace100-truth-case.v1"
_TRUTH_CERTIFICATE_SET_FORMAT = "witnessgap.workspace100-truth-certificates.v1"
_TRUTH_SET_FORMAT = "witnessgap.workspace100-truth-set.v1"


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


@dataclass(frozen=True, slots=True)
class TruthCaseRecord:
    """Private expected attribution for one participant-visible evidence case."""

    case_id: str
    pair_id: str
    task_id: str
    template_id: TemplateId
    split: Split
    view: ViewKind
    evidence_digest: str
    assignment_episode_ids: tuple[str, ...]
    route_digest: str
    public_case: PublicEvidenceCase
    certificate: VerifiedAttribution
    minimal_witnesses: tuple[Witness, ...] | None

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if self.case_id != _case_id(self.evidence_digest):
            raise ValueError("truth case_id contradicts its evidence digest")
        if not _is_opaque_id(self.pair_id, "wgp") or not _is_opaque_id(
            self.task_id,
            "wgt",
        ):
            raise ValueError("truth case routing IDs must be opaque")
        if type(self.template_id) is not TemplateId:
            raise TypeError("truth case template_id must be exact")
        if type(self.split) is not Split:
            raise TypeError("truth case split must be exact")
        if self.split is not _template_for(self.template_id).split:
            raise ValueError("truth case split contradicts its frozen template")
        if type(self.view) is not ViewKind:
            raise TypeError("truth case view must be exact")
        if not _is_sha256(self.evidence_digest) or not _is_sha256(self.route_digest):
            raise ValueError("truth case bindings must be SHA-256 digests")
        if type(self.public_case) is not PublicEvidenceCase:
            raise TypeError("truth case must contain one exact public evidence case")
        self.public_case.validate()
        if (
            self.public_case.template_id,
            self.public_case.split,
            self.public_case.view,
            self.public_case.evidence_digest,
        ) != (
            self.template_id,
            self.split,
            self.view,
            self.evidence_digest,
        ):
            raise ValueError("truth case metadata contradicts its public evidence")
        _validate_case_assignments(self)
        _validate_certificate_round_trip(self.certificate)
        if self.certificate.evidence_digest != self.evidence_digest:
            raise ValueError("truth case certificate contradicts its evidence digest")
        _validate_case_verdict_shape(self)

    @property
    def digest(self) -> str:
        return canonical_digest(_TRUTH_CASE_FORMAT, self.root_payload())

    def root_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "assignment_episode_ids": self.assignment_episode_ids,
            "case_id": self.case_id,
            "certificate": _canonical_object(self.certificate.to_canonical_bytes()),
            "evidence_digest": self.evidence_digest,
            "format": _TRUTH_CASE_FORMAT,
            "minimal_witnesses": self.minimal_witnesses,
            "pair_id": self.pair_id,
            "public_case": self.public_case.root_payload(),
            "route_digest": self.route_digest,
            "split": self.split.value,
            "task_id": self.task_id,
            "template_id": self.template_id.value,
            "view": self.view.value,
        }


@dataclass(frozen=True, slots=True)
class Workspace100TruthSet:
    """Closed private truth records for all 300 Workspace-100 cases."""

    corpus_root: str
    assignment_root: str
    evidence_root: str
    projection_root: str
    _routes: tuple[_TruthPairRoute, ...]
    cases: tuple[TruthCaseRecord, ...]

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        _validate_truth_set_types(self)
        for route in self._routes:
            route.validate()
        for case in self.cases:
            case.validate()
        _validate_truth_set_order(self)
        _validate_projection_binding(self)
        _validate_truth_set_routes(self)
        _validate_truth_set_cases(self)
        _validate_truth_set_counts(self)

    @property
    def route_root(self) -> str:
        return _route_root(self._routes)

    @property
    def certificate_root(self) -> str:
        return _certificate_root(self.cases)

    @property
    def truth_root(self) -> str:
        return _truth_root(
            self,
            route_root=_route_root(self._routes),
            certificate_root=_certificate_root(self.cases),
        )


def build_workspace100_truth(
    corpus: Workspace100Corpus,
    views: Workspace100EvidenceViews,
    *,
    trust_anchors: tuple[VerificationTrustAnchor, ...],
) -> Workspace100TruthSet:
    """Replay every source and issue truth using only caller-pinned anchors."""

    if type(corpus) is not Workspace100Corpus:
        raise TypeError("truth authoring requires an exact Workspace100Corpus")
    if type(views) is not Workspace100EvidenceViews:
        raise TypeError("truth authoring requires exact Workspace100EvidenceViews")
    corpus.validate()
    views.validate()
    anchors_by_registry = _normalize_anchor_collection(trust_anchors, views)
    pairs_by_id = {pair.pair_id: pair for pair in corpus.pairs}
    evidence_routes_by_id = {route.pair_id: route for route in views._routes}
    if set(pairs_by_id) != set(evidence_routes_by_id):
        raise ValueError("truth corpus and evidence routes name different pair sets")

    routes = tuple(
        sorted(
            (
                _author_truth_route(
                    pair,
                    evidence_routes_by_id[pair.pair_id],
                    anchors_by_registry[evidence_routes_by_id[pair.pair_id].manifest.digest],
                )
                for pair in corpus.pairs
            ),
            key=_truth_route_sort_key,
        )
    )
    cases_by_digest = {case.evidence_digest: case for case in views.cases}
    assignments_by_digest = _assignments_by_evidence(views)
    authored_cases: list[TruthCaseRecord] = []
    for route in routes:
        pair = pairs_by_id[route.pair_id]
        pair_cases = _public_cases_for_route(route, cases_by_digest)
        panels = {
            completion.completion_commitment: verify_source_panel(
                completion.source,
                manifest=route.manifest,
            )
            for completion in pair.completions
        }
        certificates = verify_registry_attributions(
            tuple(completion.source for completion in pair.completions),
            manifest=route.manifest,
            trust_anchor=route.trust_anchor,
            evidences=tuple(case.envelope.evidence for case in pair_cases),
        )
        authored_cases.extend(
            _author_truth_case(
                case,
                route=route,
                certificate=certificate,
                panels=panels,
                assignment_episode_ids=assignments_by_digest[case.evidence_digest],
            )
            for case, certificate in zip(pair_cases, certificates, strict=True)
        )

    return Workspace100TruthSet(
        corpus_root=corpus.root,
        assignment_root=views.assignment_root,
        evidence_root=views.evidence_root,
        projection_root=views.projection_root,
        _routes=routes,
        cases=tuple(sorted(authored_cases, key=_truth_case_sort_key)),
    )


def _author_truth_case(
    case: PublicEvidenceCase,
    *,
    route: _TruthPairRoute,
    certificate: VerifiedAttribution,
    panels: dict[str, VerifiedPanel],
    assignment_episode_ids: tuple[str, ...],
) -> TruthCaseRecord:
    expected_sources = tuple(
        source
        for source in route.sources
        if source.evidence_digest_for(case.view) == case.evidence_digest
    )
    expected_episode_ids = tuple(source.episode_id for source in expected_sources)
    if assignment_episode_ids != expected_episode_ids:
        raise ValueError("public evidence assignments contradict the private truth route")
    minimal_witnesses = (
        None
        if case.view in _AMBIGUOUS_VIEWS
        else panels[expected_sources[0].completion_commitment].minimal_witnesses
    )
    return TruthCaseRecord(
        case_id=_case_id(case.evidence_digest),
        pair_id=route.pair_id,
        task_id=route.task_id,
        template_id=case.template_id,
        split=case.split,
        view=case.view,
        evidence_digest=case.evidence_digest,
        assignment_episode_ids=assignment_episode_ids,
        route_digest=route.digest,
        public_case=case,
        certificate=certificate,
        minimal_witnesses=minimal_witnesses,
    )


def _normalize_anchor_collection(
    anchors: object,
    views: Workspace100EvidenceViews,
) -> dict[str, VerificationTrustAnchor]:
    if (
        type(anchors) is not tuple
        or len(anchors) != _PAIR_COUNT
        or any(type(anchor) is not VerificationTrustAnchor for anchor in anchors)
    ):
        raise TypeError("truth authoring requires exactly 50 exact trust anchors")
    normalized: list[VerificationTrustAnchor] = []
    for anchor in anchors:
        _validate_anchor_round_trip(anchor)
        normalized.append(VerificationTrustAnchor.from_canonical_bytes(anchor.to_canonical_bytes()))
    anchors_by_registry = {anchor.registry_digest: anchor for anchor in normalized}
    if len(anchors_by_registry) != _PAIR_COUNT:
        raise ValueError("truth trust anchors must have unique registry digests")
    expected_registries = {route.manifest.digest for route in views._routes}
    if set(anchors_by_registry) != expected_registries:
        raise ValueError("truth trust anchors do not exhaust the evidence registries")
    current_verifier = verifier_implementation_digest()
    if any(
        anchor.verifier_implementation_digest != current_verifier
        for anchor in anchors_by_registry.values()
    ):
        raise ValueError("truth trust anchor differs from the installed verifier")
    return anchors_by_registry


def _assignments_by_evidence(
    views: Workspace100EvidenceViews,
) -> dict[str, tuple[str, ...]]:
    grouped: defaultdict[str, list[str]] = defaultdict(list)
    for assignment in views._assignments:
        grouped[assignment.evidence_digest].append(assignment.episode_id)
    routes_by_episode = {
        source.episode_id: (route, index)
        for route in views._routes
        for index, source in enumerate(route.completions)
    }
    return {
        digest: tuple(
            sorted(
                episode_ids,
                key=lambda episode_id: (
                    routes_by_episode[episode_id][0].pair_id,
                    routes_by_episode[episode_id][1],
                ),
            )
        )
        for digest, episode_ids in grouped.items()
    }


def _public_cases_for_route(
    route: _TruthPairRoute,
    cases_by_digest: dict[str, PublicEvidenceCase],
) -> tuple[PublicEvidenceCase, ...]:
    digests = {digest for source in route.sources for _view, digest in source.evidence_digests}
    if len(digests) != _CASES_PER_PAIR:
        raise ValueError("every truth route must bind exactly six unique evidence cases")
    try:
        cases = tuple(cases_by_digest[digest] for digest in digests)
    except KeyError as error:
        raise ValueError("truth route names an unavailable public evidence case") from error
    return tuple(sorted(cases, key=_public_case_sort_key))


def _validate_case_assignments(case: TruthCaseRecord) -> None:
    expected_count = _PAIR_SIZE if case.view in _AMBIGUOUS_VIEWS else 1
    if (
        type(case.assignment_episode_ids) is not tuple
        or len(case.assignment_episode_ids) != expected_count
        or any(not _is_opaque_id(episode_id, "wge") for episode_id in case.assignment_episode_ids)
        or len(set(case.assignment_episode_ids)) != expected_count
    ):
        raise ValueError("truth case has invalid assignment episode IDs")


def _validate_certificate_round_trip(certificate: object) -> None:
    if type(certificate) is not VerifiedAttribution:
        raise TypeError("truth case certificate must be exact")
    try:
        encoded = certificate.to_canonical_bytes()
        parsed = VerifiedAttribution.from_canonical_bytes(encoded)
    except (TypeError, ValueError) as error:
        raise ValueError("truth case certificate failed closed-schema validation") from error
    if parsed != certificate or parsed.to_canonical_bytes() != encoded:
        raise ValueError("truth case certificate failed canonical round-trip")


def _validate_case_verdict_shape(case: TruthCaseRecord) -> None:
    certificate = case.certificate
    if case.view in _AMBIGUOUS_VIEWS:
        if (
            certificate.kind is not VerdictKind.NOT_IDENTIFIABLE
            or certificate.unknown_reason is not UnknownReason.AMBIGUOUS_WORLDS
            or certificate.target_family is not None
            or case.minimal_witnesses is not None
        ):
            raise ValueError("ambiguous truth case has an identified verdict or witnesses")
        return
    if case.view not in _DECISIVE_VIEWS:
        raise ValueError("truth case view is outside the frozen protocol")
    if (
        certificate.kind is not VerdictKind.IDENTIFIED_SINGLETON
        or certificate.target_family not in {_ENVIRONMENT_TARGET, _POLICY_TARGET}
        or certificate.unknown_reason is not None
    ):
        raise ValueError("decisive truth case does not contain one singleton target")
    _validate_minimal_witnesses(case.minimal_witnesses)


def _validate_minimal_witnesses(witnesses: object) -> None:
    if (
        type(witnesses) is not tuple
        or len(witnesses) != 1
        or type(witnesses[0]) is not tuple
        or len(witnesses[0]) != 1
        or type(witnesses[0][0]) is not str
    ):
        raise ValueError("identified truth case must contain one singleton minimal witness")


def _validate_truth_set_types(truth: Workspace100TruthSet) -> None:
    for field_name, digest in (
        ("corpus_root", truth.corpus_root),
        ("assignment_root", truth.assignment_root),
        ("evidence_root", truth.evidence_root),
        ("projection_root", truth.projection_root),
    ):
        if not _is_sha256(digest):
            raise ValueError(f"truth set {field_name} must be a lowercase SHA-256 digest")
    if (
        type(truth._routes) is not tuple
        or len(truth._routes) != _PAIR_COUNT
        or any(type(route) is not _TruthPairRoute for route in truth._routes)
    ):
        raise TypeError("Workspace-100 truth requires 50 exact routes")
    if (
        type(truth.cases) is not tuple
        or len(truth.cases) != _CASE_COUNT
        or any(type(case) is not TruthCaseRecord for case in truth.cases)
    ):
        raise TypeError("Workspace-100 truth requires 300 exact cases")


def _validate_truth_set_order(truth: Workspace100TruthSet) -> None:
    if truth._routes != tuple(sorted(truth._routes, key=_truth_route_sort_key)):
        raise ValueError("Workspace-100 truth routes are not in canonical order")
    if truth.cases != tuple(sorted(truth.cases, key=_truth_case_sort_key)):
        raise ValueError("Workspace-100 truth cases are not in canonical order")


def _validate_projection_binding(truth: Workspace100TruthSet) -> None:
    public_views = _reconstruct_public_views(truth)
    reconstructed_assignment_root = views_module._assignment_root(public_views)
    reconstructed_evidence_root = views_module._evidence_root(public_views)
    if truth.assignment_root != reconstructed_assignment_root:
        raise ValueError("truth assignment root contradicts its private routing records")
    if truth.evidence_root != reconstructed_evidence_root:
        raise ValueError("truth evidence root contradicts its public evidence records")
    payload: dict[str, JsonValue] = {
        "assignment_root": truth.assignment_root,
        "evidence_root": truth.evidence_root,
        "format": "witnessgap.workspace100-evidence-projection.v1",
        "protocol_id": PROTOCOL_ID,
    }
    expected = canonical_digest(
        "witnessgap.workspace100-evidence-projection.v1",
        payload,
    )
    if truth.projection_root != expected:
        raise ValueError("truth projection root contradicts its assignment and evidence roots")


def _reconstruct_public_views(
    truth: Workspace100TruthSet,
) -> Workspace100EvidenceViews:
    evidence_routes: list[_EvidencePairRoute] = []
    for route in truth._routes:
        completions = tuple(
            _EvidenceCompletionRoute(
                episode_id=source.episode_id,
                completion_commitment=source.completion_commitment,
                source_snapshot_digest=source.source_snapshot_digest,
                evidence_digests=source.evidence_digests,
            )
            for source in route.sources
        )
        evidence_routes.append(
            _EvidencePairRoute(
                pair_id=route.pair_id,
                template_id=route.template_id,
                split=route.split,
                manifest=route.manifest,
                completions=(completions[0], completions[1]),
            )
        )

    assignments = [
        _EvidenceAssignment(
            pair_id=case.pair_id,
            task_id=case.task_id,
            episode_id=episode_id,
            template_id=case.template_id,
            split=case.split,
            view=case.view,
            evidence_digest=case.evidence_digest,
        )
        for case in truth.cases
        for episode_id in case.assignment_episode_ids
    ]
    return Workspace100EvidenceViews(
        _routes=tuple(evidence_routes),
        _assignments=tuple(
            sorted(
                assignments,
                key=lambda assignment: (
                    _TEMPLATE_RANK[assignment.template_id],
                    assignment.task_id,
                    assignment.pair_id,
                    assignment.episode_id,
                    _VIEW_RANK[assignment.view],
                    assignment.evidence_digest,
                ),
            )
        ),
        cases=tuple(case.public_case for case in truth.cases),
    )


def _validate_truth_set_routes(truth: Workspace100TruthSet) -> None:
    pair_ids = tuple(route.pair_id for route in truth._routes)
    task_ids = tuple(route.task_id for route in truth._routes)
    registry_digests = tuple(route.manifest.digest for route in truth._routes)
    anchor_digests = tuple(route.trust_anchor.digest for route in truth._routes)
    sources = tuple(source for route in truth._routes for source in route.sources)
    unique_collections: tuple[tuple[str, tuple[str, ...]], ...] = (
        ("pair IDs", pair_ids),
        ("task IDs", task_ids),
        ("registry digests", registry_digests),
        ("trust anchors", anchor_digests),
        ("episode IDs", tuple(source.episode_id for source in sources)),
        (
            "completion commitments",
            tuple(source.completion_commitment for source in sources),
        ),
        (
            "source snapshots",
            tuple(source.source_snapshot_digest for source in sources),
        ),
    )
    for label, values in unique_collections:
        if len(set(values)) != len(values):
            raise ValueError(f"Workspace-100 truth contains duplicate {label}")
    if len(sources) != _SOURCE_COUNT:
        raise ValueError("Workspace-100 truth must bind exactly 100 sources")


def _validate_truth_set_cases(truth: Workspace100TruthSet) -> None:
    routes_by_pair = {route.pair_id: route for route in truth._routes}
    for case in truth.cases:
        route = routes_by_pair.get(case.pair_id)
        if route is None:
            raise ValueError("truth case has no matching pair route")
        if (
            case.task_id,
            case.template_id,
            case.split,
            case.route_digest,
        ) != (
            route.task_id,
            route.template_id,
            route.split,
            route.digest,
        ):
            raise ValueError("truth case metadata contradicts its pair route")
        expected_sources = tuple(
            source
            for source in route.sources
            if source.evidence_digest_for(case.view) == case.evidence_digest
        )
        expected_episode_ids = tuple(source.episode_id for source in expected_sources)
        if case.assignment_episode_ids != expected_episode_ids:
            raise ValueError("truth case assignments contradict its routed evidence")
        expected_commitments = tuple(source.completion_commitment for source in expected_sources)
        if case.certificate.compatible_completion_commitments != expected_commitments:
            raise ValueError("truth certificate compatibility contradicts its assignments")
        if case.certificate.registry_digest != route.manifest.digest:
            raise ValueError("truth certificate registry contradicts its pair route")
        verify_attribution_certificate(
            case.certificate.to_canonical_bytes(),
            trust_anchor=route.trust_anchor,
            expected_proof_root=case.certificate.proof_root,
        )
        _validate_routed_verdict(case, route, expected_sources)


def _validate_routed_verdict(
    case: TruthCaseRecord,
    route: _TruthPairRoute,
    expected_sources: tuple[_TruthSourceBinding, ...],
) -> None:
    certificate = case.certificate
    if case.view in _AMBIGUOUS_VIEWS:
        expected_commitments = tuple(source.completion_commitment for source in route.sources)
        if (
            len(expected_sources) != _PAIR_SIZE
            or certificate.ambiguity_commitments != expected_commitments
            or certificate.compatible_completion_commitments != expected_commitments
        ):
            raise ValueError("ambiguous truth certificate contradicts its twin route")
        return
    if len(expected_sources) != 1 or certificate.target_family is None:
        raise ValueError("decisive truth certificate does not select one routed source")
    target = certificate.target_family[0][0]
    matching_atoms = tuple(atom.name for atom in route.manifest.atoms if atom.target == target)
    if len(matching_atoms) != 1 or case.minimal_witnesses != ((matching_atoms[0],),):
        raise ValueError("truth case minimal witness contradicts its verified target")


def _validate_truth_set_counts(truth: Workspace100TruthSet) -> None:
    case_ids = tuple(case.case_id for case in truth.cases)
    evidence_digests = tuple(case.evidence_digest for case in truth.cases)
    proof_roots = tuple(case.certificate.proof_root for case in truth.cases)
    for label, values in (
        ("case IDs", case_ids),
        ("evidence digests", evidence_digests),
        ("certificate proof roots", proof_roots),
    ):
        if len(set(values)) != _CASE_COUNT:
            raise ValueError(f"Workspace-100 truth must contain 300 unique {label}")
    if Counter(case.view for case in truth.cases) != _EXPECTED_CASES_BY_VIEW:
        raise ValueError("Workspace-100 truth has invalid view denominators")
    if Counter(case.split for case in truth.cases) != _EXPECTED_CASES_BY_SPLIT:
        raise ValueError("Workspace-100 truth has invalid split denominators")
    if Counter(case.template_id for case in truth.cases) != Counter(
        dict.fromkeys(TemplateId, _CASES_PER_TEMPLATE)
    ):
        raise ValueError("Workspace-100 truth must contain 60 cases per template")
    if Counter(case.certificate.kind for case in truth.cases) != Counter(
        {
            VerdictKind.NOT_IDENTIFIABLE: 100,
            VerdictKind.IDENTIFIED_SINGLETON: 200,
        }
    ):
        raise ValueError("Workspace-100 truth has invalid verdict denominators")
    if Counter(case.certificate.target_family for case in truth.cases) != Counter(
        {
            None: 100,
            _ENVIRONMENT_TARGET: 100,
            _POLICY_TARGET: 100,
        }
    ):
        raise ValueError("Workspace-100 truth does not balance causal targets")
    _validate_per_pair_counts(truth)
    _validate_certificate_multiplicities(truth)


def _validate_per_pair_counts(truth: Workspace100TruthSet) -> None:
    cases_by_pair: defaultdict[str, list[TruthCaseRecord]] = defaultdict(list)
    for case in truth.cases:
        cases_by_pair[case.pair_id].append(case)
    if len(cases_by_pair) != _PAIR_COUNT:
        raise ValueError("Workspace-100 truth must cover exactly 50 pairs")
    for cases in cases_by_pair.values():
        if (
            len(cases) != _CASES_PER_PAIR
            or Counter(case.view for case in cases)
            != Counter(
                {
                    ViewKind.TRACE_ONLY: 1,
                    ViewKind.OWNER_PROBE: 1,
                    ViewKind.EPOCH_PROBE: 2,
                    ViewKind.REFRESH_RECEIPT: 2,
                }
            )
            or Counter(case.certificate.target_family for case in cases)
            != Counter(
                {
                    None: 2,
                    _ENVIRONMENT_TARGET: 2,
                    _POLICY_TARGET: 2,
                }
            )
            or len({case.certificate.panel_root for case in cases}) != _PANEL_ROOTS_PER_PAIR
        ):
            raise ValueError("every truth pair must contain its frozen six-case matrix")


def _validate_certificate_multiplicities(truth: Workspace100TruthSet) -> None:
    panel_roots = Counter(case.certificate.panel_root for case in truth.cases)
    if len(panel_roots) != _PANEL_ROOT_COUNT or set(panel_roots.values()) != {_PAIR_SIZE}:
        raise ValueError("Workspace-100 truth must contain 150 twice-used panel roots")
    commitment_references = Counter(
        commitment
        for case in truth.cases
        for commitment in case.certificate.compatible_completion_commitments
    )
    if len(commitment_references) != _SOURCE_COUNT or set(commitment_references.values()) != {4}:
        raise ValueError("every truth completion must appear in four certificates")
    if Counter(
        len(case.certificate.compatible_completion_commitments) for case in truth.cases
    ) != Counter({1: 200, _PAIR_SIZE: 100}):
        raise ValueError("Workspace-100 truth has invalid compatibility denominators")
    if Counter(case.minimal_witnesses is None for case in truth.cases) != Counter(
        {True: 100, False: 200}
    ):
        raise ValueError("Workspace-100 truth has invalid witness denominators")


def _route_root(routes: tuple[_TruthPairRoute, ...]) -> str:
    payload: dict[str, JsonValue] = {
        "format": _TRUTH_ROUTE_SET_FORMAT,
        "protocol_id": PROTOCOL_ID,
        "routes": tuple(route.root_payload() for route in routes),
    }
    return canonical_digest(_TRUTH_ROUTE_SET_FORMAT, payload)


def _certificate_root(cases: tuple[TruthCaseRecord, ...]) -> str:
    payload: dict[str, JsonValue] = {
        "cases": tuple(case.root_payload() for case in cases),
        "format": _TRUTH_CERTIFICATE_SET_FORMAT,
        "protocol_id": PROTOCOL_ID,
    }
    return canonical_digest(_TRUTH_CERTIFICATE_SET_FORMAT, payload)


def _truth_root(
    truth: Workspace100TruthSet,
    *,
    route_root: str,
    certificate_root: str,
) -> str:
    payload: dict[str, JsonValue] = {
        "assignment_root": truth.assignment_root,
        "certificate_root": certificate_root,
        "corpus_root": truth.corpus_root,
        "evidence_root": truth.evidence_root,
        "format": _TRUTH_SET_FORMAT,
        "projection_root": truth.projection_root,
        "protocol_id": PROTOCOL_ID,
        "route_root": route_root,
    }
    return canonical_digest(_TRUTH_SET_FORMAT, payload)


def _truth_route_sort_key(route: _TruthPairRoute) -> tuple[int, str, str]:
    return (
        _TEMPLATE_RANK[route.template_id],
        route.task_id,
        route.pair_id,
    )


def _public_case_sort_key(case: PublicEvidenceCase) -> tuple[int, int, str]:
    return (
        _VIEW_RANK[case.view],
        _TEMPLATE_RANK[case.template_id],
        case.evidence_digest,
    )


def _truth_case_sort_key(case: TruthCaseRecord) -> tuple[int, int, str]:
    return (
        _VIEW_RANK[case.view],
        _TEMPLATE_RANK[case.template_id],
        case.evidence_digest,
    )


def _case_id(evidence_digest: str) -> str:
    if not _is_sha256(evidence_digest):
        raise ValueError("truth case evidence digest must be lowercase SHA-256")
    return _opaque_id("wgc", evidence_digest)


def _canonical_object(payload: bytes) -> JsonValue:
    try:
        raw: object = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("nested truth record is not valid UTF-8 JSON") from error
    try:
        canonical = type(raw) is dict and canonical_json(cast(JsonValue, raw)) == payload
    except TypeError as error:
        raise ValueError("nested truth record contains unsupported JSON") from error
    if not canonical:
        raise ValueError("nested truth record is not one canonical JSON object")
    return cast(JsonValue, raw)


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
