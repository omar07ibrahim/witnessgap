from __future__ import annotations

from collections import Counter
from dataclasses import replace

import pytest

from witnessgap.identifiability import UnknownReason, VerdictKind
from witnessgap.model import TargetFamily
from witnessgap.trust import VerificationTrustAnchor
from witnessgap.verifier import (
    trust_anchor_for_manifest,
    verify_attribution_certificate,
)
from witnessgap.workspace100 import truth as truth_module
from witnessgap.workspace100.generation import Workspace100Corpus, generate_workspace100
from witnessgap.workspace100.records import Split, TemplateId
from witnessgap.workspace100.truth import (
    Workspace100TruthSet,
    build_workspace100_truth,
)
from witnessgap.workspace100.views import (
    ViewKind,
    Workspace100EvidenceViews,
    build_workspace100_evidence_views,
)

_SEED = bytes.fromhex("713d96c0fcadb930599f4f4370df3484766872ac406f1c26c5a360a996f29ec5")
_SHA256_HEX_LENGTH = 64
_PAIR_COUNT = 50
_SOURCE_COUNT = 100
_CASE_COUNT = 300
_PANEL_ROOT_COUNT = 150
_ENVIRONMENT_TARGET: TargetFamily = (("environment",),)
_POLICY_TARGET: TargetFamily = (("policy",),)
_EXPECTED_CORPUS_ROOT = "01d062caee7878056e8965ebb7766552b38dd442b60ca64f3893fa83cd844a93"
_EXPECTED_ASSIGNMENT_ROOT = "6a82d84186e25b6df926ac481f40a58d7808bc49ca7deb4e1a6bfab1aad1c454"
_EXPECTED_EVIDENCE_ROOT = "4f5ed5eac99d3bf4eaedcafa3bbc019c06debba6372b4935dd57c6f09c9f3d71"
_EXPECTED_PROJECTION_ROOT = "2b99bac2b2f914a06e33b87caab3959bcb5c4017496dd747f2dedec36e0b4776"
_EXPECTED_ROUTE_ROOT = "791f4d94941422c439bda3d30b835615e1938556e92ca16cf3e2ec36b7bcb6f4"
_EXPECTED_CERTIFICATE_ROOT = "66fbfc15bd120c5f4690b54f5ea16d7a11c3ba60578073bb2538eefed26c2089"
_EXPECTED_TRUTH_ROOT = "c66543a10c7cdd7f09d0b3b27807ac3290060c5929b5ab411fd795fc874681f9"


@pytest.fixture(scope="module")
def corpus() -> Workspace100Corpus:
    return generate_workspace100(_SEED)


@pytest.fixture(scope="module")
def evidence_views(corpus: Workspace100Corpus) -> Workspace100EvidenceViews:
    return build_workspace100_evidence_views(corpus)


@pytest.fixture(scope="module")
def trust_anchors(
    evidence_views: Workspace100EvidenceViews,
) -> tuple[VerificationTrustAnchor, ...]:
    return tuple(trust_anchor_for_manifest(route.manifest) for route in evidence_views._routes)


@pytest.fixture(scope="module")
def truth_set(
    corpus: Workspace100Corpus,
    evidence_views: Workspace100EvidenceViews,
    trust_anchors: tuple[VerificationTrustAnchor, ...],
) -> Workspace100TruthSet:
    worker_bytes = tuple(case.worker_bytes for case in evidence_views.cases)
    public_roots = (
        evidence_views.assignment_root,
        evidence_views.evidence_root,
        evidence_views.projection_root,
    )
    truth = build_workspace100_truth(
        corpus,
        evidence_views,
        trust_anchors=tuple(reversed(trust_anchors)),
    )
    assert tuple(case.worker_bytes for case in evidence_views.cases) == worker_bytes
    assert (
        evidence_views.assignment_root,
        evidence_views.evidence_root,
        evidence_views.projection_root,
    ) == public_roots
    return truth


def test_truth_route_binds_external_anchor_and_exact_source_provenance(
    corpus: Workspace100Corpus,
    evidence_views: Workspace100EvidenceViews,
) -> None:
    pair = corpus.pairs[0]
    evidence_route = next(
        route for route in evidence_views._routes if route.pair_id == pair.pair_id
    )
    anchor = trust_anchor_for_manifest(evidence_route.manifest)

    route = truth_module._author_truth_route(pair, evidence_route, anchor)

    assert route.pair_id == pair.pair_id
    assert route.task_id == pair.task_id
    assert route.manifest == evidence_route.manifest
    assert route.trust_anchor is anchor
    assert tuple(source.episode_id for source in route.sources) == tuple(
        completion.episode_id for completion in pair.completions
    )
    assert tuple(source.completion_commitment for source in route.sources) == tuple(
        completion.completion_commitment for completion in pair.completions
    )
    assert tuple(source.source_snapshot_digest for source in route.sources) == tuple(
        completion.source.snapshot_digest for completion in pair.completions
    )
    assert all(
        source.evidence_digests == routed.evidence_digests
        for source, routed in zip(route.sources, evidence_route.completions, strict=True)
    )
    assert len(route.digest) == _SHA256_HEX_LENGTH
    assert (
        route.digest
        == truth_module._author_truth_route(
            pair,
            evidence_route,
            anchor,
        ).digest
    )


def test_truth_route_rejects_registry_anchor_and_source_transplants(
    corpus: Workspace100Corpus,
    evidence_views: Workspace100EvidenceViews,
) -> None:
    first_pair, second_pair = corpus.pairs[:2]
    routes_by_pair = {route.pair_id: route for route in evidence_views._routes}
    first_route = routes_by_pair[first_pair.pair_id]
    second_route = routes_by_pair[second_pair.pair_id]
    first_anchor = trust_anchor_for_manifest(first_route.manifest)
    second_anchor = trust_anchor_for_manifest(second_route.manifest)

    with pytest.raises(ValueError, match="anchor contradicts"):
        truth_module._author_truth_route(first_pair, first_route, second_anchor)
    with pytest.raises(ValueError, match="metadata contradicts"):
        truth_module._author_truth_route(second_pair, first_route, first_anchor)

    route = truth_module._author_truth_route(first_pair, first_route, first_anchor)
    with pytest.raises(ValueError, match="episode contradicts"):
        replace(
            route.sources[0],
            completion_commitment=route.sources[1].completion_commitment,
        )
    forged_source = replace(
        route.sources[0],
        source_snapshot_digest=route.sources[1].source_snapshot_digest,
    )
    with pytest.raises(ValueError, match="source snapshots must be unique"):
        replace(route, sources=(forged_source, route.sources[1]))


def test_truth_route_payload_excludes_openings_panels_and_search_labels(
    corpus: Workspace100Corpus,
    evidence_views: Workspace100EvidenceViews,
) -> None:
    pair = corpus.pairs[0]
    evidence_route = next(
        route for route in evidence_views._routes if route.pair_id == pair.pair_id
    )
    route = truth_module._author_truth_route(
        pair,
        evidence_route,
        trust_anchor_for_manifest(evidence_route.manifest),
    )
    payload = repr(route.root_payload()).casefold()

    for forbidden in (
        "commitment_salt",
        "minimal_witnesses",
        "probe_receipt",
        "repairpanel",
        "source_bytes",
        "target_family",
        "verifiedpanel",
    ):
        assert forbidden not in payload


def test_truth_builder_issues_the_frozen_300_case_matrix(
    truth_set: Workspace100TruthSet,
) -> None:
    assert len(truth_set._routes) == _PAIR_COUNT
    assert (
        len({source.episode_id for route in truth_set._routes for source in route.sources})
        == _SOURCE_COUNT
    )
    assert len(truth_set.cases) == _CASE_COUNT
    assert Counter(case.view for case in truth_set.cases) == {
        ViewKind.TRACE_ONLY: 50,
        ViewKind.OWNER_PROBE: 50,
        ViewKind.EPOCH_PROBE: 100,
        ViewKind.REFRESH_RECEIPT: 100,
    }
    assert Counter(case.split for case in truth_set.cases) == {
        Split.DEVELOPMENT: 120,
        Split.VALIDATION: 60,
        Split.TEST: 120,
    }
    assert Counter(case.template_id for case in truth_set.cases) == dict.fromkeys(
        TemplateId,
        60,
    )
    assert Counter(case.certificate.kind for case in truth_set.cases) == {
        VerdictKind.NOT_IDENTIFIABLE: 100,
        VerdictKind.IDENTIFIED_SINGLETON: 200,
    }
    assert Counter(case.certificate.target_family for case in truth_set.cases) == {
        None: 100,
        _ENVIRONMENT_TARGET: 100,
        _POLICY_TARGET: 100,
    }
    panel_roots = Counter(case.certificate.panel_root for case in truth_set.cases)
    assert len(panel_roots) == _PANEL_ROOT_COUNT
    assert set(panel_roots.values()) == {2}
    assert len({case.certificate.proof_root for case in truth_set.cases}) == _CASE_COUNT


def test_truth_release_roots_are_frozen(
    truth_set: Workspace100TruthSet,
) -> None:
    assert truth_set.corpus_root == _EXPECTED_CORPUS_ROOT
    assert truth_set.assignment_root == _EXPECTED_ASSIGNMENT_ROOT
    assert truth_set.evidence_root == _EXPECTED_EVIDENCE_ROOT
    assert truth_set.projection_root == _EXPECTED_PROJECTION_ROOT
    assert truth_set.route_root == _EXPECTED_ROUTE_ROOT
    assert truth_set.certificate_root == _EXPECTED_CERTIFICATE_ROOT
    assert truth_set.truth_root == _EXPECTED_TRUTH_ROOT


def test_every_truth_certificate_rejoins_its_external_route(
    truth_set: Workspace100TruthSet,
) -> None:
    routes_by_pair = {route.pair_id: route for route in truth_set._routes}

    for case in truth_set.cases:
        route = routes_by_pair[case.pair_id]
        sources = tuple(
            source
            for source in route.sources
            if source.evidence_digest_for(case.view) == case.evidence_digest
        )
        assert case.route_digest == route.digest
        assert case.assignment_episode_ids == tuple(source.episode_id for source in sources)
        assert case.certificate.compatible_completion_commitments == tuple(
            source.completion_commitment for source in sources
        )
        assert (
            verify_attribution_certificate(
                case.certificate.to_canonical_bytes(),
                trust_anchor=route.trust_anchor,
                expected_proof_root=case.certificate.proof_root,
            )
            == case.certificate
        )
        if case.view in {ViewKind.TRACE_ONLY, ViewKind.OWNER_PROBE}:
            assert case.certificate.unknown_reason is UnknownReason.AMBIGUOUS_WORLDS
            assert case.certificate.ambiguity_commitments == tuple(
                source.completion_commitment for source in route.sources
            )
            assert case.minimal_witnesses is None
        else:
            assert len(sources) == 1
            assert case.certificate.kind is VerdictKind.IDENTIFIED_SINGLETON
            assert case.minimal_witnesses is not None
            target = case.certificate.target_family
            assert target is not None
            atom = next(
                candidate.name
                for candidate in route.manifest.atoms
                if candidate.target == target[0][0]
            )
            assert case.minimal_witnesses == ((atom,),)


def test_external_anchor_order_is_canonical_and_bad_sets_fail_before_replay(
    monkeypatch: pytest.MonkeyPatch,
    corpus: Workspace100Corpus,
    evidence_views: Workspace100EvidenceViews,
    trust_anchors: tuple[VerificationTrustAnchor, ...],
) -> None:
    forward = truth_module._normalize_anchor_collection(trust_anchors, evidence_views)
    reverse = truth_module._normalize_anchor_collection(
        tuple(reversed(trust_anchors)),
        evidence_views,
    )
    assert forward == reverse

    def forbidden_replay(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("invalid anchors reached source replay")

    monkeypatch.setattr(truth_module, "verify_source_panel", forbidden_replay)
    monkeypatch.setattr(truth_module, "verify_registry_attributions", forbidden_replay)

    with pytest.raises(TypeError, match="exactly 50"):
        truth_module._normalize_anchor_collection(trust_anchors[:-1], evidence_views)
    duplicate = (*trust_anchors[:-1], trust_anchors[0])
    with pytest.raises(ValueError, match=r"unique|exhaust"):
        truth_module._normalize_anchor_collection(duplicate, evidence_views)
    wrong_verifier = (
        replace(
            trust_anchors[0],
            verifier_implementation_digest="0" * _SHA256_HEX_LENGTH,
        ),
        *trust_anchors[1:],
    )
    with pytest.raises(ValueError, match="installed verifier"):
        build_workspace100_truth(
            corpus,
            evidence_views,
            trust_anchors=wrong_verifier,
        )


@pytest.mark.parametrize(
    ("left_view", "right_view"),
    [
        (ViewKind.TRACE_ONLY, ViewKind.OWNER_PROBE),
        (ViewKind.EPOCH_PROBE, ViewKind.REFRESH_RECEIPT),
    ],
)
def test_truth_rejects_consistent_same_pair_view_route_relabels(
    truth_set: Workspace100TruthSet,
    left_view: ViewKind,
    right_view: ViewKind,
) -> None:
    route = truth_set._routes[0]
    relabeled_case = next(
        case for case in truth_set.cases if case.pair_id == route.pair_id and case.view is left_view
    )
    with pytest.raises(ValueError, match="public evidence"):
        replace(relabeled_case, view=right_view)

    forged_sources = []
    for source in route.sources:
        bindings = dict(source.evidence_digests)
        bindings[left_view], bindings[right_view] = (
            bindings[right_view],
            bindings[left_view],
        )
        forged_sources.append(
            replace(
                source,
                evidence_digests=tuple((view, bindings[view]) for view in ViewKind),
            )
        )
    forged_route = replace(
        route,
        sources=(forged_sources[0], forged_sources[1]),
    )
    forged_routes = tuple(
        forged_route if candidate is route else candidate for candidate in truth_set._routes
    )
    forged_cases = tuple(
        replace(case, route_digest=forged_route.digest) if case.pair_id == route.pair_id else case
        for case in truth_set.cases
    )

    with pytest.raises(ValueError, match=r"completion route|assignment|routed evidence"):
        replace(
            truth_set,
            _routes=forged_routes,
            cases=forged_cases,
        )


def test_truth_reconstruction_rejects_bijective_source_snapshot_swap(
    truth_set: Workspace100TruthSet,
) -> None:
    route = truth_set._routes[0]
    left, right = route.sources
    forged_route = replace(
        route,
        sources=(
            replace(left, source_snapshot_digest=right.source_snapshot_digest),
            replace(right, source_snapshot_digest=left.source_snapshot_digest),
        ),
    )
    forged_routes = tuple(
        forged_route if candidate is route else candidate for candidate in truth_set._routes
    )
    forged_cases = tuple(
        replace(case, route_digest=forged_route.digest) if case.pair_id == route.pair_id else case
        for case in truth_set.cases
    )

    with pytest.raises(ValueError, match="assignment root contradicts"):
        replace(
            truth_set,
            _routes=forged_routes,
            cases=forged_cases,
        )


def test_truth_rejects_certificate_and_witness_transplants(
    truth_set: Workspace100TruthSet,
) -> None:
    trace = next(case for case in truth_set.cases if case.view is ViewKind.TRACE_ONLY)
    owner = next(
        case
        for case in truth_set.cases
        if case.pair_id == trace.pair_id and case.view is ViewKind.OWNER_PROBE
    )
    decisive = next(case for case in truth_set.cases if case.view is ViewKind.EPOCH_PROBE)
    route = next(
        candidate for candidate in truth_set._routes if candidate.pair_id == decisive.pair_id
    )
    wrong_atom = next(
        atom.name for atom in route.manifest.atoms if decisive.minimal_witnesses != ((atom.name,),)
    )

    with pytest.raises(ValueError, match="evidence digest"):
        replace(trace, certificate=owner.certificate)
    forged_decisive = replace(decisive, minimal_witnesses=((wrong_atom,),))
    forged_cases = tuple(forged_decisive if case is decisive else case for case in truth_set.cases)
    with pytest.raises(ValueError, match="minimal witness"):
        replace(truth_set, cases=forged_cases)


def test_truth_rejects_public_root_and_singleton_assignment_tampering(
    truth_set: Workspace100TruthSet,
) -> None:
    with pytest.raises(ValueError, match="assignment root"):
        replace(
            truth_set,
            assignment_root="0" * _SHA256_HEX_LENGTH,
        )
    with pytest.raises(ValueError, match="evidence root"):
        replace(
            truth_set,
            evidence_root="0" * _SHA256_HEX_LENGTH,
        )

    first = next(case for case in truth_set.cases if case.view is ViewKind.EPOCH_PROBE)
    second = next(
        case
        for case in truth_set.cases
        if case.pair_id == first.pair_id and case.view is ViewKind.EPOCH_PROBE and case is not first
    )
    forged_first = replace(
        first,
        assignment_episode_ids=second.assignment_episode_ids,
    )
    forged_second = replace(
        second,
        assignment_episode_ids=first.assignment_episode_ids,
    )
    forged_cases = tuple(
        forged_first if case is first else forged_second if case is second else case
        for case in truth_set.cases
    )
    with pytest.raises(ValueError, match=r"completion route|assignments|compatibility"):
        replace(truth_set, cases=forged_cases)
