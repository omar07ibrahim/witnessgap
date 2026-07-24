from __future__ import annotations

from dataclasses import replace

import pytest

from witnessgap.verifier import trust_anchor_for_manifest
from witnessgap.workspace100 import truth as truth_module
from witnessgap.workspace100.generation import Workspace100Corpus, generate_workspace100
from witnessgap.workspace100.views import (
    Workspace100EvidenceViews,
    build_workspace100_evidence_views,
)

_SEED = bytes.fromhex("713d96c0fcadb930599f4f4370df3484766872ac406f1c26c5a360a996f29ec5")
_SHA256_HEX_LENGTH = 64


@pytest.fixture(scope="module")
def corpus() -> Workspace100Corpus:
    return generate_workspace100(_SEED)


@pytest.fixture(scope="module")
def evidence_views(corpus: Workspace100Corpus) -> Workspace100EvidenceViews:
    return build_workspace100_evidence_views(corpus)


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
