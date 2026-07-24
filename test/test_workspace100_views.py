from __future__ import annotations

import inspect
import subprocess
import sys
import textwrap
from collections import Counter, defaultdict
from collections.abc import Iterator
from dataclasses import replace
from typing import cast

import pytest

from witnessgap.identifiability import ProbeObservation
from witnessgap.model import Outcome, TargetFamily
from witnessgap.workspace100 import views as views_module
from witnessgap.workspace100.evidence import PublicEvidenceEnvelope
from witnessgap.workspace100.generation import Workspace100Corpus, generate_workspace100
from witnessgap.workspace100.records import Split, TemplateId
from witnessgap.workspace100.views import (
    VerifiedCompletionMaterial,
    VerifiedPairMaterial,
    ViewKind,
    Workspace100EvidenceViews,
    verify_workspace100_materials,
    workspace100_projection_roots,
)

_SEED = bytes.fromhex("713d96c0fcadb930599f4f4370df3484766872ac406f1c26c5a360a996f29ec5")
_PAIR_COUNT = 50
_COMPLETION_COUNT = 100
_PANEL_RECEIPT_COUNT = 400
_PROBE_RECEIPT_COUNT = 200
_ASSIGNMENT_COUNT = 400
_EVIDENCE_CASE_COUNT = 300
_ENVIRONMENT_TARGET: TargetFamily = (("environment",),)
_POLICY_TARGET: TargetFamily = (("policy",),)
_EXPECTED_ASSIGNMENT_ROOT = "6a82d84186e25b6df926ac481f40a58d7808bc49ca7deb4e1a6bfab1aad1c454"
_EXPECTED_EVIDENCE_ROOT = "4f5ed5eac99d3bf4eaedcafa3bbc019c06debba6372b4935dd57c6f09c9f3d71"
_EXPECTED_PROJECTION_ROOT = "2b99bac2b2f914a06e33b87caab3959bcb5c4017496dd747f2dedec36e0b4776"


@pytest.fixture(scope="module")
def corpus() -> Workspace100Corpus:
    return generate_workspace100(_SEED)


@pytest.fixture(scope="module")
def materials(corpus: Workspace100Corpus) -> tuple[VerifiedPairMaterial, ...]:
    return verify_workspace100_materials(corpus)


@pytest.fixture(scope="module")
def evidence_views(
    materials: tuple[VerifiedPairMaterial, ...],
) -> Workspace100EvidenceViews:
    return views_module._project_verified_materials(materials)


def test_all_authored_sources_receive_independent_panels_and_probe_receipts(
    corpus: Workspace100Corpus,
    materials: tuple[VerifiedPairMaterial, ...],
) -> None:
    completions = tuple(completion for material in materials for completion in material.completions)

    assert len(materials) == _PAIR_COUNT
    assert len(completions) == _COMPLETION_COUNT
    assert sum(len(completion.panel.receipts) for completion in completions) == (
        _PANEL_RECEIPT_COUNT
    )
    assert sum(len(completion.probes) for completion in completions) == (_PROBE_RECEIPT_COUNT)
    assert tuple(material.pair_id for material in materials) == tuple(
        pair.pair_id for pair in corpus.pairs
    )
    assert tuple(completion.episode_id for completion in completions) == tuple(
        completion.episode_id for completion in corpus.completions
    )


def test_pair_materials_bind_every_receipt_to_the_direct_manifest(
    corpus: Workspace100Corpus,
    materials: tuple[VerifiedPairMaterial, ...],
) -> None:
    for pair, material in zip(corpus.pairs, materials, strict=True):
        expected_commitments = tuple(
            completion.completion_commitment for completion in pair.completions
        )

        assert material.task_id == pair.task_id
        assert material.template_id is pair.template_id
        assert material.split is pair.split
        assert material.manifest.task_id == pair.task_id
        assert material.manifest.candidate_commitments == expected_commitments
        assert (
            tuple(completion.panel.completion_commitment for completion in material.completions)
            == expected_commitments
        )
        for completion in material.completions:
            assert tuple(receipt.name for receipt in completion.probes) == (
                material.manifest.probe_names
            )
            assert all(
                receipt.probe_contract_digest == material.manifest.probe_contract_digest
                for receipt in completion.probes
            )


def test_verified_twin_views_preserve_neutral_and_separating_probes(
    corpus: Workspace100Corpus,
    materials: tuple[VerifiedPairMaterial, ...],
) -> None:
    templates = {template.template_id: template for template in corpus.templates}
    for material in materials:
        template = templates[material.template_id]
        left, right = material.completions

        assert left.probe_for("workspace_owner").value == right.probe_for("workspace_owner").value
        assert (
            left.probe_for(template.epoch_probe).value
            != right.probe_for(template.epoch_probe).value
        )
        left_baseline = left.panel.receipt_for(())
        right_baseline = right.panel.receipt_for(())
        assert left_baseline.outcome is Outcome.FAILURE
        assert right_baseline.outcome is Outcome.FAILURE
        assert left_baseline.artifact.public_trace == right_baseline.artifact.public_trace
        assert {left.panel.target_family, right.panel.target_family} == {
            _ENVIRONMENT_TARGET,
            _POLICY_TARGET,
        }


def test_verified_panels_balance_the_two_singleton_target_families(
    materials: tuple[VerifiedPairMaterial, ...],
) -> None:
    target_counts = Counter(
        completion.panel.target_family
        for material in materials
        for completion in material.completions
    )

    assert target_counts == {
        _ENVIRONMENT_TARGET: 50,
        _POLICY_TARGET: 50,
    }
    assert all(
        len(completion.panel.minimal_witnesses) == 1
        for material in materials
        for completion in material.completions
    )


def test_material_records_reject_cross_completion_and_cross_pair_transplants(
    materials: tuple[VerifiedPairMaterial, ...],
) -> None:
    first, second = materials[:2]
    first_completion = first.completions[0]
    other_completion = first.completions[1]
    transplanted_probe = replace(
        first_completion.probes[0],
        completion_commitment=other_completion.panel.completion_commitment,
    )

    with pytest.raises(ValueError, match="different completion panel"):
        VerifiedCompletionMaterial(
            episode_id=first_completion.episode_id,
            panel=first_completion.panel,
            probes=(transplanted_probe, first_completion.probes[1]),
        )
    with pytest.raises(ValueError, match="contradicts its manifest"):
        VerifiedPairMaterial(
            pair_id=first.pair_id,
            task_id=first.task_id,
            template_id=first.template_id,
            split=first.split,
            manifest=second.manifest,
            completions=first.completions,
        )


def test_material_records_bind_routing_metadata_to_verified_content(
    materials: tuple[VerifiedPairMaterial, ...],
) -> None:
    pair = materials[0]
    left, right = pair.completions

    with pytest.raises(ValueError, match="pair_id contradicts"):
        replace(pair, pair_id="wgp_" + "0" * 24)
    with pytest.raises(ValueError, match="frozen template"):
        replace(pair, template_id=TemplateId.MOVE_WORK_ITEM)
    with pytest.raises(ValueError, match="frozen template"):
        replace(pair, split=Split.TEST)
    with pytest.raises(ValueError, match="episode_id contradicts"):
        replace(left, episode_id=right.episode_id)


def test_material_records_rederive_panels_instead_of_trusting_cached_labels(
    materials: tuple[VerifiedPairMaterial, ...],
) -> None:
    pair = materials[0]
    left, right = pair.completions

    forged_panels = (
        replace(left.panel, target_family=(("forged",),)),
        replace(left.panel, minimal_witnesses=(("forged_intervention",),)),
        replace(left.panel, receipts=()),
        replace(left.panel, runner_contract_digest="0" * 64),
    )
    expected_messages = (
        "target family contradicts",
        "minimal witnesses contradict",
        "complete exact receipt lattice",
        "contracts differ",
    )
    for panel, message in zip(forged_panels, expected_messages, strict=True):
        forged = replace(left, panel=panel)
        with pytest.raises((TypeError, ValueError), match=message):
            replace(pair, completions=(forged, right))


def test_pair_manifest_binds_atom_names_to_their_frozen_targets(
    materials: tuple[VerifiedPairMaterial, ...],
) -> None:
    pair = materials[0]
    forged_atoms = tuple(
        replace(
            atom,
            target="policy" if atom.target == "environment" else "environment",
        )
        for atom in pair.manifest.atoms
    )
    forged_manifest = replace(pair.manifest, atoms=forged_atoms)

    with pytest.raises(ValueError, match="frozen template"):
        replace(pair, manifest=forged_manifest)


def test_verified_receipts_project_to_the_frozen_400_to_300_join(
    evidence_views: Workspace100EvidenceViews,
) -> None:
    assignments = evidence_views._assignments
    cases = evidence_views.cases
    assignments_by_digest = Counter(assignment.evidence_digest for assignment in assignments)
    digests_by_pair: defaultdict[str, set[str]] = defaultdict(set)
    for assignment in assignments:
        digests_by_pair[assignment.pair_id].add(assignment.evidence_digest)

    assert evidence_views.assignment_count == _ASSIGNMENT_COUNT
    assert evidence_views.case_count == _EVIDENCE_CASE_COUNT
    assert Counter(assignment.view for assignment in assignments) == dict.fromkeys(ViewKind, 100)
    assert Counter(case.view for case in cases) == {
        ViewKind.TRACE_ONLY: 50,
        ViewKind.OWNER_PROBE: 50,
        ViewKind.EPOCH_PROBE: 100,
        ViewKind.REFRESH_RECEIPT: 100,
    }
    assert Counter(case.split for case in cases) == {
        Split.DEVELOPMENT: 120,
        Split.VALIDATION: 60,
        Split.TEST: 120,
    }
    assert Counter(case.template_id for case in cases) == dict.fromkeys(TemplateId, 60)
    assert {len(digests) for digests in digests_by_pair.values()} == {6}
    for case in cases:
        expected = 2 if case.view in {ViewKind.TRACE_ONLY, ViewKind.OWNER_PROBE} else 1
        assert assignments_by_digest[case.evidence_digest] == expected


def test_each_view_is_a_literal_projection_of_verified_receipts(
    materials: tuple[VerifiedPairMaterial, ...],
    evidence_views: Workspace100EvidenceViews,
) -> None:
    materials_by_pair = {material.pair_id: material for material in materials}
    cases_by_digest = {case.evidence_digest: case for case in evidence_views.cases}
    for assignment in evidence_views._assignments:
        material = materials_by_pair[assignment.pair_id]
        completion = next(
            candidate
            for candidate in material.completions
            if candidate.episode_id == assignment.episode_id
        )
        case = cases_by_digest[assignment.evidence_digest]
        evidence = case.envelope.evidence
        baseline = completion.panel.receipt_for(())

        assert evidence.registry_digest == material.manifest.digest
        assert evidence.coverage_manifest_digest == material.manifest.coverage_digest
        assert evidence.public_trace == baseline.artifact.public_trace
        assert evidence.outcome is baseline.outcome
        if assignment.view is ViewKind.TRACE_ONLY:
            assert evidence.probes == ()
            assert evidence.intervention_observations == ()
        elif assignment.view is ViewKind.OWNER_PROBE:
            owner = completion.probe_for("workspace_owner")
            assert evidence.probes == (ProbeObservation(name=owner.name, value=owner.value),)
            assert evidence.intervention_observations == ()
        elif assignment.view is ViewKind.EPOCH_PROBE:
            epoch_name = next(
                name for name in material.manifest.probe_names if name != "workspace_owner"
            )
            epoch = completion.probe_for(epoch_name)
            assert evidence.probes == (ProbeObservation(name=epoch.name, value=epoch.value),)
            assert evidence.intervention_observations == ()
        else:
            refresh_atom = next(
                atom.name for atom in material.manifest.atoms if atom.target == "environment"
            )
            receipt = completion.panel.receipt_for((refresh_atom,))
            assert evidence.probes == ()
            assert len(evidence.intervention_observations) == 1
            observation = evidence.intervention_observations[0]
            assert observation.interventions == receipt.interventions
            assert observation.public_trace == receipt.artifact.public_trace
            assert observation.outcome is receipt.outcome


def test_evidence_roots_are_order_independent_and_frozen(
    materials: tuple[VerifiedPairMaterial, ...],
    evidence_views: Workspace100EvidenceViews,
) -> None:
    reversed_views = views_module._project_verified_materials(tuple(reversed(materials)))

    assert reversed_views == evidence_views
    assert evidence_views.assignment_root == _EXPECTED_ASSIGNMENT_ROOT
    assert evidence_views.evidence_root == _EXPECTED_EVIDENCE_ROOT
    assert evidence_views.projection_root == _EXPECTED_PROJECTION_ROOT
    roots = workspace100_projection_roots(evidence_views)
    assert (
        roots.assignment_root,
        roots.evidence_root,
        roots.projection_root,
    ) == (
        _EXPECTED_ASSIGNMENT_ROOT,
        _EXPECTED_EVIDENCE_ROOT,
        _EXPECTED_PROJECTION_ROOT,
    )


def test_case_metadata_cannot_relabel_a_worker_request(
    evidence_views: Workspace100EvidenceViews,
) -> None:
    trace_case = next(
        case
        for case in evidence_views.cases
        if case.view is ViewKind.TRACE_ONLY and case.template_id is TemplateId.PUBLISH_DRAFT
    )
    first_assignment = evidence_views._assignments[0]

    with pytest.raises(ValueError, match="owner-probe"):
        replace(trace_case, view=ViewKind.OWNER_PROBE)
    with pytest.raises(ValueError, match="split contradicts"):
        replace(trace_case, split=Split.TEST)
    with pytest.raises(ValueError, match="split contradicts"):
        replace(first_assignment, split=Split.TEST)


def test_assignment_routes_reject_episode_and_task_transplants(
    evidence_views: Workspace100EvidenceViews,
) -> None:
    first = evidence_views._assignments[0]
    other = next(
        assignment
        for assignment in evidence_views._assignments
        if assignment.pair_id != first.pair_id
    )
    forged_episode = replace(first, episode_id=other.episode_id)
    forged_task = replace(first, task_id=other.task_id)

    for forged in (forged_episode, forged_task):
        assignments = tuple(
            sorted(
                (
                    forged if assignment is first else assignment
                    for assignment in evidence_views._assignments
                ),
                key=views_module._assignment_sort_key,
            )
        )
        with pytest.raises(ValueError, match=r"pair route|route or case"):
            replace(evidence_views, _assignments=assignments)


def test_completion_routes_reject_same_pair_twin_transposition(
    evidence_views: Workspace100EvidenceViews,
) -> None:
    route = evidence_views._routes[0]
    left_episode, right_episode = route.episode_ids
    decisive_views = {ViewKind.EPOCH_PROBE, ViewKind.REFRESH_RECEIPT}
    assignments = tuple(
        sorted(
            (
                replace(candidate, episode_id=right_episode)
                if candidate.episode_id == left_episode and candidate.view in decisive_views
                else replace(candidate, episode_id=left_episode)
                if candidate.episode_id == right_episode and candidate.view in decisive_views
                else candidate
                for candidate in evidence_views._assignments
            ),
            key=views_module._assignment_sort_key,
        )
    )

    with pytest.raises(ValueError, match="completion route"):
        replace(evidence_views, _assignments=assignments)


def test_projection_rejects_a_routing_id_hidden_inside_hex_evidence(
    evidence_views: Workspace100EvidenceViews,
) -> None:
    case = next(
        candidate for candidate in evidence_views.cases if candidate.view is ViewKind.TRACE_ONLY
    )
    assignment = next(
        candidate
        for candidate in evidence_views._assignments
        if candidate.evidence_digest == case.evidence_digest
    )
    route = next(
        candidate for candidate in evidence_views._routes if candidate.pair_id == assignment.pair_id
    )
    forged_evidence = replace(
        case.envelope.evidence,
        public_trace=route.pair_id.encode(),
    )
    forged_case = replace(
        case,
        envelope=PublicEvidenceEnvelope(forged_evidence),
    )
    forged_cases = tuple(
        sorted(
            (forged_case if candidate is case else candidate for candidate in evidence_views.cases),
            key=views_module._case_sort_key,
        )
    )
    forged_assignments = tuple(
        sorted(
            (
                replace(
                    candidate,
                    evidence_digest=forged_case.evidence_digest,
                )
                if candidate.evidence_digest == case.evidence_digest
                else candidate
                for candidate in evidence_views._assignments
            ),
            key=views_module._assignment_sort_key,
        )
    )
    forged_completion_routes = tuple(
        replace(
            completion,
            evidence_digests=tuple(
                (
                    view,
                    forged_case.evidence_digest if digest == case.evidence_digest else digest,
                )
                for view, digest in completion.evidence_digests
            ),
        )
        for completion in route.completions
    )
    forged_route = replace(
        route,
        completions=(
            forged_completion_routes[0],
            forged_completion_routes[1],
        ),
    )
    forged_routes = tuple(
        sorted(
            (
                forged_route if candidate is route else candidate
                for candidate in evidence_views._routes
            ),
            key=views_module._route_sort_key,
        )
    )

    with pytest.raises(ValueError, match="private routing value"):
        replace(
            evidence_views,
            _routes=forged_routes,
            _assignments=forged_assignments,
            cases=forged_cases,
        )


def test_worker_requests_are_closed_id_free_and_recursively_label_free(
    materials: tuple[VerifiedPairMaterial, ...],
    evidence_views: Workspace100EvidenceViews,
) -> None:
    private_values = tuple(
        value.encode()
        for material in materials
        for value in (
            material.pair_id,
            material.task_id,
            *(completion.episode_id for completion in material.completions),
            *material.manifest.candidate_commitments,
            *(completion.panel.source_snapshot_digest for completion in material.completions),
        )
    )
    requests = tuple(case.worker_bytes for case in evidence_views.cases)

    assert len(requests) == _EVIDENCE_CASE_COUNT
    assert len(set(requests)) == _EVIDENCE_CASE_COUNT
    for request, case in zip(requests, evidence_views.cases, strict=True):
        assert PublicEvidenceEnvelope.from_canonical_bytes(request) == case.envelope
        assert all(identifier not in request for identifier in private_values)
        for forbidden_field in (
            b'"case_id"',
            b'"evidence_digest"',
            b'"episode_id"',
            b'"pair_id"',
            b'"split"',
            b'"template_id"',
            b'"view"',
        ):
            assert forbidden_field not in request
        public_strings = tuple(_walk_public_strings(case.envelope.to_payload()))
        assert not any(
            private.decode() in value for value in public_strings for private in private_values
        )
        assert not any(
            forbidden in value.casefold()
            for value in public_strings
            for forbidden in (
                "causal_target",
                "completion_side",
                "current",
                "environment",
                "policy",
                "resolver_aligned",
                "selector_aligned",
                "stale",
                "target_label",
            )
        )


def test_receipt_projection_uses_no_runtime_or_verifier_capability(
    monkeypatch: pytest.MonkeyPatch,
    materials: tuple[VerifiedPairMaterial, ...],
    evidence_views: Workspace100EvidenceViews,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("projection crossed the verified-receipt boundary")

    monkeypatch.setattr(views_module, "workspace100_pair_worlds", forbidden)
    monkeypatch.setattr(views_module, "verify_source_panel", forbidden)
    monkeypatch.setattr(views_module, "verify_source_probe", forbidden)

    assert views_module._project_verified_materials(materials) == evidence_views


def test_view_authoring_source_has_no_search_or_cached_panel_dependency() -> None:
    source = inspect.getsource(views_module)

    assert "CandidateRegistry" not in source
    assert "RepairPanel" not in source
    assert "witnessgap.oracle" not in source


def test_verifying_one_pair_does_not_import_the_search_oracle() -> None:
    script = textwrap.dedent(
        f"""
        import sys

        from witnessgap.workspace100.generation import generate_workspace100
        from witnessgap.workspace100.views import _verify_pair_material

        corpus = generate_workspace100(bytes.fromhex({_SEED.hex()!r}))
        assert "witnessgap.oracle" not in sys.modules
        material = _verify_pair_material(corpus.pairs[0])
        assert len(material.completions) == 2
        assert "witnessgap.oracle" not in sys.modules
        """
    )

    subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
    )


def _walk_public_strings(value: object) -> Iterator[str]:
    if type(value) is dict:
        for key, nested in cast(dict[object, object], value).items():
            yield str(key)
            if str(key).endswith("_hex") and type(nested) is str:
                try:
                    decoded = bytes.fromhex(nested).decode()
                except (UnicodeDecodeError, ValueError):
                    pass
                else:
                    yield decoded
            yield from _walk_public_strings(nested)
    elif type(value) in {tuple, list}:
        for nested in cast(tuple[object, ...] | list[object], value):
            yield from _walk_public_strings(nested)
    elif type(value) is str:
        yield value
