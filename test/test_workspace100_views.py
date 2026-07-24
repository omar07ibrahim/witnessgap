from __future__ import annotations

import inspect
import subprocess
import sys
import textwrap
from collections import Counter
from dataclasses import replace

import pytest

from witnessgap.model import TargetFamily
from witnessgap.workspace100 import views as views_module
from witnessgap.workspace100.generation import Workspace100Corpus, generate_workspace100
from witnessgap.workspace100.views import (
    VerifiedCompletionMaterial,
    VerifiedPairMaterial,
    verify_workspace100_materials,
)

_SEED = bytes.fromhex("713d96c0fcadb930599f4f4370df3484766872ac406f1c26c5a360a996f29ec5")
_PAIR_COUNT = 50
_COMPLETION_COUNT = 100
_PANEL_RECEIPT_COUNT = 400
_PROBE_RECEIPT_COUNT = 200
_ENVIRONMENT_TARGET: TargetFamily = (("environment",),)
_POLICY_TARGET: TargetFamily = (("policy",),)


@pytest.fixture(scope="module")
def corpus() -> Workspace100Corpus:
    return generate_workspace100(_SEED)


@pytest.fixture(scope="module")
def materials(corpus: Workspace100Corpus) -> tuple[VerifiedPairMaterial, ...]:
    return verify_workspace100_materials(corpus)


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
