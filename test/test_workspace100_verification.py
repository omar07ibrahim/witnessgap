from __future__ import annotations

from dataclasses import dataclass

import pytest

from witnessgap.identifiability import CandidateRegistry
from witnessgap.model import ExecutionArtifact
from witnessgap.source import SealedWorldSource
from witnessgap.verifier import VerificationError, verify_source_panel
from witnessgap.workspace100 import runtime as runtime_module
from witnessgap.workspace100.generation import (
    GeneratedPair,
    Workspace100Corpus,
    generate_workspace100,
)
from witnessgap.workspace100.runtime import (
    Workspace100SourceAdapter,
    Workspace100World,
    workspace100_pair_worlds,
)

_SEED = bytes.fromhex("713d96c0fcadb930599f4f4370df3484766872ac406f1c26c5a360a996f29ec5")
_PAIR_COUNT = 50
_PANEL_COUNT = 100
_RECEIPT_COUNT = 400
_RECEIPTS_PER_PANEL = 4
_VERIFIER_RUN_COUNT = 800
_VERIFIER_DECODE_COUNT = 1000


@dataclass(frozen=True, slots=True)
class _PairRuntime:
    pair: GeneratedPair
    worlds: tuple[Workspace100World, Workspace100World]
    registry: CandidateRegistry


@pytest.fixture(scope="module")
def corpus() -> Workspace100Corpus:
    return generate_workspace100(_SEED)


@pytest.fixture(scope="module")
def pair_runtimes(corpus: Workspace100Corpus) -> tuple[_PairRuntime, ...]:
    return tuple(
        _PairRuntime(
            pair=pair,
            worlds=(worlds := workspace100_pair_worlds(pair)),
            registry=CandidateRegistry.build(worlds),
        )
        for pair in corpus.pairs
    )


def test_independent_verifier_matches_all_search_panels_with_freshness_counts(
    pair_runtimes: tuple[_PairRuntime, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decode_count = 0
    run_count = 0
    original_decode = Workspace100SourceAdapter.decode
    original_run = runtime_module._Workspace100Runner.run

    def counted_decode(
        adapter: Workspace100SourceAdapter,
        source: SealedWorldSource,
    ) -> Workspace100World:
        nonlocal decode_count
        decode_count += 1
        return original_decode(adapter, source)

    def counted_run(
        runner: runtime_module._Workspace100Runner,
        interventions: frozenset[str],
    ) -> ExecutionArtifact:
        nonlocal run_count
        run_count += 1
        return original_run(runner, interventions)

    monkeypatch.setattr(Workspace100SourceAdapter, "decode", counted_decode)
    monkeypatch.setattr(runtime_module._Workspace100Runner, "run", counted_run)

    panel_count = 0
    receipt_count = 0
    for pair_runtime in pair_runtimes:
        for completion in pair_runtime.pair.completions:
            verified = verify_source_panel(
                completion.source,
                manifest=pair_runtime.registry.manifest,
            )
            search_candidate = next(
                candidate
                for candidate in pair_runtime.registry.candidates
                if candidate.completion_commitment == completion.completion_commitment
            )

            assert verified.completion_commitment == completion.completion_commitment
            assert verified.minimal_witnesses == search_candidate.panel.minimal_witnesses
            assert verified.target_family == search_candidate.panel.target_family
            assert len(verified.receipts) == _RECEIPTS_PER_PANEL
            for verified_receipt, search_receipt in zip(
                verified.receipts,
                search_candidate.panel.receipts,
                strict=True,
            ):
                assert verified_receipt.interventions == search_receipt.interventions
                assert verified_receipt.artifact.public_trace == search_receipt.result.public_trace
                assert verified_receipt.outcome is search_receipt.result.outcome
                assert (
                    tuple(
                        sorted({read.channel for read in verified_receipt.artifact.state_read_log})
                    )
                    == search_receipt.result.state_reads
                )

            panel_count += 1
            receipt_count += len(verified.receipts)

    assert len(pair_runtimes) == _PAIR_COUNT
    assert panel_count == _PANEL_COUNT
    assert receipt_count == _RECEIPT_COUNT
    assert run_count == _VERIFIER_RUN_COUNT
    assert decode_count == _VERIFIER_DECODE_COUNT


def test_pair_manifest_rejects_a_source_from_another_authored_pair(
    pair_runtimes: tuple[_PairRuntime, ...],
) -> None:
    first, second = pair_runtimes[:2]

    with pytest.raises(VerificationError, match=r"declaration|committed"):
        verify_source_panel(
            second.pair.completions[0].source,
            manifest=first.registry.manifest,
        )
