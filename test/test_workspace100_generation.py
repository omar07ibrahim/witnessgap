from __future__ import annotations

from collections import Counter
from dataclasses import replace
from hashlib import sha256
from typing import cast

import pytest

from witnessgap.canonical import JsonValue
from witnessgap.source import SealedWorldSource
from witnessgap.workspace100 import generation as generation_module
from witnessgap.workspace100.catalog import VARIANTS
from witnessgap.workspace100.generation import (
    GeneratedCompletion,
    GeneratedPair,
    Workspace100Corpus,
    construction_matrix,
    generate_workspace100,
)
from witnessgap.workspace100.records import (
    CompletionSourceRecord,
    Split,
)

_SEED = bytes.fromhex("713d96c0fcadb930599f4f4370df3484766872ac406f1c26c5a360a996f29ec5")
_OTHER_SEED = bytes.fromhex("4c0b429664b4ddf0bda8e10d4798d56315075d9108a15532f063699d42724a3d")
_TEMPLATE_COUNT = 5
_PAIR_COUNT = 50
_SOURCE_COUNT = 100
_SHA256_HEX_LENGTH = 64
_EXPECTED_CORPUS_ROOT = "01d062caee7878056e8965ebb7766552b38dd442b60ca64f3893fa83cd844a93"


@pytest.fixture(scope="module")
def corpus() -> Workspace100Corpus:
    return generate_workspace100(_SEED)


def test_generation_has_the_frozen_authored_size(corpus: Workspace100Corpus) -> None:
    assert len(corpus.templates) == _TEMPLATE_COUNT
    assert len(corpus.variants) == _PAIR_COUNT
    assert len(corpus.pairs) == _PAIR_COUNT
    assert len(corpus.completions) == _SOURCE_COUNT
    assert len(corpus.sources) == _SOURCE_COUNT


def test_generation_preserves_the_grouped_split(corpus: Workspace100Corpus) -> None:
    pair_counts = Counter(pair.split for pair in corpus.pairs)
    source_counts = Counter(pair.split for pair in corpus.pairs for _completion in pair.completions)

    assert pair_counts == {
        Split.DEVELOPMENT: 20,
        Split.VALIDATION: 10,
        Split.TEST: 20,
    }
    assert source_counts == {
        Split.DEVELOPMENT: 40,
        Split.VALIDATION: 20,
        Split.TEST: 40,
    }


def test_generation_is_byte_identical_for_one_seed(corpus: Workspace100Corpus) -> None:
    repeated = generate_workspace100(_SEED)

    assert repeated == corpus
    assert repeated.root == corpus.root
    assert corpus.root == _EXPECTED_CORPUS_ROOT
    assert repeated.root_payload() == corpus.root_payload()


def test_seed_changes_only_salts_commitments_and_opaque_ids(
    corpus: Workspace100Corpus,
) -> None:
    other = generate_workspace100(_OTHER_SEED)

    assert sorted(source.source_bytes for source in other.sources) == sorted(
        source.source_bytes for source in corpus.sources
    )
    assert {source.commitment_salt for source in other.sources} != {
        source.commitment_salt for source in corpus.sources
    }
    assert {source.completion_commitment for source in other.sources} != {
        source.completion_commitment for source in corpus.sources
    }
    assert other.root != corpus.root


def test_all_generated_identities_are_globally_unique(
    corpus: Workspace100Corpus,
) -> None:
    completions = corpus.completions
    fields: tuple[tuple[object, ...], ...] = (
        tuple(completion.source.commitment_salt for completion in completions),
        tuple(completion.source.snapshot_digest for completion in completions),
        tuple(completion.completion_commitment for completion in completions),
        tuple(completion.episode_id for completion in completions),
        tuple(pair.pair_id for pair in corpus.pairs),
        tuple(pair.task_id for pair in corpus.pairs),
    )

    assert all(len(set(values)) == len(values) for values in fields)
    assert len({source.source_bytes for source in corpus.sources}) == _SOURCE_COUNT


def test_pair_and_episode_ids_are_opaque_and_commitment_ordered(
    corpus: Workspace100Corpus,
) -> None:
    forbidden = ("environment", "policy", "stale", "current", "cause")

    for pair in corpus.pairs:
        assert pair.pair_id.startswith("wgp_")
        assert all(term not in pair.pair_id.casefold() for term in forbidden)
        commitments = tuple(completion.completion_commitment for completion in pair.completions)
        assert commitments == tuple(sorted(commitments))
        for completion in pair.completions:
            assert completion.episode_id.startswith("wge_")
            assert all(term not in completion.episode_id.casefold() for term in forbidden)


def test_every_pair_satisfies_the_frozen_twin_matrix(
    corpus: Workspace100Corpus,
) -> None:
    for pair in corpus.pairs:
        matrices = tuple(construction_matrix(completion.record) for completion in pair.completions)
        intended = pair.completions[0].record.intended_concrete_id
        observed = pair.completions[0].record.observed_concrete_id

        assert all(matrix[0] == observed for matrix in matrices)
        assert sorted(matrix[1] for matrix in matrices) == sorted((intended, observed))
        assert sorted(matrix[2] for matrix in matrices) == sorted((intended, observed))
        assert all(matrix[3] == intended for matrix in matrices)


def test_sources_have_closed_round_trips_without_side_labels(
    corpus: Workspace100Corpus,
) -> None:
    for completion in corpus.completions:
        parsed = CompletionSourceRecord.from_canonical_bytes(completion.source.source_bytes)
        assert parsed == completion.record
        strings = tuple(_walk_strings(parsed.to_payload()))
        assert not any(
            forbidden in value.casefold()
            for forbidden in ("environment", "policy", "stale", "current", "cause")
            for value in strings
        )


def test_root_manifest_does_not_embed_the_release_seed(
    corpus: Workspace100Corpus,
) -> None:
    payload = corpus.root_payload()
    strings = tuple(_walk_strings(payload))

    assert "seed" not in payload
    assert _SEED.hex() not in strings
    assert len(corpus.root) == _SHA256_HEX_LENGTH


def test_pair_rejects_two_completions_with_the_same_twin_shape(
    corpus: Workspace100Corpus,
) -> None:
    original_pair = corpus.pairs[0]
    selector_aligned = next(
        completion
        for completion in original_pair.completions
        if completion.record.selected_selector == completion.record.goal_selector
    )
    duplicate_shape = _reseal(
        replace(
            selector_aligned.record,
            initial_epoch_id="draft_index_shadow_001",
        ),
        domain=b"duplicate-shape",
    )
    completions = cast(
        tuple[GeneratedCompletion, GeneratedCompletion],
        tuple(
            sorted(
                (selector_aligned, duplicate_shape),
                key=lambda completion: completion.completion_commitment,
            )
        ),
    )

    with pytest.raises(ValueError, match="complementary twin"):
        GeneratedPair(
            pair_id=original_pair.pair_id,
            task_id=original_pair.task_id,
            template_id=original_pair.template_id,
            variant_id=original_pair.variant_id,
            split=original_pair.split,
            completions=completions,
        )


def test_corpus_rejects_sources_that_drift_from_the_authored_variant(
    corpus: Workspace100Corpus,
) -> None:
    original_pair = corpus.pairs[0]
    crafted_completions = tuple(
        _reseal(
            replace(
                completion.record,
                public_task=f"{completion.record.public_task} Proceed after review.",
            ),
            domain=f"catalog-drift-{index}".encode(),
        )
        for index, completion in enumerate(original_pair.completions)
    )
    ordered = cast(
        tuple[GeneratedCompletion, GeneratedCompletion],
        tuple(
            sorted(
                crafted_completions,
                key=lambda completion: completion.completion_commitment,
            )
        ),
    )
    commitments = cast(
        tuple[str, str],
        tuple(completion.completion_commitment for completion in ordered),
    )
    crafted_pair = GeneratedPair(
        pair_id=generation_module._pair_id(commitments),
        task_id=original_pair.task_id,
        template_id=original_pair.template_id,
        variant_id=original_pair.variant_id,
        split=original_pair.split,
        completions=ordered,
    )

    with pytest.raises(ValueError, match="frozen authored catalog"):
        Workspace100Corpus(
            protocol_id=corpus.protocol_id,
            templates=corpus.templates,
            variants=corpus.variants,
            pairs=(crafted_pair, *corpus.pairs[1:]),
        )


def test_generation_rejects_post_import_frozen_catalog_mutation() -> None:
    variant = VARIANTS[0]
    original = variant.intended_concrete_id
    object.__setattr__(
        variant,
        "intended_concrete_id",
        "revision_northstar_99",
    )
    try:
        with pytest.raises(ValueError, match="frozen protocol digest"):
            generate_workspace100(_SEED)
    finally:
        object.__setattr__(variant, "intended_concrete_id", original)


@pytest.mark.parametrize("seed", [b"", b"x" * 31, b"x" * 33])
def test_generation_rejects_wrong_seed_lengths(seed: bytes) -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        generate_workspace100(seed)


@pytest.mark.parametrize("seed", [None, "x" * 32, bytearray(32)])
def test_generation_rejects_nonbyte_seeds(seed: object) -> None:
    with pytest.raises(TypeError, match="exact bytes"):
        generate_workspace100(cast(bytes, seed))


def test_generation_rejects_a_bytes_subclass() -> None:
    class StatefulSeed(bytes):
        pass

    with pytest.raises(TypeError, match="exact bytes"):
        generate_workspace100(StatefulSeed(_SEED))


def test_generated_completion_revalidates_post_init_mutation(
    corpus: Workspace100Corpus,
) -> None:
    completion = corpus.completions[0]
    object.__setattr__(completion, "episode_id", "wge_000000000000000000000000")

    with pytest.raises(ValueError, match="completion commitment"):
        completion.validate()


def _walk_strings(value: JsonValue) -> tuple[str, ...]:
    if type(value) is str:
        return (value,)
    if type(value) is dict:
        return tuple(value) + tuple(
            string for nested in value.values() for string in _walk_strings(nested)
        )
    if type(value) in {tuple, list}:
        sequence = cast(tuple[JsonValue, ...] | list[JsonValue], value)
        return tuple(string for nested in sequence for string in _walk_strings(nested))
    return ()


def _reseal(
    record: CompletionSourceRecord,
    *,
    domain: bytes,
) -> GeneratedCompletion:
    source_bytes = record.to_canonical_bytes()
    source = SealedWorldSource(
        source_bytes=source_bytes,
        commitment_salt=sha256(domain + source_bytes).digest(),
    )
    return GeneratedCompletion(
        episode_id=f"wge_{source.completion_commitment[:24]}",
        record=record,
        source=source,
    )
