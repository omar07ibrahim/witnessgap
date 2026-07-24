from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from typing import cast

import pytest

from witnessgap.adapters import TrustedAdapterError, resolve_trusted_adapter
from witnessgap.canonical import JsonValue, canonical_json
from witnessgap.identifiability import CandidateRegistry
from witnessgap.model import ExecutionArtifact, Outcome, StateRead
from witnessgap.source import SealedWorldSource
from witnessgap.workspace100.generation import (
    GeneratedPair,
    Workspace100Corpus,
    generate_workspace100,
)
from witnessgap.workspace100.runtime import (
    WORKSPACE100_ADAPTER_ID,
    WORKSPACE100_OWNER_PROBE,
    Workspace100SourceAdapter,
    Workspace100World,
    workspace100_adapter_implementation_digest,
    workspace100_pair_worlds,
)

_SEED = bytes.fromhex("713d96c0fcadb930599f4f4370df3484766872ac406f1c26c5a360a996f29ec5")
_PAIR_COUNT = 50
_SOURCE_COUNT = 100
_ARTIFACT_COUNT = 400
_FORGERIES_PER_ARTIFACT = 5
_SHA256_HEX_LENGTH = 64
_FORBIDDEN_PUBLIC_TERMS = (
    "environment",
    "policy",
    "stale",
    "current",
    "selector_aligned",
    "resolver_aligned",
    "completion_side",
    "side_label",
    "target_label",
    "causal_target",
)


@pytest.fixture(scope="module")
def corpus() -> Workspace100Corpus:
    return generate_workspace100(_SEED)


def test_adapter_identity_binds_the_complete_runtime_bundle() -> None:
    adapter = Workspace100SourceAdapter()

    assert adapter.adapter_id == WORKSPACE100_ADAPTER_ID
    assert adapter.source_format_id == "witnessgap.workspace100-source.v1"
    assert adapter.implementation_digest == workspace100_adapter_implementation_digest()
    assert len(adapter.implementation_digest) == _SHA256_HEX_LENGTH


def test_closed_adapter_registry_resolves_only_the_installed_runtime() -> None:
    adapter = Workspace100SourceAdapter()
    resolved = resolve_trusted_adapter(
        adapter.adapter_id,
        expected_implementation_digest=adapter.implementation_digest,
    )

    assert type(resolved) is Workspace100SourceAdapter
    with pytest.raises(TrustedAdapterError, match="implementation"):
        resolve_trusted_adapter(
            adapter.adapter_id,
            expected_implementation_digest="0" * _SHA256_HEX_LENGTH,
        )
    with pytest.raises(TrustedAdapterError, match="not trusted"):
        resolve_trusted_adapter(
            "participant_supplied_adapter",
            expected_implementation_digest=adapter.implementation_digest,
        )


def test_adapter_decodes_all_exact_authored_sources(
    corpus: Workspace100Corpus,
) -> None:
    adapter = Workspace100SourceAdapter()
    worlds = tuple(adapter.decode(source) for source in corpus.sources)

    assert len(worlds) == _SOURCE_COUNT
    assert len({world.world_id for world in worlds}) == _SOURCE_COUNT
    for source, world in zip(corpus.sources, worlds, strict=True):
        assert world.completion_commitment == source.completion_commitment
        assert world.source_snapshot_digest == source.snapshot_digest
        assert world.record.to_canonical_bytes() == source.source_bytes
        assert world.task_schema_id == world.template.task_schema_id
        assert world.task_id == world.record.task_id
        assert world.adapter_implementation_digest == adapter.implementation_digest


def test_every_twin_has_one_shared_failure_trace_and_neutral_control_probe(
    corpus: Workspace100Corpus,
) -> None:
    for pair in corpus.pairs:
        left, right = workspace100_pair_worlds(pair)
        left_baseline = left.replay(frozenset())
        right_baseline = right.replay(frozenset())

        assert left_baseline == right_baseline
        assert left_baseline.outcome is Outcome.FAILURE
        assert left.probe(WORKSPACE100_OWNER_PROBE) == right.probe(WORKSPACE100_OWNER_PROBE)
        assert left.probe(left.template.epoch_probe) != right.probe(right.template.epoch_probe)
        assert not any(
            term in left_baseline.public_trace.decode().casefold()
            for term in _FORBIDDEN_PUBLIC_TERMS
        )
        assert not any(
            term in left.probe(left.template.epoch_probe).decode().casefold()
            for term in _FORBIDDEN_PUBLIC_TERMS
        )


def test_every_twin_satisfies_the_runtime_intervention_matrix(
    corpus: Workspace100Corpus,
) -> None:
    for pair in corpus.pairs:
        for world in workspace100_pair_worlds(pair):
            refresh = frozenset((world.template.refresh_atom,))
            repair = frozenset((world.template.repair_atom,))
            both = refresh | repair
            selector_aligned = world.record.selected_selector == world.record.goal_selector

            assert world.replay(frozenset()).outcome is Outcome.FAILURE
            assert world.replay(refresh).outcome is (
                Outcome.SUCCESS if selector_aligned else Outcome.FAILURE
            )
            assert world.replay(repair).outcome is (
                Outcome.FAILURE if selector_aligned else Outcome.SUCCESS
            )
            assert world.replay(both).outcome is Outcome.SUCCESS


def test_search_registry_agrees_with_all_fifty_authored_pairs(
    corpus: Workspace100Corpus,
) -> None:
    registries = tuple(
        CandidateRegistry.build(workspace100_pair_worlds(pair)) for pair in corpus.pairs
    )

    assert len(registries) == _PAIR_COUNT
    for pair, registry in zip(corpus.pairs, registries, strict=True):
        assert registry.manifest.task_id == pair.task_id
        assert registry.manifest.candidate_commitments == tuple(
            completion.completion_commitment for completion in pair.completions
        )
        assert {atom.target for atom in registry.manifest.atoms} == {
            "environment",
            "policy",
        }
        for candidate in registry.candidates:
            world = next(
                world
                for world in workspace100_pair_worlds(pair)
                if world.world_id == candidate.world_id
            )
            selector_aligned = world.record.selected_selector == world.record.goal_selector
            expected_witness = (
                (world.template.refresh_atom,)
                if selector_aligned
                else (world.template.repair_atom,)
            )
            expected_target = (("environment",),) if selector_aligned else (("policy",),)

            assert candidate.panel.minimal_witnesses == (expected_witness,)
            assert candidate.panel.target_family == expected_target


def test_runner_records_both_and_only_declared_state_reads(
    corpus: Workspace100Corpus,
) -> None:
    for pair in corpus.pairs:
        for world in workspace100_pair_worlds(pair):
            artifact = world.fresh_runner().run(frozenset())

            assert tuple(read.channel for read in artifact.state_read_log) == (
                world.template.selection_channel,
                world.template.resolver_channel,
            )
            assert {read.channel for read in artifact.state_read_log} == set(
                world.declared_state_channels
            )
            assert world.validate_artifact(artifact) is Outcome.FAILURE


def test_runner_is_single_use_and_rejects_an_open_intervention_type(
    corpus: Workspace100Corpus,
) -> None:
    world = workspace100_pair_worlds(corpus.pairs[0])[0]
    runner = world.fresh_runner()
    runner.run(frozenset())

    with pytest.raises(RuntimeError, match="single-use"):
        runner.run(frozenset())
    with pytest.raises(TypeError, match="exact frozenset"):
        world.fresh_runner().run(cast(frozenset[str], set()))


def test_complete_artifact_validator_rejects_every_forged_surface(
    corpus: Workspace100Corpus,
) -> None:
    world = workspace100_pair_worlds(corpus.pairs[0])[0]
    artifact = world.fresh_runner().run(frozenset())
    first_read = artifact.state_read_log[0]
    for forged in (
        replace(artifact, source_snapshot_digest="0" * _SHA256_HEX_LENGTH),
        replace(artifact, public_trace=canonical_json({"forged": True})),
        replace(artifact, terminal_state=canonical_json({"forged": True})),
        replace(
            artifact,
            state_read_log=(
                replace(first_read, value_digest="0" * _SHA256_HEX_LENGTH),
                *artifact.state_read_log[1:],
            ),
        ),
        replace(artifact, intervention_log=(world.template.refresh_atom,)),
    ):
        with pytest.raises(ValueError):
            world.validate_artifact(forged)


def test_validator_rejects_a_twin_log_after_snapshot_rebinding(
    corpus: Workspace100Corpus,
) -> None:
    left, right = workspace100_pair_worlds(corpus.pairs[0])
    left_artifact = left.fresh_runner().run(frozenset())
    right_artifact = right.fresh_runner().run(frozenset())
    transplant = replace(
        right_artifact,
        source_snapshot_digest=left.source_snapshot_digest,
    )

    assert left_artifact.public_trace == transplant.public_trace
    assert left_artifact.terminal_state == transplant.terminal_state
    assert left_artifact.state_read_log != transplant.state_read_log
    with pytest.raises(ValueError, match="contradicts the sealed"):
        left.validate_artifact(transplant)


def test_every_runtime_artifact_rejects_all_top_level_surface_forgeries(
    corpus: Workspace100Corpus,
) -> None:
    artifact_count = 0
    rejection_count = 0
    for pair in corpus.pairs:
        for world in workspace100_pair_worlds(pair):
            atom_names = tuple(atom.name for atom in world.atoms)
            intervention_subsets: tuple[frozenset[str], ...] = (
                frozenset(),
                frozenset((atom_names[0],)),
                frozenset((atom_names[1],)),
                frozenset(atom_names),
            )
            for interventions in intervention_subsets:
                artifact = world.fresh_runner().run(interventions)
                first_read = artifact.state_read_log[0]
                toggled = interventions ^ frozenset((atom_names[0],))
                for forged in (
                    replace(
                        artifact,
                        source_snapshot_digest="0" * _SHA256_HEX_LENGTH,
                    ),
                    replace(
                        artifact,
                        public_trace=canonical_json({"forged": True}),
                    ),
                    replace(
                        artifact,
                        terminal_state=canonical_json(
                            {
                                "resolved_concrete_id": "forged_concrete_id",
                                "success": False,
                            }
                        ),
                    ),
                    replace(
                        artifact,
                        state_read_log=(
                            replace(
                                first_read,
                                value_digest="0" * _SHA256_HEX_LENGTH,
                            ),
                            *artifact.state_read_log[1:],
                        ),
                    ),
                    replace(
                        artifact,
                        intervention_log=tuple(sorted(toggled)),
                    ),
                ):
                    with pytest.raises(ValueError):
                        world.validate_artifact(forged)
                    rejection_count += 1
                artifact_count += 1

    assert artifact_count == _ARTIFACT_COUNT
    assert rejection_count == _ARTIFACT_COUNT * _FORGERIES_PER_ARTIFACT


def test_each_template_rejects_closed_trace_terminal_and_read_log_splices(
    corpus: Workspace100Corpus,
) -> None:
    representative_pairs = corpus.pairs[::10]

    for pair in representative_pairs:
        world = workspace100_pair_worlds(pair)[0]
        artifact = world.fresh_runner().run(frozenset())
        trace = cast(dict[str, object], json.loads(artifact.public_trace))
        forged_traces: list[bytes] = []

        payload = deepcopy(trace)
        payload["unknown_field"] = "forged"
        forged_traces.append(canonical_json(cast(JsonValue, payload)))

        payload = deepcopy(trace)
        del payload["terminal"]
        forged_traces.append(canonical_json(cast(JsonValue, payload)))

        payload = deepcopy(trace)
        payload["task"] = "Perform an unrelated workspace operation."
        forged_traces.append(canonical_json(cast(JsonValue, payload)))

        payload = deepcopy(trace)
        payload["terminal"] = world.template.terminal_success
        forged_traces.append(canonical_json(cast(JsonValue, payload)))

        payload = deepcopy(trace)
        payload["interventions"] = [world.template.refresh_atom]
        forged_traces.append(canonical_json(cast(JsonValue, payload)))

        for event_index, field, value in (
            (0, "tool", "forged_lookup"),
            (1, "tool", "forged_action"),
        ):
            payload = deepcopy(trace)
            events = cast(list[dict[str, object]], payload["events"])
            events[event_index][field] = value
            forged_traces.append(canonical_json(cast(JsonValue, payload)))

        for event_index, section, field, value in (
            (0, "arguments", "workspace", "forged_workspace"),
            (0, "result", "concrete_id", "forged_concrete_id"),
            (1, "arguments", "subject_id", "forged_subject"),
            (1, "result", "status", "forged_status"),
        ):
            payload = deepcopy(trace)
            events = cast(list[dict[str, object]], payload["events"])
            nested = cast(dict[str, object], events[event_index][section])
            nested[field] = value
            forged_traces.append(canonical_json(cast(JsonValue, payload)))

        for forged_trace in forged_traces:
            with pytest.raises(ValueError, match="contradicts the sealed"):
                world.validate_artifact(replace(artifact, public_trace=forged_trace))

        terminal = cast(dict[str, object], json.loads(artifact.terminal_state))
        forged_terminals: list[bytes] = []
        terminal_mutations: tuple[tuple[str, object], ...] = (
            ("resolved_concrete_id", "forged_concrete_id"),
            ("success", True),
            ("unknown_field", "forged"),
        )
        for terminal_field, terminal_value in terminal_mutations:
            payload = deepcopy(terminal)
            payload[terminal_field] = terminal_value
            forged_terminals.append(canonical_json(cast(JsonValue, payload)))
        payload = deepcopy(terminal)
        del payload["resolved_concrete_id"]
        forged_terminals.append(canonical_json(cast(JsonValue, payload)))

        for forged_terminal in forged_terminals:
            with pytest.raises(ValueError, match="contradicts the sealed"):
                world.validate_artifact(replace(artifact, terminal_state=forged_terminal))

        first, second = artifact.state_read_log
        extra = StateRead(
            sequence=2,
            channel=world.template.selection_channel,
            value_digest=first.value_digest,
        )
        forged_logs = (
            (first,),
            (*artifact.state_read_log, extra),
            (
                replace(second, sequence=0),
                replace(first, sequence=1),
            ),
            (
                replace(first, channel=world.template.resolver_channel),
                second,
            ),
            (
                replace(first, channel="undeclared_channel"),
                second,
            ),
        )
        for forged_log in forged_logs:
            with pytest.raises(ValueError, match="contradicts the sealed"):
                world.validate_artifact(replace(artifact, state_read_log=forged_log))


def test_artifact_validator_rejects_undeclared_interventions(
    corpus: Workspace100Corpus,
) -> None:
    world = workspace100_pair_worlds(corpus.pairs[0])[0]
    artifact = world.fresh_runner().run(frozenset())
    forged = replace(artifact, intervention_log=("unregistered_action",))

    with pytest.raises(ValueError, match="unknown interventions"):
        world.validate_artifact(forged)


def test_adapter_rejects_structurally_valid_but_unauthored_sources(
    corpus: Workspace100Corpus,
) -> None:
    completion = corpus.completions[0]
    adapter = Workspace100SourceAdapter()
    drifted_record = replace(
        completion.record,
        public_task=f"{completion.record.public_task} Skip the approval queue.",
    )
    drifted_source = SealedWorldSource(
        source_bytes=drifted_record.to_canonical_bytes(),
        commitment_salt=completion.source.commitment_salt,
    )
    unknown_record = replace(
        completion.record,
        variant_id="v99",
    )
    unknown_source = SealedWorldSource(
        source_bytes=unknown_record.to_canonical_bytes(),
        commitment_salt=completion.source.commitment_salt,
    )

    with pytest.raises(ValueError, match="differs from its frozen authored record"):
        adapter.decode(drifted_source)
    with pytest.raises(ValueError, match="outside the frozen authored catalog"):
        adapter.decode(unknown_source)


def test_adapter_rejects_noncanonical_and_inexact_sources(
    corpus: Workspace100Corpus,
) -> None:
    source = corpus.sources[0]
    adapter = Workspace100SourceAdapter()
    noncanonical = replace(source, source_bytes=source.source_bytes + b" ")

    with pytest.raises(ValueError, match="canonical"):
        adapter.decode(noncanonical)
    with pytest.raises(TypeError, match="exact SealedWorldSource"):
        adapter.decode(cast(SealedWorldSource, object()))


def test_runtime_trace_is_closed_canonical_json(
    corpus: Workspace100Corpus,
) -> None:
    world = workspace100_pair_worlds(corpus.pairs[0])[0]
    artifact = world.fresh_runner().run(frozenset())
    payload = cast(JsonValue, json.loads(artifact.public_trace))

    assert canonical_json(payload) == artifact.public_trace
    assert tuple(read.sequence for read in artifact.state_read_log) == (0, 1)
    assert all(type(read) is StateRead for read in artifact.state_read_log)
    assert type(artifact) is ExecutionArtifact


def test_pair_world_helper_requires_an_exact_generated_pair() -> None:
    with pytest.raises(TypeError, match="exact GeneratedPair"):
        workspace100_pair_worlds(cast(GeneratedPair, object()))


def test_unknown_probes_fail_closed(corpus: Workspace100Corpus) -> None:
    world: Workspace100World = workspace100_pair_worlds(corpus.pairs[0])[0]

    with pytest.raises(KeyError):
        world.probe("hidden_target")
