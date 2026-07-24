from __future__ import annotations

from dataclasses import replace

import pytest

from witnessgap.canonical import canonical_json
from witnessgap.model import Outcome
from witnessgap.worlds.workspace import (
    WorkspaceCause,
    WorkspaceSourceAdapter,
    WorkspaceWorld,
    workspace_source,
)


def world(cause: WorkspaceCause) -> WorkspaceWorld:
    return WorkspaceWorld(cause)


@pytest.mark.parametrize("cause", list(WorkspaceCause))
def test_fresh_workspace_runners_are_byte_deterministic(cause: WorkspaceCause) -> None:
    source = world(cause)

    first = source.fresh_runner().run(frozenset())
    second = source.fresh_runner().run(frozenset())

    assert first == second
    assert first.source_snapshot_digest == source.sealed_source.snapshot_digest
    assert source.evaluate_terminal(first.terminal_state) is Outcome.FAILURE


def test_workspace_runner_is_single_use() -> None:
    runner = world(WorkspaceCause.ENVIRONMENT).fresh_runner()
    runner.run(frozenset())

    with pytest.raises(RuntimeError, match="single-use"):
        runner.run(frozenset())


@pytest.mark.parametrize("cause", list(WorkspaceCause))
def test_workspace_source_round_trips_through_the_closed_decoder(
    cause: WorkspaceCause,
) -> None:
    source = workspace_source(cause)

    decoded = WorkspaceSourceAdapter().decode(source)

    assert decoded.cause is cause
    assert decoded.sealed_source is source
    assert decoded.completion_commitment == source.completion_commitment
    assert decoded.source_snapshot_digest == source.snapshot_digest


def test_hidden_read_logs_do_not_change_the_causal_twin_trace() -> None:
    environment = world(WorkspaceCause.ENVIRONMENT).fresh_runner().run(frozenset())
    policy = world(WorkspaceCause.POLICY).fresh_runner().run(frozenset())

    assert environment.public_trace == policy.public_trace
    assert environment.terminal_state == policy.terminal_state
    assert tuple(read.channel for read in environment.state_read_log) == (
        "policy_selection",
        "draft_store_epoch",
    )
    assert tuple(read.channel for read in policy.state_read_log) == ("policy_selection",)
    assert environment.state_read_log != policy.state_read_log


def test_runner_records_exactly_the_requested_interventions() -> None:
    requested = frozenset({"refresh_draft_store", "repair_draft_selection"})
    artifact = world(WorkspaceCause.ENVIRONMENT).fresh_runner().run(requested)

    assert artifact.intervention_log == (
        "refresh_draft_store",
        "repair_draft_selection",
    )
    assert (
        world(WorkspaceCause.ENVIRONMENT).evaluate_terminal(artifact.terminal_state)
        is Outcome.SUCCESS
    )
    assert world(WorkspaceCause.ENVIRONMENT).validate_artifact(artifact) is Outcome.SUCCESS


def test_artifact_validator_rejects_trace_terminal_split_brain() -> None:
    source = world(WorkspaceCause.POLICY)
    artifact = source.fresh_runner().run(frozenset())
    forged_terminal = canonical_json(
        {
            "approved_content_present": True,
            "published_document": "release-notes-v21",
        }
    )

    with pytest.raises(ValueError, match="source snapshot"):
        source.validate_artifact(replace(artifact, terminal_state=forged_terminal))


def test_artifact_validator_rejects_a_different_source_snapshot() -> None:
    environment_artifact = world(WorkspaceCause.ENVIRONMENT).fresh_runner().run(frozenset())

    with pytest.raises(ValueError, match="different source snapshot"):
        world(WorkspaceCause.POLICY).validate_artifact(environment_artifact)


def test_artifact_validator_rejects_a_forged_state_read_log() -> None:
    source = world(WorkspaceCause.ENVIRONMENT)
    artifact = source.fresh_runner().run(frozenset())

    with pytest.raises(ValueError, match="state-read log"):
        source.validate_artifact(replace(artifact, state_read_log=()))


@pytest.mark.parametrize(
    "terminal_state",
    [
        b'{"approved_content_present":false,"published_document":"release-notes-v17"}',
        canonical_json(
            {
                "approved_content_present": True,
                "published_document": "release-notes-v17",
            }
        ),
        canonical_json({"approved_content_present": False}),
    ],
)
def test_success_oracle_rejects_noncanonical_or_contradictory_state(
    terminal_state: bytes,
) -> None:
    source = world(WorkspaceCause.POLICY)

    with pytest.raises(ValueError, match="terminal state"):
        source.evaluate_terminal(terminal_state)
