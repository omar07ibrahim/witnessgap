from __future__ import annotations

import pytest

from witnessgap.canonical import canonical_json
from witnessgap.model import Outcome
from witnessgap.worlds.workspace import WorkspaceCause, WorkspaceWorld


def world(cause: WorkspaceCause) -> WorkspaceWorld:
    return WorkspaceWorld(cause)


@pytest.mark.parametrize("cause", list(WorkspaceCause))
def test_fresh_workspace_runners_are_byte_deterministic(cause: WorkspaceCause) -> None:
    source = world(cause)

    first = source.fresh_runner().run(frozenset())
    second = source.fresh_runner().run(frozenset())

    assert first == second
    assert source.evaluate_terminal(first.terminal_state) is Outcome.FAILURE


def test_workspace_runner_is_single_use() -> None:
    runner = world(WorkspaceCause.ENVIRONMENT).fresh_runner()
    runner.run(frozenset())

    with pytest.raises(RuntimeError, match="single-use"):
        runner.run(frozenset())


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
