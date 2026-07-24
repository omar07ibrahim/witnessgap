from __future__ import annotations

from dataclasses import dataclass

import pytest

from witnessgap.model import InterventionAtom, Outcome, ReplayResult
from witnessgap.oracle import InvalidWorldError, enumerate_repair_panel


@dataclass(frozen=True)
class BooleanWorld:
    world_id: str
    atoms: tuple[InterventionAtom, ...]
    successful_sets: frozenset[frozenset[str]]
    baseline_outcome: Outcome = Outcome.FAILURE

    def replay(self, interventions: frozenset[str]) -> ReplayResult:
        outcome = (
            self.baseline_outcome
            if not interventions
            else Outcome.SUCCESS
            if interventions in self.successful_sets
            else Outcome.FAILURE
        )
        return ReplayResult(public_trace=b"same public trace", outcome=outcome)


def atom(name: str, target: str | None = None) -> InterventionAtom:
    return InterventionAtom(name=name, target=target or name)


def test_enumerates_a_compound_witness_and_every_subset() -> None:
    world = BooleanWorld(
        world_id="compound",
        atoms=(atom("environment"), atom("red_herring"), atom("tool")),
        successful_sets=frozenset(
            {
                frozenset({"environment", "tool"}),
                frozenset({"environment", "red_herring", "tool"}),
            }
        ),
    )

    panel = enumerate_repair_panel(world)

    assert len(panel.receipts) == 1 << len(world.atoms)
    assert panel.minimal_witnesses == (("environment", "tool"),)
    assert panel.target_family == (("environment", "tool"),)


def test_preserves_alternative_minimal_repairs() -> None:
    world = BooleanWorld(
        world_id="alternatives",
        atoms=(atom("repair_cache", "environment"), atom("repair_query", "policy")),
        successful_sets=frozenset(
            {
                frozenset({"repair_cache"}),
                frozenset({"repair_query"}),
                frozenset({"repair_cache", "repair_query"}),
            }
        ),
    )

    panel = enumerate_repair_panel(world)

    assert panel.minimal_witnesses == (("repair_cache",), ("repair_query",))
    assert panel.target_family == (("environment",), ("policy",))


def test_does_not_assume_success_is_monotonic() -> None:
    world = BooleanWorld(
        world_id="non_monotonic",
        atoms=(atom("first"), atom("second")),
        successful_sets=frozenset({frozenset({"first"})}),
    )

    panel = enumerate_repair_panel(world)

    assert panel.minimal_witnesses == (("first",),)
    assert panel.receipt_for(("first", "second")).result.outcome is Outcome.FAILURE


def test_rejects_a_successful_baseline() -> None:
    world = BooleanWorld(
        world_id="already_successful",
        atoms=(atom("tool"),),
        successful_sets=frozenset(),
        baseline_outcome=Outcome.SUCCESS,
    )

    with pytest.raises(InvalidWorldError, match="unmodified"):
        enumerate_repair_panel(world)


def test_rejects_duplicate_or_unsorted_atoms() -> None:
    duplicate = BooleanWorld(
        world_id="duplicate",
        atoms=(atom("tool"), atom("tool", "environment")),
        successful_sets=frozenset(),
    )
    unsorted = BooleanWorld(
        world_id="unsorted",
        atoms=(atom("tool"), atom("environment")),
        successful_sets=frozenset(),
    )

    with pytest.raises(InvalidWorldError, match="unique"):
        enumerate_repair_panel(duplicate)
    with pytest.raises(InvalidWorldError, match="sorted"):
        enumerate_repair_panel(unsorted)
