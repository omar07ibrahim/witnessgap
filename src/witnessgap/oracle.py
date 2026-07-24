"""Exhaustive ground-truth oracle for bounded intervention algebras."""

from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations

from witnessgap.model import (
    FiniteWorld,
    Outcome,
    ReplayResult,
    TargetFamily,
    Witness,
    normalize_witness,
)

MAX_ATOMS = 12


class InvalidWorldError(ValueError):
    """Raised when a world violates the finite-oracle contract."""


class NonDeterministicWorldError(InvalidWorldError):
    """Raised when the same bounded replay produces different results."""


@dataclass(frozen=True, slots=True)
class ReplayReceipt:
    """The result of applying exactly one intervention subset."""

    interventions: Witness
    result: ReplayResult


@dataclass(frozen=True, slots=True)
class RepairPanel:
    """Complete replay panel and its inclusion-minimal successful subsets."""

    world_id: str
    atom_names: tuple[str, ...]
    receipts: tuple[ReplayReceipt, ...]
    minimal_witnesses: tuple[Witness, ...]
    target_family: TargetFamily

    def receipt_for(self, interventions: Witness) -> ReplayReceipt:
        """Return the exact receipt for a canonical intervention tuple."""

        if interventions != tuple(sorted(interventions)):
            raise ValueError("interventions must be sorted")
        for receipt in self.receipts:
            if receipt.interventions == interventions:
                return receipt
        raise KeyError(interventions)


def enumerate_repair_panel(world: FiniteWorld) -> RepairPanel:
    """Replay every subset and derive all inclusion-minimal repairs.

    Every one of the ``2**n`` subsets is executed. In particular, a successful
    subset does not prune its supersets: the world contract does not assume
    monotonic repair effects.
    """

    world_id = world.world_id
    atoms = world.atoms
    if not isinstance(atoms, tuple):
        raise InvalidWorldError("intervention atoms must be a tuple")
    if len(atoms) > MAX_ATOMS:
        raise InvalidWorldError(f"intervention algebra exceeds the {MAX_ATOMS}-atom bound")

    atom_names = tuple(atom.name for atom in atoms)
    if len(set(atom_names)) != len(atom_names):
        raise InvalidWorldError("intervention atom names must be unique")
    if atom_names != tuple(sorted(atom_names)):
        raise InvalidWorldError("intervention atoms must be sorted by name")

    atom_targets = {atom.name: atom.target for atom in atoms}
    receipts: list[ReplayReceipt] = []
    successful: list[frozenset[str]] = []

    for size in range(len(atom_names) + 1):
        for selected in combinations(atom_names, size):
            intervention_set = frozenset(selected)
            result = world.replay(intervention_set)
            repeated_result = world.replay(intervention_set)
            if result != repeated_result:
                raise NonDeterministicWorldError(
                    f"{world_id}: replay diverged for {normalize_witness(intervention_set)!r}"
                )
            canonical = normalize_witness(intervention_set)
            receipts.append(ReplayReceipt(interventions=canonical, result=result))
            if result.outcome is Outcome.SUCCESS:
                successful.append(intervention_set)

    if receipts[0].result.outcome is not Outcome.FAILURE:
        raise InvalidWorldError("the unmodified benchmark episode must fail")

    minimal = tuple(
        normalize_witness(candidate)
        for candidate in successful
        if not any(other < candidate for other in successful)
    )
    projected_targets = {frozenset(atom_targets[name] for name in witness) for witness in minimal}
    minimal_targets = {
        targets
        for targets in projected_targets
        if not any(other < targets for other in projected_targets)
    }
    target_family = tuple(sorted(tuple(sorted(targets)) for targets in minimal_targets))
    if world.atoms != atoms:
        raise NonDeterministicWorldError(f"{world_id}: intervention algebra changed during replay")
    if world.world_id != world_id:
        raise NonDeterministicWorldError(f"{world_id}: world ID changed during replay")

    return RepairPanel(
        world_id=world_id,
        atom_names=atom_names,
        receipts=tuple(receipts),
        minimal_witnesses=minimal,
        target_family=target_family,
    )
