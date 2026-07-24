from __future__ import annotations

from dataclasses import dataclass

import pytest

from witnessgap.identifiability import (
    CandidateRegistry,
    Evidence,
    EvidenceMismatchError,
    InterventionObservation,
    ProbeObservation,
    RegistryError,
    VerdictKind,
)
from witnessgap.model import InterventionAtom, Outcome, ReplayResult
from witnessgap.oracle import enumerate_repair_panel
from witnessgap.worlds.workspace import workspace_twins


def test_workspace_twins_force_unknown_from_the_trace_alone() -> None:
    registry = CandidateRegistry.build(workspace_twins())
    evidence = registry.observe("workspace_environment")

    verdict = registry.attribute(evidence)

    assert verdict.kind is VerdictKind.NOT_IDENTIFIABLE
    assert verdict.compatible_world_ids == ("workspace_environment", "workspace_policy")
    assert verdict.ambiguity is not None
    assert verdict.ambiguity.left_target_family == (("environment",),)
    assert verdict.ambiguity.right_target_family == (("policy",),)


def test_workspace_twins_replay_the_same_failure_but_different_repairs() -> None:
    environment, policy = workspace_twins()
    environment_panel = enumerate_repair_panel(environment)
    policy_panel = enumerate_repair_panel(policy)

    assert (
        environment_panel.receipt_for(()).result.public_trace
        == policy_panel.receipt_for(()).result.public_trace
    )
    assert environment_panel.receipt_for(("refresh_draft_store",)).result.outcome is Outcome.SUCCESS
    assert (
        environment_panel.receipt_for(("repair_draft_selection",)).result.outcome is Outcome.FAILURE
    )
    assert policy_panel.receipt_for(("refresh_draft_store",)).result.outcome is Outcome.FAILURE
    assert policy_panel.receipt_for(("repair_draft_selection",)).result.outcome is Outcome.SUCCESS


@pytest.mark.parametrize(
    ("world_id", "target"),
    [
        ("workspace_environment", "environment"),
        ("workspace_policy", "policy"),
    ],
)
def test_informative_probe_turns_unknown_into_identified(world_id: str, target: str) -> None:
    registry = CandidateRegistry.build(workspace_twins())
    evidence = registry.observe(world_id, probes=("draft_store_epoch",))

    verdict = registry.attribute(evidence)

    assert verdict.kind is VerdictKind.IDENTIFIED_SINGLETON
    assert verdict.compatible_world_ids == (world_id,)
    assert verdict.target_family == ((target,),)


@pytest.mark.parametrize(
    ("world_id", "intervention", "target"),
    [
        ("workspace_environment", ("refresh_draft_store",), "environment"),
        ("workspace_policy", ("repair_draft_selection",), "policy"),
    ],
)
def test_informative_replay_turns_unknown_into_identified(
    world_id: str,
    intervention: tuple[str, ...],
    target: str,
) -> None:
    registry = CandidateRegistry.build(workspace_twins())
    evidence = registry.observe(world_id, interventions=(intervention,))

    verdict = registry.attribute(evidence)

    assert verdict.kind is VerdictKind.IDENTIFIED_SINGLETON
    assert verdict.compatible_world_ids == (world_id,)
    assert verdict.target_family == ((target,),)


def test_uninformative_replay_preserves_ambiguity() -> None:
    registry = CandidateRegistry.build(workspace_twins())
    evidence = registry.observe(
        "workspace_environment",
        interventions=(("refresh_draft_store", "repair_draft_selection"),),
    )

    verdict = registry.attribute(evidence)

    assert verdict.kind is VerdictKind.NOT_IDENTIFIABLE
    assert len(verdict.compatible_world_ids) == len(workspace_twins())


def test_irrelevant_probe_preserves_ambiguity() -> None:
    registry = CandidateRegistry.build(workspace_twins())
    evidence = registry.observe("workspace_environment", probes=("workspace_owner",))

    verdict = registry.attribute(evidence)

    assert verdict.kind is VerdictKind.NOT_IDENTIFIABLE
    assert len(verdict.compatible_world_ids) == len(workspace_twins())


def test_rejects_evidence_outside_the_declared_world_family() -> None:
    registry = CandidateRegistry.build(workspace_twins())
    evidence = Evidence(
        public_trace=b"unregistered trace\n",
        outcome=Outcome.FAILURE,
    )

    with pytest.raises(EvidenceMismatchError):
        registry.attribute(evidence)


def test_rejects_an_unknown_or_unsorted_probe_request() -> None:
    registry = CandidateRegistry.build(workspace_twins())

    with pytest.raises(KeyError, match="unknown_probe"):
        registry.observe("workspace_policy", probes=("unknown_probe",))
    with pytest.raises(ValueError, match="sorted"):
        registry.observe(
            "workspace_policy",
            probes=("workspace_owner", "draft_store_epoch"),
        )


@dataclass(frozen=True)
class RegistryFixtureWorld:
    world_id: str
    probe_names: tuple[str, ...] = ()
    repair_mode: str = "singleton"

    @property
    def atoms(self) -> tuple[InterventionAtom, ...]:
        if self.repair_mode == "singleton":
            return (InterventionAtom(name="repair", target="tool"),)
        return (
            InterventionAtom(name="repair_environment", target="environment"),
            InterventionAtom(name="repair_tool", target="tool"),
        )

    def probe(self, name: str) -> bytes:
        raise KeyError(name)

    def replay(self, interventions: frozenset[str]) -> ReplayResult:
        if self.repair_mode == "compound":
            successful = interventions == {"repair_environment", "repair_tool"}
        elif self.repair_mode == "alternatives":
            successful = bool(interventions)
        else:
            successful = bool(interventions)
        return ReplayResult(
            public_trace=b"failed\n",
            outcome=Outcome.SUCCESS if successful else Outcome.FAILURE,
        )


def test_registry_requires_sorted_unique_worlds_and_probes() -> None:
    with pytest.raises(RegistryError, match="cannot be empty"):
        CandidateRegistry.build(())
    with pytest.raises(RegistryError, match="unique"):
        CandidateRegistry.build((RegistryFixtureWorld("same"), RegistryFixtureWorld("same")))
    with pytest.raises(RegistryError, match="sorted"):
        CandidateRegistry.build((RegistryFixtureWorld("z"), RegistryFixtureWorld("a")))
    with pytest.raises(RegistryError, match="probe names"):
        CandidateRegistry.build((RegistryFixtureWorld("a", ("z", "a")),))


def test_probe_values_are_part_of_evidence_identity() -> None:
    registry = CandidateRegistry.build(workspace_twins())
    genuine = registry.observe("workspace_policy", probes=("draft_store_epoch",))
    forged = Evidence(
        public_trace=genuine.public_trace,
        outcome=genuine.outcome,
        probes=(ProbeObservation("draft_store_epoch", b"not a registered observation"),),
    )

    with pytest.raises(EvidenceMismatchError):
        registry.attribute(forged)


def test_intervention_results_are_part_of_evidence_identity() -> None:
    registry = CandidateRegistry.build(workspace_twins())
    genuine = registry.observe(
        "workspace_policy",
        interventions=(("repair_draft_selection",),),
    )
    forged = Evidence(
        public_trace=genuine.public_trace,
        outcome=genuine.outcome,
        intervention_observations=(
            InterventionObservation(
                interventions=("repair_draft_selection",),
                public_trace=b"forged replay\n",
                outcome=Outcome.SUCCESS,
            ),
        ),
    )

    with pytest.raises(EvidenceMismatchError):
        registry.attribute(forged)


@pytest.mark.parametrize(
    ("mode", "kind"),
    [
        ("compound", VerdictKind.IDENTIFIED_COMPOUND),
        ("alternatives", VerdictKind.IDENTIFIED_EQUIVALENCE_CLASS),
    ],
)
def test_distinguishes_compound_from_alternative_repairs(
    mode: str,
    kind: VerdictKind,
) -> None:
    registry = CandidateRegistry.build((RegistryFixtureWorld("world", repair_mode=mode),))

    verdict = registry.attribute(registry.observe("world"))

    assert verdict.kind is kind
