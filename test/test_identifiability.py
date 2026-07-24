from __future__ import annotations

from dataclasses import dataclass, replace

import pytest

from witnessgap.canonical import JsonValue, canonical_digest
from witnessgap.identifiability import (
    CandidateRegistry,
    Evidence,
    EvidenceMismatchError,
    InterventionObservation,
    ProbeObservation,
    RegistryError,
    UnknownReason,
    VerdictKind,
)
from witnessgap.model import InterventionAtom, Outcome, ReplayResult
from witnessgap.oracle import enumerate_repair_panel
from witnessgap.worlds.workspace import WorkspaceCause, WorkspaceWorld, workspace_twins


def workspace_world(cause: WorkspaceCause) -> WorkspaceWorld:
    return next(world for world in workspace_twins() if world.cause is cause)


def test_workspace_twins_force_unknown_from_the_trace_alone() -> None:
    worlds = workspace_twins()
    registry = CandidateRegistry.build(worlds)
    evidence = registry.observe(workspace_world(WorkspaceCause.ENVIRONMENT).world_id)

    verdict = registry.attribute(evidence)

    assert verdict.kind is VerdictKind.NOT_IDENTIFIABLE
    assert verdict.compatible_world_ids == tuple(world.world_id for world in worlds)
    assert verdict.ambiguity is not None
    assert {
        verdict.ambiguity.left_target_family,
        verdict.ambiguity.right_target_family,
    } == {(("environment",),), (("policy",),)}


def test_workspace_twins_replay_the_same_failure_but_different_repairs() -> None:
    environment = workspace_world(WorkspaceCause.ENVIRONMENT)
    policy = workspace_world(WorkspaceCause.POLICY)
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
    ("cause", "target"),
    [
        (WorkspaceCause.ENVIRONMENT, "environment"),
        (WorkspaceCause.POLICY, "policy"),
    ],
)
def test_informative_probe_turns_unknown_into_identified(
    cause: WorkspaceCause,
    target: str,
) -> None:
    registry = CandidateRegistry.build(workspace_twins())
    world_id = workspace_world(cause).world_id
    evidence = registry.observe(world_id, probes=("draft_store_epoch",))

    verdict = registry.attribute(evidence)

    assert verdict.kind is VerdictKind.IDENTIFIED_SINGLETON
    assert verdict.compatible_world_ids == (world_id,)
    assert verdict.target_family == ((target,),)


@pytest.mark.parametrize(
    ("cause", "intervention", "target"),
    [
        (WorkspaceCause.ENVIRONMENT, ("refresh_draft_store",), "environment"),
        (WorkspaceCause.POLICY, ("repair_draft_selection",), "policy"),
    ],
)
def test_informative_replay_turns_unknown_into_identified(
    cause: WorkspaceCause,
    intervention: tuple[str, ...],
    target: str,
) -> None:
    registry = CandidateRegistry.build(workspace_twins())
    world_id = workspace_world(cause).world_id
    evidence = registry.observe(world_id, interventions=(intervention,))

    verdict = registry.attribute(evidence)

    assert verdict.kind is VerdictKind.IDENTIFIED_SINGLETON
    assert verdict.compatible_world_ids == (world_id,)
    assert verdict.target_family == ((target,),)


def test_uninformative_replay_preserves_ambiguity() -> None:
    registry = CandidateRegistry.build(workspace_twins())
    evidence = registry.observe(
        workspace_world(WorkspaceCause.ENVIRONMENT).world_id,
        interventions=(("refresh_draft_store", "repair_draft_selection"),),
    )

    verdict = registry.attribute(evidence)

    assert verdict.kind is VerdictKind.NOT_IDENTIFIABLE
    assert len(verdict.compatible_world_ids) == len(workspace_twins())


def test_irrelevant_probe_preserves_ambiguity() -> None:
    registry = CandidateRegistry.build(workspace_twins())
    evidence = registry.observe(
        workspace_world(WorkspaceCause.ENVIRONMENT).world_id,
        probes=("workspace_owner",),
    )

    verdict = registry.attribute(evidence)

    assert verdict.kind is VerdictKind.NOT_IDENTIFIABLE
    assert len(verdict.compatible_world_ids) == len(workspace_twins())


def test_rejects_evidence_outside_the_declared_world_family() -> None:
    registry = CandidateRegistry.build(workspace_twins())
    evidence = Evidence(
        registry_digest=registry.manifest.digest,
        coverage_manifest_digest=registry.manifest.coverage_digest,
        public_trace=b"unregistered trace\n",
        outcome=Outcome.FAILURE,
    )

    with pytest.raises(EvidenceMismatchError):
        registry.attribute(evidence)


def test_rejects_an_unknown_or_unsorted_probe_request() -> None:
    registry = CandidateRegistry.build(workspace_twins())
    policy_id = workspace_world(WorkspaceCause.POLICY).world_id

    with pytest.raises(KeyError, match="unknown_probe"):
        registry.observe(policy_id, probes=("unknown_probe",))
    with pytest.raises(ValueError, match="sorted"):
        registry.observe(
            policy_id,
            probes=("workspace_owner", "draft_store_epoch"),
        )


@dataclass(frozen=True)
class RegistryFixtureWorld:
    world_id: str
    probe_names: tuple[str, ...] = ()
    repair_mode: str = "singleton"
    task_schema_id: str = "registry_fixture_v1"
    task_id: str = "registry_fixture_task"
    declared_state_channels: tuple[str, ...] = ()
    state_reads: tuple[str, ...] = ()
    intervention_contract_version: str = "fixture_interventions_v1"
    probe_contract_version: str = "fixture_probes_v1"

    @property
    def completion_commitment(self) -> str:
        payload: dict[str, JsonValue] = {
            "repair_mode": self.repair_mode,
            "state_reads": self.state_reads,
            "world_id": self.world_id,
        }
        return canonical_digest("witnessgap.test-completion.v1", payload)

    @property
    def intervention_contract_digest(self) -> str:
        return canonical_digest(
            "witnessgap.intervention-contract.v1",
            {"version": self.intervention_contract_version},
        )

    @property
    def probe_contract_digest(self) -> str:
        return canonical_digest(
            "witnessgap.probe-contract.v1",
            {"version": self.probe_contract_version},
        )

    @property
    def atoms(self) -> tuple[InterventionAtom, ...]:
        if self.repair_mode == "singleton":
            return (InterventionAtom(name="repair", target="tool"),)
        return (
            InterventionAtom(name="repair_environment", target="environment"),
            InterventionAtom(name="repair_tool", target="tool"),
        )

    def probe(self, name: str) -> bytes:
        if name not in self.probe_names:
            raise KeyError(name)
        return b"same probe result\n"

    def replay(self, interventions: frozenset[str]) -> ReplayResult:
        if self.repair_mode == "compound":
            successful = interventions == {"repair_environment", "repair_tool"}
        elif self.repair_mode == "alternatives":
            successful = bool(interventions)
        elif self.repair_mode == "never":
            successful = False
        else:
            successful = bool(interventions)
        return ReplayResult(
            public_trace=b"failed\n",
            outcome=Outcome.SUCCESS if successful else Outcome.FAILURE,
            state_reads=self.state_reads,
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
    with pytest.raises(RegistryError, match="state channels"):
        CandidateRegistry.build((RegistryFixtureWorld("a", declared_state_channels=("z", "a")),))


def test_registry_rejects_candidate_specific_contracts() -> None:
    reference = RegistryFixtureWorld("a")
    mismatches = (
        replace(RegistryFixtureWorld("b"), task_schema_id="other_schema"),
        replace(RegistryFixtureWorld("b"), task_id="other_task"),
        replace(RegistryFixtureWorld("b"), repair_mode="compound"),
        replace(RegistryFixtureWorld("b"), probe_names=("diagnostic",)),
        replace(
            RegistryFixtureWorld("b"),
            declared_state_channels=("declared_channel",),
        ),
        replace(
            RegistryFixtureWorld("b"),
            intervention_contract_version="fixture_interventions_v2",
        ),
        replace(
            RegistryFixtureWorld("b"),
            probe_contract_version="fixture_probes_v2",
        ),
    )

    for mismatch in mismatches:
        with pytest.raises(RegistryError, match="share one"):
            CandidateRegistry.build((reference, mismatch))


def test_registry_rejects_reads_outside_the_public_coverage_contract() -> None:
    world = RegistryFixtureWorld("world", state_reads=("hidden_channel",))

    with pytest.raises(RegistryError, match="undeclared state"):
        CandidateRegistry.build((world,))


def test_sealed_read_logs_do_not_split_publicly_compatible_worlds() -> None:
    declared = ("first_channel", "second_channel")
    worlds = (
        RegistryFixtureWorld(
            "a",
            declared_state_channels=declared,
            state_reads=("first_channel",),
        ),
        RegistryFixtureWorld(
            "b",
            declared_state_channels=declared,
            state_reads=("second_channel",),
        ),
    )
    registry = CandidateRegistry.build(worlds)

    verdict = registry.attribute(registry.observe("a"))

    assert verdict.kind is VerdictKind.IDENTIFIED_SINGLETON
    assert verdict.compatible_world_ids == ("a", "b")


def test_manifest_binds_evidence_and_the_declared_candidate_family() -> None:
    worlds = workspace_twins()
    registry = CandidateRegistry.build(worlds)
    evidence = registry.observe(worlds[0].world_id)
    verdict = registry.attribute(evidence)

    assert evidence.registry_digest == registry.manifest.digest
    assert evidence.coverage_manifest_digest == registry.manifest.coverage_digest
    assert verdict.registry_digest == registry.manifest.digest
    assert registry.manifest.candidate_commitments == tuple(
        sorted(world.completion_commitment for world in worlds)
    )
    assert CandidateRegistry.build(worlds).manifest.digest == registry.manifest.digest

    forged = replace(evidence, registry_digest="0" * 64)
    with pytest.raises(EvidenceMismatchError, match="registry manifest"):
        registry.attribute(forged)


def test_workspace_completion_ids_are_opaque() -> None:
    for world in workspace_twins():
        assert world.world_id.startswith("wgc_")
        assert world.world_id.removeprefix("wgc_") == world.completion_commitment[:24]
        assert WorkspaceCause.ENVIRONMENT.value not in world.world_id
        assert WorkspaceCause.POLICY.value not in world.world_id


def test_probe_values_are_part_of_evidence_identity() -> None:
    registry = CandidateRegistry.build(workspace_twins())
    genuine = registry.observe(
        workspace_world(WorkspaceCause.POLICY).world_id,
        probes=("draft_store_epoch",),
    )
    forged = Evidence(
        registry_digest=genuine.registry_digest,
        coverage_manifest_digest=genuine.coverage_manifest_digest,
        public_trace=genuine.public_trace,
        outcome=genuine.outcome,
        probes=(ProbeObservation("draft_store_epoch", b"not a registered observation"),),
    )

    with pytest.raises(EvidenceMismatchError):
        registry.attribute(forged)


def test_intervention_results_are_part_of_evidence_identity() -> None:
    registry = CandidateRegistry.build(workspace_twins())
    genuine = registry.observe(
        workspace_world(WorkspaceCause.POLICY).world_id,
        interventions=(("repair_draft_selection",),),
    )
    forged = Evidence(
        registry_digest=genuine.registry_digest,
        coverage_manifest_digest=genuine.coverage_manifest_digest,
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
        ("alternatives", VerdictKind.ALTERNATIVE_MINIMAL_REPAIRS),
    ],
)
def test_distinguishes_compound_from_alternative_repairs(
    mode: str,
    kind: VerdictKind,
) -> None:
    registry = CandidateRegistry.build((RegistryFixtureWorld("world", repair_mode=mode),))

    verdict = registry.attribute(registry.observe("world"))

    assert verdict.kind is kind


def test_reports_when_the_declared_algebra_contains_no_repair() -> None:
    world = RegistryFixtureWorld("world", repair_mode="never")
    registry = CandidateRegistry.build((world,))

    verdict = registry.attribute(registry.observe(world.world_id))

    assert verdict.kind is VerdictKind.NOT_IDENTIFIABLE
    assert verdict.unknown_reason is UnknownReason.NO_REPAIR_IN_DECLARED_ALGEBRA
