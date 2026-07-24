from __future__ import annotations

from dataclasses import dataclass, field, replace

import pytest

from witnessgap.identifiability import CandidateRegistry, Evidence, VerdictKind
from witnessgap.model import ExecutionRunner, Outcome
from witnessgap.verifier import (
    VerificationError,
    evidence_digest,
    verify_registry_attribution,
    verify_world_panel,
)
from witnessgap.worlds.workspace import WorkspaceCause, WorkspaceWorld, workspace_twins


def world(cause: WorkspaceCause) -> WorkspaceWorld:
    return next(candidate for candidate in workspace_twins() if candidate.cause is cause)


def verify(evidence: Evidence) -> tuple[CandidateRegistry, object]:
    worlds = workspace_twins()
    registry = CandidateRegistry.build(worlds)
    verdict = verify_registry_attribution(
        worlds,
        manifest=registry.manifest,
        trusted_registry_digest=registry.manifest.digest,
        evidence=evidence,
    )
    return registry, verdict


def test_independent_verifier_reconstructs_the_ambiguity_witness() -> None:
    worlds = workspace_twins()
    registry = CandidateRegistry.build(worlds)
    evidence = registry.observe(world(WorkspaceCause.ENVIRONMENT).world_id)

    verified = verify_registry_attribution(
        worlds,
        manifest=registry.manifest,
        trusted_registry_digest=registry.manifest.digest,
        evidence=evidence,
    )

    assert verified.kind is VerdictKind.NOT_IDENTIFIABLE
    assert verified.target_family is None
    assert verified.ambiguity_commitments is not None
    assert set(verified.ambiguity_commitments) == {
        candidate.completion_commitment for candidate in worlds
    }
    assert verified.evidence_digest == evidence_digest(evidence)


@pytest.mark.parametrize(
    ("cause", "probe", "intervention", "target"),
    [
        (WorkspaceCause.ENVIRONMENT, "draft_store_epoch", None, "environment"),
        (WorkspaceCause.POLICY, "draft_store_epoch", None, "policy"),
        (
            WorkspaceCause.ENVIRONMENT,
            None,
            ("refresh_draft_store",),
            "environment",
        ),
        (
            WorkspaceCause.POLICY,
            None,
            ("repair_draft_selection",),
            "policy",
        ),
    ],
)
def test_independent_verifier_reconstructs_identified_views(
    cause: WorkspaceCause,
    probe: str | None,
    intervention: tuple[str, ...] | None,
    target: str,
) -> None:
    worlds = workspace_twins()
    registry = CandidateRegistry.build(worlds)
    evidence = registry.observe(
        world(cause).world_id,
        probes=(probe,) if probe is not None else (),
        interventions=(intervention,) if intervention is not None else (),
    )

    verified = verify_registry_attribution(
        worlds,
        manifest=registry.manifest,
        trusted_registry_digest=registry.manifest.digest,
        evidence=evidence,
    )

    assert verified.kind is VerdictKind.IDENTIFIED_SINGLETON
    assert verified.target_family == ((target,),)
    assert verified.compatible_completion_commitments == (world(cause).completion_commitment,)


@pytest.mark.parametrize(
    ("cause", "minimal_witness", "target"),
    [
        (
            WorkspaceCause.ENVIRONMENT,
            ("refresh_draft_store",),
            (("environment",),),
        ),
        (
            WorkspaceCause.POLICY,
            ("repair_draft_selection",),
            (("policy",),),
        ),
    ],
)
def test_verified_panel_contains_every_subset_and_raw_minimal_witness(
    cause: WorkspaceCause,
    minimal_witness: tuple[str, ...],
    target: tuple[tuple[str, ...], ...],
) -> None:
    source = world(cause)
    registry = CandidateRegistry.build(workspace_twins())

    panel = verify_world_panel(source, manifest=registry.manifest)

    assert len(panel.receipts) == 1 << len(source.atoms)
    assert panel.minimal_witnesses == (minimal_witness,)
    assert panel.target_family == target
    assert panel.receipt_for(()).outcome is Outcome.FAILURE


def test_solver_cache_mutation_cannot_change_the_verified_result() -> None:
    worlds = workspace_twins()
    registry = CandidateRegistry.build(worlds)
    evidence = registry.observe(world(WorkspaceCause.ENVIRONMENT).world_id)
    forged_candidates = tuple(
        replace(
            candidate,
            panel=replace(candidate.panel, target_family=(("forged_target",),)),
        )
        for candidate in registry.candidates
    )
    forged_registry = replace(registry, candidates=forged_candidates)

    forged_solver_verdict = forged_registry.attribute(evidence)
    verified = verify_registry_attribution(
        worlds,
        manifest=registry.manifest,
        trusted_registry_digest=registry.manifest.digest,
        evidence=evidence,
    )

    assert forged_solver_verdict.kind is VerdictKind.IDENTIFIED_SINGLETON
    assert forged_solver_verdict.target_family == (("forged_target",),)
    assert verified.kind is VerdictKind.NOT_IDENTIFIABLE


def test_verifier_requires_an_external_trust_anchor_and_complete_sources() -> None:
    worlds = workspace_twins()
    registry = CandidateRegistry.build(worlds)
    evidence = registry.observe(worlds[0].world_id)

    with pytest.raises(VerificationError, match="trusted digest"):
        verify_registry_attribution(
            worlds,
            manifest=registry.manifest,
            trusted_registry_digest="0" * 64,
            evidence=evidence,
        )
    with pytest.raises(VerificationError, match="exhaust"):
        verify_registry_attribution(
            (worlds[0],),
            manifest=registry.manifest,
            trusted_registry_digest=registry.manifest.digest,
            evidence=evidence,
        )


@dataclass
class ReusedRunnerWorld:
    source: WorkspaceWorld
    _runner: ExecutionRunner = field(init=False)

    def __post_init__(self) -> None:
        self._runner = self.source.fresh_runner()

    @property
    def world_id(self) -> str:
        return self.source.world_id

    @property
    def task_schema_id(self) -> str:
        return self.source.task_schema_id

    @property
    def task_id(self) -> str:
        return self.source.task_id

    @property
    def atoms(self) -> tuple[object, ...]:
        return self.source.atoms

    @property
    def probe_names(self) -> tuple[str, ...]:
        return self.source.probe_names

    @property
    def declared_state_channels(self) -> tuple[str, ...]:
        return self.source.declared_state_channels

    @property
    def completion_commitment(self) -> str:
        return self.source.completion_commitment

    @property
    def intervention_contract_digest(self) -> str:
        return self.source.intervention_contract_digest

    @property
    def probe_contract_digest(self) -> str:
        return self.source.probe_contract_digest

    def probe(self, name: str) -> bytes:
        return self.source.probe(name)

    def fresh_runner(self) -> ExecutionRunner:
        return self._runner

    def evaluate_terminal(self, terminal_state: bytes) -> Outcome:
        return self.source.evaluate_terminal(terminal_state)


def test_verifier_rejects_a_factory_that_reuses_runner_state() -> None:
    source = world(WorkspaceCause.ENVIRONMENT)
    registry = CandidateRegistry.build(workspace_twins())

    with pytest.raises(VerificationError, match="fresh replay failed"):
        verify_world_panel(ReusedRunnerWorld(source), manifest=registry.manifest)


def test_proof_roots_are_byte_deterministic() -> None:
    worlds = workspace_twins()
    registry = CandidateRegistry.build(worlds)
    evidence = registry.observe(worlds[0].world_id)

    first = verify_registry_attribution(
        worlds,
        manifest=registry.manifest,
        trusted_registry_digest=registry.manifest.digest,
        evidence=evidence,
    )
    second = verify_registry_attribution(
        worlds,
        manifest=registry.manifest,
        trusted_registry_digest=registry.manifest.digest,
        evidence=evidence,
    )

    assert first == second
