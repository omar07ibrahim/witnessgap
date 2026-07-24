from __future__ import annotations

import json
from dataclasses import replace
from typing import cast

import pytest

from witnessgap.canonical import JsonValue, canonical_json
from witnessgap.identifiability import (
    CandidateRegistry,
    Evidence,
    ProbeObservation,
    VerdictKind,
)
from witnessgap.model import Outcome
from witnessgap.source import SealedWorldSource
from witnessgap.verifier import (
    VerificationError,
    VerifiedAttribution,
    evidence_digest,
    trust_anchor_for_manifest,
    verify_attribution_certificate,
    verify_registry_attribution,
    verify_source_panel,
)
from witnessgap.worlds.workspace import (
    WorkspaceCause,
    WorkspaceWorld,
    workspace_source,
    workspace_sources,
    workspace_twins,
)


def world(cause: WorkspaceCause) -> WorkspaceWorld:
    return next(candidate for candidate in workspace_twins() if candidate.cause is cause)


def verify(evidence: Evidence) -> tuple[CandidateRegistry, object]:
    worlds = workspace_twins()
    registry = CandidateRegistry.build(worlds)
    verdict = verify_registry_attribution(
        workspace_sources(),
        manifest=registry.manifest,
        trust_anchor=trust_anchor_for_manifest(registry.manifest),
        evidence=evidence,
    )
    return registry, verdict


def test_independent_verifier_reconstructs_the_ambiguity_witness() -> None:
    worlds = workspace_twins()
    registry = CandidateRegistry.build(worlds)
    evidence = registry.observe(world(WorkspaceCause.ENVIRONMENT).world_id)

    verified = verify_registry_attribution(
        workspace_sources(),
        manifest=registry.manifest,
        trust_anchor=trust_anchor_for_manifest(registry.manifest),
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
        workspace_sources(),
        manifest=registry.manifest,
        trust_anchor=trust_anchor_for_manifest(registry.manifest),
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
    source = workspace_source(cause)
    registry = CandidateRegistry.build(workspace_twins())

    panel = verify_source_panel(source, manifest=registry.manifest)

    assert len(panel.receipts) == 1 << len(registry.manifest.atoms)
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
        workspace_sources(),
        manifest=registry.manifest,
        trust_anchor=trust_anchor_for_manifest(registry.manifest),
        evidence=evidence,
    )

    assert forged_solver_verdict.kind is VerdictKind.IDENTIFIED_SINGLETON
    assert forged_solver_verdict.target_family == (("forged_target",),)
    assert verified.kind is VerdictKind.NOT_IDENTIFIABLE


def test_verifier_requires_an_external_trust_anchor_and_complete_sources() -> None:
    worlds = workspace_twins()
    registry = CandidateRegistry.build(worlds)
    evidence = registry.observe(worlds[0].world_id)
    genuine_anchor = trust_anchor_for_manifest(registry.manifest)

    with pytest.raises(VerificationError, match="trust anchor"):
        verify_registry_attribution(
            workspace_sources(),
            manifest=registry.manifest,
            trust_anchor=replace(genuine_anchor, registry_digest="0" * 64),
            evidence=evidence,
        )
    with pytest.raises(VerificationError, match="exhaust"):
        verify_registry_attribution(
            (workspace_sources()[0],),
            manifest=registry.manifest,
            trust_anchor=trust_anchor_for_manifest(registry.manifest),
            evidence=evidence,
        )


def test_verifier_rejects_executable_world_objects_at_the_input_boundary() -> None:
    worlds = workspace_twins()
    registry = CandidateRegistry.build(worlds)
    evidence = registry.observe(worlds[0].world_id)

    with pytest.raises(VerificationError, match="exact SealedWorldSource"):
        verify_registry_attribution(
            cast(tuple[SealedWorldSource, ...], worlds),
            manifest=registry.manifest,
            trust_anchor=trust_anchor_for_manifest(registry.manifest),
            evidence=evidence,
        )


def test_source_byte_mutation_breaks_the_committed_candidate_family() -> None:
    worlds = workspace_twins()
    registry = CandidateRegistry.build(worlds)
    evidence = registry.observe(worlds[0].world_id)
    sources = workspace_sources()
    mutated = replace(sources[0], source_bytes=sources[0].source_bytes + b" ")

    with pytest.raises(VerificationError, match="exhaust"):
        verify_registry_attribution(
            (mutated, sources[1]),
            manifest=registry.manifest,
            trust_anchor=trust_anchor_for_manifest(registry.manifest),
            evidence=evidence,
        )


def test_verifier_rejects_an_adapter_not_in_its_internal_trust_store() -> None:
    worlds = workspace_twins()
    registry = CandidateRegistry.build(worlds)
    forged_manifest = replace(registry.manifest, adapter_id="forged_workspace_adapter")
    evidence = replace(
        registry.observe(worlds[0].world_id),
        registry_digest=forged_manifest.digest,
    )
    forged_anchor = replace(
        trust_anchor_for_manifest(registry.manifest),
        registry_digest=forged_manifest.digest,
    )

    with pytest.raises(VerificationError, match="not trusted"):
        verify_registry_attribution(
            workspace_sources(),
            manifest=forged_manifest,
            trust_anchor=forged_anchor,
            evidence=evidence,
        )


def test_verifier_rejects_an_untrusted_adapter_implementation_digest() -> None:
    worlds = workspace_twins()
    registry = CandidateRegistry.build(worlds)
    forged_manifest = replace(
        registry.manifest,
        adapter_implementation_digest="0" * 64,
    )
    evidence = replace(
        registry.observe(worlds[0].world_id),
        registry_digest=forged_manifest.digest,
    )
    forged_anchor = replace(
        trust_anchor_for_manifest(registry.manifest),
        registry_digest=forged_manifest.digest,
        adapter_implementation_digest=forged_manifest.adapter_implementation_digest,
    )

    with pytest.raises(VerificationError, match="installed adapter implementation"):
        verify_registry_attribution(
            workspace_sources(),
            manifest=forged_manifest,
            trust_anchor=forged_anchor,
            evidence=evidence,
        )


def test_verifier_rejects_undeclared_probe_before_source_replay() -> None:
    worlds = workspace_twins()
    registry = CandidateRegistry.build(worlds)
    forged_manifest = replace(
        registry.manifest,
        adapter_id="forged_workspace_adapter",
    )
    evidence = replace(
        registry.observe(worlds[0].world_id),
        registry_digest=forged_manifest.digest,
        probes=(ProbeObservation(name="cause", value=b"environment"),),
    )
    forged_anchor = replace(
        trust_anchor_for_manifest(registry.manifest),
        registry_digest=forged_manifest.digest,
    )

    with pytest.raises(VerificationError, match="undeclared probes"):
        verify_registry_attribution(
            workspace_sources(),
            manifest=forged_manifest,
            trust_anchor=forged_anchor,
            evidence=evidence,
        )


def test_verifier_revalidates_nested_evidence_at_runtime() -> None:
    worlds = workspace_twins()
    registry = CandidateRegistry.build(worlds)
    evidence = registry.observe(worlds[0].world_id)
    object.__setattr__(
        evidence,
        "probes",
        (cast(ProbeObservation, object()),),
    )

    with pytest.raises(VerificationError, match="nested runtime validation"):
        verify_registry_attribution(
            workspace_sources(),
            manifest=registry.manifest,
            trust_anchor=trust_anchor_for_manifest(registry.manifest),
            evidence=evidence,
        )


def test_verifier_revalidates_the_manifest_at_runtime() -> None:
    worlds = workspace_twins()
    registry = CandidateRegistry.build(worlds)
    evidence = registry.observe(worlds[0].world_id)
    genuine_anchor = trust_anchor_for_manifest(registry.manifest)
    duplicate = registry.manifest.candidate_commitments[0]
    object.__setattr__(
        registry.manifest,
        "candidate_commitments",
        (duplicate, duplicate),
    )

    with pytest.raises(VerificationError, match="closed-schema validation"):
        verify_registry_attribution(
            workspace_sources(),
            manifest=registry.manifest,
            trust_anchor=genuine_anchor,
            evidence=evidence,
        )


def test_proof_roots_are_byte_deterministic() -> None:
    worlds = workspace_twins()
    registry = CandidateRegistry.build(worlds)
    evidence = registry.observe(worlds[0].world_id)

    first = verify_registry_attribution(
        workspace_sources(),
        manifest=registry.manifest,
        trust_anchor=trust_anchor_for_manifest(registry.manifest),
        evidence=evidence,
    )
    second = verify_registry_attribution(
        workspace_sources(),
        manifest=registry.manifest,
        trust_anchor=trust_anchor_for_manifest(registry.manifest),
        evidence=evidence,
    )

    assert first == second


def test_certificate_root_binds_evidence_even_when_panel_compatibility_is_equal() -> None:
    worlds = workspace_twins()
    registry = CandidateRegistry.build(worlds)
    trace_only = registry.observe(worlds[0].world_id)
    owner_probe = registry.observe(
        worlds[0].world_id,
        probes=("workspace_owner",),
    )

    trace_certificate = verify_registry_attribution(
        workspace_sources(),
        manifest=registry.manifest,
        trust_anchor=trust_anchor_for_manifest(registry.manifest),
        evidence=trace_only,
    )
    owner_certificate = verify_registry_attribution(
        workspace_sources(),
        manifest=registry.manifest,
        trust_anchor=trust_anchor_for_manifest(registry.manifest),
        evidence=owner_probe,
    )

    assert trace_certificate.compatible_completion_commitments == (
        owner_certificate.compatible_completion_commitments
    )
    assert trace_certificate.panel_root == owner_certificate.panel_root
    assert trace_certificate.evidence_digest != owner_certificate.evidence_digest
    assert trace_certificate.proof_root != owner_certificate.proof_root


def test_certificate_record_round_trips_against_pinned_release_digests() -> None:
    worlds = workspace_twins()
    registry = CandidateRegistry.build(worlds)
    anchor = trust_anchor_for_manifest(registry.manifest)
    evidence = registry.observe(worlds[0].world_id)
    certificate = verify_registry_attribution(
        workspace_sources(),
        manifest=registry.manifest,
        trust_anchor=anchor,
        evidence=evidence,
    )

    encoded = certificate.to_canonical_bytes()
    parsed = verify_attribution_certificate(
        encoded,
        trust_anchor=anchor,
        expected_proof_root=certificate.proof_root,
    )

    assert parsed == certificate
    assert VerifiedAttribution.from_canonical_bytes(encoded) == certificate


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("registry_digest", "0" * 64),
        ("evidence_digest", "0" * 64),
        ("adapter_implementation_digest", "0" * 64),
        ("verifier_implementation_digest", "0" * 64),
        ("trust_anchor_digest", "0" * 64),
        ("panel_root", "0" * 64),
        ("proof_root", "0" * 64),
        ("kind", "effect_only"),
        ("compatible_completion_commitments", ["0" * 64]),
        ("target_family", [["environment"]]),
        ("unknown_reason", "no_repair_in_declared_algebra"),
        ("ambiguity_commitments", ["0" * 64, "1" * 64]),
        ("format", "witnessgap.attribution-certificate.v2"),
    ],
)
def test_certificate_parser_rejects_every_field_mutation(
    field: str,
    replacement: JsonValue,
) -> None:
    worlds = workspace_twins()
    registry = CandidateRegistry.build(worlds)
    anchor = trust_anchor_for_manifest(registry.manifest)
    evidence = registry.observe(worlds[0].world_id)
    certificate = verify_registry_attribution(
        workspace_sources(),
        manifest=registry.manifest,
        trust_anchor=anchor,
        evidence=evidence,
    )
    raw: object = json.loads(certificate.to_canonical_bytes())
    assert type(raw) is dict
    mutated = cast(dict[str, JsonValue], raw)
    mutated[field] = replacement

    with pytest.raises((TypeError, ValueError, VerificationError)):
        verify_attribution_certificate(
            canonical_json(mutated),
            trust_anchor=anchor,
            expected_proof_root=certificate.proof_root,
        )
