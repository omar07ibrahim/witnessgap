from __future__ import annotations

import json
from dataclasses import replace
from typing import cast

import pytest

from witnessgap import workspace100
from witnessgap.canonical import JsonValue, canonical_json
from witnessgap.identifiability import UnknownReason, VerdictKind
from witnessgap.workspace100.baselines import (
    BUILTIN_BASELINE_SET_ROOT,
    BuiltinBaselineSet,
    builtin_baseline_set,
)
from witnessgap.workspace100.claims import (
    Workspace100ClaimRun,
    Workspace100ClaimSet,
    build_workspace100_claim_set,
    load_verified_workspace100_claim_set,
    verify_workspace100_claim_bindings,
)
from witnessgap.workspace100.evidence import ParticipantClaim
from witnessgap.workspace100.generation import generate_workspace100
from witnessgap.workspace100.views import (
    Workspace100EvidenceViews,
    build_workspace100_evidence_views,
)
from witnessgap.workspace100.worker import (
    WorkerFailureKind,
    WorkerLimits,
    WorkerRunRecord,
    WorkerRunStatus,
    workspace100_worker_request_digest,
)

_SEED = bytes.fromhex("713d96c0fcadb930599f4f4370df3484766872ac406f1c26c5a360a996f29ec5")
_BACKEND_DIGEST = "a" * 64
_METHOD_COUNT = 4
_CASE_COUNT = 300
_RUN_COUNT = _METHOD_COUNT * _CASE_COUNT
_EXPECTED_METHOD_REGISTRY_ROOT = (
    "0e19fbc61b979dc2af8b523d4ef56620a5d552c320fc2c95a69c83d120bf0e53"
)
_EXPECTED_RUN_ROOT = (
    "6ac4fbf05b993552feee76149559b1bfa1ae2fa7d3c33419feb9ddeb3aad0e96"
)
_EXPECTED_CLAIM_SET_ROOT = (
    "1e1d58d1760255d5b29e4afc0fc0f9ae26494b4cc40f27869d70851e2ee017e5"
)
_UNKNOWN_CLAIM = ParticipantClaim(
    kind=VerdictKind.NOT_IDENTIFIABLE,
    unknown_reason=UnknownReason.AMBIGUOUS_WORLDS,
)


@pytest.fixture(scope="module")
def evidence_views() -> Workspace100EvidenceViews:
    return build_workspace100_evidence_views(generate_workspace100(_SEED))


@pytest.fixture(scope="module")
def baseline_set() -> BuiltinBaselineSet:
    return builtin_baseline_set()


@pytest.fixture(scope="module")
def limits() -> WorkerLimits:
    return WorkerLimits()


@pytest.fixture(scope="module")
def worker_records(
    evidence_views: Workspace100EvidenceViews,
    baseline_set: BuiltinBaselineSet,
    limits: WorkerLimits,
) -> tuple[WorkerRunRecord, ...]:
    return tuple(
        WorkerRunRecord(
            method_id=artifact.bundle.method_id,
            implementation_digest=(
                artifact.bundle.program_implementation_digest
            ),
            backend_implementation_digest=_BACKEND_DIGEST,
            limits_digest=limits.digest,
            evidence_digest=case.evidence_digest,
            request_digest=workspace100_worker_request_digest(case.envelope),
            status=WorkerRunStatus.CLAIMED,
            claim=_UNKNOWN_CLAIM,
        )
        for artifact in baseline_set.bundles
        for case in evidence_views.cases
    )


@pytest.fixture(scope="module")
def claim_set(
    evidence_views: Workspace100EvidenceViews,
    baseline_set: BuiltinBaselineSet,
    worker_records: tuple[WorkerRunRecord, ...],
    limits: WorkerLimits,
) -> Workspace100ClaimSet:
    return build_workspace100_claim_set(
        evidence_views,
        baseline_set,
        tuple(reversed(worker_records)),
        backend_implementation_digest=_BACKEND_DIGEST,
        limits=limits,
    )


def test_claim_set_is_closed_complete_and_root_pinned(
    claim_set: Workspace100ClaimSet,
    evidence_views: Workspace100EvidenceViews,
    baseline_set: BuiltinBaselineSet,
) -> None:
    payload = claim_set.to_canonical_bytes()
    parsed = load_verified_workspace100_claim_set(
        payload,
        evidence_views,
        baseline_set,
        expected_backend_implementation_digest=_BACKEND_DIGEST,
        expected_limits=claim_set.limits,
    )

    assert parsed == claim_set
    assert parsed.to_canonical_bytes() == payload
    assert claim_set.baseline_set_root == BUILTIN_BASELINE_SET_ROOT
    assert claim_set.method_registry_root == _EXPECTED_METHOD_REGISTRY_ROOT
    assert claim_set.run_root == _EXPECTED_RUN_ROOT
    assert claim_set.claim_set_root == _EXPECTED_CLAIM_SET_ROOT
    assert len(claim_set.methods) == _METHOD_COUNT
    assert len(claim_set.runs) == _RUN_COUNT
    assert (
        len({run.worker_run.evidence_digest for run in claim_set.runs})
        == _CASE_COUNT
    )
    assert "Workspace100ClaimSet" not in workspace100.__all__
    assert not hasattr(workspace100, "build_workspace100_claim_set")


def test_claim_assembly_is_independent_of_input_record_order(
    evidence_views: Workspace100EvidenceViews,
    baseline_set: BuiltinBaselineSet,
    worker_records: tuple[WorkerRunRecord, ...],
    limits: WorkerLimits,
) -> None:
    forward = build_workspace100_claim_set(
        evidence_views,
        baseline_set,
        worker_records,
        backend_implementation_digest=_BACKEND_DIGEST,
        limits=limits,
    )
    interleaved = worker_records[::2] + worker_records[1::2]
    reordered = build_workspace100_claim_set(
        evidence_views,
        baseline_set,
        interleaved,
        backend_implementation_digest=_BACKEND_DIGEST,
        limits=limits,
    )

    assert forward.to_canonical_bytes() == reordered.to_canonical_bytes()
    assert forward.claim_set_root == reordered.claim_set_root


def test_claim_set_preserves_worker_failures_as_rooted_runs(
    evidence_views: Workspace100EvidenceViews,
    baseline_set: BuiltinBaselineSet,
    worker_records: tuple[WorkerRunRecord, ...],
    limits: WorkerLimits,
) -> None:
    failed = replace(
        worker_records[0],
        status=WorkerRunStatus.FAILED,
        claim=None,
        failure=WorkerFailureKind.TIMED_OUT,
    )
    records = (failed, *worker_records[1:])
    failed_set = build_workspace100_claim_set(
        evidence_views,
        baseline_set,
        records,
        backend_implementation_digest=_BACKEND_DIGEST,
        limits=limits,
    )
    stored = next(
        run.worker_run
        for run in failed_set.runs
        if run.worker_run.method_id == failed.method_id
        and run.worker_run.evidence_digest == failed.evidence_digest
    )

    assert stored == failed
    assert stored.failure is WorkerFailureKind.TIMED_OUT
    assert failed_set.claim_set_root != _EXPECTED_CLAIM_SET_ROOT


def test_claim_builder_rejects_incomplete_mixed_or_substituted_records(
    evidence_views: Workspace100EvidenceViews,
    baseline_set: BuiltinBaselineSet,
    worker_records: tuple[WorkerRunRecord, ...],
    limits: WorkerLimits,
) -> None:
    with pytest.raises(TypeError, match="1,200"):
        build_workspace100_claim_set(
            evidence_views,
            baseline_set,
            worker_records[:-1],
            backend_implementation_digest=_BACKEND_DIGEST,
            limits=limits,
        )

    duplicate = (*worker_records[:-1], worker_records[0])
    with pytest.raises(ValueError, match="keys must be unique"):
        build_workspace100_claim_set(
            evidence_views,
            baseline_set,
            duplicate,
            backend_implementation_digest=_BACKEND_DIGEST,
            limits=limits,
        )

    mixed_backend = (
        replace(worker_records[0], backend_implementation_digest="b" * 64),
        *worker_records[1:],
    )
    with pytest.raises(ValueError, match="expected backend"):
        build_workspace100_claim_set(
            evidence_views,
            baseline_set,
            mixed_backend,
            backend_implementation_digest=_BACKEND_DIGEST,
            limits=limits,
        )

    mixed_limits = (
        replace(worker_records[0], limits_digest="b" * 64),
        *worker_records[1:],
    )
    with pytest.raises(ValueError, match="expected limits"):
        build_workspace100_claim_set(
            evidence_views,
            baseline_set,
            mixed_limits,
            backend_implementation_digest=_BACKEND_DIGEST,
            limits=limits,
        )

    substituted_method = (
        replace(worker_records[0], method_id="substituted_method"),
        *worker_records[1:],
    )
    with pytest.raises(ValueError, match="unknown method"):
        build_workspace100_claim_set(
            evidence_views,
            baseline_set,
            substituted_method,
            backend_implementation_digest=_BACKEND_DIGEST,
            limits=limits,
        )


def test_claim_set_parser_rejects_open_reordered_and_nested_mutations(
    claim_set: Workspace100ClaimSet,
) -> None:
    canonical = claim_set.to_canonical_bytes()
    parsed = cast(dict[str, JsonValue], json.loads(canonical))
    mutations: list[dict[str, JsonValue]] = []

    opened = dict(parsed)
    opened["execution_order"] = ()
    mutations.append(opened)

    missing = dict(parsed)
    missing.pop("claim_set_root")
    mutations.append(missing)

    reordered_methods = cast(dict[str, JsonValue], json.loads(canonical))
    reordered_methods["methods"] = tuple(
        reversed(cast(list[JsonValue], reordered_methods["methods"]))
    )
    mutations.append(reordered_methods)

    reordered_runs = cast(dict[str, JsonValue], json.loads(canonical))
    reordered_runs["runs"] = tuple(
        reversed(cast(list[JsonValue], reordered_runs["runs"]))
    )
    mutations.append(reordered_runs)

    open_worker = cast(dict[str, JsonValue], json.loads(canonical))
    first_run = cast(
        dict[str, JsonValue],
        cast(list[JsonValue], open_worker["runs"])[0],
    )
    worker_run = cast(dict[str, JsonValue], first_run["worker_run"])
    worker_run["case_id"] = "forged"
    mutations.append(open_worker)

    for mutation in mutations:
        with pytest.raises(ValueError):
            Workspace100ClaimSet.from_canonical_bytes(canonical_json(mutation))

    for noncanonical in (
        canonical.rstrip(b"\n"),
        canonical + b"\n",
        b" " + canonical,
    ):
        with pytest.raises(ValueError, match="canonical"):
            Workspace100ClaimSet.from_canonical_bytes(noncanonical)

    with pytest.raises(ValueError, match="unsupported JSON"):
        Workspace100ClaimSet.from_canonical_bytes(b'{"value":"\\ud800"}\n')
    with pytest.raises(ValueError, match="byte bound"):
        Workspace100ClaimSet.from_canonical_bytes(b"{" * ((8 << 20) + 1))


def test_external_join_rejects_a_self_consistent_request_substitution(
    claim_set: Workspace100ClaimSet,
    evidence_views: Workspace100EvidenceViews,
    baseline_set: BuiltinBaselineSet,
) -> None:
    evidence_digests = tuple(
        sorted({run.worker_run.evidence_digest for run in claim_set.runs})
    )
    first_evidence, second_evidence = evidence_digests[:2]
    request_by_evidence = {
        run.worker_run.evidence_digest: run.worker_run.request_digest
        for run in claim_set.runs
        if run.worker_run.evidence_digest in {first_evidence, second_evidence}
    }
    substitutions = {
        first_evidence: request_by_evidence[second_evidence],
        second_evidence: request_by_evidence[first_evidence],
    }
    mutated_runs = tuple(
        replace(
            run,
            worker_run=replace(
                run.worker_run,
                request_digest=substitutions[run.worker_run.evidence_digest],
            ),
        )
        if run.worker_run.evidence_digest in substitutions
        else run
        for run in claim_set.runs
    )
    mutated = Workspace100ClaimSet.from_canonical_bytes(
        replace(claim_set, runs=mutated_runs).to_canonical_bytes()
    )

    assert mutated.claim_set_root != claim_set.claim_set_root
    with pytest.raises(ValueError, match="request digest"):
        verify_workspace100_claim_bindings(
            mutated,
            evidence_views,
            baseline_set,
            expected_backend_implementation_digest=_BACKEND_DIGEST,
            expected_limits=claim_set.limits,
        )


def test_external_join_requires_caller_pinned_backend_and_limits(
    claim_set: Workspace100ClaimSet,
    evidence_views: Workspace100EvidenceViews,
    baseline_set: BuiltinBaselineSet,
) -> None:
    substituted_backend = "b" * 64
    backend_runs = tuple(
        replace(
            run,
            worker_run=replace(
                run.worker_run,
                backend_implementation_digest=substituted_backend,
            ),
        )
        for run in claim_set.runs
    )
    backend_set = replace(
        claim_set,
        backend_implementation_digest=substituted_backend,
        runs=backend_runs,
    )
    with pytest.raises(ValueError, match="expected execution"):
        verify_workspace100_claim_bindings(
            backend_set,
            evidence_views,
            baseline_set,
            expected_backend_implementation_digest=_BACKEND_DIGEST,
            expected_limits=claim_set.limits,
        )

    substituted_limits = WorkerLimits(timeout_ms=6_000)
    limits_runs = tuple(
        replace(
            run,
            worker_run=replace(
                run.worker_run,
                limits_digest=substituted_limits.digest,
            ),
        )
        for run in claim_set.runs
    )
    limits_set = replace(
        claim_set,
        limits=substituted_limits,
        runs=limits_runs,
    )
    with pytest.raises(ValueError, match="expected execution"):
        verify_workspace100_claim_bindings(
            limits_set,
            evidence_views,
            baseline_set,
            expected_backend_implementation_digest=_BACKEND_DIGEST,
            expected_limits=claim_set.limits,
        )


def test_claim_set_rejects_a_coordinated_projection_root_rewrite(
    claim_set: Workspace100ClaimSet,
) -> None:
    with pytest.raises(ValueError, match="projection root contradicts"):
        replace(claim_set, projection_root="0" * 64)


def test_claim_set_revalidates_post_init_mutation(
    claim_set: Workspace100ClaimSet,
) -> None:
    mutated = Workspace100ClaimSet.from_canonical_bytes(
        claim_set.to_canonical_bytes()
    )
    object.__setattr__(mutated.runs[0], "method_digest", "0" * 64)

    with pytest.raises(ValueError, match="unknown method"):
        mutated.to_canonical_bytes()


def test_claim_set_serialization_contains_no_routing_or_schedule_metadata(
    claim_set: Workspace100ClaimSet,
) -> None:
    payload = claim_set.to_canonical_bytes()

    for forbidden in (
        b"case_id",
        b"duration",
        b"episode_id",
        b"execution_order",
        b"pair_id",
        b"schedule",
        b"split",
        b"template_id",
        b"timestamp",
        b"truth",
        b"view",
    ):
        assert forbidden not in payload


def test_claim_run_rejects_a_mismatched_stored_worker_digest(
    claim_set: Workspace100ClaimSet,
) -> None:
    payload = claim_set.runs[0].to_payload()
    payload["worker_run_digest"] = "0" * 64

    with pytest.raises(ValueError, match="contradicts"):
        Workspace100ClaimRun.from_payload(payload)
