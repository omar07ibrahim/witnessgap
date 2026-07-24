from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from dataclasses import replace
from typing import cast

import pytest

from witnessgap.canonical import JsonValue, canonical_json
from witnessgap.identifiability import UnknownReason, VerdictKind
from witnessgap.model import Outcome, TargetFamily, Witness
from witnessgap.trust import VerificationTrustAnchor
from witnessgap.verifier import trust_anchor_for_manifest
from witnessgap.workspace100 import scoring as scoring_module
from witnessgap.workspace100.baselines import (
    PUBLIC_BASELINE_VOCABULARY,
    BuiltinBaseline,
    BuiltinBaselineSet,
    PublicBaselineVocabulary,
    builtin_baseline_set,
)
from witnessgap.workspace100.catalog import TEMPLATES
from witnessgap.workspace100.claims import (
    Workspace100ClaimRun,
    Workspace100ClaimSet,
    build_workspace100_claim_set,
)
from witnessgap.workspace100.evidence import ParticipantClaim
from witnessgap.workspace100.generation import (
    Workspace100Corpus,
    generate_workspace100,
)
from witnessgap.workspace100.records import TemplateId
from witnessgap.workspace100.scoring import (
    Workspace100ExactRatio,
    Workspace100FailureCounts,
    Workspace100MacroMetrics,
    Workspace100Rate,
    Workspace100ScoreBindings,
    Workspace100ScoreCategory,
    Workspace100ScoreCounts,
    Workspace100ScoredRun,
    Workspace100ScoreMetrics,
    Workspace100ScoreReport,
    Workspace100ScoreSlice,
    Workspace100SliceKind,
    Workspace100UnavailableReason,
    load_verified_workspace100_score_report,
    score_workspace100_claim_run,
    score_workspace100_claims,
    workspace100_scoring_implementation_digest,
)
from witnessgap.workspace100.truth import (
    TruthCaseRecord,
    Workspace100TruthSet,
    build_workspace100_truth,
)
from witnessgap.workspace100.views import (
    ViewKind,
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

_SEED = bytes.fromhex(
    "713d96c0fcadb930599f4f4370df3484766872ac406f1c26c5a360a996f29ec5"
)
_METHOD_DIGEST = "a" * 64
_IMPLEMENTATION_DIGEST = "b" * 64
_BACKEND_DIGEST = "c" * 64
_LIMITS_DIGEST = "d" * 64
_SYNTHETIC_BACKEND_DIGEST = "f" * 64
_SHA256_HEX_LENGTH = 64
_RAW_RATE_NUMERATOR = 50
_RAW_RATE_DENOMINATOR = 300
_UNIFORM_CATEGORY_TOTALS = (9, 4, 5, 4, 3)
_FAILURE_TOTAL = 15
_INVALID_CLAIM_COUNT = 5
_METHOD_COUNT = 4
_CASE_COUNT = 300
_RUN_COUNT = _METHOD_COUNT * _CASE_COUNT
_SLICE_COUNT = 30
_MACRO_COUNT = 5
_DEFINED_MACRO_COMPONENTS = 2


@pytest.fixture(scope="module")
def corpus() -> Workspace100Corpus:
    return generate_workspace100(_SEED)


@pytest.fixture(scope="module")
def evidence_views(
    corpus: Workspace100Corpus,
) -> Workspace100EvidenceViews:
    return build_workspace100_evidence_views(corpus)


@pytest.fixture(scope="module")
def truth_set(
    corpus: Workspace100Corpus,
    evidence_views: Workspace100EvidenceViews,
) -> Workspace100TruthSet:
    anchors: tuple[VerificationTrustAnchor, ...] = tuple(
        trust_anchor_for_manifest(route.manifest)
        for route in evidence_views._routes
    )
    return build_workspace100_truth(
        corpus,
        evidence_views,
        trust_anchors=anchors,
    )


@pytest.fixture(scope="module")
def baseline_set() -> BuiltinBaselineSet:
    return builtin_baseline_set()


@pytest.fixture(scope="module")
def limits() -> WorkerLimits:
    return WorkerLimits()


def _baseline_claim(
    baseline: BuiltinBaseline,
    vocabulary: PublicBaselineVocabulary,
    *,
    refresh_outcome: Outcome | None,
) -> ParticipantClaim:
    if baseline is BuiltinBaseline.ALWAYS_UNKNOWN:
        return _unknown(UnknownReason.AMBIGUOUS_WORLDS)
    if baseline is BuiltinBaseline.FORCED_ENVIRONMENT:
        return _identified(
            (("environment",),),
            ((vocabulary.refresh_atom,),),
        )
    if refresh_outcome is None:
        return _unknown(UnknownReason.AMBIGUOUS_WORLDS)
    if refresh_outcome is Outcome.SUCCESS:
        return _identified(
            (("environment",),),
            ((vocabulary.refresh_atom,),),
        )
    if baseline is BuiltinBaseline.REFRESH_OUTCOME:
        return _identified(
            (("policy",),),
            ((vocabulary.repair_atom,),),
        )
    return _unknown(UnknownReason.AMBIGUOUS_WORLDS)


@pytest.fixture(scope="module")
def baseline_claim_set(
    evidence_views: Workspace100EvidenceViews,
    baseline_set: BuiltinBaselineSet,
    limits: WorkerLimits,
) -> Workspace100ClaimSet:
    template_by_id = {
        template.template_id: template for template in TEMPLATES
    }
    vocabulary_by_action = {
        entry.action_tool: entry for entry in PUBLIC_BASELINE_VOCABULARY
    }
    records = tuple(
        WorkerRunRecord(
            method_id=artifact.bundle.method_id,
            implementation_digest=(
                artifact.bundle.program_implementation_digest
            ),
            backend_implementation_digest=_SYNTHETIC_BACKEND_DIGEST,
            limits_digest=limits.digest,
            evidence_digest=case.evidence_digest,
            request_digest=workspace100_worker_request_digest(case.envelope),
            status=WorkerRunStatus.CLAIMED,
            claim=_baseline_claim(
                artifact.bundle.baseline,
                vocabulary_by_action[
                    template_by_id[case.template_id].action_tool
                ],
                refresh_outcome=(
                    case.envelope.evidence.intervention_observations[0].outcome
                    if case.view is ViewKind.REFRESH_RECEIPT
                    else None
                ),
            ),
        )
        for artifact in baseline_set.bundles
        for case in evidence_views.cases
    )
    return build_workspace100_claim_set(
        evidence_views,
        baseline_set,
        tuple(reversed(records)),
        backend_implementation_digest=_SYNTHETIC_BACKEND_DIGEST,
        limits=limits,
    )


@pytest.fixture(scope="module")
def score_bindings(
    baseline_claim_set: Workspace100ClaimSet,
    truth_set: Workspace100TruthSet,
) -> Workspace100ScoreBindings:
    return Workspace100ScoreBindings(
        claim_set_root=baseline_claim_set.claim_set_root,
        truth_root=truth_set.truth_root,
        baseline_set_root=baseline_claim_set.baseline_set_root,
        assignment_root=baseline_claim_set.assignment_root,
        evidence_root=baseline_claim_set.evidence_root,
        projection_root=baseline_claim_set.projection_root,
        method_registry_root=baseline_claim_set.method_registry_root,
        scoring_implementation_digest=(
            workspace100_scoring_implementation_digest()
        ),
    )


@pytest.fixture(scope="module")
def score_report(
    baseline_claim_set: Workspace100ClaimSet,
    truth_set: Workspace100TruthSet,
    score_bindings: Workspace100ScoreBindings,
) -> Workspace100ScoreReport:
    return score_workspace100_claims(
        baseline_claim_set,
        truth_set,
        expected=score_bindings,
    )


@pytest.fixture(scope="module")
def score_report_bytes(score_report: Workspace100ScoreReport) -> bytes:
    return score_report.to_canonical_bytes()


@pytest.fixture(scope="module")
def ambiguous_case(truth_set: Workspace100TruthSet) -> TruthCaseRecord:
    return next(
        case for case in truth_set.cases if case.view is ViewKind.TRACE_ONLY
    )


@pytest.fixture(scope="module")
def identifiable_case(truth_set: Workspace100TruthSet) -> TruthCaseRecord:
    return next(
        case for case in truth_set.cases if case.view is ViewKind.EPOCH_PROBE
    )


def _claim_run(
    truth_case: TruthCaseRecord,
    *,
    claim: ParticipantClaim | None = None,
    failure: WorkerFailureKind | None = None,
) -> Workspace100ClaimRun:
    if (claim is None) == (failure is None):
        raise ValueError("test run requires exactly one claim or failure")
    status = (
        WorkerRunStatus.CLAIMED
        if claim is not None
        else WorkerRunStatus.FAILED
    )
    return Workspace100ClaimRun(
        method_digest=_METHOD_DIGEST,
        worker_run=WorkerRunRecord(
            method_id="test_method",
            implementation_digest=_IMPLEMENTATION_DIGEST,
            backend_implementation_digest=_BACKEND_DIGEST,
            limits_digest=_LIMITS_DIGEST,
            evidence_digest=truth_case.evidence_digest,
            request_digest=workspace100_worker_request_digest(
                truth_case.public_case.envelope
            ),
            status=status,
            claim=claim,
            failure=failure,
        ),
    )


def _unknown(reason: UnknownReason) -> ParticipantClaim:
    return ParticipantClaim(
        kind=VerdictKind.NOT_IDENTIFIABLE,
        unknown_reason=reason,
    )


def _identified(
    target: TargetFamily,
    witnesses: tuple[Witness, ...],
) -> ParticipantClaim:
    return ParticipantClaim(
        kind=VerdictKind.IDENTIFIED_SINGLETON,
        target_family=target,
        minimal_witnesses=witnesses,
    )


@pytest.mark.parametrize("failure", tuple(WorkerFailureKind))
def test_every_worker_failure_is_preserved_and_partitioned_by_truth(
    failure: WorkerFailureKind,
    ambiguous_case: TruthCaseRecord,
    identifiable_case: TruthCaseRecord,
) -> None:
    ambiguous = score_workspace100_claim_run(
        _claim_run(ambiguous_case, failure=failure),
        ambiguous_case,
    )
    identifiable = score_workspace100_claim_run(
        _claim_run(identifiable_case, failure=failure),
        identifiable_case,
    )

    assert ambiguous.category is Workspace100ScoreCategory.FAILED_AMBIGUOUS
    assert identifiable.category is Workspace100ScoreCategory.FAILED_IDENTIFIABLE
    assert ambiguous.failure is failure
    assert identifiable.failure is failure


def test_abstention_categories_are_reason_and_truth_sensitive(
    ambiguous_case: TruthCaseRecord,
    identifiable_case: TruthCaseRecord,
) -> None:
    correct = score_workspace100_claim_run(
        _claim_run(
            ambiguous_case,
            claim=_unknown(UnknownReason.AMBIGUOUS_WORLDS),
        ),
        ambiguous_case,
    )
    wrong_reason = score_workspace100_claim_run(
        _claim_run(
            ambiguous_case,
            claim=_unknown(UnknownReason.BUDGET_EXHAUSTED),
        ),
        ambiguous_case,
    )
    missed = score_workspace100_claim_run(
        _claim_run(
            identifiable_case,
            claim=_unknown(UnknownReason.AMBIGUOUS_WORLDS),
        ),
        identifiable_case,
    )

    assert correct.category is Workspace100ScoreCategory.CORRECT_ABSTENTION
    assert (
        wrong_reason.category
        is Workspace100ScoreCategory.WRONG_REASON_ABSTENTION
    )
    assert missed.category is Workspace100ScoreCategory.MISSED_IDENTIFIABLE


def test_decisive_categories_use_target_first_then_exact_witness(
    ambiguous_case: TruthCaseRecord,
    identifiable_case: TruthCaseRecord,
) -> None:
    exact_target = cast(
        TargetFamily,
        identifiable_case.certificate.target_family,
    )
    exact_witness = cast(
        tuple[Witness, ...],
        identifiable_case.minimal_witnesses,
    )
    wrong_target: TargetFamily = (
        (("policy",),)
        if exact_target == (("environment",),)
        else (("environment",),)
    )
    wrong_witness: tuple[Witness, ...] = (("wrong_atom",),)

    exact = score_workspace100_claim_run(
        _claim_run(
            identifiable_case,
            claim=_identified(exact_target, exact_witness),
        ),
        identifiable_case,
    )
    witness_error = score_workspace100_claim_run(
        _claim_run(
            identifiable_case,
            claim=_identified(exact_target, wrong_witness),
        ),
        identifiable_case,
    )
    target_error = score_workspace100_claim_run(
        _claim_run(
            identifiable_case,
            claim=_identified(wrong_target, exact_witness),
        ),
        identifiable_case,
    )
    ambiguous_decisive = score_workspace100_claim_run(
        _claim_run(
            ambiguous_case,
            claim=_identified((("environment",),), (("wrong_atom",),)),
        ),
        ambiguous_case,
    )

    assert exact.category is Workspace100ScoreCategory.EXACT_DECISIVE
    assert witness_error.category is Workspace100ScoreCategory.WRONG_WITNESS
    assert target_error.category is Workspace100ScoreCategory.WRONG_TARGET
    assert (
        ambiguous_decisive.category
        is Workspace100ScoreCategory.DECISIVE_ON_AMBIGUOUS
    )


def test_single_run_scoring_rejects_join_and_request_faults(
    ambiguous_case: TruthCaseRecord,
    identifiable_case: TruthCaseRecord,
) -> None:
    valid = _claim_run(
        ambiguous_case,
        claim=_unknown(UnknownReason.AMBIGUOUS_WORLDS),
    )
    foreign = Workspace100ClaimRun(
        method_digest=valid.method_digest,
        worker_run=WorkerRunRecord(
            method_id=valid.worker_run.method_id,
            implementation_digest=valid.worker_run.implementation_digest,
            backend_implementation_digest=(
                valid.worker_run.backend_implementation_digest
            ),
            limits_digest=valid.worker_run.limits_digest,
            evidence_digest=identifiable_case.evidence_digest,
            request_digest=valid.worker_run.request_digest,
            status=WorkerRunStatus.CLAIMED,
            claim=cast(ParticipantClaim, valid.worker_run.claim),
        ),
    )
    bad_request = Workspace100ClaimRun(
        method_digest=valid.method_digest,
        worker_run=WorkerRunRecord(
            method_id=valid.worker_run.method_id,
            implementation_digest=valid.worker_run.implementation_digest,
            backend_implementation_digest=(
                valid.worker_run.backend_implementation_digest
            ),
            limits_digest=valid.worker_run.limits_digest,
            evidence_digest=valid.worker_run.evidence_digest,
            request_digest="e" * 64,
            status=WorkerRunStatus.CLAIMED,
            claim=cast(ParticipantClaim, valid.worker_run.claim),
        ),
    )

    with pytest.raises(ValueError, match="evidence does not match"):
        score_workspace100_claim_run(foreign, ambiguous_case)
    with pytest.raises(ValueError, match="request digest"):
        score_workspace100_claim_run(bad_request, ambiguous_case)


def test_scored_run_closed_payload_round_trips(
    ambiguous_case: TruthCaseRecord,
) -> None:
    scored = score_workspace100_claim_run(
        _claim_run(
            ambiguous_case,
            claim=_unknown(UnknownReason.AMBIGUOUS_WORLDS),
        ),
        ambiguous_case,
    )

    assert Workspace100ScoredRun.from_payload(scored.to_payload()) == scored
    assert len(scored.scored_run_digest) == _SHA256_HEX_LENGTH
    opened = dict(scored.to_payload())
    opened["private_route"] = "forbidden"
    with pytest.raises(ValueError, match="unknown or missing"):
        Workspace100ScoredRun.from_payload(opened)


def test_exact_ratio_is_reduced_and_zero_denominator_is_explicit_na() -> None:
    assert Workspace100ExactRatio.from_fraction(6, 8) == (
        Workspace100ExactRatio(3, 4)
    )
    assert Workspace100ExactRatio.from_fraction(0, 7) == (
        Workspace100ExactRatio(0, 1)
    )
    unavailable = Workspace100ExactRatio.from_fraction(0, 0)

    assert unavailable == Workspace100ExactRatio(None, None)
    assert unavailable.to_payload() == {
        "kind": "not_applicable",
        "reason": "zero_denominator",
    }
    assert (
        Workspace100ExactRatio.from_payload(unavailable.to_payload())
        == unavailable
    )


@pytest.mark.parametrize(
    ("numerator", "denominator", "error"),
    (
        (2, 4, "reduced"),
        (1, 0, "positive denominator"),
        (2, 1, "cannot exceed"),
        (-1, 2, "cannot be negative"),
        (True, 2, "exact integer"),
    ),
)
def test_exact_ratio_rejects_noncanonical_values(
    numerator: object,
    denominator: object,
    error: str,
) -> None:
    with pytest.raises((TypeError, ValueError), match=error):
        Workspace100ExactRatio(
            cast(int, numerator),
            cast(int, denominator),
        )


def test_rates_publish_raw_event_counts_and_reduced_value() -> None:
    rate = Workspace100Rate.from_counts(
        _RAW_RATE_NUMERATOR,
        _RAW_RATE_DENOMINATOR,
    )

    assert rate.numerator == _RAW_RATE_NUMERATOR
    assert rate.denominator == _RAW_RATE_DENOMINATOR
    assert rate.ratio == Workspace100ExactRatio(1, 6)
    assert Workspace100Rate.from_payload(rate.to_payload()) == rate


def test_nine_way_counts_derive_the_seven_exact_metrics() -> None:
    counts = Workspace100ScoreCounts(
        failed_ambiguous=1,
        failed_identifiable=1,
        correct_abstention=1,
        wrong_reason_abstention=1,
        missed_identifiable=1,
        exact_decisive=1,
        wrong_witness=1,
        wrong_target=1,
        decisive_on_ambiguous=1,
    )
    metrics = Workspace100ScoreMetrics.from_counts(counts)

    assert (
        counts.total_cases,
        counts.ambiguous_cases,
        counts.identifiable_cases,
        counts.decisive_claims,
        counts.false_certain_claims,
    ) == _UNIFORM_CATEGORY_TOTALS
    assert metrics.decisive_coverage.ratio == Workspace100ExactRatio(4, 9)
    assert metrics.false_certainty_risk.ratio == Workspace100ExactRatio(3, 4)
    assert metrics.false_certainty_incidence.ratio == Workspace100ExactRatio(1, 3)
    assert metrics.ambiguity_false_certainty.ratio == Workspace100ExactRatio(1, 4)
    assert metrics.correct_abstention.ratio == Workspace100ExactRatio(1, 4)
    assert metrics.exact_target_family.ratio == Workspace100ExactRatio(2, 5)
    assert metrics.exact_minimal_witness.ratio == Workspace100ExactRatio(1, 5)
    assert (
        metrics.intervention_count.reason
        is Workspace100UnavailableReason.NOT_OBSERVED_BY_PROTOCOL
    )
    assert (
        metrics.verifier_rejection_count.reason
        is Workspace100UnavailableReason.VERIFICATION_FAULTS_ABORT_REPORT
    )
    assert Workspace100ScoreCounts.from_payload(counts.to_payload()) == counts
    assert Workspace100ScoreMetrics.from_payload(metrics.to_payload()) == metrics


def test_failure_counts_preserve_all_five_worker_outcomes() -> None:
    counts = Workspace100FailureCounts(
        timed_out=1,
        output_limit_exceeded=2,
        nonzero_exit=3,
        empty_output=4,
        invalid_claim=5,
    )

    assert counts.total == _FAILURE_TOTAL
    assert (
        counts.count_for(WorkerFailureKind.INVALID_CLAIM)
        == _INVALID_CLAIM_COUNT
    )
    assert Workspace100FailureCounts.from_payload(counts.to_payload()) == counts


def test_scoring_source_closure_has_a_stable_digest_shape() -> None:
    digest = workspace100_scoring_implementation_digest()

    assert len(digest) == _SHA256_HEX_LENGTH
    assert set(digest) <= set("0123456789abcdef")


def test_scoring_fresh_import_is_covered_by_its_source_closure() -> None:
    script = textwrap.dedent(
        """
        import importlib
        import sys
        from pathlib import Path

        import witnessgap

        scoring = importlib.import_module("witnessgap.workspace100.scoring")
        assert "witnessgap.oracle" not in sys.modules
        package_root = Path(witnessgap.__file__).resolve().parent
        executed = set()
        for module in tuple(sys.modules.values()):
            module_file = getattr(module, "__file__", None)
            if not module_file or not module_file.endswith(".py"):
                continue
            try:
                relative = Path(module_file).resolve().relative_to(package_root)
            except ValueError:
                continue
            executed.add(relative.as_posix())
        uncovered = sorted(
            executed - set(scoring._SCORING_IMPLEMENTATION_PATHS)
        )
        assert not uncovered, uncovered
        """
    )
    result = subprocess.run(
        (sys.executable, "-c", script),
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_complete_report_is_closed_rooted_and_rebuild_verified(
    score_report: Workspace100ScoreReport,
    score_report_bytes: bytes,
    baseline_claim_set: Workspace100ClaimSet,
    truth_set: Workspace100TruthSet,
    score_bindings: Workspace100ScoreBindings,
) -> None:
    parsed = Workspace100ScoreReport.from_canonical_bytes(score_report_bytes)
    loaded = load_verified_workspace100_score_report(
        score_report_bytes,
        baseline_claim_set,
        truth_set,
        expected=score_bindings,
        expected_report_root=score_report.report_root,
    )

    assert parsed == score_report
    assert loaded == score_report
    assert parsed.to_canonical_bytes() == score_report_bytes
    assert len(score_report.scored_runs) == _RUN_COUNT
    assert len(score_report.methods) == _METHOD_COUNT
    assert all(
        len(method.slices) == _SLICE_COUNT
        and len(method.template_macros) == _MACRO_COUNT
        for method in score_report.methods
    )
    assert len(score_report.adjudication_root) == _SHA256_HEX_LENGTH
    assert len(score_report.aggregate_root) == _SHA256_HEX_LENGTH
    assert len(score_report.report_root) == _SHA256_HEX_LENGTH


def _category_vector(
    counts: Workspace100ScoreCounts,
) -> tuple[int, ...]:
    return (
        counts.failed_ambiguous,
        counts.failed_identifiable,
        counts.correct_abstention,
        counts.wrong_reason_abstention,
        counts.missed_identifiable,
        counts.exact_decisive,
        counts.wrong_witness,
        counts.wrong_target,
        counts.decisive_on_ambiguous,
    )


def _contains_float(value: object) -> bool:
    if type(value) is float:
        return True
    if type(value) is list:
        return any(_contains_float(item) for item in cast(list[object], value))
    if type(value) is dict:
        return any(
            _contains_float(item)
            for item in cast(dict[str, object], value).values()
        )
    return False


def _slice_for(
    report: Workspace100ScoreReport,
    baseline: BuiltinBaseline,
    kind: Workspace100SliceKind,
    *,
    view: ViewKind | None = None,
) -> Workspace100ScoreSlice:
    method = next(
        candidate
        for candidate in report.methods
        if candidate.baseline is baseline
    )
    return next(
        score_slice
        for score_slice in method.slices
        if score_slice.kind is kind and score_slice.view is view
    )


def test_frozen_baselines_produce_the_expected_exact_score_vectors(
    score_report: Workspace100ScoreReport,
) -> None:
    expected = {
        BuiltinBaseline.ALWAYS_UNKNOWN: (0, 0, 100, 0, 200, 0, 0, 0, 0),
        BuiltinBaseline.FORCED_ENVIRONMENT: (
            0,
            0,
            0,
            0,
            0,
            100,
            0,
            100,
            100,
        ),
        BuiltinBaseline.REFRESH_SUCCESS_ONLY: (
            0,
            0,
            100,
            0,
            150,
            50,
            0,
            0,
            0,
        ),
        BuiltinBaseline.REFRESH_OUTCOME: (
            0,
            0,
            100,
            0,
            100,
            100,
            0,
            0,
            0,
        ),
    }

    assert {
        method.baseline: _category_vector(method.slices[0].counts)
        for method in score_report.methods
    } == expected
    assert all(
        method.slices[0].kind is Workspace100SliceKind.OVERALL
        for method in score_report.methods
    )


def test_frozen_baseline_rates_are_exact_and_float_free(
    score_report: Workspace100ScoreReport,
    score_report_bytes: bytes,
) -> None:
    expected = {
        BuiltinBaseline.ALWAYS_UNKNOWN: (
            Workspace100ExactRatio(0, 1),
            Workspace100ExactRatio(None, None),
            Workspace100ExactRatio(0, 1),
            Workspace100ExactRatio(0, 1),
            Workspace100ExactRatio(1, 1),
            Workspace100ExactRatio(0, 1),
            Workspace100ExactRatio(0, 1),
        ),
        BuiltinBaseline.FORCED_ENVIRONMENT: (
            Workspace100ExactRatio(1, 1),
            Workspace100ExactRatio(2, 3),
            Workspace100ExactRatio(2, 3),
            Workspace100ExactRatio(1, 1),
            Workspace100ExactRatio(0, 1),
            Workspace100ExactRatio(1, 2),
            Workspace100ExactRatio(1, 2),
        ),
        BuiltinBaseline.REFRESH_SUCCESS_ONLY: (
            Workspace100ExactRatio(1, 6),
            Workspace100ExactRatio(0, 1),
            Workspace100ExactRatio(0, 1),
            Workspace100ExactRatio(0, 1),
            Workspace100ExactRatio(1, 1),
            Workspace100ExactRatio(1, 4),
            Workspace100ExactRatio(1, 4),
        ),
        BuiltinBaseline.REFRESH_OUTCOME: (
            Workspace100ExactRatio(1, 3),
            Workspace100ExactRatio(0, 1),
            Workspace100ExactRatio(0, 1),
            Workspace100ExactRatio(0, 1),
            Workspace100ExactRatio(1, 1),
            Workspace100ExactRatio(1, 2),
            Workspace100ExactRatio(1, 2),
        ),
    }

    assert {
        method.baseline: tuple(
            rate.ratio for rate in method.slices[0].metrics._rates()
        )
        for method in score_report.methods
    } == expected
    assert not _contains_float(json.loads(score_report_bytes))
    assert b"NaN" not in score_report_bytes
    assert b"Infinity" not in score_report_bytes


def test_view_template_and_oracle_tables_are_complete(
    score_report: Workspace100ScoreReport,
) -> None:
    expected_views = {
        BuiltinBaseline.ALWAYS_UNKNOWN: {
            ViewKind.TRACE_ONLY: (0, 0, 50, 0, 0, 0, 0, 0, 0),
            ViewKind.OWNER_PROBE: (0, 0, 50, 0, 0, 0, 0, 0, 0),
            ViewKind.EPOCH_PROBE: (0, 0, 0, 0, 100, 0, 0, 0, 0),
            ViewKind.REFRESH_RECEIPT: (0, 0, 0, 0, 100, 0, 0, 0, 0),
        },
        BuiltinBaseline.FORCED_ENVIRONMENT: {
            ViewKind.TRACE_ONLY: (0, 0, 0, 0, 0, 0, 0, 0, 50),
            ViewKind.OWNER_PROBE: (0, 0, 0, 0, 0, 0, 0, 0, 50),
            ViewKind.EPOCH_PROBE: (0, 0, 0, 0, 0, 50, 0, 50, 0),
            ViewKind.REFRESH_RECEIPT: (0, 0, 0, 0, 0, 50, 0, 50, 0),
        },
        BuiltinBaseline.REFRESH_SUCCESS_ONLY: {
            ViewKind.TRACE_ONLY: (0, 0, 50, 0, 0, 0, 0, 0, 0),
            ViewKind.OWNER_PROBE: (0, 0, 50, 0, 0, 0, 0, 0, 0),
            ViewKind.EPOCH_PROBE: (0, 0, 0, 0, 100, 0, 0, 0, 0),
            ViewKind.REFRESH_RECEIPT: (0, 0, 0, 0, 50, 50, 0, 0, 0),
        },
        BuiltinBaseline.REFRESH_OUTCOME: {
            ViewKind.TRACE_ONLY: (0, 0, 50, 0, 0, 0, 0, 0, 0),
            ViewKind.OWNER_PROBE: (0, 0, 50, 0, 0, 0, 0, 0, 0),
            ViewKind.EPOCH_PROBE: (0, 0, 0, 0, 100, 0, 0, 0, 0),
            ViewKind.REFRESH_RECEIPT: (0, 0, 0, 0, 0, 100, 0, 0, 0),
        },
    }
    actual = {
        baseline: {
            view: _category_vector(
                _slice_for(
                    score_report,
                    baseline,
                    Workspace100SliceKind.VIEW,
                    view=view,
                ).counts
            )
            for view in ViewKind
        }
        for baseline in BuiltinBaseline
    }

    assert actual == expected_views
    assert all(
        len(
            tuple(
                score_slice
                for score_slice in method.slices
                if score_slice.kind is Workspace100SliceKind.VIEW_TEMPLATE
            )
        )
        == len(ViewKind) * len(TEMPLATES)
        for method in score_report.methods
    )
    oracle = score_report.oracle_ceiling.slices[0].counts
    assert _category_vector(oracle) == (0, 0, 100, 0, 0, 200, 0, 0, 0)


def test_template_macro_is_unweighted_and_excludes_na_components() -> None:
    template_counts = (
        Workspace100ScoreCounts(wrong_target=1, missed_identifiable=59),
        Workspace100ScoreCounts(exact_decisive=3, missed_identifiable=57),
        Workspace100ScoreCounts(missed_identifiable=60),
        Workspace100ScoreCounts(missed_identifiable=60),
        Workspace100ScoreCounts(missed_identifiable=60),
    )
    slices = tuple(
        Workspace100ScoreSlice(
            kind=Workspace100SliceKind.TEMPLATE,
            view=None,
            template_id=template_id,
            counts=counts,
            failure_counts=Workspace100FailureCounts(),
            metrics=Workspace100ScoreMetrics.from_counts(counts),
        )
        for template_id, counts in zip(
            TemplateId,
            template_counts,
            strict=True,
        )
    )
    macro = Workspace100MacroMetrics.from_slices(slices)
    combined = Workspace100ScoreCounts(
        wrong_target=1,
        exact_decisive=3,
        missed_identifiable=296,
    )

    assert (
        macro.false_certainty_risk.defined_template_count
        == _DEFINED_MACRO_COMPONENTS
    )
    assert macro.false_certainty_risk.ratio == Workspace100ExactRatio(1, 2)
    assert (
        Workspace100ScoreMetrics.from_counts(combined)
        .false_certainty_risk.ratio
        == Workspace100ExactRatio(1, 4)
    )


def test_expected_scorer_identity_is_checked_before_artifact_scoring(
    baseline_claim_set: Workspace100ClaimSet,
    truth_set: Workspace100TruthSet,
    score_bindings: Workspace100ScoreBindings,
) -> None:
    wrong = replace(
        score_bindings,
        scoring_implementation_digest="0" * _SHA256_HEX_LENGTH,
    )

    with pytest.raises(ValueError, match="scorer identity"):
        score_workspace100_claims(
            baseline_claim_set,
            truth_set,
            expected=wrong,
        )


def test_scorer_recomputes_worker_request_digests_from_truth(
    baseline_claim_set: Workspace100ClaimSet,
    truth_set: Workspace100TruthSet,
    score_bindings: Workspace100ScoreBindings,
) -> None:
    evidence_digests = tuple(
        dict.fromkeys(
            run.worker_run.evidence_digest
            for run in baseline_claim_set.runs
        )
    )
    first, second = evidence_digests[:2]
    request_by_evidence = {
        run.worker_run.evidence_digest: run.worker_run.request_digest
        for run in baseline_claim_set.runs
    }
    swapped = {
        first: request_by_evidence[second],
        second: request_by_evidence[first],
    }
    runs = tuple(
        replace(
            run,
            worker_run=replace(
                run.worker_run,
                request_digest=swapped.get(
                    run.worker_run.evidence_digest,
                    run.worker_run.request_digest,
                ),
            ),
        )
        for run in baseline_claim_set.runs
    )
    forged = Workspace100ClaimSet(
        baseline_set_root=baseline_claim_set.baseline_set_root,
        assignment_root=baseline_claim_set.assignment_root,
        evidence_root=baseline_claim_set.evidence_root,
        projection_root=baseline_claim_set.projection_root,
        backend_implementation_digest=(
            baseline_claim_set.backend_implementation_digest
        ),
        limits=baseline_claim_set.limits,
        methods=baseline_claim_set.methods,
        runs=runs,
    )
    attacker_pinned = replace(
        score_bindings,
        claim_set_root=forged.claim_set_root,
    )

    with pytest.raises(ValueError, match="request digest"):
        score_workspace100_claims(
            forged,
            truth_set,
            expected=attacker_pinned,
        )


def test_structural_parser_rejects_root_tampering_and_open_json(
    score_report_bytes: bytes,
) -> None:
    raw = cast(dict[str, object], json.loads(score_report_bytes))
    raw["report_root"] = "0" * _SHA256_HEX_LENGTH
    tampered = canonical_json(cast(JsonValue, raw))

    with pytest.raises(ValueError, match="stored roots"):
        Workspace100ScoreReport.from_canonical_bytes(tampered)
    with pytest.raises(ValueError, match="unknown or missing"):
        opened = cast(dict[str, object], json.loads(score_report_bytes))
        opened["generated_at"] = "now"
        Workspace100ScoreReport.from_canonical_bytes(
            canonical_json(cast(JsonValue, opened))
        )
    with pytest.raises(ValueError, match="valid bounded JSON"):
        Workspace100ScoreReport.from_canonical_bytes(b"{")


def test_safe_loader_rejects_a_coherently_rerooted_score(
    score_report: Workspace100ScoreReport,
    baseline_claim_set: Workspace100ClaimSet,
    truth_set: Workspace100TruthSet,
    score_bindings: Workspace100ScoreBindings,
) -> None:
    changed = replace(
        score_report.scored_runs[0],
        category=Workspace100ScoreCategory.WRONG_REASON_ABSTENTION,
    )
    forged_runs = (changed, *score_report.scored_runs[1:])
    forged_methods = tuple(
        scoring_module._build_method_report(
            method.claim_method,
            tuple(
                scored_run
                for scored_run in forged_runs
                if scored_run.method_digest == method.method_digest
            ),
        )
        for method in score_report.methods
    )
    forged = replace(
        score_report,
        scored_runs=forged_runs,
        methods=forged_methods,
    )
    forged_bytes = forged.to_canonical_bytes()

    assert (
        Workspace100ScoreReport.from_canonical_bytes(forged_bytes) == forged
    )
    with pytest.raises(ValueError, match="authenticated source rebuild"):
        load_verified_workspace100_score_report(
            forged_bytes,
            baseline_claim_set,
            truth_set,
            expected=score_bindings,
            expected_report_root=forged.report_root,
        )


def test_report_serialization_excludes_private_routing_and_host_paths(
    score_report_bytes: bytes,
) -> None:
    lowered = score_report_bytes.lower()

    for forbidden in (
        b'"pair_id"',
        b'"task_id"',
        b'"episode_id"',
        b'"route_digest"',
        b'"source_snapshot_digest"',
        b"/home/",
        b"generated_at",
    ):
        assert forbidden not in lowered
