from __future__ import annotations

from typing import cast

import pytest

from witnessgap.identifiability import UnknownReason, VerdictKind
from witnessgap.model import TargetFamily, Witness
from witnessgap.trust import VerificationTrustAnchor
from witnessgap.verifier import trust_anchor_for_manifest
from witnessgap.workspace100.claims import Workspace100ClaimRun
from witnessgap.workspace100.evidence import ParticipantClaim
from witnessgap.workspace100.generation import (
    Workspace100Corpus,
    generate_workspace100,
)
from witnessgap.workspace100.scoring import (
    Workspace100ExactRatio,
    Workspace100FailureCounts,
    Workspace100Rate,
    Workspace100ScoreCategory,
    Workspace100ScoreCounts,
    Workspace100ScoredRun,
    Workspace100ScoreMetrics,
    Workspace100UnavailableReason,
    score_workspace100_claim_run,
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
_SHA256_HEX_LENGTH = 64
_RAW_RATE_NUMERATOR = 50
_RAW_RATE_DENOMINATOR = 300
_UNIFORM_CATEGORY_TOTALS = (9, 4, 5, 4, 3)
_FAILURE_TOTAL = 15
_INVALID_CLAIM_COUNT = 5


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
