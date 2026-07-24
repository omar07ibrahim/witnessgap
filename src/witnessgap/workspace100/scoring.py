"""Truth-joined exact scoring primitives for Workspace-100.

The scorer is evaluator-side code.  It consumes complete ClaimSet and truth
artifacts, never participant output directly, and treats any broken binding as
an artifact error rather than as a method prediction.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from math import gcd
from typing import cast

from witnessgap.canonical import JsonValue, canonical_digest
from witnessgap.identifiability import UnknownReason, VerdictKind
from witnessgap.source import package_implementation_digest
from witnessgap.workspace100.catalog import TEMPLATES
from witnessgap.workspace100.claims import Workspace100ClaimRun
from witnessgap.workspace100.evidence import ParticipantClaim
from witnessgap.workspace100.records import PROTOCOL_ID, Split, TemplateId
from witnessgap.workspace100.truth import TruthCaseRecord
from witnessgap.workspace100.views import ViewKind
from witnessgap.workspace100.worker import (
    WorkerFailureKind,
    WorkerRunStatus,
    workspace100_worker_request_digest,
)

SCORE_CASE_FORMAT = "witnessgap.workspace100-score-case.v1"
SCORE_COUNTS_FORMAT = "witnessgap.workspace100-score-counts.v1"
SCORE_FAILURE_COUNTS_FORMAT = "witnessgap.workspace100-score-failure-counts.v1"
SCORE_METRICS_FORMAT = "witnessgap.workspace100-score-metrics.v1"
SCORE_RATE_FORMAT = "witnessgap.workspace100-score-rate.v1"

_SCORING_IMPLEMENTATION_DOMAIN = (
    "witnessgap.workspace100-scoring-implementation.v1"
)
_SCORING_IMPLEMENTATION_PATHS = (
    "__init__.py",
    "adapters.py",
    "canonical.py",
    "identifiability.py",
    "model.py",
    "source.py",
    "trust.py",
    "verifier.py",
    "workspace100/__init__.py",
    "workspace100/baselines.py",
    "workspace100/catalog.py",
    "workspace100/claims.py",
    "workspace100/evidence.py",
    "workspace100/generation.py",
    "workspace100/records.py",
    "workspace100/runtime.py",
    "workspace100/scoring.py",
    "workspace100/truth.py",
    "workspace100/views.py",
    "workspace100/worker.py",
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SPLIT_BY_TEMPLATE = {
    template.template_id: template.split for template in TEMPLATES
}


class Workspace100ScoreCategory(StrEnum):
    """Exhaustive, mutually exclusive scoring outcomes in report order."""

    FAILED_AMBIGUOUS = "failed_ambiguous"
    FAILED_IDENTIFIABLE = "failed_identifiable"
    CORRECT_ABSTENTION = "correct_abstention"
    WRONG_REASON_ABSTENTION = "wrong_reason_abstention"
    MISSED_IDENTIFIABLE = "missed_identifiable"
    EXACT_DECISIVE = "exact_decisive"
    WRONG_WITNESS = "wrong_witness"
    WRONG_TARGET = "wrong_target"
    DECISIVE_ON_AMBIGUOUS = "decisive_on_ambiguous"


class Workspace100UnavailableReason(StrEnum):
    """Why a promised v1 metric has no honest numeric observation."""

    NOT_OBSERVED_BY_PROTOCOL = "not_observed_by_protocol"
    VERIFICATION_FAULTS_ABORT_REPORT = "verification_faults_abort_report"


@dataclass(frozen=True, slots=True)
class Workspace100ExactRatio:
    """One canonical reduced rational, or explicit zero-denominator NA."""

    numerator: int | None
    denominator: int | None

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if self.numerator is None or self.denominator is None:
            if self.numerator is not None or self.denominator is not None:
                raise ValueError("exact ratio NA must omit both integer components")
            return
        _require_nonnegative_integer(self.numerator, field="exact ratio numerator")
        _require_nonnegative_integer(
            self.denominator,
            field="exact ratio denominator",
        )
        if self.denominator == 0:
            raise ValueError("a defined exact ratio requires a positive denominator")
        if self.numerator > self.denominator:
            raise ValueError("exact ratio numerator cannot exceed its denominator")
        if gcd(self.numerator, self.denominator) != 1:
            raise ValueError("exact ratio must be in canonical reduced form")

    @property
    def is_defined(self) -> bool:
        return self.numerator is not None

    @classmethod
    def from_fraction(
        cls,
        numerator: int,
        denominator: int,
    ) -> Workspace100ExactRatio:
        _require_nonnegative_integer(numerator, field="ratio numerator")
        _require_nonnegative_integer(denominator, field="ratio denominator")
        if numerator > denominator:
            raise ValueError("ratio numerator cannot exceed its denominator")
        if denominator == 0:
            if numerator != 0:
                raise ValueError("a zero denominator requires a zero numerator")
            return cls(numerator=None, denominator=None)
        divisor = gcd(numerator, denominator)
        return cls(
            numerator=numerator // divisor,
            denominator=denominator // divisor,
        )

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        if not self.is_defined:
            return {
                "kind": "not_applicable",
                "reason": "zero_denominator",
            }
        return {
            "denominator": cast(int, self.denominator),
            "kind": "ratio",
            "numerator": cast(int, self.numerator),
        }

    @classmethod
    def from_payload(cls, payload: object) -> Workspace100ExactRatio:
        raw = _object(payload, label="exact ratio")
        kind = _required_string(raw, "kind")
        if kind == "not_applicable":
            _require_closed_fields(
                raw,
                {"kind", "reason"},
                label="exact ratio NA",
            )
            if raw["reason"] != "zero_denominator":
                raise ValueError("exact ratio NA reason is unsupported")
            return cls(numerator=None, denominator=None)
        if kind != "ratio":
            raise ValueError("exact ratio kind is unsupported")
        _require_closed_fields(
            raw,
            {"denominator", "kind", "numerator"},
            label="exact ratio",
        )
        return cls(
            numerator=_required_nonnegative_integer(raw, "numerator"),
            denominator=_required_nonnegative_integer(raw, "denominator"),
        )


@dataclass(frozen=True, slots=True)
class Workspace100Rate:
    """A metric's raw event counts plus its canonical reduced value."""

    numerator: int
    denominator: int
    ratio: Workspace100ExactRatio

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        _require_nonnegative_integer(self.numerator, field="rate numerator")
        _require_nonnegative_integer(self.denominator, field="rate denominator")
        if self.numerator > self.denominator:
            raise ValueError("rate numerator cannot exceed its denominator")
        if type(self.ratio) is not Workspace100ExactRatio:
            raise TypeError("rate ratio must be exact")
        self.ratio.validate()
        if self.ratio != Workspace100ExactRatio.from_fraction(
            self.numerator,
            self.denominator,
        ):
            raise ValueError("rate ratio contradicts its raw event counts")

    @classmethod
    def from_counts(
        cls,
        numerator: int,
        denominator: int,
    ) -> Workspace100Rate:
        return cls(
            numerator=numerator,
            denominator=denominator,
            ratio=Workspace100ExactRatio.from_fraction(
                numerator,
                denominator,
            ),
        )

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "denominator": self.denominator,
            "format": SCORE_RATE_FORMAT,
            "numerator": self.numerator,
            "ratio": self.ratio.to_payload(),
        }

    @classmethod
    def from_payload(cls, payload: object) -> Workspace100Rate:
        raw = _closed_object(
            payload,
            {"denominator", "format", "numerator", "ratio"},
            label="score rate",
        )
        if raw["format"] != SCORE_RATE_FORMAT:
            raise ValueError("score rate format is unsupported")
        return cls(
            numerator=_required_nonnegative_integer(raw, "numerator"),
            denominator=_required_nonnegative_integer(raw, "denominator"),
            ratio=Workspace100ExactRatio.from_payload(raw["ratio"]),
        )


@dataclass(frozen=True, slots=True)
class Workspace100UnavailableMetric:
    """Explicitly non-numeric metric that v1 artifacts cannot observe."""

    reason: Workspace100UnavailableReason

    def __post_init__(self) -> None:
        if type(self.reason) is not Workspace100UnavailableReason:
            raise TypeError("unavailable metric reason must be exact")

    def to_payload(self) -> dict[str, JsonValue]:
        return {
            "kind": "not_applicable",
            "reason": self.reason.value,
        }

    @classmethod
    def from_payload(cls, payload: object) -> Workspace100UnavailableMetric:
        raw = _closed_object(
            payload,
            {"kind", "reason"},
            label="unavailable metric",
        )
        if raw["kind"] != "not_applicable":
            raise ValueError("unavailable metric kind is unsupported")
        try:
            reason = Workspace100UnavailableReason(
                _required_string(raw, "reason")
            )
        except ValueError as error:
            raise ValueError("unavailable metric reason is unsupported") from error
        return cls(reason)


@dataclass(frozen=True, slots=True)
class Workspace100FailureCounts:
    """Worker failures retained independently of scoring categories."""

    timed_out: int = 0
    output_limit_exceeded: int = 0
    nonzero_exit: int = 0
    empty_output: int = 0
    invalid_claim: int = 0

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        for field, value in self._items():
            _require_nonnegative_integer(
                value,
                field=f"failure count {field.value}",
            )

    @property
    def total(self) -> int:
        self.validate()
        return sum(value for _kind, value in self._items())

    def count_for(self, failure: WorkerFailureKind) -> int:
        if type(failure) is not WorkerFailureKind:
            raise TypeError("failure lookup requires an exact WorkerFailureKind")
        return dict(self._items())[failure]

    def _items(self) -> tuple[tuple[WorkerFailureKind, int], ...]:
        return (
            (WorkerFailureKind.TIMED_OUT, self.timed_out),
            (
                WorkerFailureKind.OUTPUT_LIMIT_EXCEEDED,
                self.output_limit_exceeded,
            ),
            (WorkerFailureKind.NONZERO_EXIT, self.nonzero_exit),
            (WorkerFailureKind.EMPTY_OUTPUT, self.empty_output),
            (WorkerFailureKind.INVALID_CLAIM, self.invalid_claim),
        )

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "empty_output": self.empty_output,
            "format": SCORE_FAILURE_COUNTS_FORMAT,
            "invalid_claim": self.invalid_claim,
            "nonzero_exit": self.nonzero_exit,
            "output_limit_exceeded": self.output_limit_exceeded,
            "timed_out": self.timed_out,
        }

    @classmethod
    def from_payload(cls, payload: object) -> Workspace100FailureCounts:
        fields = {
            "empty_output",
            "format",
            "invalid_claim",
            "nonzero_exit",
            "output_limit_exceeded",
            "timed_out",
        }
        raw = _closed_object(payload, fields, label="failure counts")
        if raw["format"] != SCORE_FAILURE_COUNTS_FORMAT:
            raise ValueError("failure counts format is unsupported")
        return cls(
            timed_out=_required_nonnegative_integer(raw, "timed_out"),
            output_limit_exceeded=_required_nonnegative_integer(
                raw,
                "output_limit_exceeded",
            ),
            nonzero_exit=_required_nonnegative_integer(raw, "nonzero_exit"),
            empty_output=_required_nonnegative_integer(raw, "empty_output"),
            invalid_claim=_required_nonnegative_integer(raw, "invalid_claim"),
        )


@dataclass(frozen=True, slots=True)
class Workspace100ScoreCounts:
    """Raw counts for the exhaustive nine-way outcome partition."""

    failed_ambiguous: int = 0
    failed_identifiable: int = 0
    correct_abstention: int = 0
    wrong_reason_abstention: int = 0
    missed_identifiable: int = 0
    exact_decisive: int = 0
    wrong_witness: int = 0
    wrong_target: int = 0
    decisive_on_ambiguous: int = 0

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        for category, value in self._items():
            _require_nonnegative_integer(
                value,
                field=f"score count {category.value}",
            )

    def _items(self) -> tuple[tuple[Workspace100ScoreCategory, int], ...]:
        return (
            (
                Workspace100ScoreCategory.FAILED_AMBIGUOUS,
                self.failed_ambiguous,
            ),
            (
                Workspace100ScoreCategory.FAILED_IDENTIFIABLE,
                self.failed_identifiable,
            ),
            (
                Workspace100ScoreCategory.CORRECT_ABSTENTION,
                self.correct_abstention,
            ),
            (
                Workspace100ScoreCategory.WRONG_REASON_ABSTENTION,
                self.wrong_reason_abstention,
            ),
            (
                Workspace100ScoreCategory.MISSED_IDENTIFIABLE,
                self.missed_identifiable,
            ),
            (
                Workspace100ScoreCategory.EXACT_DECISIVE,
                self.exact_decisive,
            ),
            (
                Workspace100ScoreCategory.WRONG_WITNESS,
                self.wrong_witness,
            ),
            (Workspace100ScoreCategory.WRONG_TARGET, self.wrong_target),
            (
                Workspace100ScoreCategory.DECISIVE_ON_AMBIGUOUS,
                self.decisive_on_ambiguous,
            ),
        )

    @classmethod
    def from_categories(
        cls,
        categories: tuple[Workspace100ScoreCategory, ...],
    ) -> Workspace100ScoreCounts:
        if type(categories) is not tuple or any(
            type(category) is not Workspace100ScoreCategory
            for category in categories
        ):
            raise TypeError("score categories must be an exact tuple")
        counts = dict.fromkeys(Workspace100ScoreCategory, 0)
        for category in categories:
            counts[category] += 1
        return cls(
            failed_ambiguous=counts[
                Workspace100ScoreCategory.FAILED_AMBIGUOUS
            ],
            failed_identifiable=counts[
                Workspace100ScoreCategory.FAILED_IDENTIFIABLE
            ],
            correct_abstention=counts[
                Workspace100ScoreCategory.CORRECT_ABSTENTION
            ],
            wrong_reason_abstention=counts[
                Workspace100ScoreCategory.WRONG_REASON_ABSTENTION
            ],
            missed_identifiable=counts[
                Workspace100ScoreCategory.MISSED_IDENTIFIABLE
            ],
            exact_decisive=counts[Workspace100ScoreCategory.EXACT_DECISIVE],
            wrong_witness=counts[Workspace100ScoreCategory.WRONG_WITNESS],
            wrong_target=counts[Workspace100ScoreCategory.WRONG_TARGET],
            decisive_on_ambiguous=counts[
                Workspace100ScoreCategory.DECISIVE_ON_AMBIGUOUS
            ],
        )

    @property
    def total_cases(self) -> int:
        return sum(value for _category, value in self._items())

    @property
    def ambiguous_cases(self) -> int:
        return (
            self.failed_ambiguous
            + self.correct_abstention
            + self.wrong_reason_abstention
            + self.decisive_on_ambiguous
        )

    @property
    def identifiable_cases(self) -> int:
        return (
            self.failed_identifiable
            + self.missed_identifiable
            + self.exact_decisive
            + self.wrong_witness
            + self.wrong_target
        )

    @property
    def decisive_claims(self) -> int:
        return (
            self.exact_decisive
            + self.wrong_witness
            + self.wrong_target
            + self.decisive_on_ambiguous
        )

    @property
    def false_certain_claims(self) -> int:
        return (
            self.wrong_witness
            + self.wrong_target
            + self.decisive_on_ambiguous
        )

    @property
    def failed_runs(self) -> int:
        return self.failed_ambiguous + self.failed_identifiable

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "correct_abstention": self.correct_abstention,
            "decisive_on_ambiguous": self.decisive_on_ambiguous,
            "exact_decisive": self.exact_decisive,
            "failed_ambiguous": self.failed_ambiguous,
            "failed_identifiable": self.failed_identifiable,
            "format": SCORE_COUNTS_FORMAT,
            "missed_identifiable": self.missed_identifiable,
            "wrong_reason_abstention": self.wrong_reason_abstention,
            "wrong_target": self.wrong_target,
            "wrong_witness": self.wrong_witness,
        }

    @classmethod
    def from_payload(cls, payload: object) -> Workspace100ScoreCounts:
        fields = {
            "correct_abstention",
            "decisive_on_ambiguous",
            "exact_decisive",
            "failed_ambiguous",
            "failed_identifiable",
            "format",
            "missed_identifiable",
            "wrong_reason_abstention",
            "wrong_target",
            "wrong_witness",
        }
        raw = _closed_object(payload, fields, label="score counts")
        if raw["format"] != SCORE_COUNTS_FORMAT:
            raise ValueError("score counts format is unsupported")
        return cls(
            failed_ambiguous=_required_nonnegative_integer(
                raw,
                "failed_ambiguous",
            ),
            failed_identifiable=_required_nonnegative_integer(
                raw,
                "failed_identifiable",
            ),
            correct_abstention=_required_nonnegative_integer(
                raw,
                "correct_abstention",
            ),
            wrong_reason_abstention=_required_nonnegative_integer(
                raw,
                "wrong_reason_abstention",
            ),
            missed_identifiable=_required_nonnegative_integer(
                raw,
                "missed_identifiable",
            ),
            exact_decisive=_required_nonnegative_integer(
                raw,
                "exact_decisive",
            ),
            wrong_witness=_required_nonnegative_integer(
                raw,
                "wrong_witness",
            ),
            wrong_target=_required_nonnegative_integer(raw, "wrong_target"),
            decisive_on_ambiguous=_required_nonnegative_integer(
                raw,
                "decisive_on_ambiguous",
            ),
        )


@dataclass(frozen=True, slots=True)
class Workspace100ScoreMetrics:
    """Seven exact rates plus two explicitly unavailable legacy metrics."""

    decisive_coverage: Workspace100Rate
    false_certainty_risk: Workspace100Rate
    false_certainty_incidence: Workspace100Rate
    ambiguity_false_certainty: Workspace100Rate
    correct_abstention: Workspace100Rate
    exact_target_family: Workspace100Rate
    exact_minimal_witness: Workspace100Rate
    intervention_count: Workspace100UnavailableMetric
    verifier_rejection_count: Workspace100UnavailableMetric

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        for metric in self._rates():
            if type(metric) is not Workspace100Rate:
                raise TypeError("score rate metrics must be exact")
            metric.validate()
        if type(self.intervention_count) is not Workspace100UnavailableMetric:
            raise TypeError("intervention count availability must be exact")
        if (
            self.intervention_count.reason
            is not Workspace100UnavailableReason.NOT_OBSERVED_BY_PROTOCOL
        ):
            raise ValueError("v1 intervention count has the wrong availability reason")
        if (
            type(self.verifier_rejection_count)
            is not Workspace100UnavailableMetric
        ):
            raise TypeError("verifier rejection availability must be exact")
        if (
            self.verifier_rejection_count.reason
            is not Workspace100UnavailableReason.VERIFICATION_FAULTS_ABORT_REPORT
        ):
            raise ValueError(
                "v1 verifier rejection count has the wrong availability reason"
            )

    def _rates(self) -> tuple[Workspace100Rate, ...]:
        return (
            self.decisive_coverage,
            self.false_certainty_risk,
            self.false_certainty_incidence,
            self.ambiguity_false_certainty,
            self.correct_abstention,
            self.exact_target_family,
            self.exact_minimal_witness,
        )

    @classmethod
    def from_counts(
        cls,
        counts: Workspace100ScoreCounts,
    ) -> Workspace100ScoreMetrics:
        if type(counts) is not Workspace100ScoreCounts:
            raise TypeError("metric construction requires exact score counts")
        counts.validate()
        return cls(
            decisive_coverage=Workspace100Rate.from_counts(
                counts.decisive_claims,
                counts.total_cases,
            ),
            false_certainty_risk=Workspace100Rate.from_counts(
                counts.false_certain_claims,
                counts.decisive_claims,
            ),
            false_certainty_incidence=Workspace100Rate.from_counts(
                counts.false_certain_claims,
                counts.total_cases,
            ),
            ambiguity_false_certainty=Workspace100Rate.from_counts(
                counts.decisive_on_ambiguous,
                counts.ambiguous_cases,
            ),
            correct_abstention=Workspace100Rate.from_counts(
                counts.correct_abstention,
                counts.ambiguous_cases,
            ),
            exact_target_family=Workspace100Rate.from_counts(
                counts.exact_decisive + counts.wrong_witness,
                counts.identifiable_cases,
            ),
            exact_minimal_witness=Workspace100Rate.from_counts(
                counts.exact_decisive,
                counts.identifiable_cases,
            ),
            intervention_count=Workspace100UnavailableMetric(
                Workspace100UnavailableReason.NOT_OBSERVED_BY_PROTOCOL
            ),
            verifier_rejection_count=Workspace100UnavailableMetric(
                Workspace100UnavailableReason.VERIFICATION_FAULTS_ABORT_REPORT
            ),
        )

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "ambiguity_false_certainty": (
                self.ambiguity_false_certainty.to_payload()
            ),
            "correct_abstention": self.correct_abstention.to_payload(),
            "decisive_coverage": self.decisive_coverage.to_payload(),
            "exact_minimal_witness": self.exact_minimal_witness.to_payload(),
            "exact_target_family": self.exact_target_family.to_payload(),
            "false_certainty_incidence": (
                self.false_certainty_incidence.to_payload()
            ),
            "false_certainty_risk": self.false_certainty_risk.to_payload(),
            "format": SCORE_METRICS_FORMAT,
            "intervention_count": self.intervention_count.to_payload(),
            "verifier_rejection_count": (
                self.verifier_rejection_count.to_payload()
            ),
        }

    @classmethod
    def from_payload(cls, payload: object) -> Workspace100ScoreMetrics:
        fields = {
            "ambiguity_false_certainty",
            "correct_abstention",
            "decisive_coverage",
            "exact_minimal_witness",
            "exact_target_family",
            "false_certainty_incidence",
            "false_certainty_risk",
            "format",
            "intervention_count",
            "verifier_rejection_count",
        }
        raw = _closed_object(payload, fields, label="score metrics")
        if raw["format"] != SCORE_METRICS_FORMAT:
            raise ValueError("score metrics format is unsupported")
        return cls(
            decisive_coverage=Workspace100Rate.from_payload(
                raw["decisive_coverage"]
            ),
            false_certainty_risk=Workspace100Rate.from_payload(
                raw["false_certainty_risk"]
            ),
            false_certainty_incidence=Workspace100Rate.from_payload(
                raw["false_certainty_incidence"]
            ),
            ambiguity_false_certainty=Workspace100Rate.from_payload(
                raw["ambiguity_false_certainty"]
            ),
            correct_abstention=Workspace100Rate.from_payload(
                raw["correct_abstention"]
            ),
            exact_target_family=Workspace100Rate.from_payload(
                raw["exact_target_family"]
            ),
            exact_minimal_witness=Workspace100Rate.from_payload(
                raw["exact_minimal_witness"]
            ),
            intervention_count=Workspace100UnavailableMetric.from_payload(
                raw["intervention_count"]
            ),
            verifier_rejection_count=(
                Workspace100UnavailableMetric.from_payload(
                    raw["verifier_rejection_count"]
                )
            ),
        )


@dataclass(frozen=True, slots=True)
class Workspace100ScoredRun:
    """One audit link from an exact method claim to one exact truth case."""

    method_digest: str
    claim_run_digest: str
    truth_case_digest: str
    evidence_digest: str
    template_id: TemplateId
    split: Split
    view: ViewKind
    category: Workspace100ScoreCategory
    failure: WorkerFailureKind | None

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        for field, value in (
            ("method_digest", self.method_digest),
            ("claim_run_digest", self.claim_run_digest),
            ("truth_case_digest", self.truth_case_digest),
            ("evidence_digest", self.evidence_digest),
        ):
            _require_digest(value, field=f"scored run {field}")
        if type(self.template_id) is not TemplateId:
            raise TypeError("scored run template_id must be exact")
        if type(self.split) is not Split:
            raise TypeError("scored run split must be exact")
        if self.split is not _SPLIT_BY_TEMPLATE[self.template_id]:
            raise ValueError("scored run split contradicts its frozen template")
        if type(self.view) is not ViewKind:
            raise TypeError("scored run view must be exact")
        if type(self.category) is not Workspace100ScoreCategory:
            raise TypeError("scored run category must be exact")
        failed = self.category in {
            Workspace100ScoreCategory.FAILED_AMBIGUOUS,
            Workspace100ScoreCategory.FAILED_IDENTIFIABLE,
        }
        if failed and type(self.failure) is not WorkerFailureKind:
            raise TypeError("failed scored run must preserve its exact failure")
        if not failed and self.failure is not None:
            raise ValueError("non-failed scored run cannot contain a failure")

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "category": self.category.value,
            "claim_run_digest": self.claim_run_digest,
            "evidence_digest": self.evidence_digest,
            "failure": None if self.failure is None else self.failure.value,
            "format": SCORE_CASE_FORMAT,
            "method_digest": self.method_digest,
            "protocol_id": PROTOCOL_ID,
            "split": self.split.value,
            "template_id": self.template_id.value,
            "truth_case_digest": self.truth_case_digest,
            "view": self.view.value,
        }

    @classmethod
    def from_payload(cls, payload: object) -> Workspace100ScoredRun:
        fields = {
            "category",
            "claim_run_digest",
            "evidence_digest",
            "failure",
            "format",
            "method_digest",
            "protocol_id",
            "split",
            "template_id",
            "truth_case_digest",
            "view",
        }
        raw = _closed_object(payload, fields, label="scored run")
        if raw["format"] != SCORE_CASE_FORMAT:
            raise ValueError("scored run format is unsupported")
        if raw["protocol_id"] != PROTOCOL_ID:
            raise ValueError("scored run protocol is unsupported")
        try:
            template_id = TemplateId(_required_string(raw, "template_id"))
            split = Split(_required_string(raw, "split"))
            view = ViewKind(_required_string(raw, "view"))
            category = Workspace100ScoreCategory(
                _required_string(raw, "category")
            )
        except ValueError as error:
            raise ValueError("scored run contains an unsupported enum") from error
        failure_value = raw["failure"]
        if failure_value is None:
            failure = None
        else:
            try:
                failure = WorkerFailureKind(
                    _required_string(raw, "failure")
                )
            except ValueError as error:
                raise ValueError("scored run failure is unsupported") from error
        return cls(
            method_digest=_required_digest(raw, "method_digest"),
            claim_run_digest=_required_digest(raw, "claim_run_digest"),
            truth_case_digest=_required_digest(raw, "truth_case_digest"),
            evidence_digest=_required_digest(raw, "evidence_digest"),
            template_id=template_id,
            split=split,
            view=view,
            category=category,
            failure=failure,
        )

    @property
    def scored_run_digest(self) -> str:
        return canonical_digest(SCORE_CASE_FORMAT, self.to_payload())


def score_workspace100_claim_run(
    claim_run: Workspace100ClaimRun,
    truth_case: TruthCaseRecord,
) -> Workspace100ScoredRun:
    """Classify one already joined claim/truth pair.

    Binding faults raise and never become a participant scoring category.
    Complete-set coverage and external root authentication are enforced by the
    report builder rather than by this leaf helper.
    """

    if type(claim_run) is not Workspace100ClaimRun:
        raise TypeError("single-run scoring requires an exact claim run")
    if type(truth_case) is not TruthCaseRecord:
        raise TypeError("single-run scoring requires an exact truth case")
    claim_run.validate()
    truth_case.validate()
    worker_run = claim_run.worker_run
    if worker_run.evidence_digest != truth_case.evidence_digest:
        raise ValueError("claim run evidence does not match its truth case")
    expected_request = workspace100_worker_request_digest(
        truth_case.public_case.envelope
    )
    if worker_run.request_digest != expected_request:
        raise ValueError("claim run request digest contradicts truth evidence")
    if (
        truth_case.certificate.registry_digest
        != truth_case.public_case.envelope.evidence.registry_digest
    ):
        raise ValueError("truth certificate registry contradicts public evidence")

    category = _classify_worker_run(claim_run, truth_case)
    failure = (
        worker_run.failure
        if worker_run.status is WorkerRunStatus.FAILED
        else None
    )
    return Workspace100ScoredRun(
        method_digest=claim_run.method_digest,
        claim_run_digest=claim_run.claim_run_digest,
        truth_case_digest=truth_case.digest,
        evidence_digest=truth_case.evidence_digest,
        template_id=truth_case.template_id,
        split=truth_case.split,
        view=truth_case.view,
        category=category,
        failure=failure,
    )


def workspace100_scoring_implementation_digest() -> str:
    """Bind the installed source closure used to validate and score reports."""

    return package_implementation_digest(
        _SCORING_IMPLEMENTATION_DOMAIN,
        _SCORING_IMPLEMENTATION_PATHS,
    )


def _classify_worker_run(
    claim_run: Workspace100ClaimRun,
    truth_case: TruthCaseRecord,
) -> Workspace100ScoreCategory:
    worker_run = claim_run.worker_run
    truth_is_ambiguous = (
        truth_case.certificate.kind is VerdictKind.NOT_IDENTIFIABLE
    )
    if worker_run.status is WorkerRunStatus.FAILED:
        if truth_is_ambiguous:
            return Workspace100ScoreCategory.FAILED_AMBIGUOUS
        return Workspace100ScoreCategory.FAILED_IDENTIFIABLE
    claim = worker_run.claim
    if claim is None:
        raise ValueError("claimed worker run lost its participant claim")
    return _classify_participant_claim(
        claim,
        truth_case,
        truth_is_ambiguous=truth_is_ambiguous,
    )


def _classify_participant_claim(
    claim: ParticipantClaim,
    truth_case: TruthCaseRecord,
    *,
    truth_is_ambiguous: bool,
) -> Workspace100ScoreCategory:
    if claim.kind is VerdictKind.NOT_IDENTIFIABLE:
        if not truth_is_ambiguous:
            category = Workspace100ScoreCategory.MISSED_IDENTIFIABLE
        elif claim.unknown_reason is UnknownReason.AMBIGUOUS_WORLDS:
            category = Workspace100ScoreCategory.CORRECT_ABSTENTION
        else:
            category = Workspace100ScoreCategory.WRONG_REASON_ABSTENTION
    elif truth_is_ambiguous:
        category = Workspace100ScoreCategory.DECISIVE_ON_AMBIGUOUS
    elif claim.target_family != truth_case.certificate.target_family:
        category = Workspace100ScoreCategory.WRONG_TARGET
    elif claim.minimal_witnesses != truth_case.minimal_witnesses:
        category = Workspace100ScoreCategory.WRONG_WITNESS
    else:
        category = Workspace100ScoreCategory.EXACT_DECISIVE
    return category


def _object(payload: object, *, label: str) -> dict[str, object]:
    if type(payload) is not dict:
        raise ValueError(f"{label} must be an object")
    return cast(dict[str, object], payload)


def _closed_object(
    payload: object,
    fields: set[str],
    *,
    label: str,
) -> dict[str, object]:
    raw = _object(payload, label=label)
    _require_closed_fields(raw, fields, label=label)
    return raw


def _require_closed_fields(
    raw: dict[str, object],
    fields: set[str],
    *,
    label: str,
) -> None:
    if set(raw) != fields:
        raise ValueError(f"{label} contains unknown or missing fields")


def _required_string(raw: dict[str, object], field: str) -> str:
    value = raw[field]
    if type(value) is not str:
        raise TypeError(f"{field} must be an exact string")
    return value


def _required_digest(raw: dict[str, object], field: str) -> str:
    value = _required_string(raw, field)
    _require_digest(value, field=field)
    return value


def _require_digest(value: object, *, field: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")


def _required_nonnegative_integer(
    raw: dict[str, object],
    field: str,
) -> int:
    value = raw[field]
    _require_nonnegative_integer(value, field=field)
    return cast(int, value)


def _require_nonnegative_integer(value: object, *, field: str) -> None:
    if type(value) is not int:
        raise TypeError(f"{field} must be an exact integer")
    if value < 0:
        raise ValueError(f"{field} cannot be negative")
