"""Truth-joined exact scoring primitives for Workspace-100.

The scorer is evaluator-side code.  It consumes complete ClaimSet and truth
artifacts, never participant output directly, and treats any broken binding as
an artifact error rather than as a method prediction.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from fractions import Fraction
from math import gcd
from typing import cast

from witnessgap.canonical import JsonValue, canonical_digest, canonical_json
from witnessgap.identifiability import UnknownReason, VerdictKind
from witnessgap.source import package_implementation_digest
from witnessgap.workspace100.baselines import (
    BUILTIN_BASELINE_SET_ROOT,
    BuiltinBaseline,
)
from witnessgap.workspace100.catalog import TEMPLATES
from witnessgap.workspace100.claims import (
    CLAIM_METHOD_REGISTRY_FORMAT,
    Workspace100ClaimMethod,
    Workspace100ClaimRun,
    Workspace100ClaimSet,
)
from witnessgap.workspace100.evidence import ParticipantClaim
from witnessgap.workspace100.records import PROTOCOL_ID, Split, TemplateId
from witnessgap.workspace100.truth import (
    TruthCaseRecord,
    Workspace100TruthSet,
)
from witnessgap.workspace100.views import ViewKind, Workspace100ProjectionRoots
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
SCORE_SLICE_FORMAT = "witnessgap.workspace100-score-slice.v1"
SCORE_MACRO_RATE_FORMAT = "witnessgap.workspace100-score-macro-rate.v1"
SCORE_MACRO_METRICS_FORMAT = "witnessgap.workspace100-score-macro-metrics.v1"
SCORE_TEMPLATE_MACRO_FORMAT = (
    "witnessgap.workspace100-score-template-macro.v1"
)
SCORE_METHOD_REPORT_FORMAT = "witnessgap.workspace100-score-method-report.v1"
SCORE_ORACLE_REPORT_FORMAT = "witnessgap.workspace100-score-oracle-report.v1"
SCORE_CASE_SET_FORMAT = "witnessgap.workspace100-score-case-set.v1"
SCORE_ADJUDICATION_SET_FORMAT = (
    "witnessgap.workspace100-score-adjudication-set.v1"
)
SCORE_AGGREGATE_SET_FORMAT = (
    "witnessgap.workspace100-score-aggregate-set.v1"
)
SCORE_REPORT_FORMAT = "witnessgap.workspace100-score-report.v1"

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
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{0,95}$")
_SPLIT_BY_TEMPLATE = {
    template.template_id: template.split for template in TEMPLATES
}
_METHOD_COUNT = 4
_CASE_COUNT = 300
_RUN_COUNT = _METHOD_COUNT * _CASE_COUNT
_SLICE_COUNT = 1 + len(ViewKind) + len(TemplateId) + (
    len(ViewKind) * len(TemplateId)
)
_MACRO_COUNT = 1 + len(ViewKind)
_MAX_SCORE_REPORT_BYTES = 4 << 20
_EXPECTED_CASES_BY_VIEW = {
    ViewKind.TRACE_ONLY: 50,
    ViewKind.OWNER_PROBE: 50,
    ViewKind.EPOCH_PROBE: 100,
    ViewKind.REFRESH_RECEIPT: 100,
}
_EXPECTED_CASES_PER_TEMPLATE = 60
_EXPECTED_CASES_BY_VIEW_TEMPLATE = {
    ViewKind.TRACE_ONLY: 10,
    ViewKind.OWNER_PROBE: 10,
    ViewKind.EPOCH_PROBE: 20,
    ViewKind.REFRESH_RECEIPT: 20,
}
_VIEW_RANK = {view: rank for rank, view in enumerate(ViewKind)}
_TEMPLATE_RANK = {
    template_id: rank for rank, template_id in enumerate(TemplateId)
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


class Workspace100SliceKind(StrEnum):
    """Closed micro-aggregation dimensions in canonical report order."""

    OVERALL = "overall"
    VIEW = "view"
    TEMPLATE = "template"
    VIEW_TEMPLATE = "view_template"


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


@dataclass(frozen=True, slots=True)
class Workspace100ScoreSlice:
    """One exact micro table at a closed report dimension."""

    kind: Workspace100SliceKind
    view: ViewKind | None
    template_id: TemplateId | None
    counts: Workspace100ScoreCounts
    failure_counts: Workspace100FailureCounts
    metrics: Workspace100ScoreMetrics

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if type(self.kind) is not Workspace100SliceKind:
            raise TypeError("score slice kind must be exact")
        _validate_slice_dimensions(self.kind, self.view, self.template_id)
        if type(self.counts) is not Workspace100ScoreCounts:
            raise TypeError("score slice counts must be exact")
        self.counts.validate()
        if type(self.failure_counts) is not Workspace100FailureCounts:
            raise TypeError("score slice failure counts must be exact")
        self.failure_counts.validate()
        if self.failure_counts.total != self.counts.failed_runs:
            raise ValueError("score slice failures contradict failed categories")
        if type(self.metrics) is not Workspace100ScoreMetrics:
            raise TypeError("score slice metrics must be exact")
        self.metrics.validate()
        if self.metrics != Workspace100ScoreMetrics.from_counts(self.counts):
            raise ValueError("score slice metrics contradict category counts")
        expected_total = _expected_slice_total(
            self.kind,
            self.view,
            self.template_id,
        )
        if self.counts.total_cases != expected_total:
            raise ValueError("score slice total contradicts its frozen dimension")

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "counts": self.counts.to_payload(),
            "failure_counts": self.failure_counts.to_payload(),
            "format": SCORE_SLICE_FORMAT,
            "kind": self.kind.value,
            "metrics": self.metrics.to_payload(),
            "protocol_id": PROTOCOL_ID,
            "template_id": (
                None if self.template_id is None else self.template_id.value
            ),
            "view": None if self.view is None else self.view.value,
        }

    @classmethod
    def from_payload(cls, payload: object) -> Workspace100ScoreSlice:
        fields = {
            "counts",
            "failure_counts",
            "format",
            "kind",
            "metrics",
            "protocol_id",
            "template_id",
            "view",
        }
        raw = _closed_object(payload, fields, label="score slice")
        if raw["format"] != SCORE_SLICE_FORMAT:
            raise ValueError("score slice format is unsupported")
        if raw["protocol_id"] != PROTOCOL_ID:
            raise ValueError("score slice protocol is unsupported")
        try:
            kind = Workspace100SliceKind(_required_string(raw, "kind"))
        except ValueError as error:
            raise ValueError("score slice kind is unsupported") from error
        return cls(
            kind=kind,
            view=_optional_view(raw["view"]),
            template_id=_optional_template(raw["template_id"]),
            counts=Workspace100ScoreCounts.from_payload(raw["counts"]),
            failure_counts=Workspace100FailureCounts.from_payload(
                raw["failure_counts"]
            ),
            metrics=Workspace100ScoreMetrics.from_payload(raw["metrics"]),
        )

    @property
    def slice_digest(self) -> str:
        return canonical_digest(SCORE_SLICE_FORMAT, self.to_payload())


@dataclass(frozen=True, slots=True)
class Workspace100MacroRate:
    """Unweighted mean over the defined template rates in one macro."""

    defined_template_count: int
    ratio: Workspace100ExactRatio

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        _require_nonnegative_integer(
            self.defined_template_count,
            field="macro defined_template_count",
        )
        if self.defined_template_count > len(TemplateId):
            raise ValueError("macro defined_template_count exceeds template count")
        if type(self.ratio) is not Workspace100ExactRatio:
            raise TypeError("macro ratio must be exact")
        self.ratio.validate()
        if self.ratio.is_defined != (self.defined_template_count > 0):
            raise ValueError("macro ratio availability contradicts component count")

    @classmethod
    def from_rates(
        cls,
        rates: tuple[Workspace100Rate, ...],
    ) -> Workspace100MacroRate:
        if (
            type(rates) is not tuple
            or len(rates) != len(TemplateId)
            or any(type(rate) is not Workspace100Rate for rate in rates)
        ):
            raise TypeError("macro construction requires five exact rates")
        for rate in rates:
            rate.validate()
        defined = tuple(rate.ratio for rate in rates if rate.ratio.is_defined)
        if not defined:
            return cls(
                defined_template_count=0,
                ratio=Workspace100ExactRatio(None, None),
            )
        total = sum(
            (
                Fraction(
                    cast(int, ratio.numerator),
                    cast(int, ratio.denominator),
                )
                for ratio in defined
            ),
            start=Fraction(0, 1),
        )
        mean = total / len(defined)
        return cls(
            defined_template_count=len(defined),
            ratio=Workspace100ExactRatio(
                numerator=mean.numerator,
                denominator=mean.denominator,
            ),
        )

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "defined_template_count": self.defined_template_count,
            "format": SCORE_MACRO_RATE_FORMAT,
            "ratio": self.ratio.to_payload(),
        }

    @classmethod
    def from_payload(cls, payload: object) -> Workspace100MacroRate:
        raw = _closed_object(
            payload,
            {"defined_template_count", "format", "ratio"},
            label="macro rate",
        )
        if raw["format"] != SCORE_MACRO_RATE_FORMAT:
            raise ValueError("macro rate format is unsupported")
        return cls(
            defined_template_count=_required_nonnegative_integer(
                raw,
                "defined_template_count",
            ),
            ratio=Workspace100ExactRatio.from_payload(raw["ratio"]),
        )


@dataclass(frozen=True, slots=True)
class Workspace100MacroMetrics:
    """Seven exact unweighted template macros and two honest v1 NAs."""

    decisive_coverage: Workspace100MacroRate
    false_certainty_risk: Workspace100MacroRate
    false_certainty_incidence: Workspace100MacroRate
    ambiguity_false_certainty: Workspace100MacroRate
    correct_abstention: Workspace100MacroRate
    exact_target_family: Workspace100MacroRate
    exact_minimal_witness: Workspace100MacroRate
    intervention_count: Workspace100UnavailableMetric
    verifier_rejection_count: Workspace100UnavailableMetric

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        for metric in self._rates():
            if type(metric) is not Workspace100MacroRate:
                raise TypeError("macro rate metrics must be exact")
            metric.validate()
        _validate_unavailable_metrics(
            self.intervention_count,
            self.verifier_rejection_count,
        )

    def _rates(self) -> tuple[Workspace100MacroRate, ...]:
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
    def from_slices(
        cls,
        slices: tuple[Workspace100ScoreSlice, ...],
    ) -> Workspace100MacroMetrics:
        if (
            type(slices) is not tuple
            or len(slices) != len(TemplateId)
            or any(type(score_slice) is not Workspace100ScoreSlice for score_slice in slices)
        ):
            raise TypeError("macro metrics require five exact template slices")
        for score_slice in slices:
            score_slice.validate()
        if tuple(score_slice.template_id for score_slice in slices) != tuple(
            TemplateId
        ):
            raise ValueError("macro slices must cover templates in order")
        first_kind = slices[0].kind
        if first_kind is Workspace100SliceKind.TEMPLATE:
            if any(
                score_slice.kind is not first_kind
                or score_slice.view is not None
                for score_slice in slices
            ):
                raise ValueError("overall macro requires five template slices")
        elif first_kind is Workspace100SliceKind.VIEW_TEMPLATE:
            first_view = slices[0].view
            if any(
                score_slice.kind is not first_kind
                or score_slice.view is not first_view
                for score_slice in slices
            ):
                raise ValueError(
                    "view macro requires five slices from one exact view"
                )
        else:
            raise ValueError("macro metrics require template-grain slices")
        rates_by_metric = tuple(
            tuple(score_slice.metrics._rates()[index] for score_slice in slices)
            for index in range(7)
        )
        macro_rates = tuple(
            Workspace100MacroRate.from_rates(rates)
            for rates in rates_by_metric
        )
        return cls(
            decisive_coverage=macro_rates[0],
            false_certainty_risk=macro_rates[1],
            false_certainty_incidence=macro_rates[2],
            ambiguity_false_certainty=macro_rates[3],
            correct_abstention=macro_rates[4],
            exact_target_family=macro_rates[5],
            exact_minimal_witness=macro_rates[6],
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
            "exact_minimal_witness": (
                self.exact_minimal_witness.to_payload()
            ),
            "exact_target_family": self.exact_target_family.to_payload(),
            "false_certainty_incidence": (
                self.false_certainty_incidence.to_payload()
            ),
            "false_certainty_risk": self.false_certainty_risk.to_payload(),
            "format": SCORE_MACRO_METRICS_FORMAT,
            "intervention_count": self.intervention_count.to_payload(),
            "verifier_rejection_count": (
                self.verifier_rejection_count.to_payload()
            ),
        }

    @classmethod
    def from_payload(cls, payload: object) -> Workspace100MacroMetrics:
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
        raw = _closed_object(payload, fields, label="macro metrics")
        if raw["format"] != SCORE_MACRO_METRICS_FORMAT:
            raise ValueError("macro metrics format is unsupported")
        return cls(
            decisive_coverage=Workspace100MacroRate.from_payload(
                raw["decisive_coverage"]
            ),
            false_certainty_risk=Workspace100MacroRate.from_payload(
                raw["false_certainty_risk"]
            ),
            false_certainty_incidence=Workspace100MacroRate.from_payload(
                raw["false_certainty_incidence"]
            ),
            ambiguity_false_certainty=Workspace100MacroRate.from_payload(
                raw["ambiguity_false_certainty"]
            ),
            correct_abstention=Workspace100MacroRate.from_payload(
                raw["correct_abstention"]
            ),
            exact_target_family=Workspace100MacroRate.from_payload(
                raw["exact_target_family"]
            ),
            exact_minimal_witness=Workspace100MacroRate.from_payload(
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
class Workspace100TemplateMacro:
    """One overall or view-scoped unweighted template macro."""

    view: ViewKind | None
    metrics: Workspace100MacroMetrics

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if self.view is not None and type(self.view) is not ViewKind:
            raise TypeError("template macro view must be exact or None")
        if type(self.metrics) is not Workspace100MacroMetrics:
            raise TypeError("template macro metrics must be exact")
        self.metrics.validate()

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "format": SCORE_TEMPLATE_MACRO_FORMAT,
            "metrics": self.metrics.to_payload(),
            "protocol_id": PROTOCOL_ID,
            "view": None if self.view is None else self.view.value,
        }

    @classmethod
    def from_payload(cls, payload: object) -> Workspace100TemplateMacro:
        raw = _closed_object(
            payload,
            {"format", "metrics", "protocol_id", "view"},
            label="template macro",
        )
        if raw["format"] != SCORE_TEMPLATE_MACRO_FORMAT:
            raise ValueError("template macro format is unsupported")
        if raw["protocol_id"] != PROTOCOL_ID:
            raise ValueError("template macro protocol is unsupported")
        return cls(
            view=_optional_view(raw["view"]),
            metrics=Workspace100MacroMetrics.from_payload(raw["metrics"]),
        )

    @property
    def macro_digest(self) -> str:
        return canonical_digest(SCORE_TEMPLATE_MACRO_FORMAT, self.to_payload())


@dataclass(frozen=True, slots=True)
class Workspace100MethodReport:
    """All micro and template-macro tables for one frozen baseline."""

    baseline: BuiltinBaseline
    baseline_bundle_digest: str
    method_id: str
    program_implementation_digest: str
    method_digest: str
    scored_run_root: str
    slices: tuple[Workspace100ScoreSlice, ...]
    template_macros: tuple[Workspace100TemplateMacro, ...]

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if type(self.baseline) is not BuiltinBaseline:
            raise TypeError("method report baseline must be exact")
        for field, value in (
            ("baseline_bundle_digest", self.baseline_bundle_digest),
            (
                "program_implementation_digest",
                self.program_implementation_digest,
            ),
            ("method_digest", self.method_digest),
            ("scored_run_root", self.scored_run_root),
        ):
            _require_digest(value, field=f"method report {field}")
        _require_identifier(self.method_id, field="method report method_id")
        method = self.claim_method
        if method.method_digest != self.method_digest:
            raise ValueError("method report digest contradicts method identity")
        _validate_slice_collection(self.slices)
        _validate_macro_collection(self.template_macros)
        if self.template_macros != _build_template_macros(self.slices):
            raise ValueError("method report macros contradict its micro slices")

    @property
    def claim_method(self) -> Workspace100ClaimMethod:
        return Workspace100ClaimMethod(
            baseline=self.baseline,
            baseline_bundle_digest=self.baseline_bundle_digest,
            method_id=self.method_id,
            program_implementation_digest=self.program_implementation_digest,
        )

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "baseline": self.baseline.value,
            "baseline_bundle_digest": self.baseline_bundle_digest,
            "format": SCORE_METHOD_REPORT_FORMAT,
            "method_digest": self.method_digest,
            "method_id": self.method_id,
            "program_implementation_digest": (
                self.program_implementation_digest
            ),
            "protocol_id": PROTOCOL_ID,
            "scored_run_root": self.scored_run_root,
            "slices": tuple(score_slice.to_payload() for score_slice in self.slices),
            "template_macros": tuple(
                macro.to_payload() for macro in self.template_macros
            ),
        }

    @classmethod
    def from_payload(cls, payload: object) -> Workspace100MethodReport:
        fields = {
            "baseline",
            "baseline_bundle_digest",
            "format",
            "method_digest",
            "method_id",
            "program_implementation_digest",
            "protocol_id",
            "scored_run_root",
            "slices",
            "template_macros",
        }
        raw = _closed_object(payload, fields, label="method report")
        if raw["format"] != SCORE_METHOD_REPORT_FORMAT:
            raise ValueError("method report format is unsupported")
        if raw["protocol_id"] != PROTOCOL_ID:
            raise ValueError("method report protocol is unsupported")
        try:
            baseline = BuiltinBaseline(_required_string(raw, "baseline"))
        except ValueError as error:
            raise ValueError("method report baseline is unsupported") from error
        return cls(
            baseline=baseline,
            baseline_bundle_digest=_required_digest(
                raw,
                "baseline_bundle_digest",
            ),
            method_id=_required_string(raw, "method_id"),
            program_implementation_digest=_required_digest(
                raw,
                "program_implementation_digest",
            ),
            method_digest=_required_digest(raw, "method_digest"),
            scored_run_root=_required_digest(raw, "scored_run_root"),
            slices=tuple(
                Workspace100ScoreSlice.from_payload(item)
                for item in _required_array(
                    raw,
                    "slices",
                    length=_SLICE_COUNT,
                )
            ),
            template_macros=tuple(
                Workspace100TemplateMacro.from_payload(item)
                for item in _required_array(
                    raw,
                    "template_macros",
                    length=_MACRO_COUNT,
                )
            ),
        )

    @property
    def method_report_digest(self) -> str:
        return canonical_digest(SCORE_METHOD_REPORT_FORMAT, self.to_payload())


@dataclass(frozen=True, slots=True)
class Workspace100OracleReport:
    """Truth-derived, non-participant oracle ceiling reported separately."""

    slices: tuple[Workspace100ScoreSlice, ...]
    template_macros: tuple[Workspace100TemplateMacro, ...]

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        _validate_slice_collection(self.slices)
        _validate_macro_collection(self.template_macros)
        if self.template_macros != _build_template_macros(self.slices):
            raise ValueError("oracle macros contradict its micro slices")
        for score_slice in self.slices:
            counts = score_slice.counts
            if (
                counts.failed_ambiguous
                or counts.failed_identifiable
                or counts.wrong_reason_abstention
                or counts.missed_identifiable
                or counts.wrong_witness
                or counts.wrong_target
                or counts.decisive_on_ambiguous
            ):
                raise ValueError("oracle ceiling contains a non-exact outcome")
            if score_slice.failure_counts.total:
                raise ValueError("oracle ceiling cannot contain worker failures")
            expected_abstentions, expected_decisive = _oracle_exact_counts(
                score_slice.kind,
                score_slice.view,
            )
            if (
                counts.correct_abstention,
                counts.exact_decisive,
            ) != (expected_abstentions, expected_decisive):
                raise ValueError(
                    "oracle ceiling contradicts the frozen truth shape"
                )

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "format": SCORE_ORACLE_REPORT_FORMAT,
            "oracle": "verified_truth_ceiling",
            "protocol_id": PROTOCOL_ID,
            "slices": tuple(score_slice.to_payload() for score_slice in self.slices),
            "template_macros": tuple(
                macro.to_payload() for macro in self.template_macros
            ),
        }

    @classmethod
    def from_payload(cls, payload: object) -> Workspace100OracleReport:
        raw = _closed_object(
            payload,
            {
                "format",
                "oracle",
                "protocol_id",
                "slices",
                "template_macros",
            },
            label="oracle report",
        )
        if raw["format"] != SCORE_ORACLE_REPORT_FORMAT:
            raise ValueError("oracle report format is unsupported")
        if raw["protocol_id"] != PROTOCOL_ID:
            raise ValueError("oracle report protocol is unsupported")
        if raw["oracle"] != "verified_truth_ceiling":
            raise ValueError("oracle report identity is unsupported")
        return cls(
            slices=tuple(
                Workspace100ScoreSlice.from_payload(item)
                for item in _required_array(
                    raw,
                    "slices",
                    length=_SLICE_COUNT,
                )
            ),
            template_macros=tuple(
                Workspace100TemplateMacro.from_payload(item)
                for item in _required_array(
                    raw,
                    "template_macros",
                    length=_MACRO_COUNT,
                )
            ),
        )

    @property
    def oracle_report_digest(self) -> str:
        return canonical_digest(SCORE_ORACLE_REPORT_FORMAT, self.to_payload())


@dataclass(frozen=True, slots=True)
class Workspace100ScoreBindings:
    """Caller-authenticated identities required before scoring can begin."""

    claim_set_root: str
    truth_root: str
    baseline_set_root: str
    assignment_root: str
    evidence_root: str
    projection_root: str
    method_registry_root: str
    scoring_implementation_digest: str

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        for field, value in (
            ("claim_set_root", self.claim_set_root),
            ("truth_root", self.truth_root),
            ("baseline_set_root", self.baseline_set_root),
            ("assignment_root", self.assignment_root),
            ("evidence_root", self.evidence_root),
            ("projection_root", self.projection_root),
            ("method_registry_root", self.method_registry_root),
            (
                "scoring_implementation_digest",
                self.scoring_implementation_digest,
            ),
        ):
            _require_digest(value, field=f"expected score binding {field}")
        if self.baseline_set_root != BUILTIN_BASELINE_SET_ROOT:
            raise ValueError("expected score baseline root is not the frozen root")
        Workspace100ProjectionRoots(
            assignment_root=self.assignment_root,
            evidence_root=self.evidence_root,
            projection_root=self.projection_root,
        )


@dataclass(frozen=True, slots=True)
class Workspace100ScoreReport:
    """Closed, exact report derived from one authenticated ClaimSet and truth."""

    claim_set_root: str
    truth_root: str
    baseline_set_root: str
    assignment_root: str
    evidence_root: str
    projection_root: str
    method_registry_root: str
    scoring_implementation_digest: str
    scored_runs: tuple[Workspace100ScoredRun, ...]
    methods: tuple[Workspace100MethodReport, ...]
    oracle_ceiling: Workspace100OracleReport

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        _validate_report_header(self)
        _validate_report_scored_runs(self)
        _validate_report_methods(self)
        if type(self.oracle_ceiling) is not Workspace100OracleReport:
            raise TypeError("score report oracle ceiling must be exact")
        self.oracle_ceiling.validate()

    @property
    def adjudication_root(self) -> str:
        self.validate()
        return _adjudication_root(self)

    @property
    def aggregate_root(self) -> str:
        self.validate()
        return _aggregate_root(self)

    @property
    def report_root(self) -> str:
        self.validate()
        return _report_root(self)

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        adjudication_root = _adjudication_root(self)
        aggregate_root = _aggregate_root(
            self,
            adjudication_root=adjudication_root,
        )
        return {
            "adjudication_root": adjudication_root,
            "aggregate_root": aggregate_root,
            "assignment_root": self.assignment_root,
            "baseline_set_root": self.baseline_set_root,
            "claim_set_root": self.claim_set_root,
            "evidence_root": self.evidence_root,
            "format": SCORE_REPORT_FORMAT,
            "method_registry_root": self.method_registry_root,
            "methods": tuple(method.to_payload() for method in self.methods),
            "oracle_ceiling": self.oracle_ceiling.to_payload(),
            "projection_root": self.projection_root,
            "protocol_id": PROTOCOL_ID,
            "report_root": _report_root(
                self,
                adjudication_root=adjudication_root,
                aggregate_root=aggregate_root,
            ),
            "scored_runs": tuple(
                scored_run.to_payload() for scored_run in self.scored_runs
            ),
            "scoring_implementation_digest": (
                self.scoring_implementation_digest
            ),
            "truth_root": self.truth_root,
        }

    def to_canonical_bytes(self) -> bytes:
        payload = canonical_json(self.to_payload())
        if len(payload) > _MAX_SCORE_REPORT_BYTES:
            raise ValueError("score report exceeds its byte bound")
        return payload

    @classmethod
    def from_canonical_bytes(
        cls,
        payload: bytes,
    ) -> Workspace100ScoreReport:
        """Parse structural integrity only; authenticate with the safe loader."""

        return _parse_score_report(payload)


def score_workspace100_claim_run(
    claim_run: Workspace100ClaimRun,
    truth_case: TruthCaseRecord,
) -> Workspace100ScoredRun:
    """Classify one already joined claim/truth pair.

    Binding faults raise and never become a participant scoring category.
    Complete-set coverage and external root authentication are enforced by the
    report builder rather than by this structural leaf helper.  Callers that
    need an authenticated result must use :func:`score_workspace100_claims`.
    """

    if type(claim_run) is not Workspace100ClaimRun:
        raise TypeError("single-run scoring requires an exact claim run")
    if type(truth_case) is not TruthCaseRecord:
        raise TypeError("single-run scoring requires an exact truth case")
    claim_run.validate()
    truth_case.validate()
    return _score_validated_claim_run(
        claim_run,
        truth_case,
        expected_request_digest=workspace100_worker_request_digest(
            truth_case.public_case.envelope
        ),
        claim_run_digest=claim_run.claim_run_digest,
        truth_case_digest=truth_case.digest,
    )


def _score_validated_claim_run(
    claim_run: Workspace100ClaimRun,
    truth_case: TruthCaseRecord,
    *,
    expected_request_digest: str,
    claim_run_digest: str,
    truth_case_digest: str,
) -> Workspace100ScoredRun:
    worker_run = claim_run.worker_run
    if worker_run.evidence_digest != truth_case.evidence_digest:
        raise ValueError("claim run evidence does not match its truth case")
    if worker_run.request_digest != expected_request_digest:
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
        claim_run_digest=claim_run_digest,
        truth_case_digest=truth_case_digest,
        evidence_digest=truth_case.evidence_digest,
        template_id=truth_case.template_id,
        split=truth_case.split,
        view=truth_case.view,
        category=category,
        failure=failure,
    )


def score_workspace100_claims(
    claim_set: Workspace100ClaimSet,
    truth: Workspace100TruthSet,
    *,
    expected: Workspace100ScoreBindings,
) -> Workspace100ScoreReport:
    """Build a complete report only after independently pinned root checks."""

    if type(claim_set) is not Workspace100ClaimSet:
        raise TypeError("report scoring requires an exact ClaimSet")
    if type(truth) is not Workspace100TruthSet:
        raise TypeError("report scoring requires an exact truth set")
    expected_snapshot = _snapshot_score_bindings(expected)
    current_implementation = workspace100_scoring_implementation_digest()
    if (
        expected_snapshot.scoring_implementation_digest
        != current_implementation
    ):
        raise ValueError(
            "expected scorer identity differs from the installed source closure"
        )
    claim_snapshot = Workspace100ClaimSet.from_canonical_bytes(
        claim_set.to_canonical_bytes()
    )
    truth_snapshot = Workspace100TruthSet.from_canonical_bytes(
        truth.to_canonical_bytes()
    )
    _verify_score_source_bindings(
        claim_snapshot,
        truth_snapshot,
        expected_snapshot,
        current_implementation=current_implementation,
    )

    truth_context_by_evidence = {
        truth_case.evidence_digest: (
            workspace100_worker_request_digest(
                truth_case.public_case.envelope
            ),
            truth_case.digest,
        )
        for truth_case in truth_snapshot.cases
    }
    if len(truth_context_by_evidence) != _CASE_COUNT:
        raise ValueError("score truth must contain 300 unique evidence digests")
    claim_by_key = {
        (claim_run.method_digest, claim_run.worker_run.evidence_digest): claim_run
        for claim_run in claim_snapshot.runs
    }
    if len(claim_by_key) != _RUN_COUNT:
        raise ValueError("score ClaimSet must contain 1,200 unique run keys")
    claim_digest_by_key = {
        key: claim_run.claim_run_digest
        for key, claim_run in claim_by_key.items()
    }

    scored_runs: list[Workspace100ScoredRun] = []
    for method in claim_snapshot.methods:
        for truth_case in truth_snapshot.cases:
            key = (method.method_digest, truth_case.evidence_digest)
            claim_run = claim_by_key.get(key)
            if claim_run is None:
                raise ValueError("score ClaimSet does not cover exact truth evidence")
            (
                expected_request_digest,
                truth_case_digest,
            ) = truth_context_by_evidence[truth_case.evidence_digest]
            scored_runs.append(
                _score_validated_claim_run(
                    claim_run,
                    truth_case,
                    expected_request_digest=expected_request_digest,
                    claim_run_digest=claim_digest_by_key[key],
                    truth_case_digest=truth_case_digest,
                )
            )
    expected_keys = {
        (method.method_digest, evidence_digest)
        for method in claim_snapshot.methods
        for evidence_digest in truth_context_by_evidence
    }
    if set(claim_by_key) != expected_keys:
        raise ValueError("score ClaimSet contains foreign truth evidence")

    scored_tuple = tuple(scored_runs)
    methods = tuple(
        _build_method_report(
            method,
            tuple(
                scored_run
                for scored_run in scored_tuple
                if scored_run.method_digest == method.method_digest
            ),
        )
        for method in claim_snapshot.methods
    )
    report = Workspace100ScoreReport(
        claim_set_root=expected_snapshot.claim_set_root,
        truth_root=expected_snapshot.truth_root,
        baseline_set_root=expected_snapshot.baseline_set_root,
        assignment_root=expected_snapshot.assignment_root,
        evidence_root=expected_snapshot.evidence_root,
        projection_root=expected_snapshot.projection_root,
        method_registry_root=expected_snapshot.method_registry_root,
        scoring_implementation_digest=(
            expected_snapshot.scoring_implementation_digest
        ),
        scored_runs=scored_tuple,
        methods=methods,
        oracle_ceiling=_build_oracle_report(truth_snapshot),
    )
    return report


def load_verified_workspace100_score_report(
    payload: bytes,
    claim_set: Workspace100ClaimSet,
    truth: Workspace100TruthSet,
    *,
    expected: Workspace100ScoreBindings,
    expected_report_root: str,
) -> Workspace100ScoreReport:
    """Parse, authenticate, and independently rebuild a score report."""

    _require_digest(
        expected_report_root,
        field="expected score report root",
    )
    parsed = Workspace100ScoreReport.from_canonical_bytes(payload)
    if parsed.report_root != expected_report_root:
        raise ValueError("score report root contradicts the expected root")
    rebuilt = score_workspace100_claims(
        claim_set,
        truth,
        expected=expected,
    )
    if (
        rebuilt.report_root != expected_report_root
        or rebuilt.to_canonical_bytes() != payload
    ):
        raise ValueError(
            "score report differs from the authenticated source rebuild"
        )
    return parsed


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


@dataclass(frozen=True, slots=True)
class _ScoreObservation:
    view: ViewKind
    template_id: TemplateId
    category: Workspace100ScoreCategory
    failure: WorkerFailureKind | None


def _snapshot_score_bindings(
    expected: Workspace100ScoreBindings,
) -> Workspace100ScoreBindings:
    if type(expected) is not Workspace100ScoreBindings:
        raise TypeError("score construction requires exact expected bindings")
    expected.validate()
    return Workspace100ScoreBindings(
        claim_set_root=expected.claim_set_root,
        truth_root=expected.truth_root,
        baseline_set_root=expected.baseline_set_root,
        assignment_root=expected.assignment_root,
        evidence_root=expected.evidence_root,
        projection_root=expected.projection_root,
        method_registry_root=expected.method_registry_root,
        scoring_implementation_digest=(
            expected.scoring_implementation_digest
        ),
    )


def _verify_score_source_bindings(
    claim_set: Workspace100ClaimSet,
    truth: Workspace100TruthSet,
    expected: Workspace100ScoreBindings,
    *,
    current_implementation: str,
) -> None:
    _require_digest(
        current_implementation,
        field="current scoring implementation",
    )
    if expected.scoring_implementation_digest != current_implementation:
        raise ValueError(
            "expected scorer identity differs from the installed source closure"
        )
    claim_bindings = (
        claim_set.claim_set_root,
        claim_set.baseline_set_root,
        claim_set.assignment_root,
        claim_set.evidence_root,
        claim_set.projection_root,
        claim_set.method_registry_root,
    )
    expected_claim_bindings = (
        expected.claim_set_root,
        expected.baseline_set_root,
        expected.assignment_root,
        expected.evidence_root,
        expected.projection_root,
        expected.method_registry_root,
    )
    if claim_bindings != expected_claim_bindings:
        raise ValueError("ClaimSet contradicts expected score bindings")
    truth_bindings = (
        truth.truth_root,
        truth.assignment_root,
        truth.evidence_root,
        truth.projection_root,
    )
    expected_truth_bindings = (
        expected.truth_root,
        expected.assignment_root,
        expected.evidence_root,
        expected.projection_root,
    )
    if truth_bindings != expected_truth_bindings:
        raise ValueError("truth set contradicts expected score bindings")
    if (
        claim_set.assignment_root,
        claim_set.evidence_root,
        claim_set.projection_root,
    ) != (
        truth.assignment_root,
        truth.evidence_root,
        truth.projection_root,
    ):
        raise ValueError("ClaimSet and truth bind different public projections")


def _validate_unavailable_metrics(
    intervention_count: object,
    verifier_rejection_count: object,
) -> None:
    if type(intervention_count) is not Workspace100UnavailableMetric:
        raise TypeError("intervention count availability must be exact")
    if (
        intervention_count.reason
        is not Workspace100UnavailableReason.NOT_OBSERVED_BY_PROTOCOL
    ):
        raise ValueError("v1 intervention count has the wrong availability reason")
    if type(verifier_rejection_count) is not Workspace100UnavailableMetric:
        raise TypeError("verifier rejection availability must be exact")
    if (
        verifier_rejection_count.reason
        is not Workspace100UnavailableReason.VERIFICATION_FAULTS_ABORT_REPORT
    ):
        raise ValueError(
            "v1 verifier rejection count has the wrong availability reason"
        )


def _validate_slice_dimensions(
    kind: Workspace100SliceKind,
    view: ViewKind | None,
    template_id: TemplateId | None,
) -> None:
    if view is not None and type(view) is not ViewKind:
        raise TypeError("score slice view must be exact or None")
    if template_id is not None and type(template_id) is not TemplateId:
        raise TypeError("score slice template_id must be exact or None")
    expected_presence = {
        Workspace100SliceKind.OVERALL: (False, False),
        Workspace100SliceKind.VIEW: (True, False),
        Workspace100SliceKind.TEMPLATE: (False, True),
        Workspace100SliceKind.VIEW_TEMPLATE: (True, True),
    }[kind]
    if (view is not None, template_id is not None) != expected_presence:
        raise ValueError("score slice dimensions contradict its kind")


def _expected_slice_total(
    kind: Workspace100SliceKind,
    view: ViewKind | None,
    template_id: TemplateId | None,
) -> int:
    _validate_slice_dimensions(kind, view, template_id)
    if kind is Workspace100SliceKind.OVERALL:
        return _CASE_COUNT
    if kind is Workspace100SliceKind.VIEW:
        return _EXPECTED_CASES_BY_VIEW[cast(ViewKind, view)]
    if kind is Workspace100SliceKind.TEMPLATE:
        return _EXPECTED_CASES_PER_TEMPLATE
    return _EXPECTED_CASES_BY_VIEW_TEMPLATE[cast(ViewKind, view)]


def _oracle_exact_counts(
    kind: Workspace100SliceKind,
    view: ViewKind | None,
) -> tuple[int, int]:
    if kind is Workspace100SliceKind.OVERALL:
        return (100, 200)
    if kind is Workspace100SliceKind.TEMPLATE:
        return (20, 40)
    resolved_view = cast(ViewKind, view)
    total = (
        _EXPECTED_CASES_BY_VIEW[resolved_view]
        if kind is Workspace100SliceKind.VIEW
        else _EXPECTED_CASES_BY_VIEW_TEMPLATE[resolved_view]
    )
    if resolved_view in {ViewKind.TRACE_ONLY, ViewKind.OWNER_PROBE}:
        return (total, 0)
    return (0, total)


def _slice_dimensions(
) -> tuple[
    tuple[Workspace100SliceKind, ViewKind | None, TemplateId | None],
    ...,
]:
    return (
        (Workspace100SliceKind.OVERALL, None, None),
        *(
            (Workspace100SliceKind.VIEW, view, None) for view in ViewKind
        ),
        *(
            (Workspace100SliceKind.TEMPLATE, None, template_id)
            for template_id in TemplateId
        ),
        *(
            (Workspace100SliceKind.VIEW_TEMPLATE, view, template_id)
            for view in ViewKind
            for template_id in TemplateId
        ),
    )


def _matches_slice(
    observation: _ScoreObservation,
    *,
    view: ViewKind | None,
    template_id: TemplateId | None,
) -> bool:
    return (
        (view is None or observation.view is view)
        and (
            template_id is None
            or observation.template_id is template_id
        )
    )


def _build_score_slice(
    observations: tuple[_ScoreObservation, ...],
    *,
    kind: Workspace100SliceKind,
    view: ViewKind | None,
    template_id: TemplateId | None,
) -> Workspace100ScoreSlice:
    selected = tuple(
        observation
        for observation in observations
        if _matches_slice(
            observation,
            view=view,
            template_id=template_id,
        )
    )
    categories = tuple(observation.category for observation in selected)
    counts = Workspace100ScoreCounts.from_categories(categories)
    failure_values = tuple(
        observation.failure
        for observation in selected
        if observation.failure is not None
    )
    failure_counts_by_kind = {
        failure: failure_values.count(failure) for failure in WorkerFailureKind
    }
    failure_counts = Workspace100FailureCounts(
        timed_out=failure_counts_by_kind[WorkerFailureKind.TIMED_OUT],
        output_limit_exceeded=failure_counts_by_kind[
            WorkerFailureKind.OUTPUT_LIMIT_EXCEEDED
        ],
        nonzero_exit=failure_counts_by_kind[WorkerFailureKind.NONZERO_EXIT],
        empty_output=failure_counts_by_kind[WorkerFailureKind.EMPTY_OUTPUT],
        invalid_claim=failure_counts_by_kind[WorkerFailureKind.INVALID_CLAIM],
    )
    return Workspace100ScoreSlice(
        kind=kind,
        view=view,
        template_id=template_id,
        counts=counts,
        failure_counts=failure_counts,
        metrics=Workspace100ScoreMetrics.from_counts(counts),
    )


def _build_slices(
    observations: tuple[_ScoreObservation, ...],
) -> tuple[Workspace100ScoreSlice, ...]:
    if type(observations) is not tuple or any(
        type(observation) is not _ScoreObservation
        for observation in observations
    ):
        raise TypeError("slice construction requires exact observations")
    return tuple(
        _build_score_slice(
            observations,
            kind=kind,
            view=view,
            template_id=template_id,
        )
        for kind, view, template_id in _slice_dimensions()
    )


def _validate_slice_collection(
    slices: tuple[Workspace100ScoreSlice, ...],
) -> None:
    if (
        type(slices) is not tuple
        or len(slices) != _SLICE_COUNT
        or any(type(score_slice) is not Workspace100ScoreSlice for score_slice in slices)
    ):
        raise TypeError("report requires 30 exact score slices")
    for score_slice in slices:
        score_slice.validate()
    actual_dimensions = tuple(
        (score_slice.kind, score_slice.view, score_slice.template_id)
        for score_slice in slices
    )
    if actual_dimensions != _slice_dimensions():
        raise ValueError("score slices are not in canonical dimension order")
    _validate_slice_additivity(slices)


def _count_vector(
    score_slice: Workspace100ScoreSlice,
) -> tuple[int, ...]:
    return tuple(
        value for _category, value in score_slice.counts._items()
    ) + tuple(
        score_slice.failure_counts.count_for(failure)
        for failure in WorkerFailureKind
    )


def _sum_count_vectors(
    slices: tuple[Workspace100ScoreSlice, ...],
) -> tuple[int, ...]:
    width = len(Workspace100ScoreCategory) + len(WorkerFailureKind)
    return tuple(
        sum(_count_vector(score_slice)[index] for score_slice in slices)
        for index in range(width)
    )


def _validate_slice_additivity(
    slices: tuple[Workspace100ScoreSlice, ...],
) -> None:
    overall = slices[0]
    overall_vector = _count_vector(overall)
    view_slices = tuple(
        score_slice
        for score_slice in slices
        if score_slice.kind is Workspace100SliceKind.VIEW
    )
    template_slices = tuple(
        score_slice
        for score_slice in slices
        if score_slice.kind is Workspace100SliceKind.TEMPLATE
    )
    if (
        _sum_count_vectors(view_slices) != overall_vector
        or _sum_count_vectors(template_slices) != overall_vector
    ):
        raise ValueError("score slice top-level tables are not additive")
    for view_slice in view_slices:
        components = tuple(
            score_slice
            for score_slice in slices
            if score_slice.kind is Workspace100SliceKind.VIEW_TEMPLATE
            and score_slice.view is view_slice.view
        )
        if _sum_count_vectors(components) != _count_vector(view_slice):
            raise ValueError(
                "view-template slices do not add to their view"
            )
    for template_slice in template_slices:
        components = tuple(
            score_slice
            for score_slice in slices
            if score_slice.kind is Workspace100SliceKind.VIEW_TEMPLATE
            and score_slice.template_id is template_slice.template_id
        )
        if _sum_count_vectors(components) != _count_vector(template_slice):
            raise ValueError(
                "view-template slices do not add to their template"
            )


def _template_slices_for(
    slices: tuple[Workspace100ScoreSlice, ...],
    *,
    view: ViewKind | None,
) -> tuple[Workspace100ScoreSlice, ...]:
    kind = (
        Workspace100SliceKind.TEMPLATE
        if view is None
        else Workspace100SliceKind.VIEW_TEMPLATE
    )
    selected = tuple(
        score_slice
        for score_slice in slices
        if score_slice.kind is kind and score_slice.view is view
    )
    if tuple(score_slice.template_id for score_slice in selected) != tuple(
        TemplateId
    ):
        raise ValueError("macro source slices do not cover templates in order")
    return selected


def _build_template_macros(
    slices: tuple[Workspace100ScoreSlice, ...],
) -> tuple[Workspace100TemplateMacro, ...]:
    _validate_slice_collection(slices)
    return tuple(
        Workspace100TemplateMacro(
            view=view,
            metrics=Workspace100MacroMetrics.from_slices(
                _template_slices_for(slices, view=view)
            ),
        )
        for view in (None, *tuple(ViewKind))
    )


def _validate_macro_collection(
    macros: tuple[Workspace100TemplateMacro, ...],
) -> None:
    if (
        type(macros) is not tuple
        or len(macros) != _MACRO_COUNT
        or any(type(macro) is not Workspace100TemplateMacro for macro in macros)
    ):
        raise TypeError("report requires five exact template macros")
    for macro in macros:
        macro.validate()
    if tuple(macro.view for macro in macros) != (None, *tuple(ViewKind)):
        raise ValueError("template macros are not in canonical view order")


def _observations_from_scored_runs(
    scored_runs: tuple[Workspace100ScoredRun, ...],
) -> tuple[_ScoreObservation, ...]:
    return tuple(
        _ScoreObservation(
            view=scored_run.view,
            template_id=scored_run.template_id,
            category=scored_run.category,
            failure=scored_run.failure,
        )
        for scored_run in scored_runs
    )


def _build_method_report(
    method: Workspace100ClaimMethod,
    scored_runs: tuple[Workspace100ScoredRun, ...],
) -> Workspace100MethodReport:
    if type(method) is not Workspace100ClaimMethod:
        raise TypeError("method report construction requires an exact method")
    method.validate()
    _validate_method_scored_runs(method.method_digest, scored_runs)
    slices = _build_slices(_observations_from_scored_runs(scored_runs))
    return Workspace100MethodReport(
        baseline=method.baseline,
        baseline_bundle_digest=method.baseline_bundle_digest,
        method_id=method.method_id,
        program_implementation_digest=method.program_implementation_digest,
        method_digest=method.method_digest,
        scored_run_root=_method_scored_run_root(
            method.method_digest,
            scored_runs,
        ),
        slices=slices,
        template_macros=_build_template_macros(slices),
    )


def _validate_method_scored_runs(
    method_digest: str,
    scored_runs: tuple[Workspace100ScoredRun, ...],
) -> None:
    _require_digest(method_digest, field="scored method digest")
    if (
        type(scored_runs) is not tuple
        or len(scored_runs) != _CASE_COUNT
        or any(type(scored_run) is not Workspace100ScoredRun for scored_run in scored_runs)
    ):
        raise TypeError("method report requires 300 exact scored runs")
    for scored_run in scored_runs:
        scored_run.validate()
    if any(
        scored_run.method_digest != method_digest
        for scored_run in scored_runs
    ):
        raise ValueError("method report contains a foreign scored run")
    evidence = tuple(scored_run.evidence_digest for scored_run in scored_runs)
    if len(set(evidence)) != _CASE_COUNT:
        raise ValueError("method report scored evidence must be unique")
    if scored_runs != tuple(
        sorted(
            scored_runs,
            key=lambda scored_run: (
                _VIEW_RANK[scored_run.view],
                _TEMPLATE_RANK[scored_run.template_id],
                scored_run.evidence_digest,
            ),
        )
    ):
        raise ValueError("method report scored runs are not in truth order")


def _method_scored_run_root(
    method_digest: str,
    scored_runs: tuple[Workspace100ScoredRun, ...],
) -> str:
    _validate_method_scored_runs(method_digest, scored_runs)
    return canonical_digest(
        SCORE_CASE_SET_FORMAT,
        {
            "format": SCORE_CASE_SET_FORMAT,
            "method_digest": method_digest,
            "protocol_id": PROTOCOL_ID,
            "scored_run_digests": tuple(
                scored_run.scored_run_digest for scored_run in scored_runs
            ),
        },
    )


def _build_oracle_report(
    truth: Workspace100TruthSet,
) -> Workspace100OracleReport:
    truth.validate()
    observations = tuple(
        _ScoreObservation(
            view=truth_case.view,
            template_id=truth_case.template_id,
            category=(
                Workspace100ScoreCategory.CORRECT_ABSTENTION
                if truth_case.certificate.kind is VerdictKind.NOT_IDENTIFIABLE
                else Workspace100ScoreCategory.EXACT_DECISIVE
            ),
            failure=None,
        )
        for truth_case in truth.cases
    )
    slices = _build_slices(observations)
    return Workspace100OracleReport(
        slices=slices,
        template_macros=_build_template_macros(slices),
    )


def _validate_report_header(report: Workspace100ScoreReport) -> None:
    for field, value in (
        ("claim_set_root", report.claim_set_root),
        ("truth_root", report.truth_root),
        ("baseline_set_root", report.baseline_set_root),
        ("assignment_root", report.assignment_root),
        ("evidence_root", report.evidence_root),
        ("projection_root", report.projection_root),
        ("method_registry_root", report.method_registry_root),
        (
            "scoring_implementation_digest",
            report.scoring_implementation_digest,
        ),
    ):
        _require_digest(value, field=f"score report {field}")
    if report.baseline_set_root != BUILTIN_BASELINE_SET_ROOT:
        raise ValueError("score report baseline root is not the frozen root")
    Workspace100ProjectionRoots(
        assignment_root=report.assignment_root,
        evidence_root=report.evidence_root,
        projection_root=report.projection_root,
    )


def _validate_report_scored_runs(report: Workspace100ScoreReport) -> None:
    if (
        type(report.scored_runs) is not tuple
        or len(report.scored_runs) != _RUN_COUNT
        or any(
            type(scored_run) is not Workspace100ScoredRun
            for scored_run in report.scored_runs
        )
    ):
        raise TypeError("score report requires 1,200 exact scored runs")
    for scored_run in report.scored_runs:
        scored_run.validate()
    keys = tuple(
        (scored_run.method_digest, scored_run.evidence_digest)
        for scored_run in report.scored_runs
    )
    if len(set(keys)) != _RUN_COUNT:
        raise ValueError("score report method/evidence keys must be unique")
    if (
        len(
            {
                scored_run.claim_run_digest
                for scored_run in report.scored_runs
            }
        )
        != _RUN_COUNT
    ):
        raise ValueError("score report claim-run digests must be unique")
    method_digests = tuple(
        dict.fromkeys(scored_run.method_digest for scored_run in report.scored_runs)
    )
    if len(method_digests) != _METHOD_COUNT:
        raise ValueError("score report must contain four method identities")
    method_rank = {
        method_digest: rank
        for rank, method_digest in enumerate(method_digests)
    }
    if report.scored_runs != tuple(
        sorted(
            report.scored_runs,
            key=lambda scored_run: (
                method_rank[scored_run.method_digest],
                _VIEW_RANK[scored_run.view],
                _TEMPLATE_RANK[scored_run.template_id],
                scored_run.evidence_digest,
            ),
        )
    ):
        raise ValueError("score report scored runs are not in canonical order")
    evidence_by_method = tuple(
        tuple(
            scored_run.evidence_digest
            for scored_run in report.scored_runs
            if scored_run.method_digest == method_digest
        )
        for method_digest in method_digests
    )
    if any(len(evidence) != _CASE_COUNT for evidence in evidence_by_method):
        raise ValueError("score report methods do not each contain 300 runs")
    expected_evidence = frozenset(evidence_by_method[0])
    if any(
        frozenset(evidence) != expected_evidence
        for evidence in evidence_by_method[1:]
    ):
        raise ValueError("score report methods cover different evidence sets")
    truth_links_by_method = tuple(
        {
            scored_run.evidence_digest: (
                scored_run.truth_case_digest,
                scored_run.template_id,
                scored_run.split,
                scored_run.view,
            )
            for scored_run in report.scored_runs
            if scored_run.method_digest == method_digest
        }
        for method_digest in method_digests
    )
    if (
        len(
            {
                link[0]
                for link in truth_links_by_method[0].values()
            }
        )
        != _CASE_COUNT
    ):
        raise ValueError("score report truth-case digests must be unique")
    if any(
        links != truth_links_by_method[0]
        for links in truth_links_by_method[1:]
    ):
        raise ValueError("score report methods bind different truth mappings")


def _validate_report_methods(report: Workspace100ScoreReport) -> None:
    if (
        type(report.methods) is not tuple
        or len(report.methods) != _METHOD_COUNT
        or any(
            type(method) is not Workspace100MethodReport
            for method in report.methods
        )
    ):
        raise TypeError("score report requires four exact method reports")
    for method in report.methods:
        method.validate()
    if tuple(method.baseline for method in report.methods) != tuple(
        BuiltinBaseline
    ):
        raise ValueError("score method reports are not in frozen baseline order")
    claim_methods = tuple(method.claim_method for method in report.methods)
    expected_registry_root = canonical_digest(
        CLAIM_METHOD_REGISTRY_FORMAT,
        {
            "baseline_set_root": report.baseline_set_root,
            "format": CLAIM_METHOD_REGISTRY_FORMAT,
            "method_digests": tuple(
                method.method_digest for method in claim_methods
            ),
            "protocol_id": PROTOCOL_ID,
        },
    )
    if report.method_registry_root != expected_registry_root:
        raise ValueError("score report method registry root is inconsistent")
    if tuple(method.method_digest for method in report.methods) != tuple(
        dict.fromkeys(
            scored_run.method_digest for scored_run in report.scored_runs
        )
    ):
        raise ValueError("method reports contradict scored-run method order")
    for method in report.methods:
        scored_runs = tuple(
            scored_run
            for scored_run in report.scored_runs
            if scored_run.method_digest == method.method_digest
        )
        expected_slices = _build_slices(
            _observations_from_scored_runs(scored_runs)
        )
        if (
            method.scored_run_root
            != _method_scored_run_root(method.method_digest, scored_runs)
            or method.slices != expected_slices
        ):
            raise ValueError("method report contradicts its scored runs")


def _adjudication_root(report: Workspace100ScoreReport) -> str:
    return canonical_digest(
        SCORE_ADJUDICATION_SET_FORMAT,
        {
            "claim_set_root": report.claim_set_root,
            "format": SCORE_ADJUDICATION_SET_FORMAT,
            "protocol_id": PROTOCOL_ID,
            "scored_run_digests": tuple(
                scored_run.scored_run_digest
                for scored_run in report.scored_runs
            ),
            "truth_root": report.truth_root,
        },
    )


def _aggregate_root(
    report: Workspace100ScoreReport,
    *,
    adjudication_root: str | None = None,
) -> str:
    resolved_adjudication = (
        _adjudication_root(report)
        if adjudication_root is None
        else adjudication_root
    )
    return canonical_digest(
        SCORE_AGGREGATE_SET_FORMAT,
        {
            "adjudication_root": resolved_adjudication,
            "format": SCORE_AGGREGATE_SET_FORMAT,
            "method_report_digests": tuple(
                method.method_report_digest for method in report.methods
            ),
            "oracle_report_digest": (
                report.oracle_ceiling.oracle_report_digest
            ),
            "protocol_id": PROTOCOL_ID,
        },
    )


def _report_root(
    report: Workspace100ScoreReport,
    *,
    adjudication_root: str | None = None,
    aggregate_root: str | None = None,
) -> str:
    resolved_adjudication = (
        _adjudication_root(report)
        if adjudication_root is None
        else adjudication_root
    )
    resolved_aggregate = (
        _aggregate_root(
            report,
            adjudication_root=resolved_adjudication,
        )
        if aggregate_root is None
        else aggregate_root
    )
    return canonical_digest(
        SCORE_REPORT_FORMAT,
        {
            "adjudication_root": resolved_adjudication,
            "aggregate_root": resolved_aggregate,
            "assignment_root": report.assignment_root,
            "baseline_set_root": report.baseline_set_root,
            "claim_set_root": report.claim_set_root,
            "evidence_root": report.evidence_root,
            "format": SCORE_REPORT_FORMAT,
            "method_registry_root": report.method_registry_root,
            "projection_root": report.projection_root,
            "protocol_id": PROTOCOL_ID,
            "scoring_implementation_digest": (
                report.scoring_implementation_digest
            ),
            "truth_root": report.truth_root,
        },
    )


def _parse_score_report(payload: object) -> Workspace100ScoreReport:
    raw = _parse_score_report_object(payload)
    fields = {
        "adjudication_root",
        "aggregate_root",
        "assignment_root",
        "baseline_set_root",
        "claim_set_root",
        "evidence_root",
        "format",
        "method_registry_root",
        "methods",
        "oracle_ceiling",
        "projection_root",
        "protocol_id",
        "report_root",
        "scored_runs",
        "scoring_implementation_digest",
        "truth_root",
    }
    _require_closed_fields(raw, fields, label="score report")
    if raw["format"] != SCORE_REPORT_FORMAT:
        raise ValueError("score report format is unsupported")
    if raw["protocol_id"] != PROTOCOL_ID:
        raise ValueError("score report protocol is unsupported")
    stored_adjudication_root = _required_digest(raw, "adjudication_root")
    stored_aggregate_root = _required_digest(raw, "aggregate_root")
    stored_report_root = _required_digest(raw, "report_root")
    report = Workspace100ScoreReport(
        claim_set_root=_required_digest(raw, "claim_set_root"),
        truth_root=_required_digest(raw, "truth_root"),
        baseline_set_root=_required_digest(raw, "baseline_set_root"),
        assignment_root=_required_digest(raw, "assignment_root"),
        evidence_root=_required_digest(raw, "evidence_root"),
        projection_root=_required_digest(raw, "projection_root"),
        method_registry_root=_required_digest(raw, "method_registry_root"),
        scoring_implementation_digest=_required_digest(
            raw,
            "scoring_implementation_digest",
        ),
        scored_runs=tuple(
            Workspace100ScoredRun.from_payload(item)
            for item in _required_array(
                raw,
                "scored_runs",
                length=_RUN_COUNT,
            )
        ),
        methods=tuple(
            Workspace100MethodReport.from_payload(item)
            for item in _required_array(
                raw,
                "methods",
                length=_METHOD_COUNT,
            )
        ),
        oracle_ceiling=Workspace100OracleReport.from_payload(
            raw["oracle_ceiling"]
        ),
    )
    adjudication_root = _adjudication_root(report)
    aggregate_root = _aggregate_root(
        report,
        adjudication_root=adjudication_root,
    )
    if (
        stored_adjudication_root,
        stored_aggregate_root,
        stored_report_root,
    ) != (
        adjudication_root,
        aggregate_root,
        _report_root(
            report,
            adjudication_root=adjudication_root,
            aggregate_root=aggregate_root,
        ),
    ):
        raise ValueError("score report stored roots contradict its contents")
    canonical = report.to_canonical_bytes()
    if canonical != payload:
        raise ValueError("score report failed canonical round-trip")
    return report


def _parse_score_report_object(payload: object) -> dict[str, object]:
    if type(payload) is not bytes:
        raise TypeError("score report payload must be exact bytes")
    if not payload or len(payload) > _MAX_SCORE_REPORT_BYTES:
        raise ValueError("score report payload exceeds its byte bound")
    try:
        decoded = json.loads(payload)
    except (
        json.JSONDecodeError,
        RecursionError,
        UnicodeDecodeError,
    ) as error:
        raise ValueError("score report is not valid bounded JSON") from error
    return _object(decoded, label="score report")


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


def _required_array(
    raw: dict[str, object],
    field: str,
    *,
    length: int,
) -> list[object]:
    value = raw[field]
    if type(value) is not list or len(value) != length:
        raise ValueError(f"{field} must contain exactly {length} items")
    return cast(list[object], value)


def _optional_view(value: object) -> ViewKind | None:
    if value is None:
        return None
    if type(value) is not str:
        raise TypeError("view must be an exact string or null")
    try:
        return ViewKind(value)
    except ValueError as error:
        raise ValueError("view is unsupported") from error


def _optional_template(value: object) -> TemplateId | None:
    if value is None:
        return None
    if type(value) is not str:
        raise TypeError("template_id must be an exact string or null")
    try:
        return TemplateId(value)
    except ValueError as error:
        raise ValueError("template_id is unsupported") from error


def _require_digest(value: object, *, field: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")


def _require_identifier(value: object, *, field: str) -> None:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{field} must be a normalized identifier")


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
