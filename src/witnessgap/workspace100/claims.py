"""Order-independent result records for Workspace-100 baseline workers.

This module belongs to the trusted evaluator.  It binds complete worker-run
records to the frozen baseline registry and public evidence projection without
importing or consulting private truth.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import cast

from witnessgap.canonical import JsonValue, canonical_digest, canonical_json
from witnessgap.workspace100.baselines import (
    BUILTIN_BASELINE_SET_ROOT,
    BuiltinBaseline,
    BuiltinBaselineArtifact,
    BuiltinBaselineBundle,
    BuiltinBaselineSet,
    builtin_baseline_set,
)
from witnessgap.workspace100.records import PROTOCOL_ID
from witnessgap.workspace100.views import (
    PublicEvidenceCase,
    Workspace100EvidenceViews,
    Workspace100ProjectionRoots,
    workspace100_projection_roots,
)
from witnessgap.workspace100.worker import (
    WorkerBackend,
    WorkerLimits,
    WorkerRunRecord,
    run_worker_once,
    workspace100_worker_request_digest,
)

CLAIM_METHOD_FORMAT = "witnessgap.workspace100-claim-method.v1"
CLAIM_RUN_FORMAT = "witnessgap.workspace100-claim-run.v1"
CLAIM_METHOD_REGISTRY_FORMAT = (
    "witnessgap.workspace100-claim-method-registry.v1"
)
CLAIM_RUN_SET_FORMAT = "witnessgap.workspace100-claim-run-set.v1"
CLAIM_SET_FORMAT = "witnessgap.workspace100-claim-set.v1"

_METHOD_COUNT = 4
_CASE_COUNT = 300
_RUN_COUNT = _METHOD_COUNT * _CASE_COUNT
_MAX_CLAIM_SET_BYTES = 8 << 20
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{0,95}$")
_EVIDENCE_PROJECTION_FORMAT = "witnessgap.workspace100-evidence-projection.v1"


@dataclass(frozen=True, slots=True)
class _ExpectedExecution:
    backend_implementation_digest: str
    limits: WorkerLimits

    def __post_init__(self) -> None:
        _require_digest(
            self.backend_implementation_digest,
            field="expected backend_implementation_digest",
        )
        if type(self.limits) is not WorkerLimits:
            raise TypeError("expected execution limits must be exact")
        self.limits.validate()


@dataclass(frozen=True, slots=True)
class Workspace100ClaimMethod:
    """One frozen baseline identity admitted to a claim set."""

    baseline: BuiltinBaseline
    baseline_bundle_digest: str
    method_id: str
    program_implementation_digest: str

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if type(self.baseline) is not BuiltinBaseline:
            raise TypeError("claim method baseline must be exact")
        _require_digest(
            self.baseline_bundle_digest,
            field="claim method baseline_bundle_digest",
        )
        _require_identifier(self.method_id, field="claim method method_id")
        _require_digest(
            self.program_implementation_digest,
            field="claim method program_implementation_digest",
        )
        expected = BuiltinBaselineBundle(self.baseline)
        if (
            self.baseline_bundle_digest,
            self.method_id,
            self.program_implementation_digest,
        ) != (
            expected.bundle_digest,
            expected.method_id,
            expected.program_implementation_digest,
        ):
            raise ValueError("claim method contradicts its frozen baseline bundle")

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "baseline": self.baseline.value,
            "baseline_bundle_digest": self.baseline_bundle_digest,
            "format": CLAIM_METHOD_FORMAT,
            "method_id": self.method_id,
            "program_implementation_digest": self.program_implementation_digest,
            "protocol_id": PROTOCOL_ID,
        }

    @classmethod
    def from_payload(cls, payload: object) -> Workspace100ClaimMethod:
        raw = _closed_object(
            payload,
            {
                "baseline",
                "baseline_bundle_digest",
                "format",
                "method_id",
                "program_implementation_digest",
                "protocol_id",
            },
            label="claim method",
        )
        if raw["format"] != CLAIM_METHOD_FORMAT:
            raise ValueError("claim method format is unsupported")
        if raw["protocol_id"] != PROTOCOL_ID:
            raise ValueError("claim method protocol is unsupported")
        try:
            baseline = BuiltinBaseline(_required_string(raw, "baseline"))
        except ValueError as error:
            raise ValueError("claim method baseline is unsupported") from error
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
        )

    @property
    def method_digest(self) -> str:
        return canonical_digest(CLAIM_METHOD_FORMAT, self.to_payload())


@dataclass(frozen=True, slots=True)
class Workspace100ClaimRun:
    """One method-bound worker record, including normalized worker failures."""

    method_digest: str
    worker_run: WorkerRunRecord

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        _require_digest(self.method_digest, field="claim run method_digest")
        if type(self.worker_run) is not WorkerRunRecord:
            raise TypeError("claim run worker record must be exact")
        self.worker_run.validate()

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "format": CLAIM_RUN_FORMAT,
            "method_digest": self.method_digest,
            "protocol_id": PROTOCOL_ID,
            "worker_run": self.worker_run.to_payload(),
            "worker_run_digest": self.worker_run.run_digest,
        }

    @classmethod
    def from_payload(cls, payload: object) -> Workspace100ClaimRun:
        raw = _closed_object(
            payload,
            {
                "format",
                "method_digest",
                "protocol_id",
                "worker_run",
                "worker_run_digest",
            },
            label="claim run",
        )
        if raw["format"] != CLAIM_RUN_FORMAT:
            raise ValueError("claim run format is unsupported")
        if raw["protocol_id"] != PROTOCOL_ID:
            raise ValueError("claim run protocol is unsupported")
        worker_run = WorkerRunRecord.from_canonical_bytes(
            canonical_json(cast(JsonValue, raw["worker_run"]))
        )
        if _required_digest(raw, "worker_run_digest") != worker_run.run_digest:
            raise ValueError("claim run stored worker digest contradicts its record")
        return cls(
            method_digest=_required_digest(raw, "method_digest"),
            worker_run=worker_run,
        )

    @property
    def claim_run_digest(self) -> str:
        return canonical_digest(CLAIM_RUN_FORMAT, self.to_payload())


@dataclass(frozen=True, slots=True)
class Workspace100RunKey:
    """Transient parent-side execution key; never part of a result artifact."""

    method_id: str
    evidence_digest: str

    def __post_init__(self) -> None:
        _require_identifier(self.method_id, field="run key method_id")
        _require_digest(self.evidence_digest, field="run key evidence_digest")


@dataclass(frozen=True, slots=True)
class Workspace100ExecutionPlan:
    """Transient ordered backends plus caller-pinned execution identity."""

    backends: tuple[WorkerBackend, ...]
    expected_backend_implementation_digest: str
    limits: WorkerLimits

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if type(self.backends) is not tuple or len(self.backends) != _METHOD_COUNT:
            raise TypeError("execution plan requires four ordered backends")
        _require_digest(
            self.expected_backend_implementation_digest,
            field="execution plan expected backend implementation_digest",
        )
        if type(self.limits) is not WorkerLimits:
            raise TypeError("execution plan requires exact worker limits")
        self.limits.validate()


@dataclass(frozen=True, slots=True)
class Workspace100ClaimSet:
    """Closed 4x300 baseline result matrix in canonical result order."""

    baseline_set_root: str
    assignment_root: str
    evidence_root: str
    projection_root: str
    backend_implementation_digest: str
    limits: WorkerLimits
    methods: tuple[Workspace100ClaimMethod, ...]
    runs: tuple[Workspace100ClaimRun, ...]

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        _validate_claim_set_header(self)
        _validate_claim_set_methods(self)
        _validate_claim_set_runs(self)

    @property
    def method_registry_root(self) -> str:
        self.validate()
        return _method_registry_root(self.baseline_set_root, self.methods)

    @property
    def run_root(self) -> str:
        self.validate()
        return _run_root(
            backend_implementation_digest=self.backend_implementation_digest,
            evidence_root=self.evidence_root,
            limits_digest=self.limits.digest,
            method_registry_root=_method_registry_root(
                self.baseline_set_root,
                self.methods,
            ),
            runs=self.runs,
        )

    @property
    def claim_set_root(self) -> str:
        self.validate()
        method_registry_root = _method_registry_root(
            self.baseline_set_root,
            self.methods,
        )
        run_root = _run_root(
            backend_implementation_digest=self.backend_implementation_digest,
            evidence_root=self.evidence_root,
            limits_digest=self.limits.digest,
            method_registry_root=method_registry_root,
            runs=self.runs,
        )
        return _claim_set_root(
            self,
            method_registry_root=method_registry_root,
            run_root=run_root,
        )

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        method_registry_root = _method_registry_root(
            self.baseline_set_root,
            self.methods,
        )
        run_root = _run_root(
            backend_implementation_digest=self.backend_implementation_digest,
            evidence_root=self.evidence_root,
            limits_digest=self.limits.digest,
            method_registry_root=method_registry_root,
            runs=self.runs,
        )
        return {
            "assignment_root": self.assignment_root,
            "backend_implementation_digest": self.backend_implementation_digest,
            "baseline_set_root": self.baseline_set_root,
            "claim_set_root": _claim_set_root(
                self,
                method_registry_root=method_registry_root,
                run_root=run_root,
            ),
            "evidence_root": self.evidence_root,
            "format": CLAIM_SET_FORMAT,
            "limits": self.limits.to_payload(),
            "limits_digest": self.limits.digest,
            "method_registry_root": method_registry_root,
            "methods": tuple(method.to_payload() for method in self.methods),
            "projection_root": self.projection_root,
            "protocol_id": PROTOCOL_ID,
            "run_root": run_root,
            "runs": tuple(run.to_payload() for run in self.runs),
        }

    def to_canonical_bytes(self) -> bytes:
        payload = canonical_json(self.to_payload())
        if len(payload) > _MAX_CLAIM_SET_BYTES:
            raise ValueError("claim set exceeds its byte bound")
        return payload

    @classmethod
    def from_canonical_bytes(cls, payload: bytes) -> Workspace100ClaimSet:
        """Parse structural integrity only; external release bindings remain."""

        return _parse_claim_set(payload)


def build_workspace100_claim_set(
    views: Workspace100EvidenceViews,
    baseline_set: BuiltinBaselineSet,
    records: tuple[WorkerRunRecord, ...],
    *,
    backend_implementation_digest: str,
    limits: WorkerLimits,
) -> Workspace100ClaimSet:
    """Assemble complete records in canonical order, never execution order."""

    expected_execution = _ExpectedExecution(
        backend_implementation_digest=backend_implementation_digest,
        limits=limits,
    )
    if (
        type(records) is not tuple
        or len(records) != _RUN_COUNT
        or any(type(record) is not WorkerRunRecord for record in records)
    ):
        raise TypeError("claim construction requires 1,200 exact worker records")
    normalized_records = tuple(
        WorkerRunRecord.from_canonical_bytes(record.to_canonical_bytes())
        for record in records
    )
    raw_keys = tuple(
        (record.method_id, record.evidence_digest)
        for record in normalized_records
    )
    if len(set(raw_keys)) != _RUN_COUNT:
        raise ValueError("claim construction method/evidence keys must be unique")
    if any(record.limits_digest != limits.digest for record in normalized_records):
        raise ValueError("claim construction records contradict the expected limits")
    backend_digests = {
        record.backend_implementation_digest for record in normalized_records
    }
    if backend_digests != {backend_implementation_digest}:
        raise ValueError("claim construction records contradict the expected backend")
    projection_roots = _validate_claim_inputs(views, baseline_set, limits)
    methods = _claim_methods_for_baseline_set(baseline_set)
    methods_by_id = {
        method.method_id: (method, method.method_digest)
        for method in methods
    }
    if len(methods_by_id) != _METHOD_COUNT:
        raise ValueError("claim construction method IDs are not unique")
    runs: list[Workspace100ClaimRun] = []
    for record in normalized_records:
        method_binding = methods_by_id.get(record.method_id)
        if method_binding is None:
            raise ValueError("claim construction contains an unknown method")
        runs.append(
            Workspace100ClaimRun(
                method_digest=method_binding[1],
                worker_run=record,
            )
        )
    method_rank = {
        method.method_digest: rank for rank, method in enumerate(methods)
    }
    claim_set = Workspace100ClaimSet(
        baseline_set_root=baseline_set.baseline_set_root,
        assignment_root=projection_roots.assignment_root,
        evidence_root=projection_roots.evidence_root,
        projection_root=projection_roots.projection_root,
        backend_implementation_digest=backend_implementation_digest,
        limits=limits,
        methods=methods,
        runs=tuple(
            sorted(
                runs,
                key=lambda run: (
                    method_rank[run.method_digest],
                    run.worker_run.evidence_digest,
                ),
            )
        ),
    )
    _verify_workspace100_claim_bindings(
        claim_set,
        views,
        baseline_set,
        projection_roots,
        expected_execution,
    )
    return claim_set


def load_verified_workspace100_claim_set(
    payload: bytes,
    views: Workspace100EvidenceViews,
    baseline_set: BuiltinBaselineSet,
    *,
    expected_backend_implementation_digest: str,
    expected_limits: WorkerLimits,
) -> Workspace100ClaimSet:
    """Parse and verify every caller-pinned external ClaimSet binding."""

    claim_set = Workspace100ClaimSet.from_canonical_bytes(payload)
    verify_workspace100_claim_bindings(
        claim_set,
        views,
        baseline_set,
        expected_backend_implementation_digest=(
            expected_backend_implementation_digest
        ),
        expected_limits=expected_limits,
    )
    return claim_set


def evaluate_workspace100_baselines(
    views: Workspace100EvidenceViews,
    baseline_set: BuiltinBaselineSet,
    *,
    execution: Workspace100ExecutionPlan,
    execution_order: tuple[Workspace100RunKey, ...],
) -> Workspace100ClaimSet:
    """Run the exact baseline/case product under an explicit transient order.

    The order is not serialized.  Backend behavior may still be stateful, so
    schedule-independent results are a property of the selected backends.
    """

    if type(execution) is not Workspace100ExecutionPlan:
        raise TypeError("baseline evaluation requires an exact execution plan")
    execution.validate()
    expected_execution = _ExpectedExecution(
        backend_implementation_digest=(
            execution.expected_backend_implementation_digest
        ),
        limits=execution.limits,
    )
    _validate_claim_inputs(views, baseline_set, execution.limits)
    normalized_order = _validate_execution_order(
        execution_order,
        views,
        baseline_set,
    )
    backend_digest, backends_by_method = _pin_execution_backends(
        execution.backends,
        baseline_set,
        expected_backend_digest=(
            expected_execution.backend_implementation_digest
        ),
    )
    artifacts_by_method = {
        artifact.bundle.method_id: artifact for artifact in baseline_set.bundles
    }
    cases_by_evidence = {
        case.evidence_digest: case for case in views.cases
    }
    records: list[WorkerRunRecord] = []
    for key in normalized_order:
        artifact = artifacts_by_method[key.method_id]
        backend = backends_by_method[key.method_id]
        case = cases_by_evidence[key.evidence_digest]
        _recheck_backend_identity(
            backend,
            expected_program_digest=(
                artifact.bundle.program_implementation_digest
            ),
            expected_backend_digest=backend_digest,
        )
        record = run_worker_once(
            artifact.bundle.worker_program,
            case.envelope,
            backend=backend,
            limits=execution.limits,
        )
        _recheck_backend_identity(
            backend,
            expected_program_digest=(
                artifact.bundle.program_implementation_digest
            ),
            expected_backend_digest=backend_digest,
        )
        _verify_evaluated_record(
            record,
            key=key,
            artifact=artifact,
            case=case,
            expected_execution=expected_execution,
        )
        records.append(record)
    return build_workspace100_claim_set(
        views,
        baseline_set,
        tuple(records),
        backend_implementation_digest=backend_digest,
        limits=execution.limits,
    )


def verify_workspace100_claim_bindings(
    claim_set: Workspace100ClaimSet,
    views: Workspace100EvidenceViews,
    baseline_set: BuiltinBaselineSet,
    *,
    expected_backend_implementation_digest: str,
    expected_limits: WorkerLimits,
) -> None:
    """Join a structural claim artifact to exact public release inputs."""

    if type(claim_set) is not Workspace100ClaimSet:
        raise TypeError("claim binding verification requires an exact claim set")
    expected_execution = _ExpectedExecution(
        backend_implementation_digest=expected_backend_implementation_digest,
        limits=expected_limits,
    )
    claim_set.validate()
    if claim_set.backend_implementation_digest != (
        expected_execution.backend_implementation_digest
    ):
        raise ValueError("claim set backend contradicts the expected execution")
    if claim_set.limits != expected_execution.limits:
        raise ValueError("claim set limits contradict the expected execution")
    projection_roots = _validate_claim_inputs(
        views,
        baseline_set,
        claim_set.limits,
    )
    _verify_workspace100_claim_bindings(
        claim_set,
        views,
        baseline_set,
        projection_roots,
        expected_execution,
    )


def _verify_workspace100_claim_bindings(
    claim_set: Workspace100ClaimSet,
    views: Workspace100EvidenceViews,
    baseline_set: BuiltinBaselineSet,
    projection_roots: Workspace100ProjectionRoots,
    expected_execution: _ExpectedExecution,
) -> None:
    if (
        claim_set.backend_implementation_digest
        != expected_execution.backend_implementation_digest
        or claim_set.limits != expected_execution.limits
    ):
        raise ValueError("claim set changed after expected execution validation")
    if claim_set.baseline_set_root != baseline_set.baseline_set_root:
        raise ValueError("claim set baseline root contradicts the supplied set")
    if claim_set.methods != _claim_methods_for_baseline_set(baseline_set):
        raise ValueError("claim set methods contradict the supplied baseline set")
    if (
        claim_set.assignment_root,
        claim_set.evidence_root,
        claim_set.projection_root,
    ) != (
        projection_roots.assignment_root,
        projection_roots.evidence_root,
        projection_roots.projection_root,
    ):
        raise ValueError("claim set roots contradict the public evidence projection")

    case_digests = tuple(case.evidence_digest for case in views.cases)
    if len(case_digests) != _CASE_COUNT or len(set(case_digests)) != _CASE_COUNT:
        raise ValueError("public evidence projection does not contain 300 unique cases")
    cases_by_digest = {case.evidence_digest: case for case in views.cases}
    request_by_evidence = {
        case.evidence_digest: workspace100_worker_request_digest(case.envelope)
        for case in views.cases
    }
    expected_evidence = frozenset(case_digests)
    evidence_by_method: dict[str, list[str]] = defaultdict(list)
    for run in claim_set.runs:
        record = run.worker_run
        case = cases_by_digest.get(record.evidence_digest)
        if case is None:
            raise ValueError("claim run does not resolve to public evidence")
        if record.request_digest != request_by_evidence[record.evidence_digest]:
            raise ValueError("claim run request digest contradicts public evidence")
        evidence_by_method[run.method_digest].append(record.evidence_digest)
    for method in claim_set.methods:
        if frozenset(evidence_by_method[method.method_digest]) != expected_evidence:
            raise ValueError("claim method does not cover the public evidence set")


def _validate_execution_order(
    execution_order: tuple[Workspace100RunKey, ...],
    views: Workspace100EvidenceViews,
    baseline_set: BuiltinBaselineSet,
) -> tuple[Workspace100RunKey, ...]:
    if (
        type(execution_order) is not tuple
        or len(execution_order) != _RUN_COUNT
        or any(type(key) is not Workspace100RunKey for key in execution_order)
    ):
        raise TypeError("execution order must contain 1,200 exact run keys")
    supplied = tuple(
        (key.method_id, key.evidence_digest) for key in execution_order
    )
    if len(set(supplied)) != _RUN_COUNT:
        raise ValueError("execution order contains duplicate run keys")
    evidence_digests = tuple(case.evidence_digest for case in views.cases)
    if len(evidence_digests) != _CASE_COUNT or len(
        set(evidence_digests)
    ) != _CASE_COUNT:
        raise ValueError("execution order evidence source is not 300 unique cases")
    expected = {
        (artifact.bundle.method_id, evidence_digest)
        for artifact in baseline_set.bundles
        for evidence_digest in evidence_digests
    }
    if set(supplied) != expected:
        raise ValueError("execution order is not the exact baseline/case product")
    return tuple(
        Workspace100RunKey(
            method_id=key.method_id,
            evidence_digest=key.evidence_digest,
        )
        for key in execution_order
    )


def _pin_execution_backends(
    backends: tuple[WorkerBackend, ...],
    baseline_set: BuiltinBaselineSet,
    *,
    expected_backend_digest: str,
) -> tuple[str, dict[str, WorkerBackend]]:
    _require_digest(
        expected_backend_digest,
        field="expected execution backend implementation_digest",
    )
    if type(backends) is not tuple or len(backends) != _METHOD_COUNT:
        raise TypeError("baseline execution requires four ordered backends")
    backend_digests: list[str] = []
    backends_by_method: dict[str, WorkerBackend] = {}
    for artifact, backend in zip(
        baseline_set.bundles,
        backends,
        strict=True,
    ):
        try:
            program_digest = backend.program_implementation_digest
            backend_digest = backend.implementation_digest
        except AttributeError as error:
            raise TypeError(
                "execution plan backend does not implement WorkerBackend"
            ) from error
        _require_digest(
            program_digest,
            field="execution backend program_implementation_digest",
        )
        _require_digest(
            backend_digest,
            field="execution backend implementation_digest",
        )
        if program_digest != artifact.bundle.program_implementation_digest:
            raise ValueError("execution backend contradicts its baseline program")
        backend_digests.append(backend_digest)
        backends_by_method[artifact.bundle.method_id] = backend
    if len(set(backend_digests)) != 1:
        raise ValueError("baseline execution requires one backend identity")
    if backend_digests[0] != expected_backend_digest:
        raise ValueError("execution backend contradicts its expected identity")
    return backend_digests[0], backends_by_method


def _recheck_backend_identity(
    backend: WorkerBackend,
    *,
    expected_program_digest: str,
    expected_backend_digest: str,
) -> None:
    if (
        backend.program_implementation_digest != expected_program_digest
        or backend.implementation_digest != expected_backend_digest
    ):
        raise ValueError("execution backend identity changed during evaluation")


def _verify_evaluated_record(
    record: WorkerRunRecord,
    *,
    key: Workspace100RunKey,
    artifact: BuiltinBaselineArtifact,
    case: PublicEvidenceCase,
    expected_execution: _ExpectedExecution,
) -> None:
    if type(record) is not WorkerRunRecord:
        raise TypeError("evaluation returned a non-exact worker record")
    if type(artifact) is not BuiltinBaselineArtifact:
        raise TypeError("evaluation baseline artifact is not exact")
    if type(case) is not PublicEvidenceCase:
        raise TypeError("evaluation evidence case is not exact")
    if (
        record.method_id,
        record.implementation_digest,
        record.backend_implementation_digest,
        record.limits_digest,
        record.evidence_digest,
        record.request_digest,
    ) != (
        key.method_id,
        artifact.bundle.program_implementation_digest,
        expected_execution.backend_implementation_digest,
        expected_execution.limits.digest,
        case.evidence_digest,
        workspace100_worker_request_digest(case.envelope),
    ):
        raise ValueError("worker record contradicts its evaluation request")


def _validate_claim_set_header(claim_set: Workspace100ClaimSet) -> None:
    for field, value in (
        ("baseline_set_root", claim_set.baseline_set_root),
        ("assignment_root", claim_set.assignment_root),
        ("evidence_root", claim_set.evidence_root),
        ("projection_root", claim_set.projection_root),
        (
            "backend_implementation_digest",
            claim_set.backend_implementation_digest,
        ),
    ):
        _require_digest(value, field=f"claim set {field}")
    if claim_set.baseline_set_root != BUILTIN_BASELINE_SET_ROOT:
        raise ValueError("claim set baseline root is not the frozen built-in root")
    expected_projection_root = canonical_digest(
        _EVIDENCE_PROJECTION_FORMAT,
        {
            "assignment_root": claim_set.assignment_root,
            "evidence_root": claim_set.evidence_root,
            "format": _EVIDENCE_PROJECTION_FORMAT,
            "protocol_id": PROTOCOL_ID,
        },
    )
    if claim_set.projection_root != expected_projection_root:
        raise ValueError("claim set projection root contradicts its component roots")
    if type(claim_set.limits) is not WorkerLimits:
        raise TypeError("claim set limits must be exact")
    claim_set.limits.validate()


def _validate_claim_set_methods(claim_set: Workspace100ClaimSet) -> None:
    if (
        type(claim_set.methods) is not tuple
        or len(claim_set.methods) != _METHOD_COUNT
        or any(
            type(method) is not Workspace100ClaimMethod
            for method in claim_set.methods
        )
    ):
        raise TypeError("claim set must contain four exact methods")
    for method in claim_set.methods:
        method.validate()
    if tuple(method.baseline for method in claim_set.methods) != tuple(
        BuiltinBaseline
    ):
        raise ValueError("claim set methods are not in frozen baseline order")
    if claim_set.methods != _claim_methods_for_baseline_set(
        builtin_baseline_set()
    ):
        raise ValueError("claim set method registry is not the frozen registry")
    method_digests = tuple(method.method_digest for method in claim_set.methods)
    if len(set(method_digests)) != _METHOD_COUNT:
        raise ValueError("claim set method digests must be unique")


def _validate_claim_set_runs(claim_set: Workspace100ClaimSet) -> None:
    if (
        type(claim_set.runs) is not tuple
        or len(claim_set.runs) != _RUN_COUNT
        or any(type(run) is not Workspace100ClaimRun for run in claim_set.runs)
    ):
        raise TypeError("claim set must contain 1,200 exact runs")
    for run in claim_set.runs:
        run.validate()
    methods_by_digest = {
        method.method_digest: method for method in claim_set.methods
    }
    method_rank = {
        method.method_digest: rank
        for rank, method in enumerate(claim_set.methods)
    }
    run_keys = tuple(
        (run.method_digest, run.worker_run.evidence_digest)
        for run in claim_set.runs
    )
    if len(set(run_keys)) != _RUN_COUNT:
        raise ValueError("claim set method/evidence run keys must be unique")
    if any(
        method_digest not in methods_by_digest
        for method_digest, _evidence_digest in run_keys
    ):
        raise ValueError("claim set run references an unknown method")
    if claim_set.runs != tuple(
        sorted(
            claim_set.runs,
            key=lambda run: (
                method_rank[run.method_digest],
                run.worker_run.evidence_digest,
            ),
        )
    ):
        raise ValueError("claim set runs are not in canonical result order")
    _validate_claim_run_context(claim_set, methods_by_digest)


def _validate_claim_run_context(
    claim_set: Workspace100ClaimSet,
    methods_by_digest: dict[str, Workspace100ClaimMethod],
) -> None:
    evidence_by_method: dict[str, list[str]] = defaultdict(list)
    request_by_evidence: dict[str, set[str]] = defaultdict(set)
    counts: Counter[str] = Counter()
    for run in claim_set.runs:
        method = methods_by_digest[run.method_digest]
        record = run.worker_run
        if (record.method_id, record.implementation_digest) != (
            method.method_id,
            method.program_implementation_digest,
        ):
            raise ValueError("claim run worker identity contradicts its method")
        if (
            record.backend_implementation_digest
            != claim_set.backend_implementation_digest
        ):
            raise ValueError("claim run backend identity is not set-wide")
        if record.limits_digest != claim_set.limits.digest:
            raise ValueError("claim run limits identity is not set-wide")
        evidence_by_method[run.method_digest].append(record.evidence_digest)
        request_by_evidence[record.evidence_digest].add(record.request_digest)
        counts[run.method_digest] += 1
    method_digests = tuple(
        method.method_digest for method in claim_set.methods
    )
    if set(counts.values()) != {_CASE_COUNT} or set(counts) != set(
        method_digests
    ):
        raise ValueError("claim set must contain 300 runs per method")
    evidence_sets = tuple(
        frozenset(evidence_by_method[method_digest])
        for method_digest in method_digests
    )
    if (
        any(len(evidence_set) != _CASE_COUNT for evidence_set in evidence_sets)
        or len(set(evidence_sets)) != 1
    ):
        raise ValueError("claim set methods must cover one identical evidence set")
    request_digests = tuple(
        next(iter(digests)) for digests in request_by_evidence.values()
    )
    if (
        len(request_by_evidence) != _CASE_COUNT
        or any(len(digests) != 1 for digests in request_by_evidence.values())
        or len(set(request_digests)) != _CASE_COUNT
    ):
        raise ValueError("claim set requests must bind 300 unique evidence records")


def _validate_claim_inputs(
    views: Workspace100EvidenceViews,
    baseline_set: BuiltinBaselineSet,
    limits: WorkerLimits,
) -> Workspace100ProjectionRoots:
    if type(views) is not Workspace100EvidenceViews:
        raise TypeError("claim construction requires exact public evidence views")
    if type(baseline_set) is not BuiltinBaselineSet:
        raise TypeError("claim construction requires an exact baseline set")
    if type(limits) is not WorkerLimits:
        raise TypeError("claim construction requires exact worker limits")
    baseline_set.validate()
    limits.validate()
    if baseline_set.baseline_set_root != BUILTIN_BASELINE_SET_ROOT:
        raise ValueError("claim construction baseline set is not frozen")
    return workspace100_projection_roots(views)


def _claim_methods_for_baseline_set(
    baseline_set: BuiltinBaselineSet,
) -> tuple[Workspace100ClaimMethod, ...]:
    baseline_set.validate()
    return tuple(
        Workspace100ClaimMethod(
            baseline=artifact.bundle.baseline,
            baseline_bundle_digest=artifact.bundle.bundle_digest,
            method_id=artifact.bundle.method_id,
            program_implementation_digest=(
                artifact.bundle.program_implementation_digest
            ),
        )
        for artifact in baseline_set.bundles
    )


def _method_registry_root(
    baseline_set_root: str,
    methods: tuple[Workspace100ClaimMethod, ...],
) -> str:
    return canonical_digest(
        CLAIM_METHOD_REGISTRY_FORMAT,
        {
            "baseline_set_root": baseline_set_root,
            "format": CLAIM_METHOD_REGISTRY_FORMAT,
            "method_digests": tuple(method.method_digest for method in methods),
            "protocol_id": PROTOCOL_ID,
        },
    )


def _run_root(
    *,
    backend_implementation_digest: str,
    evidence_root: str,
    limits_digest: str,
    method_registry_root: str,
    runs: tuple[Workspace100ClaimRun, ...],
) -> str:
    return canonical_digest(
        CLAIM_RUN_SET_FORMAT,
        {
            "backend_implementation_digest": backend_implementation_digest,
            "claim_run_digests": tuple(run.claim_run_digest for run in runs),
            "evidence_root": evidence_root,
            "format": CLAIM_RUN_SET_FORMAT,
            "limits_digest": limits_digest,
            "method_registry_root": method_registry_root,
            "protocol_id": PROTOCOL_ID,
        },
    )


def _claim_set_root(
    claim_set: Workspace100ClaimSet,
    *,
    method_registry_root: str,
    run_root: str,
) -> str:
    return canonical_digest(
        CLAIM_SET_FORMAT,
        {
            "assignment_root": claim_set.assignment_root,
            "baseline_set_root": claim_set.baseline_set_root,
            "evidence_root": claim_set.evidence_root,
            "format": CLAIM_SET_FORMAT,
            "method_registry_root": method_registry_root,
            "projection_root": claim_set.projection_root,
            "protocol_id": PROTOCOL_ID,
            "run_root": run_root,
        },
    )


def _parse_claim_set(payload: object) -> Workspace100ClaimSet:
    raw = _parse_claim_set_object(payload)
    _require_closed_fields(
        raw,
        {
            "assignment_root",
            "backend_implementation_digest",
            "baseline_set_root",
            "claim_set_root",
            "evidence_root",
            "format",
            "limits",
            "limits_digest",
            "method_registry_root",
            "methods",
            "projection_root",
            "protocol_id",
            "run_root",
            "runs",
        },
        label="claim set",
    )
    if raw["format"] != CLAIM_SET_FORMAT:
        raise ValueError("claim set format is unsupported")
    if raw["protocol_id"] != PROTOCOL_ID:
        raise ValueError("claim set protocol is unsupported")
    methods_raw = _required_array(raw, "methods")
    runs_raw = _required_array(raw, "runs")
    if len(methods_raw) != _METHOD_COUNT:
        raise ValueError("claim set payload must contain four methods")
    if len(runs_raw) != _RUN_COUNT:
        raise ValueError("claim set payload must contain 1,200 runs")
    limits = WorkerLimits.from_payload(raw["limits"])
    claim_set = Workspace100ClaimSet(
        baseline_set_root=_required_digest(raw, "baseline_set_root"),
        assignment_root=_required_digest(raw, "assignment_root"),
        evidence_root=_required_digest(raw, "evidence_root"),
        projection_root=_required_digest(raw, "projection_root"),
        backend_implementation_digest=_required_digest(
            raw,
            "backend_implementation_digest",
        ),
        limits=limits,
        methods=tuple(
            Workspace100ClaimMethod.from_payload(item) for item in methods_raw
        ),
        runs=tuple(Workspace100ClaimRun.from_payload(item) for item in runs_raw),
    )
    for field, stored, derived in (
        ("limits", _required_digest(raw, "limits_digest"), claim_set.limits.digest),
        (
            "method registry",
            _required_digest(raw, "method_registry_root"),
            claim_set.method_registry_root,
        ),
        ("run", _required_digest(raw, "run_root"), claim_set.run_root),
        (
            "claim set",
            _required_digest(raw, "claim_set_root"),
            claim_set.claim_set_root,
        ),
    ):
        if stored != derived:
            raise ValueError(f"stored {field} root contradicts the claim records")
    if claim_set.to_canonical_bytes() != payload:
        raise ValueError("claim set failed canonical round-trip")
    return claim_set


def _parse_claim_set_object(payload: object) -> dict[str, object]:
    if type(payload) is not bytes:
        raise TypeError("claim set payload must be exact bytes")
    if not payload or len(payload) > _MAX_CLAIM_SET_BYTES:
        raise ValueError("claim set payload exceeds its byte bound")
    try:
        raw: object = json.loads(payload)
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise ValueError("claim set is not valid UTF-8 JSON") from error
    try:
        canonical = (
            type(raw) is dict
            and canonical_json(cast(JsonValue, raw)) == payload
        )
    except (RecursionError, TypeError, UnicodeEncodeError) as error:
        raise ValueError("claim set contains unsupported JSON") from error
    if not canonical:
        raise ValueError("claim set is not one canonical JSON object")
    return cast(dict[str, object], raw)


def _closed_object(
    value: object,
    fields: set[str],
    *,
    label: str,
) -> dict[str, object]:
    if type(value) is not dict:
        raise ValueError(f"{label} must be an object")
    raw = cast(dict[str, object], value)
    _require_closed_fields(raw, fields, label=label)
    return raw


def _require_closed_fields(
    payload: dict[str, object],
    fields: set[str],
    *,
    label: str,
) -> None:
    if set(payload) != fields:
        raise ValueError(f"{label} contains unknown or missing fields")


def _required_array(
    payload: dict[str, object],
    field: str,
) -> list[object]:
    value = payload[field]
    if type(value) is not list:
        raise ValueError(f"{field} must be an array")
    return cast(list[object], value)


def _required_string(payload: dict[str, object], field: str) -> str:
    value = payload[field]
    if type(value) is not str:
        raise ValueError(f"{field} must be a string")
    return value


def _required_digest(payload: dict[str, object], field: str) -> str:
    value = _required_string(payload, field)
    _require_digest(value, field=field)
    return value


def _require_identifier(value: object, *, field: str) -> None:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase identifier")


def _require_digest(value: object, *, field: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{field} must be one lowercase SHA-256 digest")
