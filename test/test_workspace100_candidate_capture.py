from __future__ import annotations

import os
import sys
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest

from witnessgap import workspace100
from witnessgap.canonical import JsonValue, canonical_digest, canonical_json
from witnessgap.identifiability import RegistryManifest
from witnessgap.trust import VerificationTrustAnchor
from witnessgap.verifier import trust_anchor_for_manifest
from witnessgap.workspace100 import candidate_capture
from witnessgap.workspace100.baselines import (
    BuiltinBaseline,
    BuiltinBaselineSet,
    builtin_baseline_set,
)
from witnessgap.workspace100.candidate_capture import (
    CANDIDATE_RECEIPT_FORMAT,
    PORTFOLIO_SEED,
    RUNTIME_ARTIFACT_SCOPE,
    CandidateCaptureError,
    Workspace100CandidateReceipt,
    _measure_interpreter,
    _validate_capture_paths,
    candidate_capture_implementation_digest,
    capture_workspace100_candidate,
    check_workspace100_candidate,
    main,
)
from witnessgap.workspace100.claims import (
    Workspace100ClaimMethod,
    Workspace100ExecutionPlan,
    Workspace100RunKey,
)
from witnessgap.workspace100.release import (
    GATE16_STATUS,
    RELEASE_FILE_MODE,
    RELEASE_KIND,
    RELEASE_LAYOUT_PATHS,
    RELEASE_PAYLOAD_PATHS,
    Workspace100ExecutionConfiguration,
    Workspace100IsolationPolicy,
    Workspace100RuntimeIdentity,
)
from witnessgap.workspace100.scoring import (
    Workspace100FailureCounts,
    Workspace100ScoreCounts,
    Workspace100ScoreMetrics,
    Workspace100ScoreSlice,
    Workspace100SliceKind,
)
from witnessgap.workspace100.views import (
    ViewKind,
    Workspace100EvidenceViews,
)
from witnessgap.workspace100.worker import (
    LocalPythonProcessBackend,
    WorkerRunStatus,
)

_DIGEST = "a" * 64
_OTHER_DIGEST = "b" * 64
_CASE_COUNT = 300
_PAIR_COUNT = 50
_RUN_COUNT = 1_200


def _private_directory(parent: Path, name: str) -> Path:
    path = parent / name
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def _method_counts(baseline: BuiltinBaseline) -> Workspace100ScoreCounts:
    if baseline is BuiltinBaseline.ALWAYS_UNKNOWN:
        return Workspace100ScoreCounts(
            correct_abstention=100,
            missed_identifiable=200,
        )
    if baseline is BuiltinBaseline.FORCED_ENVIRONMENT:
        return Workspace100ScoreCounts(
            exact_decisive=100,
            wrong_target=100,
            decisive_on_ambiguous=100,
        )
    if baseline is BuiltinBaseline.REFRESH_SUCCESS_ONLY:
        return Workspace100ScoreCounts(
            correct_abstention=100,
            missed_identifiable=150,
            exact_decisive=50,
        )
    return Workspace100ScoreCounts(
        correct_abstention=100,
        missed_identifiable=100,
        exact_decisive=100,
    )


def _score_payload(
    counts: Workspace100ScoreCounts,
) -> dict[str, JsonValue]:
    failures = Workspace100FailureCounts()
    metrics = Workspace100ScoreMetrics.from_counts(counts)
    score_slice = Workspace100ScoreSlice(
        kind=Workspace100SliceKind.OVERALL,
        view=None,
        template_id=None,
        counts=counts,
        failure_counts=failures,
        metrics=metrics,
    )
    return {
        "counts": counts.to_payload(),
        "failure_counts": failures.to_payload(),
        "metrics": metrics.to_payload(),
        "slice_digest": score_slice.slice_digest,
    }


def _receipt_body() -> dict[str, JsonValue]:
    scores: list[JsonValue] = []
    for baseline, artifact in zip(
        BuiltinBaseline,
        builtin_baseline_set().bundles,
        strict=True,
    ):
        bundle = artifact.bundle
        method = Workspace100ClaimMethod(
            baseline=baseline,
            baseline_bundle_digest=bundle.bundle_digest,
            method_id=bundle.method_id,
            program_implementation_digest=(bundle.program_implementation_digest),
        )
        score = _score_payload(_method_counts(baseline))
        score.update(
            {
                "baseline": baseline.value,
                "method_digest": method.method_digest,
                "method_id": method.method_id,
                "method_report_digest": _DIGEST,
                "program_implementation_digest": (method.program_implementation_digest),
            }
        )
        scores.append(score)
    oracle = Workspace100ScoreCounts(
        correct_abstention=100,
        exact_decisive=200,
    )
    runtime = Workspace100RuntimeIdentity(
        runtime_id="cpython_3_12_3_linux_x86_64",
        runtime_artifact_digest=_DIGEST,
        interpreter_digest=_DIGEST,
        implementation="CPython",
        version="3.12.3",
    )
    roots: dict[str, JsonValue] = dict.fromkeys(
        candidate_capture._ROOT_FIELDS,
        _DIGEST,
    )
    roots["runtime"] = runtime.runtime_root
    return {
        "anchor_authority": candidate_capture._ANCHOR_AUTHORITY,
        "counts": {
            "assignments": 400,
            "completions": 100,
            "methods": 4,
            "pairs": 50,
            "participant_cases": _CASE_COUNT,
            "payload_files": len(RELEASE_PAYLOAD_PATHS),
            "templates": 5,
            "tree_files": len(RELEASE_LAYOUT_PATHS),
            "trust_anchors": 50,
            "variants": 50,
            "view_cases": {
                ViewKind.EPOCH_PROBE.value: 100,
                ViewKind.OWNER_PROBE.value: 50,
                ViewKind.REFRESH_RECEIPT.value: 100,
                ViewKind.TRACE_ONLY.value: 50,
            },
            "worker_runs": _RUN_COUNT,
            "worker_status": {
                WorkerRunStatus.CLAIMED.value: _RUN_COUNT,
                WorkerRunStatus.FAILED.value: 0,
            },
        },
        "files": tuple(
            {
                "byte_length": index + 1,
                "content_digest": _DIGEST,
                "mode": RELEASE_FILE_MODE,
                "path": path,
            }
            for index, path in enumerate(RELEASE_LAYOUT_PATHS)
        ),
        "format": CANDIDATE_RECEIPT_FORMAT,
        "gate16_status": GATE16_STATUS,
        "nonclaims": candidate_capture._NONCLAIMS,
        "official": False,
        "oracle_ceiling_overall": _score_payload(oracle),
        "protocol_id": "workspace-100-v1",
        "receipt_relation": candidate_capture._RECEIPT_RELATION,
        "release_kind": RELEASE_KIND,
        "root_authentication": candidate_capture._ROOT_AUTHENTICATION,
        "roots": roots,
        "runtime": {
            "artifact_scope": RUNTIME_ARTIFACT_SCOPE,
            "implementation": runtime.implementation,
            "interpreter_sha256": runtime.interpreter_digest,
            "runtime_artifact_sha256": runtime.runtime_artifact_digest,
            "runtime_id": runtime.runtime_id,
            "version": runtime.version,
        },
        "score_scope": "overall_exact_counts_and_ratios",
        "scores": tuple(scores),
    }


def _receipt() -> Workspace100CandidateReceipt:
    return Workspace100CandidateReceipt.from_payload(_receipt_body())


def test_capture_tool_is_separate_pinned_and_not_package_exported() -> None:
    first = candidate_capture_implementation_digest()
    second = candidate_capture_implementation_digest()

    assert len(PORTFOLIO_SEED) == sha256().digest_size
    assert first == second
    assert len(first) == sha256().digest_size * 2
    assert all(character in "0123456789abcdef" for character in first)
    assert "Workspace100CandidateReceipt" not in workspace100.__all__
    assert not hasattr(workspace100, "capture_workspace100_candidate")


def test_interpreter_measurement_hashes_the_exact_resolved_binary() -> None:
    interpreter = os.path.realpath(sys.executable)

    measured = _measure_interpreter(interpreter)

    expected = sha256(Path(interpreter).read_bytes()).hexdigest()
    assert measured.path == interpreter
    assert measured.digest == expected
    assert measured.runtime_identity.runtime_artifact_digest == expected
    assert measured.runtime_identity.interpreter_digest == expected
    assert measured.runtime_identity.runtime_root
    assert measured.implementation == "CPython"
    assert measured.version


def test_interpreter_measurement_rejects_an_unresolved_alias() -> None:
    if os.path.realpath(sys.executable) == sys.executable:
        pytest.skip("the current executable is already a resolved path")

    with pytest.raises(CandidateCaptureError, match="resolved physical"):
        _measure_interpreter(sys.executable)


def test_interpreter_measurement_requires_linux(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        candidate_capture,
        "_interpreter_metadata",
        lambda _path: {
            "implementation": "CPython",
            "machine": "arm64",
            "system": "Darwin",
            "version": "3.12.3",
        },
    )

    with pytest.raises(CandidateCaptureError, match="Linux/POSIX"):
        _measure_interpreter(os.path.realpath(sys.executable))


def test_capture_paths_require_private_disjoint_physical_directories(
    tmp_path: Path,
) -> None:
    checkout = Path.cwd().resolve()
    output = _private_directory(tmp_path, "output")
    scratch = _private_directory(tmp_path, "scratch")

    paths = _validate_capture_paths(
        checkout_root=str(checkout),
        output_parent=str(output),
        scratch_parent=str(scratch),
    )

    assert paths.output_parent == str(output)
    assert paths.scratch_parent == str(scratch)

    scratch.chmod(0o755)
    with pytest.raises(CandidateCaptureError, match="0700"):
        _validate_capture_paths(
            checkout_root=str(checkout),
            output_parent=str(output),
            scratch_parent=str(scratch),
        )


def test_capture_paths_reject_overlap_alias_and_existing_destination(
    tmp_path: Path,
) -> None:
    checkout = Path.cwd().resolve()
    output = _private_directory(tmp_path, "output")
    nested = _private_directory(output, "nested")
    alias = tmp_path / "alias"
    alias.symlink_to(output, target_is_directory=True)

    with pytest.raises(CandidateCaptureError, match="disjoint"):
        _validate_capture_paths(
            checkout_root=str(checkout),
            output_parent=str(output),
            scratch_parent=str(nested),
        )
    with pytest.raises(CandidateCaptureError, match="symbolic"):
        _validate_capture_paths(
            checkout_root=str(checkout),
            output_parent=str(alias),
            scratch_parent=str(_private_directory(tmp_path, "separate-scratch")),
        )

    (output / "workspace100").mkdir()
    with pytest.raises(FileExistsError, match="already exists"):
        _validate_capture_paths(
            checkout_root=str(checkout),
            output_parent=str(output),
            scratch_parent=str(_private_directory(tmp_path, "third-scratch")),
        )


def test_candidate_receipt_is_closed_rooted_canonical_and_path_free() -> None:
    receipt = _receipt()
    payload = receipt.to_payload()
    encoded = receipt.to_canonical_bytes()

    assert encoded == canonical_json(payload)
    assert Workspace100CandidateReceipt.from_canonical_bytes(encoded) == receipt
    assert receipt.release_root == _DIGEST
    assert payload["official"] is False
    assert payload["gate16_status"] == "not_established"
    assert payload["anchor_authority"] == ("locally_derived_reproducibility_only")
    assert b"/home/" not in encoded
    assert b"timestamp" not in encoded
    assert b"pid" not in encoded


@pytest.mark.parametrize(
    "mutation",
    ("unknown", "scope", "root", "file_size", "metric"),
)
def test_candidate_receipt_rejects_tampering(mutation: str) -> None:
    payload = _receipt().to_payload()
    if mutation == "unknown":
        payload["unexpected"] = True
    elif mutation == "scope":
        runtime = cast(dict[str, JsonValue], payload["runtime"])
        runtime["artifact_scope"] = "full_runtime"
    elif mutation == "root":
        payload["receipt_root"] = _OTHER_DIGEST
    elif mutation == "file_size":
        files = cast(list[JsonValue], payload["files"])
        first = cast(dict[str, JsonValue], files[0])
        first["byte_length"] = 0
    else:
        scores = cast(list[JsonValue], payload["scores"])
        first = cast(dict[str, JsonValue], scores[0])
        metrics = cast(dict[str, JsonValue], first["metrics"])
        coverage = cast(
            dict[str, JsonValue],
            metrics["decisive_coverage"],
        )
        coverage["numerator"] = 1

    with pytest.raises(ValueError):
        Workspace100CandidateReceipt.from_canonical_bytes(canonical_json(payload))


@pytest.mark.parametrize(
    "mutation",
    (
        "runtime_root",
        "embedded_path",
        "slice_digest",
        "method_identity",
        "oracle_ceiling",
    ),
)
def test_candidate_receipt_rejects_rerooted_semantic_contradictions(
    mutation: str,
) -> None:
    payload = _receipt().to_payload()
    if mutation == "runtime_root":
        roots = cast(dict[str, JsonValue], payload["roots"])
        roots["runtime"] = _OTHER_DIGEST
    elif mutation == "embedded_path":
        runtime = cast(dict[str, JsonValue], payload["runtime"])
        runtime["version"] = "3.12 built at /home/example/private/python"
    elif mutation == "slice_digest":
        scores = cast(list[JsonValue], payload["scores"])
        first = cast(dict[str, JsonValue], scores[0])
        first["slice_digest"] = _OTHER_DIGEST
    elif mutation == "method_identity":
        scores = cast(list[JsonValue], payload["scores"])
        first = cast(dict[str, JsonValue], scores[0])
        first["method_id"] = "workspace100_wrong_v1"
    else:
        payload["oracle_ceiling_overall"] = _score_payload(
            Workspace100ScoreCounts(
                correct_abstention=100,
                missed_identifiable=200,
            )
        )
    body = {key: value for key, value in payload.items() if key != "receipt_root"}
    payload["receipt_root"] = canonical_digest(
        CANDIDATE_RECEIPT_FORMAT,
        body,
    )

    with pytest.raises(ValueError):
        Workspace100CandidateReceipt.from_canonical_bytes(canonical_json(payload))


def test_candidate_receipt_normalizes_encoding_failures_to_value_error() -> None:
    with pytest.raises(ValueError, match="unsupported JSON"):
        Workspace100CandidateReceipt.from_canonical_bytes(b'{"bad":"\\ud800"}')


def test_candidate_receipt_normalizes_recursion_failures_to_value_error() -> None:
    depth = sys.getrecursionlimit() * 2
    payload = b'{"x":' + (b"[" * depth) + b"0" + (b"]" * depth) + b"}"

    with pytest.raises(ValueError, match="unsupported JSON"):
        Workspace100CandidateReceipt.from_canonical_bytes(payload)


def test_check_orchestration_uses_the_explicit_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout = str(Path.cwd().resolve())
    output = str(_private_directory(tmp_path, "output"))
    expected = _DIGEST
    sentinel_loaded = object()
    sentinel_verified = object()
    calls: list[tuple[str, object]] = []

    def load(
        output_parent: str,
        *,
        expected_release_root: str,
        forbidden_roots: tuple[str, ...],
    ) -> object:
        calls.append(
            (
                "load",
                (output_parent, expected_release_root, forbidden_roots),
            )
        )
        return sentinel_loaded

    def verify(
        release: object,
        *,
        expected_release_root: str,
    ) -> object:
        calls.append(("verify", (release, expected_release_root)))
        return sentinel_verified

    def make_receipt(
        verified: object,
        *,
        tool_implementation_digest: str,
    ) -> Workspace100CandidateReceipt:
        assert verified is sentinel_verified
        assert len(tool_implementation_digest) == sha256().digest_size * 2
        return _receipt()

    monkeypatch.setattr(
        candidate_capture,
        "load_workspace100_release_directory",
        load,
    )
    monkeypatch.setattr(
        candidate_capture,
        "verify_workspace100_release",
        verify,
    )
    monkeypatch.setattr(
        candidate_capture,
        "_receipt_from_verified_release",
        make_receipt,
    )

    receipt = check_workspace100_candidate(
        checkout_root=checkout,
        output_parent=output,
        expected_release_root=expected,
    )

    assert receipt == _receipt()
    assert calls == [
        ("load", (output, expected, (checkout,))),
        ("verify", (sentinel_loaded, expected)),
    ]


def test_candidate_construction_wires_the_full_reviewed_product_without_invoking_workers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch = str(_private_directory(tmp_path, "scratch"))
    measured = _measure_interpreter(os.path.realpath(sys.executable))
    paths = candidate_capture._CapturePaths(
        checkout_root=str(Path.cwd().resolve()),
        output_parent=str(_private_directory(tmp_path, "output")),
        scratch_parent=scratch,
    )
    derived_anchors: list[VerificationTrustAnchor] = []
    captured_execution: list[Workspace100ExecutionPlan] = []
    original_anchor_derivation = trust_anchor_for_manifest

    def derive_anchor(
        manifest: RegistryManifest,
    ) -> VerificationTrustAnchor:
        anchor = original_anchor_derivation(manifest)
        derived_anchors.append(anchor)
        return anchor

    class FakeClaimSet:
        backend_implementation_digest: str

        def __init__(self, backend_implementation_digest: str) -> None:
            self.backend_implementation_digest = backend_implementation_digest

        def to_canonical_bytes(self) -> bytes:
            return b"reviewed-claim-set-double"

    def evaluate(
        views: Workspace100EvidenceViews,
        baseline_set: BuiltinBaselineSet,
        *,
        execution: Workspace100ExecutionPlan,
        execution_order: tuple[Workspace100RunKey, ...],
    ) -> FakeClaimSet:
        assert views.case_count == _CASE_COUNT
        assert baseline_set == builtin_baseline_set()
        assert len(execution.backends) == len(BuiltinBaseline)
        assert all(type(backend) is LocalPythonProcessBackend for backend in execution.backends)
        for backend, artifact in zip(
            execution.backends,
            baseline_set.bundles,
            strict=True,
        ):
            local_backend = cast(LocalPythonProcessBackend, backend)
            assert local_backend.program_source == artifact.program_source
            assert local_backend.runtime_digest == measured.runtime_identity.runtime_root
            assert local_backend.interpreter == measured.path
            assert local_backend.scratch_root == scratch
            assert (
                local_backend.implementation_digest
                == execution.expected_backend_implementation_digest
            )
        expected_order = tuple(
            Workspace100RunKey(
                method_id=artifact.bundle.method_id,
                evidence_digest=case.evidence_digest,
            )
            for artifact in baseline_set.bundles
            for case in views.cases
        )
        assert execution_order == expected_order
        assert len(execution_order) == _RUN_COUNT
        assert len(set(execution_order)) == _RUN_COUNT
        captured_execution.append(execution)
        return FakeClaimSet(execution.expected_backend_implementation_digest)

    class FakeRelease:
        release_root = _DIGEST

    release = FakeRelease()

    def build(
        seed: bytes,
        trust_anchors: tuple[VerificationTrustAnchor, ...],
        claim_set_bytes: bytes,
        execution_configuration: Workspace100ExecutionConfiguration,
    ) -> object:
        assert seed == PORTFOLIO_SEED
        assert len(derived_anchors) == _PAIR_COUNT
        assert trust_anchors == tuple(derived_anchors)
        assert claim_set_bytes == b"reviewed-claim-set-double"
        assert len(captured_execution) == 1
        execution = captured_execution[0]
        assert (
            execution_configuration.backend_implementation_digest
            == execution.expected_backend_implementation_digest
        )
        assert execution_configuration.limits == execution.limits
        assert execution_configuration.runtime_identity == measured.runtime_identity
        assert execution_configuration.isolation_policy == Workspace100IsolationPolicy()
        return release

    monkeypatch.setattr(
        candidate_capture,
        "trust_anchor_for_manifest",
        derive_anchor,
    )
    monkeypatch.setattr(
        candidate_capture,
        "evaluate_workspace100_baselines",
        evaluate,
    )
    monkeypatch.setattr(
        candidate_capture,
        "build_workspace100_release",
        build,
    )

    result = candidate_capture._construct_candidate_release(paths, measured)

    assert cast(object, result) is release


def test_capture_orchestration_materializes_then_reloads_and_verifies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout = str(Path.cwd().resolve())
    output = str(_private_directory(tmp_path, "output"))
    scratch = str(_private_directory(tmp_path, "scratch"))
    interpreter = os.path.realpath(sys.executable)
    sentinel_loaded = object()
    sentinel_verified = object()
    calls: list[str] = []

    class Release:
        release_root = _DIGEST

    release = Release()

    def construct(paths: object, measured: object) -> object:
        assert paths is not None
        assert measured is not None
        return release

    monkeypatch.setattr(
        candidate_capture,
        "_construct_candidate_release",
        construct,
    )

    def materialize(
        value: object,
        output_parent: str,
        *,
        forbidden_roots: tuple[str, ...],
    ) -> str:
        assert value is release
        assert output_parent == output
        assert forbidden_roots == (checkout, scratch)
        calls.append("materialize")
        return f"{output}/workspace100/v1"

    def load(
        output_parent: str,
        *,
        expected_release_root: str,
        forbidden_roots: tuple[str, ...],
    ) -> object:
        assert output_parent == output
        assert expected_release_root == _DIGEST
        assert forbidden_roots == (checkout, scratch)
        calls.append("load")
        return sentinel_loaded

    def verify(
        value: object,
        *,
        expected_release_root: str,
    ) -> object:
        assert value is sentinel_loaded
        assert expected_release_root == _DIGEST
        calls.append("verify")
        return sentinel_verified

    def make_receipt(
        verified: object,
        *,
        tool_implementation_digest: str,
    ) -> Workspace100CandidateReceipt:
        assert verified is sentinel_verified
        assert len(tool_implementation_digest) == sha256().digest_size * 2
        return _receipt()

    monkeypatch.setattr(
        candidate_capture,
        "materialize_workspace100_release",
        materialize,
    )
    monkeypatch.setattr(
        candidate_capture,
        "load_workspace100_release_directory",
        load,
    )
    monkeypatch.setattr(
        candidate_capture,
        "verify_workspace100_release",
        verify,
    )
    monkeypatch.setattr(
        candidate_capture,
        "_receipt_from_verified_release",
        make_receipt,
    )

    receipt = capture_workspace100_candidate(
        checkout_root=checkout,
        output_parent=output,
        scratch_parent=scratch,
        interpreter=interpreter,
    )

    assert receipt == _receipt()
    assert calls == ["materialize", "load", "verify"]


def test_cli_check_emits_only_the_canonical_receipt(
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    expected = _receipt()
    received: dict[str, str] = {}

    def check(**kwargs: str) -> Workspace100CandidateReceipt:
        received.update(kwargs)
        return expected

    monkeypatch.setattr(
        candidate_capture,
        "check_workspace100_candidate",
        check,
    )

    assert (
        main(
            (
                "check",
                "--checkout-root",
                "/checkout",
                "--output-parent",
                "/output",
                "--expected-release-root",
                _DIGEST,
            )
        )
        == 0
    )

    output = capfd.readouterr()
    assert output.out.encode() == expected.to_canonical_bytes()
    assert output.err == ""
    assert received["expected_release_root"] == _DIGEST


def test_cli_check_requires_an_expected_release_root() -> None:
    with pytest.raises(SystemExit):
        candidate_capture._parser().parse_args(
            (
                "check",
                "--checkout-root",
                "/checkout",
                "--output-parent",
                "/output",
            )
        )
