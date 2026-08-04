"""Capture and verify one development-only Workspace-100 release candidate.

This module is intentionally not exported from :mod:`witnessgap.workspace100`.
It is an operator tool for the four frozen, reviewed built-ins, not a
third-party participant runner.  The emitted receipt is outside the release
root and does not authenticate that root.

Path checks assume an operator-controlled host and mount namespace.  They fail
closed on ordinary symlink aliases, overlap, ownership, and mode errors, but do
not claim containment against a privileged mount-namespace adversary or a
same-UID process racing directory replacement after validation.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import cast

from witnessgap.canonical import JsonValue, canonical_digest, canonical_json
from witnessgap.source import package_implementation_digest
from witnessgap.trust import VerificationTrustAnchor
from witnessgap.verifier import trust_anchor_for_manifest
from witnessgap.workspace100.baselines import (
    BuiltinBaseline,
    BuiltinBaselineSet,
    builtin_baseline_set,
)
from witnessgap.workspace100.claims import (
    Workspace100ClaimMethod,
    Workspace100ExecutionPlan,
    Workspace100RunKey,
    evaluate_workspace100_baselines,
)
from witnessgap.workspace100.records import PROTOCOL_ID
from witnessgap.workspace100.release import (
    GATE16_STATUS,
    RELEASE_FILE_MODE,
    RELEASE_KIND,
    RELEASE_LAYOUT_PATHS,
    RELEASE_PAYLOAD_PATHS,
    Workspace100ExecutionConfiguration,
    Workspace100IsolationPolicy,
    Workspace100RuntimeIdentity,
    workspace100_release_file_content_digest,
)
from witnessgap.workspace100.release_builder import (
    Workspace100VerifiedRelease,
    build_workspace100_release,
    verify_workspace100_release,
)
from witnessgap.workspace100.release_io import (
    Workspace100ReleaseDirectory,
    load_workspace100_release_directory,
    materialize_workspace100_release,
)
from witnessgap.workspace100.release_storage import (
    Workspace100GenerationProvenance,
    Workspace100RegistrySet,
    Workspace100VerifiedMaterialSet,
    load_workspace100_public_evidence_views,
    workspace100_public_evidence_views_jsonl,
)
from witnessgap.workspace100.scoring import (
    Workspace100FailureCounts,
    Workspace100MethodReport,
    Workspace100ScoreCounts,
    Workspace100ScoreMetrics,
    Workspace100ScoreSlice,
    Workspace100SliceKind,
)
from witnessgap.workspace100.views import (
    ViewKind,
    verify_workspace100_materials,
)
from witnessgap.workspace100.worker import (
    LocalPythonProcessBackend,
    WorkerBackend,
    WorkerLimits,
    WorkerRunStatus,
)

CANDIDATE_RECEIPT_FORMAT = "witnessgap.workspace100-development-candidate-receipt.v1"
RUNTIME_ARTIFACT_SCOPE = "resolved_interpreter_binary_bytes_only"
PORTFOLIO_SEED = bytes.fromhex("713d96c0fcadb930599f4f4370df3484766872ac406f1c26c5a360a996f29ec5")

_CAPTURE_IMPLEMENTATION_DOMAIN = "witnessgap.workspace100-candidate-capture-implementation.v1"
_CAPTURE_IMPLEMENTATION_PATHS = ("workspace100/candidate_capture.py",)
_ANCHOR_AUTHORITY = "locally_derived_reproducibility_only"
_ROOT_AUTHENTICATION = "not_established_by_this_receipt"
_RECEIPT_RELATION = "outside_release_and_artifact_tree_roots"
_MAX_RECEIPT_BYTES = 1 << 20
_HASH_CHUNK_BYTES = 1 << 20
_METADATA_OUTPUT_BYTES = 1 << 12
_PRIVATE_DIRECTORY_MODE = 0o700
_METADATA_TEXT_LENGTH = 80
_ASCII_PRINTABLE_MIN = 32
_ASCII_PRINTABLE_MAX = 126
_IDENTIFIER_LENGTH = 96
_RUNTIME_TEXT_LENGTH = 240
_CASE_COUNT = 300
_RUN_COUNT = 1_200
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{0,95}$")
_RUNTIME_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+()-]{0,239}$")
_WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:[\\/]")
_NONCLAIMS = (
    "development_candidate_not_an_official_release",
    "synthetic_finite_workspace100_corpus_only",
    "frozen_reviewed_builtins_only",
    "hostile_code_containment_not_established",
    "local_backend_retains_host_uid_filesystem_and_network_access",
    "content_digests_are_not_signatures_or_runtime_attestations",
    "locally_derived_anchors_are_not_independent_authentication",
    "same_process_expected_root_replay_is_not_independent_authentication",
    "runtime_digest_covers_resolved_interpreter_binary_bytes_only",
    "runtime_measurement_does_not_prove_historical_execution_provenance",
    "receipt_is_not_bound_by_release_or_artifact_tree_root",
    "path_checks_do_not_defend_against_privileged_mount_namespace_aliases",
    "same_uid_directory_replacement_races_are_out_of_scope",
)
_ROOT_FIELDS = {
    "adapter_implementation",
    "adjudication",
    "aggregate",
    "artifact_tree",
    "assignment",
    "backend",
    "baseline_set",
    "claim_set",
    "claims_implementation",
    "evidence",
    "execution_configuration",
    "generation_provenance",
    "isolation_policy",
    "limits",
    "method_registry",
    "panel",
    "projection",
    "protocol",
    "public_vocabulary",
    "registry",
    "release",
    "release_builder_implementation",
    "report",
    "run",
    "runtime",
    "scoring_implementation",
    "seed",
    "source",
    "source_opening",
    "template_catalog",
    "tool_implementation",
    "trust_anchor",
    "truth",
    "variant_catalog",
    "verifier_implementation",
    "worker_implementation",
}


class CandidateCaptureError(RuntimeError):
    """An operator precondition or candidate invariant failed."""


@dataclass(frozen=True, slots=True)
class _CapturePaths:
    checkout_root: str
    output_parent: str
    scratch_parent: str


@dataclass(frozen=True, slots=True)
class _CheckPaths:
    checkout_root: str
    output_parent: str


@dataclass(frozen=True, slots=True)
class _MeasuredInterpreter:
    path: str
    digest: str
    snapshot: tuple[int, ...]
    implementation: str
    version: str
    runtime_id: str

    @property
    def runtime_identity(self) -> Workspace100RuntimeIdentity:
        return Workspace100RuntimeIdentity(
            runtime_id=self.runtime_id,
            runtime_artifact_digest=self.digest,
            interpreter_digest=self.digest,
            implementation=self.implementation,
            version=self.version,
        )


@dataclass(frozen=True, slots=True)
class Workspace100CandidateReceipt:
    """One bounded, closed, path-free development receipt."""

    canonical_bytes: bytes

    def __post_init__(self) -> None:
        if type(self.canonical_bytes) is not bytes:
            raise TypeError("candidate receipt must contain exact bytes")
        _parse_and_validate_receipt(self.canonical_bytes)

    @classmethod
    def from_payload(
        cls,
        body: dict[str, JsonValue],
    ) -> Workspace100CandidateReceipt:
        if type(body) is not dict or "receipt_root" in body:
            raise ValueError("candidate receipt body must omit receipt_root")
        payload = dict(body)
        payload["receipt_root"] = canonical_digest(
            CANDIDATE_RECEIPT_FORMAT,
            body,
        )
        return cls(canonical_json(payload))

    @classmethod
    def from_canonical_bytes(
        cls,
        payload: bytes,
    ) -> Workspace100CandidateReceipt:
        return cls(payload)

    def to_canonical_bytes(self) -> bytes:
        return bytes(self.canonical_bytes)

    def to_payload(self) -> dict[str, JsonValue]:
        raw: object = json.loads(self.canonical_bytes)
        if type(raw) is not dict:  # pragma: no cover - constructor guarantees.
            raise RuntimeError("validated candidate receipt is not an object")
        return cast(dict[str, JsonValue], raw)

    @property
    def release_root(self) -> str:
        roots = self.to_payload()["roots"]
        if type(roots) is not dict:  # pragma: no cover - constructor guarantees.
            raise RuntimeError("validated candidate receipt roots are not an object")
        return cast(str, roots["release"])


def candidate_capture_implementation_digest() -> str:
    """Bind the exact orchestration implementation, separately from release."""

    return package_implementation_digest(
        _CAPTURE_IMPLEMENTATION_DOMAIN,
        _CAPTURE_IMPLEMENTATION_PATHS,
    )


def capture_workspace100_candidate(
    *,
    checkout_root: str,
    output_parent: str,
    scratch_parent: str,
    interpreter: str,
) -> Workspace100CandidateReceipt:
    """Execute, materialize, reload, and semantically verify one candidate."""

    implementation_start = candidate_capture_implementation_digest()
    paths = _validate_capture_paths(
        checkout_root=checkout_root,
        output_parent=output_parent,
        scratch_parent=scratch_parent,
    )
    measured = _measure_interpreter(interpreter)
    _require_disjoint_path(measured.path, paths.checkout_root)
    _require_disjoint_path(measured.path, paths.output_parent)
    _require_disjoint_path(measured.path, paths.scratch_parent)
    release = _construct_candidate_release(paths, measured)
    _verify_interpreter_unchanged(measured)
    expected_release_root = release.release_root
    materialize_workspace100_release(
        release,
        paths.output_parent,
        forbidden_roots=(paths.checkout_root, paths.scratch_parent),
    )
    loaded = load_workspace100_release_directory(
        paths.output_parent,
        expected_release_root=expected_release_root,
        forbidden_roots=(paths.checkout_root, paths.scratch_parent),
    )
    verified = verify_workspace100_release(
        loaded,
        expected_release_root=expected_release_root,
    )
    _verify_interpreter_unchanged(measured)
    receipt = _receipt_from_verified_release(
        verified,
        tool_implementation_digest=implementation_start,
    )
    if candidate_capture_implementation_digest() != implementation_start:
        raise CandidateCaptureError("candidate capture implementation changed during capture")
    return receipt


def check_workspace100_candidate(
    *,
    checkout_root: str,
    output_parent: str,
    expected_release_root: str,
) -> Workspace100CandidateReceipt:
    """Structurally load and semantically replay a caller-rooted candidate."""

    implementation_start = candidate_capture_implementation_digest()
    _require_digest(expected_release_root, field="expected_release_root")
    paths = _validate_check_paths(
        checkout_root=checkout_root,
        output_parent=output_parent,
    )
    loaded = load_workspace100_release_directory(
        paths.output_parent,
        expected_release_root=expected_release_root,
        forbidden_roots=(paths.checkout_root,),
    )
    verified = verify_workspace100_release(
        loaded,
        expected_release_root=expected_release_root,
    )
    receipt = _receipt_from_verified_release(
        verified,
        tool_implementation_digest=implementation_start,
    )
    if candidate_capture_implementation_digest() != implementation_start:
        raise CandidateCaptureError("candidate capture implementation changed during verification")
    return receipt


def _construct_candidate_release(
    paths: _CapturePaths,
    measured: _MeasuredInterpreter,
) -> Workspace100ReleaseDirectory:
    provenance = Workspace100GenerationProvenance(PORTFOLIO_SEED)
    corpus = provenance.corpus
    materials = verify_workspace100_materials(corpus)
    registries = Workspace100RegistrySet(
        provenance=provenance,
        manifests=tuple(material.manifest for material in materials),
    )
    anchors: tuple[VerificationTrustAnchor, ...] = tuple(
        trust_anchor_for_manifest(manifest) for manifest in registries.manifests
    )
    material_set = Workspace100VerifiedMaterialSet(
        registry_set=registries,
        materials=materials,
    )
    public_views = load_workspace100_public_evidence_views(
        workspace100_public_evidence_views_jsonl(material_set),
        material_set,
    )
    baseline_set = BuiltinBaselineSet.from_canonical_bytes(
        builtin_baseline_set().to_canonical_bytes()
    )
    runtime_identity = measured.runtime_identity
    backends = cast(
        tuple[WorkerBackend, ...],
        tuple(
            LocalPythonProcessBackend(
                artifact.program_source,
                runtime_digest=runtime_identity.runtime_root,
                interpreter=measured.path,
                scratch_root=paths.scratch_parent,
            )
            for artifact in baseline_set.bundles
        ),
    )
    backend_digests = {backend.implementation_digest for backend in backends}
    if len(backend_digests) != 1:
        raise CandidateCaptureError("reviewed built-ins produced mixed backend identities")
    backend_digest = next(iter(backend_digests))
    execution_order = tuple(
        Workspace100RunKey(
            method_id=artifact.bundle.method_id,
            evidence_digest=case.evidence_digest,
        )
        for artifact in baseline_set.bundles
        for case in public_views.cases
    )
    limits = WorkerLimits()
    claim_set = evaluate_workspace100_baselines(
        public_views,
        baseline_set,
        execution=Workspace100ExecutionPlan(
            backends=backends,
            expected_backend_implementation_digest=backend_digest,
            limits=limits,
        ),
        execution_order=execution_order,
    )
    if claim_set.backend_implementation_digest != backend_digest:
        raise CandidateCaptureError("ClaimSet backend differs from the measured execution backend")
    configuration = Workspace100ExecutionConfiguration(
        runtime_identity=runtime_identity,
        limits=limits,
        isolation_policy=Workspace100IsolationPolicy(),
        backend_implementation_digest=backend_digest,
    )
    return build_workspace100_release(
        PORTFOLIO_SEED,
        anchors,
        claim_set.to_canonical_bytes(),
        configuration,
    )


def _receipt_from_verified_release(
    verified: Workspace100VerifiedRelease,
    *,
    tool_implementation_digest: str,
) -> Workspace100CandidateReceipt:
    if type(verified) is not Workspace100VerifiedRelease:
        raise TypeError("candidate receipt requires an exact verified release")
    _require_digest(
        tool_implementation_digest,
        field="tool_implementation_digest",
    )
    verified.directory.validate()
    manifest = verified.directory.manifest
    bindings = manifest.bindings
    configuration = manifest.execution_configuration
    runtime = configuration.runtime_identity
    if runtime.interpreter_digest != runtime.runtime_artifact_digest:
        raise CandidateCaptureError(
            "development candidate runtime scope requires one binary digest"
        )
    expected_anchors = tuple(
        trust_anchor_for_manifest(registry) for registry in verified.registries.manifests
    )
    if verified.trust_anchors.anchors != expected_anchors:
        raise CandidateCaptureError(
            "candidate anchors are not the locally derived reproducibility set"
        )

    statuses = Counter(run.worker_run.status for run in verified.claim_set.runs)
    method_scores = tuple(_method_score_payload(method) for method in verified.score_report.methods)
    oracle_overall = _overall_slice(verified.score_report.oracle_ceiling.slices)
    files: tuple[JsonValue, ...] = tuple(
        cast(
            JsonValue,
            {
                "byte_length": len(payload),
                "content_digest": workspace100_release_file_content_digest(payload),
                "mode": RELEASE_FILE_MODE,
                "path": path,
            },
        )
        for path, payload in verified.directory.files
    )
    body: dict[str, JsonValue] = {
        "anchor_authority": _ANCHOR_AUTHORITY,
        "counts": {
            "assignments": verified.public_views.assignment_count,
            "completions": len(verified.corpus.completions),
            "methods": len(verified.score_report.methods),
            "pairs": len(verified.corpus.pairs),
            "participant_cases": verified.public_views.case_count,
            "payload_files": len(verified.directory.payloads),
            "templates": len(verified.corpus.templates),
            "tree_files": len(verified.directory.files),
            "trust_anchors": len(verified.trust_anchors.anchors),
            "variants": len(verified.corpus.variants),
            "view_cases": {
                view.value: sum(case.view is view for case in verified.public_views.cases)
                for view in ViewKind
            },
            "worker_runs": len(verified.claim_set.runs),
            "worker_status": {status.value: statuses[status] for status in WorkerRunStatus},
        },
        "files": files,
        "format": CANDIDATE_RECEIPT_FORMAT,
        "gate16_status": GATE16_STATUS,
        "nonclaims": _NONCLAIMS,
        "official": False,
        "oracle_ceiling_overall": _score_slice_payload(oracle_overall),
        "protocol_id": PROTOCOL_ID,
        "receipt_relation": _RECEIPT_RELATION,
        "release_kind": RELEASE_KIND,
        "root_authentication": _ROOT_AUTHENTICATION,
        "roots": {
            "adapter_implementation": (bindings.adapter_implementation_digest),
            "adjudication": verified.score_report.adjudication_root,
            "aggregate": verified.score_report.aggregate_root,
            "artifact_tree": manifest.artifact_tree_root,
            "assignment": bindings.assignment_root,
            "backend": bindings.backend_implementation_digest,
            "baseline_set": bindings.baseline_set_root,
            "claim_set": bindings.claim_set_root,
            "claims_implementation": (bindings.claims_implementation_digest),
            "evidence": bindings.evidence_root,
            "execution_configuration": (configuration.execution_configuration_root),
            "generation_provenance": (verified.provenance.generation_provenance_root),
            "isolation_policy": bindings.isolation_policy_root,
            "limits": bindings.limits_root,
            "method_registry": verified.claim_set.method_registry_root,
            "panel": bindings.panel_root,
            "projection": bindings.projection_root,
            "protocol": bindings.protocol_root,
            "public_vocabulary": bindings.public_vocabulary_digest,
            "registry": bindings.registry_root,
            "release": verified.directory.release_root,
            "release_builder_implementation": (bindings.release_builder_implementation_digest),
            "report": bindings.report_root,
            "run": verified.claim_set.run_root,
            "runtime": bindings.runtime_root,
            "scoring_implementation": (bindings.scoring_implementation_digest),
            "seed": verified.provenance.seed_digest,
            "source": bindings.source_root,
            "source_opening": verified.provenance.source_opening_root,
            "template_catalog": bindings.template_catalog_digest,
            "tool_implementation": tool_implementation_digest,
            "trust_anchor": bindings.trust_anchor_root,
            "truth": bindings.truth_root,
            "variant_catalog": bindings.variant_catalog_digest,
            "verifier_implementation": (bindings.verifier_implementation_digest),
            "worker_implementation": (bindings.worker_implementation_digest),
        },
        "runtime": {
            "artifact_scope": RUNTIME_ARTIFACT_SCOPE,
            "implementation": runtime.implementation,
            "interpreter_sha256": runtime.interpreter_digest,
            "runtime_artifact_sha256": runtime.runtime_artifact_digest,
            "runtime_id": runtime.runtime_id,
            "version": runtime.version,
        },
        "score_scope": "overall_exact_counts_and_ratios",
        "scores": method_scores,
    }
    return Workspace100CandidateReceipt.from_payload(body)


def _method_score_payload(method: object) -> dict[str, JsonValue]:
    if type(method) is not Workspace100MethodReport:
        raise TypeError("candidate score requires an exact method report")
    report = method
    payload = _score_slice_payload(_overall_slice(report.slices))
    payload.update(
        {
            "baseline": report.baseline.value,
            "method_digest": report.method_digest,
            "method_id": report.method_id,
            "method_report_digest": report.method_report_digest,
            "program_implementation_digest": (report.program_implementation_digest),
        }
    )
    return payload


def _score_slice_payload(
    score_slice: Workspace100ScoreSlice,
) -> dict[str, JsonValue]:
    if type(score_slice) is not Workspace100ScoreSlice:
        raise TypeError("candidate score requires an exact score slice")
    score_slice.validate()
    return {
        "counts": score_slice.counts.to_payload(),
        "failure_counts": score_slice.failure_counts.to_payload(),
        "metrics": score_slice.metrics.to_payload(),
        "slice_digest": score_slice.slice_digest,
    }


def _overall_slice(
    slices: tuple[Workspace100ScoreSlice, ...],
) -> Workspace100ScoreSlice:
    matches = tuple(
        score_slice for score_slice in slices if score_slice.kind is Workspace100SliceKind.OVERALL
    )
    if len(matches) != 1:
        raise CandidateCaptureError("score report does not contain exactly one overall slice")
    return matches[0]


def _validate_capture_paths(
    *,
    checkout_root: str,
    output_parent: str,
    scratch_parent: str,
) -> _CapturePaths:
    checkout = _validate_checkout_root(checkout_root)
    output = _validate_private_directory(
        output_parent,
        label="output parent",
    )
    scratch = _validate_private_directory(
        scratch_parent,
        label="scratch parent",
    )
    _require_disjoint_path(checkout, output)
    _require_disjoint_path(checkout, scratch)
    _require_disjoint_path(output, scratch)
    _require_absent_destination(output)
    return _CapturePaths(checkout, output, scratch)


def _validate_check_paths(
    *,
    checkout_root: str,
    output_parent: str,
) -> _CheckPaths:
    checkout = _validate_checkout_root(checkout_root)
    output = _validate_private_directory(
        output_parent,
        label="output parent",
    )
    _require_disjoint_path(checkout, output)
    return _CheckPaths(checkout, output)


def _validate_checkout_root(path: str) -> str:
    normalized = _validate_existing_directory(
        path,
        label="checkout root",
    )
    imported_package = Path(__file__).resolve().parents[1]
    expected_package = Path(normalized) / "src" / "witnessgap"
    if expected_package.resolve() != imported_package:
        raise CandidateCaptureError(
            "checkout root does not contain the imported WitnessGap package"
        )
    return normalized


def _validate_private_directory(path: str, *, label: str) -> str:
    normalized = _validate_existing_directory(path, label=label)
    metadata = os.stat(normalized, follow_symlinks=False)
    if stat.S_IMODE(metadata.st_mode) != _PRIVATE_DIRECTORY_MODE:
        raise CandidateCaptureError(f"{label} mode must be exactly 0700")
    if metadata.st_uid != os.geteuid():
        raise CandidateCaptureError(f"{label} must be owned by the effective UID")
    return normalized


def _validate_existing_directory(path: str, *, label: str) -> str:
    normalized = _validate_absolute_path(path, label=label)
    if os.path.realpath(normalized) != normalized:
        raise CandidateCaptureError(f"{label} must not contain symbolic links")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(normalized, flags)
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise CandidateCaptureError(f"{label} must be a directory")
    finally:
        os.close(descriptor)
    return normalized


def _validate_absolute_path(path: object, *, label: str) -> str:
    if type(path) is not str:
        raise TypeError(f"{label} must be an exact string")
    if not path or "\0" in path or not os.path.isabs(path) or os.path.normpath(path) != path:
        raise CandidateCaptureError(f"{label} must be a normalized absolute path")
    return path


def _require_disjoint_path(first: str, second: str) -> None:
    first_path = os.path.realpath(first)
    second_path = os.path.realpath(second)
    common = os.path.commonpath((first_path, second_path))
    if common in {first_path, second_path}:
        raise CandidateCaptureError(
            "checkout, output, scratch, and interpreter paths must be disjoint"
        )


def _require_absent_destination(output_parent: str) -> None:
    destination = os.path.join(output_parent, "workspace100")
    try:
        os.stat(destination, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise FileExistsError("Workspace-100 release destination already exists")


def _measure_interpreter(path: str) -> _MeasuredInterpreter:
    normalized = _validate_absolute_path(path, label="interpreter")
    if os.path.realpath(normalized) != normalized:
        raise CandidateCaptureError("interpreter must be the exact resolved physical path")
    current = os.path.realpath(sys.executable)
    if normalized != current:
        raise CandidateCaptureError("interpreter must be the current resolved Python executable")
    digest, snapshot = _hash_interpreter(normalized)
    metadata = _interpreter_metadata(normalized)
    implementation = _required_metadata_string(
        metadata,
        "implementation",
    )
    version = _required_metadata_string(metadata, "version")
    system = _required_metadata_string(metadata, "system")
    machine = _required_metadata_string(metadata, "machine")
    if os.name != "posix" or system != "Linux":
        raise CandidateCaptureError(
            "candidate capture requires the measured interpreter to run on Linux/POSIX"
        )
    runtime_id = _runtime_identifier(
        implementation,
        version,
        system,
        machine,
    )
    return _MeasuredInterpreter(
        path=normalized,
        digest=digest,
        snapshot=snapshot,
        implementation=implementation,
        version=version,
        runtime_id=runtime_id,
    )


def _hash_interpreter(path: str) -> tuple[str, tuple[int, ...]]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise CandidateCaptureError("interpreter must be a regular file")
        if stat.S_IMODE(before.st_mode) & 0o111 == 0:
            raise CandidateCaptureError("interpreter must be executable")
        digest = sha256()
        while chunk := os.read(descriptor, _HASH_CHUNK_BYTES):
            digest.update(chunk)
        after = os.fstat(descriptor)
        before_snapshot = _file_snapshot(before)
        if _file_snapshot(after) != before_snapshot:
            raise CandidateCaptureError("interpreter changed while it was being hashed")
        return digest.hexdigest(), before_snapshot
    finally:
        os.close(descriptor)


def _verify_interpreter_unchanged(measured: _MeasuredInterpreter) -> None:
    digest, snapshot = _hash_interpreter(measured.path)
    if digest != measured.digest or snapshot != measured.snapshot:
        raise CandidateCaptureError("interpreter changed during candidate capture")


def _file_snapshot(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _interpreter_metadata(path: str) -> dict[str, object]:
    source = (
        "import json,platform;"
        "print(json.dumps({"
        "'implementation':platform.python_implementation(),"
        "'machine':platform.machine(),"
        "'system':platform.system(),"
        "'version':platform.python_version()"
        "},sort_keys=True,separators=(',',':')))"
    )
    completed = subprocess.run(
        (path, "-I", "-S", "-B", "-c", source),
        check=False,
        capture_output=True,
        env={
            "HOME": "/",
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONNOUSERSITE": "1",
            "TZ": "UTC",
        },
        timeout=10,
    )
    if (
        completed.returncode != 0
        or completed.stderr
        or not completed.stdout
        or len(completed.stdout) > _METADATA_OUTPUT_BYTES
    ):
        raise CandidateCaptureError("interpreter metadata probe failed closed")
    try:
        raw: object = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CandidateCaptureError("interpreter metadata is not valid JSON") from error
    if type(raw) is not dict or set(raw) != {
        "implementation",
        "machine",
        "system",
        "version",
    }:
        raise CandidateCaptureError("interpreter metadata has an unsupported shape")
    return cast(dict[str, object], raw)


def _required_metadata_string(
    metadata: dict[str, object],
    field: str,
) -> str:
    value = metadata[field]
    if (
        type(value) is not str
        or not value
        or len(value) > _METADATA_TEXT_LENGTH
        or any(
            ord(character) < _ASCII_PRINTABLE_MIN or ord(character) > _ASCII_PRINTABLE_MAX
            for character in value
        )
    ):
        raise CandidateCaptureError(f"interpreter metadata {field} is invalid")
    return value


def _runtime_identifier(
    implementation: str,
    version: str,
    system: str,
    machine: str,
) -> str:
    raw = "_".join((implementation, version, system, machine)).lower()
    identifier = re.sub(r"[^a-z0-9]+", "_", raw).strip("_")
    if (
        not identifier
        or len(identifier) > _IDENTIFIER_LENGTH
        or _IDENTIFIER.fullmatch(identifier) is None
    ):
        raise CandidateCaptureError("interpreter metadata cannot form a runtime identifier")
    return identifier


def _parse_and_validate_receipt(payload: bytes) -> dict[str, object]:
    if not payload or len(payload) > _MAX_RECEIPT_BYTES:
        raise ValueError("candidate receipt exceeds its byte bound")
    try:
        raw: object = json.loads(payload)
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("candidate receipt is not valid JSON") from error
    if type(raw) is not dict:
        raise ValueError("candidate receipt must be an object")
    opened = cast(dict[str, object], raw)
    try:
        canonical = canonical_json(cast(JsonValue, opened))
    except (RecursionError, TypeError, UnicodeEncodeError) as error:
        raise ValueError("candidate receipt contains unsupported JSON") from error
    if canonical != payload:
        raise ValueError("candidate receipt is not canonical JSON")
    expected_fields = {
        "anchor_authority",
        "counts",
        "files",
        "format",
        "gate16_status",
        "nonclaims",
        "official",
        "oracle_ceiling_overall",
        "protocol_id",
        "receipt_relation",
        "receipt_root",
        "release_kind",
        "root_authentication",
        "roots",
        "runtime",
        "score_scope",
        "scores",
    }
    if set(opened) != expected_fields:
        raise ValueError("candidate receipt contains unknown or missing fields")
    fixed = (
        opened["format"] == CANDIDATE_RECEIPT_FORMAT
        and opened["protocol_id"] == PROTOCOL_ID
        and opened["official"] is False
        and opened["release_kind"] == RELEASE_KIND
        and opened["gate16_status"] == GATE16_STATUS
        and opened["anchor_authority"] == _ANCHOR_AUTHORITY
        and opened["root_authentication"] == _ROOT_AUTHENTICATION
        and opened["receipt_relation"] == _RECEIPT_RELATION
        and opened["score_scope"] == "overall_exact_counts_and_ratios"
    )
    if not fixed:
        raise ValueError("candidate receipt identity or scope is unsupported")
    nonclaims = opened["nonclaims"]
    if type(nonclaims) is not list or tuple(nonclaims) != _NONCLAIMS:
        raise ValueError("candidate receipt nonclaims differ from the closed set")
    roots = _required_object(opened, "roots")
    if set(roots) != _ROOT_FIELDS:
        raise ValueError("candidate receipt roots contain unknown or missing fields")
    for field, value in roots.items():
        _require_digest(value, field=f"candidate root {field}")
    runtime = _required_object(opened, "runtime")
    runtime_identity = _validate_runtime_payload(runtime)
    if runtime_identity.runtime_root != roots["runtime"]:
        raise ValueError("candidate runtime payload contradicts its rooted identity")
    counts = _required_object(opened, "counts")
    worker_failures = _validate_counts_payload(counts)
    _validate_files_payload(opened["files"])
    _validate_scores_payload(opened["scores"], worker_failures)
    _validate_oracle_payload(opened["oracle_ceiling_overall"])
    stored_root = opened["receipt_root"]
    _require_digest(stored_root, field="receipt_root")
    body = {key: cast(JsonValue, value) for key, value in opened.items() if key != "receipt_root"}
    if stored_root != canonical_digest(CANDIDATE_RECEIPT_FORMAT, body):
        raise ValueError("candidate receipt root contradicts its body")
    _reject_absolute_paths(cast(JsonValue, opened))
    return opened


def _validate_runtime_payload(
    runtime: dict[str, object],
) -> Workspace100RuntimeIdentity:
    if set(runtime) != {
        "artifact_scope",
        "implementation",
        "interpreter_sha256",
        "runtime_artifact_sha256",
        "runtime_id",
        "version",
    }:
        raise ValueError("candidate runtime contains unknown or missing fields")
    if runtime["artifact_scope"] != RUNTIME_ARTIFACT_SCOPE:
        raise ValueError("candidate runtime artifact scope is unsupported")
    interpreter_digest = runtime["interpreter_sha256"]
    artifact_digest = runtime["runtime_artifact_sha256"]
    _require_digest(interpreter_digest, field="interpreter_sha256")
    _require_digest(artifact_digest, field="runtime_artifact_sha256")
    if interpreter_digest != artifact_digest:
        raise ValueError("candidate runtime binary digests disagree")
    runtime_id = runtime["runtime_id"]
    if type(runtime_id) is not str or _IDENTIFIER.fullmatch(runtime_id) is None:
        raise ValueError("candidate runtime_id is invalid")
    for field in ("implementation", "version"):
        value = runtime[field]
        if (
            type(value) is not str
            or not value
            or len(value) > _RUNTIME_TEXT_LENGTH
            or _RUNTIME_TEXT.fullmatch(value) is None
        ):
            raise ValueError(f"candidate runtime {field} is invalid")
    return Workspace100RuntimeIdentity(
        runtime_id=runtime_id,
        runtime_artifact_digest=cast(str, artifact_digest),
        interpreter_digest=cast(str, interpreter_digest),
        implementation=cast(str, runtime["implementation"]),
        version=cast(str, runtime["version"]),
    )


def _validate_counts_payload(counts: dict[str, object]) -> int:
    expected_fields = {
        "assignments",
        "completions",
        "methods",
        "pairs",
        "participant_cases",
        "payload_files",
        "templates",
        "tree_files",
        "trust_anchors",
        "variants",
        "view_cases",
        "worker_runs",
        "worker_status",
    }
    if set(counts) != expected_fields:
        raise ValueError("candidate counts contain unknown or missing fields")
    expected = {
        "assignments": 400,
        "completions": 100,
        "methods": 4,
        "pairs": 50,
        "participant_cases": 300,
        "payload_files": len(RELEASE_PAYLOAD_PATHS),
        "templates": 5,
        "tree_files": len(RELEASE_LAYOUT_PATHS),
        "trust_anchors": 50,
        "variants": 50,
        "worker_runs": 1_200,
    }
    if any(counts[field] != value for field, value in expected.items()):
        raise ValueError("candidate counts contradict Workspace-100")
    views = counts["view_cases"]
    if type(views) is not dict or views != {
        ViewKind.EPOCH_PROBE.value: 100,
        ViewKind.OWNER_PROBE.value: 50,
        ViewKind.REFRESH_RECEIPT.value: 100,
        ViewKind.TRACE_ONLY.value: 50,
    }:
        raise ValueError("candidate view counts contradict Workspace-100")
    statuses = counts["worker_status"]
    if type(statuses) is not dict or set(statuses) != {status.value for status in WorkerRunStatus}:
        raise ValueError("candidate worker statuses are incomplete")
    claimed = _nonnegative_integer(statuses["claimed"], field="claimed")
    failed = _nonnegative_integer(statuses["failed"], field="failed")
    if claimed + failed != _RUN_COUNT:
        raise ValueError("candidate worker statuses do not cover 1,200 runs")
    return failed


def _validate_files_payload(value: object) -> None:
    if type(value) is not list or len(value) != len(RELEASE_LAYOUT_PATHS):
        raise ValueError("candidate file inventory has the wrong size")
    for expected_path, item in zip(RELEASE_LAYOUT_PATHS, value, strict=True):
        if type(item) is not dict or set(item) != {
            "byte_length",
            "content_digest",
            "mode",
            "path",
        }:
            raise ValueError("candidate file record is not closed")
        if item["path"] != expected_path:
            raise ValueError("candidate file inventory order is not canonical")
        if item["mode"] != RELEASE_FILE_MODE:
            raise ValueError("candidate file mode must be exactly 0444")
        byte_length = item["byte_length"]
        if type(byte_length) is not int or isinstance(byte_length, bool) or byte_length < 1:
            raise ValueError("candidate file byte_length is invalid")
        _require_digest(item["content_digest"], field="file content_digest")


def _validate_scores_payload(value: object, worker_failures: int) -> None:
    if type(value) is not list or len(value) != len(BuiltinBaseline):
        raise ValueError("candidate score summary must contain four methods")
    total_failures = 0
    frozen_bundles = builtin_baseline_set().bundles
    for expected_baseline, frozen_artifact, item in zip(
        BuiltinBaseline,
        frozen_bundles,
        value,
        strict=True,
    ):
        if type(item) is not dict or set(item) != {
            "baseline",
            "counts",
            "failure_counts",
            "method_digest",
            "method_id",
            "method_report_digest",
            "metrics",
            "program_implementation_digest",
            "slice_digest",
        }:
            raise ValueError("candidate method score is not closed")
        if item["baseline"] != expected_baseline.value:
            raise ValueError("candidate methods are not in frozen order")
        for field in (
            "method_digest",
            "method_report_digest",
            "program_implementation_digest",
            "slice_digest",
        ):
            _require_digest(item[field], field=f"candidate score {field}")
        frozen_bundle = frozen_artifact.bundle
        claim_method = Workspace100ClaimMethod(
            baseline=expected_baseline,
            baseline_bundle_digest=frozen_bundle.bundle_digest,
            method_id=frozen_bundle.method_id,
            program_implementation_digest=(frozen_bundle.program_implementation_digest),
        )
        if (
            item["method_id"],
            item["program_implementation_digest"],
            item["method_digest"],
        ) != (
            claim_method.method_id,
            claim_method.program_implementation_digest,
            claim_method.method_digest,
        ):
            raise ValueError("candidate method identity contradicts its frozen baseline")
        counts = Workspace100ScoreCounts.from_payload(item["counts"])
        failures = Workspace100FailureCounts.from_payload(item["failure_counts"])
        metrics = Workspace100ScoreMetrics.from_payload(item["metrics"])
        if counts.total_cases != _CASE_COUNT:
            raise ValueError("candidate method score must cover 300 cases")
        if failures.total != counts.failed_runs:
            raise ValueError("candidate method failures contradict counts")
        if metrics != Workspace100ScoreMetrics.from_counts(counts):
            raise ValueError("candidate method metrics contradict counts")
        expected_slice = Workspace100ScoreSlice(
            kind=Workspace100SliceKind.OVERALL,
            view=None,
            template_id=None,
            counts=counts,
            failure_counts=failures,
            metrics=metrics,
        )
        if item["slice_digest"] != expected_slice.slice_digest:
            raise ValueError("candidate method slice digest contradicts its table")
        total_failures += failures.total
    if total_failures != worker_failures:
        raise ValueError("candidate score failures contradict worker statuses")


def _validate_oracle_payload(value: object) -> None:
    if type(value) is not dict or set(value) != {
        "counts",
        "failure_counts",
        "metrics",
        "slice_digest",
    }:
        raise ValueError("candidate oracle summary is not closed")
    counts = Workspace100ScoreCounts.from_payload(value["counts"])
    failures = Workspace100FailureCounts.from_payload(value["failure_counts"])
    metrics = Workspace100ScoreMetrics.from_payload(value["metrics"])
    _require_digest(value["slice_digest"], field="oracle slice_digest")
    expected_counts = Workspace100ScoreCounts(
        correct_abstention=100,
        exact_decisive=200,
    )
    expected_slice = Workspace100ScoreSlice(
        kind=Workspace100SliceKind.OVERALL,
        view=None,
        template_id=None,
        counts=counts,
        failure_counts=failures,
        metrics=metrics,
    )
    if (
        counts != expected_counts
        or failures.total != 0
        or metrics != Workspace100ScoreMetrics.from_counts(counts)
        or value["slice_digest"] != expected_slice.slice_digest
    ):
        raise ValueError("candidate oracle summary is inconsistent")


def _required_object(
    payload: dict[str, object],
    field: str,
) -> dict[str, object]:
    value = payload[field]
    if type(value) is not dict:
        raise ValueError(f"candidate receipt {field} must be an object")
    return cast(dict[str, object], value)


def _require_digest(value: object, *, field: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{field} must be lowercase SHA-256")


def _nonnegative_integer(value: object, *, field: str) -> int:
    if type(value) is not int or isinstance(value, bool) or value < 0:
        raise ValueError(f"{field} must be a nonnegative integer")
    return value


def _reject_absolute_paths(value: JsonValue) -> None:
    if type(value) is str:
        if value.startswith("/") or _WINDOWS_ABSOLUTE.match(value) is not None or "\\" in value:
            raise ValueError("candidate receipt contains an absolute host path")
        return
    if type(value) is dict:
        for key, item in value.items():
            _reject_absolute_paths(key)
            _reject_absolute_paths(item)
    elif type(value) is list or type(value) is tuple:
        for item in value:
            _reject_absolute_paths(item)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m witnessgap.workspace100.candidate_capture",
        description=("Capture or verify a development-only Workspace-100 candidate."),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser(
        "capture",
        help="run 1,200 reviewed built-in processes and materialize a candidate",
    )
    capture.add_argument("--checkout-root", required=True)
    capture.add_argument("--output-parent", required=True)
    capture.add_argument("--scratch-parent", required=True)
    capture.add_argument("--interpreter", required=True)
    check = commands.add_parser(
        "check",
        help="verify a materialized candidate under a caller-supplied root",
    )
    check.add_argument("--checkout-root", required=True)
    check.add_argument("--output-parent", required=True)
    check.add_argument("--expected-release-root", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the closed development capture/check command set."""

    parser = _parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "capture":
            receipt = capture_workspace100_candidate(
                checkout_root=arguments.checkout_root,
                output_parent=arguments.output_parent,
                scratch_parent=arguments.scratch_parent,
                interpreter=arguments.interpreter,
            )
        elif arguments.command == "check":
            receipt = check_workspace100_candidate(
                checkout_root=arguments.checkout_root,
                output_parent=arguments.output_parent,
                expected_release_root=arguments.expected_release_root,
            )
        else:  # pragma: no cover - argparse enforces the closed command set.
            raise RuntimeError("unsupported candidate command")
    except (CandidateCaptureError, FileExistsError, OSError, ValueError) as error:
        print(f"candidate command failed: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(receipt.to_canonical_bytes())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
