from __future__ import annotations

import inspect
import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast

import pytest

from witnessgap.canonical import JsonValue, canonical_json
from witnessgap.identifiability import UnknownReason, VerdictKind
from witnessgap.trust import VerificationTrustAnchor
from witnessgap.verifier import verifier_implementation_digest
from witnessgap.workspace100 import release_builder as release_builder_module
from witnessgap.workspace100.baselines import builtin_baseline_set
from witnessgap.workspace100.claims import (
    Workspace100ClaimSet,
    build_workspace100_claim_set,
)
from witnessgap.workspace100.evidence import ParticipantClaim
from witnessgap.workspace100.generation import generate_workspace100
from witnessgap.workspace100.release import (
    RELEASE_PAYLOAD_PATHS,
    Workspace100ExecutionConfiguration,
    Workspace100IsolationPolicy,
    Workspace100ReleaseManifest,
    Workspace100RuntimeIdentity,
    workspace100_release_file_content_digest,
)
from witnessgap.workspace100.release_builder import (
    Workspace100VerifiedRelease,
    build_workspace100_release,
    verify_workspace100_release,
)
from witnessgap.workspace100.release_io import Workspace100ReleaseDirectory
from witnessgap.workspace100.release_storage import (
    Workspace100GenerationProvenance,
    Workspace100RegistrySet,
    Workspace100VerifiedMaterialSet,
    load_workspace100_public_evidence_views,
    workspace100_public_evidence_views_jsonl,
)
from witnessgap.workspace100.views import verify_workspace100_materials
from witnessgap.workspace100.worker import (
    WorkerLimits,
    WorkerRunRecord,
    WorkerRunStatus,
    workspace100_worker_request_digest,
)

_SEED = bytes.fromhex(
    "713d96c0fcadb930599f4f4370df3484766872ac406f1c26c5a360a996f29ec5"
)
_BACKEND_DIGEST = "a" * 64
_RUNTIME_ARTIFACT_DIGEST = "b" * 64
_INTERPRETER_DIGEST = "c" * 64
_REPLACEMENT_ROOT = "d" * 64
_WRONG_ROOT = "e" * 64
_ANCHOR_COUNT = 50
_UNKNOWN_CLAIM = ParticipantClaim(
    kind=VerdictKind.NOT_IDENTIFIABLE,
    unknown_reason=UnknownReason.AMBIGUOUS_WORLDS,
)


@dataclass(frozen=True, slots=True)
class _FrozenInputs:
    trust_anchors: tuple[VerificationTrustAnchor, ...]
    claim_set: Workspace100ClaimSet
    execution_configuration: Workspace100ExecutionConfiguration


@pytest.fixture(scope="module")
def frozen_inputs() -> _FrozenInputs:
    provenance = Workspace100GenerationProvenance(_SEED)
    corpus = generate_workspace100(_SEED)
    materials = verify_workspace100_materials(corpus)
    registries = Workspace100RegistrySet(
        provenance=provenance,
        manifests=tuple(material.manifest for material in materials),
    )
    verifier_digest = verifier_implementation_digest()
    anchors = tuple(
        VerificationTrustAnchor(
            registry_digest=manifest.digest,
            adapter_implementation_digest=(
                manifest.adapter_implementation_digest
            ),
            verifier_implementation_digest=verifier_digest,
        )
        for manifest in registries.manifests
    )
    material_set = Workspace100VerifiedMaterialSet(
        registry_set=registries,
        materials=materials,
    )
    public_view_bytes = workspace100_public_evidence_views_jsonl(material_set)
    views = load_workspace100_public_evidence_views(
        public_view_bytes,
        material_set,
    )
    baseline_set = builtin_baseline_set()
    limits = WorkerLimits()
    records = tuple(
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
        for case in views.cases
    )
    claim_set = build_workspace100_claim_set(
        views,
        baseline_set,
        records,
        backend_implementation_digest=_BACKEND_DIGEST,
        limits=limits,
    )
    configuration = _execution_configuration(limits)
    return _FrozenInputs(
        trust_anchors=anchors,
        claim_set=claim_set,
        execution_configuration=configuration,
    )


@pytest.fixture(scope="module")
def release_directory(
    frozen_inputs: _FrozenInputs,
) -> Workspace100ReleaseDirectory:
    return build_workspace100_release(
        _SEED,
        frozen_inputs.trust_anchors,
        frozen_inputs.claim_set.to_canonical_bytes(),
        frozen_inputs.execution_configuration,
    )


@pytest.fixture(scope="module")
def verified_release(
    release_directory: Workspace100ReleaseDirectory,
) -> Workspace100VerifiedRelease:
    return verify_workspace100_release(
        release_directory,
        expected_release_root=release_directory.release_root,
    )


def test_builder_and_semantic_verifier_close_the_frozen_release(
    release_directory: Workspace100ReleaseDirectory,
    verified_release: Workspace100VerifiedRelease,
) -> None:
    assert tuple(path for path, _ in release_directory.payloads) == (
        RELEASE_PAYLOAD_PATHS
    )
    assert len(release_directory.payloads) == len(RELEASE_PAYLOAD_PATHS)
    assert verified_release.directory == release_directory
    assert (
        verified_release.claim_set.claim_set_root
        == release_directory.manifest.bindings.claim_set_root
    )
    assert (
        verified_release.score_report.report_root
        == release_directory.manifest.bindings.report_root
    )
    assert (
        verified_release.implementation_digests.release_builder
        == release_directory.manifest.bindings.release_builder_implementation_digest
    )
    assert (
        release_directory.manifest.execution_configuration.isolation_policy.hostile_code_containment
        == "not_established"
    )
    assert (
        release_directory.manifest.execution_configuration.isolation_policy.participant_scope
        == "frozen_reviewed_builtins_only"
    )


def test_builder_has_no_report_input_or_anchor_authority() -> None:
    parameters = inspect.signature(build_workspace100_release).parameters
    assert tuple(parameters) == (
        "seed",
        "trust_anchors",
        "claim_set_bytes",
        "execution_configuration",
    )
    source_path = Path(release_builder_module.__file__)
    source = source_path.read_text(encoding="utf-8")
    forbidden_helper = "trust_anchor_" + "for_manifest"
    assert forbidden_helper not in source
    assert "VerificationTrustAnchor(" not in source


def test_builder_rejects_inexact_inputs_before_replay(
    frozen_inputs: _FrozenInputs,
) -> None:
    with pytest.raises(TypeError, match="exact bytes"):
        build_workspace100_release(
            cast(bytes, bytearray(_SEED)),
            frozen_inputs.trust_anchors,
            frozen_inputs.claim_set.to_canonical_bytes(),
            frozen_inputs.execution_configuration,
        )
    with pytest.raises(ValueError, match="32"):
        build_workspace100_release(
            _SEED[:-1],
            frozen_inputs.trust_anchors,
            frozen_inputs.claim_set.to_canonical_bytes(),
            frozen_inputs.execution_configuration,
        )
    with pytest.raises(TypeError, match="exactly 50"):
        build_workspace100_release(
            _SEED,
            frozen_inputs.trust_anchors[:-1],
            frozen_inputs.claim_set.to_canonical_bytes(),
            frozen_inputs.execution_configuration,
        )


def test_builder_structural_claim_check_precedes_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    anchor = VerificationTrustAnchor(
        registry_digest="0" * 64,
        adapter_implementation_digest="1" * 64,
        verifier_implementation_digest="2" * 64,
    )

    def unexpected_replay(_corpus: object) -> object:
        raise AssertionError("source replay ran before ClaimSet parsing")

    monkeypatch.setattr(
        release_builder_module,
        "verify_workspace100_materials",
        unexpected_replay,
    )
    with pytest.raises(ValueError, match=r"ClaimSet|claim set"):
        build_workspace100_release(
            _SEED,
            (anchor,) * _ANCHOR_COUNT,
            b"{}\n",
            _execution_configuration(WorkerLimits()),
        )


def test_semantic_verifier_requires_an_independent_release_root(
    release_directory: Workspace100ReleaseDirectory,
) -> None:
    with pytest.raises(ValueError, match="independently expected"):
        verify_workspace100_release(
            release_directory,
            expected_release_root=_WRONG_ROOT,
        )


def test_semantic_verifier_parses_report_before_replay(
    release_directory: Workspace100ReleaseDirectory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = "results/report.json"
    opened = _object(_payload(release_directory, path))
    opened["report_root"] = _REPLACEMENT_ROOT
    tampered = _replace_payload(
        release_directory,
        path=path,
        payload=canonical_json(cast(JsonValue, opened)),
    )

    def unexpected_replay(_corpus: object) -> object:
        raise AssertionError("source replay ran before report parsing")

    monkeypatch.setattr(
        release_builder_module,
        "verify_workspace100_materials",
        unexpected_replay,
    )
    with pytest.raises(ValueError, match=r"root|inconsistent"):
        verify_workspace100_release(
            tampered,
            expected_release_root=tampered.release_root,
        )


def test_semantic_verifier_rejects_canonical_payload_tampering(
    release_directory: Workspace100ReleaseDirectory,
) -> None:
    payload = _payload(release_directory, "protocol.json")
    opened = _object(payload)
    dimensions = cast(dict[str, JsonValue], opened["dimensions"])
    dimensions["pairs"] = 49
    tampered = _replace_payload(
        release_directory,
        path="protocol.json",
        payload=canonical_json(cast(JsonValue, opened)),
    )
    with pytest.raises(
        ValueError,
        match=r"contradict|matches|inconsistent",
    ):
        verify_workspace100_release(
            tampered,
            expected_release_root=tampered.release_root,
        )


@pytest.mark.parametrize(
    ("path", "field"),
    (
        ("verified/panels.jsonl", "material_digest"),
        ("public/views.jsonl", "evidence_digest"),
        ("truth/labels.jsonl", "truth_root"),
    ),
)
def test_semantic_verifier_rejects_panel_public_and_truth_tampering(
    release_directory: Workspace100ReleaseDirectory,
    path: str,
    field: str,
) -> None:
    payload = _payload(release_directory, path)
    if path.endswith(".jsonl") and path != "truth/labels.jsonl":
        lines = payload.splitlines()
        opened = _object(lines[0] + b"\n")
        opened[field] = _REPLACEMENT_ROOT
        lines[0] = canonical_json(cast(JsonValue, opened)).rstrip(b"\n")
        changed = b"\n".join(lines) + b"\n"
    else:
        opened = _object(payload)
        opened[field] = _REPLACEMENT_ROOT
        changed = canonical_json(cast(JsonValue, opened))
    tampered = _replace_payload(
        release_directory,
        path=path,
        payload=changed,
    )
    with pytest.raises(
        ValueError,
        match=r"contradict|differs|inconsistent|matches|round-trip",
    ):
        verify_workspace100_release(
            tampered,
            expected_release_root=tampered.release_root,
        )


def test_semantic_verifier_rejects_coherently_rerooted_bindings(
    release_directory: Workspace100ReleaseDirectory,
) -> None:
    files = tuple(
        replace(record, semantic_root=_REPLACEMENT_ROOT)
        if record.path == "baselines/baseline-set.json"
        else record
        for record in release_directory.manifest.files
    )
    bindings = replace(
        release_directory.manifest.bindings,
        baseline_set_root=_REPLACEMENT_ROOT,
    )
    manifest = replace(
        release_directory.manifest,
        bindings=bindings,
        files=files,
    )
    rerooted = Workspace100ReleaseDirectory(
        manifest=manifest,
        payloads=release_directory.payloads,
    )
    with pytest.raises(
        ValueError,
        match=r"(?:ClaimSet header|header bindings)",
    ):
        verify_workspace100_release(
            rerooted,
            expected_release_root=rerooted.release_root,
        )


def test_semantic_verifier_rejects_substituted_trust_anchor(
    release_directory: Workspace100ReleaseDirectory,
) -> None:
    path = "verified/trust-anchors.jsonl"
    lines = _payload(release_directory, path).splitlines()
    first = _object(lines[0] + b"\n")
    first["verifier_implementation_digest"] = _REPLACEMENT_ROOT
    lines[0] = canonical_json(cast(JsonValue, first)).rstrip(b"\n")
    payload = b"\n".join(lines) + b"\n"
    files = tuple(
        replace(
            record,
            byte_length=len(payload),
            content_digest=workspace100_release_file_content_digest(payload),
            semantic_root=_REPLACEMENT_ROOT,
        )
        if record.path == path
        else record
        for record in release_directory.manifest.files
    )
    bindings = replace(
        release_directory.manifest.bindings,
        trust_anchor_root=_REPLACEMENT_ROOT,
    )
    manifest = replace(
        release_directory.manifest,
        bindings=bindings,
        files=files,
    )
    payloads = tuple(
        (candidate, payload if candidate == path else original)
        for candidate, original in release_directory.payloads
    )
    tampered = Workspace100ReleaseDirectory(
        manifest=manifest,
        payloads=payloads,
    )
    with pytest.raises(ValueError, match="not aligned"):
        verify_workspace100_release(
            tampered,
            expected_release_root=tampered.release_root,
        )


def _replace_payload(
    release: Workspace100ReleaseDirectory,
    *,
    path: str,
    payload: bytes,
) -> Workspace100ReleaseDirectory:
    files = tuple(
        replace(
            record,
            byte_length=len(payload),
            content_digest=workspace100_release_file_content_digest(payload),
        )
        if record.path == path
        else record
        for record in release.manifest.files
    )
    manifest = Workspace100ReleaseManifest(
        generation_provenance_root=(
            release.manifest.generation_provenance_root
        ),
        execution_configuration=release.manifest.execution_configuration,
        bindings=release.manifest.bindings,
        files=files,
    )
    payloads = tuple(
        (candidate, payload if candidate == path else original)
        for candidate, original in release.payloads
    )
    return Workspace100ReleaseDirectory(
        manifest=manifest,
        payloads=payloads,
    )


def _payload(
    release: Workspace100ReleaseDirectory,
    path: str,
) -> bytes:
    return dict(release.payloads)[path]


def _object(payload: bytes) -> dict[str, object]:
    raw: object = json.loads(payload)
    assert type(raw) is dict
    return cast(dict[str, object], raw)


def _execution_configuration(
    limits: WorkerLimits,
) -> Workspace100ExecutionConfiguration:
    return Workspace100ExecutionConfiguration(
        runtime_identity=Workspace100RuntimeIdentity(
            runtime_id="controlled_test_runtime",
            runtime_artifact_digest=_RUNTIME_ARTIFACT_DIGEST,
            interpreter_digest=_INTERPRETER_DIGEST,
            implementation="CPython",
            version="3.13-test",
        ),
        limits=limits,
        isolation_policy=Workspace100IsolationPolicy(),
        backend_implementation_digest=_BACKEND_DIGEST,
    )
