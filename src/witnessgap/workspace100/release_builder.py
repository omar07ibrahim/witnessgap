"""Semantic construction and verification for Workspace-100 releases.

The filesystem loader authenticates exact bytes under a caller-pinned release
root.  This module supplies the next boundary: it deterministically rebuilds
every semantic payload from the opened seed, externally supplied trust
anchors, the canonical ClaimSet, and an exact execution configuration.

Trust anchors are inputs only.  This module never authors or substitutes one.
The v1 execution policy remains limited to the frozen reviewed built-ins and
continues to record that hostile-code containment is not established.

The installed implementation source closure is a trusted input.  The caller
must provide an immutable source tree or exclusive access that prevents
concurrent writes during a build or verification.  Start/end digest checks
fail closed on ordinary drift, but cannot prove the absence of an ABA
replacement that restores the same bytes between observations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from witnessgap.trust import VerificationTrustAnchor
from witnessgap.verifier import verifier_implementation_digest
from witnessgap.workspace100.baselines import (
    BuiltinBaselineSet,
    builtin_baseline_set,
)
from witnessgap.workspace100.claims import (
    Workspace100ClaimSet,
    load_verified_workspace100_claim_set,
    workspace100_claims_implementation_digest,
)
from witnessgap.workspace100.generation import Workspace100Corpus
from witnessgap.workspace100.records import TemplateRecord, VariantRecord
from witnessgap.workspace100.release import (
    RELEASE_PAYLOAD_PATHS,
    Workspace100ExecutionConfiguration,
    Workspace100ReleaseBindings,
    Workspace100ReleaseFile,
    Workspace100ReleaseManifest,
    workspace100_release_file_content_digest,
    workspace100_release_implementation_digest,
)
from witnessgap.workspace100.release_io import Workspace100ReleaseDirectory
from witnessgap.workspace100.release_storage import (
    Workspace100GenerationProvenance,
    Workspace100ProtocolRecord,
    Workspace100RegistrySet,
    Workspace100TrustAnchorSet,
    Workspace100VerifiedMaterialSet,
    load_workspace100_public_evidence_views,
    load_workspace100_source_openings,
    load_workspace100_template_catalog,
    load_workspace100_variant_catalog,
    workspace100_public_evidence_views_jsonl,
    workspace100_source_openings_jsonl,
    workspace100_template_catalog_bytes,
    workspace100_variant_catalog_bytes,
)
from witnessgap.workspace100.runtime import (
    workspace100_adapter_implementation_digest,
)
from witnessgap.workspace100.scoring import (
    Workspace100ScoreBindings,
    Workspace100ScoreReport,
    load_verified_workspace100_score_report,
    score_workspace100_claims,
    workspace100_scoring_implementation_digest,
)
from witnessgap.workspace100.truth import (
    Workspace100TruthSet,
    build_workspace100_truth,
)
from witnessgap.workspace100.views import (
    Workspace100EvidenceViews,
    verify_workspace100_materials,
)
from witnessgap.workspace100.worker import (
    workspace100_worker_implementation_digest,
)

_ANCHOR_COUNT = 50
_SEED_BYTES = 32
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class Workspace100ReleaseImplementationDigests:
    """One stable snapshot of every implementation identity in gate 17."""

    adapter: str
    verifier: str
    worker: str
    claims: str
    scoring: str
    release_builder: str

    def __post_init__(self) -> None:
        for field, value in (
            ("adapter", self.adapter),
            ("verifier", self.verifier),
            ("worker", self.worker),
            ("claims", self.claims),
            ("scoring", self.scoring),
            ("release_builder", self.release_builder),
        ):
            if type(value) is not str or _SHA256.fullmatch(value) is None:
                raise ValueError(
                    f"release implementation {field} must be lowercase SHA-256"
                )


@dataclass(frozen=True, slots=True)
class Workspace100VerifiedRelease:
    """Typed result of complete semantic verification under an external root."""

    directory: Workspace100ReleaseDirectory
    provenance: Workspace100GenerationProvenance
    corpus: Workspace100Corpus
    protocol: Workspace100ProtocolRecord
    baseline_set: BuiltinBaselineSet
    templates: tuple[TemplateRecord, ...]
    variants: tuple[VariantRecord, ...]
    registries: Workspace100RegistrySet
    trust_anchors: Workspace100TrustAnchorSet
    verified_materials: Workspace100VerifiedMaterialSet
    public_views: Workspace100EvidenceViews
    truth: Workspace100TruthSet
    claim_set: Workspace100ClaimSet
    score_report: Workspace100ScoreReport
    implementation_digests: Workspace100ReleaseImplementationDigests


@dataclass(frozen=True, slots=True)
class _Workspace100SemanticState:
    provenance: Workspace100GenerationProvenance
    corpus: Workspace100Corpus
    protocol: Workspace100ProtocolRecord
    baseline_set: BuiltinBaselineSet
    templates: tuple[TemplateRecord, ...]
    variants: tuple[VariantRecord, ...]
    registries: Workspace100RegistrySet
    trust_anchors: Workspace100TrustAnchorSet
    verified_materials: Workspace100VerifiedMaterialSet
    public_views: Workspace100EvidenceViews
    truth: Workspace100TruthSet
    claim_set: Workspace100ClaimSet
    score_bindings: Workspace100ScoreBindings
    score_report: Workspace100ScoreReport
    implementation_digests: Workspace100ReleaseImplementationDigests
    payloads: tuple[tuple[str, bytes], ...]


@dataclass(frozen=True, slots=True)
class _Workspace100ReportVerification:
    payload: bytes
    expected_root: str


@dataclass(frozen=True, slots=True)
class _Workspace100OpenedHeader:
    provenance: Workspace100GenerationProvenance
    corpus: Workspace100Corpus
    protocol: Workspace100ProtocolRecord
    baseline_set: BuiltinBaselineSet
    templates: tuple[TemplateRecord, ...]
    variants: tuple[VariantRecord, ...]
    registries: Workspace100RegistrySet
    trust_anchors: Workspace100TrustAnchorSet


def build_workspace100_release(
    seed: bytes,
    trust_anchors: tuple[VerificationTrustAnchor, ...],
    claim_set_bytes: bytes,
    execution_configuration: Workspace100ExecutionConfiguration,
) -> Workspace100ReleaseDirectory:
    """Build one deterministic 13-payload release from caller-pinned inputs.

    The score report is always recomputed from the authenticated ClaimSet and
    rebuilt truth.  No report bytes are accepted from the caller.
    """

    _validate_builder_inputs(
        seed,
        trust_anchors,
        claim_set_bytes,
        execution_configuration,
    )
    # Structural parsing enforces ClaimSet canonicality and its tighter byte
    # bound before source replay.  The authenticated loader still runs later.
    configuration = _snapshot_execution_configuration(
        execution_configuration
    )
    structural_claim = Workspace100ClaimSet.from_canonical_bytes(
        claim_set_bytes
    )
    _verify_claim_execution_header(
        structural_claim,
        configuration,
    )
    state = _rebuild_semantics(
        seed=seed,
        trust_anchors=trust_anchors,
        claim_set_bytes=claim_set_bytes,
        execution_configuration=configuration,
        report_verification=None,
    )
    return _assemble_release_directory(state, configuration)


def verify_workspace100_release(
    release: Workspace100ReleaseDirectory,
    *,
    expected_release_root: str,
) -> Workspace100VerifiedRelease:
    """Replay every semantic payload under an independently obtained root.

    A self-consistent structural manifest is insufficient.  The expected root
    must arrive through a channel independent of ``release``.
    """

    if type(release) is not Workspace100ReleaseDirectory:
        raise TypeError(
            "semantic release verification requires an exact release directory"
        )
    _require_digest(expected_release_root, field="expected_release_root")
    snapshot = _snapshot_release_directory(release)
    if snapshot.release_root != expected_release_root:
        raise ValueError(
            "release directory contradicts the independently expected root"
        )

    payload_by_path = dict(snapshot.payloads)
    # Cheap bounded structural parsing rejects hostile bulk before any replay.
    structural_claim = Workspace100ClaimSet.from_canonical_bytes(
        payload_by_path["results/claims.json"]
    )
    structural_report = Workspace100ScoreReport.from_canonical_bytes(
        payload_by_path["results/report.json"]
    )
    configuration = _snapshot_execution_configuration(
        snapshot.manifest.execution_configuration
    )
    _verify_claim_execution_header(
        structural_claim,
        configuration,
    )
    _verify_structural_result_headers(
        structural_claim,
        structural_report,
        snapshot.manifest,
    )
    provenance = Workspace100GenerationProvenance.from_canonical_bytes(
        payload_by_path["sealed/generation.json"]
    )
    protocol = Workspace100ProtocolRecord.from_canonical_bytes(
        payload_by_path["protocol.json"]
    )
    baseline_set = BuiltinBaselineSet.from_canonical_bytes(
        payload_by_path["baselines/baseline-set.json"]
    )
    templates = load_workspace100_template_catalog(
        payload_by_path["authored/templates.json"]
    )
    variants = load_workspace100_variant_catalog(
        payload_by_path["authored/variants.json"]
    )
    corpus = load_workspace100_source_openings(
        payload_by_path["sealed/sources.jsonl"],
        provenance,
    )
    # Registry parsing regenerates its exact manifests from the opened seed.
    registries = Workspace100RegistrySet.from_jsonl(
        payload_by_path["registries.jsonl"],
        provenance,
    )
    anchor_set = Workspace100TrustAnchorSet.from_jsonl(
        payload_by_path["verified/trust-anchors.jsonl"],
        registries,
    )
    stored_materials = Workspace100VerifiedMaterialSet.from_jsonl(
        payload_by_path["verified/panels.jsonl"],
        registries,
    )
    stored_views = load_workspace100_public_evidence_views(
        payload_by_path["public/views.jsonl"],
        stored_materials,
    )
    stored_truth = Workspace100TruthSet.from_canonical_bytes(
        payload_by_path["truth/labels.jsonl"]
    )
    _verify_opened_header_bindings(
        snapshot.manifest.bindings,
        _Workspace100OpenedHeader(
            provenance=provenance,
            corpus=corpus,
            protocol=protocol,
            baseline_set=baseline_set,
            templates=templates,
            variants=variants,
            registries=registries,
            trust_anchors=anchor_set,
        ),
    )
    opened_semantic_roots = (
        stored_materials.panel_root,
        stored_views.assignment_root,
        stored_views.evidence_root,
        stored_views.projection_root,
        stored_truth.truth_root,
    )
    bound_semantic_roots = (
        snapshot.manifest.bindings.panel_root,
        snapshot.manifest.bindings.assignment_root,
        snapshot.manifest.bindings.evidence_root,
        snapshot.manifest.bindings.projection_root,
        snapshot.manifest.bindings.truth_root,
    )
    if opened_semantic_roots != bound_semantic_roots:
        raise ValueError(
            "release semantic bindings contradict opened payload roots"
        )
    state = _rebuild_semantics(
        seed=provenance.seed,
        trust_anchors=anchor_set.anchors,
        claim_set_bytes=payload_by_path["results/claims.json"],
        execution_configuration=configuration,
        report_verification=_Workspace100ReportVerification(
            payload=payload_by_path["results/report.json"],
            expected_root=snapshot.manifest.bindings.report_root,
        ),
    )
    rebuilt = _assemble_release_directory(state, configuration)

    if rebuilt.manifest.bindings != snapshot.manifest.bindings:
        raise ValueError(
            "release bindings differ from the complete semantic rebuild"
        )
    if rebuilt.payloads != snapshot.payloads:
        raise ValueError(
            "release payload bytes differ from the complete semantic rebuild"
        )
    if rebuilt.manifest_bytes != snapshot.manifest_bytes:
        raise ValueError(
            "release manifest differs from the complete semantic rebuild"
        )
    if rebuilt.release_root != expected_release_root:
        raise ValueError(
            "semantic rebuild contradicts the independently expected root"
        )
    if (
        _capture_implementation_digests()
        != state.implementation_digests
    ):
        raise RuntimeError(
            "release implementation identities changed during final verification"
        )

    return Workspace100VerifiedRelease(
        directory=snapshot,
        provenance=state.provenance,
        corpus=state.corpus,
        protocol=state.protocol,
        baseline_set=state.baseline_set,
        templates=state.templates,
        variants=state.variants,
        registries=state.registries,
        trust_anchors=state.trust_anchors,
        verified_materials=state.verified_materials,
        public_views=state.public_views,
        truth=state.truth,
        claim_set=state.claim_set,
        score_report=state.score_report,
        implementation_digests=state.implementation_digests,
    )


def _rebuild_semantics(
    *,
    seed: bytes,
    trust_anchors: tuple[VerificationTrustAnchor, ...],
    claim_set_bytes: bytes,
    execution_configuration: Workspace100ExecutionConfiguration,
    report_verification: _Workspace100ReportVerification | None,
) -> _Workspace100SemanticState:
    implementation_start = _capture_implementation_digests()
    provenance = Workspace100GenerationProvenance(seed)
    corpus = provenance.corpus
    protocol = Workspace100ProtocolRecord.for_provenance(provenance)
    baseline_set = builtin_baseline_set()

    template_bytes = workspace100_template_catalog_bytes()
    templates = load_workspace100_template_catalog(template_bytes)
    variant_bytes = workspace100_variant_catalog_bytes()
    variants = load_workspace100_variant_catalog(variant_bytes)
    source_bytes = workspace100_source_openings_jsonl(provenance)

    materials = verify_workspace100_materials(corpus)
    registries = Workspace100RegistrySet(
        provenance=provenance,
        manifests=tuple(material.manifest for material in materials),
    )
    registry_bytes = registries.to_jsonl()
    supplied_anchor_set = Workspace100TrustAnchorSet(
        registry_set=registries,
        anchors=trust_anchors,
    )
    anchor_bytes = supplied_anchor_set.to_jsonl()
    # Parse the caller's exact bytes into private immutable snapshots before
    # any truth or manifest roots are derived from them.
    anchor_set = Workspace100TrustAnchorSet.from_jsonl(
        anchor_bytes,
        registries,
    )
    material_set = Workspace100VerifiedMaterialSet(
        registry_set=registries,
        materials=materials,
    )
    material_bytes = material_set.to_jsonl()
    public_views_bytes = workspace100_public_evidence_views_jsonl(material_set)
    public_views = load_workspace100_public_evidence_views(
        public_views_bytes,
        material_set,
    )
    truth = build_workspace100_truth(
        corpus,
        public_views,
        trust_anchors=anchor_set.anchors,
    )
    truth_bytes = truth.to_canonical_bytes()
    claim_set = load_verified_workspace100_claim_set(
        claim_set_bytes,
        public_views,
        baseline_set,
        expected_backend_implementation_digest=(
            execution_configuration.backend_implementation_digest
        ),
        expected_limits=execution_configuration.limits,
    )
    score_bindings = _score_bindings(
        claim_set,
        truth,
        implementation_start,
    )
    if report_verification is None:
        report = score_workspace100_claims(
            claim_set,
            truth,
            expected=score_bindings,
        )
    else:
        report = load_verified_workspace100_score_report(
            report_verification.payload,
            claim_set,
            truth,
            expected=score_bindings,
            expected_report_root=report_verification.expected_root,
        )
    canonical_report_bytes = report.to_canonical_bytes()
    implementation_end = _capture_implementation_digests()
    if implementation_end != implementation_start:
        raise RuntimeError(
            "release implementation identities changed during semantic rebuild"
        )

    payloads = (
        ("protocol.json", protocol.to_canonical_bytes()),
        ("baselines/baseline-set.json", baseline_set.to_canonical_bytes()),
        ("authored/templates.json", template_bytes),
        ("authored/variants.json", variant_bytes),
        ("sealed/generation.json", provenance.to_canonical_bytes()),
        ("sealed/sources.jsonl", source_bytes),
        ("registries.jsonl", registry_bytes),
        ("verified/trust-anchors.jsonl", anchor_bytes),
        ("verified/panels.jsonl", material_bytes),
        ("public/views.jsonl", public_views_bytes),
        ("truth/labels.jsonl", truth_bytes),
        ("results/claims.json", claim_set.to_canonical_bytes()),
        ("results/report.json", canonical_report_bytes),
    )
    if tuple(path for path, _ in payloads) != RELEASE_PAYLOAD_PATHS:
        raise RuntimeError(
            "semantic builder payload order differs from the release layout"
        )
    return _Workspace100SemanticState(
        provenance=provenance,
        corpus=corpus,
        protocol=protocol,
        baseline_set=baseline_set,
        templates=templates,
        variants=variants,
        registries=registries,
        trust_anchors=anchor_set,
        verified_materials=material_set,
        public_views=public_views,
        truth=truth,
        claim_set=claim_set,
        score_bindings=score_bindings,
        score_report=report,
        implementation_digests=implementation_end,
        payloads=payloads,
    )


def _assemble_release_directory(
    state: _Workspace100SemanticState,
    execution_configuration: Workspace100ExecutionConfiguration,
) -> Workspace100ReleaseDirectory:
    implementations = state.implementation_digests
    bindings = Workspace100ReleaseBindings(
        protocol_root=state.protocol.protocol_root,
        public_vocabulary_digest=(
            state.baseline_set.public_vocabulary_digest
        ),
        baseline_set_root=state.baseline_set.baseline_set_root,
        template_catalog_digest=state.provenance.template_catalog_digest,
        variant_catalog_digest=state.provenance.variant_catalog_digest,
        source_root=state.provenance.source_root,
        registry_root=state.registries.registry_root,
        panel_root=state.verified_materials.panel_root,
        assignment_root=state.public_views.assignment_root,
        evidence_root=state.public_views.evidence_root,
        projection_root=state.public_views.projection_root,
        truth_root=state.truth.truth_root,
        claim_set_root=state.claim_set.claim_set_root,
        report_root=state.score_report.report_root,
        adapter_implementation_digest=implementations.adapter,
        verifier_implementation_digest=implementations.verifier,
        worker_implementation_digest=implementations.worker,
        claims_implementation_digest=implementations.claims,
        scoring_implementation_digest=implementations.scoring,
        backend_implementation_digest=(
            execution_configuration.backend_implementation_digest
        ),
        runtime_root=execution_configuration.runtime_identity.runtime_root,
        limits_root=execution_configuration.limits.digest,
        isolation_policy_root=(
            execution_configuration.isolation_policy.isolation_policy_root
        ),
        trust_anchor_root=state.trust_anchors.trust_anchor_root,
        release_builder_implementation_digest=(
            implementations.release_builder
        ),
    )
    semantic_roots = (
        bindings.protocol_root,
        bindings.baseline_set_root,
        bindings.template_catalog_digest,
        bindings.variant_catalog_digest,
        state.provenance.generation_provenance_root,
        bindings.source_root,
        bindings.registry_root,
        bindings.trust_anchor_root,
        bindings.panel_root,
        bindings.evidence_root,
        bindings.truth_root,
        bindings.claim_set_root,
        bindings.report_root,
    )
    files = tuple(
        Workspace100ReleaseFile(
            path=path,
            byte_length=len(payload),
            content_digest=workspace100_release_file_content_digest(payload),
            semantic_root=semantic_root,
        )
        for (path, payload), semantic_root in zip(
            state.payloads,
            semantic_roots,
            strict=True,
        )
    )
    manifest = Workspace100ReleaseManifest(
        generation_provenance_root=(
            state.provenance.generation_provenance_root
        ),
        execution_configuration=execution_configuration,
        bindings=bindings,
        files=files,
    )
    directory = Workspace100ReleaseDirectory(
        manifest=manifest,
        payloads=state.payloads,
    )
    if (
        _capture_implementation_digests()
        != state.implementation_digests
    ):
        raise RuntimeError(
            "release implementation identities changed during serialization"
        )
    return directory


def _score_bindings(
    claim_set: Workspace100ClaimSet,
    truth: Workspace100TruthSet,
    implementations: Workspace100ReleaseImplementationDigests,
) -> Workspace100ScoreBindings:
    return Workspace100ScoreBindings(
        claim_set_root=claim_set.claim_set_root,
        truth_root=truth.truth_root,
        baseline_set_root=claim_set.baseline_set_root,
        assignment_root=claim_set.assignment_root,
        evidence_root=claim_set.evidence_root,
        projection_root=claim_set.projection_root,
        method_registry_root=claim_set.method_registry_root,
        scoring_implementation_digest=implementations.scoring,
    )


def _verify_claim_execution_header(
    claim_set: Workspace100ClaimSet,
    execution_configuration: Workspace100ExecutionConfiguration,
) -> None:
    baseline_set = builtin_baseline_set()
    actual = (
        claim_set.baseline_set_root,
        claim_set.backend_implementation_digest,
        claim_set.limits,
    )
    expected = (
        baseline_set.baseline_set_root,
        execution_configuration.backend_implementation_digest,
        execution_configuration.limits,
    )
    if actual != expected:
        raise ValueError(
            "ClaimSet header contradicts the frozen baseline or execution configuration"
        )


def _verify_structural_result_headers(
    claim_set: Workspace100ClaimSet,
    report: Workspace100ScoreReport,
    manifest: Workspace100ReleaseManifest,
) -> None:
    bindings = manifest.bindings
    claim_actual = (
        claim_set.claim_set_root,
        claim_set.baseline_set_root,
        claim_set.assignment_root,
        claim_set.evidence_root,
        claim_set.projection_root,
    )
    claim_expected = (
        bindings.claim_set_root,
        bindings.baseline_set_root,
        bindings.assignment_root,
        bindings.evidence_root,
        bindings.projection_root,
    )
    if claim_actual != claim_expected:
        raise ValueError("release ClaimSet header contradicts manifest bindings")
    report_actual = (
        report.report_root,
        report.claim_set_root,
        report.truth_root,
        report.baseline_set_root,
        report.assignment_root,
        report.evidence_root,
        report.projection_root,
        report.method_registry_root,
        report.scoring_implementation_digest,
    )
    report_expected = (
        bindings.report_root,
        bindings.claim_set_root,
        bindings.truth_root,
        bindings.baseline_set_root,
        bindings.assignment_root,
        bindings.evidence_root,
        bindings.projection_root,
        claim_set.method_registry_root,
        bindings.scoring_implementation_digest,
    )
    if report_actual != report_expected:
        raise ValueError("release score report header contradicts manifest bindings")


def _verify_opened_header_bindings(
    bindings: Workspace100ReleaseBindings,
    header: _Workspace100OpenedHeader,
) -> None:
    if not header.templates or not header.variants:
        raise ValueError("release authored catalogs must not be empty")
    actual = (
        bindings.protocol_root,
        bindings.public_vocabulary_digest,
        bindings.baseline_set_root,
        bindings.template_catalog_digest,
        bindings.variant_catalog_digest,
        bindings.source_root,
        bindings.registry_root,
        bindings.trust_anchor_root,
    )
    expected = (
        header.protocol.protocol_root,
        header.baseline_set.public_vocabulary_digest,
        header.baseline_set.baseline_set_root,
        header.provenance.template_catalog_digest,
        header.provenance.variant_catalog_digest,
        header.corpus.root,
        header.registries.registry_root,
        header.trust_anchors.trust_anchor_root,
    )
    if actual != expected:
        raise ValueError(
            "release header bindings contradict their canonical payloads"
        )
    if (
        header.protocol.source_root != header.provenance.source_root
        or header.protocol.source_opening_root
        != header.provenance.source_opening_root
        or header.corpus.root != header.provenance.source_root
    ):
        raise ValueError(
            "release protocol, provenance, and source openings disagree"
        )


def _capture_implementation_digests(
) -> Workspace100ReleaseImplementationDigests:
    return Workspace100ReleaseImplementationDigests(
        adapter=workspace100_adapter_implementation_digest(),
        verifier=verifier_implementation_digest(),
        worker=workspace100_worker_implementation_digest(),
        claims=workspace100_claims_implementation_digest(),
        scoring=workspace100_scoring_implementation_digest(),
        release_builder=workspace100_release_implementation_digest(),
    )


def _validate_builder_inputs(
    seed: object,
    trust_anchors: object,
    claim_set_bytes: object,
    execution_configuration: object,
) -> None:
    if type(seed) is not bytes:
        raise TypeError("release seed must be exact bytes")
    if len(seed) != _SEED_BYTES:
        raise ValueError("release seed must contain exactly 32 bytes")
    if (
        type(trust_anchors) is not tuple
        or len(trust_anchors) != _ANCHOR_COUNT
        or any(
            type(anchor) is not VerificationTrustAnchor
            for anchor in trust_anchors
        )
    ):
        raise TypeError("release requires exactly 50 external trust anchors")
    for anchor in trust_anchors:
        anchor.validate()
    if type(claim_set_bytes) is not bytes:
        raise TypeError("release ClaimSet must be exact bytes")
    if not claim_set_bytes:
        raise ValueError("release ClaimSet must not be empty")
    if (
        type(execution_configuration)
        is not Workspace100ExecutionConfiguration
    ):
        raise TypeError(
            "release requires an exact Workspace-100 execution configuration"
        )
    execution_configuration.validate()


def _snapshot_execution_configuration(
    execution_configuration: Workspace100ExecutionConfiguration,
) -> Workspace100ExecutionConfiguration:
    if (
        type(execution_configuration)
        is not Workspace100ExecutionConfiguration
    ):
        raise TypeError(
            "release requires an exact Workspace-100 execution configuration"
        )
    return Workspace100ExecutionConfiguration.from_payload(
        execution_configuration.to_payload()
    )


def _snapshot_release_directory(
    release: Workspace100ReleaseDirectory,
) -> Workspace100ReleaseDirectory:
    release.validate()
    manifest = Workspace100ReleaseManifest.from_canonical_bytes(
        release.manifest_bytes
    )
    payloads = tuple((path, payload) for path, payload in release.payloads)
    return Workspace100ReleaseDirectory(
        manifest=manifest,
        payloads=payloads,
    )


def _require_digest(value: object, *, field: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{field} must be lowercase SHA-256")
