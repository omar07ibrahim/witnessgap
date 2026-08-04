"""Closed, bounded storage records for a Workspace-100 release candidate.

This module only defines deterministic in-memory records and byte encodings.
It performs no filesystem writes, authors no trust anchors, and deliberately
does not import the release materializer.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import cast

from witnessgap.canonical import JsonValue, canonical_digest, canonical_json, tagged_digest
from witnessgap.identifiability import RegistryManifest
from witnessgap.model import ExecutionArtifact, Outcome, StateRead, TargetFamily, Witness
from witnessgap.source import SealedWorldSource
from witnessgap.trust import VerificationTrustAnchor
from witnessgap.verifier import (
    VerifiedPanel,
    VerifiedProbeReceipt,
    VerifiedReceipt,
    verifier_implementation_digest,
)
from witnessgap.workspace100 import views as workspace100_views
from witnessgap.workspace100.baselines import (
    BUILTIN_BASELINE_SET_ROOT,
    builtin_baseline_set,
    public_baseline_vocabulary_digest,
    public_baseline_vocabulary_payload,
)
from witnessgap.workspace100.catalog import (
    TEMPLATES,
    VARIANTS,
    template_catalog_digest,
    variant_catalog_digest,
)
from witnessgap.workspace100.generation import (
    GeneratedPair,
    Workspace100Corpus,
    generate_workspace100,
)
from witnessgap.workspace100.records import (
    PROTOCOL_ID,
    Split,
    TemplateId,
    TemplateRecord,
    VariantRecord,
)
from witnessgap.workspace100.runtime import (
    workspace100_adapter_implementation_digest,
    workspace100_pair_worlds,
)
from witnessgap.workspace100.views import (
    PublicEvidenceCase,
    VerifiedCompletionMaterial,
    VerifiedPairMaterial,
    ViewKind,
    Workspace100EvidenceViews,
)

GENERATION_PROVENANCE_FORMAT = "witnessgap.workspace100-generation-provenance.v1"
CATALOG_SET_FORMAT = "witnessgap.workspace100-catalog-set.v1"
TEMPLATE_CATALOG_FORMAT = "witnessgap.workspace100-template-catalog.v1"
VARIANT_CATALOG_FORMAT = "witnessgap.workspace100-variant-catalog.v1"
SOURCE_OPENING_FORMAT = "witnessgap.workspace100-source-opening.v1"
SOURCE_OPENING_SET_FORMAT = "witnessgap.workspace100-source-opening-set.v1"
PROTOCOL_RECORD_FORMAT = "witnessgap.workspace100-protocol-record.v1"
REGISTRY_SET_FORMAT = "witnessgap.workspace100-registry-set.v1"
TRUST_ANCHOR_SET_FORMAT = "witnessgap.workspace100-trust-anchor-set.v1"
VERIFIED_MATERIAL_FORMAT = "witnessgap.workspace100-verified-material.v1"
VERIFIED_MATERIAL_SET_FORMAT = "witnessgap.workspace100-verified-material-set.v1"
VERIFIED_COMPLETION_FORMAT = "witnessgap.workspace100-verified-completion.v1"
VERIFIED_PANEL_STORAGE_FORMAT = "witnessgap.workspace100-verified-panel-storage.v1"
VERIFIED_RECEIPT_STORAGE_FORMAT = "witnessgap.workspace100-verified-receipt-storage.v1"
VERIFIED_PROBE_STORAGE_FORMAT = "witnessgap.workspace100-verified-probe-storage.v1"
EXECUTION_ARTIFACT_STORAGE_FORMAT = "witnessgap.execution-artifact-storage.v1"
PUBLIC_EVIDENCE_CASE_FORMAT = "witnessgap.workspace100-evidence-case.v1"

_GENERATION_SEED_DOMAIN = "witnessgap.workspace100-generation-seed.v1"
_PAIR_COUNT = 50
_PAIR_SIZE = 2
_COMPLETION_COUNT = 100
_TEMPLATE_COUNT = 5
_VARIANT_COUNT = 50
_ASSIGNMENT_COUNT = 400
_EVIDENCE_CASE_COUNT = 300
_METHOD_COUNT = 4
_VIEW_COUNT = 4
_RECEIPTS_PER_PANEL = 4
_PROBES_PER_COMPLETION = 2
_SEED_BYTES = 32
_SHA256_HEX_LENGTH = 64
_MAX_PROVENANCE_BYTES = 1 << 14
_MAX_CATALOG_BYTES = 1 << 20
_MAX_TEMPLATE_CATALOG_BYTES = 1 << 17
_MAX_VARIANT_CATALOG_BYTES = 1 << 20
_MAX_SOURCE_JSONL_BYTES = 4 << 20
_MAX_SOURCE_LINE_BYTES = 1 << 17
_MAX_PROTOCOL_BYTES = 1 << 17
_MAX_REGISTRY_JSONL_BYTES = 2 << 20
_MAX_REGISTRY_LINE_BYTES = 1 << 16
_MAX_ANCHOR_JSONL_BYTES = 1 << 18
_MAX_ANCHOR_LINE_BYTES = 1 << 13
_MAX_MATERIAL_JSONL_BYTES = 32 << 20
_MAX_MATERIAL_LINE_BYTES = 1 << 20
_MAX_PUBLIC_EVIDENCE_JSONL_BYTES = 4 << 20
_MAX_PUBLIC_EVIDENCE_LINE_BYTES = 1 << 16
_MAX_ARTIFACT_BYTES = 1 << 16
_MAX_PROBE_BYTES = 1 << 16
_MAX_STATE_READS = 64
_MAX_INTERVENTIONS = 12
_LOWER_HEX = re.compile(r"^[0-9a-f]+$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class Workspace100GenerationProvenance:
    """One exact seed opening and every identity deterministically derived from it."""

    seed: bytes

    def __post_init__(self) -> None:
        if type(self.seed) is not bytes:
            raise TypeError("generation provenance seed must be exact bytes")
        if len(self.seed) != _SEED_BYTES:
            raise ValueError(f"generation provenance seed must contain {_SEED_BYTES} bytes")

    @property
    def seed_digest(self) -> str:
        return tagged_digest(_GENERATION_SEED_DOMAIN, self.seed)

    @property
    def corpus(self) -> Workspace100Corpus:
        return generate_workspace100(self.seed)

    @property
    def source_root(self) -> str:
        """Gate-17 source identity, equal to the frozen corpus/truth root."""

        return self.corpus.root

    @property
    def source_opening_root(self) -> str:
        """Direct aggregate over the complete canonical source-opening records."""

        return workspace100_source_opening_root(self.corpus)

    @property
    def template_catalog_digest(self) -> str:
        return template_catalog_digest(TEMPLATES)

    @property
    def variant_catalog_digest(self) -> str:
        return variant_catalog_digest(VARIANTS)

    @property
    def adapter_implementation_digest(self) -> str:
        return workspace100_adapter_implementation_digest()

    def root_payload(self) -> dict[str, JsonValue]:
        return {
            "adapter_implementation_digest": self.adapter_implementation_digest,
            "format": GENERATION_PROVENANCE_FORMAT,
            "protocol_id": PROTOCOL_ID,
            "seed_digest": self.seed_digest,
            "seed_hex": self.seed.hex(),
            "source_opening_root": self.source_opening_root,
            "source_root": self.source_root,
            "template_catalog_digest": self.template_catalog_digest,
            "variant_catalog_digest": self.variant_catalog_digest,
        }

    @property
    def generation_provenance_root(self) -> str:
        return canonical_digest(GENERATION_PROVENANCE_FORMAT, self.root_payload())

    def to_payload(self) -> dict[str, JsonValue]:
        return {
            **self.root_payload(),
            "generation_provenance_root": self.generation_provenance_root,
        }

    def to_canonical_bytes(self) -> bytes:
        payload = canonical_json(self.to_payload())
        if len(payload) > _MAX_PROVENANCE_BYTES:
            raise ValueError("generation provenance exceeds its byte bound")
        return payload

    @classmethod
    def from_canonical_bytes(cls, payload: bytes) -> Workspace100GenerationProvenance:
        raw = _canonical_object(
            payload,
            label="generation provenance",
            maximum=_MAX_PROVENANCE_BYTES,
        )
        _require_closed_fields(
            raw,
            {
                "adapter_implementation_digest",
                "format",
                "generation_provenance_root",
                "protocol_id",
                "seed_digest",
                "seed_hex",
                "source_opening_root",
                "source_root",
                "template_catalog_digest",
                "variant_catalog_digest",
            },
            label="generation provenance",
        )
        if raw["format"] != GENERATION_PROVENANCE_FORMAT:
            raise ValueError("generation provenance format is unsupported")
        if raw["protocol_id"] != PROTOCOL_ID:
            raise ValueError("generation provenance protocol is unsupported")
        seed = _required_hex_bytes(
            raw,
            "seed_hex",
            exact_bytes=_SEED_BYTES,
        )
        provenance = cls(seed)
        _require_payload_matches(
            raw,
            provenance.to_payload(),
            label="generation provenance",
        )
        if provenance.to_canonical_bytes() != payload:
            raise ValueError("generation provenance failed canonical round-trip")
        return provenance


@dataclass(frozen=True, slots=True)
class Workspace100CatalogSet:
    """The exact five-template, fifty-variant authored catalog."""

    @property
    def templates(self) -> tuple[TemplateRecord, ...]:
        return TEMPLATES

    @property
    def variants(self) -> tuple[VariantRecord, ...]:
        return VARIANTS

    @property
    def template_digest(self) -> str:
        return template_catalog_digest(self.templates)

    @property
    def variant_digest(self) -> str:
        return variant_catalog_digest(self.variants)

    def root_payload(self) -> dict[str, JsonValue]:
        return {
            "format": CATALOG_SET_FORMAT,
            "protocol_id": PROTOCOL_ID,
            "template_catalog_digest": self.template_digest,
            "variant_catalog_digest": self.variant_digest,
        }

    @property
    def catalog_root(self) -> str:
        return canonical_digest(CATALOG_SET_FORMAT, self.root_payload())

    def to_payload(self) -> dict[str, JsonValue]:
        return {
            **self.root_payload(),
            "catalog_root": self.catalog_root,
            "templates": tuple(template.to_payload() for template in self.templates),
            "variants": tuple(variant.to_payload() for variant in self.variants),
        }

    def to_canonical_bytes(self) -> bytes:
        payload = canonical_json(self.to_payload())
        if len(payload) > _MAX_CATALOG_BYTES:
            raise ValueError("Workspace-100 catalog set exceeds its byte bound")
        return payload

    @classmethod
    def from_canonical_bytes(cls, payload: bytes) -> Workspace100CatalogSet:
        raw = _canonical_object(
            payload,
            label="Workspace-100 catalog set",
            maximum=_MAX_CATALOG_BYTES,
        )
        _require_closed_fields(
            raw,
            {
                "catalog_root",
                "format",
                "protocol_id",
                "template_catalog_digest",
                "templates",
                "variant_catalog_digest",
                "variants",
            },
            label="Workspace-100 catalog set",
        )
        if raw["format"] != CATALOG_SET_FORMAT or raw["protocol_id"] != PROTOCOL_ID:
            raise ValueError("Workspace-100 catalog set identity is unsupported")
        templates_raw = _required_array(raw, "templates")
        variants_raw = _required_array(raw, "variants")
        if len(templates_raw) != _TEMPLATE_COUNT or len(variants_raw) != _VARIANT_COUNT:
            raise ValueError("Workspace-100 catalog set has the wrong cardinality")
        templates = tuple(
            TemplateRecord.from_canonical_bytes(
                canonical_json(cast(JsonValue, value))
            )
            for value in templates_raw
        )
        variants = tuple(
            VariantRecord.from_canonical_bytes(
                canonical_json(cast(JsonValue, value))
            )
            for value in variants_raw
        )
        if templates != TEMPLATES or variants != VARIANTS:
            raise ValueError("Workspace-100 catalog set differs from the frozen catalog")
        catalog = cls()
        _require_payload_matches(raw, catalog.to_payload(), label="Workspace-100 catalog set")
        if catalog.to_canonical_bytes() != payload:
            raise ValueError("Workspace-100 catalog set failed canonical round-trip")
        return catalog


def workspace100_template_catalog_bytes() -> bytes:
    """Encode the exact frozen template catalog under its semantic-root payload."""

    payload = canonical_json(
        {
            "format": TEMPLATE_CATALOG_FORMAT,
            "protocol_id": PROTOCOL_ID,
            "templates": tuple(template.to_payload() for template in TEMPLATES),
        }
    )
    if len(payload) > _MAX_TEMPLATE_CATALOG_BYTES:
        raise ValueError("Workspace-100 template catalog exceeds its byte bound")
    return payload


def load_workspace100_template_catalog(
    payload: bytes,
) -> tuple[TemplateRecord, ...]:
    """Load only the exact catalog committed by ``template_catalog_digest``."""

    raw = _canonical_object(
        payload,
        label="Workspace-100 template catalog",
        maximum=_MAX_TEMPLATE_CATALOG_BYTES,
    )
    _require_closed_fields(
        raw,
        {"format", "protocol_id", "templates"},
        label="Workspace-100 template catalog",
    )
    if raw["format"] != TEMPLATE_CATALOG_FORMAT or raw["protocol_id"] != PROTOCOL_ID:
        raise ValueError("Workspace-100 template catalog identity is unsupported")
    templates_raw = _required_array(raw, "templates")
    if len(templates_raw) != _TEMPLATE_COUNT:
        raise ValueError("Workspace-100 template catalog has the wrong cardinality")
    templates = tuple(
        TemplateRecord.from_canonical_bytes(canonical_json(cast(JsonValue, value)))
        for value in templates_raw
    )
    if (
        templates != TEMPLATES
        or template_catalog_digest(templates) != template_catalog_digest(TEMPLATES)
    ):
        raise ValueError("Workspace-100 template catalog differs from the frozen catalog")
    if workspace100_template_catalog_bytes() != payload:
        raise ValueError("Workspace-100 template catalog failed canonical round-trip")
    return templates


def workspace100_variant_catalog_bytes() -> bytes:
    """Encode the exact frozen variant catalog under its semantic-root payload."""

    payload = canonical_json(
        {
            "format": VARIANT_CATALOG_FORMAT,
            "protocol_id": PROTOCOL_ID,
            "variants": tuple(variant.to_payload() for variant in VARIANTS),
        }
    )
    if len(payload) > _MAX_VARIANT_CATALOG_BYTES:
        raise ValueError("Workspace-100 variant catalog exceeds its byte bound")
    return payload


def load_workspace100_variant_catalog(
    payload: bytes,
) -> tuple[VariantRecord, ...]:
    """Load only the exact catalog committed by ``variant_catalog_digest``."""

    raw = _canonical_object(
        payload,
        label="Workspace-100 variant catalog",
        maximum=_MAX_VARIANT_CATALOG_BYTES,
    )
    _require_closed_fields(
        raw,
        {"format", "protocol_id", "variants"},
        label="Workspace-100 variant catalog",
    )
    if raw["format"] != VARIANT_CATALOG_FORMAT or raw["protocol_id"] != PROTOCOL_ID:
        raise ValueError("Workspace-100 variant catalog identity is unsupported")
    variants_raw = _required_array(raw, "variants")
    if len(variants_raw) != _VARIANT_COUNT:
        raise ValueError("Workspace-100 variant catalog has the wrong cardinality")
    variants = tuple(
        VariantRecord.from_canonical_bytes(canonical_json(cast(JsonValue, value)))
        for value in variants_raw
    )
    if (
        variants != VARIANTS
        or variant_catalog_digest(variants) != variant_catalog_digest(VARIANTS)
    ):
        raise ValueError("Workspace-100 variant catalog differs from the frozen catalog")
    if workspace100_variant_catalog_bytes() != payload:
        raise ValueError("Workspace-100 variant catalog failed canonical round-trip")
    return variants


@dataclass(frozen=True, slots=True)
class Workspace100ProtocolRecord:
    """Closed protocol metadata bound to one exact generated source set."""

    source_root: str
    source_opening_root: str

    def __post_init__(self) -> None:
        _require_digest_value(self.source_root, field="protocol source_root")
        _require_digest_value(
            self.source_opening_root,
            field="protocol source_opening_root",
        )

    @classmethod
    def for_provenance(
        cls,
        provenance: Workspace100GenerationProvenance,
    ) -> Workspace100ProtocolRecord:
        _require_provenance(provenance)
        return cls(
            source_root=provenance.source_root,
            source_opening_root=provenance.source_opening_root,
        )

    def root_payload(self) -> dict[str, JsonValue]:
        baseline_set = builtin_baseline_set()
        return {
            "baseline_set_root": BUILTIN_BASELINE_SET_ROOT,
            "dimensions": {
                "assignments": _ASSIGNMENT_COUNT,
                "completions": _COMPLETION_COUNT,
                "evidence_cases": _EVIDENCE_CASE_COUNT,
                "methods": _METHOD_COUNT,
                "pairs": _PAIR_COUNT,
                "templates": _TEMPLATE_COUNT,
                "variants": _VARIANT_COUNT,
                "views": _VIEW_COUNT,
            },
            "format": PROTOCOL_RECORD_FORMAT,
            "method_order": tuple(
                artifact.bundle.method_id for artifact in baseline_set.bundles
            ),
            "protocol_id": PROTOCOL_ID,
            "public_vocabulary": public_baseline_vocabulary_payload(),
            "public_vocabulary_digest": public_baseline_vocabulary_digest(),
            "source_opening_root": self.source_opening_root,
            "source_root": self.source_root,
            "template_catalog_digest": template_catalog_digest(TEMPLATES),
            "template_order": tuple(template.value for template in TemplateId),
            "variant_catalog_digest": variant_catalog_digest(VARIANTS),
            "view_order": tuple(view.value for view in ViewKind),
        }

    @property
    def protocol_root(self) -> str:
        return canonical_digest(PROTOCOL_RECORD_FORMAT, self.root_payload())

    def to_payload(self) -> dict[str, JsonValue]:
        return {**self.root_payload(), "protocol_root": self.protocol_root}

    def to_canonical_bytes(self) -> bytes:
        payload = canonical_json(self.to_payload())
        if len(payload) > _MAX_PROTOCOL_BYTES:
            raise ValueError("Workspace-100 protocol record exceeds its byte bound")
        return payload

    @classmethod
    def from_canonical_bytes(cls, payload: bytes) -> Workspace100ProtocolRecord:
        raw = _canonical_object(
            payload,
            label="Workspace-100 protocol record",
            maximum=_MAX_PROTOCOL_BYTES,
        )
        _require_closed_fields(
            raw,
            {
                "baseline_set_root",
                "dimensions",
                "format",
                "method_order",
                "protocol_id",
                "protocol_root",
                "public_vocabulary",
                "public_vocabulary_digest",
                "source_opening_root",
                "source_root",
                "template_catalog_digest",
                "template_order",
                "variant_catalog_digest",
                "view_order",
            },
            label="Workspace-100 protocol record",
        )
        if raw["format"] != PROTOCOL_RECORD_FORMAT or raw["protocol_id"] != PROTOCOL_ID:
            raise ValueError("Workspace-100 protocol record identity is unsupported")
        record = cls(
            source_root=_required_digest(raw, "source_root"),
            source_opening_root=_required_digest(raw, "source_opening_root"),
        )
        _require_payload_matches(raw, record.to_payload(), label="Workspace-100 protocol record")
        if record.to_canonical_bytes() != payload:
            raise ValueError("Workspace-100 protocol record failed canonical round-trip")
        return record


@dataclass(frozen=True, slots=True)
class Workspace100RegistrySet:
    """Fifty exact registry manifests aligned with one generated corpus."""

    provenance: Workspace100GenerationProvenance
    manifests: tuple[RegistryManifest, ...]

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        _require_provenance(self.provenance)
        if (
            type(self.manifests) is not tuple
            or len(self.manifests) != _PAIR_COUNT
            or any(type(manifest) is not RegistryManifest for manifest in self.manifests)
        ):
            raise TypeError("registry set must contain 50 exact manifests")
        expected = tuple(
            _expected_manifest(pair) for pair in self.provenance.corpus.pairs
        )
        for manifest in self.manifests:
            manifest.validate()
        if self.manifests != expected:
            raise ValueError("registry set differs from the generated corpus")
        digests = tuple(manifest.digest for manifest in self.manifests)
        if len(set(digests)) != _PAIR_COUNT:
            raise ValueError("registry set manifest digests must be unique")

    @property
    def manifest_digests(self) -> tuple[str, ...]:
        return tuple(manifest.digest for manifest in self.manifests)

    @property
    def registry_root(self) -> str:
        self.validate()
        return canonical_digest(
            REGISTRY_SET_FORMAT,
            {
                "format": REGISTRY_SET_FORMAT,
                "manifest_digests": self.manifest_digests,
                "protocol_id": PROTOCOL_ID,
                "source_root": self.provenance.source_root,
            },
        )

    def to_jsonl(self) -> bytes:
        self.validate()
        return _encode_jsonl(
            tuple(manifest.to_payload() for manifest in self.manifests),
            maximum=_MAX_REGISTRY_JSONL_BYTES,
        )

    @classmethod
    def from_jsonl(
        cls,
        payload: bytes,
        provenance: Workspace100GenerationProvenance,
    ) -> Workspace100RegistrySet:
        _require_provenance(provenance)
        lines = _parse_jsonl(
            payload,
            expected_count=_PAIR_COUNT,
            label="Workspace-100 registries",
            maximum=_MAX_REGISTRY_JSONL_BYTES,
            line_maximum=_MAX_REGISTRY_LINE_BYTES,
        )
        manifests = tuple(
            RegistryManifest.from_canonical_bytes(
                canonical_json(cast(JsonValue, line))
            )
            for line in lines
        )
        registry_set = cls(provenance=provenance, manifests=manifests)
        if registry_set.to_jsonl() != payload:
            raise ValueError("Workspace-100 registries failed canonical JSONL round-trip")
        return registry_set


@dataclass(frozen=True, slots=True)
class Workspace100TrustAnchorSet:
    """Externally supplied anchors aligned one-for-one with a registry set."""

    registry_set: Workspace100RegistrySet
    anchors: tuple[VerificationTrustAnchor, ...]

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if type(self.registry_set) is not Workspace100RegistrySet:
            raise TypeError("trust-anchor set requires an exact registry set")
        self.registry_set.validate()
        if (
            type(self.anchors) is not tuple
            or len(self.anchors) != _PAIR_COUNT
            or any(type(anchor) is not VerificationTrustAnchor for anchor in self.anchors)
        ):
            raise TypeError("trust-anchor set must contain 50 exact anchors")
        current_verifier = verifier_implementation_digest()
        for manifest, anchor in zip(
            self.registry_set.manifests,
            self.anchors,
            strict=True,
        ):
            anchor.validate()
            if (
                anchor.registry_digest != manifest.digest
                or anchor.adapter_implementation_digest
                != manifest.adapter_implementation_digest
                or anchor.verifier_implementation_digest != current_verifier
            ):
                raise ValueError("trust anchor is not aligned with its exact registry")
        if len({anchor.digest for anchor in self.anchors}) != _PAIR_COUNT:
            raise ValueError("trust-anchor set digests must be unique")

    @property
    def trust_anchor_root(self) -> str:
        self.validate()
        return canonical_digest(
            TRUST_ANCHOR_SET_FORMAT,
            {
                "anchor_digests": tuple(anchor.digest for anchor in self.anchors),
                "format": TRUST_ANCHOR_SET_FORMAT,
                "protocol_id": PROTOCOL_ID,
                "registry_root": self.registry_set.registry_root,
            },
        )

    def to_jsonl(self) -> bytes:
        self.validate()
        return _encode_jsonl(
            tuple(anchor.to_payload() for anchor in self.anchors),
            maximum=_MAX_ANCHOR_JSONL_BYTES,
        )

    @classmethod
    def from_jsonl(
        cls,
        payload: bytes,
        registry_set: Workspace100RegistrySet,
    ) -> Workspace100TrustAnchorSet:
        if type(registry_set) is not Workspace100RegistrySet:
            raise TypeError("trust-anchor parsing requires an exact registry set")
        lines = _parse_jsonl(
            payload,
            expected_count=_PAIR_COUNT,
            label="Workspace-100 trust anchors",
            maximum=_MAX_ANCHOR_JSONL_BYTES,
            line_maximum=_MAX_ANCHOR_LINE_BYTES,
        )
        anchors = tuple(
            VerificationTrustAnchor.from_canonical_bytes(
                canonical_json(cast(JsonValue, line))
            )
            for line in lines
        )
        anchor_set = cls(registry_set=registry_set, anchors=anchors)
        if anchor_set.to_jsonl() != payload:
            raise ValueError("Workspace-100 trust anchors failed canonical JSONL round-trip")
        return anchor_set


@dataclass(frozen=True, slots=True)
class Workspace100VerifiedMaterialSet:
    """Full replay/probe material for all one hundred sealed completions."""

    registry_set: Workspace100RegistrySet
    materials: tuple[VerifiedPairMaterial, ...]

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if type(self.registry_set) is not Workspace100RegistrySet:
            raise TypeError("verified-material set requires an exact registry set")
        self.registry_set.validate()
        if (
            type(self.materials) is not tuple
            or len(self.materials) != _PAIR_COUNT
            or any(type(material) is not VerifiedPairMaterial for material in self.materials)
        ):
            raise TypeError("verified-material set must contain 50 exact pair materials")
        corpus = self.registry_set.provenance.corpus
        for index, (pair, manifest, material) in enumerate(
            zip(corpus.pairs, self.registry_set.manifests, self.materials, strict=True)
        ):
            material.validate()
            if (
                material.pair_id,
                material.task_id,
                material.template_id,
                material.split,
                material.manifest,
            ) != (
                pair.pair_id,
                pair.task_id,
                pair.template_id,
                pair.split,
                manifest,
            ):
                raise ValueError(
                    f"verified pair material {index} contradicts corpus or registry metadata"
                )
            for generated, verified in zip(
                pair.completions,
                material.completions,
                strict=True,
            ):
                if (
                    verified.episode_id,
                    verified.panel.completion_commitment,
                    verified.panel.source_snapshot_digest,
                ) != (
                    generated.episode_id,
                    generated.completion_commitment,
                    generated.source.snapshot_digest,
                ):
                    raise ValueError(
                        "verified completion material contradicts its source opening"
                    )
        completions = tuple(
            completion
            for material in self.materials
            for completion in material.completions
        )
        if len(completions) != _COMPLETION_COUNT:
            raise ValueError("verified-material set has the wrong completion count")
        if sum(len(completion.panel.receipts) for completion in completions) != (
            _COMPLETION_COUNT * _RECEIPTS_PER_PANEL
        ):
            raise ValueError("verified-material set has the wrong replay receipt count")
        if sum(len(completion.probes) for completion in completions) != (
            _COMPLETION_COUNT * _PROBES_PER_COMPLETION
        ):
            raise ValueError("verified-material set has the wrong probe receipt count")

    @property
    def material_digests(self) -> tuple[str, ...]:
        return tuple(
            _material_record_digest(_material_body(index, material))
            for index, material in enumerate(self.materials)
        )

    @property
    def verified_material_root(self) -> str:
        self.validate()
        return canonical_digest(
            VERIFIED_MATERIAL_SET_FORMAT,
            {
                "format": VERIFIED_MATERIAL_SET_FORMAT,
                "material_digests": self.material_digests,
                "protocol_id": PROTOCOL_ID,
                "registry_root": self.registry_set.registry_root,
                "source_root": self.registry_set.provenance.source_root,
            },
        )

    @property
    def panel_root(self) -> str:
        """Gate-17 panel root, committing full replay and probe bytes."""

        return self.verified_material_root

    def to_jsonl(self) -> bytes:
        self.validate()
        payloads = tuple(
            {
                **_material_body(index, material),
                "material_digest": _material_record_digest(
                    _material_body(index, material)
                ),
            }
            for index, material in enumerate(self.materials)
        )
        return _encode_jsonl(payloads, maximum=_MAX_MATERIAL_JSONL_BYTES)

    @classmethod
    def from_jsonl(
        cls,
        payload: bytes,
        registry_set: Workspace100RegistrySet,
    ) -> Workspace100VerifiedMaterialSet:
        if type(registry_set) is not Workspace100RegistrySet:
            raise TypeError("verified-material parsing requires an exact registry set")
        lines = _parse_jsonl(
            payload,
            expected_count=_PAIR_COUNT,
            label="Workspace-100 verified materials",
            maximum=_MAX_MATERIAL_JSONL_BYTES,
            line_maximum=_MAX_MATERIAL_LINE_BYTES,
        )
        materials = tuple(
            _parse_material_record(line, index=index)
            for index, line in enumerate(lines)
        )
        material_set = cls(registry_set=registry_set, materials=materials)
        if material_set.to_jsonl() != payload:
            raise ValueError(
                "Workspace-100 verified materials failed canonical JSONL round-trip"
            )
        return material_set


def workspace100_public_evidence_views_jsonl(
    material_set: Workspace100VerifiedMaterialSet,
) -> bytes:
    """Project and encode the 300 exact public cases from authenticated material."""

    views = _public_evidence_views_for_materials(material_set)
    if any(type(case) is not PublicEvidenceCase for case in views.cases):
        raise TypeError("Workspace-100 public evidence requires exact evidence cases")
    return _encode_jsonl(
        tuple(case.root_payload() for case in views.cases),
        maximum=_MAX_PUBLIC_EVIDENCE_JSONL_BYTES,
        line_maximum=_MAX_PUBLIC_EVIDENCE_LINE_BYTES,
    )


def load_workspace100_public_evidence_views(
    payload: bytes,
    material_set: Workspace100VerifiedMaterialSet,
) -> Workspace100EvidenceViews:
    """Load cases only when they equal the deterministic material projection."""

    lines = _parse_jsonl(
        payload,
        expected_count=_EVIDENCE_CASE_COUNT,
        label="Workspace-100 public evidence views",
        maximum=_MAX_PUBLIC_EVIDENCE_JSONL_BYTES,
        line_maximum=_MAX_PUBLIC_EVIDENCE_LINE_BYTES,
    )
    expected = _public_evidence_views_for_materials(material_set)
    expected_payloads = tuple(case.root_payload() for case in expected.cases)
    for index, (line, expected_payload) in enumerate(
        zip(lines, expected_payloads, strict=True)
    ):
        _require_closed_fields(
            line,
            {
                "evidence",
                "evidence_digest",
                "format",
                "split",
                "template_id",
                "view",
            },
            label=f"Workspace-100 public evidence case {index}",
        )
        if line["format"] != PUBLIC_EVIDENCE_CASE_FORMAT:
            raise ValueError("Workspace-100 public evidence case format is unsupported")
        _require_payload_matches(
            line,
            expected_payload,
            label=f"Workspace-100 public evidence case {index}",
        )
    if workspace100_public_evidence_views_jsonl(material_set) != payload:
        raise ValueError(
            "Workspace-100 public evidence views failed canonical JSONL round-trip"
        )
    return expected


def _public_evidence_views_for_materials(
    material_set: Workspace100VerifiedMaterialSet,
) -> Workspace100EvidenceViews:
    if type(material_set) is not Workspace100VerifiedMaterialSet:
        raise TypeError("public-evidence projection requires an exact verified-material set")
    material_set.validate()
    views = workspace100_views._project_verified_materials(material_set.materials)
    if type(views) is not Workspace100EvidenceViews:
        raise TypeError("public-evidence projection returned an inexact view set")
    views.validate()
    return views


def workspace100_source_root(corpus: Workspace100Corpus) -> str:
    """Return the frozen corpus root used by truth and gate 17."""

    if type(corpus) is not Workspace100Corpus:
        raise TypeError("source root requires an exact Workspace100Corpus")
    corpus.validate()
    return corpus.root


def workspace100_source_opening_root(corpus: Workspace100Corpus) -> str:
    """Bind all exact source-opening records in pair/completion order."""

    if type(corpus) is not Workspace100Corpus:
        raise TypeError("source-opening root requires an exact Workspace100Corpus")
    corpus.validate()
    entries = _source_entry_payloads(corpus)
    return canonical_digest(
        SOURCE_OPENING_SET_FORMAT,
        {
            "entry_digests": tuple(
                _required_digest(
                    cast(dict[str, object], entry),
                    "source_opening_digest",
                )
                for entry in entries
            ),
            "format": SOURCE_OPENING_SET_FORMAT,
            "protocol_id": PROTOCOL_ID,
        },
    )


def workspace100_source_openings_jsonl(
    provenance: Workspace100GenerationProvenance,
) -> bytes:
    """Serialize all source openings regenerated from one exact provenance seed."""

    _require_provenance(provenance)
    payload = _encode_jsonl(
        _source_entry_payloads(provenance.corpus),
        maximum=_MAX_SOURCE_JSONL_BYTES,
    )
    if (
        workspace100_source_root(provenance.corpus) != provenance.source_root
        or workspace100_source_opening_root(provenance.corpus)
        != provenance.source_opening_root
    ):
        raise ValueError("source serialization changed a provenance source identity")
    return payload


def load_workspace100_source_openings(
    payload: bytes,
    provenance: Workspace100GenerationProvenance,
) -> Workspace100Corpus:
    """Parse source JSONL and require exact regeneration from the provenance seed."""

    _require_provenance(provenance)
    lines = _parse_jsonl(
        payload,
        expected_count=_COMPLETION_COUNT,
        label="Workspace-100 source openings",
        maximum=_MAX_SOURCE_JSONL_BYTES,
        line_maximum=_MAX_SOURCE_LINE_BYTES,
    )
    expected_corpus = provenance.corpus
    expected_entries = _source_entry_payloads(expected_corpus)
    seen_episodes: set[str] = set()
    seen_commitments: set[str] = set()
    for position, (raw, expected) in enumerate(
        zip(lines, expected_entries, strict=True)
    ):
        _parse_source_entry(raw, expected_position=position)
        episode_id = _required_string(raw, "episode_id")
        commitment = _required_digest(raw, "completion_commitment")
        if episode_id in seen_episodes or commitment in seen_commitments:
            raise ValueError("source openings contain a duplicate identity")
        seen_episodes.add(episode_id)
        seen_commitments.add(commitment)
        _require_payload_matches(raw, expected, label="Workspace-100 source opening")
    expected_bytes = _encode_jsonl(
        expected_entries,
        maximum=_MAX_SOURCE_JSONL_BYTES,
    )
    if expected_bytes != payload:
        raise ValueError("source openings differ from exact seed regeneration")
    if (
        workspace100_source_root(expected_corpus) != provenance.source_root
        or workspace100_source_opening_root(expected_corpus)
        != provenance.source_opening_root
    ):
        raise ValueError("regenerated source identities contradict provenance")
    return expected_corpus


def _source_entry_payloads(
    corpus: Workspace100Corpus,
) -> tuple[dict[str, JsonValue], ...]:
    entries: list[dict[str, JsonValue]] = []
    for pair_index, pair in enumerate(corpus.pairs):
        for completion_index, completion in enumerate(pair.completions):
            body: dict[str, JsonValue] = {
                "commitment_salt_hex": completion.source.commitment_salt.hex(),
                "completion_commitment": completion.completion_commitment,
                "completion_index": completion_index,
                "episode_id": completion.episode_id,
                "format": SOURCE_OPENING_FORMAT,
                "pair_id": pair.pair_id,
                "pair_index": pair_index,
                "protocol_id": PROTOCOL_ID,
                "source_bytes_hex": completion.source.source_bytes.hex(),
                "source_snapshot_digest": completion.source.snapshot_digest,
                "task_id": pair.task_id,
                "template_id": pair.template_id.value,
                "variant_id": pair.variant_id,
            }
            entries.append(
                {
                    **body,
                    "source_opening_digest": canonical_digest(
                        SOURCE_OPENING_FORMAT,
                        body,
                    ),
                }
            )
    if len(entries) != _COMPLETION_COUNT:
        raise ValueError("source opening serialization did not cover 100 completions")
    return tuple(entries)


def _parse_source_entry(
    raw: dict[str, object],
    *,
    expected_position: int,
) -> None:
    _require_closed_fields(
        raw,
        {
            "commitment_salt_hex",
            "completion_commitment",
            "completion_index",
            "episode_id",
            "format",
            "pair_id",
            "pair_index",
            "protocol_id",
            "source_bytes_hex",
            "source_opening_digest",
            "source_snapshot_digest",
            "task_id",
            "template_id",
            "variant_id",
        },
        label="Workspace-100 source opening",
    )
    if raw["format"] != SOURCE_OPENING_FORMAT or raw["protocol_id"] != PROTOCOL_ID:
        raise ValueError("Workspace-100 source opening identity is unsupported")
    expected_pair_index, expected_completion_index = divmod(expected_position, 2)
    if (
        _required_int(raw, "pair_index") != expected_pair_index
        or _required_int(raw, "completion_index") != expected_completion_index
    ):
        raise ValueError("Workspace-100 source openings are reordered")
    source_bytes = _required_hex_bytes(
        raw,
        "source_bytes_hex",
        maximum_bytes=1 << 20,
    )
    salt = _required_hex_bytes(
        raw,
        "commitment_salt_hex",
        exact_bytes=32,
    )
    source = SealedWorldSource(source_bytes=source_bytes, commitment_salt=salt)
    if (
        _required_digest(raw, "source_snapshot_digest") != source.snapshot_digest
        or _required_digest(raw, "completion_commitment")
        != source.completion_commitment
    ):
        raise ValueError("source opening digest fields contradict its exact bytes")
    body = dict(raw)
    stored_digest = _required_digest(body, "source_opening_digest")
    del body["source_opening_digest"]
    if canonical_digest(
        SOURCE_OPENING_FORMAT,
        cast(dict[str, JsonValue], body),
    ) != stored_digest:
        raise ValueError("source opening digest contradicts its record")


def _expected_manifest(pair: GeneratedPair) -> RegistryManifest:
    worlds = workspace100_pair_worlds(pair)
    first, _second = worlds
    declarations = tuple(
        (
            world.task_schema_id,
            world.task_id,
            world.source_format_id,
            world.adapter_id,
            world.adapter_implementation_digest,
            world.atoms,
            world.intervention_contract_digest,
            world.probe_names,
            world.probe_contract_digest,
            world.runner_contract_digest,
            world.artifact_validator_contract_digest,
            world.success_oracle_contract_digest,
            world.state_access_contract_digest,
            world.declared_state_channels,
        )
        for world in worlds
    )
    if declarations[0] != declarations[1]:
        raise ValueError("generated pair worlds disagree on their registry declaration")
    commitments = tuple(world.completion_commitment for world in worlds)
    return RegistryManifest(
        task_schema_id=first.task_schema_id,
        task_id=first.task_id,
        source_format_id=first.source_format_id,
        adapter_id=first.adapter_id,
        adapter_implementation_digest=first.adapter_implementation_digest,
        atoms=first.atoms,
        intervention_contract_digest=first.intervention_contract_digest,
        probe_names=first.probe_names,
        probe_contract_digest=first.probe_contract_digest,
        runner_contract_digest=first.runner_contract_digest,
        artifact_validator_contract_digest=(
            first.artifact_validator_contract_digest
        ),
        success_oracle_contract_digest=first.success_oracle_contract_digest,
        state_access_contract_digest=first.state_access_contract_digest,
        declared_state_channels=first.declared_state_channels,
        candidate_commitments=commitments,
    )


def _material_body(
    pair_index: int,
    material: VerifiedPairMaterial,
) -> dict[str, JsonValue]:
    material.validate()
    return {
        "completions": tuple(
            _completion_payload(completion)
            for completion in material.completions
        ),
        "format": VERIFIED_MATERIAL_FORMAT,
        "manifest": material.manifest.to_payload(),
        "manifest_digest": material.manifest.digest,
        "pair_id": material.pair_id,
        "pair_index": pair_index,
        "protocol_id": PROTOCOL_ID,
        "split": material.split.value,
        "task_id": material.task_id,
        "template_id": material.template_id.value,
    }


def _material_record_digest(payload: dict[str, JsonValue]) -> str:
    return canonical_digest(VERIFIED_MATERIAL_FORMAT, payload)


def _completion_payload(
    completion: VerifiedCompletionMaterial,
) -> dict[str, JsonValue]:
    completion.validate()
    body: dict[str, JsonValue] = {
        "episode_id": completion.episode_id,
        "format": VERIFIED_COMPLETION_FORMAT,
        "panel": _panel_payload(completion.panel),
        "probes": tuple(_probe_payload(probe) for probe in completion.probes),
    }
    return {
        **body,
        "completion_material_digest": canonical_digest(
            VERIFIED_COMPLETION_FORMAT,
            body,
        ),
    }


def _panel_payload(panel: VerifiedPanel) -> dict[str, JsonValue]:
    body: dict[str, JsonValue] = {
        "adapter_implementation_digest": panel.adapter_implementation_digest,
        "artifact_validator_contract_digest": (
            panel.artifact_validator_contract_digest
        ),
        "atom_names": panel.atom_names,
        "completion_commitment": panel.completion_commitment,
        "format": VERIFIED_PANEL_STORAGE_FORMAT,
        "minimal_witnesses": panel.minimal_witnesses,
        "receipts": tuple(_receipt_payload(receipt) for receipt in panel.receipts),
        "runner_contract_digest": panel.runner_contract_digest,
        "source_snapshot_digest": panel.source_snapshot_digest,
        "state_access_contract_digest": panel.state_access_contract_digest,
        "success_oracle_contract_digest": panel.success_oracle_contract_digest,
        "target_family": panel.target_family,
    }
    return {**body, "panel_digest": panel.digest}


def _receipt_payload(receipt: VerifiedReceipt) -> dict[str, JsonValue]:
    return {
        "artifact": _artifact_payload(receipt.artifact),
        "format": VERIFIED_RECEIPT_STORAGE_FORMAT,
        "interventions": receipt.interventions,
        "outcome": receipt.outcome.value,
        "receipt_digest": receipt.digest,
    }


def _artifact_payload(artifact: ExecutionArtifact) -> dict[str, JsonValue]:
    artifact.validate()
    return {
        "format": EXECUTION_ARTIFACT_STORAGE_FORMAT,
        "intervention_log": artifact.intervention_log,
        "public_trace_hex": artifact.public_trace.hex(),
        "source_snapshot_digest": artifact.source_snapshot_digest,
        "state_read_log": tuple(
            {
                "channel": read.channel,
                "sequence": read.sequence,
                "value_digest": read.value_digest,
            }
            for read in artifact.state_read_log
        ),
        "terminal_state_hex": artifact.terminal_state.hex(),
    }


def _probe_payload(receipt: VerifiedProbeReceipt) -> dict[str, JsonValue]:
    return {
        "adapter_implementation_digest": receipt.adapter_implementation_digest,
        "completion_commitment": receipt.completion_commitment,
        "format": VERIFIED_PROBE_STORAGE_FORMAT,
        "name": receipt.name,
        "probe_contract_digest": receipt.probe_contract_digest,
        "probe_digest": receipt.digest,
        "source_snapshot_digest": receipt.source_snapshot_digest,
        "value_hex": receipt.value.hex(),
    }


def _parse_material_record(
    raw: dict[str, object],
    *,
    index: int,
) -> VerifiedPairMaterial:
    _require_closed_fields(
        raw,
        {
            "completions",
            "format",
            "manifest",
            "manifest_digest",
            "material_digest",
            "pair_id",
            "pair_index",
            "protocol_id",
            "split",
            "task_id",
            "template_id",
        },
        label="verified pair material",
    )
    if raw["format"] != VERIFIED_MATERIAL_FORMAT or raw["protocol_id"] != PROTOCOL_ID:
        raise ValueError("verified pair material identity is unsupported")
    if _required_int(raw, "pair_index") != index:
        raise ValueError("verified pair materials are reordered")
    manifest = RegistryManifest.from_canonical_bytes(
        canonical_json(cast(JsonValue, raw["manifest"]))
    )
    if _required_digest(raw, "manifest_digest") != manifest.digest:
        raise ValueError("verified pair material manifest digest is inconsistent")
    completions_raw = _required_array(raw, "completions")
    if len(completions_raw) != _PAIR_SIZE:
        raise ValueError("verified pair material must contain two completions")
    completions = tuple(
        _parse_completion(value) for value in completions_raw
    )
    body = dict(raw)
    stored_digest = _required_digest(body, "material_digest")
    del body["material_digest"]
    if _material_record_digest(
        cast(dict[str, JsonValue], body)
    ) != stored_digest:
        raise ValueError("verified pair material digest is inconsistent")
    try:
        template_id = TemplateId(_required_string(raw, "template_id"))
        split = Split(_required_string(raw, "split"))
    except ValueError as error:
        raise ValueError("verified pair material enum is unsupported") from error
    return VerifiedPairMaterial(
        pair_id=_required_string(raw, "pair_id"),
        task_id=_required_string(raw, "task_id"),
        template_id=template_id,
        split=split,
        manifest=manifest,
        completions=(completions[0], completions[1]),
    )


def _parse_completion(value: object) -> VerifiedCompletionMaterial:
    raw = _closed_object(
        value,
        {
            "completion_material_digest",
            "episode_id",
            "format",
            "panel",
            "probes",
        },
        label="verified completion material",
    )
    if raw["format"] != VERIFIED_COMPLETION_FORMAT:
        raise ValueError("verified completion material format is unsupported")
    probes_raw = _required_array(raw, "probes")
    if len(probes_raw) != _PROBES_PER_COMPLETION:
        raise ValueError("verified completion material must contain two probes")
    panel = _parse_panel(raw["panel"])
    probes = tuple(_parse_probe(value) for value in probes_raw)
    body = dict(raw)
    stored_digest = _required_digest(body, "completion_material_digest")
    del body["completion_material_digest"]
    if canonical_digest(
        VERIFIED_COMPLETION_FORMAT,
        cast(dict[str, JsonValue], body),
    ) != stored_digest:
        raise ValueError("verified completion material digest is inconsistent")
    return VerifiedCompletionMaterial(
        episode_id=_required_string(raw, "episode_id"),
        panel=panel,
        probes=probes,
    )


def _parse_panel(value: object) -> VerifiedPanel:
    raw = _closed_object(
        value,
        {
            "adapter_implementation_digest",
            "artifact_validator_contract_digest",
            "atom_names",
            "completion_commitment",
            "format",
            "minimal_witnesses",
            "panel_digest",
            "receipts",
            "runner_contract_digest",
            "source_snapshot_digest",
            "state_access_contract_digest",
            "success_oracle_contract_digest",
            "target_family",
        },
        label="verified panel",
    )
    if raw["format"] != VERIFIED_PANEL_STORAGE_FORMAT:
        raise ValueError("verified panel storage format is unsupported")
    receipts_raw = _required_array(raw, "receipts")
    if len(receipts_raw) != _RECEIPTS_PER_PANEL:
        raise ValueError("verified panel must contain four receipts")
    panel = VerifiedPanel(
        completion_commitment=_required_digest(raw, "completion_commitment"),
        source_snapshot_digest=_required_digest(raw, "source_snapshot_digest"),
        adapter_implementation_digest=_required_digest(
            raw,
            "adapter_implementation_digest",
        ),
        runner_contract_digest=_required_digest(raw, "runner_contract_digest"),
        artifact_validator_contract_digest=_required_digest(
            raw,
            "artifact_validator_contract_digest",
        ),
        success_oracle_contract_digest=_required_digest(
            raw,
            "success_oracle_contract_digest",
        ),
        state_access_contract_digest=_required_digest(
            raw,
            "state_access_contract_digest",
        ),
        atom_names=_required_string_tuple(raw, "atom_names"),
        receipts=tuple(_parse_receipt(receipt) for receipt in receipts_raw),
        minimal_witnesses=_parse_witnesses(raw["minimal_witnesses"]),
        target_family=_parse_target_family(raw["target_family"]),
    )
    if _required_digest(raw, "panel_digest") != panel.digest:
        raise ValueError("verified panel digest is inconsistent")
    return panel


def _parse_receipt(value: object) -> VerifiedReceipt:
    raw = _closed_object(
        value,
        {
            "artifact",
            "format",
            "interventions",
            "outcome",
            "receipt_digest",
        },
        label="verified receipt",
    )
    if raw["format"] != VERIFIED_RECEIPT_STORAGE_FORMAT:
        raise ValueError("verified receipt storage format is unsupported")
    try:
        outcome = Outcome(_required_string(raw, "outcome"))
    except ValueError as error:
        raise ValueError("verified receipt outcome is unsupported") from error
    receipt = VerifiedReceipt(
        interventions=_parse_witness(raw["interventions"]),
        artifact=_parse_artifact(raw["artifact"]),
        outcome=outcome,
    )
    if _required_digest(raw, "receipt_digest") != receipt.digest:
        raise ValueError("verified receipt digest is inconsistent")
    return receipt


def _parse_artifact(value: object) -> ExecutionArtifact:
    raw = _closed_object(
        value,
        {
            "format",
            "intervention_log",
            "public_trace_hex",
            "source_snapshot_digest",
            "state_read_log",
            "terminal_state_hex",
        },
        label="execution artifact",
    )
    if raw["format"] != EXECUTION_ARTIFACT_STORAGE_FORMAT:
        raise ValueError("execution artifact storage format is unsupported")
    reads_raw = _required_array(raw, "state_read_log")
    if len(reads_raw) > _MAX_STATE_READS:
        raise ValueError("execution artifact contains too many state reads")
    reads: list[StateRead] = []
    for item in reads_raw:
        read = _closed_object(
            item,
            {"channel", "sequence", "value_digest"},
            label="execution artifact state read",
        )
        reads.append(
            StateRead(
                sequence=_required_int(read, "sequence"),
                channel=_required_string(read, "channel"),
                value_digest=_required_digest(read, "value_digest"),
            )
        )
    intervention_log = _required_string_tuple(raw, "intervention_log")
    if len(intervention_log) > _MAX_INTERVENTIONS:
        raise ValueError("execution artifact contains too many interventions")
    return ExecutionArtifact(
        source_snapshot_digest=_required_digest(raw, "source_snapshot_digest"),
        public_trace=_required_hex_bytes(
            raw,
            "public_trace_hex",
            maximum_bytes=_MAX_ARTIFACT_BYTES,
        ),
        terminal_state=_required_hex_bytes(
            raw,
            "terminal_state_hex",
            maximum_bytes=_MAX_ARTIFACT_BYTES,
        ),
        state_read_log=tuple(reads),
        intervention_log=intervention_log,
    )


def _parse_probe(value: object) -> VerifiedProbeReceipt:
    raw = _closed_object(
        value,
        {
            "adapter_implementation_digest",
            "completion_commitment",
            "format",
            "name",
            "probe_contract_digest",
            "probe_digest",
            "source_snapshot_digest",
            "value_hex",
        },
        label="verified probe receipt",
    )
    if raw["format"] != VERIFIED_PROBE_STORAGE_FORMAT:
        raise ValueError("verified probe storage format is unsupported")
    receipt = VerifiedProbeReceipt(
        completion_commitment=_required_digest(raw, "completion_commitment"),
        source_snapshot_digest=_required_digest(raw, "source_snapshot_digest"),
        adapter_implementation_digest=_required_digest(
            raw,
            "adapter_implementation_digest",
        ),
        probe_contract_digest=_required_digest(raw, "probe_contract_digest"),
        name=_required_string(raw, "name"),
        value=_required_hex_bytes(
            raw,
            "value_hex",
            maximum_bytes=_MAX_PROBE_BYTES,
        ),
    )
    if _required_digest(raw, "probe_digest") != receipt.digest:
        raise ValueError("verified probe receipt digest is inconsistent")
    return receipt


def _parse_witness(value: object) -> Witness:
    if type(value) is not list or any(type(item) is not str for item in value):
        raise TypeError("witness must be an exact JSON string array")
    witness = tuple(cast(list[str], value))
    if len(witness) > _MAX_INTERVENTIONS or tuple(sorted(set(witness))) != witness:
        raise ValueError("witness must be unique, sorted, and bounded")
    return witness


def _parse_witnesses(value: object) -> tuple[Witness, ...]:
    if type(value) is not list:
        raise TypeError("minimal witnesses must be an exact JSON array")
    witnesses = tuple(_parse_witness(item) for item in value)
    if tuple(sorted(set(witnesses))) != witnesses:
        raise ValueError("minimal witnesses must be unique and sorted")
    return witnesses


def _parse_target_family(value: object) -> TargetFamily:
    if type(value) is not list:
        raise TypeError("target family must be an exact JSON array")
    family = tuple(_parse_witness(item) for item in value)
    if tuple(sorted(set(family))) != family:
        raise ValueError("target family must be unique and sorted")
    return family


def _require_provenance(value: object) -> None:
    if type(value) is not Workspace100GenerationProvenance:
        raise TypeError("operation requires exact generation provenance")
    value.__post_init__()


def _encode_jsonl(
    payloads: tuple[dict[str, JsonValue], ...],
    *,
    maximum: int,
    line_maximum: int | None = None,
) -> bytes:
    if type(payloads) is not tuple:
        raise TypeError("canonical JSONL construction requires an exact tuple")
    lines = tuple(canonical_json(payload) for payload in payloads)
    if any(
        not line
        or not line.endswith(b"\n")
        or line.count(b"\n") != 1
        or b"\r" in line
        for line in lines
    ):
        raise ValueError("canonical JSONL lines must be LF-terminated single-line JSON")
    if line_maximum is not None and any(
        len(line) > line_maximum for line in lines
    ):
        raise ValueError("canonical JSONL line exceeds its byte bound")
    payload = b"".join(lines)
    if not payload or len(payload) > maximum:
        raise ValueError("canonical JSONL payload exceeds its byte bound")
    return payload


def _parse_jsonl(
    payload: object,
    *,
    expected_count: int,
    label: str,
    maximum: int,
    line_maximum: int,
) -> tuple[dict[str, object], ...]:
    if type(payload) is not bytes:
        raise TypeError(f"{label} payload must be exact bytes")
    if not payload or len(payload) > maximum:
        raise ValueError(f"{label} payload exceeds its byte bound")
    if b"\r" in payload or not payload.endswith(b"\n"):
        raise ValueError(f"{label} must use canonical LF-terminated JSONL")
    encoded_lines = payload[:-1].split(b"\n")
    if (
        len(encoded_lines) != expected_count
        or any(
            not line or len(line) + 1 > line_maximum
            for line in encoded_lines
        )
    ):
        raise ValueError(f"{label} has the wrong line count or line size")
    return tuple(
        _canonical_object(
            line + b"\n",
            label=f"{label} line",
            maximum=line_maximum,
        )
        for line in encoded_lines
    )


def _canonical_object(
    payload: object,
    *,
    label: str,
    maximum: int,
) -> dict[str, object]:
    if type(payload) is not bytes:
        raise TypeError(f"{label} payload must be exact bytes")
    if not payload or len(payload) > maximum:
        raise ValueError(f"{label} payload exceeds its byte bound")
    try:
        raw: object = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from error
    try:
        canonical = (
            type(raw) is dict
            and canonical_json(cast(JsonValue, raw)) == payload
        )
    except (RecursionError, TypeError, ValueError) as error:
        raise ValueError(f"{label} contains unsupported JSON") from error
    if not canonical:
        raise ValueError(f"{label} is not one canonical JSON object")
    return cast(dict[str, object], raw)


def _closed_object(
    value: object,
    fields: set[str],
    *,
    label: str,
) -> dict[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise ValueError(f"{label} contains unknown or missing fields")
    return cast(dict[str, object], value)


def _require_closed_fields(
    raw: dict[str, object],
    fields: set[str],
    *,
    label: str,
) -> None:
    if set(raw) != fields:
        raise ValueError(f"{label} contains unknown or missing fields")


def _required_array(raw: dict[str, object], field: str) -> list[object]:
    value = raw.get(field)
    if type(value) is not list:
        raise TypeError(f"{field} must be an exact JSON array")
    return cast(list[object], value)


def _required_string(raw: dict[str, object], field: str) -> str:
    value = raw.get(field)
    if type(value) is not str:
        raise TypeError(f"{field} must be an exact string")
    return value


def _required_string_tuple(
    raw: dict[str, object],
    field: str,
) -> tuple[str, ...]:
    values = _required_array(raw, field)
    if any(type(value) is not str for value in values):
        raise TypeError(f"{field} must contain exact strings")
    return tuple(cast(list[str], values))


def _required_int(raw: dict[str, object], field: str) -> int:
    value = raw.get(field)
    if type(value) is not int:
        raise TypeError(f"{field} must be an exact integer")
    return value


def _required_digest(raw: dict[str, object], field: str) -> str:
    value = _required_string(raw, field)
    _require_digest_value(value, field=field)
    return value


def _require_digest_value(value: object, *, field: str) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{field} must be lowercase SHA-256")


def _required_hex_bytes(
    raw: dict[str, object],
    field: str,
    *,
    exact_bytes: int | None = None,
    maximum_bytes: int | None = None,
) -> bytes:
    value = _required_string(raw, field)
    if (
        len(value) % 2
        or (value and _LOWER_HEX.fullmatch(value) is None)
        or (not value and exact_bytes not in (None, 0))
    ):
        raise ValueError(f"{field} must be lowercase even-length hex")
    byte_count = len(value) // 2
    if exact_bytes is not None and byte_count != exact_bytes:
        raise ValueError(f"{field} has the wrong exact byte length")
    if maximum_bytes is not None and byte_count > maximum_bytes:
        raise ValueError(f"{field} exceeds its byte bound")
    return bytes.fromhex(value)


def _require_payload_matches(
    raw: dict[str, object],
    expected: dict[str, JsonValue],
    *,
    label: str,
) -> None:
    if canonical_json(cast(JsonValue, raw)) != canonical_json(expected):
        raise ValueError(f"{label} contradicts its deterministic derivation")


__all__ = [
    "CATALOG_SET_FORMAT",
    "GENERATION_PROVENANCE_FORMAT",
    "PROTOCOL_RECORD_FORMAT",
    "PUBLIC_EVIDENCE_CASE_FORMAT",
    "REGISTRY_SET_FORMAT",
    "SOURCE_OPENING_FORMAT",
    "SOURCE_OPENING_SET_FORMAT",
    "TEMPLATE_CATALOG_FORMAT",
    "TRUST_ANCHOR_SET_FORMAT",
    "VARIANT_CATALOG_FORMAT",
    "VERIFIED_MATERIAL_FORMAT",
    "VERIFIED_MATERIAL_SET_FORMAT",
    "Workspace100CatalogSet",
    "Workspace100GenerationProvenance",
    "Workspace100ProtocolRecord",
    "Workspace100RegistrySet",
    "Workspace100TrustAnchorSet",
    "Workspace100VerifiedMaterialSet",
    "load_workspace100_public_evidence_views",
    "load_workspace100_source_openings",
    "load_workspace100_template_catalog",
    "load_workspace100_variant_catalog",
    "workspace100_public_evidence_views_jsonl",
    "workspace100_source_opening_root",
    "workspace100_source_openings_jsonl",
    "workspace100_source_root",
    "workspace100_template_catalog_bytes",
    "workspace100_variant_catalog_bytes",
]
