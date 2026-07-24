"""Deterministic sealed-source generation for the authored Workspace-100 corpus."""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import cast

from witnessgap.canonical import JsonValue, canonical_digest
from witnessgap.source import SealedWorldSource
from witnessgap.workspace100.catalog import (
    TEMPLATES,
    VARIANTS,
    template_catalog_digest,
    validate_frozen_catalog,
    variant_catalog_digest,
)
from witnessgap.workspace100.records import (
    PROTOCOL_ID,
    SOURCE_FORMAT_ID,
    CompletionSourceRecord,
    ResolverBinding,
    Split,
    TemplateId,
    TemplateRecord,
    VariantRecord,
)

_SEED_BYTES = 32
_PAIR_SIZE = 2
_TEMPLATE_COUNT = 5
_VARIANT_COUNT = 50
_SOURCE_COUNT = 100
_ID_DIGEST_CHARACTERS = 24
_SALT_DOMAIN = b"witnessgap.workspace100-source-salt.v1\0"


@dataclass(frozen=True, slots=True)
class _InitialSourceState:
    selected_selector: str
    epoch_id: str
    resolver: tuple[ResolverBinding, ResolverBinding]


@dataclass(frozen=True, slots=True)
class GeneratedCompletion:
    """One opaque episode backed by an exact sealed source opening."""

    episode_id: str
    record: CompletionSourceRecord
    source: SealedWorldSource

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if type(self.record) is not CompletionSourceRecord:
            raise TypeError("generated completion record must be exact")
        self.record.validate()
        if type(self.source) is not SealedWorldSource:
            raise TypeError("generated completion source must be exact")
        self.source.validate()
        if self.source.source_bytes != self.record.to_canonical_bytes():
            raise ValueError("sealed source bytes contradict the completion record")
        expected_episode_id = _opaque_id("wge", self.source.completion_commitment)
        if type(self.episode_id) is not str or self.episode_id != expected_episode_id:
            raise ValueError("episode_id must derive from the completion commitment")

    @property
    def completion_commitment(self) -> str:
        return self.source.completion_commitment


@dataclass(frozen=True, slots=True)
class GeneratedPair:
    """Two commitment-ordered completions for one authored variant."""

    pair_id: str
    task_id: str
    template_id: TemplateId
    variant_id: str
    split: Split
    completions: tuple[GeneratedCompletion, GeneratedCompletion]

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if type(self.template_id) is not TemplateId:
            raise TypeError("generated pair template_id must be exact")
        if type(self.split) is not Split:
            raise TypeError("generated pair split must be exact")
        if type(self.task_id) is not str:
            raise TypeError("generated pair task_id must be an exact string")
        if type(self.variant_id) is not str:
            raise TypeError("generated pair variant_id must be an exact string")
        if (
            type(self.completions) is not tuple
            or len(self.completions) != _PAIR_SIZE
            or any(type(completion) is not GeneratedCompletion for completion in self.completions)
        ):
            raise TypeError("generated pair must contain two exact completions")
        for completion in self.completions:
            completion.validate()
            record = completion.record
            if (
                record.task_id != self.task_id
                or record.template_id is not self.template_id
                or record.variant_id != self.variant_id
            ):
                raise ValueError("generated completion identity contradicts its pair")
        records = tuple(completion.record for completion in self.completions)
        selector_aligned = tuple(
            record for record in records if record.selected_selector == record.goal_selector
        )
        resolver_aligned = tuple(
            record for record in records if record.selected_selector != record.goal_selector
        )
        if len(selector_aligned) != 1 or len(resolver_aligned) != 1:
            raise ValueError("generated pair must contain complementary twin source shapes")
        _validate_twin_construction(selector_aligned[0], resolver_aligned[0])
        commitments = cast(
            tuple[str, str],
            tuple(completion.completion_commitment for completion in self.completions),
        )
        if commitments != tuple(sorted(set(commitments))):
            raise ValueError("pair completions must have unique commitment order")
        expected_pair_id = _pair_id(commitments)
        if type(self.pair_id) is not str or self.pair_id != expected_pair_id:
            raise ValueError("pair_id must derive from both completion commitments")


@dataclass(frozen=True, slots=True)
class Workspace100Corpus:
    """In-memory authored corpus; no result, label, or evaluation artifact."""

    protocol_id: str
    templates: tuple[TemplateRecord, ...]
    variants: tuple[VariantRecord, ...]
    pairs: tuple[GeneratedPair, ...]

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if type(self.protocol_id) is not str or self.protocol_id != PROTOCOL_ID:
            raise ValueError(f"corpus protocol_id must equal {PROTOCOL_ID!r}")
        if (
            type(self.templates) is not tuple
            or len(self.templates) != _TEMPLATE_COUNT
            or any(type(record) is not TemplateRecord for record in self.templates)
        ):
            raise TypeError("corpus must contain five exact template records")
        if (
            type(self.variants) is not tuple
            or len(self.variants) != _VARIANT_COUNT
            or any(type(record) is not VariantRecord for record in self.variants)
        ):
            raise TypeError("corpus must contain 50 exact variant records")
        if (
            type(self.pairs) is not tuple
            or len(self.pairs) != _VARIANT_COUNT
            or any(type(pair) is not GeneratedPair for pair in self.pairs)
        ):
            raise TypeError("corpus must contain 50 exact generated pairs")
        validate_frozen_catalog(self.templates, self.variants)
        for pair in self.pairs:
            pair.validate()
        expected_keys = tuple(
            (variant.template_id, variant.variant_id) for variant in self.variants
        )
        actual_keys = tuple((pair.template_id, pair.variant_id) for pair in self.pairs)
        if actual_keys != expected_keys:
            raise ValueError("generated pair order differs from the authored catalog")
        template_splits = {template.template_id: template.split for template in self.templates}
        if any(pair.split is not template_splits[pair.template_id] for pair in self.pairs):
            raise ValueError("generated pair split contradicts its template")
        _validate_pairs_match_authored_catalog(self)
        _validate_global_generation_uniqueness(self)

    @property
    def completions(self) -> tuple[GeneratedCompletion, ...]:
        return tuple(completion for pair in self.pairs for completion in pair.completions)

    @property
    def sources(self) -> tuple[SealedWorldSource, ...]:
        return tuple(completion.source for completion in self.completions)

    def root_payload(self) -> dict[str, JsonValue]:
        """Return the deterministic manifest committed by ``root``."""

        self.validate()
        pair_entries: tuple[JsonValue, ...] = tuple(
            {
                "completion_commitments": tuple(
                    completion.completion_commitment for completion in pair.completions
                ),
                "pair_id": pair.pair_id,
                "source_snapshot_digests": tuple(
                    completion.source.snapshot_digest for completion in pair.completions
                ),
                "task_id": pair.task_id,
                "template_id": pair.template_id.value,
                "variant_id": pair.variant_id,
            }
            for pair in self.pairs
        )
        return {
            "format": "witnessgap.workspace100-corpus.v1",
            "pairs": pair_entries,
            "protocol_id": self.protocol_id,
            "template_catalog_digest": template_catalog_digest(self.templates),
            "variant_catalog_digest": variant_catalog_digest(self.variants),
        }

    @property
    def root(self) -> str:
        return canonical_digest(
            "witnessgap.workspace100-corpus.v1",
            self.root_payload(),
        )


def generate_workspace100(seed: bytes) -> Workspace100Corpus:
    """Generate all sealed sources from one explicit 32-byte release seed.

    The seed affects only salts and derived opaque IDs. Canonical source bytes
    depend exclusively on the authored catalog.
    """

    if type(seed) is not bytes:
        raise TypeError("Workspace-100 seed must be exact bytes")
    if len(seed) != _SEED_BYTES:
        raise ValueError(f"Workspace-100 seed must contain {_SEED_BYTES} bytes")
    validate_frozen_catalog(TEMPLATES, VARIANTS)
    templates_by_id = {template.template_id: template for template in TEMPLATES}
    pairs: list[GeneratedPair] = []
    for variant in VARIANTS:
        template = templates_by_id[variant.template_id]
        first_record, second_record = _completion_records(template, variant)
        _validate_twin_construction(first_record, second_record)
        completions = tuple(
            sorted(
                (
                    _seal_completion(first_record, seed),
                    _seal_completion(second_record, seed),
                ),
                key=lambda completion: completion.completion_commitment,
            )
        )
        typed_completions = cast(
            tuple[GeneratedCompletion, GeneratedCompletion],
            completions,
        )
        commitments = cast(
            tuple[str, str],
            tuple(completion.completion_commitment for completion in typed_completions),
        )
        pairs.append(
            GeneratedPair(
                pair_id=_pair_id(commitments),
                task_id=first_record.task_id,
                template_id=variant.template_id,
                variant_id=variant.variant_id,
                split=template.split,
                completions=typed_completions,
            )
        )
    return Workspace100Corpus(
        protocol_id=PROTOCOL_ID,
        templates=TEMPLATES,
        variants=VARIANTS,
        pairs=tuple(pairs),
    )


def construction_matrix(
    record: CompletionSourceRecord,
) -> tuple[str, str, str, str]:
    """Resolve baseline, refresh-only, repair-only, and combined states."""

    if type(record) is not CompletionSourceRecord:
        raise TypeError("construction matrix requires an exact source record")
    record.validate()
    return (
        _resolve_record(record, refresh=False, repair=False),
        _resolve_record(record, refresh=True, repair=False),
        _resolve_record(record, refresh=False, repair=True),
        _resolve_record(record, refresh=True, repair=True),
    )


def _completion_records(
    template: TemplateRecord,
    variant: VariantRecord,
) -> tuple[CompletionSourceRecord, CompletionSourceRecord]:
    task_id = _task_id(variant)
    reference_resolver = _resolver(
        ResolverBinding(
            selector=template.goal_selector,
            concrete_id=variant.intended_concrete_id,
        ),
        ResolverBinding(
            selector=template.alternate_selector,
            concrete_id=variant.observed_concrete_id,
        ),
    )
    alternate_resolver = _resolver(
        ResolverBinding(
            selector=template.goal_selector,
            concrete_id=variant.observed_concrete_id,
        ),
        ResolverBinding(
            selector=template.alternate_selector,
            concrete_id=variant.observed_concrete_id,
        ),
    )
    selector_aligned = _source_record(
        template,
        variant,
        task_id=task_id,
        initial_state=_InitialSourceState(
            selected_selector=template.goal_selector,
            epoch_id=variant.alternate_epoch_id,
            resolver=alternate_resolver,
        ),
        refresh_resolver=reference_resolver,
    )
    resolver_aligned = _source_record(
        template,
        variant,
        task_id=task_id,
        initial_state=_InitialSourceState(
            selected_selector=template.alternate_selector,
            epoch_id=variant.reference_epoch_id,
            resolver=reference_resolver,
        ),
        refresh_resolver=reference_resolver,
    )
    return selector_aligned, resolver_aligned


def _source_record(
    template: TemplateRecord,
    variant: VariantRecord,
    *,
    task_id: str,
    initial_state: _InitialSourceState,
    refresh_resolver: tuple[ResolverBinding, ResolverBinding],
) -> CompletionSourceRecord:
    return CompletionSourceRecord(
        protocol_id=PROTOCOL_ID,
        source_format_id=SOURCE_FORMAT_ID,
        task_schema_id=template.task_schema_id,
        task_id=task_id,
        template_id=variant.template_id,
        variant_id=variant.variant_id,
        workspace_slug=variant.workspace_slug,
        subject_id=variant.subject_id,
        subject_display=variant.subject_display,
        owner=variant.owner,
        public_task=variant.public_task,
        intended_concrete_id=variant.intended_concrete_id,
        intended_display=variant.intended_display,
        observed_concrete_id=variant.observed_concrete_id,
        observed_display=variant.observed_display,
        goal_selector=template.goal_selector,
        selected_selector=initial_state.selected_selector,
        initial_epoch_id=initial_state.epoch_id,
        initial_resolver=initial_state.resolver,
        refresh_epoch_id=variant.reference_epoch_id,
        refresh_resolver=refresh_resolver,
    )


def _seal_completion(
    record: CompletionSourceRecord,
    seed: bytes,
) -> GeneratedCompletion:
    source_bytes = record.to_canonical_bytes()
    if CompletionSourceRecord.from_canonical_bytes(source_bytes) != record:
        raise ValueError("completion source failed a closed canonical round-trip")
    salt = hmac.digest(seed, _SALT_DOMAIN + source_bytes, "sha256")
    source = SealedWorldSource(
        source_bytes=source_bytes,
        commitment_salt=salt,
    )
    return GeneratedCompletion(
        episode_id=_opaque_id("wge", source.completion_commitment),
        record=record,
        source=source,
    )


def _validate_twin_construction(
    selector_aligned: CompletionSourceRecord,
    resolver_aligned: CompletionSourceRecord,
) -> None:
    if _shared_source_payload(selector_aligned) != _shared_source_payload(resolver_aligned):
        raise ValueError("twin sources do not share one authored task declaration")
    intended = selector_aligned.intended_concrete_id
    observed = selector_aligned.observed_concrete_id
    if (
        resolver_aligned.intended_concrete_id != intended
        or resolver_aligned.observed_concrete_id != observed
    ):
        raise ValueError("twin sources do not share intended and observed concrete IDs")
    expected_first = (observed, intended, observed, intended)
    expected_second = (observed, observed, intended, intended)
    if construction_matrix(selector_aligned) != expected_first:
        raise ValueError("selector-aligned source violates the intervention matrix")
    if construction_matrix(resolver_aligned) != expected_second:
        raise ValueError("resolver-aligned source violates the intervention matrix")
    if selector_aligned.to_canonical_bytes() == resolver_aligned.to_canonical_bytes():
        raise ValueError("twin completion source bytes must be distinct")


def _shared_source_payload(
    record: CompletionSourceRecord,
) -> dict[str, JsonValue]:
    payload = record.to_payload()
    for field in ("initial_epoch_id", "initial_resolver", "selected_selector"):
        del payload[field]
    return payload


def _resolve_record(
    record: CompletionSourceRecord,
    *,
    refresh: bool,
    repair: bool,
) -> str:
    resolver = record.refresh_resolver if refresh else record.initial_resolver
    selector = record.goal_selector if repair else record.selected_selector
    for binding in resolver:
        if binding.selector == selector:
            return binding.concrete_id
    raise ValueError("source resolver does not contain the selected key")


def _resolver(
    first: ResolverBinding,
    second: ResolverBinding,
) -> tuple[ResolverBinding, ResolverBinding]:
    return cast(
        tuple[ResolverBinding, ResolverBinding],
        tuple(sorted((first, second))),
    )


def _task_id(variant: VariantRecord) -> str:
    digest = canonical_digest(
        "witnessgap.workspace100-task.v1",
        {
            "format": "witnessgap.workspace100-task.v1",
            "protocol_id": PROTOCOL_ID,
            "variant": variant.to_payload(),
        },
    )
    return _opaque_id("wgt", digest)


def _pair_id(commitments: tuple[str, str]) -> str:
    digest = canonical_digest(
        "witnessgap.workspace100-pair.v1",
        {
            "completion_commitments": commitments,
            "format": "witnessgap.workspace100-pair.v1",
            "protocol_id": PROTOCOL_ID,
        },
    )
    return _opaque_id("wgp", digest)


def _opaque_id(prefix: str, digest: str) -> str:
    return f"{prefix}_{digest[:_ID_DIGEST_CHARACTERS]}"


def _validate_global_generation_uniqueness(corpus: Workspace100Corpus) -> None:
    completions = corpus.completions
    if len(completions) != _SOURCE_COUNT:
        raise ValueError(f"Workspace-100 must contain exactly {_SOURCE_COUNT} sources")
    unique_fields = {
        "commitment salts": tuple(completion.source.commitment_salt for completion in completions),
        "completion commitments": tuple(
            completion.completion_commitment for completion in completions
        ),
        "episode IDs": tuple(completion.episode_id for completion in completions),
        "snapshot digests": tuple(completion.source.snapshot_digest for completion in completions),
    }
    for label, values in unique_fields.items():
        if len(set(values)) != len(values):
            raise ValueError(f"generated {label} must be globally unique")


def _validate_pairs_match_authored_catalog(corpus: Workspace100Corpus) -> None:
    templates = {template.template_id: template for template in corpus.templates}
    variants = {(variant.template_id, variant.variant_id): variant for variant in corpus.variants}
    for pair in corpus.pairs:
        template = templates[pair.template_id]
        variant = variants[(pair.template_id, pair.variant_id)]
        expected_records = _completion_records(template, variant)
        expected_sources = sorted(record.to_canonical_bytes() for record in expected_records)
        actual_sources = sorted(
            completion.record.to_canonical_bytes() for completion in pair.completions
        )
        if actual_sources != expected_sources:
            raise ValueError(
                f"{pair.template_id.value}/{pair.variant_id} sources differ "
                "from the frozen authored catalog"
            )
    for label, values in (
        ("pair IDs", tuple(pair.pair_id for pair in corpus.pairs)),
        ("task IDs", tuple(pair.task_id for pair in corpus.pairs)),
    ):
        if len(set(values)) != len(values):
            raise ValueError(f"generated {label} must be globally unique")
