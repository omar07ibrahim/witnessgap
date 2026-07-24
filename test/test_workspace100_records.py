from __future__ import annotations

from typing import cast

import pytest

from witnessgap.canonical import JsonValue, canonical_json
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


def template_record() -> TemplateRecord:
    return TemplateRecord(
        template_id=TemplateId.PUBLISH_DRAFT,
        split=Split.DEVELOPMENT,
        task_schema_id="workspace_publish_draft_v1",
        goal_selector="approved_draft",
        alternate_selector="legacy_draft",
        refresh_atom="refresh_draft_catalog",
        repair_atom="repair_draft_selection",
        epoch_probe="draft_catalog_epoch",
        selection_channel="draft_selection",
        resolver_channel="draft_catalog",
        lookup_tool="read_release_draft",
        action_tool="publish_release_notes",
        terminal_success="approved_content_present",
        terminal_failure="approved_content_missing",
    )


def variant_record() -> VariantRecord:
    return VariantRecord(
        template_id=TemplateId.PUBLISH_DRAFT,
        variant_id="v00",
        workspace_slug="northstar",
        subject_id="release_notes_northstar",
        subject_display="Northstar release notes",
        owner="release_team",
        public_task="Publish the approved Northstar release notes.",
        intended_concrete_id="draft_northstar_021",
        observed_concrete_id="draft_northstar_017",
        intended_display="Northstar release notes r21",
        observed_display="Northstar release notes r17",
        reference_epoch_id="draft_catalog_northstar_042",
        alternate_epoch_id="draft_catalog_northstar_037",
    )


def source_record(*, selector_aligned: bool = True) -> CompletionSourceRecord:
    template = template_record()
    variant = variant_record()
    reference = tuple(
        sorted(
            (
                ResolverBinding(
                    selector=template.goal_selector,
                    concrete_id=variant.intended_concrete_id,
                ),
                ResolverBinding(
                    selector=template.alternate_selector,
                    concrete_id=variant.observed_concrete_id,
                ),
            )
        )
    )
    alternate = tuple(
        sorted(
            (
                ResolverBinding(
                    selector=template.goal_selector,
                    concrete_id=variant.observed_concrete_id,
                ),
                ResolverBinding(
                    selector=template.alternate_selector,
                    concrete_id=variant.observed_concrete_id,
                ),
            )
        )
    )
    return CompletionSourceRecord(
        protocol_id=PROTOCOL_ID,
        source_format_id=SOURCE_FORMAT_ID,
        task_schema_id=template.task_schema_id,
        task_id="wgt_0123456789abcdef01234567",
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
        selected_selector=(
            template.goal_selector if selector_aligned else template.alternate_selector
        ),
        initial_epoch_id=(
            variant.alternate_epoch_id if selector_aligned else variant.reference_epoch_id
        ),
        initial_resolver=cast(
            tuple[ResolverBinding, ResolverBinding],
            alternate if selector_aligned else reference,
        ),
        refresh_epoch_id=variant.reference_epoch_id,
        refresh_resolver=cast(
            tuple[ResolverBinding, ResolverBinding],
            reference,
        ),
    )


@pytest.mark.parametrize(
    "record",
    [
        pytest.param(template_record(), id="template"),
        pytest.param(variant_record(), id="variant"),
        pytest.param(source_record(), id="selector-aligned-source"),
        pytest.param(source_record(selector_aligned=False), id="resolver-aligned-source"),
    ],
)
def test_authored_records_have_closed_canonical_round_trips(record: object) -> None:
    parsed: TemplateRecord | VariantRecord | CompletionSourceRecord
    if type(record) is TemplateRecord:
        encoded = record.to_canonical_bytes()
        parsed = TemplateRecord.from_canonical_bytes(encoded)
    elif type(record) is VariantRecord:
        encoded = record.to_canonical_bytes()
        parsed = VariantRecord.from_canonical_bytes(encoded)
    else:
        source = cast(CompletionSourceRecord, record)
        encoded = source.to_canonical_bytes()
        parsed = CompletionSourceRecord.from_canonical_bytes(encoded)

    assert parsed == record
    assert parsed.to_canonical_bytes() == encoded


def test_template_parser_rejects_unknown_fields() -> None:
    payload = template_record().to_payload()
    payload["note"] = "trust me"

    with pytest.raises(ValueError, match="unknown or missing"):
        TemplateRecord.from_canonical_bytes(canonical_json(payload))


def test_variant_parser_rejects_missing_fields() -> None:
    payload = variant_record().to_payload()
    del payload["owner"]

    with pytest.raises(ValueError, match="unknown or missing"):
        VariantRecord.from_canonical_bytes(canonical_json(payload))


def test_source_parser_rejects_noncanonical_json() -> None:
    encoded = source_record().to_canonical_bytes()

    with pytest.raises(ValueError, match="canonical"):
        CompletionSourceRecord.from_canonical_bytes(encoded.rstrip())


def test_source_parser_rejects_wrong_nested_type() -> None:
    payload = source_record().to_payload()
    payload["initial_resolver"] = "not-an-array"

    with pytest.raises(ValueError, match="two-entry JSON array"):
        CompletionSourceRecord.from_canonical_bytes(canonical_json(payload))


def test_source_parser_rejects_unsorted_resolver() -> None:
    payload = source_record().to_payload()
    resolver = cast(tuple[JsonValue, ...], payload["initial_resolver"])
    payload["initial_resolver"] = tuple(reversed(resolver))

    with pytest.raises(ValueError, match="must be sorted"):
        CompletionSourceRecord.from_canonical_bytes(canonical_json(payload))


def test_source_parser_rejects_duplicate_resolver_selectors() -> None:
    payload = source_record().to_payload()
    resolver = cast(tuple[JsonValue, ...], payload["initial_resolver"])
    payload["initial_resolver"] = (resolver[0], resolver[0])

    with pytest.raises(ValueError, match="selector names must be unique"):
        CompletionSourceRecord.from_canonical_bytes(canonical_json(payload))


def test_source_rejects_a_nonexact_payload_type() -> None:
    class Payload(bytes):
        pass

    with pytest.raises(TypeError, match="exact bytes"):
        CompletionSourceRecord.from_canonical_bytes(Payload(source_record().to_canonical_bytes()))


def test_serialization_revalidates_post_init_mutation() -> None:
    record = source_record()
    object.__setattr__(record, "protocol_id", "workspace-100-v2")

    with pytest.raises(ValueError, match="protocol_id"):
        record.to_canonical_bytes()


def test_source_rejects_a_snapshot_outside_the_twin_construction() -> None:
    record = source_record()
    object.__setattr__(record, "initial_epoch_id", record.refresh_epoch_id)

    with pytest.raises(ValueError, match="alternate resolver"):
        record.to_canonical_bytes()
