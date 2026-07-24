from __future__ import annotations

import re
from dataclasses import replace

import pytest

from witnessgap.workspace100.catalog import (
    FORBIDDEN_PARTICIPANT_TERMS,
    TEMPLATE_CATALOG_DIGEST,
    TEMPLATES,
    VARIANT_CATALOG_DIGEST,
    VARIANTS,
    participant_facing_leaks,
    template_catalog_digest,
    validate_authored_catalog,
    variant_catalog_digest,
)
from witnessgap.workspace100.records import Split, TemplateId

_VARIANT_IDS = (
    "v00",
    "v01",
    "v02",
    "v03",
    "v04",
    "v05",
    "v06",
    "v07",
    "v08",
    "v09",
)
_TEMPLATE_COUNT = 5
_VARIANT_COUNT = 50
_SOURCE_ID_COUNT = 100
_EXPECTED_TEMPLATE_DIGEST = "f79b66036002be18d0ea565a938138a893e999ba56ffac4fb7e1b2eedf19a0ee"
_EXPECTED_VARIANT_DIGEST = "86a2583224475a81d0485f0f0110e973156bac3c11c8e28aba337d12b6434aa3"


def test_catalog_has_frozen_template_and_variant_counts() -> None:
    assert type(TEMPLATES) is tuple
    assert type(VARIANTS) is tuple
    assert len(TEMPLATES) == _TEMPLATE_COUNT
    assert len(VARIANTS) == _VARIANT_COUNT
    assert tuple(template.template_id for template in TEMPLATES) == (
        TemplateId.PUBLISH_DRAFT,
        TemplateId.INVITE_MEMBER,
        TemplateId.MOVE_WORK_ITEM,
        TemplateId.SCHEDULE_REVIEW,
        TemplateId.GRANT_ACCESS,
    )


def test_each_template_has_v00_through_v09_in_protocol_order() -> None:
    for offset, template in zip((0, 10, 20, 30, 40), TEMPLATES, strict=True):
        block = VARIANTS[offset : offset + 10]
        assert tuple(variant.template_id for variant in block) == (template.template_id,) * 10
        assert tuple(variant.variant_id for variant in block) == _VARIANT_IDS


def test_grouped_splits_have_twenty_ten_twenty_pairs() -> None:
    split_by_template = {template.template_id: template.split for template in TEMPLATES}
    pair_counts = {
        split: sum(split_by_template[variant.template_id] is split for variant in VARIANTS)
        for split in Split
    }

    assert pair_counts == {
        Split.DEVELOPMENT: 20,
        Split.VALIDATION: 10,
        Split.TEST: 20,
    }


def test_variant_identifiers_are_globally_unique() -> None:
    workspace_slugs = tuple(variant.workspace_slug for variant in VARIANTS)
    subject_ids = tuple(variant.subject_id for variant in VARIANTS)
    concrete_ids = tuple(
        concrete_id
        for variant in VARIANTS
        for concrete_id in (
            variant.intended_concrete_id,
            variant.observed_concrete_id,
        )
    )
    epoch_ids = tuple(
        epoch_id
        for variant in VARIANTS
        for epoch_id in (
            variant.reference_epoch_id,
            variant.alternate_epoch_id,
        )
    )

    assert len(set(workspace_slugs)) == _VARIANT_COUNT
    assert len(set(subject_ids)) == _VARIANT_COUNT
    assert len(set(concrete_ids)) == _SOURCE_ID_COUNT
    assert len(set(epoch_ids)) == _SOURCE_ID_COUNT


def test_public_tasks_map_to_their_subject_goal_and_workspace() -> None:
    for variant in VARIANTS:
        assert variant.subject_display in variant.public_task
        assert variant.intended_display in variant.public_task
        assert variant.observed_display not in variant.public_task
        assert variant.workspace_slug.replace("_", " ").title() in variant.public_task
        assert variant.intended_concrete_id != variant.observed_concrete_id
        assert variant.reference_epoch_id != variant.alternate_epoch_id


def test_authored_catalog_has_no_participant_facing_reserved_terms() -> None:
    payload = {
        "templates": tuple(template.to_payload() for template in TEMPLATES),
        "variants": tuple(variant.to_payload() for variant in VARIANTS),
    }

    assert participant_facing_leaks(payload) == ()
    for variant in VARIANTS:
        concrete_values = (
            variant.intended_concrete_id,
            variant.observed_concrete_id,
        )
        assert all(
            term not in value.casefold()
            for value in concrete_values
            for term in FORBIDDEN_PARTICIPANT_TERMS
        )


def test_recursive_leak_scan_includes_nested_keys_and_values() -> None:
    leaks = participant_facing_leaks(
        {
            "outer": [
                {
                    "Stale_Label": "neutral",
                    "display": "Policy lane",
                }
            ]
        }
    )

    assert leaks == (
        "$.outer[0].<key>:stale",
        "$.outer[0].display:policy",
    )


def test_catalog_digests_are_stable_nonempty_sha256_values() -> None:
    assert template_catalog_digest() == TEMPLATE_CATALOG_DIGEST
    assert variant_catalog_digest() == VARIANT_CATALOG_DIGEST
    assert TEMPLATE_CATALOG_DIGEST == _EXPECTED_TEMPLATE_DIGEST
    assert VARIANT_CATALOG_DIGEST == _EXPECTED_VARIANT_DIGEST
    assert re.fullmatch(r"[0-9a-f]{64}", TEMPLATE_CATALOG_DIGEST)
    assert re.fullmatch(r"[0-9a-f]{64}", VARIANT_CATALOG_DIGEST)
    assert TEMPLATE_CATALOG_DIGEST != VARIANT_CATALOG_DIGEST


def test_catalog_validator_rejects_a_crafted_global_duplicate() -> None:
    duplicate = replace(VARIANTS[-1], subject_id=VARIANTS[0].subject_id)
    crafted = (*VARIANTS[:-1], duplicate)

    with pytest.raises(ValueError, match=r"subject IDs.*globally unique"):
        validate_authored_catalog(variants=crafted)


def test_catalog_validator_rejects_a_crafted_participant_leak() -> None:
    original = VARIANTS[0]
    leaked = replace(
        original,
        public_task=f"{original.public_task[:-1]} for the Policy audit.",
    )
    crafted = (leaked, *VARIANTS[1:])

    with pytest.raises(ValueError, match="leaks reserved terms"):
        validate_authored_catalog(variants=crafted)
