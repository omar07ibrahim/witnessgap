from __future__ import annotations

import inspect
import json
from dataclasses import replace
from typing import cast

import pytest

from witnessgap.canonical import JsonValue, canonical_json
from witnessgap.model import ExecutionArtifact, StateRead
from witnessgap.trust import VerificationTrustAnchor
from witnessgap.verifier import (
    VerifiedPanel,
    VerifiedProbeReceipt,
    VerifiedReceipt,
    verifier_implementation_digest,
)
from witnessgap.workspace100 import release_storage as storage_module
from witnessgap.workspace100.release_storage import (
    Workspace100CatalogSet,
    Workspace100GenerationProvenance,
    Workspace100ProtocolRecord,
    Workspace100RegistrySet,
    Workspace100TrustAnchorSet,
    Workspace100VerifiedMaterialSet,
    load_workspace100_source_openings,
    workspace100_source_opening_root,
    workspace100_source_openings_jsonl,
    workspace100_source_root,
)
from witnessgap.workspace100.views import (
    VerifiedCompletionMaterial,
    VerifiedPairMaterial,
    verify_workspace100_materials,
)

_SEED = bytes.fromhex(
    "713d96c0fcadb930599f4f4370df3484766872ac406f1c26c5a360a996f29ec5"
)
_OTHER_SEED = bytes.fromhex(
    "4c0b429664b4ddf0bda8e10d4798d56315075d9108a15532f063699d42724a3d"
)
_PAIR_COUNT = 50
_COMPLETION_COUNT = 100
_TEMPLATE_COUNT = 5
_VARIANT_COUNT = 50
_RECEIPT_COUNT = 400
_PROBE_COUNT = 200
_SHA256_HEX_LENGTH = 64
_EXPECTED_PROVENANCE_ROOT = (
    "70ab924d982617dff435b3598396ceae9ba1350268e0fdc0cdfc2a00b4caa63f"
)
_EXPECTED_SOURCE_ROOT = (
    "01d062caee7878056e8965ebb7766552b38dd442b60ca64f3893fa83cd844a93"
)
_EXPECTED_SOURCE_OPENING_ROOT = (
    "c4b70c36c5765e6b647452cb2ab42ef1d42786f842b817c66fb7a8ed1775a6e6"
)
_EXPECTED_CATALOG_ROOT = (
    "57e85b605cb8e193c9f1e84ae5b0f03e9f2e6bd73b6d00de8f5353798d795d94"
)
_EXPECTED_PROTOCOL_ROOT = (
    "438b0405b79aa4403e3ee5737bcf0d2d3aa080078d0e2fd8650aa82899eb5f94"
)
_EXPECTED_REGISTRY_ROOT = (
    "8e2aa9af9d3a0f804f7698a13e5710e28918867840a938534c5cc71ebb25831f"
)
_EXPECTED_TRUST_ANCHOR_ROOT = (
    "65296e53f7ca6544c26df5c0f7157455d2418c53bcda097e906e2b166c70a1ad"
)
_EXPECTED_VERIFIED_MATERIAL_ROOT = (
    "08600100802a8dab1e55243e268c3b64b18f48a2b024a89f76fc8634dc353ded"
)


@pytest.fixture(scope="module")
def provenance() -> Workspace100GenerationProvenance:
    return Workspace100GenerationProvenance(_SEED)


@pytest.fixture(scope="module")
def source_jsonl(
    provenance: Workspace100GenerationProvenance,
) -> bytes:
    return workspace100_source_openings_jsonl(provenance)


@pytest.fixture(scope="module")
def materials(
    provenance: Workspace100GenerationProvenance,
) -> tuple[VerifiedPairMaterial, ...]:
    return verify_workspace100_materials(provenance.corpus)


@pytest.fixture(scope="module")
def registry_set(
    provenance: Workspace100GenerationProvenance,
    materials: tuple[VerifiedPairMaterial, ...],
) -> Workspace100RegistrySet:
    return Workspace100RegistrySet(
        provenance=provenance,
        manifests=tuple(material.manifest for material in materials),
    )


@pytest.fixture(scope="module")
def trust_anchor_set(
    registry_set: Workspace100RegistrySet,
) -> Workspace100TrustAnchorSet:
    verifier_digest = verifier_implementation_digest()
    anchors = tuple(
        VerificationTrustAnchor(
            registry_digest=manifest.digest,
            adapter_implementation_digest=(
                manifest.adapter_implementation_digest
            ),
            verifier_implementation_digest=verifier_digest,
        )
        for manifest in registry_set.manifests
    )
    return Workspace100TrustAnchorSet(
        registry_set=registry_set,
        anchors=anchors,
    )


@pytest.fixture(scope="module")
def verified_material_set(
    registry_set: Workspace100RegistrySet,
    materials: tuple[VerifiedPairMaterial, ...],
) -> Workspace100VerifiedMaterialSet:
    return Workspace100VerifiedMaterialSet(
        registry_set=registry_set,
        materials=materials,
    )


def _opened(payload: bytes) -> dict[str, object]:
    raw: object = json.loads(payload)
    assert type(raw) is dict
    return cast(dict[str, object], raw)


def _jsonl_objects(payload: bytes) -> list[dict[str, object]]:
    objects: list[dict[str, object]] = []
    for line in payload.splitlines():
        raw: object = json.loads(line)
        assert type(raw) is dict
        objects.append(cast(dict[str, object], raw))
    return objects


def _jsonl_bytes(objects: list[dict[str, object]]) -> bytes:
    return b"".join(canonical_json(cast(JsonValue, value)) for value in objects)


def _nested_object(raw: dict[str, object], field: str) -> dict[str, object]:
    value = raw[field]
    assert type(value) is dict
    return cast(dict[str, object], value)


def _nested_array(raw: dict[str, object], field: str) -> list[object]:
    value = raw[field]
    assert type(value) is list
    return cast(list[object], value)


def test_generation_provenance_is_seed_derived_closed_and_frozen(
    provenance: Workspace100GenerationProvenance,
) -> None:
    payload = provenance.to_canonical_bytes()
    parsed = Workspace100GenerationProvenance.from_canonical_bytes(payload)
    opened = _opened(payload)

    assert parsed == provenance
    assert parsed.to_canonical_bytes() == payload
    assert opened["seed_hex"] == _SEED.hex()
    assert provenance.generation_provenance_root == _EXPECTED_PROVENANCE_ROOT
    assert provenance.source_root == _EXPECTED_SOURCE_ROOT
    assert provenance.source_root == provenance.corpus.root
    assert provenance.source_opening_root == _EXPECTED_SOURCE_OPENING_ROOT
    assert workspace100_source_root(provenance.corpus) == _EXPECTED_SOURCE_ROOT
    assert workspace100_source_opening_root(provenance.corpus) == (
        _EXPECTED_SOURCE_OPENING_ROOT
    )
    assert opened["source_root"] == _EXPECTED_SOURCE_ROOT
    assert opened["source_opening_root"] == _EXPECTED_SOURCE_OPENING_ROOT
    assert provenance.corpus.root == parsed.corpus.root
    assert len(cast(str, opened["seed_digest"])) == _SHA256_HEX_LENGTH


def test_generation_provenance_rejects_nonexact_seed_and_tampering(
    provenance: Workspace100GenerationProvenance,
) -> None:
    with pytest.raises(TypeError, match="exact bytes"):
        Workspace100GenerationProvenance(cast(bytes, bytearray(_SEED)))
    with pytest.raises(ValueError, match="32"):
        Workspace100GenerationProvenance(_SEED[:-1])

    opened = _opened(provenance.to_canonical_bytes())
    opened["source_root"] = "0" * 64
    with pytest.raises(ValueError, match="deterministic derivation"):
        Workspace100GenerationProvenance.from_canonical_bytes(
            canonical_json(cast(JsonValue, opened))
        )

    opened = _opened(provenance.to_canonical_bytes())
    opened["source_opening_root"] = "0" * 64
    with pytest.raises(ValueError, match="deterministic derivation"):
        Workspace100GenerationProvenance.from_canonical_bytes(
            canonical_json(cast(JsonValue, opened))
        )

    opened = _opened(provenance.to_canonical_bytes())
    opened["timestamp"] = "2026-07-24T00:00:00Z"
    with pytest.raises(ValueError, match="unknown or missing"):
        Workspace100GenerationProvenance.from_canonical_bytes(
            canonical_json(cast(JsonValue, opened))
        )

    other = Workspace100GenerationProvenance(_OTHER_SEED)
    assert other.seed_digest != provenance.seed_digest
    assert other.source_root != provenance.source_root
    assert other.source_opening_root != provenance.source_opening_root


def test_catalog_set_is_exact_closed_and_frozen() -> None:
    catalog = Workspace100CatalogSet()
    payload = catalog.to_canonical_bytes()
    parsed = Workspace100CatalogSet.from_canonical_bytes(payload)
    opened = _opened(payload)

    assert parsed == catalog
    assert len(catalog.templates) == _TEMPLATE_COUNT
    assert len(catalog.variants) == _VARIANT_COUNT
    assert catalog.catalog_root == _EXPECTED_CATALOG_ROOT
    assert len(_nested_array(opened, "templates")) == _TEMPLATE_COUNT
    assert len(_nested_array(opened, "variants")) == _VARIANT_COUNT


def test_catalog_parser_rejects_reorder_and_open_schema() -> None:
    payload = Workspace100CatalogSet().to_canonical_bytes()
    opened = _opened(payload)
    templates = _nested_array(opened, "templates")
    templates[0], templates[1] = templates[1], templates[0]
    with pytest.raises(ValueError):
        Workspace100CatalogSet.from_canonical_bytes(
            canonical_json(cast(JsonValue, opened))
        )

    opened = _opened(payload)
    opened["absolute_path"] = "/tmp/catalog"
    with pytest.raises(ValueError, match="unknown or missing"):
        Workspace100CatalogSet.from_canonical_bytes(
            canonical_json(cast(JsonValue, opened))
        )


def test_source_openings_are_exact_seed_regeneration(
    provenance: Workspace100GenerationProvenance,
    source_jsonl: bytes,
) -> None:
    parsed_corpus = load_workspace100_source_openings(source_jsonl, provenance)
    objects = _jsonl_objects(source_jsonl)

    assert parsed_corpus == provenance.corpus
    assert workspace100_source_openings_jsonl(provenance) == source_jsonl
    assert source_jsonl.endswith(b"\n")
    assert b"\r" not in source_jsonl
    assert len(objects) == _COMPLETION_COUNT
    assert tuple(cast(int, item["pair_index"]) for item in objects) == tuple(
        index // 2 for index in range(_COMPLETION_COUNT)
    )
    assert tuple(
        cast(int, item["completion_index"]) for item in objects
    ) == tuple(index % 2 for index in range(_COMPLETION_COUNT))
    assert len({cast(str, item["episode_id"]) for item in objects}) == (
        _COMPLETION_COUNT
    )
    assert len(
        {cast(str, item["completion_commitment"]) for item in objects}
    ) == _COMPLETION_COUNT


@pytest.mark.parametrize(
    "mutation",
    ["missing-final-lf", "crlf", "reorder", "duplicate"],
)
def test_source_jsonl_rejects_noncanonical_framing_and_order(
    source_jsonl: bytes,
    provenance: Workspace100GenerationProvenance,
    mutation: str,
) -> None:
    if mutation == "missing-final-lf":
        changed = source_jsonl[:-1]
    elif mutation == "crlf":
        changed = source_jsonl.replace(b"\n", b"\r\n", 1)
    else:
        objects = _jsonl_objects(source_jsonl)
        if mutation == "reorder":
            objects[0], objects[1] = objects[1], objects[0]
        else:
            objects[1] = objects[0]
        changed = _jsonl_bytes(objects)

    with pytest.raises((TypeError, ValueError)):
        load_workspace100_source_openings(changed, provenance)


def test_source_jsonl_rejects_byte_salt_digest_and_schema_tampering(
    source_jsonl: bytes,
    provenance: Workspace100GenerationProvenance,
) -> None:
    for field, replacement in (
        ("source_bytes_hex", "00"),
        ("commitment_salt_hex", "00" * 32),
        ("source_snapshot_digest", "0" * 64),
        ("completion_commitment", "0" * 64),
    ):
        objects = _jsonl_objects(source_jsonl)
        objects[0][field] = replacement
        with pytest.raises(ValueError):
            load_workspace100_source_openings(
                _jsonl_bytes(objects),
                provenance,
            )

    objects = _jsonl_objects(source_jsonl)
    objects[0]["path"] = "/tmp/opening"
    with pytest.raises(ValueError, match="unknown or missing"):
        load_workspace100_source_openings(
            _jsonl_bytes(objects),
            provenance,
        )


def test_protocol_record_binds_all_frozen_orders_and_roots(
    provenance: Workspace100GenerationProvenance,
) -> None:
    record = Workspace100ProtocolRecord.for_provenance(provenance)
    payload = record.to_canonical_bytes()
    parsed = Workspace100ProtocolRecord.from_canonical_bytes(payload)
    opened = _opened(payload)

    assert parsed == record
    assert record.protocol_root == _EXPECTED_PROTOCOL_ROOT
    assert record.source_root == _EXPECTED_SOURCE_ROOT
    assert record.source_opening_root == _EXPECTED_SOURCE_OPENING_ROOT
    assert opened["view_order"] == [
        "trace_only",
        "owner_probe",
        "epoch_probe",
        "refresh_receipt",
    ]
    assert opened["template_order"] == [
        "publish_draft",
        "invite_member",
        "move_work_item",
        "schedule_review",
        "grant_access",
    ]
    assert opened["method_order"] == [
        "workspace100_always_unknown_v1",
        "workspace100_forced_environment_v1",
        "workspace100_refresh_success_only_v1",
        "workspace100_refresh_outcome_v1",
    ]
    dimensions = _nested_object(opened, "dimensions")
    assert dimensions == {
        "assignments": 400,
        "completions": 100,
        "evidence_cases": 300,
        "methods": 4,
        "pairs": 50,
        "templates": 5,
        "variants": 50,
        "views": 4,
    }


def test_protocol_parser_rejects_relabelled_order_and_vocabulary(
    provenance: Workspace100GenerationProvenance,
) -> None:
    payload = Workspace100ProtocolRecord.for_provenance(
        provenance
    ).to_canonical_bytes()
    opened = _opened(payload)
    method_order = _nested_array(opened, "method_order")
    method_order[0], method_order[1] = method_order[1], method_order[0]
    with pytest.raises(ValueError, match="deterministic derivation"):
        Workspace100ProtocolRecord.from_canonical_bytes(
            canonical_json(cast(JsonValue, opened))
        )

    opened = _opened(payload)
    vocabulary = _nested_object(opened, "public_vocabulary")
    entries = _nested_array(vocabulary, "entries")
    first = cast(dict[str, object], entries[0])
    first["action_tool"] = "substituted_action"
    with pytest.raises(ValueError, match="deterministic derivation"):
        Workspace100ProtocolRecord.from_canonical_bytes(
            canonical_json(cast(JsonValue, opened))
        )


def test_registry_set_round_trips_and_has_frozen_root(
    provenance: Workspace100GenerationProvenance,
    registry_set: Workspace100RegistrySet,
) -> None:
    payload = registry_set.to_jsonl()
    parsed = Workspace100RegistrySet.from_jsonl(payload, provenance)

    assert parsed == registry_set
    assert parsed.to_jsonl() == payload
    assert len(registry_set.manifests) == _PAIR_COUNT
    assert len(set(registry_set.manifest_digests)) == _PAIR_COUNT
    assert registry_set.registry_root == _EXPECTED_REGISTRY_ROOT


def test_registry_set_rejects_reorder_duplicate_and_manifest_rewrite(
    provenance: Workspace100GenerationProvenance,
    registry_set: Workspace100RegistrySet,
) -> None:
    payload = registry_set.to_jsonl()
    for mutation in ("reorder", "duplicate", "rewrite"):
        objects = _jsonl_objects(payload)
        if mutation == "reorder":
            objects[0], objects[1] = objects[1], objects[0]
        elif mutation == "duplicate":
            objects[1] = objects[0]
        else:
            objects[0]["task_id"] = "wgt_rewritten_task"
        with pytest.raises((TypeError, ValueError)):
            Workspace100RegistrySet.from_jsonl(
                _jsonl_bytes(objects),
                provenance,
            )


def test_trust_anchor_set_uses_only_external_exact_anchors(
    registry_set: Workspace100RegistrySet,
    trust_anchor_set: Workspace100TrustAnchorSet,
) -> None:
    payload = trust_anchor_set.to_jsonl()
    parsed = Workspace100TrustAnchorSet.from_jsonl(payload, registry_set)
    production_source = inspect.getsource(storage_module)

    assert parsed == trust_anchor_set
    assert parsed.to_jsonl() == payload
    assert trust_anchor_set.trust_anchor_root == _EXPECTED_TRUST_ANCHOR_ROOT
    assert "trust_anchor_for_manifest" not in production_source
    assert "workspace100.release" not in production_source


def test_trust_anchor_set_rejects_reorder_and_wrong_verifier(
    registry_set: Workspace100RegistrySet,
    trust_anchor_set: Workspace100TrustAnchorSet,
) -> None:
    objects = _jsonl_objects(trust_anchor_set.to_jsonl())
    objects[0], objects[1] = objects[1], objects[0]
    with pytest.raises(ValueError, match="aligned"):
        Workspace100TrustAnchorSet.from_jsonl(
            _jsonl_bytes(objects),
            registry_set,
        )

    first = trust_anchor_set.anchors[0]
    changed = (
        replace(first, verifier_implementation_digest="0" * 64),
        *trust_anchor_set.anchors[1:],
    )
    with pytest.raises(ValueError, match="aligned"):
        Workspace100TrustAnchorSet(
            registry_set=registry_set,
            anchors=changed,
        )


def test_verified_material_jsonl_round_trips_full_semantic_bytes(
    registry_set: Workspace100RegistrySet,
    verified_material_set: Workspace100VerifiedMaterialSet,
) -> None:
    payload = verified_material_set.to_jsonl()
    parsed = Workspace100VerifiedMaterialSet.from_jsonl(
        payload,
        registry_set,
    )
    objects = _jsonl_objects(payload)
    completions = tuple(
        cast(dict[str, object], completion)
        for pair in objects
        for completion in _nested_array(pair, "completions")
    )
    panels = tuple(_nested_object(completion, "panel") for completion in completions)
    receipts = tuple(
        cast(dict[str, object], receipt)
        for panel in panels
        for receipt in _nested_array(panel, "receipts")
    )
    probes = tuple(
        cast(dict[str, object], probe)
        for completion in completions
        for probe in _nested_array(completion, "probes")
    )
    first_artifact = _nested_object(receipts[0], "artifact")

    assert parsed == verified_material_set
    assert parsed.to_jsonl() == payload
    assert len(objects) == _PAIR_COUNT
    assert len(completions) == _COMPLETION_COUNT
    assert len(receipts) == _RECEIPT_COUNT
    assert len(probes) == _PROBE_COUNT
    assert "public_trace_hex" in first_artifact
    assert "terminal_state_hex" in first_artifact
    assert "state_read_log" in first_artifact
    assert "intervention_log" in first_artifact
    assert "value_hex" in probes[0]
    assert verified_material_set.panel_root == (
        _EXPECTED_VERIFIED_MATERIAL_ROOT
    )
    assert verified_material_set.verified_material_root == (
        _EXPECTED_VERIFIED_MATERIAL_ROOT
    )


def test_verified_material_root_changes_with_full_artifact_state(
    verified_material_set: Workspace100VerifiedMaterialSet,
) -> None:
    material = verified_material_set.materials[0]
    completion = material.completions[0]
    panel = completion.panel
    receipt = panel.receipts[0]
    artifact = receipt.artifact
    changed_reads = tuple(
        replace(
            read,
            value_digest=(
                "0" * 64 if read.value_digest != "0" * 64 else "1" * 64
            ),
        )
        for read in artifact.state_read_log
    )
    changed_artifact = replace(
        artifact,
        terminal_state=artifact.terminal_state + b"\nrelease-storage-change",
        state_read_log=changed_reads,
    )
    changed_receipt = replace(receipt, artifact=changed_artifact)
    changed_panel = replace(
        panel,
        receipts=(changed_receipt, *panel.receipts[1:]),
    )
    changed_completion = replace(completion, panel=changed_panel)
    changed_material = replace(
        material,
        completions=(changed_completion, material.completions[1]),
    )
    changed_set = Workspace100VerifiedMaterialSet(
        registry_set=verified_material_set.registry_set,
        materials=(changed_material, *verified_material_set.materials[1:]),
    )

    assert changed_panel.digest != panel.digest
    assert changed_set.verified_material_root != (
        verified_material_set.verified_material_root
    )
    assert changed_set.to_jsonl() != verified_material_set.to_jsonl()


def test_verified_material_root_changes_with_raw_probe_bytes(
    verified_material_set: Workspace100VerifiedMaterialSet,
) -> None:
    material = verified_material_set.materials[0]
    completion = material.completions[0]
    probe = completion.probes[0]
    changed_probe = replace(probe, value=probe.value + b"-changed")
    changed_completion = replace(
        completion,
        probes=(changed_probe, completion.probes[1]),
    )
    changed_material = replace(
        material,
        completions=(changed_completion, material.completions[1]),
    )
    changed_set = Workspace100VerifiedMaterialSet(
        registry_set=verified_material_set.registry_set,
        materials=(changed_material, *verified_material_set.materials[1:]),
    )

    assert changed_probe.digest != probe.digest
    assert changed_set.verified_material_root != (
        verified_material_set.verified_material_root
    )


def test_verified_material_parser_rejects_nested_tampering_and_reorder(
    registry_set: Workspace100RegistrySet,
    verified_material_set: Workspace100VerifiedMaterialSet,
) -> None:
    payload = verified_material_set.to_jsonl()
    objects = _jsonl_objects(payload)
    completions = _nested_array(objects[0], "completions")
    first_completion = cast(dict[str, object], completions[0])
    panel = _nested_object(first_completion, "panel")
    receipts = _nested_array(panel, "receipts")
    first_receipt = cast(dict[str, object], receipts[0])
    artifact = _nested_object(first_receipt, "artifact")
    artifact["terminal_state_hex"] = "00"
    with pytest.raises(ValueError):
        Workspace100VerifiedMaterialSet.from_jsonl(
            _jsonl_bytes(objects),
            registry_set,
        )

    objects = _jsonl_objects(payload)
    objects[0], objects[1] = objects[1], objects[0]
    with pytest.raises(ValueError, match="reordered"):
        Workspace100VerifiedMaterialSet.from_jsonl(
            _jsonl_bytes(objects),
            registry_set,
        )

    objects = _jsonl_objects(payload)
    objects[0]["timestamp"] = 0
    with pytest.raises(ValueError, match="unknown or missing"):
        Workspace100VerifiedMaterialSet.from_jsonl(
            _jsonl_bytes(objects),
            registry_set,
        )


def test_release_storage_payloads_have_no_floats_timestamps_or_paths(
    provenance: Workspace100GenerationProvenance,
    source_jsonl: bytes,
    registry_set: Workspace100RegistrySet,
    trust_anchor_set: Workspace100TrustAnchorSet,
    verified_material_set: Workspace100VerifiedMaterialSet,
) -> None:
    values: tuple[object, ...] = (
        json.loads(provenance.to_canonical_bytes()),
        json.loads(Workspace100CatalogSet().to_canonical_bytes()),
        json.loads(
            Workspace100ProtocolRecord.for_provenance(
                provenance
            ).to_canonical_bytes()
        ),
        *_jsonl_objects(source_jsonl),
        *_jsonl_objects(registry_set.to_jsonl()),
        *_jsonl_objects(trust_anchor_set.to_jsonl()),
        *_jsonl_objects(verified_material_set.to_jsonl()),
    )

    keys: list[str] = []
    scalars: list[object] = []

    def walk(value: object) -> None:
        if type(value) is dict:
            for key, nested in cast(dict[str, object], value).items():
                keys.append(key)
                walk(nested)
        elif type(value) is list:
            for nested in cast(list[object], value):
                walk(nested)
        else:
            scalars.append(value)

    for value in values:
        walk(value)

    assert not any(type(value) is float for value in scalars)
    assert not any(
        token in key.casefold()
        for key in keys
        for token in ("timestamp", "absolute_path", "filesystem_path")
    )


def test_storage_boundaries_reject_nonbytes_and_oversized_payloads(
    provenance: Workspace100GenerationProvenance,
) -> None:
    with pytest.raises(TypeError, match="exact bytes"):
        Workspace100GenerationProvenance.from_canonical_bytes(
            cast(bytes, bytearray(provenance.to_canonical_bytes()))
        )
    with pytest.raises(ValueError, match="byte bound"):
        Workspace100GenerationProvenance.from_canonical_bytes(
            b"{" + b" " * (1 << 14) + b"}"
        )
    with pytest.raises(ValueError, match="byte bound"):
        Workspace100RegistrySet.from_jsonl(
            b"x" * ((2 << 20) + 1),
            provenance,
        )
    with pytest.raises(TypeError, match="exact registry set"):
        Workspace100TrustAnchorSet.from_jsonl(
            b"{}\n",
            cast(Workspace100RegistrySet, object()),
        )


def test_material_types_used_by_storage_remain_exact(
    verified_material_set: Workspace100VerifiedMaterialSet,
) -> None:
    material = verified_material_set.materials[0]
    completion = material.completions[0]
    panel = completion.panel
    receipt = panel.receipts[0]
    probe = completion.probes[0]
    artifact = receipt.artifact

    assert type(material) is VerifiedPairMaterial
    assert type(completion) is VerifiedCompletionMaterial
    assert type(panel) is VerifiedPanel
    assert type(receipt) is VerifiedReceipt
    assert type(probe) is VerifiedProbeReceipt
    assert type(artifact) is ExecutionArtifact
    assert all(type(read) is StateRead for read in artifact.state_read_log)
