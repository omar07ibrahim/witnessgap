from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import fields, replace
from hashlib import sha256
from typing import cast

import pytest

from witnessgap import workspace100
from witnessgap.canonical import JsonValue, canonical_json
from witnessgap.workspace100.records import PROTOCOL_ID
from witnessgap.workspace100.release import (
    EXECUTION_CONFIGURATION_FORMAT,
    GATE16_STATUS,
    ISOLATION_POLICY_FORMAT,
    RELEASE_DIRECTORY,
    RELEASE_FILE_FORMAT,
    RELEASE_FILE_MODE,
    RELEASE_KIND,
    RELEASE_LAYOUT_PATHS,
    RELEASE_MANIFEST_FORMAT,
    RELEASE_MANIFEST_PATH,
    RELEASE_PAYLOAD_PATHS,
    RUNTIME_IDENTITY_FORMAT,
    Workspace100ExecutionConfiguration,
    Workspace100IsolationPolicy,
    Workspace100ReleaseBindings,
    Workspace100ReleaseFile,
    Workspace100ReleaseManifest,
    Workspace100RuntimeIdentity,
    workspace100_release_file_content_digest,
    workspace100_release_implementation_digest,
)
from witnessgap.workspace100.worker import WorkerLimits

_MAX_RELEASE_FILE_BYTES = 64 << 20
_MAX_MANIFEST_BYTES = 1 << 20
_SHA256_HEX_LENGTH = 64
_EXPECTED_FILE_COUNT = 13
_READ_ONLY_FILE_MODE = 292
_EXPECTED_RUNTIME_ROOT = (
    "ba8583aed90db031b47fe04c3e544c85f36b13fd161cd0f8f23638d02912f53d"
)
_EXPECTED_ISOLATION_POLICY_ROOT = (
    "a60de642a9873120be09401504762cb58628399366682da1685d1bd6f2f97315"
)
_EXPECTED_EXECUTION_CONFIGURATION_ROOT = (
    "9a31f6808b034eaf6aae0eeb39e94443b43194fd07a0493a5f8f50e0a3a675a3"
)
_EXPECTED_ARTIFACT_TREE_ROOT = (
    "2677269f20d742160417e939e08971a37531f5359aa701bd82d35e13030b5cbf"
)
_EXPECTED_RELEASE_ROOT = (
    "537599af6d21699bbe125419ed6044c5250fa4b3b765ad961ebe1d8f0b633ade"
)


def _digest(label: str) -> str:
    return sha256(label.encode("ascii")).hexdigest()


@pytest.fixture
def runtime_identity() -> Workspace100RuntimeIdentity:
    return Workspace100RuntimeIdentity(
        runtime_id="cpython_3_12_linux_x86_64",
        runtime_artifact_digest=_digest("runtime artifact"),
        interpreter_digest=_digest("interpreter"),
        implementation="CPython",
        version="3.12.11",
    )


@pytest.fixture
def isolation_policy() -> Workspace100IsolationPolicy:
    return Workspace100IsolationPolicy()


@pytest.fixture
def limits() -> WorkerLimits:
    return WorkerLimits(
        timeout_ms=4_000,
        stdout_bytes=8_192,
        stderr_bytes=16_384,
    )


@pytest.fixture
def execution_configuration(
    runtime_identity: Workspace100RuntimeIdentity,
    isolation_policy: Workspace100IsolationPolicy,
    limits: WorkerLimits,
) -> Workspace100ExecutionConfiguration:
    return Workspace100ExecutionConfiguration(
        runtime_identity=runtime_identity,
        limits=limits,
        isolation_policy=isolation_policy,
        backend_implementation_digest=_digest("backend implementation"),
    )


@pytest.fixture
def release_bindings(
    execution_configuration: Workspace100ExecutionConfiguration,
) -> Workspace100ReleaseBindings:
    return Workspace100ReleaseBindings(
        protocol_root=_digest("protocol"),
        public_vocabulary_digest=_digest("public vocabulary"),
        baseline_set_root=_digest("baseline set"),
        template_catalog_digest=_digest("template catalog"),
        variant_catalog_digest=_digest("variant catalog"),
        source_root=_digest("source set"),
        registry_root=_digest("registry set"),
        panel_root=_digest("panel set"),
        assignment_root=_digest("assignment set"),
        evidence_root=_digest("evidence set"),
        projection_root=_digest("projection"),
        truth_root=_digest("truth"),
        claim_set_root=_digest("claim set"),
        report_root=_digest("report"),
        adapter_implementation_digest=_digest("adapter implementation"),
        verifier_implementation_digest=_digest("verifier implementation"),
        worker_implementation_digest=_digest("worker implementation"),
        claims_implementation_digest=_digest("claims implementation"),
        scoring_implementation_digest=_digest("scoring implementation"),
        backend_implementation_digest=(
            execution_configuration.backend_implementation_digest
        ),
        runtime_root=execution_configuration.runtime_identity.runtime_root,
        limits_root=execution_configuration.limits.digest,
        isolation_policy_root=(
            execution_configuration.isolation_policy.isolation_policy_root
        ),
        trust_anchor_root=_digest("trust anchor set"),
        release_builder_implementation_digest=_digest(
            "release builder implementation"
        ),
    )


def _semantic_roots(
    bindings: Workspace100ReleaseBindings,
    generation_provenance_root: str,
) -> tuple[str, ...]:
    return (
        bindings.protocol_root,
        bindings.baseline_set_root,
        bindings.template_catalog_digest,
        bindings.variant_catalog_digest,
        generation_provenance_root,
        bindings.source_root,
        bindings.registry_root,
        bindings.trust_anchor_root,
        bindings.panel_root,
        bindings.evidence_root,
        bindings.truth_root,
        bindings.claim_set_root,
        bindings.report_root,
    )


def _release_files(
    bindings: Workspace100ReleaseBindings,
    generation_provenance_root: str,
) -> tuple[Workspace100ReleaseFile, ...]:
    roots = _semantic_roots(bindings, generation_provenance_root)
    return tuple(
        Workspace100ReleaseFile(
            path=path,
            byte_length=len(content),
            content_digest=workspace100_release_file_content_digest(content),
            semantic_root=semantic_root,
        )
        for path, semantic_root in zip(
            RELEASE_PAYLOAD_PATHS,
            roots,
            strict=True,
        )
        for content in (f"fixture:{path}\n".encode(),)
    )


@pytest.fixture
def release_manifest(
    execution_configuration: Workspace100ExecutionConfiguration,
    release_bindings: Workspace100ReleaseBindings,
) -> Workspace100ReleaseManifest:
    generation_root = _digest("generation provenance")
    return Workspace100ReleaseManifest(
        generation_provenance_root=generation_root,
        execution_configuration=execution_configuration,
        bindings=release_bindings,
        files=_release_files(release_bindings, generation_root),
    )


def _manifest_raw(
    manifest: Workspace100ReleaseManifest,
) -> dict[str, object]:
    raw: object = json.loads(manifest.to_canonical_bytes())
    assert type(raw) is dict
    return cast(dict[str, object], raw)


def _canonical(payload: object) -> bytes:
    return canonical_json(cast(JsonValue, payload))


def _object(value: object) -> dict[str, object]:
    assert type(value) is dict
    return cast(dict[str, object], value)


def _array(value: object) -> list[object]:
    assert type(value) is list
    return cast(list[object], value)


def _json_with_float(payload: object) -> bytes:
    return (
        json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        + b"\n"
    )


def test_release_layout_excludes_only_the_self_referential_manifest() -> None:
    assert len(RELEASE_PAYLOAD_PATHS) == _EXPECTED_FILE_COUNT
    assert RELEASE_MANIFEST_PATH not in RELEASE_PAYLOAD_PATHS
    assert (
        *RELEASE_PAYLOAD_PATHS,
        RELEASE_MANIFEST_PATH,
    ) == RELEASE_LAYOUT_PATHS
    assert len(set(RELEASE_LAYOUT_PATHS)) == len(RELEASE_LAYOUT_PATHS)
    assert all(
        path
        and not path.startswith("/")
        and "\\" not in path
        and all(component not in {"", ".", ".."} for component in path.split("/"))
        for path in RELEASE_LAYOUT_PATHS
    )


def test_runtime_identity_is_closed_and_self_rooted(
    runtime_identity: Workspace100RuntimeIdentity,
) -> None:
    payload = runtime_identity.to_payload()
    parsed = Workspace100RuntimeIdentity.from_payload(payload)

    assert parsed == runtime_identity
    assert payload == {
        "format": RUNTIME_IDENTITY_FORMAT,
        "implementation": "CPython",
        "interpreter_digest": _digest("interpreter"),
        "protocol_id": PROTOCOL_ID,
        "runtime_artifact_digest": _digest("runtime artifact"),
        "runtime_id": "cpython_3_12_linux_x86_64",
        "runtime_root": runtime_identity.runtime_root,
        "version": "3.12.11",
    }
    assert runtime_identity.runtime_root == _EXPECTED_RUNTIME_ROOT


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("runtime_id", "CPython"),
        ("runtime_id", "/usr/bin/python"),
        ("runtime_artifact_digest", "A" * 64),
        ("interpreter_digest", "0" * 63),
        ("implementation", ""),
        ("implementation", "/usr/bin/python"),
        ("implementation", "\N{SNOWMAN}"),
        ("version", "x" * 241),
    ],
)
def test_runtime_identity_rejects_invalid_fields(
    runtime_identity: Workspace100RuntimeIdentity,
    field: str,
    value: str,
) -> None:
    with pytest.raises(ValueError):
        replace(runtime_identity, **{field: value})


def test_runtime_identity_parser_rejects_open_missing_and_rerooted_records(
    runtime_identity: Workspace100RuntimeIdentity,
) -> None:
    for field, value, remove in (
        ("unexpected", None, False),
        ("version", None, True),
        ("runtime_root", "0" * 64, False),
        ("format", "foreign.runtime.v1", False),
        ("protocol_id", "workspace-101-v1", False),
    ):
        payload = cast(dict[str, object], runtime_identity.to_payload())
        if remove:
            del payload[field]
        else:
            payload[field] = value
        with pytest.raises(ValueError):
            Workspace100RuntimeIdentity.from_payload(payload)


def test_isolation_policy_can_only_describe_the_honest_local_noncontainment() -> None:
    policy = Workspace100IsolationPolicy()

    assert policy.to_payload() == {
        "filesystem_isolation": "host_uid_access",
        "format": ISOLATION_POLICY_FORMAT,
        "hostile_code_containment": GATE16_STATUS,
        "isolation_policy_root": policy.isolation_policy_root,
        "network_isolation": "not_enforced",
        "participant_scope": "frozen_reviewed_builtins_only",
        "policy_id": "local_python_trusted_builtins_v1",
        "process_isolation": "process_group_lifecycle_only",
        "protocol_id": PROTOCOL_ID,
    }
    assert policy.isolation_policy_root == _EXPECTED_ISOLATION_POLICY_ROOT
    assert Workspace100IsolationPolicy.from_payload(policy.to_payload()) == policy


@pytest.mark.parametrize(
    ("field", "claim"),
    [
        ("policy_id", "external_sandbox_v1"),
        ("participant_scope", "arbitrary_third_party_code"),
        ("filesystem_isolation", "fresh_rootfs"),
        ("network_isolation", "fully_denied"),
        ("process_isolation", "new_pid_namespace"),
        ("hostile_code_containment", "verified"),
    ],
)
def test_isolation_policy_rejects_any_stronger_claim(
    field: str,
    claim: str,
) -> None:
    with pytest.raises(ValueError, match="exact non-containment policy"):
        replace(Workspace100IsolationPolicy(), **{field: claim})


def test_isolation_policy_parser_rejects_stored_root_and_open_schema() -> None:
    valid = Workspace100IsolationPolicy().to_payload()
    for field, value in (
        ("isolation_policy_root", "0" * 64),
        ("format", "foreign.policy.v1"),
        ("protocol_id", "workspace-101-v1"),
    ):
        payload = dict(valid)
        payload[field] = value
        with pytest.raises(ValueError):
            Workspace100IsolationPolicy.from_payload(payload)
    open_payload = dict(valid)
    open_payload["gate16_passed"] = True
    with pytest.raises(ValueError, match="unknown or missing"):
        Workspace100IsolationPolicy.from_payload(open_payload)


def test_execution_configuration_round_trip_and_root_layers(
    execution_configuration: Workspace100ExecutionConfiguration,
) -> None:
    payload = execution_configuration.to_payload()
    parsed = Workspace100ExecutionConfiguration.from_payload(payload)

    assert parsed == execution_configuration
    assert payload["format"] == EXECUTION_CONFIGURATION_FORMAT
    assert payload["runtime_root"] == (
        execution_configuration.runtime_identity.runtime_root
    )
    assert payload["limits_root"] == execution_configuration.limits.digest
    assert payload["isolation_policy_root"] == (
        execution_configuration.isolation_policy.isolation_policy_root
    )
    assert payload["execution_configuration_root"] == (
        execution_configuration.execution_configuration_root
    )
    assert (
        execution_configuration.execution_configuration_root
        == _EXPECTED_EXECUTION_CONFIGURATION_ROOT
    )


@pytest.mark.parametrize(
    "field",
    [
        "runtime_root",
        "limits_root",
        "isolation_policy_root",
        "execution_configuration_root",
    ],
)
def test_execution_configuration_rejects_nested_stored_root_tampering(
    execution_configuration: Workspace100ExecutionConfiguration,
    field: str,
) -> None:
    payload = execution_configuration.to_payload()
    payload[field] = "0" * 64

    with pytest.raises(ValueError, match="stored roots"):
        Workspace100ExecutionConfiguration.from_payload(payload)


def test_execution_configuration_requires_exact_nested_records(
    execution_configuration: Workspace100ExecutionConfiguration,
) -> None:
    with pytest.raises(TypeError, match="exact runtime"):
        replace(
            execution_configuration,
            runtime_identity=cast(Workspace100RuntimeIdentity, object()),
        )
    with pytest.raises(TypeError, match="exact limits"):
        replace(
            execution_configuration,
            limits=cast(WorkerLimits, object()),
        )
    with pytest.raises(TypeError, match="exact isolation"):
        replace(
            execution_configuration,
            isolation_policy=cast(Workspace100IsolationPolicy, object()),
        )


def test_release_bindings_cover_gate17_catalog_and_builder_fields(
    release_bindings: Workspace100ReleaseBindings,
) -> None:
    expected_names = {
        "protocol_root",
        "public_vocabulary_digest",
        "baseline_set_root",
        "template_catalog_digest",
        "variant_catalog_digest",
        "source_root",
        "registry_root",
        "panel_root",
        "assignment_root",
        "evidence_root",
        "projection_root",
        "truth_root",
        "claim_set_root",
        "report_root",
        "adapter_implementation_digest",
        "verifier_implementation_digest",
        "worker_implementation_digest",
        "claims_implementation_digest",
        "scoring_implementation_digest",
        "backend_implementation_digest",
        "runtime_root",
        "limits_root",
        "isolation_policy_root",
        "trust_anchor_root",
        "release_builder_implementation_digest",
    }
    dataclass_names = {field.name for field in fields(Workspace100ReleaseBindings)}
    payload = release_bindings.to_payload()

    assert dataclass_names == expected_names
    assert set(payload) == {"format", "protocol_id", *expected_names}
    assert Workspace100ReleaseBindings.from_payload(payload) == release_bindings


@pytest.mark.parametrize(
    "field",
    [field.name for field in fields(Workspace100ReleaseBindings)],
)
def test_each_release_binding_requires_one_exact_digest(
    release_bindings: Workspace100ReleaseBindings,
    field: str,
) -> None:
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        replace(release_bindings, **{field: "A" * 64})


def test_release_bindings_parser_is_closed(
    release_bindings: Workspace100ReleaseBindings,
) -> None:
    open_payload = release_bindings.to_payload()
    open_payload["signature"] = "self-authored"
    with pytest.raises(ValueError, match="unknown or missing"):
        Workspace100ReleaseBindings.from_payload(open_payload)

    missing_payload = release_bindings.to_payload()
    del missing_payload["trust_anchor_root"]
    with pytest.raises(ValueError, match="unknown or missing"):
        Workspace100ReleaseBindings.from_payload(missing_payload)


def test_release_file_descriptor_is_closed_bounded_and_read_only() -> None:
    content = b"payload\n"
    record = Workspace100ReleaseFile(
        path=RELEASE_PAYLOAD_PATHS[0],
        byte_length=len(content),
        content_digest=workspace100_release_file_content_digest(content),
        semantic_root=_digest("semantic root"),
    )

    assert record.mode == RELEASE_FILE_MODE == _READ_ONLY_FILE_MODE
    assert record.to_payload()["format"] == RELEASE_FILE_FORMAT
    assert Workspace100ReleaseFile.from_payload(record.to_payload()) == record


@pytest.mark.parametrize(
    "path",
    [
        RELEASE_MANIFEST_PATH,
        "/workspace100/v1/protocol.json",
        "../protocol.json",
        "public/../protocol.json",
        "unknown.json",
        "",
    ],
)
def test_release_file_rejects_paths_outside_the_payload_allowlist(
    path: str,
) -> None:
    with pytest.raises(ValueError, match="allowlist"):
        Workspace100ReleaseFile(
            path=path,
            byte_length=1,
            content_digest=_digest("content"),
            semantic_root=_digest("semantic"),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("byte_length", 0),
        ("byte_length", _MAX_RELEASE_FILE_BYTES + 1),
        ("byte_length", True),
        ("content_digest", "0" * 63),
        ("semantic_root", "F" * 64),
        ("mode", 0o400),
        ("mode", 0o644),
        ("mode", True),
    ],
)
def test_release_file_rejects_wrong_size_digest_or_mode(
    field: str,
    value: object,
) -> None:
    valid = Workspace100ReleaseFile(
        path=RELEASE_PAYLOAD_PATHS[0],
        byte_length=1,
        content_digest=_digest("content"),
        semantic_root=_digest("semantic"),
    )
    payload = valid.to_payload()
    payload[field] = cast(JsonValue, value)
    with pytest.raises(ValueError):
        Workspace100ReleaseFile.from_payload(payload)


def test_release_file_parser_rejects_open_or_missing_fields() -> None:
    valid = Workspace100ReleaseFile(
        path=RELEASE_PAYLOAD_PATHS[0],
        byte_length=1,
        content_digest=_digest("content"),
        semantic_root=_digest("semantic"),
    ).to_payload()
    for field, value, remove in (
        ("absolute_path", "/tmp/protocol.json", False),
        ("mode", None, True),
        ("format", "foreign.file.v1", False),
    ):
        payload = dict(valid)
        if remove:
            del payload[field]
        else:
            payload[field] = value
        with pytest.raises(ValueError):
            Workspace100ReleaseFile.from_payload(payload)


def test_content_digest_helper_is_exact_and_domain_separated() -> None:
    payload = b"same bytes\n"
    digest = workspace100_release_file_content_digest(payload)

    assert len(digest) == _SHA256_HEX_LENGTH
    assert digest != sha256(payload).hexdigest()
    assert digest != workspace100_release_file_content_digest(payload + b"x")
    with pytest.raises(TypeError, match="exact bytes"):
        workspace100_release_file_content_digest(cast(bytes, bytearray(payload)))
    with pytest.raises(ValueError, match="byte bound"):
        workspace100_release_file_content_digest(b"")
    with pytest.raises(ValueError, match="byte bound"):
        workspace100_release_file_content_digest(
            b"x" * (_MAX_RELEASE_FILE_BYTES + 1)
        )


def test_manifest_round_trip_pins_layered_roots(
    release_manifest: Workspace100ReleaseManifest,
) -> None:
    encoded = release_manifest.to_canonical_bytes()
    parsed = Workspace100ReleaseManifest.from_canonical_bytes(encoded)
    payload = parsed.to_payload()

    assert parsed == release_manifest
    assert parsed.to_canonical_bytes() == encoded
    assert payload["format"] == RELEASE_MANIFEST_FORMAT
    assert payload["protocol_id"] == PROTOCOL_ID
    assert payload["release_kind"] == RELEASE_KIND
    assert payload["gate16_status"] == GATE16_STATUS
    assert payload["release_directory"] == RELEASE_DIRECTORY
    assert payload["artifact_tree_root"] == release_manifest.artifact_tree_root
    assert payload["release_root"] == release_manifest.release_root
    assert release_manifest.artifact_tree_root == _EXPECTED_ARTIFACT_TREE_ROOT
    assert release_manifest.release_root == _EXPECTED_RELEASE_ROOT


def test_manifest_inventory_has_exact_semantic_mapping(
    release_manifest: Workspace100ReleaseManifest,
) -> None:
    assert tuple(record.path for record in release_manifest.files) == (
        RELEASE_PAYLOAD_PATHS
    )
    assert tuple(record.semantic_root for record in release_manifest.files) == (
        _semantic_roots(
            release_manifest.bindings,
            release_manifest.generation_provenance_root,
        )
    )
    assert {record.mode for record in release_manifest.files} == {
        RELEASE_FILE_MODE
    }


def test_manifest_contains_no_timestamp_or_absolute_path(
    release_manifest: Workspace100ReleaseManifest,
) -> None:
    raw = _manifest_raw(release_manifest)
    forbidden_keys = {
        "absolute_path",
        "created_at",
        "cwd",
        "mtime",
        "timestamp",
    }

    def walk(value: object) -> None:
        if type(value) is dict:
            mapping = cast(dict[str, object], value)
            assert forbidden_keys.isdisjoint(mapping)
            for nested in mapping.values():
                walk(nested)
        elif type(value) is list:
            for nested in cast(list[object], value):
                walk(nested)
        elif type(value) is str:
            if value in RELEASE_LAYOUT_PATHS or value == RELEASE_DIRECTORY:
                assert not value.startswith("/")

    walk(raw)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("release_kind", "public_release", "kind"),
        ("gate16_status", "verified", "gate 16"),
        ("release_directory", "/workspace100/v1", "directory"),
        ("format", "foreign.release.v1", "format"),
        ("protocol_id", "workspace-101-v1", "protocol"),
    ],
)
def test_manifest_parser_rejects_unsupported_identity_fields(
    release_manifest: Workspace100ReleaseManifest,
    field: str,
    value: str,
    message: str,
) -> None:
    raw = _manifest_raw(release_manifest)
    raw[field] = value
    with pytest.raises(ValueError, match=message):
        Workspace100ReleaseManifest.from_canonical_bytes(_canonical(raw))


def test_manifest_parser_rejects_open_and_missing_top_level_fields(
    release_manifest: Workspace100ReleaseManifest,
) -> None:
    open_payload = _manifest_raw(release_manifest)
    open_payload["signature"] = {"algorithm": "none"}
    with pytest.raises(ValueError, match="unknown or missing"):
        Workspace100ReleaseManifest.from_canonical_bytes(
            _canonical(open_payload)
        )

    missing_payload = _manifest_raw(release_manifest)
    del missing_payload["bindings"]
    with pytest.raises(ValueError, match="unknown or missing"):
        Workspace100ReleaseManifest.from_canonical_bytes(
            _canonical(missing_payload)
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda payload: payload.rstrip(b"\n"),
        lambda payload: b" " + payload,
        lambda payload: payload + b"\n",
    ],
)
def test_manifest_parser_rejects_noncanonical_bytes(
    release_manifest: Workspace100ReleaseManifest,
    mutation: Callable[[bytes], bytes],
) -> None:
    noncanonical = mutation(release_manifest.to_canonical_bytes())
    with pytest.raises(ValueError, match="canonical"):
        Workspace100ReleaseManifest.from_canonical_bytes(noncanonical)


def test_manifest_parser_rejects_float_oversize_and_malformed_json(
    release_manifest: Workspace100ReleaseManifest,
) -> None:
    with_float = _manifest_raw(release_manifest)
    files = _array(with_float["files"])
    first = _object(files[0])
    first["byte_length"] = 1.5
    nesting_depth = 2_000
    deeply_nested = (
        b'{"unexpected":'
        + (b"[" * nesting_depth)
        + b"0"
        + (b"]" * nesting_depth)
        + b"}\n"
    )

    invalid_payloads = (
        _json_with_float(with_float),
        b"{" * (_MAX_MANIFEST_BYTES + 1),
        b"{\n",
        b"[]\n",
        b'{"release_kind":"\\ud800"}\n',
        deeply_nested,
    )
    for payload in invalid_payloads:
        with pytest.raises(ValueError):
            Workspace100ReleaseManifest.from_canonical_bytes(payload)


def test_manifest_rejects_reordered_duplicate_or_missing_inventory(
    release_manifest: Workspace100ReleaseManifest,
) -> None:
    with pytest.raises(ValueError, match="canonical layout order"):
        replace(release_manifest, files=tuple(reversed(release_manifest.files)))

    duplicate = (
        release_manifest.files[0],
        release_manifest.files[0],
        *release_manifest.files[2:],
    )
    with pytest.raises(ValueError, match="canonical layout order"):
        replace(release_manifest, files=duplicate)

    with pytest.raises(TypeError, match="exact payload file inventory"):
        replace(release_manifest, files=release_manifest.files[:-1])


def test_manifest_rejects_file_semantic_root_substitution(
    release_manifest: Workspace100ReleaseManifest,
) -> None:
    files = (
        replace(
            release_manifest.files[0],
            semantic_root=_digest("substituted protocol root"),
        ),
        *release_manifest.files[1:],
    )
    with pytest.raises(ValueError, match="semantic roots"):
        replace(release_manifest, files=files)


def test_manifest_rejects_swapped_anchor_and_panel_semantic_roots(
    release_manifest: Workspace100ReleaseManifest,
) -> None:
    anchor_index = RELEASE_PAYLOAD_PATHS.index(
        "verified/trust-anchors.jsonl"
    )
    panel_index = RELEASE_PAYLOAD_PATHS.index("verified/panels.jsonl")
    files = list(release_manifest.files)
    anchor = files[anchor_index]
    panel = files[panel_index]
    files[anchor_index] = replace(anchor, semantic_root=panel.semantic_root)
    files[panel_index] = replace(panel, semantic_root=anchor.semantic_root)

    with pytest.raises(ValueError, match="semantic roots"):
        replace(release_manifest, files=tuple(files))


def test_manifest_rejects_missing_trust_anchor_artifact(
    release_manifest: Workspace100ReleaseManifest,
) -> None:
    anchor_index = RELEASE_PAYLOAD_PATHS.index(
        "verified/trust-anchors.jsonl"
    )
    files = (
        *release_manifest.files[:anchor_index],
        *release_manifest.files[anchor_index + 1 :],
    )

    with pytest.raises(TypeError, match="exact payload file inventory"):
        replace(release_manifest, files=files)


@pytest.mark.parametrize(
    "field",
    [
        "backend_implementation_digest",
        "runtime_root",
        "limits_root",
        "isolation_policy_root",
    ],
)
def test_manifest_rejects_execution_binding_substitution(
    release_manifest: Workspace100ReleaseManifest,
    field: str,
) -> None:
    bindings = replace(
        release_manifest.bindings,
        **{field: _digest(f"substituted {field}")},
    )
    with pytest.raises(ValueError, match="execution configuration"):
        replace(release_manifest, bindings=bindings)


@pytest.mark.parametrize(
    "field",
    ["artifact_tree_root", "release_root"],
)
def test_manifest_parser_rejects_top_level_stored_root_tampering(
    release_manifest: Workspace100ReleaseManifest,
    field: str,
) -> None:
    raw = _manifest_raw(release_manifest)
    raw[field] = "0" * 64
    with pytest.raises(ValueError, match="stored roots"):
        Workspace100ReleaseManifest.from_canonical_bytes(_canonical(raw))


def test_manifest_parser_rejects_nested_stored_root_tampering(
    release_manifest: Workspace100ReleaseManifest,
) -> None:
    mutations = (
        ("execution_configuration", "execution_configuration_root"),
        ("execution_configuration", "runtime_root"),
        ("execution_configuration", "limits_root"),
        ("execution_configuration", "isolation_policy_root"),
    )
    for parent, field in mutations:
        raw = _manifest_raw(release_manifest)
        _object(raw[parent])[field] = "0" * 64
        with pytest.raises(ValueError):
            Workspace100ReleaseManifest.from_canonical_bytes(_canonical(raw))

    raw = _manifest_raw(release_manifest)
    execution = _object(raw["execution_configuration"])
    runtime = _object(execution["runtime_identity"])
    runtime["runtime_root"] = "0" * 64
    with pytest.raises(ValueError, match="runtime identity root"):
        Workspace100ReleaseManifest.from_canonical_bytes(_canonical(raw))

    raw = _manifest_raw(release_manifest)
    execution = _object(raw["execution_configuration"])
    policy = _object(execution["isolation_policy"])
    policy["isolation_policy_root"] = "0" * 64
    with pytest.raises(ValueError, match="isolation policy root"):
        Workspace100ReleaseManifest.from_canonical_bytes(_canonical(raw))


def test_manifest_parser_rejects_descriptor_tampering_without_reroot(
    release_manifest: Workspace100ReleaseManifest,
) -> None:
    for field, value in (
        ("byte_length", release_manifest.files[0].byte_length + 1),
        ("content_digest", _digest("substituted content")),
        ("mode", 0o644),
    ):
        raw = _manifest_raw(release_manifest)
        first = _object(_array(raw["files"])[0])
        first[field] = value
        with pytest.raises(ValueError):
            Workspace100ReleaseManifest.from_canonical_bytes(_canonical(raw))


def test_coherent_reroot_is_structurally_valid_but_not_externally_pinned(
    release_manifest: Workspace100ReleaseManifest,
) -> None:
    trusted_root = release_manifest.release_root
    modified_files = (
        replace(
            release_manifest.files[0],
            content_digest=_digest("attacker controlled protocol bytes"),
        ),
        *release_manifest.files[1:],
    )
    coherently_rewritten = replace(
        release_manifest,
        files=modified_files,
    )

    parsed = Workspace100ReleaseManifest.from_canonical_bytes(
        coherently_rewritten.to_canonical_bytes()
    )
    assert parsed == coherently_rewritten
    assert parsed.artifact_tree_root != release_manifest.artifact_tree_root
    assert parsed.release_root != trusted_root
    assert trusted_root == release_manifest.release_root


def test_root_layers_change_at_the_expected_boundaries(
    release_manifest: Workspace100ReleaseManifest,
) -> None:
    content_changed = replace(
        release_manifest,
        files=(
            replace(
                release_manifest.files[0],
                content_digest=_digest("different exact bytes"),
            ),
            *release_manifest.files[1:],
        ),
    )
    assert content_changed.bindings == release_manifest.bindings
    assert (
        content_changed.artifact_tree_root
        != release_manifest.artifact_tree_root
    )
    assert content_changed.release_root != release_manifest.release_root

    new_generation_root = _digest("different generation provenance")
    generation_changed = replace(
        release_manifest,
        generation_provenance_root=new_generation_root,
        files=(
            *release_manifest.files[:4],
            replace(
                release_manifest.files[4],
                semantic_root=new_generation_root,
            ),
            *release_manifest.files[5:],
        ),
    )
    assert (
        generation_changed.artifact_tree_root
        != release_manifest.artifact_tree_root
    )
    assert generation_changed.release_root != release_manifest.release_root


def test_release_implementation_digest_is_one_stable_sha256() -> None:
    first = workspace100_release_implementation_digest()
    second = workspace100_release_implementation_digest()

    assert first == second
    assert len(first) == _SHA256_HEX_LENGTH
    assert set(first) <= set("0123456789abcdef")


def test_release_schema_is_not_exported_through_workspace100_initializer() -> None:
    forbidden = {
        "Workspace100ExecutionConfiguration",
        "Workspace100IsolationPolicy",
        "Workspace100ReleaseBindings",
        "Workspace100ReleaseFile",
        "Workspace100ReleaseManifest",
        "Workspace100RuntimeIdentity",
        "workspace100_release_implementation_digest",
    }

    assert forbidden.isdisjoint(workspace100.__all__)
    assert forbidden.isdisjoint(vars(workspace100))
