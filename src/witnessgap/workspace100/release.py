"""Closed records for an authenticated Workspace-100 release candidate.

This module defines integrity records only.  A structurally valid manifest is
not a signature, an execution attestation, or evidence that hostile participant
code was contained.  Callers must obtain an expected release root through an
independent authenticated channel and use the verified directory loader.

The v1 candidate is deliberately limited to the four frozen, reviewed
baselines.  Its isolation policy records that release gate 16 is not
established; there is no public-third-party release constructor in this module.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import cast

from witnessgap.canonical import (
    JsonValue,
    canonical_digest,
    canonical_json,
    tagged_digest,
)
from witnessgap.source import package_implementation_digest
from witnessgap.workspace100.records import PROTOCOL_ID
from witnessgap.workspace100.worker import WorkerLimits

RUNTIME_IDENTITY_FORMAT = "witnessgap.workspace100-runtime-identity.v1"
ISOLATION_POLICY_FORMAT = "witnessgap.workspace100-isolation-policy.v1"
EXECUTION_CONFIGURATION_FORMAT = (
    "witnessgap.workspace100-execution-configuration.v1"
)
RELEASE_BINDINGS_FORMAT = "witnessgap.workspace100-release-bindings.v1"
RELEASE_FILE_FORMAT = "witnessgap.workspace100-release-file.v1"
RELEASE_TREE_FORMAT = "witnessgap.workspace100-release-tree.v1"
RELEASE_MANIFEST_FORMAT = "witnessgap.workspace100-release-manifest.v1"
RELEASE_FILE_CONTENT_DOMAIN = (
    "witnessgap.workspace100-release-file-content.v1"
)
RELEASE_KIND = "pre_release_reproducibility_candidate"
GATE16_STATUS = "not_established"
RELEASE_DIRECTORY = "workspace100/v1"
RELEASE_MANIFEST_PATH = "release-manifest.json"
RELEASE_FILE_MODE = 0o444
RELEASE_DIRECTORY_MODE = 0o555

RELEASE_PAYLOAD_PATHS = (
    "protocol.json",
    "baselines/baseline-set.json",
    "authored/templates.json",
    "authored/variants.json",
    "sealed/generation.json",
    "sealed/sources.jsonl",
    "registries.jsonl",
    "verified/trust-anchors.jsonl",
    "verified/panels.jsonl",
    "public/views.jsonl",
    "truth/labels.jsonl",
    "results/claims.json",
    "results/report.json",
)
RELEASE_LAYOUT_PATHS = (*RELEASE_PAYLOAD_PATHS, RELEASE_MANIFEST_PATH)

_RELEASE_IMPLEMENTATION_DOMAIN = (
    "witnessgap.workspace100-release-implementation.v1"
)
_RELEASE_IMPLEMENTATION_PATHS = (
    "__init__.py",
    "adapters.py",
    "canonical.py",
    "identifiability.py",
    "model.py",
    "source.py",
    "trust.py",
    "verifier.py",
    "workspace100/__init__.py",
    "workspace100/baselines.py",
    "workspace100/catalog.py",
    "workspace100/claims.py",
    "workspace100/evidence.py",
    "workspace100/generation.py",
    "workspace100/records.py",
    "workspace100/release.py",
    "workspace100/release_io.py",
    "workspace100/release_storage.py",
    "workspace100/runtime.py",
    "workspace100/scoring.py",
    "workspace100/truth.py",
    "workspace100/views.py",
    "workspace100/worker.py",
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{0,95}$")
_MAX_TEXT_LENGTH = 240
_MAX_MANIFEST_BYTES = 1 << 20
_MAX_RELEASE_FILE_BYTES = 64 << 20
_MAX_RELEASE_TREE_BYTES = 256 << 20
_EXPECTED_FILE_COUNT = len(RELEASE_PAYLOAD_PATHS)
_ASCII_PRINTABLE_MIN = 32
_ASCII_PRINTABLE_MAX = 126

_LOCAL_POLICY_ID = "local_python_trusted_builtins_v1"
_LOCAL_PARTICIPANT_SCOPE = "frozen_reviewed_builtins_only"
_LOCAL_FILESYSTEM_ISOLATION = "host_uid_access"
_LOCAL_NETWORK_ISOLATION = "not_enforced"
_LOCAL_PROCESS_ISOLATION = "process_group_lifecycle_only"
_LOCAL_HOSTILE_CODE_CONTAINMENT = GATE16_STATUS


@dataclass(frozen=True, slots=True)
class Workspace100RuntimeIdentity:
    """Caller-authenticated runtime identity, not a runtime attestation."""

    runtime_id: str
    runtime_artifact_digest: str
    interpreter_digest: str
    implementation: str
    version: str

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        _require_identifier(self.runtime_id, field="runtime_id")
        _require_digest(
            self.runtime_artifact_digest,
            field="runtime_artifact_digest",
        )
        _require_digest(self.interpreter_digest, field="interpreter_digest")
        _require_text(self.implementation, field="runtime implementation")
        _require_text(self.version, field="runtime version")

    def root_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "format": RUNTIME_IDENTITY_FORMAT,
            "implementation": self.implementation,
            "interpreter_digest": self.interpreter_digest,
            "protocol_id": PROTOCOL_ID,
            "runtime_artifact_digest": self.runtime_artifact_digest,
            "runtime_id": self.runtime_id,
            "version": self.version,
        }

    @property
    def runtime_root(self) -> str:
        return canonical_digest(RUNTIME_IDENTITY_FORMAT, self.root_payload())

    def to_payload(self) -> dict[str, JsonValue]:
        payload = self.root_payload()
        payload["runtime_root"] = self.runtime_root
        return payload

    @classmethod
    def from_payload(cls, payload: object) -> Workspace100RuntimeIdentity:
        raw = _closed_object(
            payload,
            {
                "format",
                "implementation",
                "interpreter_digest",
                "protocol_id",
                "runtime_artifact_digest",
                "runtime_id",
                "runtime_root",
                "version",
            },
            label="runtime identity",
        )
        _require_format_and_protocol(
            raw,
            expected_format=RUNTIME_IDENTITY_FORMAT,
            label="runtime identity",
        )
        identity = cls(
            runtime_id=_required_string(raw, "runtime_id"),
            runtime_artifact_digest=_required_digest(
                raw,
                "runtime_artifact_digest",
            ),
            interpreter_digest=_required_digest(raw, "interpreter_digest"),
            implementation=_required_string(raw, "implementation"),
            version=_required_string(raw, "version"),
        )
        if _required_digest(raw, "runtime_root") != identity.runtime_root:
            raise ValueError("runtime identity root contradicts its record")
        return identity


@dataclass(frozen=True, slots=True)
class Workspace100IsolationPolicy:
    """Honest v1 policy for reviewed built-ins; gate 16 remains open."""

    policy_id: str = _LOCAL_POLICY_ID
    participant_scope: str = _LOCAL_PARTICIPANT_SCOPE
    filesystem_isolation: str = _LOCAL_FILESYSTEM_ISOLATION
    network_isolation: str = _LOCAL_NETWORK_ISOLATION
    process_isolation: str = _LOCAL_PROCESS_ISOLATION
    hostile_code_containment: str = _LOCAL_HOSTILE_CODE_CONTAINMENT

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        expected = (
            _LOCAL_POLICY_ID,
            _LOCAL_PARTICIPANT_SCOPE,
            _LOCAL_FILESYSTEM_ISOLATION,
            _LOCAL_NETWORK_ISOLATION,
            _LOCAL_PROCESS_ISOLATION,
            _LOCAL_HOSTILE_CODE_CONTAINMENT,
        )
        actual = (
            self.policy_id,
            self.participant_scope,
            self.filesystem_isolation,
            self.network_isolation,
            self.process_isolation,
            self.hostile_code_containment,
        )
        if actual != expected:
            raise ValueError(
                "v1 release candidates require the exact non-containment policy"
            )

    def root_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "filesystem_isolation": self.filesystem_isolation,
            "format": ISOLATION_POLICY_FORMAT,
            "hostile_code_containment": self.hostile_code_containment,
            "network_isolation": self.network_isolation,
            "participant_scope": self.participant_scope,
            "policy_id": self.policy_id,
            "process_isolation": self.process_isolation,
            "protocol_id": PROTOCOL_ID,
        }

    @property
    def isolation_policy_root(self) -> str:
        return canonical_digest(ISOLATION_POLICY_FORMAT, self.root_payload())

    def to_payload(self) -> dict[str, JsonValue]:
        payload = self.root_payload()
        payload["isolation_policy_root"] = self.isolation_policy_root
        return payload

    @classmethod
    def from_payload(cls, payload: object) -> Workspace100IsolationPolicy:
        raw = _closed_object(
            payload,
            {
                "filesystem_isolation",
                "format",
                "hostile_code_containment",
                "isolation_policy_root",
                "network_isolation",
                "participant_scope",
                "policy_id",
                "process_isolation",
                "protocol_id",
            },
            label="isolation policy",
        )
        _require_format_and_protocol(
            raw,
            expected_format=ISOLATION_POLICY_FORMAT,
            label="isolation policy",
        )
        policy = cls(
            policy_id=_required_string(raw, "policy_id"),
            participant_scope=_required_string(raw, "participant_scope"),
            filesystem_isolation=_required_string(
                raw,
                "filesystem_isolation",
            ),
            network_isolation=_required_string(raw, "network_isolation"),
            process_isolation=_required_string(raw, "process_isolation"),
            hostile_code_containment=_required_string(
                raw,
                "hostile_code_containment",
            ),
        )
        if (
            _required_digest(raw, "isolation_policy_root")
            != policy.isolation_policy_root
        ):
            raise ValueError("isolation policy root contradicts its record")
        return policy


@dataclass(frozen=True, slots=True)
class Workspace100ExecutionConfiguration:
    """Exact runtime, limits, backend, and non-containment policy snapshot."""

    runtime_identity: Workspace100RuntimeIdentity
    limits: WorkerLimits
    isolation_policy: Workspace100IsolationPolicy
    backend_implementation_digest: str

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if type(self.runtime_identity) is not Workspace100RuntimeIdentity:
            raise TypeError(
                "execution configuration requires an exact runtime identity"
            )
        self.runtime_identity.validate()
        if type(self.limits) is not WorkerLimits:
            raise TypeError("execution configuration requires exact limits")
        self.limits.validate()
        if type(self.isolation_policy) is not Workspace100IsolationPolicy:
            raise TypeError(
                "execution configuration requires an exact isolation policy"
            )
        self.isolation_policy.validate()
        _require_digest(
            self.backend_implementation_digest,
            field="backend_implementation_digest",
        )

    def root_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "backend_implementation_digest": (
                self.backend_implementation_digest
            ),
            "format": EXECUTION_CONFIGURATION_FORMAT,
            "isolation_policy": self.isolation_policy.to_payload(),
            "isolation_policy_root": (
                self.isolation_policy.isolation_policy_root
            ),
            "limits": self.limits.to_payload(),
            "limits_root": self.limits.digest,
            "protocol_id": PROTOCOL_ID,
            "runtime_identity": self.runtime_identity.to_payload(),
            "runtime_root": self.runtime_identity.runtime_root,
        }

    @property
    def execution_configuration_root(self) -> str:
        return canonical_digest(
            EXECUTION_CONFIGURATION_FORMAT,
            self.root_payload(),
        )

    def to_payload(self) -> dict[str, JsonValue]:
        payload = self.root_payload()
        payload["execution_configuration_root"] = (
            self.execution_configuration_root
        )
        return payload

    @classmethod
    def from_payload(
        cls,
        payload: object,
    ) -> Workspace100ExecutionConfiguration:
        raw = _closed_object(
            payload,
            {
                "backend_implementation_digest",
                "execution_configuration_root",
                "format",
                "isolation_policy",
                "isolation_policy_root",
                "limits",
                "limits_root",
                "protocol_id",
                "runtime_identity",
                "runtime_root",
            },
            label="execution configuration",
        )
        _require_format_and_protocol(
            raw,
            expected_format=EXECUTION_CONFIGURATION_FORMAT,
            label="execution configuration",
        )
        runtime = Workspace100RuntimeIdentity.from_payload(
            raw["runtime_identity"]
        )
        policy = Workspace100IsolationPolicy.from_payload(
            raw["isolation_policy"]
        )
        limits = WorkerLimits.from_payload(raw["limits"])
        configuration = cls(
            runtime_identity=runtime,
            limits=limits,
            isolation_policy=policy,
            backend_implementation_digest=_required_digest(
                raw,
                "backend_implementation_digest",
            ),
        )
        stored = (
            _required_digest(raw, "runtime_root"),
            _required_digest(raw, "limits_root"),
            _required_digest(raw, "isolation_policy_root"),
            _required_digest(raw, "execution_configuration_root"),
        )
        expected = (
            runtime.runtime_root,
            limits.digest,
            policy.isolation_policy_root,
            configuration.execution_configuration_root,
        )
        if stored != expected:
            raise ValueError(
                "execution configuration stored roots contradict its records"
            )
        return configuration


@dataclass(frozen=True, slots=True)
class Workspace100ReleaseBindings:
    """Direct content identities required by release gate 17."""

    protocol_root: str
    public_vocabulary_digest: str
    baseline_set_root: str
    template_catalog_digest: str
    variant_catalog_digest: str
    source_root: str
    registry_root: str
    panel_root: str
    assignment_root: str
    evidence_root: str
    projection_root: str
    truth_root: str
    claim_set_root: str
    report_root: str
    adapter_implementation_digest: str
    verifier_implementation_digest: str
    worker_implementation_digest: str
    claims_implementation_digest: str
    scoring_implementation_digest: str
    backend_implementation_digest: str
    runtime_root: str
    limits_root: str
    isolation_policy_root: str
    trust_anchor_root: str
    release_builder_implementation_digest: str

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        for field, value in self._items():
            _require_digest(value, field=f"release binding {field}")

    def _items(self) -> tuple[tuple[str, str], ...]:
        return (
            ("protocol_root", self.protocol_root),
            ("public_vocabulary_digest", self.public_vocabulary_digest),
            ("baseline_set_root", self.baseline_set_root),
            ("template_catalog_digest", self.template_catalog_digest),
            ("variant_catalog_digest", self.variant_catalog_digest),
            ("source_root", self.source_root),
            ("registry_root", self.registry_root),
            ("panel_root", self.panel_root),
            ("assignment_root", self.assignment_root),
            ("evidence_root", self.evidence_root),
            ("projection_root", self.projection_root),
            ("truth_root", self.truth_root),
            ("claim_set_root", self.claim_set_root),
            ("report_root", self.report_root),
            (
                "adapter_implementation_digest",
                self.adapter_implementation_digest,
            ),
            (
                "verifier_implementation_digest",
                self.verifier_implementation_digest,
            ),
            (
                "worker_implementation_digest",
                self.worker_implementation_digest,
            ),
            (
                "claims_implementation_digest",
                self.claims_implementation_digest,
            ),
            (
                "scoring_implementation_digest",
                self.scoring_implementation_digest,
            ),
            (
                "backend_implementation_digest",
                self.backend_implementation_digest,
            ),
            ("runtime_root", self.runtime_root),
            ("limits_root", self.limits_root),
            ("isolation_policy_root", self.isolation_policy_root),
            ("trust_anchor_root", self.trust_anchor_root),
            (
                "release_builder_implementation_digest",
                self.release_builder_implementation_digest,
            ),
        )

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        payload: dict[str, JsonValue] = {
            "format": RELEASE_BINDINGS_FORMAT,
            "protocol_id": PROTOCOL_ID,
        }
        payload.update(dict(self._items()))
        return payload

    @classmethod
    def from_payload(cls, payload: object) -> Workspace100ReleaseBindings:
        field_names = {
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
        raw = _closed_object(
            payload,
            {"format", "protocol_id", *field_names},
            label="release bindings",
        )
        _require_format_and_protocol(
            raw,
            expected_format=RELEASE_BINDINGS_FORMAT,
            label="release bindings",
        )
        values = {
            field: _required_digest(raw, field) for field in field_names
        }
        return cls(
            protocol_root=values["protocol_root"],
            public_vocabulary_digest=values["public_vocabulary_digest"],
            baseline_set_root=values["baseline_set_root"],
            template_catalog_digest=values["template_catalog_digest"],
            variant_catalog_digest=values["variant_catalog_digest"],
            source_root=values["source_root"],
            registry_root=values["registry_root"],
            panel_root=values["panel_root"],
            assignment_root=values["assignment_root"],
            evidence_root=values["evidence_root"],
            projection_root=values["projection_root"],
            truth_root=values["truth_root"],
            claim_set_root=values["claim_set_root"],
            report_root=values["report_root"],
            adapter_implementation_digest=values[
                "adapter_implementation_digest"
            ],
            verifier_implementation_digest=values[
                "verifier_implementation_digest"
            ],
            worker_implementation_digest=values[
                "worker_implementation_digest"
            ],
            claims_implementation_digest=values[
                "claims_implementation_digest"
            ],
            scoring_implementation_digest=values[
                "scoring_implementation_digest"
            ],
            backend_implementation_digest=values[
                "backend_implementation_digest"
            ],
            runtime_root=values["runtime_root"],
            limits_root=values["limits_root"],
            isolation_policy_root=values["isolation_policy_root"],
            trust_anchor_root=values["trust_anchor_root"],
            release_builder_implementation_digest=values[
                "release_builder_implementation_digest"
            ],
        )


@dataclass(frozen=True, slots=True)
class Workspace100ReleaseFile:
    """One exact payload file committed by the release tree root."""

    path: str
    byte_length: int
    content_digest: str
    semantic_root: str
    mode: int = RELEASE_FILE_MODE

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if type(self.path) is not str or self.path not in RELEASE_PAYLOAD_PATHS:
            raise ValueError("release file path is outside the frozen allowlist")
        _bounded_integer(
            self.byte_length,
            field="release file byte_length",
            minimum=1,
            maximum=_MAX_RELEASE_FILE_BYTES,
        )
        _require_digest(self.content_digest, field="release file content_digest")
        _require_digest(self.semantic_root, field="release file semantic_root")
        if type(self.mode) is not int or self.mode != RELEASE_FILE_MODE:
            raise ValueError("release payload file mode must be exactly 0444")

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "byte_length": self.byte_length,
            "content_digest": self.content_digest,
            "format": RELEASE_FILE_FORMAT,
            "mode": self.mode,
            "path": self.path,
            "semantic_root": self.semantic_root,
        }

    @classmethod
    def from_payload(cls, payload: object) -> Workspace100ReleaseFile:
        raw = _closed_object(
            payload,
            {
                "byte_length",
                "content_digest",
                "format",
                "mode",
                "path",
                "semantic_root",
            },
            label="release file",
        )
        if raw["format"] != RELEASE_FILE_FORMAT:
            raise ValueError("release file format is unsupported")
        return cls(
            path=_required_string(raw, "path"),
            byte_length=_required_bounded_integer(
                raw,
                "byte_length",
                minimum=1,
                maximum=_MAX_RELEASE_FILE_BYTES,
            ),
            content_digest=_required_digest(raw, "content_digest"),
            semantic_root=_required_digest(raw, "semantic_root"),
            mode=_required_bounded_integer(
                raw,
                "mode",
                minimum=0,
                maximum=0o777,
            ),
        )


@dataclass(frozen=True, slots=True)
class Workspace100ReleaseManifest:
    """Closed pre-release manifest with no self-authentication claim."""

    generation_provenance_root: str
    execution_configuration: Workspace100ExecutionConfiguration
    bindings: Workspace100ReleaseBindings
    files: tuple[Workspace100ReleaseFile, ...]

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        _require_digest(
            self.generation_provenance_root,
            field="generation_provenance_root",
        )
        if (
            type(self.execution_configuration)
            is not Workspace100ExecutionConfiguration
        ):
            raise TypeError("release manifest requires exact execution config")
        self.execution_configuration.validate()
        if type(self.bindings) is not Workspace100ReleaseBindings:
            raise TypeError("release manifest requires exact release bindings")
        self.bindings.validate()
        if (
            type(self.files) is not tuple
            or len(self.files) != _EXPECTED_FILE_COUNT
            or any(
                type(record) is not Workspace100ReleaseFile
                for record in self.files
            )
        ):
            raise TypeError(
                "release manifest requires the exact payload file inventory"
            )
        for record in self.files:
            record.validate()
        paths = tuple(record.path for record in self.files)
        if paths != RELEASE_PAYLOAD_PATHS:
            raise ValueError(
                "release file inventory differs from canonical layout order"
            )
        total_bytes = sum(record.byte_length for record in self.files)
        if total_bytes > _MAX_RELEASE_TREE_BYTES:
            raise ValueError("release payload tree exceeds its byte bound")
        self._validate_execution_bindings()
        self._validate_semantic_roots()

    def _validate_execution_bindings(self) -> None:
        configuration = self.execution_configuration
        actual = (
            self.bindings.backend_implementation_digest,
            self.bindings.runtime_root,
            self.bindings.limits_root,
            self.bindings.isolation_policy_root,
        )
        expected = (
            configuration.backend_implementation_digest,
            configuration.runtime_identity.runtime_root,
            configuration.limits.digest,
            configuration.isolation_policy.isolation_policy_root,
        )
        if actual != expected:
            raise ValueError(
                "release bindings contradict the execution configuration"
            )

    def _validate_semantic_roots(self) -> None:
        expected = (
            self.bindings.protocol_root,
            self.bindings.baseline_set_root,
            self.bindings.template_catalog_digest,
            self.bindings.variant_catalog_digest,
            self.generation_provenance_root,
            self.bindings.source_root,
            self.bindings.registry_root,
            self.bindings.trust_anchor_root,
            self.bindings.panel_root,
            self.bindings.evidence_root,
            self.bindings.truth_root,
            self.bindings.claim_set_root,
            self.bindings.report_root,
        )
        actual = tuple(record.semantic_root for record in self.files)
        if actual != expected:
            raise ValueError(
                "release file semantic roots contradict release bindings"
            )

    @property
    def artifact_tree_root(self) -> str:
        self.validate()
        return canonical_digest(
            RELEASE_TREE_FORMAT,
            {
                "files": tuple(record.to_payload() for record in self.files),
                "format": RELEASE_TREE_FORMAT,
                "protocol_id": PROTOCOL_ID,
                "release_directory": RELEASE_DIRECTORY,
            },
        )

    def root_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "artifact_tree_root": self.artifact_tree_root,
            "bindings": self.bindings.to_payload(),
            "execution_configuration": (
                self.execution_configuration.to_payload()
            ),
            "files": tuple(record.to_payload() for record in self.files),
            "format": RELEASE_MANIFEST_FORMAT,
            "gate16_status": GATE16_STATUS,
            "generation_provenance_root": (
                self.generation_provenance_root
            ),
            "protocol_id": PROTOCOL_ID,
            "release_directory": RELEASE_DIRECTORY,
            "release_kind": RELEASE_KIND,
        }

    @property
    def release_root(self) -> str:
        return canonical_digest(
            RELEASE_MANIFEST_FORMAT,
            self.root_payload(),
        )

    def to_payload(self) -> dict[str, JsonValue]:
        payload = self.root_payload()
        payload["release_root"] = self.release_root
        return payload

    def to_canonical_bytes(self) -> bytes:
        payload = canonical_json(self.to_payload())
        if len(payload) > _MAX_MANIFEST_BYTES:
            raise ValueError("release manifest exceeds its byte bound")
        return payload

    @classmethod
    def from_canonical_bytes(
        cls,
        payload: bytes,
    ) -> Workspace100ReleaseManifest:
        """Parse structural integrity only; expected roots remain external."""

        raw = _canonical_object(
            payload,
            label="release manifest",
            maximum_bytes=_MAX_MANIFEST_BYTES,
        )
        expected_fields = {
            "artifact_tree_root",
            "bindings",
            "execution_configuration",
            "files",
            "format",
            "gate16_status",
            "generation_provenance_root",
            "protocol_id",
            "release_directory",
            "release_kind",
            "release_root",
        }
        if set(raw) != expected_fields:
            raise ValueError(
                "release manifest contains unknown or missing fields"
            )
        _require_format_and_protocol(
            raw,
            expected_format=RELEASE_MANIFEST_FORMAT,
            label="release manifest",
        )
        if raw["release_kind"] != RELEASE_KIND:
            raise ValueError("release manifest kind is unsupported")
        if raw["gate16_status"] != GATE16_STATUS:
            raise ValueError(
                "v1 release manifest cannot claim gate 16 containment"
            )
        if raw["release_directory"] != RELEASE_DIRECTORY:
            raise ValueError("release manifest directory is unsupported")
        files_raw = raw["files"]
        if type(files_raw) is not list or len(files_raw) != _EXPECTED_FILE_COUNT:
            raise ValueError(
                "release manifest files must be the exact payload array"
            )
        manifest = cls(
            generation_provenance_root=_required_digest(
                raw,
                "generation_provenance_root",
            ),
            execution_configuration=(
                Workspace100ExecutionConfiguration.from_payload(
                    raw["execution_configuration"]
                )
            ),
            bindings=Workspace100ReleaseBindings.from_payload(
                raw["bindings"]
            ),
            files=tuple(
                Workspace100ReleaseFile.from_payload(record)
                for record in files_raw
            ),
        )
        stored_roots = (
            _required_digest(raw, "artifact_tree_root"),
            _required_digest(raw, "release_root"),
        )
        expected_roots = (
            manifest.artifact_tree_root,
            manifest.release_root,
        )
        if stored_roots != expected_roots:
            raise ValueError("release manifest stored roots are inconsistent")
        if manifest.to_canonical_bytes() != payload:
            raise ValueError("release manifest failed canonical round-trip")
        return manifest


def workspace100_release_implementation_digest() -> str:
    """Bind the installed evaluator-side release implementation closure."""

    return package_implementation_digest(
        _RELEASE_IMPLEMENTATION_DOMAIN,
        _RELEASE_IMPLEMENTATION_PATHS,
    )


def workspace100_release_file_content_digest(payload: bytes) -> str:
    """Bind exact payload bytes independently of their semantic root."""

    if type(payload) is not bytes:
        raise TypeError("release file payload must be exact bytes")
    if not payload or len(payload) > _MAX_RELEASE_FILE_BYTES:
        raise ValueError("release file payload exceeds its byte bound")
    return tagged_digest(RELEASE_FILE_CONTENT_DOMAIN, payload)


def _canonical_object(
    payload: bytes,
    *,
    label: str,
    maximum_bytes: int,
) -> dict[str, object]:
    if type(payload) is not bytes:
        raise TypeError(f"{label} payload must be exact bytes")
    if not payload or len(payload) > maximum_bytes:
        raise ValueError(f"{label} payload exceeds its byte bound")
    try:
        parsed: object = json.loads(payload)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
    ) as error:
        raise ValueError(f"{label} is not valid bounded JSON") from error
    if type(parsed) is not dict:
        raise ValueError(f"{label} must be one JSON object")
    try:
        encoded = canonical_json(cast(JsonValue, parsed))
    except (TypeError, ValueError, RecursionError) as error:
        raise ValueError(f"{label} is not canonical JSON") from error
    if encoded != payload:
        raise ValueError(f"{label} is not exact canonical JSON")
    return cast(dict[str, object], parsed)


def _closed_object(
    payload: object,
    fields: set[str],
    *,
    label: str,
) -> dict[str, object]:
    if type(payload) is not dict or set(payload) != fields:
        raise ValueError(f"{label} contains unknown or missing fields")
    return cast(dict[str, object], payload)


def _require_format_and_protocol(
    raw: dict[str, object],
    *,
    expected_format: str,
    label: str,
) -> None:
    if raw["format"] != expected_format:
        raise ValueError(f"{label} format is unsupported")
    if raw["protocol_id"] != PROTOCOL_ID:
        raise ValueError(f"{label} protocol is unsupported")


def _require_identifier(value: object, *, field: str) -> None:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{field} must be an exact lowercase identifier")


def _require_text(value: object, *, field: str) -> None:
    if (
        type(value) is not str
        or not value
        or len(value) > _MAX_TEXT_LENGTH
        or "/" in value
        or "\\" in value
        or any(
            ord(character) < _ASCII_PRINTABLE_MIN
            or ord(character) > _ASCII_PRINTABLE_MAX
            for character in value
        )
    ):
        raise ValueError(
            f"{field} must be bounded path-free printable ASCII"
        )


def _require_digest(value: object, *, field: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")


def _required_string(raw: dict[str, object], field: str) -> str:
    value = raw[field]
    if type(value) is not str:
        raise ValueError(f"{field} must be an exact string")
    return value


def _required_digest(raw: dict[str, object], field: str) -> str:
    value = _required_string(raw, field)
    _require_digest(value, field=field)
    return value


def _bounded_integer(
    value: object,
    *,
    field: str,
    minimum: int,
    maximum: int,
) -> None:
    if (
        type(value) is not int
        or isinstance(value, bool)
        or value < minimum
        or value > maximum
    ):
        raise ValueError(
            f"{field} must be an integer from {minimum} through {maximum}"
        )


def _required_bounded_integer(
    raw: dict[str, object],
    field: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    value = raw[field]
    _bounded_integer(
        value,
        field=field,
        minimum=minimum,
        maximum=maximum,
    )
    return cast(int, value)
