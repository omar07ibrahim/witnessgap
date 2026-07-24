"""Pinned stdlib-only baseline bundles for the Workspace-100 protocol.

This is a trusted-parent authoring module.  Each returned program is a
standalone source file: the participant process receives that file and one
``PublicEvidenceEnvelope` only.  It never imports WitnessGap or reads a
repository resource.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from witnessgap.canonical import JsonValue, canonical_digest, canonical_json
from witnessgap.workspace100.records import PROTOCOL_ID
from witnessgap.workspace100.worker import WorkerProgram, python_worker_program_digest

BASELINE_ARTIFACT_FORMAT = "witnessgap.workspace100-baseline-artifact.v1"
BASELINE_BUNDLE_FORMAT = "witnessgap.workspace100-baseline-bundle.v1"
BASELINE_SET_FORMAT = "witnessgap.workspace100-baseline-set.v1"
PUBLIC_BASELINE_VOCABULARY_FORMAT = (
    "witnessgap.workspace100-public-baseline-vocabulary.v1"
)
PUBLIC_BASELINE_VOCABULARY_DIGEST = (
    "62be02f2222129a1d72aaa5329d0f1e687f1014326e91cbbf7b5141973c651dd"
)
BUILTIN_BASELINE_SET_ROOT = (
    "f8e5c3aadd426220d52d797cef178efc5aec51cd788092749cf46cf7edf53d4d"
)

_BASELINE_BUNDLE_DOMAIN = "witnessgap.workspace100-baseline-bundle.v1"
_PUBLIC_VOCABULARY_DOMAIN = "witnessgap.workspace100-public-baseline-vocabulary.v1"
_MAX_BASELINE_SET_BYTES = 1 << 20
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_LOWER_HEX = re.compile(r"^[0-9a-f]+$")
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{0,95}$")
_TEMPLATE_COUNT = 5


class BuiltinBaseline(StrEnum):
    """Frozen reference methods in release order."""

    ALWAYS_UNKNOWN = "always_unknown"
    FORCED_ENVIRONMENT = "forced_environment"
    REFRESH_SUCCESS_ONLY = "refresh_success_only"
    REFRESH_OUTCOME = "refresh_outcome"


def _expected_program_digest(baseline: BuiltinBaseline) -> str:
    if baseline is BuiltinBaseline.ALWAYS_UNKNOWN:
        return "464fc2b8de3034120857a551401a89d12b1fc8cd4e2eeafeedc4ca2416aa90f6"
    if baseline is BuiltinBaseline.FORCED_ENVIRONMENT:
        return "3bca346813676cec998857d8f406cab80533b939ce6e6f4a1a559e1740a2b90d"
    if baseline is BuiltinBaseline.REFRESH_SUCCESS_ONLY:
        return "6c813f81504177adf6dc86ea8583f104f4a395eb819df7dbd6d3c6528dd95185"
    if baseline is BuiltinBaseline.REFRESH_OUTCOME:
        return "e2ea0d5fef5e7817087c3d22508911d12bf3b9b5b9ad0cdf1890dd07c19deb02"
    raise ValueError("baseline program identity is unsupported")


@dataclass(frozen=True, order=True, slots=True)
class PublicBaselineVocabulary:
    """Public template semantics needed to emit a concrete singleton witness."""

    action_tool: str
    lookup_tool: str
    epoch_probe: str
    refresh_atom: str
    repair_atom: str

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        for field, value in (
            ("action_tool", self.action_tool),
            ("lookup_tool", self.lookup_tool),
            ("epoch_probe", self.epoch_probe),
            ("refresh_atom", self.refresh_atom),
            ("repair_atom", self.repair_atom),
        ):
            _require_identifier(value, field=f"public baseline {field}")
        if self.action_tool == self.lookup_tool:
            raise ValueError("public baseline tools must be distinct")
        if self.refresh_atom == self.repair_atom:
            raise ValueError("public baseline intervention atoms must be distinct")

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "action_tool": self.action_tool,
            "epoch_probe": self.epoch_probe,
            "lookup_tool": self.lookup_tool,
            "refresh_atom": self.refresh_atom,
            "repair_atom": self.repair_atom,
        }

    @classmethod
    def from_payload(cls, payload: object) -> PublicBaselineVocabulary:
        raw = _closed_object(
            payload,
            {
                "action_tool",
                "epoch_probe",
                "lookup_tool",
                "refresh_atom",
                "repair_atom",
            },
            label="public baseline vocabulary entry",
        )
        return cls(
            action_tool=_required_string(raw, "action_tool"),
            lookup_tool=_required_string(raw, "lookup_tool"),
            epoch_probe=_required_string(raw, "epoch_probe"),
            refresh_atom=_required_string(raw, "refresh_atom"),
            repair_atom=_required_string(raw, "repair_atom"),
        )


def _require_identifier(value: object, *, field: str) -> None:
    if type(value) is not str or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{field} must be a lowercase identifier")


PUBLIC_BASELINE_VOCABULARY = (
    PublicBaselineVocabulary(
        action_tool="book_review_slot",
        lookup_tool="resolve_review_window",
        epoch_probe="calendar_epoch",
        refresh_atom="refresh_calendar_snapshot",
        repair_atom="repair_review_selection",
    ),
    PublicBaselineVocabulary(
        action_tool="grant_workspace_access",
        lookup_tool="resolve_access_scope",
        epoch_probe="permission_catalog_epoch",
        refresh_atom="refresh_permission_catalog",
        repair_atom="repair_scope_selection",
    ),
    PublicBaselineVocabulary(
        action_tool="invite_workspace_member",
        lookup_tool="resolve_member_role",
        epoch_probe="role_catalog_epoch",
        refresh_atom="refresh_role_catalog",
        repair_atom="repair_role_selection",
    ),
    PublicBaselineVocabulary(
        action_tool="move_board_item",
        lookup_tool="resolve_board_lane",
        epoch_probe="lane_resolver_epoch",
        refresh_atom="refresh_lane_resolver",
        repair_atom="repair_lane_selection",
    ),
    PublicBaselineVocabulary(
        action_tool="publish_draft",
        lookup_tool="read_draft",
        epoch_probe="draft_store_epoch",
        refresh_atom="refresh_draft_store",
        repair_atom="repair_draft_selection",
    ),
)


@dataclass(frozen=True, slots=True)
class BuiltinBaselineBundle:
    """One reproducible participant source and its parent-side identity."""

    baseline: BuiltinBaseline

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if type(self.baseline) is not BuiltinBaseline:
            raise TypeError("baseline bundle requires an exact BuiltinBaseline")
        _validate_public_vocabulary()
        source = _render_worker_source(self.baseline)
        if (
            python_worker_program_digest(source)
            != _expected_program_digest(self.baseline)
        ):
            raise ValueError("baseline program source is not the frozen built-in source")

    @property
    def method_id(self) -> str:
        self.validate()
        return f"workspace100_{self.baseline.value}_v1"

    @property
    def program_source(self) -> bytes:
        self.validate()
        return _render_worker_source(self.baseline)

    @property
    def program_implementation_digest(self) -> str:
        return python_worker_program_digest(self.program_source)

    @property
    def worker_program(self) -> WorkerProgram:
        return WorkerProgram(
            method_id=self.method_id,
            implementation_digest=self.program_implementation_digest,
        )

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "baseline": self.baseline.value,
            "format": BASELINE_BUNDLE_FORMAT,
            "method_id": self.method_id,
            "program_implementation_digest": self.program_implementation_digest,
            "protocol_id": PROTOCOL_ID,
            "public_vocabulary_digest": public_baseline_vocabulary_digest(),
        }

    @classmethod
    def from_payload(cls, payload: object) -> BuiltinBaselineBundle:
        raw = _closed_object(
            payload,
            {
                "baseline",
                "format",
                "method_id",
                "program_implementation_digest",
                "protocol_id",
                "public_vocabulary_digest",
            },
            label="baseline bundle",
        )
        if raw["format"] != BASELINE_BUNDLE_FORMAT:
            raise ValueError("baseline bundle format is unsupported")
        if raw["protocol_id"] != PROTOCOL_ID:
            raise ValueError("baseline bundle protocol is unsupported")
        try:
            baseline = BuiltinBaseline(_required_string(raw, "baseline"))
        except ValueError as error:
            raise ValueError("baseline bundle method is unsupported") from error
        bundle = cls(baseline)
        for field, expected in (
            ("method_id", bundle.method_id),
            (
                "program_implementation_digest",
                bundle.program_implementation_digest,
            ),
            (
                "public_vocabulary_digest",
                public_baseline_vocabulary_digest(),
            ),
        ):
            actual = _required_string(raw, field)
            if actual != expected:
                raise ValueError(f"baseline bundle {field} contradicts its source")
        return bundle

    @property
    def bundle_digest(self) -> str:
        return canonical_digest(_BASELINE_BUNDLE_DOMAIN, self.to_payload())


@dataclass(frozen=True, slots=True)
class BuiltinBaselineArtifact:
    """One exact built-in bundle plus source bytes needed to rerun it."""

    bundle: BuiltinBaselineBundle
    program_source: bytes

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if type(self.bundle) is not BuiltinBaselineBundle:
            raise TypeError("baseline artifact requires an exact bundle")
        if type(self.program_source) is not bytes or not self.program_source:
            raise TypeError("baseline artifact source must be non-empty exact bytes")
        self.bundle.validate()
        if self.program_source != self.bundle.program_source:
            raise ValueError("baseline artifact source is not the frozen built-in source")
        if (
            python_worker_program_digest(self.program_source)
            != self.bundle.program_implementation_digest
        ):
            raise ValueError("baseline artifact source contradicts its program digest")

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "bundle": self.bundle.to_payload(),
            "bundle_digest": self.bundle.bundle_digest,
            "format": BASELINE_ARTIFACT_FORMAT,
            "program_source_hex": self.program_source.hex(),
        }

    @classmethod
    def from_payload(cls, payload: object) -> BuiltinBaselineArtifact:
        raw = _closed_object(
            payload,
            {
                "bundle",
                "bundle_digest",
                "format",
                "program_source_hex",
            },
            label="baseline artifact",
        )
        if raw["format"] != BASELINE_ARTIFACT_FORMAT:
            raise ValueError("baseline artifact format is unsupported")
        bundle = BuiltinBaselineBundle.from_payload(raw["bundle"])
        stored_bundle_digest = _required_digest(raw, "bundle_digest")
        if stored_bundle_digest != bundle.bundle_digest:
            raise ValueError("baseline artifact bundle digest contradicts its bundle")
        source_hex = _required_string(raw, "program_source_hex")
        if (
            not source_hex
            or len(source_hex) % 2
            or _LOWER_HEX.fullmatch(source_hex) is None
        ):
            raise ValueError("baseline artifact source must be non-empty lowercase hex")
        return cls(bundle=bundle, program_source=bytes.fromhex(source_hex))


@dataclass(frozen=True, slots=True)
class BuiltinBaselineSet:
    """Self-contained, canonical release record for the four built-in controls."""

    public_vocabulary: tuple[PublicBaselineVocabulary, ...]
    bundles: tuple[BuiltinBaselineArtifact, ...]

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if (
            type(self.public_vocabulary) is not tuple
            or any(
                type(entry) is not PublicBaselineVocabulary
                for entry in self.public_vocabulary
            )
        ):
            raise TypeError("baseline set vocabulary must be an exact tuple")
        if self.public_vocabulary != PUBLIC_BASELINE_VOCABULARY:
            raise ValueError("baseline set vocabulary is not the frozen public vocabulary")
        if (
            type(self.bundles) is not tuple
            or any(type(entry) is not BuiltinBaselineArtifact for entry in self.bundles)
        ):
            raise TypeError("baseline set bundles must be an exact tuple")
        if tuple(entry.bundle.baseline for entry in self.bundles) != tuple(
            BuiltinBaseline
        ):
            raise ValueError("baseline set must contain each built-in once in release order")
        for entry in self.public_vocabulary:
            entry.validate()
        for artifact in self.bundles:
            artifact.validate()
        method_ids = tuple(artifact.bundle.method_id for artifact in self.bundles)
        program_digests = tuple(
            artifact.bundle.program_implementation_digest
            for artifact in self.bundles
        )
        if len(set(method_ids)) != len(self.bundles):
            raise ValueError("baseline set method IDs must be unique")
        if len(set(program_digests)) != len(self.bundles):
            raise ValueError("baseline set program digests must be unique")
        if len(set(self.bundle_digests)) != len(self.bundles):
            raise ValueError("baseline set bundle digests must be unique")
        derived_root = canonical_digest(
            BASELINE_SET_FORMAT,
            {
                "bundle_digests": self.bundle_digests,
                "format": BASELINE_SET_FORMAT,
                "protocol_id": PROTOCOL_ID,
                "public_vocabulary_digest": _public_baseline_vocabulary_digest(
                    self.public_vocabulary
                ),
            },
        )
        if derived_root != BUILTIN_BASELINE_SET_ROOT:
            raise ValueError("baseline set root is not the frozen built-in root")

    @property
    def public_vocabulary_digest(self) -> str:
        self.validate()
        return _public_baseline_vocabulary_digest(self.public_vocabulary)

    @property
    def bundle_digests(self) -> tuple[str, ...]:
        return tuple(artifact.bundle.bundle_digest for artifact in self.bundles)

    def root_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "bundle_digests": self.bundle_digests,
            "format": BASELINE_SET_FORMAT,
            "protocol_id": PROTOCOL_ID,
            "public_vocabulary_digest": _public_baseline_vocabulary_digest(
                self.public_vocabulary
            ),
        }

    @property
    def baseline_set_root(self) -> str:
        return canonical_digest(BASELINE_SET_FORMAT, self.root_payload())

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "baseline_set_root": self.baseline_set_root,
            "bundles": tuple(artifact.to_payload() for artifact in self.bundles),
            "format": BASELINE_SET_FORMAT,
            "protocol_id": PROTOCOL_ID,
            "public_vocabulary": _public_baseline_vocabulary_payload(
                self.public_vocabulary
            ),
            "public_vocabulary_digest": _public_baseline_vocabulary_digest(
                self.public_vocabulary
            ),
        }

    def to_canonical_bytes(self) -> bytes:
        return canonical_json(self.to_payload())

    @classmethod
    def from_canonical_bytes(cls, payload: bytes) -> BuiltinBaselineSet:
        return _parse_builtin_baseline_set(payload)


def builtin_baseline_bundles() -> tuple[BuiltinBaselineBundle, ...]:
    """Return all trusted built-in methods in frozen release order."""

    return tuple(BuiltinBaselineBundle(baseline) for baseline in BuiltinBaseline)


def builtin_baseline_set() -> BuiltinBaselineSet:
    """Return the self-contained release record for all built-in methods."""

    return BuiltinBaselineSet(
        public_vocabulary=PUBLIC_BASELINE_VOCABULARY,
        bundles=tuple(
            BuiltinBaselineArtifact(
                bundle=bundle,
                program_source=bundle.program_source,
            )
            for bundle in builtin_baseline_bundles()
        ),
    )


def public_baseline_vocabulary_payload() -> dict[str, JsonValue]:
    """Return the machine-readable vocabulary embedded in protocol artifacts."""

    _validate_public_vocabulary()
    return _public_baseline_vocabulary_payload(PUBLIC_BASELINE_VOCABULARY)


def public_baseline_vocabulary_digest() -> str:
    """Bind the documented semantics available to every participant bundle."""

    return canonical_digest(
        _PUBLIC_VOCABULARY_DOMAIN,
        public_baseline_vocabulary_payload(),
    )


def _public_baseline_vocabulary_payload(
    entries: tuple[PublicBaselineVocabulary, ...],
) -> dict[str, JsonValue]:
    return {
        "entries": tuple(entry.to_payload() for entry in entries),
        "format": PUBLIC_BASELINE_VOCABULARY_FORMAT,
        "protocol_id": PROTOCOL_ID,
    }


def _public_baseline_vocabulary_digest(
    entries: tuple[PublicBaselineVocabulary, ...],
) -> str:
    return canonical_digest(
        _PUBLIC_VOCABULARY_DOMAIN,
        _public_baseline_vocabulary_payload(entries),
    )


def _validate_public_vocabulary() -> None:
    if (
        type(PUBLIC_BASELINE_VOCABULARY) is not tuple
        or len(PUBLIC_BASELINE_VOCABULARY) != _TEMPLATE_COUNT
        or any(
            type(entry) is not PublicBaselineVocabulary
            for entry in PUBLIC_BASELINE_VOCABULARY
        )
    ):
        raise TypeError("public baseline vocabulary must contain five exact entries")
    for entry in PUBLIC_BASELINE_VOCABULARY:
        entry.validate()
    action_tools = tuple(entry.action_tool for entry in PUBLIC_BASELINE_VOCABULARY)
    if tuple(sorted(set(action_tools))) != action_tools:
        raise ValueError("public baseline vocabulary must be uniquely action-tool ordered")
    for field in ("lookup_tool", "epoch_probe", "refresh_atom", "repair_atom"):
        values = tuple(
            getattr(entry, field)
            for entry in PUBLIC_BASELINE_VOCABULARY
        )
        if len(set(values)) != _TEMPLATE_COUNT:
            raise ValueError(f"public baseline {field} values must be unique")
    if (
        _public_baseline_vocabulary_digest(PUBLIC_BASELINE_VOCABULARY)
        != PUBLIC_BASELINE_VOCABULARY_DIGEST
    ):
        raise ValueError("public baseline vocabulary is not the frozen vocabulary")


def _parse_builtin_baseline_set(payload: object) -> BuiltinBaselineSet:
    raw = _parse_baseline_set_object(payload)
    _require_closed_fields(
        raw,
        {
            "baseline_set_root",
            "bundles",
            "format",
            "protocol_id",
            "public_vocabulary",
            "public_vocabulary_digest",
        },
        label="baseline set",
    )
    if raw["format"] != BASELINE_SET_FORMAT:
        raise ValueError("baseline set format is unsupported")
    if raw["protocol_id"] != PROTOCOL_ID:
        raise ValueError("baseline set protocol is unsupported")

    public_vocabulary = _parse_public_baseline_vocabulary(
        raw["public_vocabulary"]
    )
    bundles_raw = _required_array(raw, "bundles")
    if len(bundles_raw) != len(BuiltinBaseline):
        raise ValueError("baseline set must contain exactly four bundles")
    baseline_set = BuiltinBaselineSet(
        public_vocabulary=public_vocabulary,
        bundles=tuple(
            BuiltinBaselineArtifact.from_payload(item) for item in bundles_raw
        ),
    )
    stored_vocabulary_digest = _required_digest(
        raw,
        "public_vocabulary_digest",
    )
    if stored_vocabulary_digest != baseline_set.public_vocabulary_digest:
        raise ValueError("stored public vocabulary digest contradicts its entries")
    stored_set_root = _required_digest(raw, "baseline_set_root")
    if stored_set_root != baseline_set.baseline_set_root:
        raise ValueError("stored baseline set root contradicts its bundles")
    if baseline_set.to_canonical_bytes() != payload:
        raise ValueError("baseline set failed canonical round-trip")
    return baseline_set


def _parse_baseline_set_object(payload: object) -> dict[str, object]:
    if type(payload) is not bytes:
        raise TypeError("baseline set payload must be exact bytes")
    if not payload or len(payload) > _MAX_BASELINE_SET_BYTES:
        raise ValueError(
            f"baseline set payload must contain 1..{_MAX_BASELINE_SET_BYTES} bytes"
        )
    try:
        raw: object = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("baseline set is not valid UTF-8 JSON") from error
    try:
        canonical = (
            type(raw) is dict
            and canonical_json(cast(JsonValue, raw)) == payload
        )
    except (RecursionError, TypeError, UnicodeEncodeError) as error:
        raise ValueError("baseline set contains unsupported JSON") from error
    if not canonical:
        raise ValueError("baseline set is not one canonical JSON object")
    return cast(dict[str, object], raw)


def _parse_public_baseline_vocabulary(
    payload: object,
) -> tuple[PublicBaselineVocabulary, ...]:
    raw = _closed_object(
        payload,
        {"entries", "format", "protocol_id"},
        label="public baseline vocabulary",
    )
    if raw["format"] != PUBLIC_BASELINE_VOCABULARY_FORMAT:
        raise ValueError("public baseline vocabulary format is unsupported")
    if raw["protocol_id"] != PROTOCOL_ID:
        raise ValueError("public baseline vocabulary protocol is unsupported")
    entries_raw = _required_array(raw, "entries")
    if len(entries_raw) != _TEMPLATE_COUNT:
        raise ValueError("public baseline vocabulary must contain five entries")
    entries = tuple(
        PublicBaselineVocabulary.from_payload(item) for item in entries_raw
    )
    if entries != PUBLIC_BASELINE_VOCABULARY:
        raise ValueError("public baseline vocabulary is not the frozen vocabulary")
    return entries


def _closed_object(
    value: object,
    fields: set[str],
    *,
    label: str,
) -> dict[str, object]:
    if type(value) is not dict:
        raise ValueError(f"{label} must be an object")
    raw = cast(dict[str, object], value)
    _require_closed_fields(raw, fields, label=label)
    return raw


def _require_closed_fields(
    payload: dict[str, object],
    fields: set[str],
    *,
    label: str,
) -> None:
    if set(payload) != fields:
        raise ValueError(f"{label} contains unknown or missing fields")


def _required_array(
    payload: dict[str, object],
    field: str,
) -> list[object]:
    value = payload[field]
    if type(value) is not list:
        raise ValueError(f"{field} must be an array")
    return cast(list[object], value)


def _required_string(payload: dict[str, object], field: str) -> str:
    value = payload[field]
    if type(value) is not str:
        raise ValueError(f"{field} must be a string")
    return value


def _required_digest(payload: dict[str, object], field: str) -> str:
    value = _required_string(payload, field)
    if _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{field} must be one lowercase SHA-256 digest")
    return value


def _source_vocabulary_payload() -> dict[str, JsonValue]:
    _validate_public_vocabulary()
    return {
        entry.action_tool: (
            entry.lookup_tool,
            entry.epoch_probe,
            entry.refresh_atom,
            entry.repair_atom,
        )
        for entry in PUBLIC_BASELINE_VOCABULARY
    }


def _render_worker_source(baseline: BuiltinBaseline) -> bytes:
    if type(baseline) is not BuiltinBaseline:
        raise TypeError("worker source requires an exact BuiltinBaseline")
    vocabulary_literal = canonical_json(_source_vocabulary_payload()).decode().strip()
    source = _BASELINE_WORKER_TEMPLATE.replace(
        "__BASELINE__",
        canonical_json(baseline.value).decode().strip(),
    ).replace(
        "__VOCABULARY__",
        vocabulary_literal,
    )
    if "__BASELINE__" in source or "__VOCABULARY__" in source:
        raise RuntimeError("baseline worker source template was not closed")
    return source.encode("utf-8")


_BASELINE_WORKER_TEMPLATE = '''import json
import sys

BASELINE = __BASELINE__
VOCABULARY = __VOCABULARY__

EVIDENCE_FORMAT = "witnessgap.workspace100-evidence-envelope.v1"
CLAIM_FORMAT = "witnessgap.workspace100-claim.v1"
PROTOCOL_ID = "workspace-100-v1"
MAX_REQUEST_BYTES = 1 << 18
MAX_TRACE_BYTES = 1 << 18


def fail():
    raise SystemExit(2)


def validate_json(value, depth=0):
    if depth > 32 or type(value) is float:
        fail()
    if value is None or type(value) in (str, int, bool):
        return
    if type(value) is list:
        for item in value:
            validate_json(item, depth + 1)
        return
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            fail()
        for item in value.values():
            validate_json(item, depth + 1)
        return
    fail()


def canonical(value):
    validate_json(value)
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\\n"
    )


def canonical_object(payload, maximum_bytes):
    if type(payload) is not bytes or not payload or len(payload) > maximum_bytes:
        fail()
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        fail()
    validate_json(value)
    if type(value) is not dict or canonical(value) != payload:
        fail()
    return value


def string(mapping, field):
    value = mapping.get(field)
    if type(value) is not str:
        fail()
    return value


def exact_hex(mapping, field):
    value = string(mapping, field)
    if (
        len(value) % 2
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        fail()
    try:
        return bytes.fromhex(value)
    except ValueError:
        fail()


def exact_digest(mapping, field):
    value = string(mapping, field)
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        fail()


def exact_string_mapping(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        fail()
    for field in fields:
        string(value, field)


def trace_vocabulary(trace_hex, expected_interventions):
    trace = canonical_object(
        exact_hex({"trace": trace_hex}, "trace"),
        MAX_TRACE_BYTES,
    )
    if set(trace) != {"events", "interventions", "task", "terminal"}:
        fail()
    if type(trace["interventions"]) is not list:
        fail()
    if trace["interventions"] != expected_interventions:
        fail()
    string(trace, "task")
    string(trace, "terminal")

    events = trace["events"]
    if type(events) is not list or len(events) != 2:
        fail()
    lookup, action = events
    if (
        type(lookup) is not dict
        or type(action) is not dict
        or set(lookup) != {"arguments", "result", "tool"}
        or set(action) != {"arguments", "result", "tool"}
    ):
        fail()
    exact_string_mapping(lookup["arguments"], ("subject_id", "workspace"))
    exact_string_mapping(lookup["result"], ("concrete_id", "display"))
    exact_string_mapping(
        action["arguments"],
        ("concrete_id", "subject_id", "workspace"),
    )
    if action["result"] != {"status": "completed"}:
        fail()

    action_tool = string(action, "tool")
    vocabulary = VOCABULARY.get(action_tool)
    if type(vocabulary) is not list or len(vocabulary) != 4:
        fail()
    if string(lookup, "tool") != vocabulary[0]:
        fail()
    return vocabulary


def parse_request(payload):
    envelope = canonical_object(payload, MAX_REQUEST_BYTES)
    expected = {
        "coverage_manifest_digest",
        "format",
        "intervention_observations",
        "outcome",
        "probes",
        "protocol_id",
        "public_trace_hex",
        "registry_digest",
    }
    if set(envelope) != expected:
        fail()
    if envelope["format"] != EVIDENCE_FORMAT or envelope["protocol_id"] != PROTOCOL_ID:
        fail()
    if envelope["outcome"] != "failure":
        fail()
    exact_digest(envelope, "coverage_manifest_digest")
    exact_digest(envelope, "registry_digest")
    vocabulary = trace_vocabulary(string(envelope, "public_trace_hex"), [])

    probes = envelope["probes"]
    observations = envelope["intervention_observations"]
    if type(probes) is not list or len(probes) > 1:
        fail()
    if type(observations) is not list or len(observations) > 1:
        fail()
    if probes and observations:
        fail()
    if probes:
        probe = probes[0]
        if type(probe) is not dict or set(probe) != {"name", "value_hex"}:
            fail()
        if string(probe, "name") not in ("workspace_owner", vocabulary[1]):
            fail()
        exact_hex(probe, "value_hex")

    observation = None
    if observations:
        observation = observations[0]
        expected_observation = {"interventions", "outcome", "public_trace_hex"}
        if type(observation) is not dict or set(observation) != expected_observation:
            fail()
        if observation["interventions"] != [vocabulary[2]]:
            fail()
        if observation["outcome"] not in ("failure", "success"):
            fail()
        observed_vocabulary = trace_vocabulary(
            string(observation, "public_trace_hex"),
            [vocabulary[2]],
        )
        if observed_vocabulary != vocabulary:
            fail()
    return vocabulary, observation


def unknown_claim():
    return {
        "format": CLAIM_FORMAT,
        "kind": "not_identifiable",
        "protocol_id": PROTOCOL_ID,
        "unknown_reason": "ambiguous_worlds",
    }


def identified_claim(target, witness):
    return {
        "format": CLAIM_FORMAT,
        "kind": "identified_singleton",
        "minimal_witnesses": [[witness]],
        "protocol_id": PROTOCOL_ID,
        "target_family": [[target]],
    }


def predict(vocabulary, observation):
    refresh_atom = vocabulary[2]
    repair_atom = vocabulary[3]
    if BASELINE == "always_unknown":
        return unknown_claim()
    if BASELINE == "forced_environment":
        return identified_claim("environment", refresh_atom)
    if observation is None:
        return unknown_claim()
    if observation["outcome"] == "success":
        return identified_claim("environment", refresh_atom)
    if BASELINE == "refresh_outcome":
        return identified_claim("policy", repair_atom)
    if BASELINE == "refresh_success_only":
        return unknown_claim()
    fail()


request = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
vocabulary, observation = parse_request(request)
sys.stdout.buffer.write(canonical(predict(vocabulary, observation)))
'''
