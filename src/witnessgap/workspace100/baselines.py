"""Pinned stdlib-only baseline bundles for the Workspace-100 protocol.

This is a trusted-parent authoring module.  Each returned program is a
standalone source file: the participant process receives that file and one
``PublicEvidenceEnvelope` only.  It never imports WitnessGap or reads a
repository resource.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from witnessgap.canonical import JsonValue, canonical_digest, canonical_json
from witnessgap.workspace100.records import PROTOCOL_ID
from witnessgap.workspace100.worker import WorkerProgram, python_worker_program_digest

BASELINE_BUNDLE_FORMAT = "witnessgap.workspace100-baseline-bundle.v1"
PUBLIC_BASELINE_VOCABULARY_FORMAT = (
    "witnessgap.workspace100-public-baseline-vocabulary.v1"
)

_BASELINE_BUNDLE_DOMAIN = "witnessgap.workspace100-baseline-bundle.v1"
_PUBLIC_VOCABULARY_DOMAIN = "witnessgap.workspace100-public-baseline-vocabulary.v1"
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{0,95}$")
_TEMPLATE_COUNT = 5


class BuiltinBaseline(StrEnum):
    """Frozen reference methods in release order."""

    ALWAYS_UNKNOWN = "always_unknown"
    FORCED_ENVIRONMENT = "forced_environment"
    REFRESH_SUCCESS_ONLY = "refresh_success_only"
    REFRESH_OUTCOME = "refresh_outcome"


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
        python_worker_program_digest(source)

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

    @property
    def bundle_digest(self) -> str:
        return canonical_digest(_BASELINE_BUNDLE_DOMAIN, self.to_payload())


def builtin_baseline_bundles() -> tuple[BuiltinBaselineBundle, ...]:
    """Return all trusted built-in methods in frozen release order."""

    return tuple(BuiltinBaselineBundle(baseline) for baseline in BuiltinBaseline)


def public_baseline_vocabulary_digest() -> str:
    """Bind the documented semantics available to every participant bundle."""

    _validate_public_vocabulary()
    payload: dict[str, JsonValue] = {
        "entries": tuple(entry.to_payload() for entry in PUBLIC_BASELINE_VOCABULARY),
        "format": PUBLIC_BASELINE_VOCABULARY_FORMAT,
        "protocol_id": PROTOCOL_ID,
    }
    return canonical_digest(_PUBLIC_VOCABULARY_DOMAIN, payload)


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
