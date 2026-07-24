"""Closed authored-record schemas for the Workspace-100 protocol."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from witnessgap.canonical import JsonValue, canonical_json

PROTOCOL_ID = "workspace-100-v1"
SOURCE_FORMAT_ID = "witnessgap.workspace100-source.v1"
TEMPLATE_FORMAT_ID = "witnessgap.workspace100-template.v1"
VARIANT_FORMAT_ID = "witnessgap.workspace100-variant.v1"

_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{0,95}$")
_VARIANT_ID = re.compile(r"^v[0-9]{2}$")
_MAX_DISPLAY_LENGTH = 240
_RESOLVER_SIZE = 2
_CONTROL_CHARACTER_BOUNDARY = 32


class TemplateId(StrEnum):
    """Frozen scenario templates in protocol order."""

    PUBLISH_DRAFT = "publish_draft"
    INVITE_MEMBER = "invite_member"
    MOVE_WORK_ITEM = "move_work_item"
    SCHEDULE_REVIEW = "schedule_review"
    GRANT_ACCESS = "grant_access"


class Split(StrEnum):
    """Template-grouped evaluation split."""

    DEVELOPMENT = "development"
    VALIDATION = "validation"
    TEST = "test"


@dataclass(frozen=True, order=True, slots=True)
class ResolverBinding:
    """One selector-to-concrete-ID binding in a source snapshot."""

    selector: str
    concrete_id: str

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        _require_identifier(self.selector, field="resolver selector")
        _require_identifier(self.concrete_id, field="resolver concrete_id")

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "concrete_id": self.concrete_id,
            "selector": self.selector,
        }

    @classmethod
    def from_payload(cls, payload: object) -> ResolverBinding:
        if type(payload) is not dict or set(payload) != {"concrete_id", "selector"}:
            raise ValueError("resolver binding contains unknown or missing fields")
        raw = cast(dict[str, object], payload)
        return cls(
            selector=_required_string(raw, "selector"),
            concrete_id=_required_string(raw, "concrete_id"),
        )


@dataclass(frozen=True, slots=True)
class TemplateRecord:
    """Versioned semantics shared by every twin pair for one template."""

    template_id: TemplateId
    split: Split
    task_schema_id: str
    goal_selector: str
    alternate_selector: str
    refresh_atom: str
    repair_atom: str
    epoch_probe: str
    selection_channel: str
    resolver_channel: str
    lookup_tool: str
    action_tool: str
    terminal_success: str
    terminal_failure: str

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if type(self.template_id) is not TemplateId:
            raise TypeError("template_id must be an exact TemplateId")
        if type(self.split) is not Split:
            raise TypeError("split must be an exact Split")
        for field, value in (
            ("task_schema_id", self.task_schema_id),
            ("goal_selector", self.goal_selector),
            ("alternate_selector", self.alternate_selector),
            ("refresh_atom", self.refresh_atom),
            ("repair_atom", self.repair_atom),
            ("epoch_probe", self.epoch_probe),
            ("selection_channel", self.selection_channel),
            ("resolver_channel", self.resolver_channel),
            ("lookup_tool", self.lookup_tool),
            ("action_tool", self.action_tool),
            ("terminal_success", self.terminal_success),
            ("terminal_failure", self.terminal_failure),
        ):
            _require_identifier(value, field=field)
        if self.goal_selector == self.alternate_selector:
            raise ValueError("template selectors must be distinct")
        if self.refresh_atom == self.repair_atom:
            raise ValueError("template intervention atoms must be distinct")
        if self.selection_channel == self.resolver_channel:
            raise ValueError("template state channels must be distinct")
        if self.lookup_tool == self.action_tool:
            raise ValueError("template tools must be distinct")
        if self.terminal_success == self.terminal_failure:
            raise ValueError("template terminal labels must be distinct")

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "action_tool": self.action_tool,
            "alternate_selector": self.alternate_selector,
            "epoch_probe": self.epoch_probe,
            "format": TEMPLATE_FORMAT_ID,
            "goal_selector": self.goal_selector,
            "lookup_tool": self.lookup_tool,
            "refresh_atom": self.refresh_atom,
            "repair_atom": self.repair_atom,
            "resolver_channel": self.resolver_channel,
            "selection_channel": self.selection_channel,
            "split": self.split.value,
            "task_schema_id": self.task_schema_id,
            "template_id": self.template_id.value,
            "terminal_failure": self.terminal_failure,
            "terminal_success": self.terminal_success,
        }

    def to_canonical_bytes(self) -> bytes:
        return canonical_json(self.to_payload())

    @classmethod
    def from_canonical_bytes(cls, payload: bytes) -> TemplateRecord:
        raw = _canonical_object(payload, label="Workspace-100 template")
        expected = {
            "action_tool",
            "alternate_selector",
            "epoch_probe",
            "format",
            "goal_selector",
            "lookup_tool",
            "refresh_atom",
            "repair_atom",
            "resolver_channel",
            "selection_channel",
            "split",
            "task_schema_id",
            "template_id",
            "terminal_failure",
            "terminal_success",
        }
        if set(raw) != expected:
            raise ValueError("Workspace-100 template contains unknown or missing fields")
        if raw["format"] != TEMPLATE_FORMAT_ID:
            raise ValueError("Workspace-100 template format is unsupported")
        try:
            template_id = TemplateId(_required_string(raw, "template_id"))
            split = Split(_required_string(raw, "split"))
        except ValueError as error:
            raise ValueError("Workspace-100 template enum value is unsupported") from error
        record = cls(
            template_id=template_id,
            split=split,
            task_schema_id=_required_string(raw, "task_schema_id"),
            goal_selector=_required_string(raw, "goal_selector"),
            alternate_selector=_required_string(raw, "alternate_selector"),
            refresh_atom=_required_string(raw, "refresh_atom"),
            repair_atom=_required_string(raw, "repair_atom"),
            epoch_probe=_required_string(raw, "epoch_probe"),
            selection_channel=_required_string(raw, "selection_channel"),
            resolver_channel=_required_string(raw, "resolver_channel"),
            lookup_tool=_required_string(raw, "lookup_tool"),
            action_tool=_required_string(raw, "action_tool"),
            terminal_success=_required_string(raw, "terminal_success"),
            terminal_failure=_required_string(raw, "terminal_failure"),
        )
        if record.to_canonical_bytes() != payload:
            raise ValueError("Workspace-100 template failed canonical round-trip")
        return record


@dataclass(frozen=True, slots=True)
class VariantRecord:
    """One explicitly authored task variant, shared by two completions."""

    template_id: TemplateId
    variant_id: str
    workspace_slug: str
    subject_id: str
    subject_display: str
    owner: str
    public_task: str
    intended_concrete_id: str
    observed_concrete_id: str
    intended_display: str
    observed_display: str
    reference_epoch_id: str
    alternate_epoch_id: str

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if type(self.template_id) is not TemplateId:
            raise TypeError("template_id must be an exact TemplateId")
        if type(self.variant_id) is not str or not _VARIANT_ID.fullmatch(self.variant_id):
            raise ValueError("variant_id must match 'v00' through 'v99'")
        for field, value in (
            ("workspace_slug", self.workspace_slug),
            ("subject_id", self.subject_id),
            ("owner", self.owner),
            ("intended_concrete_id", self.intended_concrete_id),
            ("observed_concrete_id", self.observed_concrete_id),
            ("reference_epoch_id", self.reference_epoch_id),
            ("alternate_epoch_id", self.alternate_epoch_id),
        ):
            _require_identifier(value, field=field)
        for field, value in (
            ("subject_display", self.subject_display),
            ("public_task", self.public_task),
            ("intended_display", self.intended_display),
            ("observed_display", self.observed_display),
        ):
            _require_display(value, field=field)
        if self.intended_concrete_id == self.observed_concrete_id:
            raise ValueError("variant concrete IDs must be distinct")
        if self.intended_display == self.observed_display:
            raise ValueError("variant display values must be distinct")
        if self.reference_epoch_id == self.alternate_epoch_id:
            raise ValueError("variant epoch IDs must be distinct")

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "alternate_epoch_id": self.alternate_epoch_id,
            "format": VARIANT_FORMAT_ID,
            "intended_concrete_id": self.intended_concrete_id,
            "intended_display": self.intended_display,
            "observed_concrete_id": self.observed_concrete_id,
            "observed_display": self.observed_display,
            "owner": self.owner,
            "public_task": self.public_task,
            "reference_epoch_id": self.reference_epoch_id,
            "subject_display": self.subject_display,
            "subject_id": self.subject_id,
            "template_id": self.template_id.value,
            "variant_id": self.variant_id,
            "workspace_slug": self.workspace_slug,
        }

    def to_canonical_bytes(self) -> bytes:
        return canonical_json(self.to_payload())

    @classmethod
    def from_canonical_bytes(cls, payload: bytes) -> VariantRecord:
        raw = _canonical_object(payload, label="Workspace-100 variant")
        expected = {
            "alternate_epoch_id",
            "format",
            "intended_concrete_id",
            "intended_display",
            "observed_concrete_id",
            "observed_display",
            "owner",
            "public_task",
            "reference_epoch_id",
            "subject_display",
            "subject_id",
            "template_id",
            "variant_id",
            "workspace_slug",
        }
        if set(raw) != expected:
            raise ValueError("Workspace-100 variant contains unknown or missing fields")
        if raw["format"] != VARIANT_FORMAT_ID:
            raise ValueError("Workspace-100 variant format is unsupported")
        try:
            template_id = TemplateId(_required_string(raw, "template_id"))
        except ValueError as error:
            raise ValueError("Workspace-100 variant template is unsupported") from error
        record = cls(
            template_id=template_id,
            variant_id=_required_string(raw, "variant_id"),
            workspace_slug=_required_string(raw, "workspace_slug"),
            subject_id=_required_string(raw, "subject_id"),
            subject_display=_required_string(raw, "subject_display"),
            owner=_required_string(raw, "owner"),
            public_task=_required_string(raw, "public_task"),
            intended_concrete_id=_required_string(raw, "intended_concrete_id"),
            observed_concrete_id=_required_string(raw, "observed_concrete_id"),
            intended_display=_required_string(raw, "intended_display"),
            observed_display=_required_string(raw, "observed_display"),
            reference_epoch_id=_required_string(raw, "reference_epoch_id"),
            alternate_epoch_id=_required_string(raw, "alternate_epoch_id"),
        )
        if record.to_canonical_bytes() != payload:
            raise ValueError("Workspace-100 variant failed canonical round-trip")
        return record


@dataclass(frozen=True, slots=True)
class CompletionSourceRecord:
    """Canonical source data for one completion, with no causal-side label."""

    protocol_id: str
    source_format_id: str
    task_schema_id: str
    task_id: str
    template_id: TemplateId
    variant_id: str
    workspace_slug: str
    subject_id: str
    subject_display: str
    owner: str
    public_task: str
    intended_concrete_id: str
    intended_display: str
    observed_concrete_id: str
    observed_display: str
    goal_selector: str
    selected_selector: str
    initial_epoch_id: str
    initial_resolver: tuple[ResolverBinding, ResolverBinding]
    refresh_epoch_id: str
    refresh_resolver: tuple[ResolverBinding, ResolverBinding]

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        _validate_source_scalar_fields(self)
        _validate_source_resolver_contract(self)

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "goal_selector": self.goal_selector,
            "initial_epoch_id": self.initial_epoch_id,
            "initial_resolver": tuple(binding.to_payload() for binding in self.initial_resolver),
            "intended_concrete_id": self.intended_concrete_id,
            "intended_display": self.intended_display,
            "observed_concrete_id": self.observed_concrete_id,
            "observed_display": self.observed_display,
            "owner": self.owner,
            "protocol_id": self.protocol_id,
            "public_task": self.public_task,
            "refresh_epoch_id": self.refresh_epoch_id,
            "refresh_resolver": tuple(binding.to_payload() for binding in self.refresh_resolver),
            "selected_selector": self.selected_selector,
            "source_format_id": self.source_format_id,
            "subject_display": self.subject_display,
            "subject_id": self.subject_id,
            "task_id": self.task_id,
            "task_schema_id": self.task_schema_id,
            "template_id": self.template_id.value,
            "variant_id": self.variant_id,
            "workspace_slug": self.workspace_slug,
        }

    def to_canonical_bytes(self) -> bytes:
        return canonical_json(self.to_payload())

    @classmethod
    def from_canonical_bytes(cls, payload: bytes) -> CompletionSourceRecord:
        raw = _canonical_object(payload, label="Workspace-100 completion source")
        expected = {
            "goal_selector",
            "initial_epoch_id",
            "initial_resolver",
            "intended_concrete_id",
            "intended_display",
            "observed_concrete_id",
            "observed_display",
            "owner",
            "protocol_id",
            "public_task",
            "refresh_epoch_id",
            "refresh_resolver",
            "selected_selector",
            "source_format_id",
            "subject_display",
            "subject_id",
            "task_id",
            "task_schema_id",
            "template_id",
            "variant_id",
            "workspace_slug",
        }
        if set(raw) != expected:
            raise ValueError("Workspace-100 completion source contains unknown or missing fields")
        try:
            template_id = TemplateId(_required_string(raw, "template_id"))
        except ValueError as error:
            raise ValueError("Workspace-100 source template is unsupported") from error
        record = cls(
            protocol_id=_required_string(raw, "protocol_id"),
            source_format_id=_required_string(raw, "source_format_id"),
            task_schema_id=_required_string(raw, "task_schema_id"),
            task_id=_required_string(raw, "task_id"),
            template_id=template_id,
            variant_id=_required_string(raw, "variant_id"),
            workspace_slug=_required_string(raw, "workspace_slug"),
            subject_id=_required_string(raw, "subject_id"),
            subject_display=_required_string(raw, "subject_display"),
            owner=_required_string(raw, "owner"),
            public_task=_required_string(raw, "public_task"),
            intended_concrete_id=_required_string(raw, "intended_concrete_id"),
            intended_display=_required_string(raw, "intended_display"),
            observed_concrete_id=_required_string(raw, "observed_concrete_id"),
            observed_display=_required_string(raw, "observed_display"),
            goal_selector=_required_string(raw, "goal_selector"),
            selected_selector=_required_string(raw, "selected_selector"),
            initial_epoch_id=_required_string(raw, "initial_epoch_id"),
            initial_resolver=_required_resolver(raw, "initial_resolver"),
            refresh_epoch_id=_required_string(raw, "refresh_epoch_id"),
            refresh_resolver=_required_resolver(raw, "refresh_resolver"),
        )
        if record.to_canonical_bytes() != payload:
            raise ValueError("Workspace-100 completion source failed canonical round-trip")
        return record


def _validate_source_scalar_fields(record: CompletionSourceRecord) -> None:
    if type(record.protocol_id) is not str or record.protocol_id != PROTOCOL_ID:
        raise ValueError(f"protocol_id must equal {PROTOCOL_ID!r}")
    if type(record.source_format_id) is not str or record.source_format_id != SOURCE_FORMAT_ID:
        raise ValueError(f"source_format_id must equal {SOURCE_FORMAT_ID!r}")
    if type(record.template_id) is not TemplateId:
        raise TypeError("template_id must be an exact TemplateId")
    if type(record.variant_id) is not str or not _VARIANT_ID.fullmatch(record.variant_id):
        raise ValueError("variant_id must match 'v00' through 'v99'")
    for field, value in (
        ("task_schema_id", record.task_schema_id),
        ("task_id", record.task_id),
        ("workspace_slug", record.workspace_slug),
        ("subject_id", record.subject_id),
        ("owner", record.owner),
        ("intended_concrete_id", record.intended_concrete_id),
        ("observed_concrete_id", record.observed_concrete_id),
        ("goal_selector", record.goal_selector),
        ("selected_selector", record.selected_selector),
        ("initial_epoch_id", record.initial_epoch_id),
        ("refresh_epoch_id", record.refresh_epoch_id),
    ):
        _require_identifier(value, field=field)
    for field, value in (
        ("subject_display", record.subject_display),
        ("public_task", record.public_task),
        ("intended_display", record.intended_display),
        ("observed_display", record.observed_display),
    ):
        _require_display(value, field=field)
    if record.intended_concrete_id == record.observed_concrete_id:
        raise ValueError("source concrete IDs must be distinct")
    if record.intended_display == record.observed_display:
        raise ValueError("source display values must be distinct")


def _validate_source_resolver_contract(record: CompletionSourceRecord) -> None:
    _validate_resolver(record.initial_resolver, field="initial_resolver")
    _validate_resolver(record.refresh_resolver, field="refresh_resolver")
    initial_selectors = tuple(binding.selector for binding in record.initial_resolver)
    refresh_selectors = tuple(binding.selector for binding in record.refresh_resolver)
    if initial_selectors != refresh_selectors:
        raise ValueError("initial and refresh resolvers must cover the same selectors")
    if record.goal_selector not in initial_selectors:
        raise ValueError("goal_selector is absent from the resolver")
    if record.selected_selector not in initial_selectors:
        raise ValueError("selected_selector is absent from the resolver")
    allowed_ids = {record.intended_concrete_id, record.observed_concrete_id}
    if any(
        binding.concrete_id not in allowed_ids
        for resolver in (record.initial_resolver, record.refresh_resolver)
        for binding in resolver
    ):
        raise ValueError("resolver contains a concrete ID outside the source declaration")
    if _resolve(record.refresh_resolver, record.goal_selector) != record.intended_concrete_id:
        raise ValueError("refresh resolver does not map the goal selector to the intended ID")
    alternate_selector = next(
        selector for selector in initial_selectors if selector != record.goal_selector
    )
    if _resolve(record.refresh_resolver, alternate_selector) != record.observed_concrete_id:
        raise ValueError("refresh resolver does not preserve the alternate observed ID")
    if _resolve(record.initial_resolver, record.selected_selector) != record.observed_concrete_id:
        raise ValueError("initial selection does not reproduce the observed ID")
    selector_aligned = record.selected_selector == record.goal_selector
    if selector_aligned:
        if (
            _resolve(record.initial_resolver, record.goal_selector) != record.observed_concrete_id
            or record.initial_epoch_id == record.refresh_epoch_id
        ):
            raise ValueError("selector-aligned source must carry the alternate resolver")
    elif (
        _resolve(record.initial_resolver, record.goal_selector) != record.intended_concrete_id
        or record.initial_epoch_id != record.refresh_epoch_id
    ):
        raise ValueError("resolver-aligned source must carry the alternate selector")


def _validate_resolver(
    resolver: object,
    *,
    field: str,
) -> None:
    if (
        type(resolver) is not tuple
        or len(resolver) != _RESOLVER_SIZE
        or any(type(binding) is not ResolverBinding for binding in resolver)
    ):
        raise TypeError(f"{field} must contain exactly two exact ResolverBinding values")
    typed = cast(tuple[ResolverBinding, ResolverBinding], resolver)
    for binding in typed:
        binding.validate()
    if tuple(sorted(typed)) != typed:
        raise ValueError(f"{field} must be sorted")
    selectors = tuple(binding.selector for binding in typed)
    if len(set(selectors)) != len(selectors):
        raise ValueError(f"{field} selector names must be unique")


def _resolve(
    resolver: tuple[ResolverBinding, ResolverBinding],
    selector: str,
) -> str:
    for binding in resolver:
        if binding.selector == selector:
            return binding.concrete_id
    raise KeyError(selector)


def _required_resolver(
    raw: dict[str, object],
    field: str,
) -> tuple[ResolverBinding, ResolverBinding]:
    value = raw[field]
    if type(value) is not list or len(value) != _RESOLVER_SIZE:
        raise ValueError(f"{field} must be a two-entry JSON array")
    bindings = tuple(ResolverBinding.from_payload(item) for item in value)
    return cast(tuple[ResolverBinding, ResolverBinding], bindings)


def _canonical_object(payload: bytes, *, label: str) -> dict[str, object]:
    if type(payload) is not bytes:
        raise TypeError(f"{label} payload must be exact bytes")
    try:
        raw: object = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from error
    try:
        canonical = type(raw) is dict and canonical_json(cast(JsonValue, raw)) == payload
    except TypeError as error:
        raise ValueError(f"{label} contains unsupported JSON values") from error
    if not canonical:
        raise ValueError(f"{label} is not one canonical JSON object")
    return cast(dict[str, object], raw)


def _required_string(raw: dict[str, object], field: str) -> str:
    value = raw[field]
    if type(value) is not str:
        raise ValueError(f"{field} must be a string")
    return value


def _require_identifier(value: object, *, field: str) -> None:
    if type(value) is not str or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{field} must match {_IDENTIFIER.pattern!r}")


def _require_display(value: object, *, field: str) -> None:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > _MAX_DISPLAY_LENGTH
        or any(ord(character) < _CONTROL_CHARACTER_BOUNDARY for character in value)
    ):
        raise ValueError(f"{field} must be a trimmed printable string")
