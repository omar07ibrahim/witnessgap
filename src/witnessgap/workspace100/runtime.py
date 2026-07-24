"""Trusted runtime adapter for the frozen Workspace-100 source family."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import cast

from witnessgap.canonical import JsonValue, canonical_digest, canonical_json
from witnessgap.model import (
    ExecutionArtifact,
    ExecutionRunner,
    InterventionAtom,
    Outcome,
    ReplayResult,
    StateRead,
)
from witnessgap.source import SealedWorldSource, package_implementation_digest
from witnessgap.workspace100.catalog import TEMPLATES
from witnessgap.workspace100.generation import (
    GeneratedPair,
    authored_completion_records,
)
from witnessgap.workspace100.records import (
    SOURCE_FORMAT_ID,
    CompletionSourceRecord,
    ResolverBinding,
    TemplateRecord,
)

WORKSPACE100_ADAPTER_ID = "workspace100_v1"
WORKSPACE100_OWNER_PROBE = "workspace_owner"

_ENVIRONMENT_TARGET = "environment"
_POLICY_TARGET = "policy"
_WORLD_ID_DIGEST_CHARACTERS = 24
_ADAPTER_IMPLEMENTATION_PATHS = (
    "__init__.py",
    "canonical.py",
    "model.py",
    "source.py",
    "workspace100/__init__.py",
    "workspace100/catalog.py",
    "workspace100/generation.py",
    "workspace100/records.py",
    "workspace100/runtime.py",
)


@dataclass(frozen=True, slots=True)
class _RuntimeState:
    selected_selector: str
    epoch_id: str
    resolver: tuple[ResolverBinding, ResolverBinding]


@dataclass(frozen=True, slots=True)
class _Resolution:
    concrete_id: str
    display: str
    success: bool


@dataclass(slots=True)
class _RecordingState:
    """The sole state capability available to task execution."""

    state: _RuntimeState
    _reads: list[StateRead] = field(default_factory=list)

    def read_selection(self, channel: str) -> str:
        value = self.state.selected_selector
        self._record(channel, value)
        return value

    def read_resolver(
        self,
        channel: str,
    ) -> tuple[ResolverBinding, ResolverBinding]:
        resolver_value: tuple[JsonValue, ...] = tuple(
            binding.to_payload() for binding in self.state.resolver
        )
        self._record(
            channel,
            {
                "epoch_id": self.state.epoch_id,
                "resolver": resolver_value,
            },
        )
        return self.state.resolver

    def _record(self, channel: str, value: JsonValue) -> None:
        self._reads.append(
            StateRead(
                sequence=len(self._reads),
                channel=channel,
                value_digest=_state_value_digest(channel, value),
            )
        )

    @property
    def read_log(self) -> tuple[StateRead, ...]:
        return tuple(self._reads)


@dataclass(slots=True)
class _Workspace100Runner:
    record: CompletionSourceRecord
    template: TemplateRecord
    source_snapshot_digest: str
    _used: bool = False

    def run(self, interventions: frozenset[str]) -> ExecutionArtifact:
        if self._used:
            raise RuntimeError("Workspace-100 runner is single-use; request a fresh snapshot")
        self._used = True
        normalized = _normalize_interventions(interventions, self.template)
        artifact, _outcome = _build_artifact(
            self.record,
            self.template,
            self.source_snapshot_digest,
            normalized,
        )
        return artifact


@dataclass(frozen=True, slots=True, init=False)
class Workspace100World:
    """One decoded authored completion, available only to trusted evaluation."""

    record: CompletionSourceRecord
    template: TemplateRecord
    sealed_source: SealedWorldSource

    @classmethod
    def _from_sealed_source(
        cls,
        record: CompletionSourceRecord,
        template: TemplateRecord,
        source: SealedWorldSource,
    ) -> Workspace100World:
        world = object.__new__(cls)
        object.__setattr__(world, "record", record)
        object.__setattr__(world, "template", template)
        object.__setattr__(world, "sealed_source", source)
        return world

    @property
    def world_id(self) -> str:
        return f"wge_{self.completion_commitment[:_WORLD_ID_DIGEST_CHARACTERS]}"

    @property
    def task_schema_id(self) -> str:
        return self.record.task_schema_id

    @property
    def task_id(self) -> str:
        return self.record.task_id

    @property
    def source_format_id(self) -> str:
        return SOURCE_FORMAT_ID

    @property
    def adapter_id(self) -> str:
        return WORKSPACE100_ADAPTER_ID

    @property
    def adapter_implementation_digest(self) -> str:
        return workspace100_adapter_implementation_digest()

    @property
    def atoms(self) -> tuple[InterventionAtom, ...]:
        return tuple(
            sorted(
                (
                    InterventionAtom(
                        name=self.template.refresh_atom,
                        target=_ENVIRONMENT_TARGET,
                    ),
                    InterventionAtom(
                        name=self.template.repair_atom,
                        target=_POLICY_TARGET,
                    ),
                )
            )
        )

    @property
    def probe_names(self) -> tuple[str, ...]:
        return tuple(sorted((self.template.epoch_probe, WORKSPACE100_OWNER_PROBE)))

    @property
    def declared_state_channels(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                (
                    self.template.selection_channel,
                    self.template.resolver_channel,
                )
            )
        )

    @property
    def completion_commitment(self) -> str:
        return self.sealed_source.completion_commitment

    @property
    def source_snapshot_digest(self) -> str:
        return self.sealed_source.snapshot_digest

    @property
    def intervention_contract_digest(self) -> str:
        payload: dict[str, JsonValue] = {
            "atoms": tuple({"name": atom.name, "target": atom.target} for atom in self.atoms),
            "format": "witnessgap.workspace100-interventions.v1",
            "task_schema_id": self.task_schema_id,
        }
        return canonical_digest("witnessgap.intervention-contract.v1", payload)

    @property
    def probe_contract_digest(self) -> str:
        payload: dict[str, JsonValue] = {
            "epoch_value": "initial_epoch_id",
            "format": "witnessgap.workspace100-probes.v1",
            "owner_source_field": "owner",
            "probe_names": self.probe_names,
            "task_schema_id": self.task_schema_id,
        }
        return canonical_digest("witnessgap.probe-contract.v1", payload)

    @property
    def runner_contract_digest(self) -> str:
        payload: dict[str, JsonValue] = {
            "action_tool": self.template.action_tool,
            "format": "witnessgap.workspace100-runner.v1",
            "lookup_tool": self.template.lookup_tool,
            "public_trace_format": "witnessgap.workspace100-public-trace.v1",
            "state_read_order": (
                self.template.selection_channel,
                self.template.resolver_channel,
            ),
            "task_schema_id": self.task_schema_id,
            "terminal_failure": self.template.terminal_failure,
            "terminal_state_format": "witnessgap.workspace100-terminal-state.v1",
            "terminal_success": self.template.terminal_success,
        }
        return canonical_digest("witnessgap.runner-contract.v1", payload)

    @property
    def artifact_validator_contract_digest(self) -> str:
        payload: dict[str, JsonValue] = {
            "format": "witnessgap.workspace100-artifact-validator.v1",
            "source_format_id": self.source_format_id,
            "task_schema_id": self.task_schema_id,
        }
        return canonical_digest("witnessgap.artifact-validator-contract.v1", payload)

    @property
    def success_oracle_contract_digest(self) -> str:
        payload: dict[str, JsonValue] = {
            "format": "witnessgap.workspace100-success-oracle.v1",
            "success_condition": "resolved_concrete_id_equals_intended_concrete_id",
            "task_schema_id": self.task_schema_id,
            "terminal_failure": self.template.terminal_failure,
            "terminal_success": self.template.terminal_success,
        }
        return canonical_digest("witnessgap.success-oracle-contract.v1", payload)

    @property
    def state_access_contract_digest(self) -> str:
        payload: dict[str, JsonValue] = {
            "declared_state_channels": self.declared_state_channels,
            "format": "witnessgap.workspace100-recording-state.v1",
            "state_value_format": "witnessgap.workspace100-state-value.v1",
            "task_schema_id": self.task_schema_id,
        }
        return canonical_digest("witnessgap.state-access-contract.v1", payload)

    def probe(self, name: str) -> bytes:
        if name == self.template.epoch_probe:
            value = self.record.initial_epoch_id
        elif name == WORKSPACE100_OWNER_PROBE:
            value = self.record.owner
        else:
            raise KeyError(name)
        return canonical_json({"name": name, "value": value})

    def fresh_runner(self) -> ExecutionRunner:
        return _Workspace100Runner(
            record=self.record,
            template=self.template,
            source_snapshot_digest=self.source_snapshot_digest,
        )

    def validate_artifact(self, artifact: ExecutionArtifact) -> Outcome:
        """Recompute and compare the complete trace, terminal, and read log."""

        if type(artifact) is not ExecutionArtifact:
            raise TypeError("artifact must be an exact ExecutionArtifact")
        artifact.validate()
        if artifact.source_snapshot_digest != self.source_snapshot_digest:
            raise ValueError("execution artifact belongs to a different source snapshot")
        interventions = _normalize_interventions(
            frozenset(artifact.intervention_log),
            self.template,
        )
        expected, outcome = _build_artifact(
            self.record,
            self.template,
            self.source_snapshot_digest,
            interventions,
        )
        if artifact != expected:
            raise ValueError("execution artifact contradicts the sealed Workspace-100 source")
        return outcome

    def replay(self, interventions: frozenset[str]) -> ReplayResult:
        artifact = self.fresh_runner().run(interventions)
        return ReplayResult(
            public_trace=artifact.public_trace,
            outcome=self.validate_artifact(artifact),
            state_reads=tuple(sorted({read.channel for read in artifact.state_read_log})),
        )


@dataclass(frozen=True, slots=True)
class Workspace100SourceAdapter:
    """Closed decoder for exact source records in the authored corpus."""

    @property
    def adapter_id(self) -> str:
        return WORKSPACE100_ADAPTER_ID

    @property
    def source_format_id(self) -> str:
        return SOURCE_FORMAT_ID

    @property
    def implementation_digest(self) -> str:
        return workspace100_adapter_implementation_digest()

    def decode(self, source: SealedWorldSource) -> Workspace100World:
        if type(source) is not SealedWorldSource:
            raise TypeError("Workspace-100 source must be an exact SealedWorldSource")
        source.validate()
        record = CompletionSourceRecord.from_canonical_bytes(source.source_bytes)
        try:
            expected_records = authored_completion_records(
                record.template_id,
                record.variant_id,
            )
        except KeyError as error:
            raise ValueError(
                "Workspace-100 source is outside the frozen authored catalog"
            ) from error
        if record not in expected_records:
            raise ValueError("Workspace-100 source differs from its frozen authored record")
        template = _template_for(record)
        return Workspace100World._from_sealed_source(record, template, source)


def workspace100_adapter_implementation_digest() -> str:
    """Bind every installed module that determines Workspace-100 semantics."""

    return package_implementation_digest(
        "witnessgap.workspace100-adapter-implementation.v1",
        _ADAPTER_IMPLEMENTATION_PATHS,
    )


def workspace100_pair_worlds(
    pair: GeneratedPair,
) -> tuple[Workspace100World, Workspace100World]:
    """Decode one generated pair through the same trusted adapter as verification."""

    if type(pair) is not GeneratedPair:
        raise TypeError("Workspace-100 pair must be an exact GeneratedPair")
    pair.validate()
    adapter = Workspace100SourceAdapter()
    worlds = tuple(
        sorted(
            (
                adapter.decode(pair.completions[0].source),
                adapter.decode(pair.completions[1].source),
            ),
            key=lambda world: world.world_id,
        )
    )
    return cast(tuple[Workspace100World, Workspace100World], worlds)


def _template_for(record: CompletionSourceRecord) -> TemplateRecord:
    try:
        template = next(
            candidate for candidate in TEMPLATES if candidate.template_id is record.template_id
        )
    except StopIteration as error:
        raise ValueError("Workspace-100 source names an unknown template") from error
    if template.task_schema_id != record.task_schema_id:
        raise ValueError("Workspace-100 source task schema contradicts its template")
    return template


def _normalize_interventions(
    interventions: frozenset[str],
    template: TemplateRecord,
) -> frozenset[str]:
    if type(interventions) is not frozenset or any(type(name) is not str for name in interventions):
        raise TypeError("interventions must be an exact frozenset of exact strings")
    known = {template.refresh_atom, template.repair_atom}
    if unknown := interventions - known:
        raise ValueError(f"unknown interventions: {sorted(unknown)!r}")
    return interventions


def _build_artifact(
    record: CompletionSourceRecord,
    template: TemplateRecord,
    source_snapshot_digest: str,
    interventions: frozenset[str],
) -> tuple[ExecutionArtifact, Outcome]:
    state = _state_after_interventions(record, template, interventions)
    recording = _RecordingState(state)
    selected_selector = recording.read_selection(template.selection_channel)
    resolver = recording.read_resolver(template.resolver_channel)
    resolved_concrete_id = _resolve(resolver, selected_selector)
    resolution = _Resolution(
        concrete_id=resolved_concrete_id,
        display=_display_for(record, resolved_concrete_id),
        success=resolved_concrete_id == record.intended_concrete_id,
    )
    intervention_log = tuple(sorted(interventions))
    artifact = ExecutionArtifact(
        source_snapshot_digest=source_snapshot_digest,
        public_trace=_public_trace(
            record,
            template,
            resolution,
            intervention_log,
        ),
        terminal_state=canonical_json(
            {
                "resolved_concrete_id": resolution.concrete_id,
                "success": resolution.success,
            }
        ),
        state_read_log=recording.read_log,
        intervention_log=intervention_log,
    )
    return artifact, Outcome.SUCCESS if resolution.success else Outcome.FAILURE


def _state_after_interventions(
    record: CompletionSourceRecord,
    template: TemplateRecord,
    interventions: frozenset[str],
) -> _RuntimeState:
    refresh = template.refresh_atom in interventions
    repair = template.repair_atom in interventions
    return _RuntimeState(
        selected_selector=record.goal_selector if repair else record.selected_selector,
        epoch_id=record.refresh_epoch_id if refresh else record.initial_epoch_id,
        resolver=record.refresh_resolver if refresh else record.initial_resolver,
    )


def _resolve(
    resolver: tuple[ResolverBinding, ResolverBinding],
    selector: str,
) -> str:
    for binding in resolver:
        if binding.selector == selector:
            return binding.concrete_id
    raise ValueError("runtime resolver does not contain the selected key")


def _display_for(record: CompletionSourceRecord, concrete_id: str) -> str:
    if concrete_id == record.intended_concrete_id:
        return record.intended_display
    if concrete_id == record.observed_concrete_id:
        return record.observed_display
    raise ValueError("runtime resolved an undeclared concrete ID")


def _public_trace(
    record: CompletionSourceRecord,
    template: TemplateRecord,
    resolution: _Resolution,
    intervention_log: tuple[str, ...],
) -> bytes:
    return canonical_json(
        {
            "events": (
                {
                    "arguments": {
                        "subject_id": record.subject_id,
                        "workspace": record.workspace_slug,
                    },
                    "result": {
                        "concrete_id": resolution.concrete_id,
                        "display": resolution.display,
                    },
                    "tool": template.lookup_tool,
                },
                {
                    "arguments": {
                        "concrete_id": resolution.concrete_id,
                        "subject_id": record.subject_id,
                        "workspace": record.workspace_slug,
                    },
                    "result": {"status": "completed"},
                    "tool": template.action_tool,
                },
            ),
            "interventions": intervention_log,
            "task": record.public_task,
            "terminal": (
                template.terminal_success if resolution.success else template.terminal_failure
            ),
        }
    )


def _state_value_digest(channel: str, value: JsonValue) -> str:
    return canonical_digest(
        "witnessgap.workspace100-state-value.v1",
        {
            "channel": channel,
            "value": value,
        },
    )
