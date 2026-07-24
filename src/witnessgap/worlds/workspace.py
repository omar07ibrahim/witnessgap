"""A small workspace world with an observationally ambiguous failure."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
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


class WorkspaceCause(StrEnum):
    ENVIRONMENT = "environment"
    POLICY = "policy"


_ATOMS = (
    InterventionAtom(name="refresh_draft_store", target="environment"),
    InterventionAtom(name="repair_draft_selection", target="policy"),
)
_PROBES = ("draft_store_epoch", "workspace_owner")
_APPROVED_REVISION = "release-notes-v21"
_PREVIOUS_REVISION = "release-notes-v17"
_TASK_SCHEMA_ID = "workspace_release_notes_v1"
_TASK_ID = "northstar_release_notes_001"
_STATE_CHANNELS = ("draft_store_epoch", "policy_selection")
_SOURCE_FORMAT = "witnessgap.workspace-source.v1"
_ADAPTER_ID = "workspace_release_notes_v1"
_ADAPTER_IMPLEMENTATION_PATHS = (
    "__init__.py",
    "canonical.py",
    "model.py",
    "source.py",
    "worlds/__init__.py",
    "worlds/workspace.py",
)
_SOURCE_SALTS = {
    WorkspaceCause.ENVIRONMENT: bytes.fromhex(
        "3129d2854013fd4074f80a374fdb021d51731ba66c416c7463cbdf546d72ee21"
    ),
    WorkspaceCause.POLICY: bytes.fromhex(
        "a5955e58dd4058e4c36cad1e41de66751078b5bff11b9989eadd7a58445b1786"
    ),
}


@dataclass(frozen=True, slots=True)
class _WorkspaceState:
    approved_pointer: str
    selected_pointer: str


@dataclass(slots=True)
class _RecordingState:
    """The only state view exposed to downstream tool execution."""

    snapshot: _WorkspaceState
    _reads: list[StateRead] = field(default_factory=list)

    def read(self, channel: str) -> str:
        if channel == "policy_selection":
            value = self.snapshot.selected_pointer
        elif channel == "draft_store_epoch":
            value = self.snapshot.approved_pointer
        else:
            raise KeyError(channel)
        self._reads.append(
            StateRead(
                sequence=len(self._reads),
                channel=channel,
                value_digest=_state_value_digest(value),
            )
        )
        return value

    @property
    def read_log(self) -> tuple[StateRead, ...]:
        return tuple(self._reads)


@dataclass(slots=True)
class _WorkspaceRunner:
    initial_state: _WorkspaceState
    source_snapshot_digest: str
    _used: bool = False

    def run(self, interventions: frozenset[str]) -> ExecutionArtifact:
        if self._used:
            raise RuntimeError("workspace runner is single-use; request a fresh snapshot")
        self._used = True

        known = {atom.name for atom in _ATOMS}
        if unknown := interventions - known:
            raise ValueError(f"unknown interventions: {sorted(unknown)!r}")

        state = _apply_interventions(self.initial_state, interventions)
        recording_state = _RecordingState(state)
        selected_pointer = recording_state.read("policy_selection")
        document = (
            recording_state.read("draft_store_epoch")
            if selected_pointer == "approved"
            else selected_pointer
        )
        approved = document == _APPROVED_REVISION
        trace = canonical_json(
            {
                "events": [
                    {
                        "arguments": {"workspace": "northstar"},
                        "result": {"draft": document},
                        "tool": "read_release_draft",
                    },
                    {
                        "arguments": {"draft": document},
                        "result": {"status": "published"},
                        "tool": "publish_release_notes",
                    },
                ],
                "interventions": tuple(sorted(interventions)),
                "task": "Publish the approved Northstar release notes.",
                "terminal": "approved_content_present" if approved else "approved_content_missing",
            }
        )
        terminal_state = canonical_json(
            {
                "approved_content_present": approved,
                "published_document": document,
            }
        )
        return ExecutionArtifact(
            source_snapshot_digest=self.source_snapshot_digest,
            public_trace=trace,
            terminal_state=terminal_state,
            state_read_log=recording_state.read_log,
            intervention_log=tuple(sorted(interventions)),
        )


@dataclass(frozen=True, slots=True, init=False)
class WorkspaceWorld:
    """Two hidden completions that share the same failed public trace."""

    cause: WorkspaceCause
    sealed_source: SealedWorldSource

    def __init__(self, cause: WorkspaceCause) -> None:
        if type(cause) is not WorkspaceCause:
            raise TypeError("cause must be a WorkspaceCause")
        object.__setattr__(self, "cause", cause)
        object.__setattr__(self, "sealed_source", workspace_source(cause))

    @classmethod
    def _from_sealed_source(
        cls,
        cause: WorkspaceCause,
        source: SealedWorldSource,
    ) -> WorkspaceWorld:
        world = object.__new__(cls)
        object.__setattr__(world, "cause", cause)
        object.__setattr__(world, "sealed_source", source)
        return world

    @property
    def world_id(self) -> str:
        return f"wgc_{self.completion_commitment[:24]}"

    @property
    def task_schema_id(self) -> str:
        return _TASK_SCHEMA_ID

    @property
    def task_id(self) -> str:
        return _TASK_ID

    @property
    def source_format_id(self) -> str:
        return _SOURCE_FORMAT

    @property
    def adapter_id(self) -> str:
        return _ADAPTER_ID

    @property
    def adapter_implementation_digest(self) -> str:
        return workspace_adapter_implementation_digest()

    @property
    def declared_state_channels(self) -> tuple[str, ...]:
        return _STATE_CHANNELS

    @property
    def completion_commitment(self) -> str:
        return self.sealed_source.completion_commitment

    @property
    def source_snapshot_digest(self) -> str:
        return self.sealed_source.snapshot_digest

    @property
    def intervention_contract_digest(self) -> str:
        payload: dict[str, JsonValue] = {
            "atoms": tuple({"name": atom.name, "target": atom.target} for atom in _ATOMS),
            "format": "witnessgap.workspace-interventions.v1",
            "task_schema_id": self.task_schema_id,
        }
        return canonical_digest("witnessgap.intervention-contract.v1", payload)

    @property
    def probe_contract_digest(self) -> str:
        payload: dict[str, JsonValue] = {
            "format": "witnessgap.workspace-probes.v1",
            "probe_names": _PROBES,
            "task_schema_id": self.task_schema_id,
        }
        return canonical_digest("witnessgap.probe-contract.v1", payload)

    @property
    def runner_contract_digest(self) -> str:
        return canonical_digest(
            "witnessgap.runner-contract.v1",
            {
                "format": "witnessgap.workspace-runner.v1",
                "task_schema_id": self.task_schema_id,
            },
        )

    @property
    def artifact_validator_contract_digest(self) -> str:
        return canonical_digest(
            "witnessgap.artifact-validator-contract.v1",
            {
                "format": "witnessgap.workspace-artifact-validator.v1",
                "source_format_id": self.source_format_id,
                "task_schema_id": self.task_schema_id,
            },
        )

    @property
    def success_oracle_contract_digest(self) -> str:
        return canonical_digest(
            "witnessgap.success-oracle-contract.v1",
            {
                "format": "witnessgap.workspace-success-oracle.v1",
                "task_schema_id": self.task_schema_id,
            },
        )

    @property
    def state_access_contract_digest(self) -> str:
        return canonical_digest(
            "witnessgap.state-access-contract.v1",
            {
                "declared_state_channels": self.declared_state_channels,
                "format": "witnessgap.workspace-recording-state.v1",
                "task_schema_id": self.task_schema_id,
            },
        )

    @property
    def atoms(self) -> tuple[InterventionAtom, ...]:
        return _ATOMS

    @property
    def probe_names(self) -> tuple[str, ...]:
        return _PROBES

    def probe(self, name: str) -> bytes:
        if name == "draft_store_epoch":
            value = (
                "stale"
                if self._initial_state().approved_pointer == _PREVIOUS_REVISION
                else "current"
            )
        elif name == "workspace_owner":
            value = "release_team"
        else:
            raise KeyError(name)
        return canonical_json({"name": name, "value": value})

    def fresh_runner(self) -> ExecutionRunner:
        return _WorkspaceRunner(
            self._initial_state(),
            source_snapshot_digest=self.source_snapshot_digest,
        )

    def validate_artifact(self, artifact: ExecutionArtifact) -> Outcome:
        """Validate the complete execution before deriving its outcome."""

        if type(artifact) is not ExecutionArtifact:
            raise TypeError("artifact must be an exact ExecutionArtifact")
        artifact.validate()
        if artifact.source_snapshot_digest != self.source_snapshot_digest:
            raise ValueError("execution artifact belongs to a different source snapshot")
        interventions = frozenset(artifact.intervention_log)
        known = {atom.name for atom in _ATOMS}
        if unknown := interventions - known:
            raise ValueError(
                f"execution artifact contains unknown interventions: {sorted(unknown)!r}"
            )

        state = _apply_interventions(self._initial_state(), interventions)
        selected_pointer = state.selected_pointer
        document = state.approved_pointer if selected_pointer == "approved" else selected_pointer
        approved = document == _APPROVED_REVISION

        expected_reads = [
            StateRead(
                sequence=0,
                channel="policy_selection",
                value_digest=_state_value_digest(selected_pointer),
            )
        ]
        if selected_pointer == "approved":
            expected_reads.append(
                StateRead(
                    sequence=1,
                    channel="draft_store_epoch",
                    value_digest=_state_value_digest(state.approved_pointer),
                )
            )
        if artifact.state_read_log != tuple(expected_reads):
            raise ValueError("execution artifact state-read log contradicts the source snapshot")

        terminal = _canonical_object(artifact.terminal_state, label="terminal state")
        if set(terminal) != {"approved_content_present", "published_document"}:
            raise ValueError("terminal state does not match the workspace oracle schema")
        if terminal["approved_content_present"] is not approved:
            raise ValueError("terminal state approval flag contradicts the source snapshot")
        if terminal["published_document"] != document:
            raise ValueError("terminal state document contradicts the source snapshot")

        trace = _canonical_object(artifact.public_trace, label="public trace")
        expected_trace: dict[str, JsonValue] = {
            "events": [
                {
                    "arguments": {"workspace": "northstar"},
                    "result": {"draft": document},
                    "tool": "read_release_draft",
                },
                {
                    "arguments": {"draft": document},
                    "result": {"status": "published"},
                    "tool": "publish_release_notes",
                },
            ],
            "interventions": list(artifact.intervention_log),
            "task": "Publish the approved Northstar release notes.",
            "terminal": "approved_content_present" if approved else "approved_content_missing",
        }
        if trace != expected_trace:
            raise ValueError("public trace contradicts the source snapshot or terminal state")
        return Outcome.SUCCESS if approved else Outcome.FAILURE

    def replay(self, interventions: frozenset[str]) -> ReplayResult:
        artifact = self.fresh_runner().run(interventions)
        return ReplayResult(
            public_trace=artifact.public_trace,
            outcome=self.validate_artifact(artifact),
            state_reads=tuple(sorted({read.channel for read in artifact.state_read_log})),
        )

    def _initial_state(self) -> _WorkspaceState:
        return _initial_state_for(self.cause)


@dataclass(frozen=True, slots=True)
class WorkspaceSourceAdapter:
    """Closed decoder for the versioned Workspace completion format."""

    @property
    def adapter_id(self) -> str:
        return _ADAPTER_ID

    @property
    def source_format_id(self) -> str:
        return _SOURCE_FORMAT

    @property
    def implementation_digest(self) -> str:
        return workspace_adapter_implementation_digest()

    def decode(self, source: SealedWorldSource) -> WorkspaceWorld:
        if type(source) is not SealedWorldSource:
            raise TypeError("workspace source must be an exact SealedWorldSource")
        source.validate()
        try:
            raw: object = json.loads(source.source_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("workspace source is not valid UTF-8 JSON") from error
        if type(raw) is not dict or canonical_json(cast(JsonValue, raw)) != source.source_bytes:
            raise ValueError("workspace source is not canonical JSON")
        if set(raw) != {"format", "initial_state", "task_id", "task_schema_id"}:
            raise ValueError("workspace source contains unknown or missing fields")
        if (
            raw["format"] != _SOURCE_FORMAT
            or raw["task_id"] != _TASK_ID
            or raw["task_schema_id"] != _TASK_SCHEMA_ID
        ):
            raise ValueError("workspace source declares an unsupported schema")
        initial_state = raw["initial_state"]
        if type(initial_state) is not dict or set(initial_state) != {
            "approved_pointer",
            "selected_pointer",
        }:
            raise ValueError("workspace source contains an invalid initial state")
        approved_pointer = initial_state["approved_pointer"]
        selected_pointer = initial_state["selected_pointer"]
        if type(approved_pointer) is not str or type(selected_pointer) is not str:
            raise ValueError("workspace source state values must be strings")
        state = _WorkspaceState(
            approved_pointer=approved_pointer,
            selected_pointer=selected_pointer,
        )
        cause = _cause_for_state(state)
        return WorkspaceWorld._from_sealed_source(cause, source)


def workspace_source(cause: WorkspaceCause) -> SealedWorldSource:
    """Return the canonical source bundle for one authored completion."""

    if type(cause) is not WorkspaceCause:
        raise TypeError("cause must be a WorkspaceCause")
    state = _initial_state_for(cause)
    source_bytes = canonical_json(
        {
            "format": _SOURCE_FORMAT,
            "initial_state": {
                "approved_pointer": state.approved_pointer,
                "selected_pointer": state.selected_pointer,
            },
            "task_id": _TASK_ID,
            "task_schema_id": _TASK_SCHEMA_ID,
        }
    )
    return SealedWorldSource(
        source_bytes=source_bytes,
        commitment_salt=_SOURCE_SALTS[cause],
    )


def workspace_sources() -> tuple[SealedWorldSource, SealedWorldSource]:
    """Return the complete authored source family in commitment order."""

    sources = tuple(workspace_source(cause) for cause in WorkspaceCause)
    first, second = sorted(sources, key=lambda source: source.completion_commitment)
    return first, second


def workspace_adapter_implementation_digest() -> str:
    """Bind the actual installed modules that implement Workspace semantics."""

    return package_implementation_digest(
        "witnessgap.workspace-adapter-implementation.v1",
        _ADAPTER_IMPLEMENTATION_PATHS,
    )


def workspace_twins() -> tuple[WorkspaceWorld, WorkspaceWorld]:
    """Return the deterministic policy/environment causal-twin pair."""

    adapter = WorkspaceSourceAdapter()
    first, second = (adapter.decode(source) for source in workspace_sources())
    return first, second


def _initial_state_for(cause: WorkspaceCause) -> _WorkspaceState:
    if cause is WorkspaceCause.ENVIRONMENT:
        return _WorkspaceState(
            approved_pointer=_PREVIOUS_REVISION,
            selected_pointer="approved",
        )
    return _WorkspaceState(
        approved_pointer=_APPROVED_REVISION,
        selected_pointer=_PREVIOUS_REVISION,
    )


def _cause_for_state(state: _WorkspaceState) -> WorkspaceCause:
    for cause in WorkspaceCause:
        if state == _initial_state_for(cause):
            return cause
    raise ValueError("workspace source initial state is outside the authored completion family")


def _apply_interventions(
    state: _WorkspaceState,
    interventions: frozenset[str],
) -> _WorkspaceState:
    updated = state
    if "refresh_draft_store" in interventions:
        updated = _WorkspaceState(
            approved_pointer=_APPROVED_REVISION,
            selected_pointer=updated.selected_pointer,
        )
    if "repair_draft_selection" in interventions:
        updated = _WorkspaceState(
            approved_pointer=updated.approved_pointer,
            selected_pointer="approved",
        )
    return updated


def _state_value_digest(value: str) -> str:
    return canonical_digest(
        "witnessgap.state-value.v1",
        {"value": value},
    )


def _canonical_object(payload: bytes, *, label: str) -> dict[str, object]:
    if type(payload) is not bytes:
        raise TypeError(f"{label} must be exact bytes")
    try:
        value: object = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from error
    if type(value) is not dict or canonical_json(cast(JsonValue, value)) != payload:
        raise ValueError(f"{label} is not canonical JSON")
    return cast(dict[str, object], value)
