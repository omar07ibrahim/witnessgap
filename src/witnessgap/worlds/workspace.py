"""A small workspace world with an observationally ambiguous failure."""

from __future__ import annotations

import json
from dataclasses import dataclass
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
from witnessgap.source import SealedWorldSource


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

    def selected_revision(self) -> str:
        if self.selected_pointer == "approved":
            return self.approved_pointer
        return self.selected_pointer


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

        state = self.initial_state
        if "refresh_draft_store" in interventions:
            state = _WorkspaceState(
                approved_pointer=_APPROVED_REVISION,
                selected_pointer=state.selected_pointer,
            )
        if "repair_draft_selection" in interventions:
            state = _WorkspaceState(
                approved_pointer=state.approved_pointer,
                selected_pointer="approved",
            )

        reads = [
            StateRead(
                sequence=0,
                channel="policy_selection",
                value_digest=canonical_digest(
                    "witnessgap.state-value.v1",
                    {"value": state.selected_pointer},
                ),
            )
        ]
        if state.selected_pointer == "approved":
            reads.append(
                StateRead(
                    sequence=1,
                    channel="draft_store_epoch",
                    value_digest=canonical_digest(
                        "witnessgap.state-value.v1",
                        {"value": state.approved_pointer},
                    ),
                )
            )

        document = state.selected_revision()
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
                "interventions": sorted(interventions),
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
            state_read_log=tuple(reads),
            intervention_log=tuple(sorted(interventions)),
        )


@dataclass(frozen=True, slots=True, init=False)
class WorkspaceWorld:
    """Two hidden completions that share the same failed public trace."""

    cause: WorkspaceCause
    sealed_source: SealedWorldSource

    def __init__(self, cause: WorkspaceCause) -> None:
        if not isinstance(cause, WorkspaceCause):
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
    def success_oracle_contract_digest(self) -> str:
        return canonical_digest(
            "witnessgap.success-oracle-contract.v1",
            {
                "format": "witnessgap.workspace-success-oracle.v1",
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

    def evaluate_terminal(self, terminal_state: bytes) -> Outcome:
        try:
            value: object = json.loads(terminal_state)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("terminal state is not valid UTF-8 JSON") from error
        if not isinstance(value, dict) or canonical_json(value) != terminal_state:
            raise ValueError("terminal state is not canonical JSON")
        if set(value) != {"approved_content_present", "published_document"}:
            raise ValueError("terminal state does not match the workspace oracle schema")
        approved = value["approved_content_present"]
        document = value["published_document"]
        if not isinstance(approved, bool) or not isinstance(document, str):
            raise ValueError("terminal state contains invalid workspace field types")
        expected_approved = document == _APPROVED_REVISION
        if approved is not expected_approved:
            raise ValueError("terminal state approval flag contradicts the published document")
        return Outcome.SUCCESS if approved else Outcome.FAILURE

    def replay(self, interventions: frozenset[str]) -> ReplayResult:
        artifact = self.fresh_runner().run(interventions)
        return ReplayResult(
            public_trace=artifact.public_trace,
            outcome=self.evaluate_terminal(artifact.terminal_state),
            state_reads=tuple(sorted({read.channel for read in artifact.state_read_log})),
        )

    def _initial_state(self) -> _WorkspaceState:
        if self.cause is WorkspaceCause.ENVIRONMENT:
            return _WorkspaceState(
                approved_pointer=_PREVIOUS_REVISION,
                selected_pointer="approved",
            )
        return _WorkspaceState(
            approved_pointer=_APPROVED_REVISION,
            selected_pointer=_PREVIOUS_REVISION,
        )


@dataclass(frozen=True, slots=True)
class WorkspaceSourceAdapter:
    """Closed decoder for the versioned Workspace completion format."""

    def decode(self, source: SealedWorldSource) -> WorkspaceWorld:
        try:
            raw: object = json.loads(source.source_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("workspace source is not valid UTF-8 JSON") from error
        if not isinstance(raw, dict) or canonical_json(cast(JsonValue, raw)) != source.source_bytes:
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
        if not isinstance(initial_state, dict) or set(initial_state) != {
            "approved_pointer",
            "selected_pointer",
        }:
            raise ValueError("workspace source contains an invalid initial state")
        approved_pointer = initial_state["approved_pointer"]
        selected_pointer = initial_state["selected_pointer"]
        if not isinstance(approved_pointer, str) or not isinstance(selected_pointer, str):
            raise ValueError("workspace source state values must be strings")
        state = _WorkspaceState(
            approved_pointer=approved_pointer,
            selected_pointer=selected_pointer,
        )
        cause = _cause_for_state(state)
        return WorkspaceWorld._from_sealed_source(cause, source)


def workspace_source(cause: WorkspaceCause) -> SealedWorldSource:
    """Return the canonical source bundle for one authored completion."""

    if not isinstance(cause, WorkspaceCause):
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
