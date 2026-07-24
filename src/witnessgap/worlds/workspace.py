"""A small workspace world with an observationally ambiguous failure."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum

from witnessgap.canonical import JsonValue, canonical_digest, canonical_json
from witnessgap.model import (
    ExecutionArtifact,
    ExecutionRunner,
    InterventionAtom,
    Outcome,
    ReplayResult,
    StateRead,
)


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
            public_trace=trace,
            terminal_state=terminal_state,
            state_read_log=tuple(reads),
            intervention_log=tuple(sorted(interventions)),
        )


@dataclass(frozen=True, slots=True)
class WorkspaceWorld:
    """Two hidden completions that share the same failed public trace."""

    cause: WorkspaceCause

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
        state = self._initial_state()
        payload: dict[str, JsonValue] = {
            "approved_pointer": state.approved_pointer,
            "format": "witnessgap.workspace-completion.v1",
            "selected_pointer": state.selected_pointer,
            "task_id": self.task_id,
        }
        return canonical_digest("witnessgap.world-completion.v1", payload)

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
        return _WorkspaceRunner(self._initial_state())

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


def workspace_twins() -> tuple[WorkspaceWorld, WorkspaceWorld]:
    """Return the deterministic policy/environment causal-twin pair."""

    worlds = (
        WorkspaceWorld(WorkspaceCause.ENVIRONMENT),
        WorkspaceWorld(WorkspaceCause.POLICY),
    )
    first, second = sorted(worlds, key=lambda world: world.world_id)
    return first, second
