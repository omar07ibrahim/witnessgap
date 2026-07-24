"""A small workspace world with an observationally ambiguous failure."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from witnessgap.canonical import JsonValue, canonical_digest, canonical_json
from witnessgap.model import InterventionAtom, Outcome, ReplayResult


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

    def replay(self, interventions: frozenset[str]) -> ReplayResult:
        known = {atom.name for atom in _ATOMS}
        if unknown := interventions - known:
            raise ValueError(f"unknown interventions: {sorted(unknown)!r}")

        state = self._initial_state()
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
        return ReplayResult(
            public_trace=trace,
            outcome=Outcome.SUCCESS if approved else Outcome.FAILURE,
            state_reads=_STATE_CHANNELS,
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
