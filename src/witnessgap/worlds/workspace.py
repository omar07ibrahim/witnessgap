"""A small workspace world with an observationally ambiguous failure."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from witnessgap.canonical import canonical_json
from witnessgap.model import InterventionAtom, Outcome, ReplayResult


class WorkspaceCause(StrEnum):
    ENVIRONMENT = "environment"
    POLICY = "policy"


_ATOMS = (
    InterventionAtom(name="refresh_draft_store", target="environment"),
    InterventionAtom(name="repair_draft_selection", target="policy"),
)
_PROBES = ("draft_store_epoch", "workspace_owner")


@dataclass(frozen=True, slots=True)
class WorkspaceWorld:
    """Two hidden completions that share the same failed public trace."""

    cause: WorkspaceCause

    @property
    def world_id(self) -> str:
        return f"workspace_{self.cause.value}"

    @property
    def atoms(self) -> tuple[InterventionAtom, ...]:
        return _ATOMS

    @property
    def probe_names(self) -> tuple[str, ...]:
        return _PROBES

    def probe(self, name: str) -> bytes:
        if name == "draft_store_epoch":
            value = "stale" if self.cause is WorkspaceCause.ENVIRONMENT else "current"
        elif name == "workspace_owner":
            value = "release_team"
        else:
            raise KeyError(name)
        return canonical_json({"name": name, "value": value})

    def replay(self, interventions: frozenset[str]) -> ReplayResult:
        known = {atom.name for atom in _ATOMS}
        if unknown := interventions - known:
            raise ValueError(f"unknown interventions: {sorted(unknown)!r}")

        if self.cause is WorkspaceCause.ENVIRONMENT:
            repaired = "refresh_draft_store" in interventions
        else:
            repaired = "repair_draft_selection" in interventions

        document = "release-notes-v21" if repaired else "release-notes-v17"
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
                "terminal": "approved_content_present" if repaired else "approved_content_missing",
            }
        )
        return ReplayResult(
            public_trace=trace,
            outcome=Outcome.SUCCESS if repaired else Outcome.FAILURE,
            state_reads=("draft_store_epoch", "policy_selection"),
        )


def workspace_twins() -> tuple[WorkspaceWorld, WorkspaceWorld]:
    """Return the deterministic policy/environment causal-twin pair."""

    return (
        WorkspaceWorld(WorkspaceCause.ENVIRONMENT),
        WorkspaceWorld(WorkspaceCause.POLICY),
    )
