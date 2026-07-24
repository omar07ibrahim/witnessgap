"""Closed registry of source adapters trusted by this verifier release."""

from __future__ import annotations

from witnessgap.source import WorldSourceAdapter
from witnessgap.workspace100.runtime import Workspace100SourceAdapter
from witnessgap.worlds.workspace import WorkspaceSourceAdapter


class TrustedAdapterError(ValueError):
    """Raised when a manifest does not name this release's audited adapter."""


def resolve_trusted_adapter(
    adapter_id: str,
    *,
    expected_implementation_digest: str,
) -> WorldSourceAdapter:
    """Resolve an adapter internally and verify its installed source bundle."""

    if adapter_id == WorkspaceSourceAdapter().adapter_id:
        adapter: WorldSourceAdapter = WorkspaceSourceAdapter()
    elif adapter_id == Workspace100SourceAdapter().adapter_id:
        adapter = Workspace100SourceAdapter()
    else:
        raise TrustedAdapterError(
            f"adapter is not trusted by this verifier release: {adapter_id!r}"
        )
    if adapter.implementation_digest != expected_implementation_digest:
        raise TrustedAdapterError("installed adapter implementation differs from the manifest")
    return adapter
