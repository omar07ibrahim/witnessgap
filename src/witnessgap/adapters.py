"""Closed registry of source adapters trusted by this verifier release."""

from __future__ import annotations

from witnessgap.source import WorldSourceAdapter

_WORKSPACE_ADAPTER_ID = "workspace_release_notes_v1"
_WORKSPACE100_ADAPTER_ID = "workspace100_v1"


class TrustedAdapterError(ValueError):
    """Raised when a manifest does not name this release's audited adapter."""


def resolve_trusted_adapter(
    adapter_id: str,
    *,
    expected_implementation_digest: str,
) -> WorldSourceAdapter:
    """Resolve an adapter internally and verify its installed source bundle."""

    if adapter_id == _WORKSPACE_ADAPTER_ID:
        # Import only the selected, digest-bound adapter bundle.
        from witnessgap.worlds.workspace import WorkspaceSourceAdapter  # noqa: PLC0415

        adapter: WorldSourceAdapter = WorkspaceSourceAdapter()
    elif adapter_id == _WORKSPACE100_ADAPTER_ID:
        # Import only the selected, digest-bound adapter bundle.
        from witnessgap.workspace100.runtime import (  # noqa: PLC0415
            Workspace100SourceAdapter,
        )

        adapter = Workspace100SourceAdapter()
    else:
        raise TrustedAdapterError(
            f"adapter is not trusted by this verifier release: {adapter_id!r}"
        )
    if adapter.adapter_id != adapter_id:
        raise TrustedAdapterError("installed adapter identity differs from the trust registry")
    if adapter.implementation_digest != expected_implementation_digest:
        raise TrustedAdapterError("installed adapter implementation differs from the manifest")
    return adapter
