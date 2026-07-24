from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest

from witnessgap.source import SealedWorldSource
from witnessgap.worlds.workspace import (
    WorkspaceCause,
    WorkspaceSourceAdapter,
    workspace_source,
)


def test_source_commitment_binds_bytes_and_salt_separately() -> None:
    source = workspace_source(WorkspaceCause.ENVIRONMENT)
    changed_bytes = replace(source, source_bytes=source.source_bytes + b" ")
    changed_salt = replace(source, commitment_salt=b"\x00" * 32)

    assert changed_bytes.snapshot_digest != source.snapshot_digest
    assert changed_bytes.completion_commitment != source.completion_commitment
    assert changed_salt.snapshot_digest == source.snapshot_digest
    assert changed_salt.completion_commitment != source.completion_commitment


@pytest.mark.parametrize(
    ("source_bytes", "salt", "error"),
    [
        ("{}", b"x" * 32, TypeError),
        (b"", b"x" * 32, ValueError),
        (b"{}", "x" * 32, TypeError),
        (b"{}", b"x" * 31, ValueError),
        (b"{}", b"x" * 33, ValueError),
    ],
)
def test_sealed_source_rejects_malformed_fields(
    source_bytes: object,
    salt: object,
    error: type[Exception],
) -> None:
    with pytest.raises(error):
        SealedWorldSource(
            source_bytes=cast(bytes, source_bytes),
            commitment_salt=cast(bytes, salt),
        )


def test_workspace_decoder_rejects_noncanonical_source_bytes() -> None:
    source = workspace_source(WorkspaceCause.POLICY)
    noncanonical = replace(source, source_bytes=source.source_bytes.rstrip(b"\n"))

    with pytest.raises(ValueError, match="canonical JSON"):
        WorkspaceSourceAdapter().decode(noncanonical)


def test_workspace_decoder_rejects_unregistered_hidden_state() -> None:
    source = workspace_source(WorkspaceCause.POLICY)
    mutated = replace(
        source,
        source_bytes=source.source_bytes.replace(
            b'"selected_pointer":"release-notes-v17"',
            b'"selected_pointer":"release-notes-v13"',
        ),
    )

    with pytest.raises(ValueError, match="outside the authored completion family"):
        WorkspaceSourceAdapter().decode(mutated)
