from __future__ import annotations

from dataclasses import replace
from typing import Self, cast

import pytest

from witnessgap.source import SealedWorldSource
from witnessgap.worlds.workspace import (
    WorkspaceCause,
    WorkspaceSourceAdapter,
    workspace_source,
)


class CommitmentSplice(bytes):
    """Regression helper for a bytes-subclass commitment substitution."""

    forged_concatenation: bytes

    def __new__(
        cls,
        value: bytes,
        forged_concatenation: bytes,
    ) -> Self:
        instance = super().__new__(cls, value)
        instance.forged_concatenation = forged_concatenation
        return instance

    def __add__(self, other: object) -> bytes:
        del other
        return self.forged_concatenation


def test_source_commitment_binds_bytes_and_salt_separately() -> None:
    source = workspace_source(WorkspaceCause.ENVIRONMENT)
    changed_bytes = replace(source, source_bytes=source.source_bytes + b" ")
    changed_salt = replace(source, commitment_salt=b"\x00" * 32)

    assert changed_bytes.snapshot_digest != source.snapshot_digest
    assert changed_bytes.completion_commitment != source.completion_commitment
    assert changed_salt.snapshot_digest == source.snapshot_digest
    assert changed_salt.completion_commitment != source.completion_commitment


def test_source_rejects_a_bytes_subclass_that_splices_another_commitment() -> None:
    environment = workspace_source(WorkspaceCause.ENVIRONMENT)
    policy = workspace_source(WorkspaceCause.POLICY)
    spliced_salt = CommitmentSplice(
        policy.commitment_salt,
        environment.commitment_salt + environment.source_bytes,
    )

    with pytest.raises(TypeError, match="exact bytes"):
        SealedWorldSource(
            source_bytes=policy.source_bytes,
            commitment_salt=spliced_salt,
        )


def test_runtime_validation_rejects_a_spliced_salt_after_object_mutation() -> None:
    environment = workspace_source(WorkspaceCause.ENVIRONMENT)
    policy = workspace_source(WorkspaceCause.POLICY)
    spliced_salt = CommitmentSplice(
        policy.commitment_salt,
        environment.commitment_salt + environment.source_bytes,
    )
    object.__setattr__(policy, "commitment_salt", spliced_salt)

    with pytest.raises(TypeError, match="exact bytes"):
        policy.validate()


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
