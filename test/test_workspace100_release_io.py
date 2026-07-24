from __future__ import annotations

import json
import os
import stat
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest

from witnessgap.canonical import JsonValue, canonical_json
from witnessgap.workspace100 import release_io
from witnessgap.workspace100.release import (
    RELEASE_DIRECTORY_MODE,
    RELEASE_FILE_MODE,
    RELEASE_MANIFEST_PATH,
    RELEASE_PAYLOAD_PATHS,
    Workspace100ExecutionConfiguration,
    Workspace100IsolationPolicy,
    Workspace100ReleaseBindings,
    Workspace100ReleaseFile,
    Workspace100ReleaseManifest,
    Workspace100RuntimeIdentity,
    workspace100_release_file_content_digest,
)
from witnessgap.workspace100.release_io import (
    Workspace100ReleaseDirectory,
    load_workspace100_release_directory,
    materialize_workspace100_release,
)
from witnessgap.workspace100.worker import WorkerLimits

_MAX_MANIFEST_BYTES = 1 << 20
_INJECTED_FAILURE_CALL = 3


def _digest(label: str) -> str:
    return sha256(label.encode("ascii")).hexdigest()


def _release() -> Workspace100ReleaseDirectory:
    runtime = Workspace100RuntimeIdentity(
        runtime_id="cpython_3_12_linux_x86_64",
        runtime_artifact_digest=_digest("runtime artifact"),
        interpreter_digest=_digest("interpreter"),
        implementation="CPython",
        version="3.12.11",
    )
    policy = Workspace100IsolationPolicy()
    limits = WorkerLimits(
        timeout_ms=4_000,
        stdout_bytes=8_192,
        stderr_bytes=16_384,
    )
    backend_digest = _digest("backend")
    execution = Workspace100ExecutionConfiguration(
        runtime_identity=runtime,
        limits=limits,
        isolation_policy=policy,
        backend_implementation_digest=backend_digest,
    )
    bindings = Workspace100ReleaseBindings(
        protocol_root=_digest("protocol"),
        public_vocabulary_digest=_digest("vocabulary"),
        baseline_set_root=_digest("baselines"),
        template_catalog_digest=_digest("templates"),
        variant_catalog_digest=_digest("variants"),
        source_root=_digest("sources"),
        registry_root=_digest("registries"),
        panel_root=_digest("panels"),
        assignment_root=_digest("assignments"),
        evidence_root=_digest("evidence"),
        projection_root=_digest("projection"),
        truth_root=_digest("truth"),
        claim_set_root=_digest("claims"),
        report_root=_digest("report"),
        adapter_implementation_digest=_digest("adapter implementation"),
        verifier_implementation_digest=_digest("verifier implementation"),
        worker_implementation_digest=_digest("worker implementation"),
        claims_implementation_digest=_digest("claims implementation"),
        scoring_implementation_digest=_digest("scoring implementation"),
        backend_implementation_digest=backend_digest,
        runtime_root=runtime.runtime_root,
        limits_root=limits.digest,
        isolation_policy_root=policy.isolation_policy_root,
        trust_anchor_root=_digest("trust anchor"),
        release_builder_implementation_digest=_digest("release builder"),
    )
    provenance_root = _digest("generation provenance")
    semantic_roots = (
        bindings.protocol_root,
        bindings.baseline_set_root,
        bindings.template_catalog_digest,
        bindings.variant_catalog_digest,
        provenance_root,
        bindings.source_root,
        bindings.registry_root,
        bindings.trust_anchor_root,
        bindings.panel_root,
        bindings.evidence_root,
        bindings.truth_root,
        bindings.claim_set_root,
        bindings.report_root,
    )
    payloads = tuple(
        (
            path,
            canonical_json(
                {
                    "fixture": "release-io",
                    "path": path,
                }
            ),
        )
        for path in RELEASE_PAYLOAD_PATHS
    )
    files = tuple(
        Workspace100ReleaseFile(
            path=path,
            byte_length=len(payload),
            content_digest=workspace100_release_file_content_digest(payload),
            semantic_root=semantic_root,
        )
        for (path, payload), semantic_root in zip(
            payloads,
            semantic_roots,
            strict=True,
        )
    )
    manifest = Workspace100ReleaseManifest(
        generation_provenance_root=provenance_root,
        execution_configuration=execution,
        bindings=bindings,
        files=files,
    )
    return Workspace100ReleaseDirectory(
        manifest=manifest,
        payloads=payloads,
    )


def _output_parent(tmp_path: Path, name: str = "output") -> Path:
    parent = tmp_path / name
    parent.mkdir()
    return parent


def _materialized_root(parent: Path) -> Path:
    return parent / "workspace100" / "v1"


def _rewrite_file(path: Path, payload: bytes) -> None:
    path.parent.chmod(0o755)
    path.chmod(0o644)
    path.write_bytes(payload)
    path.chmod(RELEASE_FILE_MODE)
    path.parent.chmod(RELEASE_DIRECTORY_MODE)


def _load(
    parent: Path,
    release: Workspace100ReleaseDirectory,
) -> Workspace100ReleaseDirectory:
    return load_workspace100_release_directory(
        str(parent),
        expected_release_root=release.release_root,
    )


def test_materializer_installs_and_loader_reopens_the_exact_tree(
    tmp_path: Path,
) -> None:
    release = _release()
    parent = _output_parent(tmp_path)

    installed = materialize_workspace100_release(release, str(parent))

    root = _materialized_root(parent)
    assert installed == str(root)
    assert _load(parent, release) == release
    assert (
        stat.S_IMODE((parent / "workspace100").stat().st_mode)
        == RELEASE_DIRECTORY_MODE
    )
    nested_directories = tuple(
        path for path in root.rglob("*") if path.is_dir()
    )
    for directory in (
        parent / "workspace100",
        root,
        *nested_directories,
    ):
        assert stat.S_IMODE(directory.stat().st_mode) == RELEASE_DIRECTORY_MODE
    for path, payload in release.files:
        materialized = root / path
        assert materialized.read_bytes() == payload
        metadata = materialized.stat()
        assert stat.S_IMODE(metadata.st_mode) == RELEASE_FILE_MODE
        assert metadata.st_nlink == 1
    serialized = b"".join(payload for _, payload in release.files)
    assert str(tmp_path).encode() not in serialized
    assert b"timestamp" not in serialized


def test_materializer_is_no_overwrite_and_preserves_the_first_tree(
    tmp_path: Path,
) -> None:
    release = _release()
    parent = _output_parent(tmp_path)
    materialize_workspace100_release(release, str(parent))
    before = (_materialized_root(parent) / "protocol.json").read_bytes()

    with pytest.raises(FileExistsError):
        materialize_workspace100_release(release, str(parent))

    assert (_materialized_root(parent) / "protocol.json").read_bytes() == before
    assert _load(parent, release) == release


@pytest.mark.parametrize("entry_kind", ["file", "directory", "symlink"])
def test_materializer_rejects_every_existing_destination_kind(
    tmp_path: Path,
    entry_kind: str,
) -> None:
    parent = _output_parent(tmp_path)
    destination = parent / "workspace100"
    if entry_kind == "file":
        destination.write_bytes(b"occupied")
    elif entry_kind == "directory":
        destination.mkdir()
    else:
        target = tmp_path / "elsewhere"
        target.mkdir()
        destination.symlink_to(target, target_is_directory=True)

    with pytest.raises(FileExistsError):
        materialize_workspace100_release(_release(), str(parent))


def test_materializer_and_loader_reject_a_symlinked_output_ancestor(
    tmp_path: Path,
) -> None:
    release = _release()
    actual = _output_parent(tmp_path, "actual")
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)

    with pytest.raises(OSError):
        materialize_workspace100_release(release, str(alias))

    materialize_workspace100_release(release, str(actual))
    with pytest.raises(OSError):
        load_workspace100_release_directory(
            str(alias),
            expected_release_root=release.release_root,
        )


def test_loader_rejects_a_symlinked_workspace100_target(
    tmp_path: Path,
) -> None:
    release = _release()
    actual = _output_parent(tmp_path, "actual")
    materialize_workspace100_release(release, str(actual))
    alias_parent = _output_parent(tmp_path, "alias-parent")
    (alias_parent / "workspace100").symlink_to(
        actual / "workspace100",
        target_is_directory=True,
    )

    with pytest.raises(OSError):
        load_workspace100_release_directory(
            str(alias_parent),
            expected_release_root=release.release_root,
        )


def test_loader_rejects_extra_and_missing_entries(tmp_path: Path) -> None:
    release = _release()
    extra_parent = _output_parent(tmp_path, "extra")
    materialize_workspace100_release(release, str(extra_parent))
    extra_root = _materialized_root(extra_parent)
    extra_root.chmod(0o755)
    (extra_root / "extra.json").write_bytes(b"{}\n")
    (extra_root / "extra.json").chmod(0o444)
    extra_root.chmod(0o555)

    with pytest.raises(ValueError, match="extra or missing"):
        _load(extra_parent, release)

    missing_parent = _output_parent(tmp_path, "missing")
    materialize_workspace100_release(release, str(missing_parent))
    missing = _materialized_root(missing_parent) / "protocol.json"
    missing.parent.chmod(0o755)
    missing.unlink()
    missing.parent.chmod(0o555)

    with pytest.raises(ValueError, match="extra or missing"):
        _load(missing_parent, release)


def test_loader_rejects_wrong_file_and_directory_modes(
    tmp_path: Path,
) -> None:
    release = _release()
    file_parent = _output_parent(tmp_path, "file-mode")
    materialize_workspace100_release(release, str(file_parent))
    (_materialized_root(file_parent) / "protocol.json").chmod(0o644)

    with pytest.raises(ValueError, match="0444"):
        _load(file_parent, release)

    directory_parent = _output_parent(tmp_path, "directory-mode")
    materialize_workspace100_release(release, str(directory_parent))
    (_materialized_root(directory_parent) / "authored").chmod(0o755)

    with pytest.raises(ValueError, match="0555"):
        _load(directory_parent, release)


def test_loader_rejects_hardlinks_symlinks_and_special_files(
    tmp_path: Path,
) -> None:
    release = _release()
    hardlink_parent = _output_parent(tmp_path, "hardlink")
    materialize_workspace100_release(release, str(hardlink_parent))
    source = _materialized_root(hardlink_parent) / "protocol.json"
    os.link(source, hardlink_parent / "outside-link")

    with pytest.raises(ValueError, match="hard link"):
        _load(hardlink_parent, release)

    symlink_parent = _output_parent(tmp_path, "symlink")
    materialize_workspace100_release(release, str(symlink_parent))
    symlink_path = _materialized_root(symlink_parent) / "protocol.json"
    symlink_path.parent.chmod(0o755)
    symlink_path.unlink()
    symlink_path.symlink_to(symlink_parent / "outside")
    symlink_path.parent.chmod(0o555)

    with pytest.raises(ValueError, match="regular file"):
        _load(symlink_parent, release)

    fifo_parent = _output_parent(tmp_path, "fifo")
    materialize_workspace100_release(release, str(fifo_parent))
    fifo_path = _materialized_root(fifo_parent) / "protocol.json"
    fifo_path.parent.chmod(0o755)
    fifo_path.unlink()
    os.mkfifo(fifo_path, mode=0o444)
    fifo_path.parent.chmod(0o555)

    with pytest.raises(ValueError, match="regular file"):
        _load(fifo_parent, release)


def test_loader_rejects_truncation_and_same_length_digest_changes(
    tmp_path: Path,
) -> None:
    release = _release()
    truncated_parent = _output_parent(tmp_path, "truncated")
    materialize_workspace100_release(release, str(truncated_parent))
    truncated = _materialized_root(truncated_parent) / "protocol.json"
    _rewrite_file(truncated, truncated.read_bytes()[:-1])

    with pytest.raises(ValueError, match="size contradicts"):
        _load(truncated_parent, release)

    changed_parent = _output_parent(tmp_path, "changed")
    materialize_workspace100_release(release, str(changed_parent))
    changed = _materialized_root(changed_parent) / "protocol.json"
    original = changed.read_bytes()
    replacement = bytes((original[0] ^ 1,)) + original[1:]
    _rewrite_file(changed, replacement)

    with pytest.raises(ValueError, match="digest contradicts"):
        _load(changed_parent, release)


@pytest.mark.parametrize("root_field", ["artifact_tree_root", "release_root"])
def test_loader_rejects_internally_wrong_manifest_roots(
    tmp_path: Path,
    root_field: str,
) -> None:
    release = _release()
    parent = _output_parent(tmp_path)
    materialize_workspace100_release(release, str(parent))
    manifest_path = _materialized_root(parent) / RELEASE_MANIFEST_PATH
    opened = cast(
        dict[str, JsonValue],
        json.loads(manifest_path.read_bytes()),
    )
    opened[root_field] = "0" * 64
    _rewrite_file(manifest_path, canonical_json(opened))

    with pytest.raises(ValueError, match="roots are inconsistent"):
        _load(parent, release)


def test_external_root_rejects_a_coherently_rerooted_tree(
    tmp_path: Path,
) -> None:
    release = _release()
    parent = _output_parent(tmp_path)
    materialize_workspace100_release(release, str(parent))
    old_root = release.release_root
    payloads = list(release.payloads)
    path, original = payloads[0]
    replacement = original + b" "
    payloads[0] = (path, replacement)
    first_file = replace(
        release.manifest.files[0],
        byte_length=len(replacement),
        content_digest=workspace100_release_file_content_digest(replacement),
    )
    rerooted_manifest = replace(
        release.manifest,
        files=(first_file, *release.manifest.files[1:]),
    )
    rerooted = Workspace100ReleaseDirectory(
        manifest=rerooted_manifest,
        payloads=tuple(payloads),
    )
    assert rerooted.release_root != old_root
    root = _materialized_root(parent)
    _rewrite_file(root / path, replacement)
    _rewrite_file(root / RELEASE_MANIFEST_PATH, rerooted.manifest_bytes)

    with pytest.raises(ValueError, match="independently expected root"):
        load_workspace100_release_directory(
            str(parent),
            expected_release_root=old_root,
        )


def test_loader_bounds_manifest_before_calling_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = _release()
    parent = _output_parent(tmp_path)
    materialize_workspace100_release(release, str(parent))
    manifest_path = _materialized_root(parent) / RELEASE_MANIFEST_PATH
    manifest_path.parent.chmod(0o755)
    manifest_path.chmod(0o644)
    with manifest_path.open("wb") as output:
        output.truncate(_MAX_MANIFEST_BYTES + 1)
    manifest_path.chmod(0o444)
    manifest_path.parent.chmod(0o555)

    def forbidden_read(file_descriptor: int, byte_count: int) -> bytes:
        raise AssertionError(
            f"os.read unexpectedly called for fd={file_descriptor}, size={byte_count}"
        )

    monkeypatch.setattr(os, "read", forbidden_read)
    with pytest.raises(ValueError, match="storage byte bound"):
        _load(parent, release)


def test_loader_never_uses_unbounded_listdir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = _release()
    parent = _output_parent(tmp_path)
    materialize_workspace100_release(release, str(parent))

    def forbidden_listdir(path: str | int) -> list[str]:
        raise AssertionError(f"os.listdir unexpectedly called for {path!r}")

    monkeypatch.setattr(os, "listdir", forbidden_listdir)
    assert _load(parent, release) == release


def test_loader_rejects_top_level_rename_during_load(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = _release()
    parent = _output_parent(tmp_path)
    materialize_workspace100_release(release, str(parent))
    original_read = release_io._read_regular_path
    renamed = False

    def read_then_rename(
        root_fd: int,
        path: str,
        *,
        maximum_bytes: int,
        expected_bytes: int | None = None,
    ) -> bytes:
        nonlocal renamed
        payload = original_read(
            root_fd,
            path,
            maximum_bytes=maximum_bytes,
            expected_bytes=expected_bytes,
        )
        if not renamed:
            renamed = True
            (parent / "workspace100").rename(parent / "moved-workspace100")
        return payload

    monkeypatch.setattr(
        release_io,
        "_read_regular_path",
        read_then_rename,
    )
    with pytest.raises((OSError, ValueError), match="changed"):
        _load(parent, release)


def test_loader_rebinds_named_v1_to_the_held_release_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = _release()
    parent = _output_parent(tmp_path)
    materialize_workspace100_release(release, str(parent))
    workspace = parent / "workspace100"
    workspace_identity = (
        workspace.stat().st_dev,
        workspace.stat().st_ino,
    )
    original_snapshot = release_io._directory_snapshot
    original_read = release_io._read_regular_path
    original_validate_tree = release_io._validate_release_tree
    frozen_workspace_snapshot: tuple[int, ...] | None = None
    frozen_release_snapshot: tuple[tuple[str, tuple[int, ...]], ...] | None = None
    replaced = False

    def hide_parent_metadata_change(file_descriptor: int) -> tuple[int, ...]:
        nonlocal frozen_workspace_snapshot
        observed = os.fstat(file_descriptor)
        if (observed.st_dev, observed.st_ino) == workspace_identity:
            if frozen_workspace_snapshot is None:
                frozen_workspace_snapshot = original_snapshot(file_descriptor)
            return frozen_workspace_snapshot
        return original_snapshot(file_descriptor)

    def hide_held_release_metadata_change(
        file_descriptor: int,
    ) -> tuple[tuple[str, tuple[int, ...]], ...]:
        nonlocal frozen_release_snapshot
        observed = original_validate_tree(file_descriptor)
        if frozen_release_snapshot is None:
            frozen_release_snapshot = observed
        return frozen_release_snapshot

    def read_then_replace_v1(
        root_fd: int,
        path: str,
        *,
        maximum_bytes: int,
        expected_bytes: int | None = None,
    ) -> bytes:
        nonlocal replaced
        payload = original_read(
            root_fd,
            path,
            maximum_bytes=maximum_bytes,
            expected_bytes=expected_bytes,
        )
        if not replaced:
            replaced = True
            workspace.chmod(0o755)
            original_v1 = workspace / "v1"
            original_v1.chmod(0o755)
            original_v1.rename(parent / "detached-v1")
            (parent / "detached-v1").chmod(RELEASE_DIRECTORY_MODE)
            (workspace / "v1").mkdir()
            (workspace / "v1").chmod(RELEASE_DIRECTORY_MODE)
            workspace.chmod(RELEASE_DIRECTORY_MODE)
        return payload

    monkeypatch.setattr(
        release_io,
        "_directory_snapshot",
        hide_parent_metadata_change,
    )
    monkeypatch.setattr(
        release_io,
        "_validate_release_tree",
        hide_held_release_metadata_change,
    )
    monkeypatch.setattr(
        release_io,
        "_read_regular_path",
        read_then_replace_v1,
    )
    with pytest.raises(ValueError, match="v1 release name changed"):
        _load(parent, release)


def test_forbidden_roots_reject_lexical_and_physical_overlap(
    tmp_path: Path,
) -> None:
    release = _release()
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    nested_parent = checkout / "output"
    nested_parent.mkdir()

    with pytest.raises(ValueError, match="overlaps"):
        materialize_workspace100_release(
            release,
            str(nested_parent),
            forbidden_roots=(str(checkout),),
        )

    physical_parent = _output_parent(tmp_path, "physical")
    alias = tmp_path / "physical-alias"
    alias.symlink_to(physical_parent, target_is_directory=True)
    with pytest.raises(ValueError, match="overlaps"):
        materialize_workspace100_release(
            release,
            str(physical_parent),
            forbidden_roots=(str(alias),),
        )


def test_loader_applies_forbidden_roots_independently(
    tmp_path: Path,
) -> None:
    release = _release()
    parent = _output_parent(tmp_path)
    materialize_workspace100_release(release, str(parent))

    with pytest.raises(ValueError, match="overlaps"):
        load_workspace100_release_directory(
            str(parent),
            expected_release_root=release.release_root,
            forbidden_roots=(str(parent),),
        )


def test_injected_write_failure_leaves_no_destination_or_stage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = _release()
    parent = _output_parent(tmp_path)
    original_write_all = release_io._write_all
    calls = 0

    def fail_on_third_write(file_descriptor: int, payload: bytes) -> None:
        nonlocal calls
        calls += 1
        if calls == _INJECTED_FAILURE_CALL:
            raise OSError("injected write fault")
        original_write_all(file_descriptor, payload)

    monkeypatch.setattr(release_io, "_write_all", fail_on_third_write)
    with pytest.raises(OSError, match="injected write fault"):
        materialize_workspace100_release(release, str(parent))

    assert not (parent / "workspace100").exists()
    assert not any(
        entry.name.startswith(".workspace100-stage-")
        for entry in parent.iterdir()
    )


def test_stage_parent_fsync_failure_leaves_no_orphan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = _release()
    parent = _output_parent(tmp_path)
    original_fsync = os.fsync
    calls = 0

    def fail_first_fsync(file_descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("injected stage parent fsync fault")
        original_fsync(file_descriptor)

    monkeypatch.setattr(os, "fsync", fail_first_fsync)
    with pytest.raises(OSError, match="stage parent fsync fault"):
        materialize_workspace100_release(release, str(parent))

    assert tuple(parent.iterdir()) == ()


def test_post_rename_fsync_failure_removes_only_the_installed_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = _release()
    parent = _output_parent(tmp_path)
    original_rename = release_io._rename_noreplace
    original_fsync = os.fsync
    renamed = False
    failed = False

    def record_rename(
        parent_fd: int,
        source_name: str,
        destination_name: str,
    ) -> None:
        nonlocal renamed
        original_rename(parent_fd, source_name, destination_name)
        renamed = True

    def fail_after_rename(file_descriptor: int) -> None:
        nonlocal failed
        if renamed and not failed:
            failed = True
            raise OSError("injected post-rename fsync fault")
        original_fsync(file_descriptor)

    monkeypatch.setattr(release_io, "_rename_noreplace", record_rename)
    monkeypatch.setattr(os, "fsync", fail_after_rename)
    with pytest.raises(OSError, match="post-rename fsync fault"):
        materialize_workspace100_release(release, str(parent))

    assert tuple(parent.iterdir()) == ()


def test_materializer_rejects_a_stage_name_swap_during_rename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = _release()
    parent = _output_parent(tmp_path)
    original_rename = release_io._rename_noreplace

    def swap_source_then_rename(
        parent_fd: int,
        source_name: str,
        destination_name: str,
    ) -> None:
        os.rename(
            source_name,
            "moved-owned-stage",
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        os.mkdir(source_name, 0o700, dir_fd=parent_fd)
        replacement_fd = os.open(
            source_name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        try:
            os.mkdir("foreign-marker", 0o700, dir_fd=replacement_fd)
        finally:
            os.close(replacement_fd)
        original_rename(parent_fd, source_name, destination_name)

    monkeypatch.setattr(
        release_io,
        "_rename_noreplace",
        swap_source_then_rename,
    )
    with pytest.raises(RuntimeError, match="cleanup was incomplete"):
        materialize_workspace100_release(release, str(parent))

    assert (parent / "workspace100" / "foreign-marker").is_dir()
    assert (parent / "moved-owned-stage" / "v1").is_dir()


def test_cleanup_preserves_an_unknown_injected_descendant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = _release()
    parent = _output_parent(tmp_path)
    original_write_all = release_io._write_all
    calls = 0

    def inject_then_fail(file_descriptor: int, payload: bytes) -> None:
        nonlocal calls
        calls += 1
        if calls == _INJECTED_FAILURE_CALL:
            (next(parent.glob(".workspace100-stage-*")) / "v1" / "sealed" / "foreign").mkdir()
            raise OSError("injected write fault after foreign entry")
        original_write_all(file_descriptor, payload)

    monkeypatch.setattr(release_io, "_write_all", inject_then_fail)
    with pytest.raises(RuntimeError, match="cleanup was incomplete"):
        materialize_workspace100_release(release, str(parent))

    stage = next(parent.glob(".workspace100-stage-*"))
    assert (stage / "v1" / "sealed" / "foreign").is_dir()
    assert not (parent / "workspace100").exists()


def test_cleanup_preserves_a_replaced_captured_descendant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = _release()
    parent = _output_parent(tmp_path)
    original_write_all = release_io._write_all
    calls = 0
    foreign = b"foreign replacement"

    def replace_then_fail(file_descriptor: int, payload: bytes) -> None:
        nonlocal calls
        calls += 1
        if calls == _INJECTED_FAILURE_CALL:
            protocol = (
                next(parent.glob(".workspace100-stage-*"))
                / "v1"
                / "protocol.json"
            )
            with protocol.open("rb"):
                protocol.unlink()
                protocol.write_bytes(foreign)
                protocol.chmod(RELEASE_FILE_MODE)
                raise OSError("injected write fault after inode replacement")
        original_write_all(file_descriptor, payload)

    monkeypatch.setattr(release_io, "_write_all", replace_then_fail)
    with pytest.raises(RuntimeError, match="cleanup was incomplete"):
        materialize_workspace100_release(release, str(parent))

    stage = next(parent.glob(".workspace100-stage-*"))
    assert (stage / "v1" / "protocol.json").read_bytes() == foreign
    assert not (parent / "workspace100").exists()


def test_cleanup_refuses_to_remove_a_replacement_inode(tmp_path: Path) -> None:
    parent = _output_parent(tmp_path)
    original = parent / "workspace100"
    original.mkdir()
    original_metadata = original.stat()
    ledger = release_io._StageLedger.for_root(original_metadata)
    original.rename(parent / "moved-original")
    replacement = parent / "workspace100"
    replacement.mkdir()
    parent_fd = os.open(
        parent,
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        with pytest.raises(OSError, match="changed after it was recorded"):
            release_io._remove_stage_tree_at(
                parent_fd,
                "workspace100",
                ledger=ledger,
            )
    finally:
        os.close(parent_fd)

    assert replacement.is_dir()
    assert (parent / "moved-original").is_dir()


def test_release_directory_rejects_payload_length_and_digest_mismatches() -> None:
    release = _release()
    payloads = list(release.payloads)
    path, payload = payloads[0]
    payloads[0] = (path, payload + b"x")

    with pytest.raises(ValueError, match="length contradicts"):
        Workspace100ReleaseDirectory(
            manifest=release.manifest,
            payloads=tuple(payloads),
        )

    first = replace(
        release.manifest.files[0],
        content_digest=_digest("wrong payload"),
    )
    with pytest.raises(ValueError, match="digest contradicts"):
        Workspace100ReleaseDirectory(
            manifest=replace(
                release.manifest,
                files=(first, *release.manifest.files[1:]),
            ),
            payloads=release.payloads,
        )
