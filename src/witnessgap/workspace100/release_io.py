"""Fail-closed filesystem I/O for a Workspace-100 release candidate.

The release manifest authenticates no directory by itself.  Materialization
accepts exact in-memory bytes, while loading requires a release root obtained
independently of the directory under review.  Every path traversal uses
directory file descriptors and refuses symbolic links.

This module performs structural storage verification only.  It does not
replay truth, claims, scoring, or generation semantics.
"""

from __future__ import annotations

import ctypes
import errno
import os
import secrets
import stat
from dataclasses import dataclass

from witnessgap.workspace100.release import (
    RELEASE_DIRECTORY,
    RELEASE_DIRECTORY_MODE,
    RELEASE_FILE_MODE,
    RELEASE_LAYOUT_PATHS,
    RELEASE_MANIFEST_PATH,
    RELEASE_PAYLOAD_PATHS,
    Workspace100ReleaseManifest,
    workspace100_release_file_content_digest,
)

_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | os.O_CLOEXEC
    | os.O_DIRECTORY
    | os.O_NOFOLLOW
)
_READ_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
_WRITE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | os.O_CLOEXEC
    | os.O_NOFOLLOW
)
_RENAME_NOREPLACE = 1
_READ_CHUNK_BYTES = 1 << 16
_MAX_MANIFEST_BYTES = 1 << 20
_MAX_RELEASE_FILE_BYTES = 64 << 20
_MAX_RELEASE_TREE_BYTES = 256 << 20
_STAGE_ATTEMPTS = 32
_SHA256_HEX_LENGTH = 64
_PAYLOAD_PAIR_LENGTH = 2

_RELEASE_COMPONENTS = tuple(RELEASE_DIRECTORY.split("/"))
if _RELEASE_COMPONENTS != ("workspace100", "v1"):
    raise RuntimeError("release I/O supports only the frozen workspace100/v1 layout")

_PAYLOAD_DIRECTORIES = tuple(
    sorted(
        {
            path.rsplit("/", 1)[0]
            for path in RELEASE_LAYOUT_PATHS
            if "/" in path
        },
        key=lambda path: (path.count("/"), path),
    )
)
_STAGE_RELEASE_PATH = _RELEASE_COMPONENTS[1]
_STAGE_DIRECTORY_PATHS = (
    "",
    _STAGE_RELEASE_PATH,
    *(f"{_STAGE_RELEASE_PATH}/{path}" for path in _PAYLOAD_DIRECTORIES),
)
_STAGE_FILE_PATHS = tuple(
    f"{_STAGE_RELEASE_PATH}/{path}" for path in RELEASE_LAYOUT_PATHS
)
_STAGE_ALLOWED_PATHS = frozenset(
    (*_STAGE_DIRECTORY_PATHS, *_STAGE_FILE_PATHS)
)


@dataclass(frozen=True, slots=True)
class _StageEntry:
    path: str
    identity: tuple[int, int]
    is_directory: bool


@dataclass(slots=True)
class _StageLedger:
    """Inodes created by this process below one private staging name."""

    entries: dict[str, _StageEntry]

    @classmethod
    def for_root(cls, value: os.stat_result) -> _StageLedger:
        if not stat.S_ISDIR(value.st_mode):
            raise OSError(errno.EIO, "release staging root is not a directory")
        return cls(
            entries={
                "": _StageEntry(
                    path="",
                    identity=_entry_identity(value),
                    is_directory=True,
                )
            }
        )

    def record(
        self,
        path: str,
        value: os.stat_result,
        *,
        is_directory: bool,
    ) -> None:
        if path not in _STAGE_ALLOWED_PATHS or not path:
            raise OSError(errno.EIO, "release staging path is outside its ledger")
        observed_directory = stat.S_ISDIR(value.st_mode)
        observed_regular = stat.S_ISREG(value.st_mode)
        if (
            (is_directory and not observed_directory)
            or (not is_directory and not observed_regular)
        ):
            raise OSError(errno.EIO, "release staging inode has the wrong type")
        entry = _StageEntry(
            path=path,
            identity=_entry_identity(value),
            is_directory=is_directory,
        )
        previous = self.entries.get(path)
        if previous is not None and previous != entry:
            raise OSError(errno.ESTALE, "release staging inode changed")
        self.entries[path] = entry

    @property
    def root_identity(self) -> tuple[int, int]:
        return self.entries[""].identity


@dataclass(frozen=True, slots=True)
class Workspace100ReleaseDirectory:
    """Exact manifest and payload bytes for one structural release tree."""

    manifest: Workspace100ReleaseManifest
    payloads: tuple[tuple[str, bytes], ...]

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if type(self.manifest) is not Workspace100ReleaseManifest:
            raise TypeError("release directory requires an exact manifest")
        self.manifest.validate()
        if (
            type(self.payloads) is not tuple
            or len(self.payloads) != len(RELEASE_PAYLOAD_PATHS)
        ):
            raise TypeError("release directory requires the exact payload tuple")
        normalized: list[tuple[str, bytes]] = []
        for item in self.payloads:
            if type(item) is not tuple or len(item) != _PAYLOAD_PAIR_LENGTH:
                raise TypeError("release payload entries must be exact pairs")
            path, payload = item
            if type(path) is not str or type(payload) is not bytes:
                raise TypeError("release payload entries require exact strings and bytes")
            normalized.append((path, payload))
        if tuple(path for path, _ in normalized) != RELEASE_PAYLOAD_PATHS:
            raise ValueError("release payload paths differ from the frozen allowlist")
        total_bytes = 0
        for descriptor, (path, payload) in zip(
            self.manifest.files,
            normalized,
            strict=True,
        ):
            if descriptor.path != path:
                raise ValueError("release payload path contradicts its descriptor")
            if not payload or len(payload) > _MAX_RELEASE_FILE_BYTES:
                raise ValueError("release payload exceeds its byte bound")
            if descriptor.byte_length != len(payload):
                raise ValueError("release payload length contradicts its descriptor")
            if (
                descriptor.content_digest
                != workspace100_release_file_content_digest(payload)
            ):
                raise ValueError("release payload digest contradicts its descriptor")
            total_bytes += len(payload)
        if total_bytes > _MAX_RELEASE_TREE_BYTES:
            raise ValueError("release payload tree exceeds its byte bound")

    @property
    def release_root(self) -> str:
        self.validate()
        return self.manifest.release_root

    @property
    def manifest_bytes(self) -> bytes:
        self.validate()
        return self.manifest.to_canonical_bytes()

    @property
    def files(self) -> tuple[tuple[str, bytes], ...]:
        """Return every exact file in canonical layout order."""

        self.validate()
        return (*self.payloads, (RELEASE_MANIFEST_PATH, self.manifest_bytes))


def materialize_workspace100_release(
    release: Workspace100ReleaseDirectory,
    output_parent: str,
    *,
    forbidden_roots: tuple[str, ...] = (),
) -> str:
    """Atomically install ``workspace100/v1`` below one exclusive directory.

    The caller must prevent every other process or principal capable of
    mutating ``output_parent`` from doing so while this function runs.  The
    inode ledger checks device/inode/type identity at every materialization
    boundary and refuses detectable namespace drift or an unknown tree, but
    POSIX unlink-by-name cannot close the final equal-privilege replacement
    window without a stronger host isolation primitive.
    """

    if type(release) is not Workspace100ReleaseDirectory:
        raise TypeError("materialization requires an exact release directory")
    release.validate()
    parent_path = _validate_absolute_path(
        output_parent,
        label="release output parent",
    )
    _validate_forbidden_roots(parent_path, forbidden_roots)
    parent_fd = _open_absolute_directory(parent_path)
    stage_name: str | None = None
    stage_ledger: _StageLedger | None = None
    stage_fd = -1
    installed = False
    try:
        if _entry_exists(parent_fd, _RELEASE_COMPONENTS[0]):
            raise FileExistsError(
                errno.EEXIST,
                "Workspace-100 release destination already exists",
                os.path.join(parent_path, _RELEASE_COMPONENTS[0]),
            )
        stage_name, stage_ledger = _create_stage_directory(parent_fd)
        stage_fd = os.open(stage_name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        if _entry_identity(os.fstat(stage_fd)) != stage_ledger.root_identity:
            raise OSError(
                errno.ESTALE,
                "release staging name changed before it was opened",
                stage_name,
            )
        _populate_stage(stage_fd, release, stage_ledger)
        os.fchmod(stage_fd, RELEASE_DIRECTORY_MODE)
        os.fsync(stage_fd)
        _validate_directory_stat(
            os.fstat(stage_fd),
            label="staged workspace100 directory",
        )
        _require_exact_entries(stage_fd, {_RELEASE_COMPONENTS[1]})
        _require_named_identity(
            parent_fd,
            stage_name,
            expected_identity=stage_ledger.root_identity,
            expect_directory=True,
            label="release staging name",
        )
        _rename_noreplace(
            parent_fd,
            stage_name,
            _RELEASE_COMPONENTS[0],
        )
        installed = True
        stage_name = None
        os.fsync(parent_fd)
        _require_named_identity(
            parent_fd,
            _RELEASE_COMPONENTS[0],
            expected_identity=stage_ledger.root_identity,
            expect_directory=True,
            label="installed workspace100 release",
        )
        if _entry_identity(os.fstat(stage_fd)) != stage_ledger.root_identity:
            raise OSError(
                errno.ESTALE,
                "held release staging inode changed after installation",
            )
    except BaseException:
        if stage_fd >= 0:
            os.close(stage_fd)
            stage_fd = -1
        cleanup_name = (
            _RELEASE_COMPONENTS[0]
            if installed
            else stage_name
        )
        if cleanup_name is not None:
            try:
                if stage_ledger is None:
                    raise RuntimeError(
                        "release staging ledger was not captured"
                    )
                _remove_stage_tree_at(
                    parent_fd,
                    cleanup_name,
                    ledger=stage_ledger,
                )
                os.fsync(parent_fd)
            except (OSError, ValueError) as cleanup_error:
                raise RuntimeError(
                    "release materialization failed and cleanup was incomplete"
                ) from cleanup_error
        raise
    finally:
        if stage_fd >= 0:
            os.close(stage_fd)
        os.close(parent_fd)
    return os.path.join(parent_path, RELEASE_DIRECTORY)


def load_workspace100_release_directory(
    output_parent: str,
    *,
    expected_release_root: str,
    forbidden_roots: tuple[str, ...] = (),
) -> Workspace100ReleaseDirectory:
    """Load a structurally exact tree under an independently expected root."""

    parent_path = _validate_absolute_path(
        output_parent,
        label="release output parent",
    )
    _require_digest(expected_release_root, field="expected_release_root")
    _validate_forbidden_roots(parent_path, forbidden_roots)
    parent_fd = _open_absolute_directory(parent_path)
    workspace_fd = -1
    release_fd = -1
    try:
        workspace_fd = _open_release_directory(
            parent_fd,
            _RELEASE_COMPONENTS[0],
            label="workspace100 release directory",
        )
        workspace_snapshot = _directory_snapshot(workspace_fd)
        _require_exact_entries(workspace_fd, {_RELEASE_COMPONENTS[1]})
        release_fd = _open_release_directory(
            workspace_fd,
            _RELEASE_COMPONENTS[1],
            label="Workspace-100 v1 directory",
        )
        first_snapshot = _validate_release_tree(release_fd)
        manifest_bytes = _read_regular_path(
            release_fd,
            RELEASE_MANIFEST_PATH,
            maximum_bytes=_MAX_MANIFEST_BYTES,
        )
        manifest = Workspace100ReleaseManifest.from_canonical_bytes(
            manifest_bytes
        )
        if manifest.release_root != expected_release_root:
            raise ValueError(
                "release manifest contradicts the independently expected root"
            )
        payloads: list[tuple[str, bytes]] = []
        for descriptor in manifest.files:
            payload = _read_regular_path(
                release_fd,
                descriptor.path,
                maximum_bytes=descriptor.byte_length,
                expected_bytes=descriptor.byte_length,
            )
            if (
                workspace100_release_file_content_digest(payload)
                != descriptor.content_digest
            ):
                raise ValueError(
                    "release payload digest contradicts its manifest descriptor"
                )
            payloads.append((descriptor.path, payload))
        second_snapshot = _validate_release_tree(release_fd)
        if first_snapshot != second_snapshot:
            raise ValueError("release directory changed while it was being loaded")
        named_release = os.stat(
            _RELEASE_COMPONENTS[1],
            dir_fd=workspace_fd,
            follow_symlinks=False,
        )
        _validate_directory_stat(
            named_release,
            label="named Workspace-100 v1 directory",
        )
        if (
            _directory_snapshot_from_stat(named_release)
            != _directory_snapshot(release_fd)
        ):
            raise ValueError(
                "Workspace-100 v1 release name changed while loading"
            )
        if (
            workspace_snapshot != _directory_snapshot(workspace_fd)
            or set(_bounded_directory_names(workspace_fd, maximum_entries=1))
            != {_RELEASE_COMPONENTS[1]}
        ):
            raise ValueError("workspace100 release directory changed while loading")
        named_workspace = os.stat(
            _RELEASE_COMPONENTS[0],
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        _validate_directory_stat(
            named_workspace,
            label="named workspace100 release directory",
        )
        if (
            _directory_snapshot_from_stat(named_workspace)
            != workspace_snapshot
        ):
            raise ValueError(
                "workspace100 release name changed while loading"
            )
        loaded = Workspace100ReleaseDirectory(
            manifest=manifest,
            payloads=tuple(payloads),
        )
        if loaded.manifest_bytes != manifest_bytes:
            raise ValueError("loaded release manifest changed during normalization")
        return loaded
    finally:
        if release_fd >= 0:
            os.close(release_fd)
        if workspace_fd >= 0:
            os.close(workspace_fd)
        os.close(parent_fd)


def _populate_stage(
    workspace_fd: int,
    release: Workspace100ReleaseDirectory,
    ledger: _StageLedger,
) -> None:
    os.mkdir(_RELEASE_COMPONENTS[1], 0o700, dir_fd=workspace_fd)
    release_entry = os.stat(
        _RELEASE_COMPONENTS[1],
        dir_fd=workspace_fd,
        follow_symlinks=False,
    )
    ledger.record(
        _STAGE_RELEASE_PATH,
        release_entry,
        is_directory=True,
    )
    release_fd = os.open(
        _RELEASE_COMPONENTS[1],
        _DIRECTORY_FLAGS,
        dir_fd=workspace_fd,
    )
    try:
        if _entry_identity(os.fstat(release_fd)) != _entry_identity(
            release_entry
        ):
            raise OSError(
                errno.ESTALE,
                "Workspace-100 staging directory changed while opening",
            )
        for directory in _PAYLOAD_DIRECTORIES:
            _mkdir_relative(release_fd, directory, ledger)
        for path, payload in release.files:
            _write_regular_path(release_fd, path, payload, ledger)
        for directory in reversed(_PAYLOAD_DIRECTORIES):
            directory_fd = _open_relative_directory(release_fd, directory)
            try:
                os.fchmod(directory_fd, RELEASE_DIRECTORY_MODE)
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        os.fchmod(release_fd, RELEASE_DIRECTORY_MODE)
        os.fsync(release_fd)
        _validate_release_tree(release_fd)
        for path, expected in release.files:
            observed = _read_regular_path(
                release_fd,
                path,
                maximum_bytes=len(expected),
                expected_bytes=len(expected),
            )
            if observed != expected:
                raise OSError(
                    errno.EIO,
                    f"staged release file {path!r} differs after write",
                )
    finally:
        os.close(release_fd)


def _write_regular_path(
    root_fd: int,
    path: str,
    payload: bytes,
    ledger: _StageLedger,
) -> None:
    parent_fd, name = _open_relative_parent(root_fd, path)
    try:
        file_fd = os.open(
            name,
            _WRITE_FLAGS,
            0o400,
            dir_fd=parent_fd,
        )
        try:
            ledger.record(
                f"{_STAGE_RELEASE_PATH}/{path}",
                os.fstat(file_fd),
                is_directory=False,
            )
            _write_all(file_fd, payload)
            os.fsync(file_fd)
            os.fchmod(file_fd, RELEASE_FILE_MODE)
            os.fsync(file_fd)
            _validate_regular_stat(
                file_stat := os.fstat(file_fd),
                label=f"staged release file {path!r}",
                maximum_bytes=_MAX_MANIFEST_BYTES
                if path == RELEASE_MANIFEST_PATH
                else _MAX_RELEASE_FILE_BYTES,
            )
            if file_stat.st_size != len(payload):
                raise OSError(
                    errno.EIO,
                    f"staged release file {path!r} has the wrong size",
                )
        finally:
            os.close(file_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _write_all(file_fd: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(file_fd, payload[offset:])
        if written <= 0:
            raise OSError(errno.EIO, "release file write made no progress")
        offset += written


def _read_regular_path(
    root_fd: int,
    path: str,
    *,
    maximum_bytes: int,
    expected_bytes: int | None = None,
) -> bytes:
    if (
        type(maximum_bytes) is not int
        or isinstance(maximum_bytes, bool)
        or maximum_bytes < 1
        or maximum_bytes > _MAX_RELEASE_FILE_BYTES
    ):
        raise ValueError("release read bound is invalid")
    if expected_bytes is not None and (
        type(expected_bytes) is not int
        or isinstance(expected_bytes, bool)
        or expected_bytes < 1
        or expected_bytes > maximum_bytes
    ):
        raise ValueError("expected release file size is invalid")
    parent_fd, name = _open_relative_parent(root_fd, path)
    try:
        file_fd = os.open(name, _READ_FLAGS, dir_fd=parent_fd)
        try:
            before = os.fstat(file_fd)
            _validate_regular_stat(
                before,
                label=f"release file {path!r}",
                maximum_bytes=maximum_bytes,
            )
            if expected_bytes is not None and before.st_size != expected_bytes:
                raise ValueError(
                    f"release file {path!r} size contradicts its manifest"
                )
            remaining = before.st_size
            chunks: list[bytes] = []
            while remaining:
                chunk = os.read(file_fd, min(remaining, _READ_CHUNK_BYTES))
                if not chunk:
                    raise ValueError(f"release file {path!r} was truncated")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(file_fd, 1):
                raise ValueError(f"release file {path!r} grew while loading")
            after = os.fstat(file_fd)
            if _file_snapshot(before) != _file_snapshot(after):
                raise ValueError(f"release file {path!r} changed while loading")
            payload = b"".join(chunks)
            if len(payload) != before.st_size:
                raise ValueError(f"release file {path!r} read was incomplete")
            return payload
        finally:
            os.close(file_fd)
    finally:
        os.close(parent_fd)


def _validate_release_tree(
    release_fd: int,
) -> tuple[tuple[str, tuple[int, ...]], ...]:
    expected = _expected_directory_entries()
    snapshots: list[tuple[str, tuple[int, ...]]] = []
    total_bytes = 0
    for directory, names in expected:
        directory_fd = (
            os.dup(release_fd)
            if not directory
            else _open_relative_directory(release_fd, directory)
        )
        try:
            directory_stat = os.fstat(directory_fd)
            _validate_directory_stat(
                directory_stat,
                label=f"release directory {directory or '.'!r}",
            )
            actual_names = _bounded_directory_names(
                directory_fd,
                maximum_entries=len(names),
            )
            if (
                len(actual_names) != len(names)
                or set(actual_names) != names
            ):
                raise ValueError(
                    f"release directory {directory or '.'!r} "
                    "contains extra or missing entries"
                )
            snapshots.append(
                (directory, _directory_snapshot_from_stat(directory_stat))
            )
            for name in sorted(names):
                relative_path = f"{directory}/{name}" if directory else name
                entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if relative_path in _PAYLOAD_DIRECTORIES:
                    _validate_directory_stat(
                        entry,
                        label=f"release directory {relative_path!r}",
                    )
                    continue
                maximum = (
                    _MAX_MANIFEST_BYTES
                    if relative_path == RELEASE_MANIFEST_PATH
                    else _MAX_RELEASE_FILE_BYTES
                )
                _validate_regular_stat(
                    entry,
                    label=f"release file {relative_path!r}",
                    maximum_bytes=maximum,
                )
                snapshots.append(
                    (relative_path, _file_snapshot(entry))
                )
                if relative_path != RELEASE_MANIFEST_PATH:
                    total_bytes += entry.st_size
        finally:
            os.close(directory_fd)
    if total_bytes > _MAX_RELEASE_TREE_BYTES:
        raise ValueError("release payload tree exceeds its storage byte bound")
    return tuple(snapshots)


def _expected_directory_entries() -> tuple[tuple[str, set[str]], ...]:
    entries: dict[str, set[str]] = {"": set()}
    for directory in _PAYLOAD_DIRECTORIES:
        parent, _, name = directory.rpartition("/")
        entries.setdefault(parent, set()).add(name)
        entries.setdefault(directory, set())
    for path in RELEASE_LAYOUT_PATHS:
        parent, _, name = path.rpartition("/")
        entries.setdefault(parent, set()).add(name)
    return tuple(
        (directory, entries[directory])
        for directory in sorted(
            entries,
            key=lambda path: (path.count("/"), path),
        )
    )


def _open_release_directory(
    parent_fd: int,
    name: str,
    *,
    label: str,
) -> int:
    directory_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    try:
        _validate_directory_stat(os.fstat(directory_fd), label=label)
    except BaseException:
        os.close(directory_fd)
        raise
    return directory_fd


def _open_absolute_directory(path: str) -> int:
    current_fd = os.open("/", _DIRECTORY_FLAGS)
    try:
        if path == "/":
            return current_fd
        for component in path[1:].split("/"):
            next_fd = os.open(
                component,
                _DIRECTORY_FLAGS,
                dir_fd=current_fd,
            )
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _open_relative_directory(root_fd: int, path: str) -> int:
    _validate_relative_layout_path(path, allow_file=False)
    current_fd = os.dup(root_fd)
    try:
        for component in path.split("/"):
            next_fd = os.open(
                component,
                _DIRECTORY_FLAGS,
                dir_fd=current_fd,
            )
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _open_relative_parent(root_fd: int, path: str) -> tuple[int, str]:
    _validate_relative_layout_path(path, allow_file=True)
    parent, _, name = path.rpartition("/")
    if not parent:
        return os.dup(root_fd), name
    return _open_relative_directory(root_fd, parent), name


def _mkdir_relative(
    root_fd: int,
    path: str,
    ledger: _StageLedger,
) -> None:
    _validate_relative_layout_path(path, allow_file=False)
    parent, _, name = path.rpartition("/")
    parent_fd = (
        os.dup(root_fd)
        if not parent
        else _open_relative_directory(root_fd, parent)
    )
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        ledger.record(
            f"{_STAGE_RELEASE_PATH}/{path}",
            os.stat(
                name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            ),
            is_directory=True,
        )
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _create_stage_directory(
    parent_fd: int,
) -> tuple[str, _StageLedger]:
    for _ in range(_STAGE_ATTEMPTS):
        name = f".workspace100-stage-{secrets.token_hex(12)}"
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        ledger = _StageLedger.for_root(
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        )
        try:
            os.fsync(parent_fd)
        except BaseException:
            try:
                _remove_stage_tree_at(
                    parent_fd,
                    name,
                    ledger=ledger,
                )
                os.fsync(parent_fd)
            except OSError as cleanup_error:
                raise RuntimeError(
                    "release staging creation failed and cleanup was incomplete"
                ) from cleanup_error
            raise
        return name, ledger
    raise FileExistsError(
        errno.EEXIST,
        "could not allocate an exclusive release staging directory",
    )


def _rename_noreplace(
    parent_fd: int,
    source_name: str,
    destination_name: str,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = libc.renameat2
    except AttributeError as error:
        raise RuntimeError(
            "atomic no-replace installation requires renameat2"
        ) from error
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = renameat2(
        parent_fd,
        os.fsencode(source_name),
        parent_fd,
        os.fsencode(destination_name),
        _RENAME_NOREPLACE,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(
            error_number,
            os.strerror(error_number),
            destination_name,
        )


def _remove_stage_tree_at(
    parent_fd: int,
    name: str,
    *,
    ledger: _StageLedger,
) -> None:
    """Remove only the complete inode inventory captured during staging.

    Validation happens before the first deletion.  Any unknown, missing, or
    replaced entry leaves the tree in place for explicit operator inspection.
    The caller is still required to own an exclusive parent namespace because
    POSIX unlinkat/rmdirat identify their final target by name, not inode.
    """

    if type(ledger) is not _StageLedger:
        raise TypeError("release cleanup requires an exact staging ledger")
    root = ledger.entries.get("")
    if root is None or not root.is_directory:
        raise OSError(errno.EIO, "release staging ledger has no directory root")
    _validate_stage_ledger_shape(ledger)
    _require_named_identity(
        parent_fd,
        name,
        expected_identity=root.identity,
        expect_directory=True,
        label="release cleanup root",
    )
    root_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    try:
        if _entry_identity(os.fstat(root_fd)) != root.identity:
            raise OSError(
                errno.ESTALE,
                "release cleanup root changed while opening",
                name,
            )
        _verify_stage_ledger(root_fd, ledger)
        _make_stage_directories_writable(root_fd, ledger)
        file_entries = sorted(
            (
                entry
                for entry in ledger.entries.values()
                if not entry.is_directory
            ),
            key=lambda entry: (entry.path.count("/"), entry.path),
            reverse=True,
        )
        for entry in file_entries:
            _remove_captured_stage_entry(root_fd, entry, ledger)
        directory_entries = sorted(
            (
                entry
                for entry in ledger.entries.values()
                if entry.is_directory and entry.path
            ),
            key=lambda entry: (entry.path.count("/"), entry.path),
            reverse=True,
        )
        for entry in directory_entries:
            _remove_captured_stage_entry(root_fd, entry, ledger)
        os.fsync(root_fd)
    finally:
        os.close(root_fd)
    _require_named_identity(
        parent_fd,
        name,
        expected_identity=root.identity,
        expect_directory=True,
        label="release cleanup root",
    )
    os.rmdir(name, dir_fd=parent_fd)


def _validate_stage_ledger_shape(ledger: _StageLedger) -> None:
    paths = frozenset(ledger.entries)
    if (
        not paths
        or "" not in paths
        or not paths.issubset(_STAGE_ALLOWED_PATHS)
    ):
        raise OSError(errno.EIO, "release staging ledger shape is invalid")
    for path, entry in ledger.entries.items():
        if entry.path != path:
            raise OSError(errno.EIO, "release staging ledger key is invalid")
        expected_directory = path in _STAGE_DIRECTORY_PATHS
        if entry.is_directory != expected_directory:
            raise OSError(errno.EIO, "release staging ledger type is invalid")
        if path:
            parent, _, _ = path.rpartition("/")
            if parent not in ledger.entries:
                raise OSError(
                    errno.EIO,
                    "release staging ledger omits an entry parent",
                )
            if not ledger.entries[parent].is_directory:
                raise OSError(
                    errno.EIO,
                    "release staging ledger parent is not a directory",
                )


def _verify_stage_ledger(root_fd: int, ledger: _StageLedger) -> None:
    for directory in sorted(
        (
            entry
            for entry in ledger.entries.values()
            if entry.is_directory
        ),
        key=lambda entry: (entry.path.count("/"), entry.path),
    ):
        directory_fd = _open_stage_ledger_directory(
            root_fd,
            directory.path,
            ledger,
        )
        try:
            expected_children = {
                _stage_basename(entry.path)
                for entry in ledger.entries.values()
                if entry.path and _stage_parent(entry.path) == directory.path
            }
            try:
                actual_children = _bounded_directory_names(
                    directory_fd,
                    maximum_entries=len(expected_children),
                )
            except ValueError as error:
                raise OSError(
                    errno.ESTALE,
                    "release cleanup found an unknown staging entry",
                    directory.path or ".",
                ) from error
            if (
                len(actual_children) != len(expected_children)
                or set(actual_children) != expected_children
            ):
                raise OSError(
                    errno.ESTALE,
                    "release cleanup staging inventory changed",
                    directory.path or ".",
                )
            for child_name in sorted(expected_children):
                child_path = (
                    child_name
                    if not directory.path
                    else f"{directory.path}/{child_name}"
                )
                expected = ledger.entries[child_path]
                observed = os.stat(
                    child_name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                _require_stage_entry_stat(observed, expected)
        finally:
            os.close(directory_fd)


def _make_stage_directories_writable(
    root_fd: int,
    ledger: _StageLedger,
) -> None:
    for entry in sorted(
        (
            value
            for value in ledger.entries.values()
            if value.is_directory
        ),
        key=lambda value: (value.path.count("/"), value.path),
        reverse=True,
    ):
        directory_fd = _open_stage_ledger_directory(
            root_fd,
            entry.path,
            ledger,
        )
        try:
            os.fchmod(directory_fd, 0o700)
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


def _remove_captured_stage_entry(
    root_fd: int,
    entry: _StageEntry,
    ledger: _StageLedger,
) -> None:
    parent_path = _stage_parent(entry.path)
    parent_fd = _open_stage_ledger_directory(
        root_fd,
        parent_path,
        ledger,
    )
    name = _stage_basename(entry.path)
    try:
        observed = os.stat(
            name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        _require_stage_entry_stat(observed, entry)
        if entry.is_directory:
            child_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
            try:
                if _entry_identity(os.fstat(child_fd)) != entry.identity:
                    raise OSError(
                        errno.ESTALE,
                        "release cleanup directory changed while opening",
                        entry.path,
                    )
                try:
                    remaining = _bounded_directory_names(
                        child_fd,
                        maximum_entries=0,
                    )
                except ValueError as error:
                    raise OSError(
                        errno.ESTALE,
                        "release cleanup directory is not empty",
                        entry.path,
                    ) from error
                if remaining:
                    raise OSError(
                        errno.ESTALE,
                        "release cleanup directory is not empty",
                        entry.path,
                    )
            finally:
                os.close(child_fd)
            _require_named_identity(
                parent_fd,
                name,
                expected_identity=entry.identity,
                expect_directory=True,
                label="release cleanup directory",
            )
            os.rmdir(name, dir_fd=parent_fd)
        else:
            _require_named_identity(
                parent_fd,
                name,
                expected_identity=entry.identity,
                expect_directory=False,
                label="release cleanup file",
            )
            os.unlink(name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _open_stage_ledger_directory(
    root_fd: int,
    path: str,
    ledger: _StageLedger,
) -> int:
    expected = ledger.entries.get(path)
    if expected is None or not expected.is_directory:
        raise OSError(errno.EIO, "release staging directory is not in its ledger")
    current_fd = os.dup(root_fd)
    try:
        if not path:
            if _entry_identity(os.fstat(current_fd)) != expected.identity:
                raise OSError(
                    errno.ESTALE,
                    "release staging root changed while opening",
                )
            return current_fd
        prefix = ""
        for component in path.split("/"):
            prefix = component if not prefix else f"{prefix}/{component}"
            component_entry = ledger.entries.get(prefix)
            if component_entry is None or not component_entry.is_directory:
                raise OSError(
                    errno.EIO,
                    "release staging directory path is not in its ledger",
                )
            next_fd = os.open(
                component,
                _DIRECTORY_FLAGS,
                dir_fd=current_fd,
            )
            os.close(current_fd)
            current_fd = next_fd
            if (
                _entry_identity(os.fstat(current_fd))
                != component_entry.identity
            ):
                raise OSError(
                    errno.ESTALE,
                    "release staging directory changed while opening",
                    prefix,
                )
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _require_stage_entry_stat(
    value: os.stat_result,
    expected: _StageEntry,
) -> None:
    observed_directory = stat.S_ISDIR(value.st_mode)
    observed_regular = stat.S_ISREG(value.st_mode)
    if (
        _entry_identity(value) != expected.identity
        or (expected.is_directory and not observed_directory)
        or (not expected.is_directory and not observed_regular)
    ):
        raise OSError(
            errno.ESTALE,
            "release staging entry changed after it was recorded",
            expected.path or ".",
        )


def _stage_parent(path: str) -> str:
    return path.rpartition("/")[0]


def _stage_basename(path: str) -> str:
    return path.rpartition("/")[2]


def _validate_regular_stat(
    value: os.stat_result,
    *,
    label: str,
    maximum_bytes: int,
) -> None:
    if not stat.S_ISREG(value.st_mode):
        raise ValueError(f"{label} is not a regular file")
    if stat.S_IMODE(value.st_mode) != RELEASE_FILE_MODE:
        raise ValueError(f"{label} mode must be exactly 0444")
    if value.st_nlink != 1:
        raise ValueError(f"{label} must have exactly one hard link")
    if value.st_size < 1 or value.st_size > maximum_bytes:
        raise ValueError(f"{label} exceeds its storage byte bound")


def _validate_directory_stat(value: os.stat_result, *, label: str) -> None:
    if not stat.S_ISDIR(value.st_mode):
        raise ValueError(f"{label} is not a directory")
    if stat.S_IMODE(value.st_mode) != RELEASE_DIRECTORY_MODE:
        raise ValueError(f"{label} mode must be exactly 0555")


def _directory_snapshot(directory_fd: int) -> tuple[int, ...]:
    return _directory_snapshot_from_stat(os.fstat(directory_fd))


def _directory_snapshot_from_stat(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _file_snapshot(value: os.stat_result) -> tuple[int, ...]:
    return _directory_snapshot_from_stat(value)


def _entry_identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _require_named_identity(
    parent_fd: int,
    name: str,
    *,
    expected_identity: tuple[int, int],
    expect_directory: bool,
    label: str,
) -> os.stat_result:
    observed = os.stat(
        name,
        dir_fd=parent_fd,
        follow_symlinks=False,
    )
    observed_type = (
        stat.S_ISDIR(observed.st_mode)
        if expect_directory
        else stat.S_ISREG(observed.st_mode)
    )
    if _entry_identity(observed) != expected_identity or not observed_type:
        raise OSError(
            errno.ESTALE,
            f"{label} changed after it was recorded",
            name,
        )
    return observed


def _require_exact_entries(directory_fd: int, expected: set[str]) -> None:
    actual = _bounded_directory_names(
        directory_fd,
        maximum_entries=len(expected),
    )
    if len(actual) != len(expected) or set(actual) != expected:
        raise ValueError("release directory contains extra or missing entries")


def _bounded_directory_names(
    directory_fd: int,
    *,
    maximum_entries: int,
) -> tuple[str, ...]:
    if (
        type(maximum_entries) is not int
        or isinstance(maximum_entries, bool)
        or maximum_entries < 0
        or maximum_entries > len(RELEASE_LAYOUT_PATHS)
    ):
        raise ValueError("release directory entry bound is invalid")
    names: list[str] = []
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            if len(names) >= maximum_entries:
                raise ValueError(
                    "release directory contains extra or missing entries"
                )
            names.append(entry.name)
    return tuple(names)


def _entry_exists(directory_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _validate_absolute_path(path: object, *, label: str) -> str:
    if type(path) is not str:
        raise TypeError(f"{label} must be an exact string")
    if (
        not path
        or "\0" in path
        or not os.path.isabs(path)
        or os.path.normpath(path) != path
    ):
        raise ValueError(f"{label} must be an exact normalized absolute path")
    return path


def _validate_relative_layout_path(path: str, *, allow_file: bool) -> None:
    allowed = RELEASE_LAYOUT_PATHS if allow_file else _PAYLOAD_DIRECTORIES
    if type(path) is not str or path not in allowed:
        raise ValueError("release path is outside the frozen allowlist")


def _validate_forbidden_roots(
    output_parent: str,
    forbidden_roots: tuple[str, ...],
) -> None:
    if type(forbidden_roots) is not tuple:
        raise TypeError("forbidden_roots must be an exact tuple")
    destination = os.path.join(output_parent, RELEASE_DIRECTORY)
    destination_physical = os.path.realpath(destination)
    for root in forbidden_roots:
        forbidden = _validate_absolute_path(
            root,
            label="forbidden release root",
        )
        forbidden_physical = os.path.realpath(forbidden)
        if (
            _paths_overlap(destination, forbidden)
            or _paths_overlap(destination_physical, forbidden_physical)
        ):
            raise ValueError(
                "release destination overlaps a forbidden root"
            )


def _paths_overlap(first: str, second: str) -> bool:
    common = os.path.commonpath((first, second))
    return common in (first, second)


def _require_digest(value: object, *, field: str) -> None:
    if (
        type(value) is not str
        or len(value) != _SHA256_HEX_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
