#!/usr/bin/env python3
"""Verify the built WitnessGap distribution through an isolated install.

The verification path deliberately builds a source archive first, validates
every archive member before extraction, builds the wheel from that extracted
source archive, verifies the wheel's metadata and RECORD closure, and finally
installs the wheel without an index into a fresh virtual environment.
"""

from __future__ import annotations

import base64
import csv
import gzip
import hashlib
import io
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import tomllib
import unicodedata
import venv
import zipfile
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from email import policy
from email.message import Message
from email.parser import BytesParser
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import BinaryIO, Final, Literal, NoReturn, cast

ROOT: Final = Path(__file__).resolve().parents[1]
EXPECTED_NAME: Final = "witnessgap"
EXPECTED_VERSION: Final = "0.0.1"
EXPECTED_SUMMARY: Final = "Identifiability certificates for tool-agent failure attribution"
EXPECTED_REQUIRES_PYTHON: Final = ">=3.12,<3.13"
EXPECTED_REQUIRES_PYTHON_SPECIFIERS: Final = frozenset({">=3.12", "<3.13"})
EXPECTED_PYTHON: Final = (3, 12, 3)
EXPECTED_BACKEND: Final = "hatchling.build"
EXPECTED_BACKEND_REQUIREMENT: Final = "hatchling==1.27.0"
EXPECTED_DEV_REQUIREMENTS: Final = frozenset(
    {
        "mypy<2,>=1.17; extra == 'dev'",
        "pytest-cov<8,>=6.2; extra == 'dev'",
        "pytest<9,>=8.4; extra == 'dev'",
        "ruff<1,>=0.12; extra == 'dev'",
    }
)
EXPECTED_ENTRY_POINTS: Final = b"[console_scripts]\nwitnessgap = witnessgap.cli:main\n"
EXPECTED_WHEEL_TAG: Final = "py3-none-any"
EXPECTED_OPTIONAL_DEV_REQUIREMENTS: Final = (
    "mypy>=1.17,<2",
    "pytest>=8.4,<9",
    "pytest-cov>=6.2,<8",
    "ruff>=0.12,<1",
)
EXPECTED_SDIST_INCLUDES: Final = (
    "/.github",
    "/.gitignore",
    "/.python-version",
    "/LICENSE",
    "/README.md",
    "/docs",
    "/pyproject.toml",
    "/requirements-dev.lock",
    "/src",
    "/test",
    "/tools",
)
EXPECTED_SDIST_ROOT_FILES: Final = frozenset(
    {
        ".python-version",
        ".gitignore",
        "LICENSE",
        "PKG-INFO",
        "README.md",
        "pyproject.toml",
        "requirements-dev.lock",
    }
)
EXPECTED_SDIST_ROOT_DIRECTORIES: Final = frozenset({".github", "docs", "src", "test", "tools"})
MAX_ARCHIVE_BYTES: Final = 64 << 20
MAX_MEMBER_BYTES: Final = 16 << 20
MAX_EXPANDED_BYTES: Final = 128 << 20
MAX_TAR_STREAM_BYTES: Final = 160 << 20
MAX_ARCHIVE_MEMBERS: Final = 4_096
MAX_METADATA_BYTES: Final = 2 << 20
MAX_PATH_BYTES: Final = 4_096
MAX_COMPONENT_BYTES: Final = 255
MAX_BUILD_OUTPUT_BYTES: Final = 1 << 20
PROCESS_TIMEOUT_SECONDS: Final = 300
PROCESS_DRAIN_TIMEOUT_SECONDS: Final = 5
MAX_COMPRESSION_RATIO: Final = 200
COMPRESSION_RATIO_GRACE_BYTES: Final = 4_096
EXPECTED_PARTICIPANT_CASES: Final = 300
EXPECTED_FRESH_PROCESS_RUNS: Final = 1_200
RECORD_FIELD_COUNT: Final = 3
_SOURCE_DATE_EPOCH: Final = "315532800"
_CONTROL_CATEGORIES: Final = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})
_WINDOWS_RESERVED_NAMES: Final = frozenset(
    {"aux", "clock$", "con", "nul", "prn"}
    | {f"com{number}" for number in range(1, 10)}
    | {f"lpt{number}" for number in range(1, 10)}
)
_VERSION_PATTERN: Final = re.compile(r"[0-9]+(?:\.[0-9]+)*(?:[a-z][0-9]+)?")
_ARCHIVE_KIND = Literal["directory", "file"]


class DistributionVerificationError(ValueError):
    """A built artifact violated the reviewed distribution contract."""


@dataclass(frozen=True, slots=True)
class _ArchiveEntry:
    path: str
    kind: _ARCHIVE_KIND
    size: int


@dataclass(frozen=True, slots=True)
class _CoreMetadata:
    name: str
    version: str
    requires_python: str
    description: str


@dataclass(frozen=True, slots=True)
class _InstalledRuntime:
    python: Path
    console: Path
    cwd: Path
    environment_root: Path
    environment: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class _WheelLayout:
    dist_info: str
    metadata: str
    wheel: str
    entry_points: str
    record: str
    license: str


def _reject(message: str) -> NoReturn:
    raise DistributionVerificationError(message)


def _path_parts(raw_path: str, *, directory: bool = False) -> tuple[str, ...]:
    if type(raw_path) is not str or not raw_path:
        _reject("archive paths must be non-empty exact strings")
    if "\x00" in raw_path or "\\" in raw_path or raw_path.startswith("/"):
        _reject(f"archive path is not a portable relative POSIX path: {raw_path!r}")

    candidate = raw_path[:-1] if directory and raw_path.endswith("/") else raw_path
    if not candidate or candidate.endswith("/"):
        _reject(f"archive path has an empty component: {raw_path!r}")
    encoded = candidate.encode("utf-8", errors="strict")
    if len(encoded) > MAX_PATH_BYTES:
        _reject("archive path exceeds the byte bound")

    parts = tuple(candidate.split("/"))
    for part in parts:
        if not part or part in {".", ".."}:
            _reject(f"archive path has an unsafe component: {raw_path!r}")
        if len(part.encode("utf-8", errors="strict")) > MAX_COMPONENT_BYTES:
            _reject("archive path component exceeds the byte bound")
        if part != unicodedata.normalize("NFC", part):
            _reject(f"archive path is not NFC-normalized: {raw_path!r}")
        if part.rstrip(" .") != part or ":" in part:
            _reject(f"archive path is not portable across supported filesystems: {raw_path!r}")
        if any(unicodedata.category(character) in _CONTROL_CATEGORIES for character in part):
            _reject(f"archive path contains a control character: {raw_path!r}")
        if part.split(".", maxsplit=1)[0].casefold() in _WINDOWS_RESERVED_NAMES:
            _reject(f"archive path uses a reserved filename: {raw_path!r}")
    return parts


def _portable_path_key(raw_path: str, *, directory: bool = False) -> str:
    parts = _path_parts(raw_path, directory=directory)
    return "/".join(unicodedata.normalize("NFKC", part).casefold() for part in parts)


def _validate_archive_entries(entries: Sequence[_ArchiveEntry]) -> tuple[_ArchiveEntry, ...]:
    if not entries or len(entries) > MAX_ARCHIVE_MEMBERS:
        _reject("archive member count is outside the accepted bound")

    by_key: dict[str, _ArchiveEntry] = {}
    total_size = 0
    for entry in entries:
        if entry.kind not in {"directory", "file"}:
            _reject("archive contains an unsupported entry type")
        if type(entry.size) is not int or entry.size < 0:
            _reject("archive member size must be a non-negative exact integer")
        if entry.kind == "directory" and entry.size != 0:
            _reject("archive directory entries must be empty")
        if entry.size > MAX_MEMBER_BYTES:
            _reject("archive member exceeds the byte bound")
        total_size += entry.size
        if total_size > MAX_EXPANDED_BYTES:
            _reject("archive expanded size exceeds the byte bound")

        key = _portable_path_key(entry.path, directory=entry.kind == "directory")
        previous = by_key.get(key)
        if previous is not None:
            _reject(
                "archive contains duplicate or normalized/casefold-colliding paths: "
                f"{previous.path!r}, {entry.path!r}"
            )
        by_key[key] = entry

    file_keys = {key for key, entry in by_key.items() if entry.kind == "file"}
    for key, entry in by_key.items():
        components = key.split("/")
        if any("/".join(components[:end]) in file_keys for end in range(1, len(components))):
            _reject(f"archive file shadows a parent directory of {entry.path!r}")
    return tuple(entries)


def _require_regular_artifact(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        _reject("expected build artifact is absent")
    if not stat.S_ISREG(metadata.st_mode):
        _reject("build artifact must be a regular file")
    if metadata.st_size < 1 or metadata.st_size > MAX_ARCHIVE_BYTES:
        _reject("build artifact size is outside the accepted bound")


def _tar_members_and_entries(
    archive: tarfile.TarFile,
) -> tuple[tuple[tarfile.TarInfo, ...], tuple[_ArchiveEntry, ...]]:
    members: list[tarfile.TarInfo] = []
    entries: list[_ArchiveEntry] = []
    total_size = 0
    for member in archive:
        if len(members) >= MAX_ARCHIVE_MEMBERS:
            _reject("source archive member count exceeds the accepted bound")
        members.append(member)
        if member.isdir():
            if member.size != 0:
                _reject(f"source archive directory has a nonzero payload: {member.name!r}")
            kind: _ARCHIVE_KIND = "directory"
            size = 0
        elif member.isfile() and not member.issparse():
            kind = "file"
            size = member.size
        else:
            _reject(f"source archive contains a link or special member: {member.name!r}")
        if member.linkname:
            _reject(f"source archive member has an unexpected link target: {member.name!r}")
        if type(size) is not int or size < 0 or size > MAX_MEMBER_BYTES:
            _reject(f"source archive member size is outside the accepted bound: {member.name!r}")
        total_size += size
        if total_size > MAX_EXPANDED_BYTES:
            _reject("source archive expanded payload exceeds the accepted bound")
        entries.append(_ArchiveEntry(member.name, kind, size))
    return tuple(members), _validate_archive_entries(entries)


def _single_sdist_root(entries: Sequence[_ArchiveEntry]) -> str:
    roots = {_path_parts(entry.path, directory=entry.kind == "directory")[0] for entry in entries}
    if len(roots) != 1:
        _reject("source archive must contain exactly one top-level directory")
    root = next(iter(roots))
    for entry in entries:
        parts = _path_parts(entry.path, directory=entry.kind == "directory")
        if len(parts) == 1 and entry.kind != "directory":
            _reject("source archive files must be nested below its top-level directory")
    return root


def _require_bounded_gzip_stream(archive_path: Path) -> None:
    expanded_bytes = 0
    try:
        with gzip.open(archive_path, mode="rb") as stream:
            while chunk := stream.read(1 << 20):
                expanded_bytes += len(chunk)
                if expanded_bytes > MAX_TAR_STREAM_BYTES:
                    _reject("source archive decompressed stream exceeds the accepted bound")
    except (EOFError, gzip.BadGzipFile, OSError) as error:
        raise DistributionVerificationError("source archive gzip stream is malformed") from error


def _extract_validated_sdist(archive_path: Path, destination: Path) -> Path:
    """Preflight every tar member, then extract regular bytes without extractall."""

    _require_regular_artifact(archive_path)
    _require_bounded_gzip_stream(archive_path)
    if destination.exists():
        _reject("source extraction destination must not already exist")
    destination.mkdir(mode=0o700, parents=True)
    destination_root = destination.resolve(strict=True)

    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            members, entries = _tar_members_and_entries(archive)
            source_root_name = _single_sdist_root(entries)
            for member, entry in zip(members, entries, strict=True):
                parts = _path_parts(entry.path, directory=entry.kind == "directory")
                target = destination.joinpath(*parts)
                resolved_target = target.resolve(strict=False)
                if not resolved_target.is_relative_to(destination_root):
                    _reject("source archive member escaped the extraction root")
                if entry.kind == "directory":
                    target.mkdir(mode=0o755, parents=True, exist_ok=True)
                    continue

                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    _reject("source archive regular member has no readable payload")
                payload = source.read(MAX_MEMBER_BYTES + 1)
                if len(payload) != entry.size:
                    _reject("source archive member size differs from its payload")
                with target.open("xb") as stream:
                    written = stream.write(payload)
                if written != len(payload):
                    _reject("source archive extraction was incomplete")
                target.chmod(0o644)
    except (tarfile.TarError, UnicodeError) as error:
        raise DistributionVerificationError("source archive is malformed") from error

    source_root = destination / source_root_name
    if not source_root.is_dir() or source_root.is_symlink():
        _reject("source archive top-level directory was not materialized safely")
    return source_root


def _zip_entry_kind(info: zipfile.ZipInfo) -> _ARCHIVE_KIND:
    if info.flag_bits & 0x1:
        _reject(f"wheel contains an encrypted member: {info.filename!r}")
    if info.filename != info.orig_filename:
        _reject("wheel member name contains an embedded NUL byte")
    unix_mode = info.external_attr >> 16
    file_type = stat.S_IFMT(unix_mode)
    if info.is_dir():
        if file_type not in {0, stat.S_IFDIR}:
            _reject(f"wheel directory has a conflicting file type: {info.filename!r}")
        return "directory"
    if file_type not in {0, stat.S_IFREG}:
        _reject(f"wheel contains a link or special member: {info.filename!r}")
    if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
        _reject(f"wheel uses an unsupported compression method: {info.filename!r}")
    if info.file_size > COMPRESSION_RATIO_GRACE_BYTES and (
        info.compress_size <= 0 or info.file_size > info.compress_size * MAX_COMPRESSION_RATIO
    ):
        _reject(f"wheel member exceeds the compression-ratio bound: {info.filename!r}")
    return "file"


def _zip_entries(archive: zipfile.ZipFile) -> tuple[_ArchiveEntry, ...]:
    entries = tuple(
        _ArchiveEntry(info.filename, _zip_entry_kind(info), info.file_size)
        for info in archive.infolist()
    )
    return _validate_archive_entries(entries)


def _read_validated_wheel(archive_path: Path) -> dict[str, bytes]:
    _require_regular_artifact(archive_path)
    try:
        with zipfile.ZipFile(archive_path, mode="r") as archive:
            entries = _zip_entries(archive)
            payloads: dict[str, bytes] = {}
            for info, entry in zip(archive.infolist(), entries, strict=True):
                if entry.kind == "directory":
                    _reject("wheel must not contain explicit directory members")
                payload = archive.read(info)
                if len(payload) != entry.size:
                    _reject("wheel member size differs from its payload")
                payloads[entry.path] = payload
            bad_member = archive.testzip()
            if bad_member is not None:
                _reject(f"wheel member failed its ZIP CRC check: {bad_member!r}")
    except (UnicodeError, zipfile.BadZipFile, RuntimeError) as error:
        raise DistributionVerificationError("wheel archive is malformed") from error
    return payloads


def _single_header(message: Message, name: str) -> str:
    values = message.get_all(name, failobj=[])
    if len(values) != 1:
        _reject(f"distribution metadata must contain exactly one {name} header")
    value = values[0]
    if not isinstance(value, str) or not value.strip():
        _reject(f"distribution metadata {name} header is malformed")
    return value.strip()


def _metadata_description(payload: bytes) -> str:
    separator = b"\r\n\r\n" if b"\r\n\r\n" in payload else b"\n\n"
    if separator not in payload:
        _reject("distribution metadata does not contain a header/body separator")
    description_payload = payload.split(separator, maxsplit=1)[1]
    try:
        description = description_payload.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise DistributionVerificationError("distribution description is not UTF-8") from error
    if not description.strip():
        _reject("distribution metadata must contain the README description")
    return description


def _parse_core_metadata(payload: bytes) -> _CoreMetadata:
    if not payload or len(payload) > MAX_METADATA_BYTES or b"\x00" in payload:
        _reject("distribution metadata size or encoding is invalid")
    try:
        message = BytesParser(policy=policy.default).parsebytes(payload)
    except (UnicodeError, ValueError) as error:
        raise DistributionVerificationError("distribution metadata is malformed") from error
    if message.defects:
        _reject("distribution metadata contains parser defects")

    name = _single_header(message, "Name")
    version = _single_header(message, "Version")
    metadata_version = _single_header(message, "Metadata-Version")
    summary = _single_header(message, "Summary")
    requires_python = _single_header(message, "Requires-Python")
    if name != EXPECTED_NAME:
        _reject("distribution metadata project name differs")
    if version != EXPECTED_VERSION or _VERSION_PATTERN.fullmatch(version) is None:
        _reject("distribution metadata version differs from the reviewed release version")
    if metadata_version != "2.4" or summary != EXPECTED_SUMMARY:
        _reject("distribution metadata version or summary differs from the reviewed contract")
    specifiers = tuple(part.strip() for part in requires_python.split(",") if part.strip())
    if len(specifiers) != len(set(specifiers)) or (
        frozenset(specifiers) != EXPECTED_REQUIRES_PYTHON_SPECIFIERS
    ):
        _reject("Requires-Python must bind the package to >=3.12,<3.13")
    requirements = message.get_all("Requires-Dist", failobj=[])
    if any(not isinstance(requirement, str) for requirement in requirements):
        _reject("distribution metadata contains a malformed Requires-Dist header")
    parsed_requirements = tuple(cast(str, requirement) for requirement in requirements)
    if len(parsed_requirements) != len(set(parsed_requirements)) or (
        frozenset(parsed_requirements) != EXPECTED_DEV_REQUIREMENTS
    ):
        _reject("distribution metadata must contain only the reviewed dev-extra requirements")
    extras = tuple(str(extra) for extra in message.get_all("Provides-Extra", failobj=[]))
    if extras != ("dev",):
        _reject("distribution metadata must expose exactly the reviewed dev extra")
    if message.get_all("Dynamic", failobj=[]):
        _reject("built distributions must not contain dynamic metadata fields")
    description = _metadata_description(payload)
    return _CoreMetadata(
        name=name,
        version=version,
        requires_python=requires_python,
        description=description,
    )


def _validate_pyproject(source_root: Path, metadata: _CoreMetadata) -> None:
    path = source_root / "pyproject.toml"
    try:
        raw = path.read_bytes()
        document = tomllib.loads(raw.decode("utf-8", errors="strict"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise DistributionVerificationError("sdist pyproject.toml is malformed") from error
    project = document.get("project")
    build_system = document.get("build-system")
    if type(project) is not dict or type(build_system) is not dict:
        _reject("sdist pyproject.toml lacks closed project/build-system tables")
    project_table = cast(dict[str, object], project)
    build_table = cast(dict[str, object], build_system)
    if (
        project_table.get("name") != metadata.name
        or project_table.get("version") != metadata.version
        or project_table.get("description") != EXPECTED_SUMMARY
        or project_table.get("requires-python") != EXPECTED_REQUIRES_PYTHON
        or project_table.get("dynamic") is not None
    ):
        _reject("sdist pyproject metadata differs from the built core metadata")
    if project_table.get("scripts") != {"witnessgap": "witnessgap.cli:main"}:
        _reject("sdist pyproject console-script table differs")
    if project_table.get("optional-dependencies") != {
        "dev": list(EXPECTED_OPTIONAL_DEV_REQUIREMENTS)
    }:
        _reject("sdist pyproject dev-extra requirements differ")
    requirements = build_table.get("requires")
    if (
        requirements != [EXPECTED_BACKEND_REQUIREMENT]
        or build_table.get("build-backend") != EXPECTED_BACKEND
    ):
        _reject("sdist build backend is not the single pinned Hatchling backend")

    tool = document.get("tool")
    if type(tool) is not dict:
        _reject("sdist pyproject lacks the reviewed Hatch build tables")
    hatch = cast(dict[str, object], tool).get("hatch")
    if type(hatch) is not dict or set(hatch) != {"build"}:
        _reject("sdist pyproject Hatch configuration is not closed")
    hatch_build = cast(dict[str, object], hatch).get("build")
    if type(hatch_build) is not dict or set(hatch_build) != {"targets"}:
        _reject("sdist pyproject Hatch build configuration is not closed")
    targets = cast(dict[str, object], hatch_build).get("targets")
    if type(targets) is not dict or set(targets) != {"sdist", "wheel"}:
        _reject("sdist pyproject Hatch target set differs")
    target_tables = cast(dict[str, object], targets)
    if target_tables.get("wheel") != {"packages": ["src/witnessgap"]} or target_tables.get(
        "sdist"
    ) != {"include": list(EXPECTED_SDIST_INCLUDES)}:
        _reject("sdist pyproject Hatch target configuration differs")


def _declared_source_payloads(source_root: Path) -> dict[str, bytes]:
    payloads: dict[str, bytes] = {}
    for declared in EXPECTED_SDIST_INCLUDES:
        relative = declared.removeprefix("/")
        path = source_root / relative
        candidates = (path,) if path.is_file() else tuple(path.rglob("*")) if path.is_dir() else ()
        if not candidates:
            _reject(f"declared sdist input is absent or empty: {declared}")
        for candidate in candidates:
            metadata = candidate.lstat()
            if candidate.is_symlink() or not (
                stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)
            ):
                _reject("declared sdist inputs contain a link or special file")
            if not stat.S_ISREG(metadata.st_mode):
                continue
            candidate_relative = candidate.relative_to(source_root).as_posix()
            components = set(candidate_relative.split("/"))
            if components.intersection(
                {".mypy_cache", ".pytest_cache", ".ruff_cache", "__pycache__"}
            ) or candidate_relative.endswith((".pyc", ".pyo")):
                continue
            payloads[candidate_relative] = candidate.read_bytes()
    if not payloads:
        _reject("declared sdist surface contains no regular files")
    return payloads


def _validate_sdist(
    archive_path: Path,
    extraction_directory: Path,
) -> tuple[Path, bytes, _CoreMetadata]:
    source_root = _extract_validated_sdist(archive_path, extraction_directory)
    relative_files = {
        path.relative_to(source_root).as_posix()
        for path in source_root.rglob("*")
        if path.is_file()
    }
    required_files = {
        ".python-version",
        "LICENSE",
        "PKG-INFO",
        "README.md",
        "pyproject.toml",
        "requirements-dev.lock",
        "src/witnessgap/py.typed",
        "test/test_distribution.py",
        "tools/verify_distribution.py",
    }
    missing = required_files - relative_files
    if missing:
        _reject("source archive omits required release inputs: " + ", ".join(sorted(missing)))
    forbidden_components = {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
    }
    if any(forbidden_components.intersection(path.split("/")) for path in relative_files):
        _reject("source archive contains repository or generated cache state")
    if any(path.endswith((".pyc", ".pyo", ".whl", ".tar.gz")) for path in relative_files):
        _reject("source archive recursively contains a generated distribution")
    unexpected = {
        path
        for path in relative_files
        if path not in EXPECTED_SDIST_ROOT_FILES
        and path.split("/", maxsplit=1)[0] not in EXPECTED_SDIST_ROOT_DIRECTORIES
    }
    if unexpected:
        _reject("source archive contains files outside the declared surface")

    actual_payloads = {
        path: (source_root / path).read_bytes() for path in relative_files if path != "PKG-INFO"
    }
    if actual_payloads != _declared_source_payloads(ROOT):
        _reject("source archive files differ byte-for-byte from the declared repository surface")

    metadata_payload = (source_root / "PKG-INFO").read_bytes()
    metadata = _parse_core_metadata(metadata_payload)
    try:
        readme_payload = (source_root / "README.md").read_bytes()
        readme_payload.decode("utf-8", errors="strict")
    except (OSError, UnicodeError) as error:
        raise DistributionVerificationError("sdist README is not readable UTF-8") from error
    if metadata.description.encode("utf-8") != readme_payload:
        _reject("sdist core metadata description differs byte-for-byte from README.md")
    expected_root = f"{EXPECTED_NAME}-{metadata.version}"
    if source_root.name != expected_root or archive_path.name != f"{expected_root}.tar.gz":
        _reject("source archive filename or top-level directory differs from metadata")
    _validate_pyproject(source_root, metadata)
    return source_root, metadata_payload, metadata


def _record_digest(payload: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=")
    return f"sha256={digest.decode('ascii')}"


def _validate_wheel_record(payloads: Mapping[str, bytes], record_path: str) -> None:
    record_payload = payloads.get(record_path)
    if record_payload is None:
        _reject("wheel omits its RECORD file")
    try:
        text = record_payload.decode("utf-8", errors="strict")
        rows = tuple(csv.reader(io.StringIO(text, newline="")))
    except (csv.Error, UnicodeError) as error:
        raise DistributionVerificationError("wheel RECORD is malformed") from error
    if not rows or not text.endswith("\n"):
        _reject("wheel RECORD must be a non-empty newline-terminated CSV")

    by_path: dict[str, tuple[str, str]] = {}
    portable_keys: set[str] = set()
    for row in rows:
        if len(row) != RECORD_FIELD_COUNT:
            _reject("wheel RECORD rows must contain exactly three fields")
        path, digest, size = row
        key = _portable_path_key(path)
        if path in by_path or key in portable_keys:
            _reject("wheel RECORD contains duplicate or colliding paths")
        by_path[path] = (digest, size)
        portable_keys.add(key)

    if set(by_path) != set(payloads):
        _reject("wheel RECORD path set does not close over the wheel payload")
    for path, payload in payloads.items():
        digest, size = by_path[path]
        if path == record_path:
            if digest or size:
                _reject("wheel RECORD must leave its own digest and size empty")
            continue
        if digest != _record_digest(payload) or size != str(len(payload)):
            _reject(f"wheel RECORD digest or size differs for {path!r}")


def _wheel_header_values(payload: bytes, name: str) -> tuple[str, ...]:
    message = BytesParser(policy=policy.default).parsebytes(payload)
    if message.defects:
        _reject("wheel WHEEL metadata contains parser defects")
    values = message.get_all(name, failobj=[])
    if any(not isinstance(value, str) for value in values):
        _reject(f"wheel {name} header is malformed")
    return tuple(cast(str, value).strip() for value in values)


def _source_package_payloads(source_root: Path) -> dict[str, bytes]:
    package_root = source_root / "src" / EXPECTED_NAME
    if not package_root.is_dir() or package_root.is_symlink():
        _reject("sdist source package directory is absent or unsafe")
    payloads: dict[str, bytes] = {}
    for path in package_root.rglob("*"):
        metadata = path.lstat()
        if path.is_symlink() or not (
            stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)
        ):
            _reject("sdist source package contains a link or special file")
        if not stat.S_ISREG(metadata.st_mode):
            continue
        relative = path.relative_to(package_root).as_posix()
        payloads[f"{EXPECTED_NAME}/{relative}"] = path.read_bytes()
    if not payloads:
        _reject("sdist source package contains no regular files")
    return payloads


def _wheel_layout(prefix: str) -> _WheelLayout:
    dist_info = f"{prefix}.dist-info"
    return _WheelLayout(
        dist_info=dist_info,
        metadata=f"{dist_info}/METADATA",
        wheel=f"{dist_info}/WHEEL",
        entry_points=f"{dist_info}/entry_points.txt",
        record=f"{dist_info}/RECORD",
        license=f"{dist_info}/licenses/LICENSE",
    )


def _validate_wheel_surface(
    payloads: Mapping[str, bytes],
    layout: _WheelLayout,
    source_root: Path,
) -> None:
    required_paths = {
        f"{EXPECTED_NAME}/__init__.py",
        f"{EXPECTED_NAME}/__main__.py",
        f"{EXPECTED_NAME}/cli.py",
        f"{EXPECTED_NAME}/py.typed",
        layout.metadata,
        layout.wheel,
        layout.entry_points,
        layout.record,
        layout.license,
    }
    missing = required_paths - set(payloads)
    if missing:
        _reject("wheel omits required package files: " + ", ".join(sorted(missing)))
    if any(not path.startswith((f"{EXPECTED_NAME}/", f"{layout.dist_info}/")) for path in payloads):
        _reject("wheel contains files outside the package and its dist-info directory")
    if any(path.endswith((".pyc", ".pyo", ".so", ".pyd")) for path in payloads):
        _reject("pure-Python wheel contains generated bytecode or a native extension")
    if any(path.endswith(("RECORD.jws", "RECORD.p7s")) for path in payloads):
        _reject("wheel contains an unreviewed RECORD signature sidecar")

    source_payloads = _source_package_payloads(source_root)
    wheel_package_payloads = {
        path: payload for path, payload in payloads.items() if path.startswith(f"{EXPECTED_NAME}/")
    }
    if wheel_package_payloads != source_payloads:
        _reject("wheel package files differ byte-for-byte from the extracted sdist source")
    expected_paths = set(source_payloads) | {
        layout.metadata,
        layout.wheel,
        layout.entry_points,
        layout.record,
        layout.license,
    }
    if set(payloads) != expected_paths:
        _reject("wheel contains files outside the exact package and dist-info surface")
    if payloads[layout.license] != (source_root / "LICENSE").read_bytes():
        _reject("wheel license differs from the extracted sdist license")


def _validate_wheel_metadata(
    payloads: Mapping[str, bytes],
    layout: _WheelLayout,
    sdist_metadata_payload: bytes,
    sdist_metadata: _CoreMetadata,
) -> None:
    _validate_wheel_record(payloads, layout.record)
    wheel_metadata_payload = payloads[layout.metadata]
    if wheel_metadata_payload != sdist_metadata_payload:
        _reject("sdist PKG-INFO and wheel METADATA are not byte-identical")
    if _parse_core_metadata(wheel_metadata_payload) != sdist_metadata:
        _reject("sdist and wheel core metadata differ")
    if payloads[layout.entry_points] != EXPECTED_ENTRY_POINTS:
        _reject("wheel console entry point differs from witnessgap.cli:main")
    if payloads[f"{EXPECTED_NAME}/py.typed"].strip():
        _reject("wheel py.typed marker must contain no marker directives")
    if _wheel_header_values(payloads[layout.wheel], "Wheel-Version") != ("1.0",):
        _reject("wheel format version differs")
    if _wheel_header_values(payloads[layout.wheel], "Root-Is-Purelib") != ("true",):
        _reject("wheel is not marked as a purelib distribution")
    if _wheel_header_values(payloads[layout.wheel], "Tag") != (EXPECTED_WHEEL_TAG,):
        _reject("wheel metadata is not tagged exactly py3-none-any")


def _validate_wheel(
    archive_path: Path,
    sdist_metadata_payload: bytes,
    sdist_metadata: _CoreMetadata,
    source_root: Path,
) -> None:
    expected_prefix = f"{EXPECTED_NAME}-{sdist_metadata.version}"
    expected_filename = f"{expected_prefix}-{EXPECTED_WHEEL_TAG}.whl"
    if archive_path.name != expected_filename:
        _reject("wheel filename is not the exact py3-none-any filename")

    payloads = _read_validated_wheel(archive_path)
    layout = _wheel_layout(expected_prefix)
    _validate_wheel_surface(payloads, layout, source_root)
    _validate_wheel_metadata(payloads, layout, sdist_metadata_payload, sdist_metadata)


def _closed_environment(home: Path, temporary: Path) -> dict[str, str]:
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary.mkdir(mode=0o700, parents=True, exist_ok=True)
    return {
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.defpath,
        "PIP_CONFIG_FILE": os.devnull,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "SOURCE_DATE_EPOCH": _SOURCE_DATE_EPOCH,
        "TMPDIR": str(temporary),
        "TZ": "UTC",
    }


def _read_bounded_pipe(
    stream: BinaryIO,
    sink: bytearray,
    exceeded: threading.Event,
) -> None:
    try:
        while chunk := stream.read(64 << 10):
            if len(sink) + len(chunk) > MAX_BUILD_OUTPUT_BYTES:
                exceeded.set()
                continue
            if not exceeded.is_set():
                sink.extend(chunk)
    finally:
        stream.close()


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    try:
        process.wait(timeout=PROCESS_DRAIN_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _bounded_process(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    label: str,
) -> subprocess.CompletedProcess[bytes]:
    arguments = tuple(command)
    try:
        process = subprocess.Popen(
            arguments,
            cwd=cwd,
            env=dict(env),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        raise DistributionVerificationError(f"{label} could not be started") from error
    if process.stdout is None or process.stderr is None:
        _kill_process_group(process)
        _reject(f"{label} did not expose bounded output pipes")

    stdout = bytearray()
    stderr = bytearray()
    exceeded = threading.Event()
    readers = (
        threading.Thread(
            target=_read_bounded_pipe,
            args=(process.stdout, stdout, exceeded),
            daemon=True,
        ),
        threading.Thread(
            target=_read_bounded_pipe,
            args=(process.stderr, stderr, exceeded),
            daemon=True,
        ),
    )
    for reader in readers:
        reader.start()

    deadline = time.monotonic() + PROCESS_TIMEOUT_SECONDS
    while process.poll() is None and not exceeded.is_set():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        exceeded.wait(timeout=min(remaining, 0.05))
    timed_out = process.poll() is None and time.monotonic() >= deadline
    if exceeded.is_set() or timed_out:
        _kill_process_group(process)
    for reader in readers:
        reader.join(timeout=PROCESS_DRAIN_TIMEOUT_SECONDS)
    if any(reader.is_alive() for reader in readers):
        _kill_process_group(process)
        _reject(f"{label} left an output pipe open after process exit")
    _kill_process_group(process)
    if exceeded.is_set():
        _reject(f"{label} produced output beyond the accepted bound")
    if timed_out:
        _reject(f"{label} exceeded the process timeout")
    returncode = process.wait()
    if returncode != 0:
        _reject(f"{label} failed with exit code {returncode}")
    return subprocess.CompletedProcess(arguments, returncode, bytes(stdout), bytes(stderr))


def _backend_build(
    function: Literal["build_sdist", "build_wheel"],
    *,
    cwd: Path,
    output: Path,
) -> Path:
    output.mkdir(mode=0o700, parents=True)
    environment = _closed_environment(
        output.parent / f"{output.name}-home",
        output.parent / f"{output.name}-tmp",
    )
    program = (
        f"import sys\nfrom hatchling.build import {function}\nprint({function}(sys.argv[1]))\n"
    )
    completed = _bounded_process(
        (sys.executable, "-I", "-B", "-c", program, str(output)),
        cwd=cwd,
        env=environment,
        label=f"Hatchling {function}",
    )
    if completed.stderr:
        _reject(f"Hatchling {function} wrote unexpected standard error")
    try:
        lines = completed.stdout.decode("utf-8", errors="strict").splitlines()
    except UnicodeError as error:
        raise DistributionVerificationError("Hatchling emitted non-UTF-8 output") from error
    if len(lines) != 1:
        _reject("Hatchling must report exactly one artifact filename")
    artifact_name = lines[0]
    if len(_path_parts(artifact_name)) != 1:
        _reject("Hatchling reported a non-local artifact filename")
    artifact = output / artifact_name
    _require_regular_artifact(artifact)
    artifacts = tuple(output.iterdir())
    if artifacts != (artifact,):
        _reject("Hatchling output directory does not contain exactly the reported artifact")
    return artifact


def _require_identical_artifacts(first: Path, second: Path, *, label: str) -> None:
    if first.name != second.name or first.read_bytes() != second.read_bytes():
        _reject(f"repeated {label} builds are not byte-for-byte reproducible")


def _require_path_free_output(payload: bytes, forbidden_paths: Sequence[Path]) -> None:
    if b"\x00" in payload:
        _reject("installed smoke output contains a NUL byte")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise DistributionVerificationError("installed smoke output is not UTF-8") from error
    forbidden = {str(path.resolve(strict=False)) for path in forbidden_paths}
    forbidden.update({"/home/", "file://", "\\"})
    if any(fragment and fragment in text for fragment in forbidden):
        _reject("installed smoke output exposes a host path")


def _json_object(payload: bytes, *, label: str) -> dict[str, object]:
    try:
        decoded = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise DistributionVerificationError(f"{label} emitted malformed JSON") from error
    if type(decoded) is not dict:
        _reject(f"{label} did not emit a JSON object")
    return cast(dict[str, object], decoded)


def _verify_installed_import(runtime: _InstalledRuntime, metadata: _CoreMetadata) -> None:
    program = (
        "import importlib.metadata, json, pathlib, witnessgap\n"
        "print(json.dumps({'package_file': str(pathlib.Path(witnessgap.__file__).resolve()), "
        "'version': importlib.metadata.version('witnessgap')}, sort_keys=True))\n"
    )
    completed = _bounded_process(
        (str(runtime.python), "-I", "-B", "-c", program),
        cwd=runtime.cwd,
        env=runtime.environment,
        label="installed metadata and import-location probe",
    )
    if completed.stderr:
        _reject("installed metadata and import-location probe wrote unexpected standard error")
    payload = _json_object(completed.stdout, label="installed metadata probe")
    package_file_value = payload.get("package_file")
    if type(package_file_value) is not str or payload.get("version") != metadata.version:
        _reject("installed metadata probe differs from wheel metadata")
    package_file = Path(package_file_value).resolve(strict=True)
    if not package_file.is_relative_to(
        runtime.environment_root.resolve(strict=True)
    ) or package_file.is_relative_to(ROOT):
        _reject("installed package import did not resolve inside the clean environment")


def _verify_installed_versions(runtime: _InstalledRuntime, metadata: _CoreMetadata) -> bytes:
    module = _bounded_process(
        (str(runtime.python), "-I", "-m", EXPECTED_NAME, "--version"),
        cwd=runtime.cwd,
        env=runtime.environment,
        label="installed module version smoke",
    )
    console = _bounded_process(
        (str(runtime.console), "--version"),
        cwd=runtime.cwd,
        env=runtime.environment,
        label="installed console version smoke",
    )
    expected = f"{EXPECTED_NAME} {metadata.version}\n".encode()
    if module.stderr or console.stderr:
        _reject("installed version smoke wrote unexpected standard error")
    if module.stdout != expected or console.stdout != expected:
        _reject("installed module and console versions differ from wheel metadata")
    return module.stdout


def _verify_installed_example(runtime: _InstalledRuntime) -> bytes:
    module = _bounded_process(
        (str(runtime.python), "-I", "-m", EXPECTED_NAME, "example", "--compact"),
        cwd=runtime.cwd,
        env=runtime.environment,
        label="installed module behavior smoke",
    )
    console = _bounded_process(
        (str(runtime.console), "example", "--compact"),
        cwd=runtime.cwd,
        env=runtime.environment,
        label="installed console behavior smoke",
    )
    if module.stderr or console.stderr:
        _reject("installed behavior smoke wrote unexpected standard error")
    if module.stdout != console.stdout:
        _reject("installed module and console entry points emit different bytes")
    receipt = _json_object(module.stdout, label="installed behavior smoke")
    if (
        receipt.get("format") != "witnessgap.example-receipt.v1"
        or receipt.get("verdict") != "not_identifiable"
        or receipt.get("official") is not False
    ):
        _reject("installed behavior smoke emitted an unexpected receipt")
    return module.stdout


def _verify_installed_workspace(runtime: _InstalledRuntime) -> bytes:
    completed = _bounded_process(
        (str(runtime.python), "-I", "-m", EXPECTED_NAME, "workspace100", "--compact"),
        cwd=runtime.cwd,
        env=runtime.environment,
        label="installed Workspace-100 construction smoke",
    )
    if completed.stderr:
        _reject("installed Workspace-100 smoke wrote unexpected standard error")
    payload = _json_object(completed.stdout, label="installed Workspace-100 smoke")
    counts = payload.get("counts")
    if (
        payload.get("format") != "witnessgap.workspace100-status.v1"
        or payload.get("official") is not False
        or payload.get("public_release_published") is not False
        or type(counts) is not dict
        or cast(dict[str, object], counts).get("participant_cases") != EXPECTED_PARTICIPANT_CASES
        or cast(dict[str, object], counts).get("fresh_process_runs_in_full_matrix")
        != EXPECTED_FRESH_PROCESS_RUNS
    ):
        _reject("installed Workspace-100 smoke emitted unexpected construction facts")
    return completed.stdout


def _isolated_install_smoke(wheel: Path, metadata: _CoreMetadata, work_root: Path) -> None:
    environment_root = work_root / "installed"
    venv.EnvBuilder(with_pip=True, clear=False, symlinks=False).create(environment_root)
    bin_directory = environment_root / "bin"
    python = bin_directory / "python"
    console = bin_directory / "witnessgap"
    if not python.is_file():
        _reject("isolated environment lacks its Python executable")

    empty_cwd = work_root / "empty-cwd"
    empty_cwd.mkdir(mode=0o700)
    environment = _closed_environment(work_root / "install-home", work_root / "install-tmp")
    environment.update(
        {
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INDEX": "1",
            "PYTHONHASHSEED": "0",
        }
    )
    install = _bounded_process(
        (
            str(python),
            "-I",
            "-m",
            "pip",
            "--isolated",
            "install",
            "--no-index",
            "--no-deps",
            "--no-cache-dir",
            "--no-compile",
            "--disable-pip-version-check",
            str(wheel),
        ),
        cwd=empty_cwd,
        env=environment,
        label="isolated no-index wheel install",
    )
    if install.stderr:
        _reject("isolated wheel install wrote unexpected standard error")
    if not console.is_file():
        _reject("isolated wheel install did not create the WitnessGap console script")
    runtime = _InstalledRuntime(
        python=python,
        console=console,
        cwd=empty_cwd,
        environment_root=environment_root,
        environment=environment,
    )
    _verify_installed_import(runtime, metadata)
    version_output = _verify_installed_versions(runtime, metadata)
    example_output = _verify_installed_example(runtime)
    workspace_output = _verify_installed_workspace(runtime)
    _require_path_free_output(
        version_output + example_output + workspace_output,
        (ROOT, work_root, empty_cwd, environment_root),
    )
    if tuple(empty_cwd.iterdir()):
        _reject("installed smoke wrote files into its empty working directory")


def verify_distribution() -> str:
    """Execute and verify the full sdist-to-installed-wheel release path."""

    if sys.implementation.name != "cpython" or sys.version_info[:3] != EXPECTED_PYTHON:
        _reject("distribution verification requires exact CPython 3.12.3")
    try:
        backend_version = importlib_metadata.version("hatchling")
    except importlib_metadata.PackageNotFoundError as error:
        raise DistributionVerificationError(
            "the pinned Hatchling backend is not installed"
        ) from error
    if f"hatchling=={backend_version}" != EXPECTED_BACKEND_REQUIREMENT:
        _reject("installed Hatchling version differs from the pinned build backend")

    with tempfile.TemporaryDirectory(prefix="witnessgap-distribution-") as temporary_name:
        work_root = Path(temporary_name).resolve(strict=True)
        if work_root == ROOT or work_root.is_relative_to(ROOT):
            _reject("distribution work directory must be outside the source checkout")
        sdist = _backend_build("build_sdist", cwd=ROOT, output=work_root / "sdist-primary")
        repeated_sdist = _backend_build(
            "build_sdist",
            cwd=ROOT,
            output=work_root / "sdist-repeat",
        )
        _require_identical_artifacts(sdist, repeated_sdist, label="sdist")
        source_root, sdist_metadata_payload, metadata = _validate_sdist(
            sdist,
            work_root / "source",
        )
        wheel = _backend_build(
            "build_wheel",
            cwd=source_root,
            output=work_root / "wheel-primary",
        )
        repeated_wheel = _backend_build(
            "build_wheel",
            cwd=source_root,
            output=work_root / "wheel-repeat",
        )
        _require_identical_artifacts(wheel, repeated_wheel, label="wheel")
        _validate_wheel(wheel, sdist_metadata_payload, metadata, source_root)
        _isolated_install_smoke(wheel, metadata, work_root)

    return (
        f"verified {EXPECTED_NAME} {metadata.version}: sdist -> {EXPECTED_WHEEL_TAG} wheel -> "
        "isolated CPython 3.12.3 install"
    )


def main() -> int:
    """Run distribution verification with a path-free success line."""

    try:
        result = verify_distribution()
    except DistributionVerificationError as error:
        print(f"distribution verification failed: {error}", file=sys.stderr)
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
