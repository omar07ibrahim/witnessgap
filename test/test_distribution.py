from __future__ import annotations

import base64
import gzip
import hashlib
import io
import os
import signal
import stat
import sys
import tarfile
import time
import zipfile
from collections.abc import Iterator
from contextlib import suppress
from pathlib import Path
from typing import cast

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import verify_distribution as distribution  # noqa: E402

EXPECTED_REGULAR_MODE = 0o644


class _OversizedTarIterator:
    def __init__(self) -> None:
        self.advanced_past_oversized_member = False

    def __iter__(self) -> Iterator[tarfile.TarInfo]:
        member = tarfile.TarInfo("package/oversized.bin")
        member.type = tarfile.REGTYPE
        member.size = distribution.MAX_MEMBER_BYTES + 1
        yield member
        self.advanced_past_oversized_member = True
        raise RuntimeError("iterator advanced past oversized member")


def _metadata_payload(
    *,
    requires_python: str = ">=3.12,<3.13",
    requirements: tuple[str, ...] | None = None,
    extra_headers: tuple[str, ...] = (),
) -> bytes:
    selected_requirements = (
        tuple(sorted(distribution.EXPECTED_DEV_REQUIREMENTS))
        if requirements is None
        else requirements
    )
    headers = [
        "Metadata-Version: 2.4",
        "Name: witnessgap",
        "Version: 0.0.1",
        "Summary: Identifiability certificates for tool-agent failure attribution",
        f"Requires-Python: {requires_python}",
        "Provides-Extra: dev",
        *(f"Requires-Dist: {requirement}" for requirement in selected_requirements),
        *extra_headers,
        "",
        "# WitnessGap",
        "",
    ]
    return "\n".join(headers).encode()


def _write_tar(
    path: Path,
    members: tuple[tuple[tarfile.TarInfo, bytes | None], ...],
) -> None:
    with tarfile.open(path, mode="w:gz") as archive:
        for member, payload in members:
            stream = io.BytesIO(payload) if payload is not None else None
            archive.addfile(member, stream)


def _regular_tar_member(name: str, payload: bytes) -> tuple[tarfile.TarInfo, bytes]:
    member = tarfile.TarInfo(name)
    member.type = tarfile.REGTYPE
    member.mode = 0o644
    member.size = len(payload)
    return member, payload


def _record_line(path: str, payload: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()
    return f"{path},sha256={digest},{len(payload)}\n"


@pytest.mark.parametrize(
    "path",
    (
        "/absolute.py",
        "../escape.py",
        "pkg/./module.py",
        "pkg//module.py",
        "pkg\\module.py",
        "pkg/module.py ",
        "pkg/C:/module.py",
        "pkg/con.txt",
        "pkg/control\x00.py",
        "pkg/e\u0301.py",
    ),
)
def test_archive_paths_reject_traversal_and_nonportable_spellings(path: str) -> None:
    with pytest.raises(distribution.DistributionVerificationError):
        distribution._portable_path_key(path)


@pytest.mark.parametrize(
    "paths",
    (
        ("pkg/README.md", "pkg/readme.md"),
        ("pkg/\u00c9.py", "pkg/\u00e9.py"),
        ("pkg/K.py", "pkg/\uff2b.py"),
    ),
)
def test_archive_paths_reject_casefold_and_unicode_collisions(
    paths: tuple[str, str],
) -> None:
    entries = tuple(distribution._ArchiveEntry(path, "file", 1) for path in paths)

    with pytest.raises(distribution.DistributionVerificationError, match="colliding paths"):
        distribution._validate_archive_entries(entries)


def test_archive_manifest_rejects_file_directory_shadowing_and_size_overflow() -> None:
    with pytest.raises(distribution.DistributionVerificationError, match="shadows"):
        distribution._validate_archive_entries(
            (
                distribution._ArchiveEntry("pkg/module", "file", 1),
                distribution._ArchiveEntry("pkg/module/data.json", "file", 1),
            )
        )

    with pytest.raises(distribution.DistributionVerificationError, match="byte bound"):
        distribution._validate_archive_entries(
            (
                distribution._ArchiveEntry(
                    "pkg/oversized.bin",
                    "file",
                    distribution.MAX_MEMBER_BYTES + 1,
                ),
            )
        )


def test_tar_preflight_rejects_oversized_member_before_advancing() -> None:
    hostile = _OversizedTarIterator()

    with pytest.raises(distribution.DistributionVerificationError, match="size"):
        distribution._tar_members_and_entries(cast(tarfile.TarFile, hostile))

    assert hostile.advanced_past_oversized_member is False


def test_gzip_stream_is_bounded_before_tar_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = tmp_path / "oversized.tar.gz"
    monkeypatch.setattr(distribution, "MAX_TAR_STREAM_BYTES", 1_024)
    with gzip.open(archive, mode="wb") as stream:
        stream.write(b"x" * 1_025)

    with pytest.raises(distribution.DistributionVerificationError, match="decompressed stream"):
        distribution._require_bounded_gzip_stream(archive)


def test_sdist_preflight_rejects_traversal_before_writing(tmp_path: Path) -> None:
    archive = tmp_path / "hostile.tar.gz"
    _write_tar(
        archive,
        (_regular_tar_member("package/../../escaped.txt", b"escaped"),),
    )
    destination = tmp_path / "source"

    with pytest.raises(distribution.DistributionVerificationError):
        distribution._extract_validated_sdist(archive, destination)

    assert not (tmp_path / "escaped.txt").exists()
    assert not tuple(destination.rglob("*"))


@pytest.mark.parametrize("member_type", (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE))
def test_sdist_preflight_rejects_links_and_special_members(
    tmp_path: Path,
    member_type: bytes,
) -> None:
    archive = tmp_path / "hostile.tar.gz"
    member = tarfile.TarInfo("package/link")
    member.type = member_type
    member.linkname = "target" if member_type != tarfile.FIFOTYPE else ""
    _write_tar(archive, ((member, None),))

    with pytest.raises(distribution.DistributionVerificationError, match="link or special"):
        distribution._extract_validated_sdist(archive, tmp_path / "source")


def test_sdist_preflight_rejects_directory_payloads(tmp_path: Path) -> None:
    archive = tmp_path / "hostile.tar.gz"
    member = tarfile.TarInfo("package/")
    member.type = tarfile.DIRTYPE
    member.mode = 0o755
    member.size = 1
    _write_tar(archive, ((member, b"x"),))

    with pytest.raises(distribution.DistributionVerificationError, match="nonzero payload"):
        distribution._extract_validated_sdist(archive, tmp_path / "source")


def test_sdist_extractor_materializes_only_preflighted_regular_bytes(tmp_path: Path) -> None:
    archive = tmp_path / "package-1.0.tar.gz"
    payload = b"print('verified')\n"
    _write_tar(
        archive,
        (
            _regular_tar_member("package-1.0/src/package/__init__.py", payload),
            _regular_tar_member("package-1.0/README.md", b"# package\n"),
        ),
    )

    source_root = distribution._extract_validated_sdist(archive, tmp_path / "source")

    extracted = source_root / "src" / "package" / "__init__.py"
    assert extracted.read_bytes() == payload
    assert extracted.stat().st_mode & 0o777 == EXPECTED_REGULAR_MODE
    assert source_root.is_dir() and not source_root.is_symlink()


def test_wheel_preflight_rejects_symlinks(tmp_path: Path) -> None:
    wheel = tmp_path / "hostile.whl"
    link = zipfile.ZipInfo("witnessgap/link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(wheel, mode="w") as archive:
        archive.writestr(link, "target")

    with pytest.raises(distribution.DistributionVerificationError, match="link or special"):
        distribution._read_validated_wheel(wheel)


def test_wheel_preflight_rejects_explicit_directories(tmp_path: Path) -> None:
    wheel = tmp_path / "hostile.whl"
    with zipfile.ZipFile(wheel, mode="w") as archive:
        archive.writestr("witnessgap/", b"")

    with pytest.raises(distribution.DistributionVerificationError, match="explicit directory"):
        distribution._read_validated_wheel(wheel)


def test_wheel_preflight_rejects_portable_name_collisions(tmp_path: Path) -> None:
    wheel = tmp_path / "hostile.whl"
    with zipfile.ZipFile(wheel, mode="w") as archive:
        archive.writestr("witnessgap/Module.py", b"first")
        archive.writestr("witnessgap/module.py", b"second")

    with pytest.raises(distribution.DistributionVerificationError, match="colliding paths"):
        distribution._read_validated_wheel(wheel)


def test_wheel_preflight_rejects_encrypted_flag() -> None:
    info = zipfile.ZipInfo("witnessgap/module.py")
    info.flag_bits |= 0x1

    with pytest.raises(distribution.DistributionVerificationError, match="encrypted"):
        distribution._zip_entry_kind(info)


def test_wheel_preflight_rejects_extreme_compression_ratio() -> None:
    info = zipfile.ZipInfo("witnessgap/payload.json")
    info.compress_type = zipfile.ZIP_DEFLATED
    info.file_size = distribution.COMPRESSION_RATIO_GRACE_BYTES + 1
    info.compress_size = 1

    with pytest.raises(distribution.DistributionVerificationError, match="compression-ratio"):
        distribution._zip_entry_kind(info)


def test_record_closes_over_every_wheel_member_and_verifies_bytes() -> None:
    record_path = "witnessgap-0.0.1.dist-info/RECORD"
    module_path = "witnessgap/__init__.py"
    metadata_path = "witnessgap-0.0.1.dist-info/METADATA"
    module = b'__version__ = "0.0.1"\n'
    metadata = _metadata_payload()
    record = (
        _record_line(module_path, module)
        + _record_line(metadata_path, metadata)
        + f"{record_path},,\n"
    ).encode()
    payloads = {
        module_path: module,
        metadata_path: metadata,
        record_path: record,
    }

    distribution._validate_wheel_record(payloads, record_path)


def test_wheel_surface_matches_every_sdist_package_byte(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    package = source_root / "src" / "witnessgap"
    package.mkdir(parents=True)
    source_payloads = {
        "__init__.py": b'__version__ = "0.0.1"\n',
        "__main__.py": b"from witnessgap.cli import main\n",
        "cli.py": b"def main() -> int:\n    return 0\n",
        "extra.py": b"VALUE = 1\n",
        "py.typed": b"",
    }
    for name, payload in source_payloads.items():
        (package / name).write_bytes(payload)
    (source_root / "LICENSE").write_bytes(b"Apache-2.0\n")

    layout = distribution._wheel_layout("witnessgap-0.0.1")
    payloads = {
        **{f"witnessgap/{name}": payload for name, payload in source_payloads.items()},
        layout.metadata: b"metadata",
        layout.wheel: b"wheel",
        layout.entry_points: distribution.EXPECTED_ENTRY_POINTS,
        layout.record: b"record",
        layout.license: b"Apache-2.0\n",
    }
    distribution._validate_wheel_surface(payloads, layout, source_root)

    payloads["witnessgap/extra.py"] = b"VALUE = 2\n"
    with pytest.raises(distribution.DistributionVerificationError, match="byte-for-byte"):
        distribution._validate_wheel_surface(payloads, layout, source_root)


@pytest.mark.parametrize("mutation", ("digest", "size", "missing", "self-hash"))
def test_record_rejects_tampering_and_incomplete_closure(mutation: str) -> None:
    record_path = "witnessgap-0.0.1.dist-info/RECORD"
    module_path = "witnessgap/__init__.py"
    module = b"verified\n"
    digest = distribution._record_digest(module)
    module_row = f"{module_path},{digest},{len(module)}\n"
    self_row = f"{record_path},,\n"
    payloads: dict[str, bytes] = {module_path: module, record_path: b""}
    if mutation == "digest":
        module_row = f"{module_path},sha256=invalid,{len(module)}\n"
    elif mutation == "size":
        module_row = f"{module_path},{digest},{len(module) + 1}\n"
    elif mutation == "missing":
        module_row = ""
    else:
        self_row = f"{record_path},{digest},{len(module)}\n"
    payloads[record_path] = (module_row + self_row).encode()

    with pytest.raises(distribution.DistributionVerificationError):
        distribution._validate_wheel_record(payloads, record_path)


def test_core_metadata_accepts_only_bounded_python_and_dev_extra_requirements() -> None:
    metadata = distribution._parse_core_metadata(_metadata_payload())

    assert metadata == distribution._CoreMetadata(
        name="witnessgap",
        version="0.0.1",
        requires_python=">=3.12,<3.13",
        description="# WitnessGap\n",
    )


@pytest.mark.parametrize(
    "payload",
    (
        _metadata_payload(requires_python=">=3.12"),
        _metadata_payload(requires_python=">=3.12,<3.13,>=3.12"),
        _metadata_payload(
            requirements=(
                *tuple(sorted(distribution.EXPECTED_DEV_REQUIREMENTS)),
                next(iter(distribution.EXPECTED_DEV_REQUIREMENTS)),
            )
        ),
        _metadata_payload(requirements=()),
        _metadata_payload(requirements=("requests>=2",)),
        _metadata_payload(extra_headers=("Name: witnessgap-again",)),
        _metadata_payload(extra_headers=("Dynamic: Version",)),
    ),
)
def test_core_metadata_rejects_unbounded_runtime_or_ambiguous_fields(payload: bytes) -> None:
    with pytest.raises(distribution.DistributionVerificationError):
        distribution._parse_core_metadata(payload)


def test_path_free_smoke_guard_rejects_checkout_and_generic_home_paths(tmp_path: Path) -> None:
    distribution._require_path_free_output(b'{"status":"verified"}\n', (tmp_path,))

    with pytest.raises(distribution.DistributionVerificationError, match="host path"):
        distribution._require_path_free_output(f"loaded {tmp_path}\n".encode(), (tmp_path,))
    with pytest.raises(distribution.DistributionVerificationError, match="host path"):
        distribution._require_path_free_output(b"loaded /home/user/project\n", ())


def test_process_output_is_stopped_at_the_streaming_bound(tmp_path: Path) -> None:
    environment = distribution._closed_environment(tmp_path / "home", tmp_path / "tmp")
    program = (
        f"import sys\nsys.stdout.buffer.write(b'x' * {distribution.MAX_BUILD_OUTPUT_BYTES + 1})\n"
    )

    with pytest.raises(distribution.DistributionVerificationError, match="output beyond"):
        distribution._bounded_process(
            (sys.executable, "-I", "-B", "-c", program),
            cwd=tmp_path,
            env=environment,
            label="adversarial output probe",
        )


def test_successful_process_cleans_background_descendants(tmp_path: Path) -> None:
    environment = distribution._closed_environment(tmp_path / "home", tmp_path / "tmp")
    child_program = "import time; time.sleep(60)"
    parent_program = (
        "import subprocess, sys\n"
        "child = subprocess.Popen("
        f"[sys.executable, '-I', '-B', '-c', {child_program!r}], "
        "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
        "print(child.pid, flush=True)\n"
    )
    completed = distribution._bounded_process(
        (sys.executable, "-I", "-B", "-c", parent_program),
        cwd=tmp_path,
        env=environment,
        label="background descendant probe",
    )
    child_pid = int(completed.stdout)

    try:
        deadline = time.monotonic() + 1
        state: str | None = None
        while time.monotonic() < deadline:
            try:
                state = Path(f"/proc/{child_pid}/stat").read_text(encoding="utf-8").split()[2]
            except FileNotFoundError:
                state = None
            if state in {None, "Z"}:
                break
            time.sleep(0.01)
        assert state in {None, "Z"}
    finally:
        with suppress(ProcessLookupError):
            os.kill(child_pid, signal.SIGKILL)
