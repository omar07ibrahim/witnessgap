from __future__ import annotations

import inspect
import sys
import time
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

import witnessgap.workspace100.worker as worker_module
from witnessgap import workspace100
from witnessgap.canonical import JsonValue, canonical_json
from witnessgap.identifiability import CandidateRegistry, UnknownReason, VerdictKind
from witnessgap.workspace100.evidence import ParticipantClaim, PublicEvidenceEnvelope
from witnessgap.workspace100.runtime import workspace100_adapter_implementation_digest
from witnessgap.workspace100.worker import (
    LocalPythonProcessBackend,
    RawWorkerExit,
    WorkerBackend,
    WorkerExitKind,
    WorkerFailureKind,
    WorkerHarnessError,
    WorkerHarnessErrorKind,
    WorkerLimits,
    WorkerProgram,
    WorkerRunRecord,
    WorkerRunStatus,
    run_worker_once,
)
from witnessgap.worlds.workspace import workspace_twins

_DIGEST_A = "a" * 64
_DIGEST_B = "b" * 64
_SHA256_HEX_LENGTH = 64
_UNKNOWN_CLAIM = ParticipantClaim(
    kind=VerdictKind.NOT_IDENTIFIABLE,
    unknown_reason=UnknownReason.AMBIGUOUS_WORLDS,
)
_IDENTIFIED_CLAIM = ParticipantClaim(
    kind=VerdictKind.IDENTIFIED_SINGLETON,
    target_family=(("environment",),),
    minimal_witnesses=(("refresh_draft_store",),),
)
_ALLOWED_ENVIRONMENT = {
    "HOME",
    "LANG",
    "LC_ALL",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONHASHSEED",
    "PYTHONNOUSERSITE",
    "PYTHONUNBUFFERED",
    "TMPDIR",
    "TZ",
}


@pytest.fixture(scope="module")
def worker_scratch_root() -> Iterator[str]:
    root = Path.cwd() / ".worker-tmp"
    root.mkdir(mode=0o700, exist_ok=True)
    yield str(root)
    root.rmdir()


def _envelope(*, with_probe: bool = True) -> PublicEvidenceEnvelope:
    worlds = workspace_twins()
    registry = CandidateRegistry.build(worlds)
    evidence = registry.observe(
        worlds[0].world_id,
        probes=("draft_store_epoch",) if with_probe else (),
        interventions=(("refresh_draft_store",),) if with_probe else (),
    )
    return PublicEvidenceEnvelope(evidence)


def _source(body: str) -> bytes:
    return (body.rstrip() + "\n").encode("utf-8")


def _constant_claim_source(claim: ParticipantClaim = _UNKNOWN_CLAIM) -> bytes:
    encoded = claim.to_canonical_bytes()
    return _source(
        "import sys\n"
        "sys.stdin.buffer.read()\n"
        f"sys.stdout.buffer.write({encoded!r})",
    )


def _local_program(
    source: bytes,
    *,
    scratch_root: str,
    method_id: str = "test_method",
) -> tuple[WorkerProgram, LocalPythonProcessBackend]:
    backend = LocalPythonProcessBackend(
        source,
        interpreter=sys.executable,
        scratch_root=scratch_root,
    )
    return (
        WorkerProgram(
            method_id=method_id,
            implementation_digest=backend.program_implementation_digest,
        ),
        backend,
    )


def _standalone_claimed_record() -> WorkerRunRecord:
    return WorkerRunRecord(
        method_id="method",
        implementation_digest=_DIGEST_A,
        backend_implementation_digest=_DIGEST_B,
        limits_digest=_DIGEST_A,
        evidence_digest=_DIGEST_B,
        request_digest=_DIGEST_A,
        status=WorkerRunStatus.CLAIMED,
        claim=_UNKNOWN_CLAIM,
    )


class _CaptureBackend:
    program_implementation_digest = _DIGEST_A
    implementation_digest = _DIGEST_B

    def __init__(self, claim: ParticipantClaim) -> None:
        self.claim = claim
        self.calls: list[tuple[bytes, WorkerLimits]] = []

    def invoke(self, request: bytes, *, limits: WorkerLimits) -> RawWorkerExit:
        self.calls.append((request, limits))
        return RawWorkerExit(
            kind=WorkerExitKind.EXITED,
            returncode=0,
            stdout=self.claim.to_canonical_bytes(),
            stderr=b"",
        )


def test_parent_passes_one_exact_envelope_without_routing_metadata() -> None:
    envelope = _envelope()
    backend = _CaptureBackend(_UNKNOWN_CLAIM)
    limits = WorkerLimits(timeout_ms=321, stdout_bytes=1_024, stderr_bytes=12)

    record = run_worker_once(
        WorkerProgram("capture_method", _DIGEST_A),
        envelope,
        backend=cast(WorkerBackend, backend),
        limits=limits,
    )

    assert backend.calls == [(envelope.to_canonical_bytes(), limits)]
    assert record.status is WorkerRunStatus.CLAIMED
    assert record.claim == _UNKNOWN_CLAIM
    request = backend.calls[0][0]
    for forbidden in (
        b"case_id",
        b"episode_id",
        b"method_id",
        b"pair_id",
        b"schedule",
        b"split",
        b"template_id",
        b"truth",
        b"view",
    ):
        assert forbidden not in request


def test_worker_surface_has_no_batch_or_package_export() -> None:
    assert "run_worker_once" not in workspace100.__all__
    assert not hasattr(workspace100, "run_worker_once")
    assert all(
        "many" not in name and "batch" not in name
        for name, value in inspect.getmembers(worker_module, inspect.isfunction)
        if not name.startswith("_")
    )


def test_local_worker_stages_source_and_accepts_one_canonical_claim(
    worker_scratch_root: str,
) -> None:
    envelope = _envelope()
    expected_request = envelope.to_canonical_bytes()
    success = _IDENTIFIED_CLAIM.to_canonical_bytes()
    source = _source(
        "import sys\n"
        "request = sys.stdin.buffer.read()\n"
        f"result = {success!r} if request == {expected_request!r} else b'invalid\\n'\n"
        "sys.stdout.buffer.write(result)",
    )
    program, backend = _local_program(source, scratch_root=worker_scratch_root)

    record = run_worker_once(program, envelope, backend=backend)

    assert record.status is WorkerRunStatus.CLAIMED
    assert record.claim == _IDENTIFIED_CLAIM
    assert record.failure is None
    assert record.implementation_digest == backend.program_implementation_digest
    assert record.backend_implementation_digest == backend.implementation_digest
    assert record.evidence_digest == envelope.evidence_digest
    assert len(record.request_digest) == _SHA256_HEX_LENGTH


@pytest.mark.parametrize(
    ("body", "failure"),
    [
        (
            "import sys\nsys.stdin.buffer.read()",
            WorkerFailureKind.EMPTY_OUTPUT,
        ),
        (
            "import sys\nsys.stdin.buffer.read()\nsys.stdout.buffer.write(b'{}\\n')",
            WorkerFailureKind.INVALID_CLAIM,
        ),
        (
            "import sys\n"
            "sys.stdin.buffer.read()\n"
            f"sys.stdout.buffer.write({_UNKNOWN_CLAIM.to_canonical_bytes()!r} + b' ')",
            WorkerFailureKind.INVALID_CLAIM,
        ),
        (
            "import sys\n"
            "sys.stdin.buffer.read()\n"
            f"claim = {_UNKNOWN_CLAIM.to_canonical_bytes()!r}\n"
            "sys.stdout.buffer.write(claim + claim)",
            WorkerFailureKind.INVALID_CLAIM,
        ),
        (
            "import sys\n"
            "sys.stdin.buffer.read()\n"
            f"sys.stdout.buffer.write({_UNKNOWN_CLAIM.to_canonical_bytes()!r})\n"
            "raise SystemExit(7)",
            WorkerFailureKind.NONZERO_EXIT,
        ),
    ],
)
def test_local_worker_normalizes_invalid_outputs(
    body: str,
    failure: WorkerFailureKind,
    worker_scratch_root: str,
) -> None:
    program, backend = _local_program(
        _source(body),
        scratch_root=worker_scratch_root,
    )

    record = run_worker_once(program, _envelope(), backend=backend)

    assert record.status is WorkerRunStatus.FAILED
    assert record.failure is failure
    assert record.claim is None


@pytest.mark.parametrize("flood_channel", ["stdout", "stderr"])
def test_local_worker_bounds_both_output_channels(
    flood_channel: str,
    worker_scratch_root: str,
) -> None:
    body = (
        "import sys\n"
        "sys.stdin.buffer.read()\n"
        f"sys.{flood_channel}.buffer.write(b'x' * 4096)\n"
        f"sys.stdout.buffer.write({_UNKNOWN_CLAIM.to_canonical_bytes()!r})"
    )
    program, backend = _local_program(
        _source(body),
        scratch_root=worker_scratch_root,
    )

    record = run_worker_once(
        program,
        _envelope(),
        backend=backend,
        limits=WorkerLimits(timeout_ms=2_000, stdout_bytes=64, stderr_bytes=64),
    )

    assert record.failure is WorkerFailureKind.OUTPUT_LIMIT_EXCEEDED


def test_local_worker_times_out_and_terminates_descendant_held_pipes(
    worker_scratch_root: str,
) -> None:
    source = _source(
        "import os\n"
        "import subprocess\n"
        "import sys\n"
        "sys.stdin.buffer.read()\n"
        "child = subprocess.Popen([sys.executable, '-c', "
        "'import time; time.sleep(30)'])\n"
        "sys.stderr.write(str(child.pid))\n",
    )
    _, backend = _local_program(source, scratch_root=worker_scratch_root)

    raw = backend.invoke(
        _envelope().to_canonical_bytes(),
        limits=WorkerLimits(timeout_ms=150),
    )

    assert raw.kind is WorkerExitKind.TIMED_OUT
    descendant_pid = int(raw.stderr)
    descendant_status = Path(f"/proc/{descendant_pid}/stat")
    deadline = time.monotonic() + 0.5
    state = ""
    while descendant_status.exists() and time.monotonic() < deadline:
        state = descendant_status.read_text(encoding="utf-8").split(") ", 1)[1][0]
        if state == "Z":
            break
        time.sleep(0.01)
    assert not descendant_status.exists() or state == "Z"


def test_local_worker_gets_fresh_process_directory_and_closed_environment(
    worker_scratch_root: str,
) -> None:
    source = _source(
        "import os\n"
        "import pathlib\n"
        "import sys\n"
        "sys.stdin.buffer.read()\n"
        "cwd = os.getcwd()\n"
        "fresh = not pathlib.Path('seen').exists()\n"
        "pathlib.Path('seen').write_text('used', encoding='utf-8')\n"
        "closed = cwd == os.environ['HOME'] == os.environ['TMPDIR']\n"
        "details = '|'.join((str(os.getpid()), cwd, "
        "','.join(sorted(os.environ)), str(int(fresh and closed))))\n"
        "sys.stderr.write(details)\n"
        f"sys.stdout.buffer.write({_UNKNOWN_CLAIM.to_canonical_bytes()!r})",
    )
    _, backend = _local_program(source, scratch_root=worker_scratch_root)
    request = _envelope().to_canonical_bytes()

    first = backend.invoke(request, limits=WorkerLimits())
    second = backend.invoke(request, limits=WorkerLimits())

    first_pid, first_cwd, first_environment, first_ok = first.stderr.decode().split("|")
    second_pid, second_cwd, second_environment, second_ok = second.stderr.decode().split("|")
    assert first.kind is second.kind is WorkerExitKind.EXITED
    assert first.returncode == second.returncode == 0
    assert first_pid != second_pid
    assert first_cwd != second_cwd
    assert first_ok == second_ok == "1"
    assert set(first_environment.split(",")) == _ALLOWED_ENVIRONMENT
    assert first_environment == second_environment
    assert not Path(first_cwd).exists()
    assert not Path(second_cwd).exists()


def test_isolated_python_flags_do_not_install_the_witnessgap_package(
    worker_scratch_root: str,
) -> None:
    source = _source(
        "import sys\n"
        "sys.stdin.buffer.read()\n"
        "try:\n"
        "    import witnessgap\n"
        "except ModuleNotFoundError:\n"
        f"    sys.stdout.buffer.write({_UNKNOWN_CLAIM.to_canonical_bytes()!r})\n"
        "else:\n"
        "    sys.stdout.buffer.write(b'package-was-importable\\n')",
    )
    program, backend = _local_program(source, scratch_root=worker_scratch_root)

    record = run_worker_once(program, _envelope(), backend=backend)

    assert record.status is WorkerRunStatus.CLAIMED
    assert record.claim == _UNKNOWN_CLAIM


def test_run_digests_are_independent_of_invocation_order(
    worker_scratch_root: str,
) -> None:
    source = _constant_claim_source()
    program, backend = _local_program(source, scratch_root=worker_scratch_root)
    envelopes = (_envelope(with_probe=False), _envelope(with_probe=True))

    forward = {
        envelope.evidence_digest: run_worker_once(
            program,
            envelope,
            backend=backend,
        ).run_digest
        for envelope in envelopes
    }
    reverse = {
        envelope.evidence_digest: run_worker_once(
            program,
            envelope,
            backend=backend,
        ).run_digest
        for envelope in reversed(envelopes)
    }

    assert forward == reverse


def test_worker_run_record_is_a_closed_canonical_union(
    worker_scratch_root: str,
) -> None:
    program, backend = _local_program(
        _constant_claim_source(),
        scratch_root=worker_scratch_root,
    )
    claimed = run_worker_once(program, _envelope(), backend=backend)
    failed = replace(
        claimed,
        status=WorkerRunStatus.FAILED,
        claim=None,
        failure=WorkerFailureKind.INVALID_CLAIM,
    )

    assert WorkerRunRecord.from_canonical_bytes(claimed.to_canonical_bytes()) == claimed
    assert WorkerRunRecord.from_canonical_bytes(failed.to_canonical_bytes()) == failed
    for forbidden in (
        b"argv",
        b"case_id",
        b"cwd",
        b"duration",
        b"exit_code",
        b"pid",
        b"stderr",
        b"timestamp",
    ):
        assert forbidden not in claimed.to_canonical_bytes()

    open_payload = claimed.to_payload()
    open_payload["case_id"] = "forged"
    with pytest.raises(ValueError, match="unknown or missing"):
        WorkerRunRecord.from_canonical_bytes(canonical_json(open_payload))
    with pytest.raises(ValueError, match="canonical"):
        WorkerRunRecord.from_canonical_bytes(claimed.to_canonical_bytes().rstrip())


def test_worker_run_record_rejects_incoherent_and_mutated_values() -> None:
    record = _standalone_claimed_record()
    with pytest.raises(ValueError, match="cannot contain a failure"):
        replace(
            record,
            failure=WorkerFailureKind.INVALID_CLAIM,
        )
    with pytest.raises(ValueError, match="cannot contain a claim"):
        replace(
            record,
            status=WorkerRunStatus.FAILED,
            failure=WorkerFailureKind.INVALID_CLAIM,
        )

    object.__setattr__(record, "request_digest", "not-a-digest")
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        record.to_canonical_bytes()


@pytest.mark.parametrize(
    "limits",
    [
        WorkerLimits(timeout_ms=1),
        WorkerLimits(stdout_bytes=1),
        WorkerLimits(stderr_bytes=0),
    ],
)
def test_worker_limits_are_integer_only_and_digest_bound(limits: WorkerLimits) -> None:
    assert len(limits.digest) == _SHA256_HEX_LENGTH
    assert limits.to_payload()["format"] == "witnessgap.workspace100-worker-limits.v1"

    with pytest.raises(ValueError, match="integer"):
        WorkerLimits(timeout_ms=cast(int, True))
    with pytest.raises(ValueError, match="integer"):
        WorkerLimits(stdout_bytes=0)
    with pytest.raises(ValueError, match="integer"):
        WorkerLimits(stderr_bytes=(1 << 16) + 1)


def test_worker_rejects_identity_mismatch_and_noncanonical_parent_values() -> None:
    backend = _CaptureBackend(_UNKNOWN_CLAIM)
    with pytest.raises(ValueError, match="differs"):
        run_worker_once(
            WorkerProgram("method", _DIGEST_B),
            _envelope(),
            backend=cast(WorkerBackend, backend),
        )
    with pytest.raises(ValueError, match="lowercase identifier"):
        WorkerProgram("Method With Spaces", _DIGEST_A)
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        WorkerProgram("method", "A" * 64)
    with pytest.raises(TypeError, match="exact"):
        run_worker_once(
            WorkerProgram("method", _DIGEST_A),
            cast(PublicEvidenceEnvelope, _envelope().to_canonical_bytes()),
            backend=cast(WorkerBackend, backend),
        )


def test_harness_faults_abort_instead_of_becoming_method_failures(
    worker_scratch_root: str,
) -> None:
    missing_interpreter = LocalPythonProcessBackend(
        _constant_claim_source(),
        interpreter=str(Path(worker_scratch_root) / "missing-python"),
        scratch_root=worker_scratch_root,
    )
    with pytest.raises(WorkerHarnessError) as captured:
        missing_interpreter.invoke(
            _envelope().to_canonical_bytes(),
            limits=WorkerLimits(),
        )
    assert captured.value.kind is WorkerHarnessErrorKind.SPAWN_FAILED

    missing_scratch = LocalPythonProcessBackend(
        _constant_claim_source(),
        interpreter=sys.executable,
        scratch_root=str(Path(worker_scratch_root) / "missing-root"),
    )
    with pytest.raises(WorkerHarnessError) as captured:
        missing_scratch.invoke(
            _envelope().to_canonical_bytes(),
            limits=WorkerLimits(),
        )
    assert captured.value.kind is WorkerHarnessErrorKind.STAGING_FAILED


def test_worker_submodule_does_not_change_the_adapter_digest() -> None:
    before = workspace100_adapter_implementation_digest()

    assert worker_module.workspace100_worker_implementation_digest()

    assert workspace100_adapter_implementation_digest() == before


def test_worker_record_parser_rejects_nested_open_claim() -> None:
    record = WorkerRunRecord(
        method_id="method",
        implementation_digest=_DIGEST_A,
        backend_implementation_digest=_DIGEST_B,
        limits_digest=_DIGEST_A,
        evidence_digest=_DIGEST_B,
        request_digest=_DIGEST_A,
        status=WorkerRunStatus.CLAIMED,
        claim=_UNKNOWN_CLAIM,
    )
    payload = record.to_payload()
    claim = cast(dict[str, JsonValue], payload["claim"])
    claim["case_id"] = "forged"

    with pytest.raises(ValueError, match="unknown or missing"):
        WorkerRunRecord.from_canonical_bytes(canonical_json(payload))
