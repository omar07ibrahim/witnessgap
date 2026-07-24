"""Fresh-process participant transport for trusted Workspace-100 methods.

The wire protocol is deliberately smaller than this parent-side module:
one canonical :class:`PublicEvidenceEnvelope` enters a worker and one canonical
:class:`ParticipantClaim` may leave it.  Method identity, digests, limits, and
failure normalization remain evaluator-side.

``LocalPythonProcessBackend`` provides lifecycle separation and bounded pipes
for trusted built-in methods.  It is not a hostile-code sandbox: the child
retains the parent's operating-system user, filesystem, and network access.
"""

from __future__ import annotations

import json
import os
import re
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO, Protocol, cast

from witnessgap.canonical import JsonValue, canonical_digest, canonical_json, tagged_digest
from witnessgap.source import package_implementation_digest
from witnessgap.workspace100.evidence import ParticipantClaim, PublicEvidenceEnvelope
from witnessgap.workspace100.records import PROTOCOL_ID

WORKER_LIMITS_FORMAT = "witnessgap.workspace100-worker-limits.v1"
WORKER_RUN_FORMAT = "witnessgap.workspace100-worker-run.v1"

_WORKER_REQUEST_DOMAIN = "witnessgap.workspace100-worker-request.v1"
_PYTHON_PROGRAM_DOMAIN = "witnessgap.workspace100-python-program.v1"
_WORKER_IMPLEMENTATION_DOMAIN = "witnessgap.workspace100-worker-implementation.v1"
_MAX_REQUEST_BYTES = 1 << 18
_MAX_CLAIM_BYTES = 1 << 14
_MAX_STDERR_BYTES = 1 << 16
_MAX_PROGRAM_BYTES = 1 << 20
_MAX_RUN_BYTES = 1 << 16
_MAX_TIMEOUT_MS = 10 * 60 * 1_000
_IO_CHUNK_BYTES = 1 << 14
_REAP_TIMEOUT_SECONDS = 1.0
_SHA256_HEX_LENGTH = 64
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{0,95}$")


class WorkerExitKind(StrEnum):
    """Transient process outcomes returned by a worker backend."""

    EXITED = "exited"
    TIMED_OUT = "timed_out"
    OUTPUT_LIMIT_EXCEEDED = "output_limit_exceeded"


class WorkerRunStatus(StrEnum):
    """Closed result union stored by the trusted parent."""

    CLAIMED = "claimed"
    FAILED = "failed"


class WorkerFailureKind(StrEnum):
    """Stable participant-visible failure taxonomy."""

    TIMED_OUT = "timed_out"
    OUTPUT_LIMIT_EXCEEDED = "output_limit_exceeded"
    NONZERO_EXIT = "nonzero_exit"
    EMPTY_OUTPUT = "empty_output"
    INVALID_CLAIM = "invalid_claim"


class WorkerHarnessErrorKind(StrEnum):
    """Evaluator infrastructure faults that must abort a run."""

    STAGING_FAILED = "staging_failed"
    SPAWN_FAILED = "spawn_failed"
    PIPE_IO_FAILED = "pipe_io_failed"
    REAP_FAILED = "reap_failed"


class WorkerHarnessError(RuntimeError):
    """Fixed-kind evaluator error without child-controlled diagnostics."""

    kind: WorkerHarnessErrorKind

    def __init__(self, kind: WorkerHarnessErrorKind) -> None:
        if type(kind) is not WorkerHarnessErrorKind:
            raise TypeError("worker harness error kind must be exact")
        self.kind = kind
        super().__init__(f"worker harness failed: {kind.value}")


@dataclass(frozen=True, slots=True)
class WorkerLimits:
    """Integer-only limits applied independently to one invocation."""

    timeout_ms: int = 5_000
    stdout_bytes: int = _MAX_CLAIM_BYTES
    stderr_bytes: int = _MAX_STDERR_BYTES

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        _bounded_integer(
            self.timeout_ms,
            field="worker timeout_ms",
            minimum=1,
            maximum=_MAX_TIMEOUT_MS,
        )
        _bounded_integer(
            self.stdout_bytes,
            field="worker stdout_bytes",
            minimum=1,
            maximum=_MAX_CLAIM_BYTES,
        )
        _bounded_integer(
            self.stderr_bytes,
            field="worker stderr_bytes",
            minimum=0,
            maximum=_MAX_STDERR_BYTES,
        )

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        return {
            "format": WORKER_LIMITS_FORMAT,
            "protocol_id": PROTOCOL_ID,
            "stderr_bytes": self.stderr_bytes,
            "stdout_bytes": self.stdout_bytes,
            "timeout_ms": self.timeout_ms,
        }

    @property
    def digest(self) -> str:
        return canonical_digest(WORKER_LIMITS_FORMAT, self.to_payload())


@dataclass(frozen=True, slots=True)
class WorkerProgram:
    """Parent-only participant identity; never serialized onto worker stdin."""

    method_id: str
    implementation_digest: str

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        _require_identifier(self.method_id, field="worker method_id")
        _require_digest(
            self.implementation_digest,
            field="worker implementation_digest",
        )


@dataclass(frozen=True, slots=True)
class RawWorkerExit:
    """Bounded, transient backend output before claim normalization."""

    kind: WorkerExitKind
    returncode: int
    stdout: bytes
    stderr: bytes

    def __post_init__(self) -> None:
        if type(self.kind) is not WorkerExitKind:
            raise TypeError("raw worker exit kind must be exact")
        if type(self.returncode) is not int:
            raise TypeError("raw worker returncode must be an exact integer")
        if type(self.stdout) is not bytes or type(self.stderr) is not bytes:
            raise TypeError("raw worker streams must be exact bytes")
        if len(self.stdout) > _MAX_CLAIM_BYTES or len(self.stderr) > _MAX_STDERR_BYTES:
            raise ValueError("raw worker streams exceed protocol-wide bounds")


class WorkerBackend(Protocol):
    """Trusted parent-side backend for one worker invocation."""

    @property
    def program_implementation_digest(self) -> str: ...

    @property
    def implementation_digest(self) -> str: ...

    def invoke(self, request: bytes, *, limits: WorkerLimits) -> RawWorkerExit: ...


@dataclass(frozen=True, slots=True)
class LocalPythonProcessBackend:
    """Stage and run one trusted stdlib-only Python program per invocation.

    ``program_source`` is copied into a fresh private directory before launch,
    so the argv does not disclose a repository or package path.  Isolated mode
    and ``-S`` remove environment and site-package import paths.  They do not
    stop the program from deliberately reading host paths or using the network.
    """

    program_source: bytes
    interpreter: str = sys.executable
    scratch_root: str | None = None

    def __post_init__(self) -> None:
        if type(self.program_source) is not bytes:
            raise TypeError("worker program_source must be exact bytes")
        if not self.program_source or len(self.program_source) > _MAX_PROGRAM_BYTES:
            raise ValueError("worker program_source exceeds its byte bounds")
        if type(self.interpreter) is not str:
            raise TypeError("worker interpreter must be an exact string")
        if (
            not self.interpreter
            or "\0" in self.interpreter
            or not Path(self.interpreter).is_absolute()
        ):
            raise ValueError("worker interpreter must be a non-empty absolute path")
        if self.scratch_root is not None:
            if type(self.scratch_root) is not str:
                raise TypeError("worker scratch_root must be an exact string or None")
            if (
                not self.scratch_root
                or "\0" in self.scratch_root
                or not Path(self.scratch_root).is_absolute()
            ):
                raise ValueError("worker scratch_root must be a non-empty absolute path")

    @property
    def program_implementation_digest(self) -> str:
        return tagged_digest(_PYTHON_PROGRAM_DOMAIN, self.program_source)

    @property
    def implementation_digest(self) -> str:
        return workspace100_worker_implementation_digest()

    def invoke(self, request: bytes, *, limits: WorkerLimits) -> RawWorkerExit:
        if type(request) is not bytes:
            raise TypeError("worker request must be exact bytes")
        if not request or len(request) > _MAX_REQUEST_BYTES:
            raise ValueError("worker request exceeds its byte bounds")
        if type(limits) is not WorkerLimits:
            raise TypeError("worker limits must be exact")
        limits.validate()

        try:
            with tempfile.TemporaryDirectory(
                prefix="witnessgap-worker-",
                dir=self.scratch_root,
            ) as directory:
                workdir = Path(directory)
                workdir.chmod(0o700)
                entrypoint = workdir / "participant.py"
                entrypoint.write_bytes(self.program_source)
                entrypoint.chmod(0o400)
                return self._invoke_staged(
                    request,
                    limits=limits,
                    workdir=workdir,
                )
        except WorkerHarnessError:
            raise
        except OSError as error:
            raise WorkerHarnessError(WorkerHarnessErrorKind.STAGING_FAILED) from error

    def _invoke_staged(
        self,
        request: bytes,
        *,
        limits: WorkerLimits,
        workdir: Path,
    ) -> RawWorkerExit:
        environment = {
            "HOME": str(workdir),
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONNOUSERSITE": "1",
            "PYTHONUNBUFFERED": "1",
            "TMPDIR": str(workdir),
            "TZ": "UTC",
        }
        try:
            process = subprocess.Popen(
                (self.interpreter, "-I", "-S", "-B", "participant.py"),
                cwd=workdir,
                env=environment,
                shell=False,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                start_new_session=True,
                bufsize=0,
            )
        except OSError as error:
            raise WorkerHarnessError(WorkerHarnessErrorKind.SPAWN_FAILED) from error
        try:
            return _exchange_with_process(process, request=request, limits=limits)
        except WorkerHarnessError:
            raise
        except (OSError, ValueError) as error:
            _abort_process(process)
            raise WorkerHarnessError(WorkerHarnessErrorKind.PIPE_IO_FAILED) from error


@dataclass(frozen=True, slots=True)
class WorkerRunRecord:
    """Deterministic parent-side normalization of one worker outcome."""

    method_id: str
    implementation_digest: str
    backend_implementation_digest: str
    limits_digest: str
    evidence_digest: str
    request_digest: str
    status: WorkerRunStatus
    claim: ParticipantClaim | None = None
    failure: WorkerFailureKind | None = None

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        _require_identifier(self.method_id, field="worker run method_id")
        for field, value in (
            ("implementation_digest", self.implementation_digest),
            ("backend_implementation_digest", self.backend_implementation_digest),
            ("limits_digest", self.limits_digest),
            ("evidence_digest", self.evidence_digest),
            ("request_digest", self.request_digest),
        ):
            _require_digest(value, field=f"worker run {field}")
        if type(self.status) is not WorkerRunStatus:
            raise TypeError("worker run status must be exact")
        if self.status is WorkerRunStatus.CLAIMED:
            if type(self.claim) is not ParticipantClaim:
                raise TypeError("claimed worker run requires an exact ParticipantClaim")
            self.claim.validate()
            if self.failure is not None:
                raise ValueError("claimed worker run cannot contain a failure")
            return
        if self.status is WorkerRunStatus.FAILED:
            if type(self.failure) is not WorkerFailureKind:
                raise TypeError("failed worker run requires an exact failure")
            if self.claim is not None:
                raise ValueError("failed worker run cannot contain a claim")
            return
        raise ValueError("worker run status is unsupported")

    def to_payload(self) -> dict[str, JsonValue]:
        self.validate()
        common: dict[str, JsonValue] = {
            "backend_implementation_digest": self.backend_implementation_digest,
            "evidence_digest": self.evidence_digest,
            "format": WORKER_RUN_FORMAT,
            "implementation_digest": self.implementation_digest,
            "limits_digest": self.limits_digest,
            "method_id": self.method_id,
            "protocol_id": PROTOCOL_ID,
            "request_digest": self.request_digest,
            "status": self.status.value,
        }
        if self.status is WorkerRunStatus.CLAIMED:
            common["claim"] = cast(ParticipantClaim, self.claim).to_payload()
        else:
            common["failure"] = cast(WorkerFailureKind, self.failure).value
        return common

    def to_canonical_bytes(self) -> bytes:
        payload = canonical_json(self.to_payload())
        if len(payload) > _MAX_RUN_BYTES:
            raise ValueError("worker run exceeds its byte bound")
        return payload

    @classmethod
    def from_canonical_bytes(cls, payload: bytes) -> WorkerRunRecord:
        raw = _canonical_object(
            payload,
            label="worker run",
            maximum_bytes=_MAX_RUN_BYTES,
        )
        common_fields = {
            "backend_implementation_digest",
            "evidence_digest",
            "format",
            "implementation_digest",
            "limits_digest",
            "method_id",
            "protocol_id",
            "request_digest",
            "status",
        }
        if raw.get("format") != WORKER_RUN_FORMAT:
            raise ValueError("worker run format is unsupported")
        if raw.get("protocol_id") != PROTOCOL_ID:
            raise ValueError("worker run protocol is unsupported")
        try:
            status = WorkerRunStatus(_required_string(raw, "status"))
        except ValueError as error:
            raise ValueError("worker run status is unsupported") from error
        method_id = _required_string(raw, "method_id")
        implementation_digest = _required_string(raw, "implementation_digest")
        backend_digest = _required_string(raw, "backend_implementation_digest")
        limits_digest = _required_string(raw, "limits_digest")
        evidence_digest = _required_string(raw, "evidence_digest")
        request_digest = _required_string(raw, "request_digest")
        if status is WorkerRunStatus.CLAIMED:
            if set(raw) != common_fields | {"claim"}:
                raise ValueError("claimed worker run contains unknown or missing fields")
            claim_payload = canonical_json(cast(JsonValue, raw["claim"]))
            record = cls(
                method_id=method_id,
                implementation_digest=implementation_digest,
                backend_implementation_digest=backend_digest,
                limits_digest=limits_digest,
                evidence_digest=evidence_digest,
                request_digest=request_digest,
                status=status,
                claim=ParticipantClaim.from_canonical_bytes(claim_payload),
            )
        else:
            if set(raw) != common_fields | {"failure"}:
                raise ValueError("failed worker run contains unknown or missing fields")
            try:
                failure = WorkerFailureKind(_required_string(raw, "failure"))
            except ValueError as error:
                raise ValueError("worker run failure is unsupported") from error
            record = cls(
                method_id=method_id,
                implementation_digest=implementation_digest,
                backend_implementation_digest=backend_digest,
                limits_digest=limits_digest,
                evidence_digest=evidence_digest,
                request_digest=request_digest,
                status=status,
                failure=failure,
            )
        if record.to_canonical_bytes() != payload:
            raise ValueError("worker run failed canonical round-trip")
        return record

    @property
    def run_digest(self) -> str:
        return canonical_digest(WORKER_RUN_FORMAT, self.to_payload())


@dataclass(frozen=True, slots=True)
class _RunContext:
    program: WorkerProgram
    backend_digest: str
    limits: WorkerLimits
    envelope: PublicEvidenceEnvelope
    request: bytes


def run_worker_once(
    program: WorkerProgram,
    envelope: PublicEvidenceEnvelope,
    *,
    backend: WorkerBackend,
    limits: WorkerLimits | None = None,
) -> WorkerRunRecord:
    """Invoke exactly one ID-free request and normalize the bounded outcome."""

    if type(program) is not WorkerProgram:
        raise TypeError("worker program must be exact")
    program.validate()
    if type(envelope) is not PublicEvidenceEnvelope:
        raise TypeError("worker envelope must be exact")
    if limits is None:
        limits = WorkerLimits()
    elif type(limits) is not WorkerLimits:
        raise TypeError("worker limits must be exact")
    limits.validate()

    request = envelope.to_canonical_bytes()
    normalized = PublicEvidenceEnvelope.from_canonical_bytes(request)
    if normalized != envelope:
        raise ValueError("worker envelope changed during canonical normalization")

    backend_program_digest = backend.program_implementation_digest
    _require_digest(
        backend_program_digest,
        field="worker backend program_implementation_digest",
    )
    if backend_program_digest != program.implementation_digest:
        raise ValueError("worker backend program differs from its parent identity")
    backend_digest = backend.implementation_digest
    _require_digest(backend_digest, field="worker backend implementation_digest")

    raw = backend.invoke(request, limits=limits)
    if type(raw) is not RawWorkerExit:
        raise TypeError("worker backend must return an exact RawWorkerExit")
    return _normalize_worker_exit(
        raw,
        context=_RunContext(
            program=program,
            backend_digest=backend_digest,
            limits=limits,
            envelope=envelope,
            request=request,
        ),
    )


def workspace100_worker_implementation_digest() -> str:
    """Bind the installed modules that determine worker transport semantics."""

    return package_implementation_digest(
        _WORKER_IMPLEMENTATION_DOMAIN,
        (
            "canonical.py",
            "identifiability.py",
            "model.py",
            "source.py",
            "workspace100/evidence.py",
            "workspace100/records.py",
            "workspace100/worker.py",
        ),
    )


def _normalize_worker_exit(
    raw: RawWorkerExit,
    *,
    context: _RunContext,
) -> WorkerRunRecord:
    if (
        len(raw.stdout) > context.limits.stdout_bytes
        or len(raw.stderr) > context.limits.stderr_bytes
    ):
        failure = WorkerFailureKind.OUTPUT_LIMIT_EXCEEDED
    elif raw.kind is WorkerExitKind.TIMED_OUT:
        failure = WorkerFailureKind.TIMED_OUT
    elif raw.kind is WorkerExitKind.OUTPUT_LIMIT_EXCEEDED:
        failure = WorkerFailureKind.OUTPUT_LIMIT_EXCEEDED
    elif raw.returncode != 0:
        failure = WorkerFailureKind.NONZERO_EXIT
    elif not raw.stdout:
        failure = WorkerFailureKind.EMPTY_OUTPUT
    else:
        failure = None
    if failure is not None:
        return _failed_run_record(context, failure)
    try:
        claim = ParticipantClaim.from_canonical_bytes(raw.stdout)
    except (TypeError, ValueError):
        return _failed_run_record(context, WorkerFailureKind.INVALID_CLAIM)
    return WorkerRunRecord(
        method_id=context.program.method_id,
        implementation_digest=context.program.implementation_digest,
        backend_implementation_digest=context.backend_digest,
        limits_digest=context.limits.digest,
        evidence_digest=context.envelope.evidence_digest,
        request_digest=tagged_digest(_WORKER_REQUEST_DOMAIN, context.request),
        status=WorkerRunStatus.CLAIMED,
        claim=claim,
    )


def _failed_run_record(
    context: _RunContext,
    failure: WorkerFailureKind,
) -> WorkerRunRecord:
    return WorkerRunRecord(
        method_id=context.program.method_id,
        implementation_digest=context.program.implementation_digest,
        backend_implementation_digest=context.backend_digest,
        limits_digest=context.limits.digest,
        evidence_digest=context.envelope.evidence_digest,
        request_digest=tagged_digest(_WORKER_REQUEST_DOMAIN, context.request),
        status=WorkerRunStatus.FAILED,
        failure=failure,
    )


@dataclass(slots=True)
class _ExchangeState:
    request_offset: int
    stdout: bytearray
    stderr: bytearray
    output_limit_exceeded: bool


def _exchange_with_process(
    process: subprocess.Popen[bytes],
    *,
    request: bytes,
    limits: WorkerLimits,
) -> RawWorkerExit:
    stdin = process.stdin
    stdout = process.stdout
    stderr = process.stderr
    if stdin is None or stdout is None or stderr is None:
        _abort_process(process)
        raise WorkerHarnessError(WorkerHarnessErrorKind.PIPE_IO_FAILED)

    selector = selectors.DefaultSelector()
    streams = (stdin, stdout, stderr)
    for stream in streams:
        os.set_blocking(stream.fileno(), False)
    selector.register(stdin, selectors.EVENT_WRITE, "stdin")
    selector.register(stdout, selectors.EVENT_READ, "stdout")
    selector.register(stderr, selectors.EVENT_READ, "stderr")

    state = _ExchangeState(
        request_offset=0,
        stdout=bytearray(),
        stderr=bytearray(),
        output_limit_exceeded=False,
    )
    deadline_ns = time.monotonic_ns() + limits.timeout_ms * 1_000_000

    try:
        while True:
            if state.output_limit_exceeded:
                returncode = _terminate_and_reap(process)
                return RawWorkerExit(
                    kind=WorkerExitKind.OUTPUT_LIMIT_EXCEEDED,
                    returncode=returncode,
                    stdout=bytes(state.stdout),
                    stderr=bytes(state.stderr),
                )
            remaining_ns = deadline_ns - time.monotonic_ns()
            if remaining_ns <= 0:
                returncode = _terminate_and_reap(process)
                return RawWorkerExit(
                    kind=WorkerExitKind.TIMED_OUT,
                    returncode=returncode,
                    stdout=bytes(state.stdout),
                    stderr=bytes(state.stderr),
                )
            if not selector.get_map():
                completed = _completed_process_exit(
                    process,
                    state=state,
                    remaining_ns=remaining_ns,
                )
                if completed is not None:
                    return completed
                continue

            events = selector.select(remaining_ns / 1_000_000_000)
            for key, _ in events:
                _handle_process_event(
                    selector,
                    key,
                    state=state,
                    request=request,
                    limits=limits,
                )
    except (OSError, ValueError) as error:
        _abort_process(process)
        raise WorkerHarnessError(WorkerHarnessErrorKind.PIPE_IO_FAILED) from error
    finally:
        selector.close()
        for stream in streams:
            with suppress(OSError):
                stream.close()


def _completed_process_exit(
    process: subprocess.Popen[bytes],
    *,
    state: _ExchangeState,
    remaining_ns: int,
) -> RawWorkerExit | None:
    returncode = process.poll()
    if returncode is None:
        try:
            returncode = process.wait(
                timeout=min(remaining_ns / 1_000_000_000, 0.05),
            )
        except subprocess.TimeoutExpired:
            return None
    return RawWorkerExit(
        kind=WorkerExitKind.EXITED,
        returncode=returncode,
        stdout=bytes(state.stdout),
        stderr=bytes(state.stderr),
    )


def _handle_process_event(
    selector: selectors.BaseSelector,
    key: selectors.SelectorKey,
    *,
    state: _ExchangeState,
    request: bytes,
    limits: WorkerLimits,
) -> None:
    stream = cast(BinaryIO, key.fileobj)
    if key.data == "stdin":
        _write_worker_request(
            selector,
            stream,
            fd=key.fd,
            state=state,
            request=request,
        )
        return
    if key.data == "stdout":
        buffer = state.stdout
        limit = limits.stdout_bytes
    else:
        buffer = state.stderr
        limit = limits.stderr_bytes
    state.output_limit_exceeded |= _read_worker_output(
        selector,
        stream,
        fd=key.fd,
        buffer=buffer,
        limit=limit,
    )


def _write_worker_request(
    selector: selectors.BaseSelector,
    stream: BinaryIO,
    *,
    fd: int,
    state: _ExchangeState,
    request: bytes,
) -> None:
    try:
        written = os.write(
            fd,
            request[state.request_offset : state.request_offset + _IO_CHUNK_BYTES],
        )
    except BrokenPipeError:
        _close_registered(selector, stream)
        return
    if written <= 0:
        raise OSError("worker stdin made no progress")
    state.request_offset += written
    if state.request_offset == len(request):
        _close_registered(selector, stream)


def _read_worker_output(
    selector: selectors.BaseSelector,
    stream: BinaryIO,
    *,
    fd: int,
    buffer: bytearray,
    limit: int,
) -> bool:
    chunk = os.read(fd, _IO_CHUNK_BYTES)
    if not chunk:
        _close_registered(selector, stream)
        return False
    return _append_bounded(buffer, chunk, limit=limit)


def _append_bounded(buffer: bytearray, chunk: bytes, *, limit: int) -> bool:
    remaining = max(0, limit - len(buffer))
    buffer.extend(chunk[:remaining])
    return len(chunk) > remaining


def _close_registered(
    selector: selectors.BaseSelector,
    stream: BinaryIO,
) -> None:
    with suppress(KeyError):
        selector.unregister(stream)
    stream.close()


def _terminate_and_reap(process: subprocess.Popen[bytes]) -> int:
    _signal_process_group(process, signal.SIGKILL)
    try:
        return process.wait(timeout=_REAP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as error:
        raise WorkerHarnessError(WorkerHarnessErrorKind.REAP_FAILED) from error


def _abort_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        _signal_process_group(process, signal.SIGKILL)
    try:
        process.wait(timeout=_REAP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as error:
        raise WorkerHarnessError(WorkerHarnessErrorKind.REAP_FAILED) from error
    finally:
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                with suppress(OSError):
                    stream.close()


def _signal_process_group(
    process: subprocess.Popen[bytes],
    selected_signal: signal.Signals,
) -> None:
    try:
        os.killpg(process.pid, selected_signal)
    except ProcessLookupError:
        if process.poll() is None:
            process.kill()
    except PermissionError:
        if process.poll() is None:
            process.kill()


def _canonical_object(
    payload: bytes,
    *,
    label: str,
    maximum_bytes: int,
) -> dict[str, object]:
    if type(payload) is not bytes:
        raise TypeError(f"{label} payload must be exact bytes")
    if not payload or len(payload) > maximum_bytes:
        raise ValueError(f"{label} payload exceeds its byte bounds")
    try:
        raw: object = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from error
    try:
        canonical = type(raw) is dict and canonical_json(cast(JsonValue, raw)) == payload
    except (TypeError, UnicodeEncodeError, RecursionError) as error:
        raise ValueError(f"{label} contains unsupported JSON values") from error
    if not canonical:
        raise ValueError(f"{label} is not one canonical JSON object")
    return cast(dict[str, object], raw)


def _required_string(raw: dict[str, object], field: str) -> str:
    value = raw.get(field)
    if type(value) is not str:
        raise ValueError(f"{field} must be a string")
    return value


def _bounded_integer(
    value: object,
    *,
    field: str,
    minimum: int,
    maximum: int,
) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{field} must be an integer in [{minimum}, {maximum}]")


def _require_identifier(value: object, *, field: str) -> None:
    if type(value) is not str or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{field} must be a lowercase identifier")


def _require_digest(value: object, *, field: str) -> None:
    if (
        type(value) is not str
        or len(value) != _SHA256_HEX_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} must be lowercase SHA-256")
