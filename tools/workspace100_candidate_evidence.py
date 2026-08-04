#!/usr/bin/env python3
"""Write or verify the reviewed Workspace-100 development-candidate receipt.

The two pinned roots below are local Git-history integrity checks.  They are
not signatures, independent attestations, or public-release authentication.
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Final, cast

ROOT: Final = Path(__file__).resolve().parents[1]
SRC: Final = ROOT / "src"
EVIDENCE_PATH: Final = ROOT / "docs" / "evidence" / "workspace100-candidate-receipt.json"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from witnessgap.verifier import verifier_implementation_digest  # noqa: E402
from witnessgap.workspace100.baselines import (  # noqa: E402
    BuiltinBaseline,
    builtin_baseline_set,
)
from witnessgap.workspace100.candidate_capture import (  # noqa: E402
    PORTFOLIO_SEED,
    RUNTIME_ARTIFACT_SCOPE,
    Workspace100CandidateReceipt,
    candidate_capture_implementation_digest,
    check_workspace100_candidate,
)
from witnessgap.workspace100.claims import (  # noqa: E402
    workspace100_claims_implementation_digest,
)
from witnessgap.workspace100.release import (  # noqa: E402
    workspace100_release_implementation_digest,
)
from witnessgap.workspace100.release_storage import (  # noqa: E402
    Workspace100GenerationProvenance,
)
from witnessgap.workspace100.runtime import (  # noqa: E402
    workspace100_adapter_implementation_digest,
)
from witnessgap.workspace100.scoring import (  # noqa: E402
    Workspace100FailureCounts,
    Workspace100ScoreCounts,
    Workspace100ScoreMetrics,
    workspace100_scoring_implementation_digest,
)
from witnessgap.workspace100.views import (  # noqa: E402
    build_workspace100_evidence_views,
)
from witnessgap.workspace100.worker import (  # noqa: E402
    workspace100_worker_implementation_digest,
)

# Local drift pins only: neither root establishes independent authentication.
EXPECTED_RELEASE_ROOT: Final = "005987000c049e34f1a5b1f886bb07bcd1d02d983c16ddfd098cde6e79c82d01"
EXPECTED_RECEIPT_ROOT: Final = "668d2093bef503c0c43300f586427124863d59fc5b75d223d2396fb28da6f313"
EXPECTED_RUNTIME_ID: Final = "cpython_3_12_3_linux_x86_64"
MAX_RECEIPT_BYTES: Final = 1 << 20
_NO_AUTHENTICATION: Final = "not_established_by_this_receipt"
_RUN_COUNT: Final = 1_200
_EXPECTED_COUNTS: Final = {
    BuiltinBaseline.ALWAYS_UNKNOWN: Workspace100ScoreCounts(
        correct_abstention=100,
        missed_identifiable=200,
    ),
    BuiltinBaseline.FORCED_ENVIRONMENT: Workspace100ScoreCounts(
        decisive_on_ambiguous=100,
        exact_decisive=100,
        wrong_target=100,
    ),
    BuiltinBaseline.REFRESH_SUCCESS_ONLY: Workspace100ScoreCounts(
        correct_abstention=100,
        exact_decisive=50,
        missed_identifiable=150,
    ),
    BuiltinBaseline.REFRESH_OUTCOME: Workspace100ScoreCounts(
        correct_abstention=100,
        exact_decisive=100,
        missed_identifiable=100,
    ),
}
_EXPECTED_ORACLE_COUNTS: Final = Workspace100ScoreCounts(
    correct_abstention=100,
    exact_decisive=200,
)


def write_evidence(
    candidate_parent: Path,
    *,
    checkout_root: Path = ROOT,
    evidence_path: Path = EVIDENCE_PATH,
) -> Workspace100CandidateReceipt:
    """Semantically replay the materialized candidate, then atomically persist its receipt."""

    receipt = check_workspace100_candidate(
        checkout_root=str(checkout_root),
        output_parent=str(candidate_parent),
        expected_release_root=EXPECTED_RELEASE_ROOT,
    )
    _validate_portfolio_evidence(receipt)
    _atomic_write(evidence_path, receipt.to_canonical_bytes())
    return receipt


def check_evidence(
    evidence_path: Path = EVIDENCE_PATH,
) -> Workspace100CandidateReceipt:
    """Bounded-read and validate the committed development-candidate receipt."""

    receipt = Workspace100CandidateReceipt.from_canonical_bytes(
        _bounded_regular_file_read(evidence_path)
    )
    _validate_portfolio_evidence(receipt)
    return receipt


def _validate_portfolio_evidence(receipt: Workspace100CandidateReceipt) -> None:
    payload = cast(dict[str, object], receipt.to_payload())
    roots = _object(payload["roots"], label="roots")
    counts = _object(payload["counts"], label="counts")
    statuses = _object(counts["worker_status"], label="worker_status")
    runtime = _object(payload["runtime"], label="runtime")

    if (
        payload["official"] is not False
        or payload["root_authentication"] != _NO_AUTHENTICATION
        or roots["release"] != EXPECTED_RELEASE_ROOT
        or payload["receipt_root"] != EXPECTED_RECEIPT_ROOT
    ):
        raise ValueError("candidate identity, non-official status, or local root pins differ")
    if counts["worker_runs"] != _RUN_COUNT or statuses != {"claimed": _RUN_COUNT, "failed": 0}:
        raise ValueError("candidate does not contain 1,200 successful claimed runs")
    if (
        runtime["artifact_scope"] != RUNTIME_ARTIFACT_SCOPE
        or runtime["runtime_id"] != EXPECTED_RUNTIME_ID
        or runtime["implementation"] != "CPython"
        or runtime["version"] != "3.12.3"
        or runtime["interpreter_sha256"] != runtime["runtime_artifact_sha256"]
    ):
        raise ValueError("candidate runtime identity or binary-hash agreement differs")
    if roots["tool_implementation"] != candidate_capture_implementation_digest():
        raise ValueError("candidate capture implementation has drifted")
    if roots["baseline_set"] != builtin_baseline_set().baseline_set_root:
        raise ValueError("candidate frozen baseline set has drifted")
    _require_current_source_closure(roots)
    _require_reference_scores(payload)


def _require_current_source_closure(roots: dict[str, object]) -> None:
    provenance = Workspace100GenerationProvenance(PORTFOLIO_SEED)
    views = build_workspace100_evidence_views(provenance.corpus)
    expected = {
        "adapter_implementation": workspace100_adapter_implementation_digest(),
        "assignment": views.assignment_root,
        "claims_implementation": workspace100_claims_implementation_digest(),
        "evidence": views.evidence_root,
        "projection": views.projection_root,
        "release_builder_implementation": workspace100_release_implementation_digest(),
        "scoring_implementation": workspace100_scoring_implementation_digest(),
        "seed": provenance.seed_digest,
        "source": provenance.source_root,
        "source_opening": provenance.source_opening_root,
        "template_catalog": provenance.template_catalog_digest,
        "variant_catalog": provenance.variant_catalog_digest,
        "verifier_implementation": verifier_implementation_digest(),
        "worker_implementation": workspace100_worker_implementation_digest(),
    }
    differing = tuple(
        field for field, expected_root in expected.items() if roots[field] != expected_root
    )
    if differing:
        raise ValueError("candidate source/content closure has drifted: " + ", ".join(differing))


def _require_reference_scores(payload: dict[str, object]) -> None:
    raw_scores = payload["scores"]
    if type(raw_scores) is not list:
        raise ValueError("candidate scores must be an array")
    scores = tuple(_object(item, label="score") for item in raw_scores)
    if tuple(item["baseline"] for item in scores) != tuple(
        baseline.value for baseline in BuiltinBaseline
    ):
        raise ValueError("candidate reference score order differs")
    empty_failures = Workspace100FailureCounts().to_payload()
    for baseline, score in zip(BuiltinBaseline, scores, strict=True):
        expected_counts = _EXPECTED_COUNTS[baseline]
        if (
            score["counts"] != expected_counts.to_payload()
            or score["failure_counts"] != empty_failures
            or score["metrics"]
            != Workspace100ScoreMetrics.from_counts(expected_counts).to_payload()
        ):
            raise ValueError(f"candidate reference score differs for {baseline.value}")

    oracle = _object(payload["oracle_ceiling_overall"], label="oracle")
    if (
        oracle["counts"] != _EXPECTED_ORACLE_COUNTS.to_payload()
        or oracle["failure_counts"] != empty_failures
        or oracle["metrics"]
        != Workspace100ScoreMetrics.from_counts(_EXPECTED_ORACLE_COUNTS).to_payload()
    ):
        raise ValueError("candidate oracle-ceiling score differs")


def _object(value: object, *, label: str) -> dict[str, object]:
    if type(value) is not dict:
        raise ValueError(f"candidate {label} must be an object")
    return cast(dict[str, object], value)


def _bounded_regular_file_read(path: Path) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("candidate receipt must be a regular file")
        if metadata.st_size < 1 or metadata.st_size > MAX_RECEIPT_BYTES:
            raise ValueError("candidate receipt exceeds its byte bound")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(MAX_RECEIPT_BYTES + 1)
        if not payload or len(payload) > MAX_RECEIPT_BYTES:
            raise ValueError("candidate receipt exceeds its byte bound")
        return payload
    finally:
        os.close(descriptor)


def _atomic_write(path: Path, payload: bytes) -> None:
    if not payload or len(payload) > MAX_RECEIPT_BYTES:
        raise ValueError("candidate receipt exceeds its byte bound")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
    )
    temporary = Path(temporary_name)
    descriptor_open = True
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor_open = False
            if stream.write(payload) != len(payload):
                raise OSError("candidate receipt write was incomplete")
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_descriptor = os.open(
            path.parent,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY,
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if descriptor_open:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Manage a non-official Workspace-100 development-candidate receipt. "
            "Pinned roots are local drift checks, not independent authentication."
        )
    )
    commands = parser.add_subparsers(dest="command", required=True)
    write = commands.add_parser(
        "write",
        help="semantically replay a materialized candidate and write canonical evidence",
    )
    write.add_argument(
        "candidate_parent",
        type=Path,
        help="private parent containing workspace100/v1",
    )
    commands.add_parser(
        "check",
        help="verify committed canonical evidence and local integrity pins",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.command == "write":
        receipt = write_evidence(arguments.candidate_parent)
        action = "wrote"
    elif arguments.command == "check":
        receipt = check_evidence()
        action = "verified"
    else:  # pragma: no cover - argparse enforces the closed command set.
        raise RuntimeError("unsupported evidence command")
    print(
        f"{action} non-official development candidate receipt "
        f"{cast(str, receipt.to_payload()['receipt_root'])}; "
        "independent authentication: not established"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
