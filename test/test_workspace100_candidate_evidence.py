from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import cast

import pytest

from witnessgap import workspace100
from witnessgap.workspace100.candidate_capture import Workspace100CandidateReceipt

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import workspace100_candidate_evidence as evidence  # noqa: E402

EXPECTED_FILE_MODE = 0o644


def test_committed_candidate_evidence_is_current_and_explicitly_unauthenticated() -> None:
    receipt = evidence.check_evidence()
    payload = cast(dict[str, object], receipt.to_payload())

    assert payload["official"] is False
    assert payload["root_authentication"] == "not_established_by_this_receipt"
    assert payload["receipt_root"] == evidence.EXPECTED_RECEIPT_ROOT
    receipt_bytes = evidence.EVIDENCE_PATH.read_bytes()
    assert receipt_bytes.endswith(b"\n")
    assert receipt_bytes.count(b"\n") == 1
    assert not hasattr(workspace100, "check_workspace100_candidate")
    assert not hasattr(workspace100, "Workspace100CandidateReceipt")


def test_write_calls_semantic_checker_with_external_root_and_writes_exact_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "candidate"
    checkout = tmp_path / "checkout"
    destination = tmp_path / "docs" / "evidence" / "workspace100-candidate-receipt.json"
    source.mkdir()
    checkout.mkdir()
    canonical = b'{"fixture":"canonical"}\n'
    observed: dict[str, str] = {}

    class StubReceipt:
        def to_canonical_bytes(self) -> bytes:
            return canonical

    receipt = cast(Workspace100CandidateReceipt, StubReceipt())

    def semantic_check(
        *,
        checkout_root: str,
        output_parent: str,
        expected_release_root: str,
    ) -> Workspace100CandidateReceipt:
        observed.update(
            checkout_root=checkout_root,
            output_parent=output_parent,
            expected_release_root=expected_release_root,
        )
        return receipt

    def accept_fixture(candidate: Workspace100CandidateReceipt) -> None:
        assert candidate is receipt

    monkeypatch.setattr(evidence, "check_workspace100_candidate", semantic_check)
    monkeypatch.setattr(evidence, "_validate_portfolio_evidence", accept_fixture)
    written = evidence.write_evidence(
        source,
        checkout_root=checkout,
        evidence_path=destination,
    )

    assert written is receipt
    assert observed == {
        "checkout_root": str(checkout),
        "output_parent": str(source),
        "expected_release_root": evidence.EXPECTED_RELEASE_ROOT,
    }
    assert destination.read_bytes() == canonical
    assert destination.stat().st_mode & 0o777 == EXPECTED_FILE_MODE
    assert not tuple(destination.parent.glob(f".{destination.name}.*"))


def test_check_is_bounded_and_rejects_symlinks(tmp_path: Path) -> None:
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + b" " * evidence.MAX_RECEIPT_BYTES)
    with pytest.raises(ValueError, match="byte bound"):
        evidence.check_evidence(oversized)

    target = tmp_path / "target.json"
    target.write_bytes(b"{}")
    alias = tmp_path / "alias.json"
    alias.symlink_to(target)
    with pytest.raises(OSError):
        evidence.check_evidence(alias)


def test_artifact_is_canonical_closed_and_contains_no_host_metadata() -> None:
    payload_bytes = evidence.EVIDENCE_PATH.read_bytes()
    payload = cast(dict[str, object], json.loads(payload_bytes))

    assert (
        payload_bytes
        == Workspace100CandidateReceipt.from_canonical_bytes(payload_bytes).to_canonical_bytes()
    )
    serialized = payload_bytes.decode("utf-8")
    assert str(evidence.ROOT) not in serialized
    assert "/home/" not in serialized
    assert set(payload).isdisjoint({"host_path", "pid", "timestamp", "secret"})
    assert payload_bytes.endswith(b"\n")
    assert payload_bytes.count(b"\n") == 1
