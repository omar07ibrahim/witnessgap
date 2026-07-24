from __future__ import annotations

import json
import subprocess
import sys
from typing import cast

import pytest

from witnessgap.canonical import JsonValue, canonical_json
from witnessgap.cli import (
    _example_payload,
    main,
)

_DIGEST_LENGTH = 64
_CAUSAL_TWIN_COUNT = 2


def _object(payload: str) -> dict[str, JsonValue]:
    opened = json.loads(payload)
    assert type(opened) is dict
    return cast(dict[str, JsonValue], opened)


def test_example_command_emits_a_verified_path_free_certificate(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(("example", "--compact")) == 0

    output = capsys.readouterr()
    payload = _object(output.out)
    assert output.err == ""
    assert output.out.encode() == canonical_json(payload)
    assert payload["verdict"] == "not_identifiable"
    assert payload["unknown_reason"] == "ambiguous_worlds"
    assert payload["compatible_completion_count"] == _CAUSAL_TWIN_COUNT
    assert payload["official"] is False
    for field in (
        "evidence_digest",
        "panel_root",
        "proof_root",
        "registry_digest",
        "trust_anchor_digest",
    ):
        value = payload[field]
        assert type(value) is str and len(value) == _DIGEST_LENGTH
    assert "/home/" not in output.out
    assert "\\\\" not in output.out


def test_example_payload_is_byte_deterministic() -> None:
    assert canonical_json(_example_payload()) == canonical_json(_example_payload())


def test_workspace100_command_derives_the_frozen_construction(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(("workspace100", "--compact")) == 0

    output = capsys.readouterr()
    payload = _object(output.out)
    counts = cast(dict[str, JsonValue], payload["counts"])
    views = cast(dict[str, JsonValue], payload["view_cases"])
    assert output.err == ""
    assert output.out.encode() == canonical_json(payload)
    assert counts == {
        "assignments": 400,
        "builtin_methods": 4,
        "completions": 100,
        "fresh_process_runs_in_full_matrix": 1200,
        "pairs": 50,
        "participant_cases": 300,
        "templates": 5,
        "variants": 50,
    }
    assert views == {
        "epoch_probe": 100,
        "owner_probe": 50,
        "refresh_receipt": 100,
        "trace_only": 50,
    }
    assert payload["gate16_status"] == "not_established"
    assert payload["hostile_code_containment"] == "not_established"
    assert payload["official"] is False
    assert payload["public_release_published"] is False
    assert "/home/" not in output.out


def test_pretty_output_is_stable_and_human_readable(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(("example",)) == 0

    output = capsys.readouterr().out
    assert output.startswith("{\n")
    assert output.endswith("}\n")
    assert '  "verdict": "not_identifiable"' in output


def test_python_module_entrypoint_matches_the_public_command() -> None:
    completed = subprocess.run(
        (sys.executable, "-m", "witnessgap", "example", "--compact"),
        check=True,
        capture_output=True,
        text=False,
    )

    assert completed.stderr == b""
    assert completed.stdout == canonical_json(_example_payload())
