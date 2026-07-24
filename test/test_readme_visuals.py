from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import cast
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[1]
VISUAL_DIRECTORY = ROOT / "docs" / "images" / "readme"
EXPECTED_SVGS = {
    "candidate-artifact-inventory.svg",
    "candidate-check-transcript.svg",
    "candidate-control-results.svg",
    "causal-twins-flow.svg",
    "evidence-views.svg",
    "isolation-boundary.svg",
    "release-binding-closure.svg",
    "release-tree.svg",
    "verdict-taxonomy.svg",
    "verification-flow.svg",
    "workspace100-funnel.svg",
}
EXPECTED_RELEASE_PAYLOAD_COUNT = 13
EXPECTED_RELEASE_FILE_COUNT = 14
EXPECTED_RELEASE_BINDING_COUNT = 25
EXPECTED_CANDIDATE_TOTAL_BYTES = 5_610_036
EXPECTED_CANDIDATE_RUN_COUNT = 1_200
EXPECTED_LOCKED_PACKAGE_COUNT = 16
EXPECTED_RECEIPT_ROOT = "668d2093bef503c0c43300f586427124863d59fc5b75d223d2396fb28da6f313"


def _object(value: object) -> dict[str, object]:
    assert type(value) is dict
    return cast(dict[str, object], value)


def _array(value: object) -> list[object]:
    assert type(value) is list
    return cast(list[object], value)


def _records_by_file() -> dict[str, dict[str, object]]:
    manifest = _object(json.loads((VISUAL_DIRECTORY / "provenance.json").read_bytes()))
    return {
        cast(str, record["file"]): record
        for record in (_object(item) for item in _array(manifest["visuals"]))
    }


def test_readme_visuals_are_source_current_accessible_and_closed() -> None:
    completed = subprocess.run(
        (sys.executable, "tools/render_readme_visuals.py", "check"),
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert "11 SVGs + provenance" in completed.stdout

    manifest = _object(json.loads((VISUAL_DIRECTORY / "provenance.json").read_bytes()))
    assert manifest["format"] == "witnessgap.readme-visual-provenance.v1"
    assert manifest["official"] is False
    assert manifest["generator"] == "tools/render_readme_visuals.py"
    records = tuple(_object(item) for item in _array(manifest["visuals"]))
    assert {cast(str, record["file"]) for record in records} == EXPECTED_SVGS

    svg_namespace = "{http://www.w3.org/2000/svg}"
    forbidden_tags = {
        f"{svg_namespace}foreignObject",
        f"{svg_namespace}image",
        f"{svg_namespace}linearGradient",
        f"{svg_namespace}radialGradient",
        f"{svg_namespace}script",
        f"{svg_namespace}style",
    }
    for record in records:
        assert record["official"] is False
        filename = cast(str, record["file"])
        source_records = tuple(_object(item) for item in _array(record["source_records"]))
        assert source_records
        assert [item["path"] for item in source_records] == record["source_paths"]
        for source_record in source_records:
            source_path = ROOT / cast(str, source_record["path"])
            assert source_path.is_file()
            assert hashlib.sha256(source_path.read_bytes()).hexdigest() == source_record["sha256"]
        payload = (VISUAL_DIRECTORY / filename).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == record["sha256"]
        root = ElementTree.fromstring(payload)
        assert root.tag == f"{svg_namespace}svg"
        assert root.attrib["role"] == "img"
        assert root.attrib["aria-labelledby"] == "visual-title visual-description"
        title = root.find(f"{svg_namespace}title")
        description = root.find(f"{svg_namespace}desc")
        assert title is not None and title.text
        assert description is not None and description.text
        assert not any(element.tag in forbidden_tags for element in root.iter())
        assert b"href=" not in payload
        assert b"url(" not in payload
        visible_text = " ".join(element.text or "" for element in root.iter())
        assert "official: false" in visible_text
        assert "nonclaim:" in visible_text

    by_file = {cast(str, record["file"]): record for record in records}
    release_facts = _object(by_file["release-tree.svg"]["facts"])
    assert release_facts["payload_count"] == EXPECTED_RELEASE_PAYLOAD_COUNT
    assert release_facts["physical_file_count"] == EXPECTED_RELEASE_FILE_COUNT
    assert release_facts["gate16_status"] == "not_established"
    binding_facts = _object(by_file["release-binding-closure.svg"]["facts"])
    assert binding_facts["binding_count"] == EXPECTED_RELEASE_BINDING_COUNT
    evidence_facts = _object(by_file["evidence-views.svg"]["facts"])
    view_facts = _object(evidence_facts["views"])
    assert {name: _object(value)["cases"] for name, value in view_facts.items()} == {
        "epoch_probe": 100,
        "owner_probe": 50,
        "refresh_receipt": 100,
        "trace_only": 50,
    }


def test_candidate_result_transcript_and_inventory_visual_facts_are_exact() -> None:
    by_file = _records_by_file()
    result_record = by_file["candidate-control-results.svg"]
    result_facts = _object(result_record["facts"])
    assert result_facts["worker_runs"] == EXPECTED_CANDIDATE_RUN_COUNT
    assert result_facts["worker_status"] == {
        "claimed": EXPECTED_CANDIDATE_RUN_COUNT,
        "failed": 0,
    }
    controls = tuple(_object(item) for item in _array(result_facts["controls"]))
    assert {
        cast(str, control["baseline"]): (
            _object(control["decisive_coverage"])["numerator"],
            _object(control["false_certainty_incidence"])["numerator"],
        )
        for control in controls
    } == {
        "always_unknown": (0, 0),
        "forced_environment": (300, 200),
        "refresh_success_only": (50, 0),
        "refresh_outcome": (100, 0),
    }
    assert {
        cast(str, _object(item)["path"]) for item in _array(result_record["source_records"])
    } == {
        "docs/evidence/workspace100-candidate-receipt.json",
        "tools/workspace100_candidate_evidence.py",
    }

    transcript_facts = _object(by_file["candidate-check-transcript.svg"]["facts"])
    assert transcript_facts["command"] == ("python tools/workspace100_candidate_evidence.py check")
    assert transcript_facts["official"] is False
    assert transcript_facts["receipt_root"] == EXPECTED_RECEIPT_ROOT
    assert transcript_facts["root_authentication"] == "not_established_by_this_receipt"
    assert transcript_facts["stdout"] == (
        "verified non-official development candidate receipt "
        f"{EXPECTED_RECEIPT_ROOT}; independent authentication: not established"
    )

    inventory_facts = _object(by_file["candidate-artifact-inventory.svg"]["facts"])
    inventory = tuple(_object(item) for item in _array(inventory_facts["files"]))
    assert inventory_facts["file_count"] == EXPECTED_RELEASE_FILE_COUNT
    assert inventory_facts["total_bytes"] == EXPECTED_CANDIDATE_TOTAL_BYTES
    assert sum(cast(int, item["byte_length"]) for item in inventory) == (
        EXPECTED_CANDIDATE_TOTAL_BYTES
    )
    assert {item["mode"] for item in inventory} == {"0444"}
    assert inventory[-1]["path"] == "release-manifest.json"


def test_verification_flow_records_current_ci_and_explicit_omissions() -> None:
    by_file = _records_by_file()
    setup_record = by_file["verification-flow.svg"]
    setup_facts = _object(setup_record["facts"])
    assert setup_facts["python_version"] == "3.12.3"
    assert setup_facts["locked_package_count"] == EXPECTED_LOCKED_PACKAGE_COUNT
    assert setup_facts["lock_hash_count"] == EXPECTED_LOCKED_PACKAGE_COUNT
    assert setup_facts["console_entrypoint"] == "witnessgap.cli:main"
    assert setup_facts["ci_check_commands"] == [
        "ruff check src test",
        "mypy --strict src test",
        "pytest",
    ]
    assert setup_facts["missing_ci_commands"] == [
        "ruff check tools",
        "mypy --strict tools",
        "python tools/workspace100_candidate_evidence.py check",
        "python tools/render_readme_visuals.py check",
        "witnessgap example  # explicit CLI smoke",
    ]
    assert {
        cast(str, _object(item)["path"]) for item in _array(setup_record["source_records"])
    } == {
        ".github/workflows/ci.yml",
        ".python-version",
        "pyproject.toml",
        "requirements-dev.lock",
    }
