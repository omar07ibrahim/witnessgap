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
    "causal-twins-flow.svg",
    "evidence-views.svg",
    "isolation-boundary.svg",
    "release-binding-closure.svg",
    "release-tree.svg",
    "verdict-taxonomy.svg",
    "workspace100-funnel.svg",
}
EXPECTED_RELEASE_PAYLOAD_COUNT = 13
EXPECTED_RELEASE_FILE_COUNT = 14
EXPECTED_RELEASE_BINDING_COUNT = 25


def _object(value: object) -> dict[str, object]:
    assert type(value) is dict
    return cast(dict[str, object], value)


def _array(value: object) -> list[object]:
    assert type(value) is list
    return cast(list[object], value)


def test_readme_visuals_are_source_current_accessible_and_closed() -> None:
    completed = subprocess.run(
        (sys.executable, "tools/render_readme_visuals.py", "check"),
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert "7 SVGs + provenance" in completed.stdout

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
