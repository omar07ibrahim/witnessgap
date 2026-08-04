from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import cast
from xml.etree import ElementTree

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.render_readme_visuals import Svg  # noqa: E402

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
MINIMUM_TEXT_CONTRAST = 4.5
FONT_FAMILY = "DejaVu Sans Mono, Liberation Mono, monospace"
EXPECTED_RENDERER_VERSION = 2
HEX_COLOR_LENGTH = 7
POINT_COORDINATE_COUNT = 2
SRGB_LINEAR_THRESHOLD = 0.04045


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


def _float_attribute(element: ElementTree.Element, name: str) -> float:
    return float(element.attrib[name])


def _text_bounds(element: ElementTree.Element) -> tuple[float, float, float, float]:
    value = element.text
    assert value
    size = _float_attribute(element, "font-size")
    assert element.attrib["font-family"] == FONT_FAMILY
    assert element.attrib["lengthAdjust"] == "spacingAndGlyphs"
    width = _float_attribute(element, "textLength")
    assert width > 0
    x = _float_attribute(element, "x")
    anchor = element.attrib.get("text-anchor", "start")
    assert anchor in {"start", "middle", "end"}
    left = x if anchor == "start" else x - width / 2 if anchor == "middle" else x - width
    baseline = _float_attribute(element, "y")
    return (left, baseline - size, left + width, baseline + size * 0.30)


def _relative_luminance(color: str) -> float:
    assert len(color) == HEX_COLOR_LENGTH and color.startswith("#")
    channels = tuple(int(color[offset : offset + 2], 16) / 255 for offset in (1, 3, 5))
    linear = tuple(
        channel / 12.92 if channel <= SRGB_LINEAR_THRESHOLD else ((channel + 0.055) / 1.055) ** 2.4
        for channel in channels
    )
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast_ratio(foreground: str, background: str) -> float:
    foreground_luminance = _relative_luminance(foreground)
    background_luminance = _relative_luminance(background)
    lighter = max(foreground_luminance, background_luminance)
    darker = min(foreground_luminance, background_luminance)
    return (lighter + 0.05) / (darker + 0.05)


def _contains(
    outer: tuple[float, float, float, float],
    inner: tuple[float, float, float, float],
) -> bool:
    return (
        outer[0] <= inner[0]
        and outer[1] <= inner[1]
        and outer[2] >= inner[2]
        and outer[3] >= inner[3]
    )


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
    assert manifest["renderer_version"] == EXPECTED_RENDERER_VERSION
    assert manifest["layout_contract"] == {
        "geometry": "viewbox-and-active-fill-bounds.v1",
        "minimum_text_contrast_ratio": MINIMUM_TEXT_CONTRAST,
        "text_width": "explicit-textLength.v1",
    }
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


def test_readme_visual_geometry_and_text_contrast_are_bounded() -> None:
    svg_namespace = "{http://www.w3.org/2000/svg}"
    for filename in sorted(EXPECTED_SVGS):
        root = ElementTree.fromstring((VISUAL_DIRECTORY / filename).read_bytes())
        origin_x, origin_y, width, height = (float(part) for part in root.attrib["viewBox"].split())
        assert (origin_x, origin_y) == (0.0, 0.0)
        assert float(root.attrib["width"]) == width
        assert float(root.attrib["height"]) == height
        painted_rectangles: list[tuple[tuple[float, float, float, float], str]] = []

        for element in root:
            local_name = element.tag.removeprefix(svg_namespace)
            if local_name == "rect":
                x = _float_attribute(element, "x")
                y = _float_attribute(element, "y")
                rectangle_width = _float_attribute(element, "width")
                rectangle_height = _float_attribute(element, "height")
                stroke_margin = float(element.attrib.get("stroke-width", "0")) / 2
                assert rectangle_width >= 0 and rectangle_height >= 0
                assert x - stroke_margin >= 0, (filename, element.attrib)
                assert y - stroke_margin >= 0, (filename, element.attrib)
                assert x + rectangle_width + stroke_margin <= width, (
                    filename,
                    element.attrib,
                )
                assert y + rectangle_height + stroke_margin <= height, (
                    filename,
                    element.attrib,
                )
                painted_rectangles.append(
                    (
                        (x, y, x + rectangle_width, y + rectangle_height),
                        element.attrib["fill"],
                    )
                )
            elif local_name == "line":
                x_values = (
                    _float_attribute(element, "x1"),
                    _float_attribute(element, "x2"),
                )
                y_values = (
                    _float_attribute(element, "y1"),
                    _float_attribute(element, "y2"),
                )
                stroke_margin = _float_attribute(element, "stroke-width") / 2
                assert min(x_values) - stroke_margin >= 0, (filename, element.attrib)
                assert max(x_values) + stroke_margin <= width, (filename, element.attrib)
                assert min(y_values) - stroke_margin >= 0, (filename, element.attrib)
                assert max(y_values) + stroke_margin <= height, (filename, element.attrib)
            elif local_name == "polygon":
                points = tuple(
                    tuple(float(coordinate) for coordinate in point.split(","))
                    for point in element.attrib["points"].split()
                )
                assert points and all(len(point) == POINT_COORDINATE_COUNT for point in points)
                assert all(0 <= point[0] <= width for point in points), (
                    filename,
                    element.attrib,
                )
                assert all(0 <= point[1] <= height for point in points), (
                    filename,
                    element.attrib,
                )
            elif local_name == "text":
                bounds = _text_bounds(element)
                assert bounds[0] >= 0 and bounds[1] >= 0, (filename, element.text)
                assert bounds[2] <= width and bounds[3] <= height, (
                    filename,
                    element.text,
                )
                anchor = (
                    _float_attribute(element, "x"),
                    _float_attribute(element, "y"),
                )
                active_rectangle, background = next(
                    (rectangle, color)
                    for rectangle, color in reversed(painted_rectangles)
                    if rectangle[0] <= anchor[0] <= rectangle[2]
                    and rectangle[1] <= anchor[1] <= rectangle[3]
                )
                assert _contains(active_rectangle, bounds), (filename, element.text)
                assert (
                    _contrast_ratio(element.attrib["fill"], background) >= MINIMUM_TEXT_CONTRAST
                ), (filename, element.text, element.attrib["fill"], background)
            else:
                assert local_name in {"title", "desc"}, (filename, local_name)


def test_svg_renderer_rejects_out_of_bounds_and_low_contrast_primitives() -> None:
    canvas = Svg(240, 120, title="contract", description="negative cases")
    with pytest.raises(ValueError, match="viewBox"):
        canvas.rect(-1, 10, 40, 40)
    with pytest.raises(ValueError, match="viewBox"):
        canvas.line(0, 10, 40, 10, width=2)
    with pytest.raises(ValueError, match="arrow head"):
        canvas.arrow(10, 5, 100, 5, width=2)
    with pytest.raises(ValueError, match="viewBox"):
        canvas.text(220, 50, "overflow", size=16)
    with pytest.raises(ValueError, match="viewBox"):
        canvas.text(8, 50, "middle overflow", size=16, anchor="middle")
    with pytest.raises(ValueError, match="viewBox"):
        canvas.text(8, 50, "end overflow", size=16, anchor="end")
    with pytest.raises(ValueError, match="contrast"):
        canvas.text(12, 50, "low contrast", size=14, color="#111f33")
    with pytest.raises(ValueError, match="six-digit hex"):
        canvas.text(12, 50, "bad color", size=14, color="white")

    card = Svg(240, 120, title="contract", description="active fill case")
    card.rect(20, 20, 80, 80)
    with pytest.raises(ValueError, match="active painted region"):
        card.text(30, 60, "escapes the card", size=14)


def test_svg_renderer_emits_repeatable_explicit_text_width() -> None:
    svg = Svg(240, 120, title="contract", description="deterministic width")
    svg.text(12, 50, "repeatable", size=14)
    first = svg.render()
    assert svg.render() == first
    root = ElementTree.fromstring(first)
    text = root.find("{http://www.w3.org/2000/svg}text")
    assert text is not None
    assert text.attrib["font-family"] == FONT_FAMILY
    assert text.attrib["textLength"] == "87"
    assert text.attrib["lengthAdjust"] == "spacingAndGlyphs"


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


def test_verification_flow_records_current_ci_gates_and_boundaries() -> None:
    by_file = _records_by_file()
    setup_record = by_file["verification-flow.svg"]
    setup_facts = _object(setup_record["facts"])
    assert setup_facts["python_version"] == "3.12.3"
    assert setup_facts["requires_python"] == ">=3.12,<3.13"
    assert setup_facts["locked_package_count"] == EXPECTED_LOCKED_PACKAGE_COUNT
    assert setup_facts["lock_hash_count"] == EXPECTED_LOCKED_PACKAGE_COUNT
    assert setup_facts["console_entrypoint"] == "witnessgap.cli:main"
    assert setup_facts["ci_check_commands"] == [
        "ruff check src test tools",
        "mypy --strict src test tools",
        "pytest",
    ]
    assert setup_facts["ci_reproducibility_commands"] == [
        "python tools/workspace100_candidate_evidence.py check",
        "python tools/render_readme_visuals.py check",
        "witnessgap example",
    ]
    assert setup_facts["ci_distribution_commands"] == ["python tools/verify_distribution.py"]
    assert setup_facts["current_ci_omission_count"] == 0
    assert setup_facts["missing_ci_commands"] == []
    assert setup_record["nonclaims"] == [
        "Local drift pins and content digests are not independent external authentication.",
        "The installed CLI smoke check does not replay the full 1,200-run candidate capture.",
        "The local process backend is not a hostile-code sandbox.",
    ]
    assert {
        cast(str, _object(item)["path"]) for item in _array(setup_record["source_records"])
    } == {
        ".github/workflows/ci.yml",
        ".python-version",
        "pyproject.toml",
        "requirements-dev.lock",
        "tools/verify_distribution.py",
    }
