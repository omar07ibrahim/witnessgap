#!/usr/bin/env python3
"""Render deterministic, source-derived README visuals for WitnessGap.

The renderer uses the Python standard library, WitnessGap's production
modules, and explicitly declared repository inputs recorded in provenance.
It does not use clocks, network resources, or host-specific output fields.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, fields
from functools import lru_cache
from html import escape
from math import gcd
from pathlib import Path
from types import ModuleType
from typing import Final, cast
from xml.etree import ElementTree

ROOT: Final = Path(__file__).resolve().parents[1]
SRC: Final = ROOT / "src"
OUTPUT_DIRECTORY: Final = ROOT / "docs" / "images" / "readme"
MANIFEST_NAME: Final = "provenance.json"
CANDIDATE_RECEIPT_PATH: Final = ROOT / "docs" / "evidence" / "workspace100-candidate-receipt.json"
CANDIDATE_EVIDENCE_TOOL_PATH: Final = ROOT / "tools" / "workspace100_candidate_evidence.py"
PYTHON_VERSION_PATH: Final = ROOT / ".python-version"
DEVELOPMENT_LOCK_PATH: Final = ROOT / "requirements-dev.lock"
PYPROJECT_PATH: Final = ROOT / "pyproject.toml"
CI_WORKFLOW_PATH: Final = ROOT / ".github" / "workflows" / "ci.yml"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from witnessgap import identifiability as identifiability_module  # noqa: E402
from witnessgap import oracle as oracle_module  # noqa: E402
from witnessgap import verifier as verifier_module  # noqa: E402
from witnessgap.identifiability import (  # noqa: E402
    CandidateRegistry,
    UnknownReason,
    VerdictKind,
)
from witnessgap.workspace100 import baselines as baselines_module  # noqa: E402
from witnessgap.workspace100 import catalog as catalog_module  # noqa: E402
from witnessgap.workspace100 import evidence as evidence_module  # noqa: E402
from witnessgap.workspace100 import generation as generation_module  # noqa: E402
from witnessgap.workspace100 import release as release_module  # noqa: E402
from witnessgap.workspace100 import release_io as release_io_module  # noqa: E402
from witnessgap.workspace100 import views as views_module  # noqa: E402
from witnessgap.workspace100 import worker as worker_module  # noqa: E402
from witnessgap.workspace100.baselines import builtin_baseline_set  # noqa: E402
from witnessgap.workspace100.evidence import ParticipantClaim  # noqa: E402
from witnessgap.workspace100.generation import generate_workspace100  # noqa: E402
from witnessgap.workspace100.release import (  # noqa: E402
    GATE16_STATUS,
    RELEASE_DIRECTORY,
    RELEASE_DIRECTORY_MODE,
    RELEASE_FILE_MODE,
    RELEASE_KIND,
    RELEASE_MANIFEST_PATH,
    RELEASE_PAYLOAD_PATHS,
    Workspace100IsolationPolicy,
    Workspace100ReleaseBindings,
)
from witnessgap.workspace100.views import (  # noqa: E402
    ViewKind,
    build_workspace100_evidence_views,
)
from witnessgap.workspace100.worker import WorkerLimits  # noqa: E402
from witnessgap.worlds import workspace as workspace_module  # noqa: E402
from witnessgap.worlds.workspace import workspace_twins  # noqa: E402

_FORMAT: Final = "witnessgap.readme-visual-provenance.v1"
_RENDERER_VERSION: Final = 1
_EXPECTED_TEMPLATE_COUNT: Final = 5
_EXPECTED_VARIANTS_PER_TEMPLATE: Final = 10
_EXPECTED_VARIANT_COUNT: Final = 50
_EXPECTED_PAIR_COUNT: Final = 50
_EXPECTED_COMPLETION_COUNT: Final = 100
_EXPECTED_ASSIGNMENT_COUNT: Final = 400
_EXPECTED_CASE_COUNT: Final = 300
_EXPECTED_BASELINE_COUNT: Final = 4
_EXPECTED_RUN_COUNT: Final = 1_200
_EXPECTED_RELEASE_PAYLOAD_COUNT: Final = 13
_EXPECTED_RELEASE_BINDING_COUNT: Final = 25
_EXPECTED_CANDIDATE_FILE_COUNT: Final = 14
_EXPECTED_CANDIDATE_RUN_COUNT: Final = 1_200
_EXPECTED_BUILTIN_SCORE_COUNT: Final = 4
_TWO_COLUMN_BINDING_THRESHOLD: Final = 8
_VALIDATION_SEED: Final = hashlib.sha256(
    b"witnessgap.readme-visuals.workspace100-validation.v1"
).digest()

_BACKGROUND: Final = "#08111f"
_PANEL: Final = "#111f33"
_PANEL_ALT: Final = "#152842"
_BORDER: Final = "#2d4665"
_TEXT: Final = "#f4f7fb"
_MUTED: Final = "#afc2d8"
_ACCENT: Final = "#58d6c9"
_BLUE: Final = "#6eb7ff"
_GOLD: Final = "#ffd166"
_RED: Final = "#ff7b86"
_GREEN: Final = "#82e39c"
_PURPLE: Final = "#b8a1ff"


@dataclass(frozen=True, slots=True)
class Visual:
    """One generated SVG and its reviewable provenance."""

    filename: str
    title: str
    description: str
    source_modules: tuple[ModuleType, ...]
    nonclaims: tuple[str, ...]
    facts: Mapping[str, object]
    svg: bytes
    source_files: tuple[Path, ...] = ()


class Svg:
    """Tiny deterministic SVG writer with no external resources."""

    def __init__(self, width: int, height: int, *, title: str, description: str) -> None:
        self.width = width
        self.height = height
        self._body: list[str] = [
            (f'<rect x="0" y="0" width="{width}" height="{height}" fill="{_BACKGROUND}"/>')
        ]
        self._title = title
        self._description = description

    def rect(  # noqa: PLR0913
        self,
        x: int,
        y: int,
        width: int,
        height: int,
        *,
        fill: str = _PANEL,
        stroke: str = _BORDER,
        stroke_width: int = 2,
        radius: int = 18,
    ) -> None:
        self._body.append(
            f'<rect x="{x}" y="{y}" width="{width}" height="{height}" '
            f'rx="{radius}" fill="{fill}" stroke="{stroke}" '
            f'stroke-width="{stroke_width}"/>'
        )

    def line(  # noqa: PLR0913
        self,
        x1: int,
        y1: int,
        x2: int,
        y2: int,
        *,
        color: str = _BORDER,
        width: int = 3,
        dash: str | None = None,
    ) -> None:
        dash_attribute = f' stroke-dasharray="{dash}"' if dash is not None else ""
        self._body.append(
            f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" '
            f'stroke="{color}" stroke-width="{width}" '
            f'stroke-linecap="round"{dash_attribute}/>'
        )

    def arrow(  # noqa: PLR0913
        self,
        x1: int,
        y1: int,
        x2: int,
        y2: int,
        *,
        color: str = _ACCENT,
        width: int = 3,
    ) -> None:
        self.line(x1, y1, x2, y2, color=color, width=width)
        if abs(x2 - x1) >= abs(y2 - y1):
            direction = 1 if x2 >= x1 else -1
            points = (
                (x2, y2),
                (x2 - direction * 13, y2 - 8),
                (x2 - direction * 13, y2 + 8),
            )
        else:
            direction = 1 if y2 >= y1 else -1
            points = (
                (x2, y2),
                (x2 - 8, y2 - direction * 13),
                (x2 + 8, y2 - direction * 13),
            )
        encoded = " ".join(f"{x},{y}" for x, y in points)
        self._body.append(f'<polygon points="{encoded}" fill="{color}"/>')

    def text(  # noqa: PLR0913
        self,
        x: int,
        y: int,
        value: str,
        *,
        size: int = 22,
        color: str = _TEXT,
        weight: int = 400,
        anchor: str = "start",
        letter_spacing: int = 0,
    ) -> None:
        self._body.append(
            f'<text x="{x}" y="{y}" fill="{color}" font-family="monospace" '
            f'font-size="{size}" font-weight="{weight}" '
            f'text-anchor="{anchor}" letter-spacing="{letter_spacing}">'
            f"{escape(value)}</text>"
        )

    def multiline(  # noqa: PLR0913
        self,
        x: int,
        y: int,
        lines: Iterable[str],
        *,
        size: int = 20,
        color: str = _TEXT,
        weight: int = 400,
        line_height: int = 30,
        anchor: str = "start",
    ) -> None:
        for index, line in enumerate(lines):
            self.text(
                x,
                y + index * line_height,
                line,
                size=size,
                color=color,
                weight=weight,
                anchor=anchor,
            )

    def pill(  # noqa: PLR0913
        self,
        x: int,
        y: int,
        width: int,
        label: str,
        *,
        fill: str = _PANEL_ALT,
        stroke: str = _ACCENT,
        color: str = _TEXT,
    ) -> None:
        self.rect(
            x,
            y,
            width,
            42,
            fill=fill,
            stroke=stroke,
            stroke_width=2,
            radius=21,
        )
        self.text(
            x + width // 2,
            y + 28,
            label,
            size=16,
            color=color,
            weight=700,
            anchor="middle",
        )

    def header(self, eyebrow: str, title: str, subtitle: str) -> None:
        self.text(60, 52, eyebrow.upper(), size=15, color=_ACCENT, weight=700, letter_spacing=2)
        self.text(60, 98, title, size=34, weight=700)
        self.text(60, 132, subtitle, size=18, color=_MUTED)

    def footer(self, source: str, nonclaim: str) -> None:
        y = self.height - 86
        self.line(60, y, self.width - 60, y, color=_BORDER, width=2)
        self.pill(
            60,
            y + 18,
            170,
            "official: false",
            fill="#2b1d28",
            stroke=_RED,
            color="#ffd7db",
        )
        self.text(250, y + 34, f"source: {source}", size=14, color=_MUTED)
        self.text(250, y + 58, f"nonclaim: {nonclaim}", size=14, color=_MUTED)

    def render(self) -> bytes:
        title = escape(self._title)
        description = escape(self._description)
        body = "\n  ".join(self._body)
        encoded = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.width}" '
            f'height="{self.height}" viewBox="0 0 {self.width} {self.height}" '
            'role="img" aria-labelledby="visual-title visual-description">\n'
            f'  <title id="visual-title">{title}</title>\n'
            f'  <desc id="visual-description">{description}</desc>\n'
            f"  {body}\n"
            "</svg>\n"
        )
        return encoded.encode("utf-8")


def _module_path(module: ModuleType) -> Path:
    source = module.__file__
    if source is None:
        raise RuntimeError(f"production module {module.__name__} has no source file")
    path = Path(source).resolve()
    try:
        path.relative_to(ROOT)
    except ValueError as error:
        raise RuntimeError(f"production source escaped repository: {path}") from error
    return path


def _relative_module_path(module: ModuleType) -> str:
    return _module_path(module).relative_to(ROOT).as_posix()


def _source_path(path: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError as error:
        raise RuntimeError(f"visual source escaped repository: {resolved}") from error
    if not resolved.is_file():
        raise RuntimeError(f"visual source is not a regular file: {resolved}")
    return resolved


def _relative_source_path(path: Path) -> str:
    return _source_path(path).relative_to(ROOT).as_posix()


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _causal_twin_facts() -> dict[str, object]:
    worlds = workspace_twins()
    registry = CandidateRegistry.build(worlds)
    baseline = registry.observe(worlds[0].world_id)
    baseline_verdict = registry.attribute(baseline)
    if (
        baseline_verdict.kind is not VerdictKind.NOT_IDENTIFIABLE
        or baseline_verdict.unknown_reason is not UnknownReason.AMBIGUOUS_WORLDS
        or baseline_verdict.ambiguity is None
    ):
        raise RuntimeError("production causal twins no longer establish ambiguity")

    probe_names = registry.manifest.probe_names
    separating_probes = tuple(
        name
        for name in probe_names
        if len(
            {
                next(item.value for item in candidate.probe_observations if item.name == name)
                for candidate in registry.candidates
            }
        )
        > 1
    )
    if len(separating_probes) != 1:
        raise RuntimeError("smallest example must expose one separating probe")
    separating_probe = separating_probes[0]

    completions: list[dict[str, object]] = []
    for index, candidate in enumerate(registry.candidates, start=1):
        refined = registry.attribute(
            registry.observe(candidate.world_id, probes=(separating_probe,))
        )
        if (
            refined.kind is not VerdictKind.IDENTIFIED_SINGLETON
            or refined.target_family is None
            or len(candidate.panel.minimal_witnesses) != 1
        ):
            raise RuntimeError("separating probe no longer yields singleton attribution")
        completions.append(
            {
                "label": f"sealed completion {index}",
                "minimal_witness": candidate.panel.minimal_witnesses[0][0],
                "target": candidate.panel.target_family[0][0],
            }
        )

    return {
        "baseline_outcome": baseline.outcome.value,
        "compatible_completions": len(baseline_verdict.compatible_world_ids),
        "completions": completions,
        "intervention_receipts": len(baseline.intervention_observations),
        "probes": len(baseline.probes),
        "reason": baseline_verdict.unknown_reason.value,
        "separating_probe": separating_probe,
        "verdict": baseline_verdict.kind.value,
    }


def _render_causal_twins() -> Visual:
    facts = _causal_twin_facts()
    completions = cast(list[dict[str, object]], facts["completions"])
    first = dict(completions[0])
    second = dict(completions[1])
    title = "Causal twins: identical evidence, incompatible repairs"
    description = (
        "The production smallest example has one failed public trace compatible with two "
        "sealed completions. Their minimal repairs target different causes, so the verifier "
        "returns not_identifiable. One separating probe refines either completion to a "
        "singleton attribution."
    )
    svg = Svg(1440, 900, title=title, description=description)
    svg.header(
        "WitnessGap / finite-family attribution",
        "Same public failure. Different minimal causes.",
        "A point attribution is withheld until bounded evidence separates compatible worlds.",
    )

    svg.rect(60, 190, 325, 300, fill=_PANEL_ALT, stroke=_BLUE)
    svg.text(88, 230, "PUBLIC EVIDENCE", size=15, color=_BLUE, weight=700, letter_spacing=1)
    svg.text(88, 274, "byte-identical trace", size=23, weight=700)
    svg.multiline(
        88,
        318,
        (
            f"outcome: {facts['baseline_outcome']}",
            f"probes: {facts['probes']}",
            f"intervention receipts: {facts['intervention_receipts']}",
            f"compatible completions: {facts['compatible_completions']}",
        ),
        size=18,
        color=_MUTED,
        line_height=36,
    )

    completion_y = (170, 420)
    completion_colors = (_GOLD, _PURPLE)
    for item, y, color in zip(completions, completion_y, completion_colors, strict=True):
        values = dict(item)
        svg.rect(510, y, 380, 205, fill=_PANEL, stroke=color)
        svg.text(540, y + 38, str(values["label"]).upper(), size=14, color=color, weight=700)
        svg.text(540, y + 82, f"hidden target: {values['target']}", size=21, weight=700)
        svg.multiline(
            540,
            y + 122,
            (
                "minimal witness:",
                f"  {values['minimal_witness']}",
            ),
            size=16,
            color=_MUTED,
            line_height=28,
        )
    svg.arrow(385, 310, 510, 272, color=_GOLD)
    svg.arrow(385, 360, 510, 522, color=_PURPLE)

    svg.rect(1015, 278, 365, 235, fill="#261c2a", stroke=_RED)
    svg.text(1045, 320, "VERIFIER VERDICT", size=15, color=_RED, weight=700)
    svg.text(1045, 367, str(facts["verdict"]), size=25, weight=700)
    svg.text(1045, 408, f"reason: {facts['reason']}", size=17, color=_MUTED)
    svg.multiline(
        1045,
        451,
        ("No unique cause is licensed", "by the available evidence."),
        size=17,
        color=_TEXT,
        line_height=28,
    )
    svg.arrow(890, 272, 1015, 360, color=_GOLD)
    svg.arrow(890, 522, 1015, 430, color=_PURPLE)

    svg.rect(60, 650, 1320, 120, fill="#0e2630", stroke=_ACCENT)
    svg.text(90, 690, "REFINE WITH BOUNDED EVIDENCE", size=14, color=_ACCENT, weight=700)
    svg.text(
        90,
        731,
        f"add separating probe: {facts['separating_probe']}",
        size=19,
        weight=700,
    )
    svg.arrow(560, 718, 690, 718, color=_ACCENT)
    svg.pill(
        720,
        683,
        275,
        f"singleton: {first['target']}",
        fill="#163022",
        stroke=_GREEN,
    )
    svg.pill(
        1020,
        683,
        295,
        f"singleton: {second['target']}",
        fill="#211c37",
        stroke=_PURPLE,
    )
    svg.footer(
        "identifiability.py · oracle.py · verifier.py · worlds/workspace.py",
        "valid only for the declared finite completion family; not production causality",
    )
    return Visual(
        filename="causal-twins-flow.svg",
        title=title,
        description=description,
        source_modules=(
            identifiability_module,
            oracle_module,
            verifier_module,
            workspace_module,
        ),
        nonclaims=(
            "Finite committed completion family only.",
            "No claim that the family exhausts production failure mechanisms.",
            "Content digests are not signatures or runtime attestations.",
        ),
        facts=facts,
        svg=svg.render(),
    )


_VERDICT_DESCRIPTIONS: Final[Mapping[VerdictKind, tuple[str, str]]] = {
    VerdictKind.IDENTIFIED_SINGLETON: (
        "one target",
        "shared by every compatible minimal repair",
    ),
    VerdictKind.IDENTIFIED_COMPOUND: (
        "one irreducible set",
        "multiple targets are jointly required",
    ),
    VerdictKind.ALTERNATIVE_MINIMAL_REPAIRS: (
        "multiple alternatives",
        "incomparable minimal repairs remain",
    ),
    VerdictKind.EFFECT_ONLY: (
        "effect observed",
        "outcome changed without localizing origin",
    ),
    VerdictKind.NOT_IDENTIFIABLE: (
        "withhold attribution",
        "available evidence cannot license a point cause",
    ),
}


def _workspace100_claim_kinds() -> tuple[VerdictKind, ...]:
    accepted: list[VerdictKind] = []
    for kind in VerdictKind:
        try:
            if kind is VerdictKind.IDENTIFIED_SINGLETON:
                claim = ParticipantClaim(
                    kind=kind,
                    target_family=(("environment",),),
                    minimal_witnesses=(("refresh_example",),),
                )
            elif kind is VerdictKind.NOT_IDENTIFIABLE:
                claim = ParticipantClaim(
                    kind=kind,
                    unknown_reason=UnknownReason.AMBIGUOUS_WORLDS,
                )
            else:
                claim = ParticipantClaim(kind=kind)
        except (TypeError, ValueError):
            continue
        claim.validate()
        accepted.append(kind)
    expected = (
        VerdictKind.IDENTIFIED_SINGLETON,
        VerdictKind.NOT_IDENTIFIABLE,
    )
    if tuple(accepted) != expected:
        raise RuntimeError("Workspace-100 participant verdict subset changed")
    return tuple(accepted)


def _render_verdict_taxonomy() -> Visual:
    verdicts = tuple(VerdictKind)
    if set(_VERDICT_DESCRIPTIONS) != set(verdicts):
        raise RuntimeError("verdict description map is stale")
    workspace100_kinds = _workspace100_claim_kinds()
    title = "WitnessGap verdict taxonomy"
    description = (
        "All five verdict forms from the production VerdictKind enum. The Workspace-100 v1 "
        "participant claim schema admits only identified_singleton and not_identifiable; "
        "the other verdicts belong to the wider WitnessGap contract."
    )
    svg = Svg(1440, 920, title=title, description=description)
    svg.header(
        "WitnessGap / closed verdict union",
        "Five ways to state what the evidence licenses",
        "The taxonomy separates positive certificates, effect-only evidence, and abstention.",
    )

    card_width = 410
    card_height = 176
    positions = (
        (60, 185),
        (515, 185),
        (970, 185),
        (285, 410),
        (745, 410),
    )
    colors = (_GREEN, _BLUE, _PURPLE, _GOLD, _RED)
    for verdict, (x, y), color in zip(verdicts, positions, colors, strict=True):
        heading, explanation = _VERDICT_DESCRIPTIONS[verdict]
        svg.rect(x, y, card_width, card_height, fill=_PANEL, stroke=color)
        svg.text(x + 24, y + 38, verdict.value, size=18, color=color, weight=700)
        svg.text(x + 24, y + 82, heading, size=22, weight=700)
        svg.multiline(
            x + 24,
            y + 119,
            _wrap_words(explanation, 38),
            size=16,
            color=_MUTED,
            line_height=25,
        )

    svg.rect(60, 650, 1320, 150, fill="#0e2630", stroke=_ACCENT)
    svg.text(
        88,
        690,
        "WORKSPACE-100 v1 PARTICIPANT CLAIM SCHEMA",
        size=15,
        color=_ACCENT,
        weight=700,
    )
    svg.text(
        88,
        729,
        "Deliberately narrower than the general verifier",
        size=20,
        weight=700,
    )
    svg.pill(690, 690, 310, workspace100_kinds[0].value, fill="#163022", stroke=_GREEN)
    svg.pill(1020, 690, 300, workspace100_kinds[1].value, fill="#2b1d28", stroke=_RED)
    svg.text(
        88,
        770,
        "compound · alternative repairs · effect_only are outside the frozen v1 claim wire",
        size=15,
        color=_MUTED,
    )
    svg.footer(
        "identifiability.VerdictKind · workspace100.evidence.ParticipantClaim",
        "taxonomy breadth is not Workspace-100 v1 case coverage or a benchmark result",
    )
    return Visual(
        filename="verdict-taxonomy.svg",
        title=title,
        description=description,
        source_modules=(identifiability_module, evidence_module),
        nonclaims=(
            "Workspace-100 v1 does not exercise every general WitnessGap verdict.",
            "The taxonomy is a protocol contract, not a performance result.",
        ),
        facts={
            "all_verdicts": [kind.value for kind in verdicts],
            "workspace100_v1_claim_kinds": [kind.value for kind in workspace100_kinds],
        },
        svg=svg.render(),
    )


def _wrap_words(value: str, width: int) -> tuple[str, ...]:
    words = value.split()
    lines: list[str] = []
    current: list[str] = []
    for word in words:
        candidate = " ".join((*current, word))
        if current and len(candidate) > width:
            lines.append(" ".join(current))
            current = [word]
        else:
            current.append(word)
    if current:
        lines.append(" ".join(current))
    return tuple(lines)


@dataclass(frozen=True, slots=True)
class EvidenceViewFact:
    """One observed production view shape and denominator."""

    kind: ViewKind
    case_count: int
    probe_counts: tuple[int, ...]
    probe_names: tuple[str, ...]
    intervention_counts: tuple[int, ...]
    intervention_atoms: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Workspace100Snapshot:
    """Cardinalities and wire shapes rebuilt by production constructors."""

    template_ids: tuple[str, ...]
    variant_count: int
    variants_per_template: int
    pair_count: int
    completion_count: int
    assignment_count: int
    case_count: int
    baseline_ids: tuple[str, ...]
    method_case_runs: int
    views: tuple[EvidenceViewFact, ...]


@lru_cache(maxsize=1)
def _workspace100_snapshot() -> Workspace100Snapshot:
    corpus = generate_workspace100(_VALIDATION_SEED)
    projected = build_workspace100_evidence_views(corpus)
    baselines = builtin_baseline_set()

    template_ids = tuple(template.template_id.value for template in corpus.templates)
    variant_counts = Counter(variant.template_id.value for variant in corpus.variants)
    if set(variant_counts) != set(template_ids) or len(set(variant_counts.values())) != 1:
        raise RuntimeError("Workspace-100 variants are no longer balanced by template")
    variants_per_template = next(iter(variant_counts.values()))

    view_facts: list[EvidenceViewFact] = []
    for view in ViewKind:
        cases = tuple(case for case in projected.cases if case.view is view)
        if not cases:
            raise RuntimeError(f"Workspace-100 view {view.value} has no cases")
        if any(
            not case.envelope.evidence.public_trace
            or case.envelope.evidence.outcome.value != "failure"
            for case in cases
        ):
            raise RuntimeError("every Workspace-100 view must retain the failed baseline")
        view_facts.append(
            EvidenceViewFact(
                kind=view,
                case_count=len(cases),
                probe_counts=tuple(sorted({len(case.envelope.evidence.probes) for case in cases})),
                probe_names=tuple(
                    sorted(
                        {probe.name for case in cases for probe in case.envelope.evidence.probes}
                    )
                ),
                intervention_counts=tuple(
                    sorted(
                        {len(case.envelope.evidence.intervention_observations) for case in cases}
                    )
                ),
                intervention_atoms=tuple(
                    sorted(
                        {
                            atom
                            for case in cases
                            for observation in (case.envelope.evidence.intervention_observations)
                            for atom in observation.interventions
                        }
                    )
                ),
            )
        )

    baseline_ids = tuple(artifact.bundle.baseline.value for artifact in baselines.bundles)
    snapshot = Workspace100Snapshot(
        template_ids=template_ids,
        variant_count=len(corpus.variants),
        variants_per_template=variants_per_template,
        pair_count=len(corpus.pairs),
        completion_count=len(corpus.completions),
        assignment_count=projected.assignment_count,
        case_count=projected.case_count,
        baseline_ids=baseline_ids,
        method_case_runs=len(baselines.bundles) * projected.case_count,
        views=tuple(view_facts),
    )
    _validate_workspace100_snapshot(snapshot)
    return snapshot


def _validate_workspace100_snapshot(snapshot: Workspace100Snapshot) -> None:
    expected_view_counts = {
        ViewKind.TRACE_ONLY: 50,
        ViewKind.OWNER_PROBE: 50,
        ViewKind.EPOCH_PROBE: 100,
        ViewKind.REFRESH_RECEIPT: 100,
    }
    actual_view_counts = {view.kind: view.case_count for view in snapshot.views}
    if (
        len(snapshot.template_ids) != _EXPECTED_TEMPLATE_COUNT
        or snapshot.variants_per_template != _EXPECTED_VARIANTS_PER_TEMPLATE
        or snapshot.variant_count != _EXPECTED_VARIANT_COUNT
        or snapshot.pair_count != _EXPECTED_PAIR_COUNT
        or snapshot.completion_count != _EXPECTED_COMPLETION_COUNT
        or snapshot.assignment_count != _EXPECTED_ASSIGNMENT_COUNT
        or snapshot.case_count != _EXPECTED_CASE_COUNT
        or len(snapshot.baseline_ids) != _EXPECTED_BASELINE_COUNT
        or snapshot.method_case_runs != _EXPECTED_RUN_COUNT
        or actual_view_counts != expected_view_counts
    ):
        raise RuntimeError("Workspace-100 frozen cardinalities changed; review the visuals")

    by_kind = {view.kind: view for view in snapshot.views}
    trace = by_kind[ViewKind.TRACE_ONLY]
    owner = by_kind[ViewKind.OWNER_PROBE]
    epoch = by_kind[ViewKind.EPOCH_PROBE]
    refresh = by_kind[ViewKind.REFRESH_RECEIPT]
    if (
        trace.probe_counts != (0,)
        or trace.intervention_counts != (0,)
        or owner.probe_counts != (1,)
        or owner.probe_names != ("workspace_owner",)
        or owner.intervention_counts != (0,)
        or epoch.probe_counts != (1,)
        or len(epoch.probe_names) != len(snapshot.template_ids)
        or epoch.intervention_counts != (0,)
        or refresh.probe_counts != (0,)
        or refresh.intervention_counts != (1,)
        or len(refresh.intervention_atoms) != len(snapshot.template_ids)
    ):
        raise RuntimeError("Workspace-100 evidence view wire shapes changed")


def _snapshot_facts(snapshot: Workspace100Snapshot) -> dict[str, object]:
    return {
        "assignments": snapshot.assignment_count,
        "baseline_ids": list(snapshot.baseline_ids),
        "completions": snapshot.completion_count,
        "method_case_runs": snapshot.method_case_runs,
        "pairs": snapshot.pair_count,
        "public_cases": snapshot.case_count,
        "template_ids": list(snapshot.template_ids),
        "templates": len(snapshot.template_ids),
        "variants": snapshot.variant_count,
        "variants_per_template": snapshot.variants_per_template,
        "views": {
            view.kind.value: {
                "cases": view.case_count,
                "intervention_atoms": list(view.intervention_atoms),
                "intervention_counts": list(view.intervention_counts),
                "probe_counts": list(view.probe_counts),
                "probe_names": list(view.probe_names),
            }
            for view in snapshot.views
        },
    }


def _render_workspace100_funnel() -> Visual:
    snapshot = _workspace100_snapshot()
    title = "Workspace-100 construction funnel"
    description = (
        "Production constructors rebuild five templates, fifty variants and causal-twin "
        "pairs, one hundred completions, four hundred private evidence assignments, three "
        "hundred unique participant cases, and twelve hundred frozen baseline method-case "
        "runs."
    )
    svg = Svg(1440, 930, title=title, description=description)
    svg.header(
        "Workspace-100 / frozen protocol cardinalities",
        "From authored templates to 1,200 method-case runs",
        "Every number below is rebuilt from production corpus, projection, and baseline objects.",
    )

    nodes = (
        (
            60,
            190,
            f"{len(snapshot.template_ids)}",
            "templates",
            f"x {snapshot.variants_per_template} authored variants",
            _BLUE,
        ),
        (
            510,
            190,
            f"{snapshot.variant_count}",
            "variants = twin pairs",
            "one pair per authored variant",
            _PURPLE,
        ),
        (
            960,
            190,
            f"{snapshot.completion_count}",
            "sealed completions",
            "2 incompatible completions / pair",
            _GOLD,
        ),
        (
            60,
            505,
            f"{snapshot.assignment_count}",
            "private assignments",
            "100 episodes x 4 evidence views",
            _BLUE,
        ),
        (
            510,
            505,
            f"{snapshot.case_count}",
            "unique public cases",
            "deduplicated by complete evidence",
            _ACCENT,
        ),
        (
            960,
            505,
            f"{snapshot.method_case_runs:,}",
            "method-case runs",
            f"{len(snapshot.baseline_ids)} frozen methods x {snapshot.case_count}",
            _GREEN,
        ),
    )
    for x, y, number, label, detail, color in nodes:
        svg.rect(x, y, 420, 190, fill=_PANEL, stroke=color)
        svg.text(x + 28, y + 68, number, size=42, color=color, weight=700)
        svg.text(x + 28, y + 108, label, size=21, weight=700)
        svg.text(x + 28, y + 148, detail, size=15, color=_MUTED)
    svg.arrow(480, 285, 510, 285, color=_PURPLE)
    svg.text(
        495,
        260,
        f"x{snapshot.variants_per_template}",
        size=14,
        color=_MUTED,
        anchor="middle",
    )
    svg.arrow(930, 285, 960, 285, color=_GOLD)
    svg.text(945, 260, "x2", size=14, color=_MUTED, anchor="middle")
    svg.arrow(1170, 380, 270, 505, color=_BLUE)
    svg.text(
        720,
        435,
        "x4 views per completion",
        size=15,
        color=_MUTED,
        anchor="middle",
    )
    svg.arrow(480, 600, 510, 600, color=_ACCENT)
    svg.text(495, 576, "dedupe", size=13, color=_MUTED, anchor="middle")
    svg.arrow(930, 600, 960, 600, color=_GREEN)
    svg.text(945, 576, "x4", size=14, color=_MUTED, anchor="middle")

    svg.rect(60, 735, 1320, 80, fill="#0e2630", stroke=_ACCENT)
    svg.text(90, 769, "FROZEN BASELINES", size=13, color=_ACCENT, weight=700)
    svg.text(
        90,
        799,
        " · ".join(snapshot.baseline_ids),
        size=15,
        color=_TEXT,
    )
    svg.footer(
        "workspace100.catalog · generation · views · baselines",
        "construction cardinalities only; not a public release or a performance result",
    )
    return Visual(
        filename="workspace100-funnel.svg",
        title=title,
        description=description,
        source_modules=(
            catalog_module,
            generation_module,
            views_module,
            baselines_module,
        ),
        nonclaims=(
            "Frozen synthetic protocol cardinalities, not statistical sample sizes.",
            "No public benchmark release or method performance is asserted.",
            "The 400 evidence assignments are distinct from 400 verifier receipts.",
        ),
        facts=_snapshot_facts(snapshot),
        svg=svg.render(),
    )


def _view_exposure(view: EvidenceViewFact) -> tuple[str, str]:
    if view.kind is ViewKind.TRACE_ONLY:
        return ("no added observation", "baseline public_trace + outcome")
    if view.kind is ViewKind.OWNER_PROBE:
        return ("+ neutral control probe", view.probe_names[0])
    if view.kind is ViewKind.EPOCH_PROBE:
        return ("+ 1 template epoch probe", f"{len(view.probe_names)} exact names across templates")
    if view.kind is ViewKind.REFRESH_RECEIPT:
        return (
            "+ 1 refresh receipt",
            "interventions + public_trace + outcome",
        )
    raise RuntimeError("unsupported production evidence view")


def _render_evidence_views() -> Visual:
    snapshot = _workspace100_snapshot()
    title = "Workspace-100 participant evidence views"
    description = (
        "Four production evidence views always expose the failed baseline trace and outcome. "
        "Trace-only and owner-probe deduplicate to fifty cases each; epoch-probe and "
        "refresh-receipt remain completion-specific at one hundred each."
    )
    svg = Svg(1440, 930, title=title, description=description)
    svg.header(
        "Workspace-100 / participant wire",
        "Four evidence views, one deliberately narrow envelope",
        (
            "Always present: baseline public_trace + failure outcome. "
            "Private routing stays parent-side."
        ),
    )

    x_positions = (60, 400, 740, 1080)
    colors = (_BLUE, _PURPLE, _GOLD, _ACCENT)
    for view, x, color in zip(snapshot.views, x_positions, colors, strict=True):
        headline, detail = _view_exposure(view)
        svg.rect(x, 205, 300, 430, fill=_PANEL, stroke=color)
        svg.text(x + 24, 246, view.kind.value, size=18, color=color, weight=700)
        svg.text(x + 24, 315, str(view.case_count), size=44, color=_TEXT, weight=700)
        svg.text(x + 24, 346, "unique public cases", size=15, color=_MUTED)
        svg.line(x + 24, 375, x + 276, 375, color=_BORDER, width=2)
        svg.multiline(
            x + 24,
            414,
            _wrap_words(headline, 27),
            size=18,
            weight=700,
            line_height=28,
        )
        svg.multiline(
            x + 24,
            486,
            _wrap_words(detail, 29),
            size=15,
            color=_MUTED,
            line_height=24,
        )
        if view.kind in {ViewKind.TRACE_ONLY, ViewKind.OWNER_PROBE}:
            svg.pill(
                x + 24,
                562,
                250,
                "pair-grain dedupe",
                fill="#18243b",
                stroke=_BLUE,
            )
        else:
            svg.pill(
                x + 24,
                562,
                250,
                "completion-specific",
                fill="#22223b",
                stroke=_PURPLE,
            )

    svg.rect(60, 680, 1320, 135, fill="#0e2630", stroke=_ACCENT)
    svg.text(88, 719, "NOT ON THE WORKER WIRE", size=14, color=_ACCENT, weight=700)
    svg.multiline(
        88,
        754,
        (
            "view · split · template_id · episode_id · pair_id · evidence_digest",
            "completion commitment · source snapshot · target label · canonical position",
        ),
        size=16,
        color=_TEXT,
        line_height=30,
    )
    svg.footer(
        "workspace100.views.ViewKind · _project_evidence · PublicEvidenceEnvelope",
        "owner_probe is a neutral control; view counts are construction invariants, not results",
    )
    return Visual(
        filename="evidence-views.svg",
        title=title,
        description=description,
        source_modules=(views_module, evidence_module, generation_module),
        nonclaims=(
            "The owner probe is deliberately non-localizing.",
            "Case denominators are construction invariants, not measured performance.",
            "Private routing and truth labels are not participant-visible.",
        ),
        facts={
            "always_exposed": ["public_trace", "outcome"],
            "assignments": snapshot.assignment_count,
            "public_cases": snapshot.case_count,
            "views": _snapshot_facts(snapshot)["views"],
        },
        svg=svg.render(),
    )


def _release_tree_facts() -> dict[str, object]:
    payloads = tuple(RELEASE_PAYLOAD_PATHS)
    if len(payloads) != _EXPECTED_RELEASE_PAYLOAD_COUNT or len(set(payloads)) != len(payloads):
        raise RuntimeError("Workspace-100 release payload allowlist changed")
    if RELEASE_MANIFEST_PATH in payloads:
        raise RuntimeError("self-referential release manifest entered payload allowlist")
    policy = Workspace100IsolationPolicy()
    if (
        RELEASE_KIND != "pre_release_reproducibility_candidate"
        or GATE16_STATUS != "not_established"
        or policy.hostile_code_containment != GATE16_STATUS
    ):
        raise RuntimeError("release candidate or gate-16 status changed")
    return {
        "directory": RELEASE_DIRECTORY,
        "directory_mode": f"{RELEASE_DIRECTORY_MODE:04o}",
        "file_mode": f"{RELEASE_FILE_MODE:04o}",
        "gate16_status": GATE16_STATUS,
        "manifest": RELEASE_MANIFEST_PATH,
        "payload_count": len(payloads),
        "payloads": list(payloads),
        "physical_file_count": len(payloads) + 1,
        "release_kind": RELEASE_KIND,
    }


def _render_release_tree() -> Visual:
    facts = _release_tree_facts()
    payloads = tuple(RELEASE_PAYLOAD_PATHS)
    title = "Workspace-100 pre-release candidate tree"
    description = (
        "The production release allowlist contains thirteen payload files plus one "
        "release-manifest file below workspace100/v1. Materialized files are mode 0444, "
        "directories are 0555, the release kind is pre-release reproducibility candidate, "
        "and hostile-code containment is not established."
    )
    svg = Svg(1440, 1200, title=title, description=description)
    svg.header(
        "Workspace-100 / deterministic release layout",
        "13 payloads + 1 manifest, in canonical order",
        "The builder and materializer exist; this diagram does not claim a published release.",
    )

    svg.rect(60, 175, 875, 900, fill=_PANEL, stroke=_BLUE)
    svg.text(92, 216, f"{RELEASE_DIRECTORY}/", size=21, color=_BLUE, weight=700)
    svg.pill(725, 190, 170, f"dirs {RELEASE_DIRECTORY_MODE:04o}", stroke=_BLUE)
    y = 258
    previous_group = ""
    for index, path in enumerate(payloads, start=1):
        group = path.split("/", maxsplit=1)[0] if "/" in path else "root"
        if group != previous_group:
            if previous_group:
                y += 10
            svg.text(94, y, group.upper(), size=12, color=_ACCENT, weight=700, letter_spacing=1)
            y += 25
            previous_group = group
        svg.text(112, y, f"{index:02d}", size=13, color=_MUTED)
        svg.text(150, y, path, size=15, color=_TEXT)
        svg.text(865, y, f"{RELEASE_FILE_MODE:04o}", size=13, color=_MUTED, anchor="end")
        y += 29
    y += 9
    svg.line(94, y, 900, y, color=_BORDER, width=2)
    svg.text(112, y + 35, "14", size=13, color=_GOLD)
    svg.text(150, y + 35, RELEASE_MANIFEST_PATH, size=15, color=_GOLD, weight=700)
    svg.text(865, y + 35, f"{RELEASE_FILE_MODE:04o}", size=13, color=_MUTED, anchor="end")

    svg.rect(985, 175, 395, 220, fill="#211c37", stroke=_PURPLE)
    svg.text(1015, 216, "RELEASE KIND", size=13, color=_PURPLE, weight=700)
    svg.multiline(
        1015,
        260,
        _wrap_words(RELEASE_KIND, 30),
        size=19,
        weight=700,
        line_height=30,
    )
    svg.text(1015, 350, "frozen reviewed built-ins only", size=14, color=_MUTED)

    svg.rect(985, 430, 395, 210, fill="#2b1d28", stroke=_RED)
    svg.text(1015, 471, "RELEASE GATE 16", size=13, color=_RED, weight=700)
    svg.text(1015, 520, GATE16_STATUS, size=24, color=_TEXT, weight=700)
    svg.multiline(
        1015,
        562,
        ("hostile participant-code", "containment is not established"),
        size=16,
        color=_MUTED,
        line_height=27,
    )

    svg.rect(985, 675, 395, 280, fill="#0e2630", stroke=_ACCENT)
    svg.text(1015, 716, "WHAT MODES DO — AND DO NOT — MEAN", size=12, color=_ACCENT, weight=700)
    svg.multiline(
        1015,
        756,
        (
            f"files {RELEASE_FILE_MODE:04o}: read-only",
            f"directories {RELEASE_DIRECTORY_MODE:04o}: read + traverse",
            "",
            "storage hygiene only",
            "not cryptographic immutability",
            "not a signature or attestation",
        ),
        size=15,
        color=_TEXT,
        line_height=30,
    )
    svg.footer(
        "workspace100.release.RELEASE_PAYLOAD_PATHS · release_io materializer",
        "candidate schema/materialization capability; no authenticated public release",
    )
    return Visual(
        filename="release-tree.svg",
        title=title,
        description=description,
        source_modules=(release_module, release_io_module),
        nonclaims=(
            "The tree is a pre-release reproducibility candidate, not a published release.",
            "POSIX modes are storage hygiene, not cryptographic immutability.",
            "The manifest is not a signature, runtime attestation, or isolation proof.",
        ),
        facts=facts,
        svg=svg.render(),
    )


def _release_binding_groups() -> dict[str, tuple[str, ...]]:
    names = tuple(field.name for field in fields(Workspace100ReleaseBindings))
    execution = {
        "backend_implementation_digest",
        "runtime_root",
        "limits_root",
        "isolation_policy_root",
    }
    external = {"trust_anchor_root"}
    implementation = {
        name for name in names if name.endswith("_implementation_digest") and name not in execution
    }
    content = set(names) - execution - external - implementation
    groups = {
        "content_roots": tuple(name for name in names if name in content),
        "implementation_identities": tuple(name for name in names if name in implementation),
        "execution_configuration": tuple(name for name in names if name in execution),
        "external_anchor_set": tuple(name for name in names if name in external),
    }
    flattened = tuple(name for group in groups.values() for name in group)
    if (
        len(names) != _EXPECTED_RELEASE_BINDING_COUNT
        or len(flattened) != _EXPECTED_RELEASE_BINDING_COUNT
        or set(flattened) != set(names)
        or len(set(flattened)) != _EXPECTED_RELEASE_BINDING_COUNT
    ):
        raise RuntimeError("Workspace100ReleaseBindings grouping is stale")
    return groups


def _render_release_bindings() -> Visual:
    groups = _release_binding_groups()
    binding_names = tuple(field.name for field in fields(Workspace100ReleaseBindings))
    title = "Workspace-100 release binding closure"
    description = (
        "All twenty-five fields of the production Workspace100ReleaseBindings dataclass are "
        "grouped into content roots, implementation identities, execution configuration, "
        "and an externally supplied trust-anchor set. File descriptors form an artifact tree "
        "root; the manifest payload forms a release root that must match an independently "
        "obtained expected root."
    )
    svg = Svg(1440, 1180, title=title, description=description)
    svg.header(
        "Workspace-100 / integrity closure",
        "25 direct bindings close over data, code, execution, and anchors",
        (
            "Authentication still begins outside the candidate: "
            "the expected release root is independent."
        ),
    )

    cards = (
        ("CONTENT ROOTS · 14", groups["content_roots"], 60, 180, 620, 415, _BLUE),
        (
            "IMPLEMENTATION IDENTITIES · 6",
            groups["implementation_identities"],
            720,
            180,
            660,
            260,
            _PURPLE,
        ),
        (
            "EXECUTION CONFIGURATION · 4",
            groups["execution_configuration"],
            720,
            470,
            660,
            190,
            _GOLD,
        ),
        (
            "EXTERNAL ANCHOR SET · 1",
            groups["external_anchor_set"],
            720,
            690,
            660,
            105,
            _ACCENT,
        ),
    )
    for heading, names, x, y, width, height, color in cards:
        svg.rect(x, y, width, height, fill=_PANEL, stroke=color)
        svg.text(x + 24, y + 35, heading, size=13, color=color, weight=700, letter_spacing=1)
        if len(names) > _TWO_COLUMN_BINDING_THRESHOLD:
            left = names[:7]
            right = names[7:]
            svg.multiline(x + 24, y + 78, left, size=14, color=_TEXT, line_height=37)
            svg.multiline(x + width // 2, y + 78, right, size=14, color=_TEXT, line_height=37)
        else:
            svg.multiline(x + 24, y + 76, names, size=14, color=_TEXT, line_height=32)

    svg.rect(60, 635, 620, 140, fill="#0e2630", stroke=_ACCENT)
    svg.text(84, 672, "MANIFEST-LEVEL INPUTS OUTSIDE THE 25", size=13, color=_ACCENT, weight=700)
    svg.multiline(
        84,
        710,
        (
            "generation_provenance_root",
            "13 x file(path, length, mode, content_digest, semantic_root)",
        ),
        size=14,
        color=_TEXT,
        line_height=30,
    )

    svg.rect(60, 830, 350, 115, fill=_PANEL_ALT, stroke=_BLUE)
    svg.text(235, 870, "artifact_tree_root", size=18, color=_BLUE, weight=700, anchor="middle")
    svg.text(235, 906, "exact file descriptors", size=14, color=_MUTED, anchor="middle")
    svg.arrow(410, 887, 515, 887, color=_BLUE)
    svg.rect(515, 810, 390, 155, fill=_PANEL_ALT, stroke=_PURPLE)
    svg.text(710, 854, "manifest root payload", size=18, color=_PURPLE, weight=700, anchor="middle")
    svg.multiline(
        710,
        890,
        ("25 bindings + execution config", "+ provenance + file inventory"),
        size=13,
        color=_MUTED,
        line_height=25,
        anchor="middle",
    )
    svg.arrow(905, 887, 1005, 887, color=_PURPLE)
    svg.rect(1005, 830, 375, 115, fill="#163022", stroke=_GREEN)
    svg.text(1192, 870, "release_root", size=21, color=_GREEN, weight=700, anchor="middle")
    svg.text(1192, 906, "deterministic integrity identity", size=13, color=_MUTED, anchor="middle")
    svg.arrow(1192, 965, 1192, 1005, color=_RED)
    svg.pill(
        985,
        1008,
        415,
        "independently expected release_root",
        fill="#2b1d28",
        stroke=_RED,
    )
    svg.footer(
        "dataclasses.fields(Workspace100ReleaseBindings) · Workspace100ReleaseManifest",
        "SHA-256 integrity closure is not authenticity, signature, or execution attestation",
    )
    return Visual(
        filename="release-binding-closure.svg",
        title=title,
        description=description,
        source_modules=(release_module,),
        nonclaims=(
            "Bindings and hashes provide deterministic integrity, not authenticity.",
            "The expected release root must arrive through an independent authenticated channel.",
            "No release root shown here is a published Workspace-100 release identity.",
        ),
        facts={
            "binding_count": len(binding_names),
            "binding_order": list(binding_names),
            "groups": {name: list(values) for name, values in groups.items()},
            "manifest_extra_inputs": [
                "generation_provenance_root",
                "13 exact file descriptors",
                "execution_configuration",
            ],
            "verification_input": "independently authenticated expected_release_root",
        },
        svg=svg.render(),
    )


def _worker_source_facts() -> dict[str, object]:
    source = _module_path(worker_module).read_text(encoding="utf-8")
    tree = ast.parse(source)
    local_backend = next(
        (
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "LocalPythonProcessBackend"
        ),
        None,
    )
    if local_backend is None:
        raise RuntimeError("LocalPythonProcessBackend source is missing")

    environment_keys: tuple[str, ...] | None = None
    launcher: tuple[str, ...] | None = None
    popen_keywords: dict[str, object] = {}
    for node in ast.walk(local_backend):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "environment"
            and isinstance(node.value, ast.Dict)
        ):
            keys = tuple(
                key.value
                for key in node.value.keys
                if isinstance(key, ast.Constant) and isinstance(key.value, str)
            )
            environment_keys = keys
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "Popen"
        ):
            if node.args and isinstance(node.args[0], ast.Tuple):
                launcher = tuple(
                    element.value
                    for element in node.args[0].elts
                    if isinstance(element, ast.Constant) and isinstance(element.value, str)
                )
            for keyword in node.keywords:
                if keyword.arg is not None and isinstance(keyword.value, ast.Constant):
                    popen_keywords[keyword.arg] = keyword.value.value

    expected_environment = (
        "HOME",
        "LANG",
        "LC_ALL",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONHASHSEED",
        "PYTHONNOUSERSITE",
        "PYTHONUNBUFFERED",
        "TMPDIR",
        "TZ",
    )
    expected_launcher = ("-s", "-S", "-B", "-P", "participant.py")
    if (
        environment_keys != expected_environment
        or launcher != expected_launcher
        or popen_keywords.get("shell") is not False
        or popen_keywords.get("close_fds") is not True
        or popen_keywords.get("start_new_session") is not True
        or "TemporaryDirectory" not in source
        or "workdir.chmod(0o700)" not in source
        or "entrypoint.chmod(0o400)" not in source
        or "os.killpg" not in source
    ):
        raise RuntimeError("local worker lifecycle source changed; review isolation visual")

    limits = WorkerLimits()
    policy = Workspace100IsolationPolicy()
    return {
        "environment_keys": list(environment_keys),
        "launcher_flags": list(launcher[:-1]),
        "participant_script": launcher[-1],
        "popen": {
            "close_fds": popen_keywords["close_fds"],
            "shell": popen_keywords["shell"],
            "start_new_session": popen_keywords["start_new_session"],
        },
        "scratch_directory_mode": "0700",
        "script_mode": "0400",
        "limits": {
            "stderr_bytes": limits.stderr_bytes,
            "stdout_bytes": limits.stdout_bytes,
            "timeout_ms": limits.timeout_ms,
        },
        "policy": policy.to_payload(),
    }


def _render_isolation_boundary() -> Visual:
    facts = _worker_source_facts()
    policy = Workspace100IsolationPolicy()
    limits = cast(dict[str, int], facts["limits"])
    title = "Workspace-100 worker lifecycle boundary"
    description = (
        "The production local backend stages one reviewed Python program in a fresh private "
        "directory, launches a new process session with a closed environment and bounded "
        "pipes, parses one claim, and performs process-group cleanup. The exact release "
        "policy still records host UID filesystem access, unenforced network isolation, and "
        "hostile-code containment not established."
    )
    svg = Svg(1440, 1020, title=title, description=description)
    svg.header(
        "Workspace-100 / trusted built-ins only",
        "Fresh process lifecycle ≠ hostile-code sandbox",
        (
            "Implemented controls reduce accidental coupling; "
            "the release policy states the remaining boundary."
        ),
    )

    svg.rect(60, 185, 350, 425, fill=_PANEL, stroke=_BLUE)
    svg.text(88, 226, "TRUSTED PARENT", size=14, color=_BLUE, weight=700)
    svg.multiline(
        88,
        275,
        (
            "1 canonical evidence envelope",
            "↓ bounded stdin",
            "",
            "monotonic deadline",
            f"timeout  {limits['timeout_ms']:,} ms",
            f"stdout   {limits['stdout_bytes']:,} bytes",
            f"stderr   {limits['stderr_bytes']:,} bytes",
            "",
            "1 closed claim parser",
            "normalized WorkerRunRecord",
        ),
        size=16,
        color=_TEXT,
        line_height=31,
    )

    svg.rect(465, 185, 480, 425, fill="#0e2630", stroke=_ACCENT)
    svg.text(493, 226, "IMPLEMENTED PROCESS LIFECYCLE", size=14, color=_ACCENT, weight=700)
    svg.multiline(
        493,
        270,
        (
            "fresh TemporaryDirectory · mode 0700",
            "participant.py · mode 0400",
            "Python flags: -s -S -B -P",
            "shell=False · close_fds=True",
            "new process session",
            "closed 9-key child environment",
            "fresh cwd = HOME = TMPDIR",
            "bounded nonblocking pipes",
            "process-group termination + reap",
        ),
        size=16,
        color=_TEXT,
        line_height=35,
    )
    svg.arrow(410, 390, 465, 390, color=_ACCENT)
    svg.arrow(945, 390, 1000, 390, color=_ACCENT)

    svg.rect(1000, 185, 380, 425, fill=_PANEL, stroke=_PURPLE)
    svg.text(1028, 226, "PARTICIPANT PROCESS", size=14, color=_PURPLE, weight=700)
    svg.multiline(
        1028,
        274,
        (
            "scope:",
            policy.participant_scope,
            "",
            "process isolation:",
            policy.process_isolation,
            "",
            "one request → one response",
            "method IDs and evaluator roots",
            "remain parent-side",
        ),
        size=15,
        color=_TEXT,
        line_height=32,
    )

    svg.rect(60, 665, 1320, 225, fill="#2b1d28", stroke=_RED)
    svg.text(90, 708, "NOT ESTABLISHED — RELEASE GATE 16", size=15, color=_RED, weight=700)
    svg.text(
        90,
        756,
        f"hostile_code_containment = {policy.hostile_code_containment}",
        size=23,
        color=_TEXT,
        weight=700,
    )
    svg.multiline(
        90,
        802,
        (
            f"filesystem_isolation = {policy.filesystem_isolation}",
            f"network_isolation    = {policy.network_isolation}",
            "The child retains the parent OS user and accessible host/network capabilities.",
        ),
        size=17,
        color="#ffd7db",
        line_height=31,
    )
    svg.footer(
        "workspace100.worker.LocalPythonProcessBackend · Workspace100IsolationPolicy",
        "lifecycle separation for reviewed built-ins; not safe execution of arbitrary code",
    )
    return Visual(
        filename="isolation-boundary.svg",
        title=title,
        description=description,
        source_modules=(worker_module, release_module),
        nonclaims=(
            "The local backend is not a hostile-code sandbox.",
            "The child retains the parent operating-system user, filesystem, and network access.",
            "Release gate 16 remains not_established.",
        ),
        facts=facts,
        svg=svg.render(),
    )


def _object_value(value: object, *, label: str) -> dict[str, object]:
    if type(value) is not dict:
        raise RuntimeError(f"{label} must be an object")
    return cast(dict[str, object], value)


def _array_value(value: object, *, label: str) -> list[object]:
    if type(value) is not list:
        raise RuntimeError(f"{label} must be an array")
    return cast(list[object], value)


def _string_value(value: object, *, label: str) -> str:
    if type(value) is not str:
        raise RuntimeError(f"{label} must be a string")
    return value


def _integer_value(value: object, *, label: str) -> int:
    if type(value) is not int:
        raise RuntimeError(f"{label} must be an integer")
    return value


@lru_cache(maxsize=1)
def _candidate_receipt_payload() -> dict[str, object]:
    raw = _source_path(CANDIDATE_RECEIPT_PATH).read_bytes()
    try:
        decoded: object = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("candidate receipt is not valid UTF-8 JSON") from error
    payload = _object_value(decoded, label="candidate receipt")
    canonical = (
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    if canonical != raw:
        raise RuntimeError("candidate receipt is not canonical JSON")

    counts = _object_value(payload.get("counts"), label="candidate counts")
    statuses = _object_value(counts.get("worker_status"), label="candidate worker status")
    files = _array_value(payload.get("files"), label="candidate files")
    scores = _array_value(payload.get("scores"), label="candidate scores")
    if (
        payload.get("format") != "witnessgap.workspace100-development-candidate-receipt.v1"
        or payload.get("official") is not False
        or payload.get("protocol_id") != "workspace-100-v1"
        or payload.get("release_kind") != "pre_release_reproducibility_candidate"
        or payload.get("root_authentication") != "not_established_by_this_receipt"
        or payload.get("gate16_status") != "not_established"
        or counts.get("worker_runs") != _EXPECTED_CANDIDATE_RUN_COUNT
        or statuses != {"claimed": _EXPECTED_CANDIDATE_RUN_COUNT, "failed": 0}
        or counts.get("payload_files") != _EXPECTED_RELEASE_PAYLOAD_COUNT
        or counts.get("tree_files") != _EXPECTED_CANDIDATE_FILE_COUNT
        or len(files) != _EXPECTED_CANDIDATE_FILE_COUNT
        or len(scores) != _EXPECTED_BUILTIN_SCORE_COUNT
    ):
        raise RuntimeError("candidate receipt identity or reviewed cardinalities changed")
    return payload


@lru_cache(maxsize=1)
def _candidate_check_stdout() -> str:
    payload = _candidate_receipt_payload()
    receipt_root = _string_value(payload.get("receipt_root"), label="candidate receipt root")
    expected = (
        "verified non-official development candidate receipt "
        f"{receipt_root}; independent authentication: not established\n"
    )
    completed = subprocess.run(
        (sys.executable, str(CANDIDATE_EVIDENCE_TOOL_PATH), "check"),
        cwd=ROOT,
        env={
            "LC_ALL": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONNOUSERSITE": "1",
        },
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if completed.returncode != 0 or completed.stderr or completed.stdout != expected:
        raise RuntimeError("candidate evidence CLI output or verification status changed")
    return completed.stdout.removesuffix("\n")


def _validated_candidate_payload() -> dict[str, object]:
    _candidate_check_stdout()
    return _candidate_receipt_payload()


@dataclass(frozen=True, slots=True)
class ExactRate:
    """One exact receipt rate with its observed and reduced fractions."""

    numerator: int
    denominator: int
    ratio_numerator: int
    ratio_denominator: int

    @property
    def observed(self) -> str:
        return f"{self.numerator}/{self.denominator}"

    @property
    def reduced(self) -> str:
        return f"{self.ratio_numerator}/{self.ratio_denominator}"


def _exact_rate(value: object, *, label: str) -> ExactRate:
    rate = _object_value(value, label=label)
    ratio = _object_value(rate.get("ratio"), label=f"{label} ratio")
    numerator = _integer_value(rate.get("numerator"), label=f"{label} numerator")
    denominator = _integer_value(rate.get("denominator"), label=f"{label} denominator")
    ratio_numerator = _integer_value(ratio.get("numerator"), label=f"{label} ratio numerator")
    ratio_denominator = _integer_value(ratio.get("denominator"), label=f"{label} ratio denominator")
    divisor = gcd(numerator, denominator)
    if (
        numerator < 0
        or denominator <= 0
        or numerator > denominator
        or ratio.get("kind") != "ratio"
        or ratio_numerator != numerator // divisor
        or ratio_denominator != denominator // divisor
    ):
        raise RuntimeError(f"{label} is not a valid exact reduced rate")
    return ExactRate(
        numerator=numerator,
        denominator=denominator,
        ratio_numerator=ratio_numerator,
        ratio_denominator=ratio_denominator,
    )


@dataclass(frozen=True, slots=True)
class CandidateScore:
    """The two displayed exact rates for one frozen built-in control."""

    baseline: str
    decisive_coverage: ExactRate
    false_certainty_incidence: ExactRate


def _candidate_scores() -> tuple[CandidateScore, ...]:
    payload = _validated_candidate_payload()
    raw_scores = _array_value(payload.get("scores"), label="candidate scores")
    scores: list[CandidateScore] = []
    for index, raw_score in enumerate(raw_scores):
        score = _object_value(raw_score, label=f"candidate score {index}")
        metrics = _object_value(score.get("metrics"), label=f"candidate score {index} metrics")
        scores.append(
            CandidateScore(
                baseline=_string_value(
                    score.get("baseline"), label=f"candidate score {index} baseline"
                ),
                decisive_coverage=_exact_rate(
                    metrics.get("decisive_coverage"),
                    label=f"candidate score {index} decisive coverage",
                ),
                false_certainty_incidence=_exact_rate(
                    metrics.get("false_certainty_incidence"),
                    label=f"candidate score {index} false-certainty incidence",
                ),
            )
        )
    expected_order = (
        "always_unknown",
        "forced_environment",
        "refresh_success_only",
        "refresh_outcome",
    )
    if tuple(score.baseline for score in scores) != expected_order:
        raise RuntimeError("candidate frozen built-in control order changed")
    if any(
        score.decisive_coverage.denominator != _EXPECTED_CASE_COUNT
        or score.false_certainty_incidence.denominator != _EXPECTED_CASE_COUNT
        for score in scores
    ):
        raise RuntimeError("candidate score denominators changed")
    return tuple(scores)


def _rate_facts(rate: ExactRate) -> dict[str, object]:
    return {
        "denominator": rate.denominator,
        "numerator": rate.numerator,
        "ratio": {
            "denominator": rate.ratio_denominator,
            "numerator": rate.ratio_numerator,
        },
    }


def _render_candidate_control_results() -> Visual:
    payload = _validated_candidate_payload()
    scores = _candidate_scores()
    counts = _object_value(payload["counts"], label="candidate counts")
    statuses = _object_value(counts["worker_status"], label="candidate worker status")
    receipt_root = _string_value(payload["receipt_root"], label="candidate receipt root")
    title = "Built-in control outcomes on the validated Workspace-100 candidate"
    description = (
        "Grouped horizontal bars show exact decisive-coverage and false-certainty-incidence "
        "rates for four frozen rule-based controls in the validated development candidate. "
        "The controls are descriptive protocol checks, not competitive systems. All 1,200 "
        "worker runs produced claims and zero worker failures."
    )
    svg = Svg(1600, 1120, title=title, description=description)
    svg.header(
        "Workspace-100 / exact candidate receipt",
        "Built-in control outcomes on 300 participant-visible cases",
        "Four frozen rule-based controls for protocol interpretation — not competing systems.",
    )

    svg.rect(60, 170, 1480, 120, fill="#0e2630", stroke=_ACCENT)
    svg.text(88, 208, "VALIDATED EXECUTION SCOPE", size=14, color=_ACCENT, weight=700)
    svg.text(
        88,
        250,
        (
            f"{counts['worker_runs']:,} worker runs  ·  "
            f"{statuses['claimed']:,} claimed  ·  {statuses['failed']} failed"
        ),
        size=25,
        weight=700,
    )
    svg.pill(1160, 208, 340, "controls ≠ competitive systems", stroke=_GOLD)

    chart_x = 470
    chart_width = 780
    ratio_x = 1280
    svg.text(60, 340, "FROZEN CONTROL", size=13, color=_MUTED, weight=700)
    svg.text(chart_x, 340, "0", size=13, color=_MUTED, anchor="middle")
    svg.text(chart_x + chart_width // 3, 340, "1/3", size=13, color=_MUTED, anchor="middle")
    svg.text(
        chart_x + (2 * chart_width) // 3,
        340,
        "2/3",
        size=13,
        color=_MUTED,
        anchor="middle",
    )
    svg.text(chart_x + chart_width, 340, "1", size=13, color=_MUTED, anchor="middle")
    svg.text(ratio_x, 340, "EXACT OBSERVED = REDUCED", size=13, color=_MUTED, weight=700)
    svg.pill(60, 360, 330, "decisive coverage", fill="#172b43", stroke=_BLUE)
    svg.pill(60, 410, 330, "false-certainty incidence", fill="#2b1d28", stroke=_RED)

    row_y = 500
    for index, score in enumerate(scores):
        y = row_y + index * 125
        svg.rect(60, y - 42, 1480, 108, fill=_PANEL, stroke=_BORDER, radius=12)
        svg.text(
            88,
            y + 5,
            score.baseline,
            size=18,
            color=(_GOLD if score.baseline == "forced_environment" else _TEXT),
            weight=700,
        )
        for offset, rate, color in (
            (0, score.decisive_coverage, _BLUE),
            (39, score.false_certainty_incidence, _RED),
        ):
            bar_y = y - 21 + offset
            svg.rect(
                chart_x,
                bar_y,
                chart_width,
                22,
                fill="#0b1728",
                stroke=_BORDER,
                stroke_width=1,
                radius=6,
            )
            if rate.numerator:
                svg.rect(
                    chart_x,
                    bar_y,
                    chart_width * rate.numerator // rate.denominator,
                    22,
                    fill=color,
                    stroke=color,
                    stroke_width=1,
                    radius=6,
                )
            svg.text(
                ratio_x,
                bar_y + 17,
                f"{rate.observed} = {rate.reduced}",
                size=15,
                color=color,
                weight=700,
            )

    svg.rect(60, 965, 1480, 58, fill="#211c37", stroke=_PURPLE, radius=12)
    svg.text(
        88,
        1002,
        f"receipt_root: {receipt_root}",
        size=15,
        color=_MUTED,
    )
    svg.footer(
        "docs/evidence/workspace100-candidate-receipt.json · scores[]",
        "development candidate; exact control outcomes are not external benchmark comparisons",
    )
    return Visual(
        filename="candidate-control-results.svg",
        title=title,
        description=description,
        source_modules=(),
        source_files=(CANDIDATE_RECEIPT_PATH, CANDIDATE_EVIDENCE_TOOL_PATH),
        nonclaims=(
            "The four built-ins are frozen rule-based controls, not competitive systems.",
            "The receipt is a non-official development candidate.",
            "The receipt does not independently authenticate its release root.",
        ),
        facts={
            "controls": [
                {
                    "baseline": score.baseline,
                    "decisive_coverage": _rate_facts(score.decisive_coverage),
                    "false_certainty_incidence": _rate_facts(score.false_certainty_incidence),
                }
                for score in scores
            ],
            "receipt_root": receipt_root,
            "worker_status": statuses,
            "worker_runs": counts["worker_runs"],
        },
        svg=svg.render(),
    )


def _render_candidate_check_transcript() -> Visual:
    payload = _validated_candidate_payload()
    stdout = _candidate_check_stdout()
    roots = _object_value(payload["roots"], label="candidate roots")
    receipt_root = _string_value(payload["receipt_root"], label="candidate receipt root")
    release_root = _string_value(roots["release"], label="candidate release root")
    title = "Deterministic candidate-receipt verification transcript"
    description = (
        "A reproducible command and its exact single-line deterministic standard output, "
        "followed by exact receipt fields. The command validates local drift pins and the "
        "committed candidate receipt; it explicitly does not establish independent "
        "authentication."
    )
    svg = Svg(1600, 880, title=title, description=description)
    svg.header(
        "Workspace-100 / reproducible CLI evidence",
        "Candidate receipt check: exact command and stdout",
        "The renderer executes this check; the transcript is not a fabricated shell capture.",
    )

    svg.rect(60, 175, 1480, 115, fill=_PANEL, stroke=_BLUE)
    svg.text(88, 213, "COMMAND", size=13, color=_BLUE, weight=700, letter_spacing=1)
    svg.text(
        88,
        258,
        "python tools/workspace100_candidate_evidence.py check",
        size=22,
        color=_TEXT,
        weight=700,
    )

    svg.rect(60, 320, 1480, 135, fill="#0e2630", stroke=_ACCENT)
    svg.text(88, 358, "EXACT STDOUT · ONE LINE", size=13, color=_ACCENT, weight=700)
    svg.text(88, 409, stdout, size=13, color=_TEXT, weight=700)

    svg.rect(60, 490, 1480, 255, fill=_PANEL, stroke=_PURPLE)
    svg.text(88, 528, "EXACT COMMITTED RECEIPT FIELDS", size=13, color=_PURPLE, weight=700)
    svg.multiline(
        88,
        570,
        (
            f"official: {str(payload['official']).lower()}",
            f"release_kind: {payload['release_kind']}",
            f"receipt_root: {receipt_root}",
            f"release_root: {release_root}",
            f"root_authentication: {payload['root_authentication']}",
        ),
        size=16,
        color=_TEXT,
        line_height=34,
    )
    svg.footer(
        "tools/workspace100_candidate_evidence.py check · committed receipt",
        "local integrity replay only; independent authentication is not established",
    )
    return Visual(
        filename="candidate-check-transcript.svg",
        title=title,
        description=description,
        source_modules=(),
        source_files=(CANDIDATE_EVIDENCE_TOOL_PATH, CANDIDATE_RECEIPT_PATH),
        nonclaims=(
            "The transcript is not an independently authenticated attestation.",
            "Pinned roots are local repository drift checks.",
            "The development candidate is not an official Workspace-100 release.",
        ),
        facts={
            "command": "python tools/workspace100_candidate_evidence.py check",
            "official": payload["official"],
            "receipt_root": receipt_root,
            "release_kind": payload["release_kind"],
            "release_root": release_root,
            "root_authentication": payload["root_authentication"],
            "stdout": stdout,
        },
        svg=svg.render(),
    )


@dataclass(frozen=True, slots=True)
class CandidateArtifact:
    """One exact file record from the committed candidate receipt."""

    path: str
    byte_length: int
    mode: int
    content_digest: str


def _candidate_artifacts() -> tuple[CandidateArtifact, ...]:
    payload = _validated_candidate_payload()
    raw_files = _array_value(payload["files"], label="candidate files")
    artifacts: list[CandidateArtifact] = []
    for index, raw_file in enumerate(raw_files):
        record = _object_value(raw_file, label=f"candidate file {index}")
        artifact = CandidateArtifact(
            path=_string_value(record.get("path"), label=f"candidate file {index} path"),
            byte_length=_integer_value(
                record.get("byte_length"), label=f"candidate file {index} byte length"
            ),
            mode=_integer_value(record.get("mode"), label=f"candidate file {index} mode"),
            content_digest=_string_value(
                record.get("content_digest"), label=f"candidate file {index} digest"
            ),
        )
        if (
            artifact.byte_length <= 0
            or artifact.mode != RELEASE_FILE_MODE
            or re.fullmatch(r"[0-9a-f]{64}", artifact.content_digest) is None
        ):
            raise RuntimeError(f"candidate file {artifact.path!r} has an invalid descriptor")
        artifacts.append(artifact)
    paths = tuple(artifact.path for artifact in artifacts)
    if (
        len(artifacts) != _EXPECTED_CANDIDATE_FILE_COUNT
        or len(set(paths)) != len(paths)
        or paths[:-1] != RELEASE_PAYLOAD_PATHS
        or paths[-1] != RELEASE_MANIFEST_PATH
    ):
        raise RuntimeError("candidate receipt file inventory differs from release allowlist")
    return tuple(artifacts)


def _render_candidate_artifact_inventory() -> Visual:
    payload = _validated_candidate_payload()
    artifacts = _candidate_artifacts()
    total_bytes = sum(artifact.byte_length for artifact in artifacts)
    payload_bytes = sum(artifact.byte_length for artifact in artifacts[:-1])
    manifest_bytes = artifacts[-1].byte_length
    maximum_bytes = max(artifact.byte_length for artifact in artifacts)
    title = "Workspace-100 candidate artifact inventory and exact sizes"
    description = (
        "All fourteen file records from the validated candidate receipt in canonical order. "
        "Every row shows its release-relative path, exact mode, exact byte length, and a "
        "proportional size bar. The total is exactly 5,610,036 bytes."
    )
    svg = Svg(1600, 1240, title=title, description=description)
    svg.header(
        "Workspace-100 / receipt-bound artifact tree",
        "All 14 materialized files and exact byte lengths",
        "13 payloads + release-manifest.json; order and sizes come from the validated receipt.",
    )

    svg.rect(60, 170, 1480, 112, fill="#0e2630", stroke=_ACCENT)
    summary = (
        ("TREE TOTAL", f"{total_bytes:,} bytes", _ACCENT),
        ("13 PAYLOADS", f"{payload_bytes:,} bytes", _BLUE),
        ("MANIFEST", f"{manifest_bytes:,} bytes", _PURPLE),
        ("FILE MODE", f"{RELEASE_FILE_MODE:04o}", _GOLD),
    )
    for index, (heading, value, color) in enumerate(summary):
        x = 88 + index * 365
        svg.text(x, 208, heading, size=12, color=color, weight=700, letter_spacing=1)
        svg.text(x, 250, value, size=22, weight=700)

    svg.rect(60, 315, 1480, 750, fill=_PANEL, stroke=_BORDER, radius=12)
    svg.text(86, 352, "#", size=13, color=_MUTED, weight=700)
    svg.text(130, 352, "RELEASE-RELATIVE PATH", size=13, color=_MUTED, weight=700)
    svg.text(790, 352, "MODE", size=13, color=_MUTED, weight=700)
    svg.text(960, 352, "EXACT BYTES", size=13, color=_MUTED, weight=700, anchor="end")
    svg.text(1010, 352, "RELATIVE SIZE", size=13, color=_MUTED, weight=700)
    svg.line(84, 370, 1516, 370, color=_BORDER, width=2)

    bar_x = 1010
    bar_width = 455
    for index, artifact in enumerate(artifacts, start=1):
        y = 408 + (index - 1) * 46
        color = _GOLD if artifact.path == RELEASE_MANIFEST_PATH else _BLUE
        if index % 2 == 0:
            svg.rect(78, y - 27, 1444, 39, fill="#0d1a2c", stroke="#0d1a2c", radius=4)
        svg.text(86, y, f"{index:02d}", size=14, color=_MUTED)
        svg.text(
            130,
            y,
            artifact.path,
            size=15,
            color=color if artifact.path == RELEASE_MANIFEST_PATH else _TEXT,
            weight=700 if artifact.path == RELEASE_MANIFEST_PATH else 400,
        )
        svg.text(790, y, f"{artifact.mode:04o}", size=14, color=_MUTED)
        svg.text(
            960,
            y,
            f"{artifact.byte_length:,}",
            size=15,
            color=_TEXT,
            weight=700,
            anchor="end",
        )
        svg.rect(
            bar_x,
            y - 17,
            bar_width,
            18,
            fill="#0b1728",
            stroke=_BORDER,
            stroke_width=1,
            radius=5,
        )
        svg.rect(
            bar_x,
            y - 17,
            max(2, bar_width * artifact.byte_length // maximum_bytes),
            18,
            fill=color,
            stroke=color,
            stroke_width=1,
            radius=5,
        )

    receipt_root = _string_value(payload["receipt_root"], label="candidate receipt root")
    svg.rect(60, 1090, 1480, 55, fill="#211c37", stroke=_PURPLE, radius=12)
    svg.text(88, 1125, f"receipt_root: {receipt_root}", size=15, color=_MUTED)
    svg.footer(
        "validated receipt files[] · exact byte_length and mode fields",
        "inventory is an integrity record, not a signature or proof of independent provenance",
    )
    return Visual(
        filename="candidate-artifact-inventory.svg",
        title=title,
        description=description,
        source_modules=(release_module,),
        source_files=(CANDIDATE_RECEIPT_PATH, CANDIDATE_EVIDENCE_TOOL_PATH),
        nonclaims=(
            "File digests and sizes do not independently authenticate the candidate.",
            "The receipt lives outside the release and artifact-tree roots.",
            "The development candidate is not an official release.",
        ),
        facts={
            "file_count": len(artifacts),
            "files": [
                {
                    "byte_length": artifact.byte_length,
                    "content_digest": artifact.content_digest,
                    "mode": f"{artifact.mode:04o}",
                    "path": artifact.path,
                }
                for artifact in artifacts
            ],
            "manifest_bytes": manifest_bytes,
            "payload_bytes": payload_bytes,
            "total_bytes": total_bytes,
        },
        svg=svg.render(),
    )


@dataclass(frozen=True, slots=True)
class SetupSnapshot:
    """Exact setup and current-CI facts derived from committed configuration."""

    python_version: str
    requires_python: str
    build_requirement: str
    locked_packages: tuple[str, ...]
    lock_hash_count: int
    console_script: str
    console_entrypoint: str
    ci_install_commands: tuple[str, ...]
    ci_check_commands: tuple[str, ...]
    missing_ci_commands: tuple[str, ...]


def _locked_requirements() -> tuple[tuple[str, ...], int]:
    lines = _source_path(DEVELOPMENT_LOCK_PATH).read_text(encoding="utf-8").splitlines()
    packages: list[str] = []
    hash_count = 0
    pending_package = False
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("--hash=sha256:"):
            digest = stripped.removeprefix("--hash=sha256:")
            if not pending_package or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                raise RuntimeError("development lock contains an unbound or invalid hash")
            hash_count += 1
            pending_package = False
            continue
        if "==" not in stripped or not stripped.endswith("\\") or pending_package:
            raise RuntimeError("development lock does not match the reviewed pinned form")
        requirement = stripped.removesuffix("\\").strip()
        name, version = requirement.split("==", maxsplit=1)
        if not name or not version:
            raise RuntimeError("development lock contains an invalid exact requirement")
        packages.append(requirement)
        pending_package = True
    if pending_package or not packages or hash_count != len(packages):
        raise RuntimeError("every locked package must have exactly one recorded wheel hash")
    return tuple(packages), hash_count


@lru_cache(maxsize=1)
def _setup_snapshot() -> SetupSnapshot:
    python_version = _source_path(PYTHON_VERSION_PATH).read_text(encoding="utf-8").strip()
    pyproject_raw: object = tomllib.loads(_source_path(PYPROJECT_PATH).read_text(encoding="utf-8"))
    pyproject = _object_value(pyproject_raw, label="pyproject")
    build_system = _object_value(pyproject.get("build-system"), label="pyproject build-system")
    project = _object_value(pyproject.get("project"), label="pyproject project")
    scripts = _object_value(project.get("scripts"), label="pyproject scripts")
    build_requirements = _array_value(
        build_system.get("requires"), label="pyproject build requirements"
    )
    if len(build_requirements) != 1:
        raise RuntimeError("pyproject build requirement set changed")
    build_requirement = _string_value(build_requirements[0], label="pyproject build requirement")
    requires_python = _string_value(
        project.get("requires-python"), label="pyproject requires-python"
    )
    console_entrypoint = _string_value(
        scripts.get("witnessgap"), label="pyproject witnessgap console entrypoint"
    )
    locked_packages, lock_hash_count = _locked_requirements()

    ci_source = _source_path(CI_WORKFLOW_PATH).read_text(encoding="utf-8")
    install_commands = (
        "python -m pip install --require-hashes -r requirements-dev.lock",
        "python -m pip install --no-deps --no-build-isolation --editable .",
    )
    check_commands = (
        "ruff check src test",
        "mypy --strict src test",
        "pytest",
    )
    missing_commands = (
        "ruff check tools",
        "mypy --strict tools",
        "python tools/workspace100_candidate_evidence.py check",
        "python tools/render_readme_visuals.py check",
        "witnessgap example  # explicit CLI smoke",
    )
    required_ci_fragments = (
        "runs-on: ubuntu-24.04",
        "architecture: x64",
        "python-version-file: .python-version",
        *install_commands,
        *check_commands,
    )
    if (
        python_version != "3.12.3"
        or requires_python != ">=3.12"
        or build_requirement != "hatchling==1.27.0"
        or console_entrypoint != "witnessgap.cli:main"
        or any(fragment not in ci_source for fragment in required_ci_fragments)
        or any(command in ci_source for command in missing_commands)
    ):
        raise RuntimeError("reproducible setup or current CI command coverage changed")
    return SetupSnapshot(
        python_version=python_version,
        requires_python=requires_python,
        build_requirement=build_requirement,
        locked_packages=locked_packages,
        lock_hash_count=lock_hash_count,
        console_script="witnessgap",
        console_entrypoint=console_entrypoint,
        ci_install_commands=install_commands,
        ci_check_commands=check_commands,
        missing_ci_commands=missing_commands,
    )


def _render_verification_flow() -> Visual:
    setup = _setup_snapshot()
    title = "Reproducible setup and current verification coverage"
    description = (
        "A source-derived setup flow from the pinned Python version, exact hashed development "
        "lock, package metadata, and current GitHub Actions workflow. The workflow installs "
        "the editable package and runs lint, strict typing, and tests. A separate red panel "
        "lists evidence, visual, tools, and explicit CLI checks that are not currently in CI."
    )
    svg = Svg(1600, 1160, title=title, description=description)
    svg.header(
        "WitnessGap / committed setup contract",
        "Pinned runtime → hashed install → editable CLI → current CI",
        "Green/blue stages are configured today; the red panel records current CI omissions.",
    )

    cards = (
        (
            "01 · RUNTIME",
            (
                f".python-version = {setup.python_version}",
                f"requires-python = {setup.requires_python}",
                "CI: Ubuntu 24.04 · x64",
            ),
            _BLUE,
        ),
        (
            "02 · HASHED TOOLCHAIN",
            (
                f"{len(setup.locked_packages)} exact packages",
                f"{setup.lock_hash_count} SHA-256 wheel hashes",
                setup.build_requirement,
            ),
            _ACCENT,
        ),
        (
            "03 · EDITABLE PACKAGE",
            (
                "--no-deps",
                "--no-build-isolation",
                f"{setup.console_script} → {setup.console_entrypoint}",
            ),
            _PURPLE,
        ),
        (
            "04 · CURRENT CI",
            (
                "lint: src + test",
                "strict types: src + test",
                "pytest: configured test suite",
            ),
            _GREEN,
        ),
    )
    for index, (heading, lines, color) in enumerate(cards):
        x = 60 + index * 380
        svg.rect(x, 180, 340, 240, fill=_PANEL, stroke=color)
        svg.text(x + 24, 219, heading, size=13, color=color, weight=700, letter_spacing=1)
        svg.multiline(
            x + 24,
            270,
            lines,
            size=15,
            color=_TEXT,
            weight=700,
            line_height=42,
        )
        if index < len(cards) - 1:
            svg.arrow(x + 340, 300, x + 380, 300, color=_ACCENT)

    svg.rect(60, 470, 720, 460, fill="#0e2630", stroke=_GREEN)
    svg.text(88, 510, "CURRENT CI · EXACT COMMANDS", size=14, color=_GREEN, weight=700)
    svg.text(88, 552, "HASH-LOCKED INSTALL", size=12, color=_ACCENT, weight=700)
    svg.multiline(
        88,
        584,
        setup.ci_install_commands,
        size=14,
        color=_TEXT,
        line_height=31,
    )
    svg.text(88, 680, "QUALITY CHECKS", size=12, color=_ACCENT, weight=700)
    svg.multiline(
        88,
        714,
        setup.ci_check_commands,
        size=17,
        color=_TEXT,
        weight=700,
        line_height=42,
    )
    svg.multiline(
        88,
        862,
        (
            "CI source scope is literal: src + test.",
            "pytest discovers test/ from pyproject.toml.",
        ),
        size=14,
        color=_MUTED,
        line_height=27,
    )

    svg.rect(820, 470, 720, 460, fill="#2b1d28", stroke=_RED)
    svg.text(848, 510, "NOT IN CURRENT CI · EXPLICIT OMISSIONS", size=14, color=_RED, weight=700)
    svg.multiline(
        848,
        558,
        (
            "tools/ is absent from explicit Ruff scope",
            "tools/ is absent from explicit mypy scope",
            "candidate evidence check is not invoked",
            "README visual freshness check is not invoked",
            "console-script smoke command is not invoked",
        ),
        size=16,
        color="#ffd7db",
        line_height=43,
    )
    svg.text(848, 795, "REPRODUCIBLE LOCAL COMMANDS", size=12, color=_GOLD, weight=700)
    svg.multiline(
        848,
        830,
        (
            "python tools/workspace100_candidate_evidence.py check",
            "python tools/render_readme_visuals.py check",
        ),
        size=13,
        color=_TEXT,
        line_height=33,
    )
    svg.rect(60, 960, 1480, 70, fill=_PANEL, stroke=_BORDER, radius=12)
    svg.text(
        88,
        1004,
        (
            f"lock coverage: {len(setup.locked_packages)} package pins / "
            f"{setup.lock_hash_count} hashes  ·  console script: "
            f"{setup.console_script} = {setup.console_entrypoint}"
        ),
        size=16,
        color=_MUTED,
    )
    svg.footer(
        ".python-version · requirements-dev.lock · pyproject.toml · ci.yml",
        "diagram distinguishes configured CI from reproducible checks not yet wired into CI",
    )
    return Visual(
        filename="verification-flow.svg",
        title=title,
        description=description,
        source_modules=(),
        source_files=(
            PYTHON_VERSION_PATH,
            DEVELOPMENT_LOCK_PATH,
            PYPROJECT_PATH,
            CI_WORKFLOW_PATH,
        ),
        nonclaims=(
            "Candidate evidence and README visual checks are not currently CI gates.",
            "The current explicit lint and type-check scopes omit tools/.",
            "The current CI has no explicit installed-console-script smoke command.",
        ),
        facts={
            "build_requirement": setup.build_requirement,
            "ci_check_commands": list(setup.ci_check_commands),
            "ci_install_commands": list(setup.ci_install_commands),
            "console_entrypoint": setup.console_entrypoint,
            "console_script": setup.console_script,
            "locked_package_count": len(setup.locked_packages),
            "locked_packages": list(setup.locked_packages),
            "lock_hash_count": setup.lock_hash_count,
            "missing_ci_commands": list(setup.missing_ci_commands),
            "python_version": setup.python_version,
            "requires_python": setup.requires_python,
        },
        svg=svg.render(),
    )


def _visuals() -> tuple[Visual, ...]:
    return (
        _render_causal_twins(),
        _render_verdict_taxonomy(),
        _render_workspace100_funnel(),
        _render_evidence_views(),
        _render_release_tree(),
        _render_release_bindings(),
        _render_isolation_boundary(),
        _render_candidate_control_results(),
        _render_candidate_check_transcript(),
        _render_candidate_artifact_inventory(),
        _render_verification_flow(),
    )


def _validate_svg(payload: bytes, *, filename: str) -> None:
    root = ElementTree.fromstring(payload)
    namespace = "{http://www.w3.org/2000/svg}"
    if root.tag != f"{namespace}svg":
        raise RuntimeError(f"{filename}: root is not SVG")
    if root.attrib.get("role") != "img":
        raise RuntimeError(f"{filename}: accessible image role is missing")
    if root.attrib.get("aria-labelledby") != "visual-title visual-description":
        raise RuntimeError(f"{filename}: accessible title/description binding is missing")
    title = root.find(f"{namespace}title")
    description = root.find(f"{namespace}desc")
    if title is None or not title.text or description is None or not description.text:
        raise RuntimeError(f"{filename}: accessible title or description is empty")
    forbidden = {
        f"{namespace}script",
        f"{namespace}image",
        f"{namespace}foreignObject",
        f"{namespace}style",
        f"{namespace}linearGradient",
        f"{namespace}radialGradient",
    }
    if any(element.tag in forbidden for element in root.iter()):
        raise RuntimeError(f"{filename}: forbidden external/dynamic SVG element")
    serialized = payload.decode("utf-8")
    if "href=" in serialized or "url(" in serialized:
        raise RuntimeError(f"{filename}: external or indirect reference is forbidden")
    text = " ".join(element.text or "" for element in root.iter())
    if "official: false" not in text:
        raise RuntimeError(f"{filename}: visible official:false marker is missing")
    if "nonclaim:" not in text:
        raise RuntimeError(f"{filename}: visible nonclaim marker is missing")


def _visual_source_paths(visual: Visual) -> tuple[Path, ...]:
    sources = {
        *(_module_path(module) for module in visual.source_modules),
        *(_source_path(path) for path in visual.source_files),
    }
    return tuple(sorted(sources, key=_relative_source_path))


def _source_record(path: Path) -> dict[str, str]:
    resolved = _source_path(path)
    return {
        "path": _relative_source_path(resolved),
        "sha256": _sha256(resolved.read_bytes()),
    }


def _source_records(visuals: tuple[Visual, ...]) -> list[dict[str, str]]:
    sources = {
        _module_path(sys.modules[__name__]),
        *(path for visual in visuals for path in _visual_source_paths(visual)),
    }
    return [_source_record(path) for path in sorted(sources, key=_relative_source_path)]


def _manifest(visuals: tuple[Visual, ...]) -> bytes:
    source_records = _source_records(visuals)
    payload = {
        "format": _FORMAT,
        "generator": "tools/render_readme_visuals.py",
        "official": False,
        "renderer_version": _RENDERER_VERSION,
        "sources": source_records,
        "visuals": [
            {
                "description": visual.description,
                "facts": visual.facts,
                "file": visual.filename,
                "nonclaims": list(visual.nonclaims),
                "official": False,
                "sha256": _sha256(visual.svg),
                "source_paths": [
                    _relative_source_path(path) for path in _visual_source_paths(visual)
                ],
                "source_records": [_source_record(path) for path in _visual_source_paths(visual)],
                "title": visual.title,
            }
            for visual in visuals
        ],
    }
    return (
        json.dumps(
            payload,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _expected_outputs() -> dict[str, bytes]:
    visuals = _visuals()
    if len({visual.filename for visual in visuals}) != len(visuals):
        raise RuntimeError("visual filenames must be unique")
    for visual in visuals:
        _validate_svg(visual.svg, filename=visual.filename)
    return {
        **{visual.filename: visual.svg for visual in visuals},
        MANIFEST_NAME: _manifest(visuals),
    }


def _write() -> int:
    outputs = _expected_outputs()
    OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)
    for filename, payload in sorted(outputs.items()):
        (OUTPUT_DIRECTORY / filename).write_bytes(payload)
        print(f"wrote {Path('docs/images/readme') / filename}")
    return 0


def _check() -> int:
    outputs = _expected_outputs()
    expected_names = set(outputs)
    if not OUTPUT_DIRECTORY.is_dir():
        print("README visual directory is missing", file=sys.stderr)
        return 1
    actual_names = {path.name for path in OUTPUT_DIRECTORY.iterdir() if path.is_file()}
    if actual_names != expected_names:
        missing = sorted(expected_names - actual_names)
        extra = sorted(actual_names - expected_names)
        if missing:
            print(f"missing generated files: {', '.join(missing)}", file=sys.stderr)
        if extra:
            print(f"unexpected generated files: {', '.join(extra)}", file=sys.stderr)
        return 1
    stale = [
        filename
        for filename, expected in sorted(outputs.items())
        if (OUTPUT_DIRECTORY / filename).read_bytes() != expected
    ]
    if stale:
        print(
            "stale generated files: " + ", ".join(stale),
            file=sys.stderr,
        )
        print("run: python tools/render_readme_visuals.py write", file=sys.stderr)
        return 1
    print(f"README visuals are current ({len(outputs) - 1} SVGs + provenance)")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Render or verify deterministic WitnessGap README SVGs."
    )
    parser.add_argument("mode", choices=("write", "check"))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    return _write() if arguments.mode == "write" else _check()


if __name__ == "__main__":
    raise SystemExit(main())
