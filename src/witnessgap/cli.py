"""Small, deterministic command-line views over WitnessGap's public contracts."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from collections.abc import Sequence
from typing import cast

from witnessgap import __version__
from witnessgap.canonical import JsonValue, canonical_json
from witnessgap.identifiability import CandidateRegistry
from witnessgap.verifier import (
    trust_anchor_for_manifest,
    verify_attribution_certificate,
    verify_registry_attribution,
)
from witnessgap.workspace100.baselines import builtin_baseline_set
from witnessgap.workspace100.generation import generate_workspace100
from witnessgap.workspace100.release import GATE16_STATUS, RELEASE_KIND
from witnessgap.workspace100.views import (
    ViewKind,
    build_workspace100_evidence_views,
)
from witnessgap.worlds.workspace import workspace_sources, workspace_twins

_WORKSPACE100_DEMONSTRATION_SEED = bytes.fromhex(
    "713d96c0fcadb930599f4f4370df3484766872ac406f1c26c5a360a996f29ec5"
)


def _example_payload() -> dict[str, JsonValue]:
    worlds = workspace_twins()
    registry = CandidateRegistry.build(worlds)
    evidence = registry.observe(worlds[0].world_id)
    anchor = trust_anchor_for_manifest(registry.manifest)
    certificate = verify_registry_attribution(
        workspace_sources(),
        manifest=registry.manifest,
        trust_anchor=anchor,
        evidence=evidence,
    )
    verified = verify_attribution_certificate(
        certificate.to_canonical_bytes(),
        trust_anchor=anchor,
        expected_proof_root=certificate.proof_root,
    )
    return {
        "boundaries": (
            "finite_committed_completion_family",
            "locally_authored_anchor_not_external_authentication",
            "content_digests_not_signatures",
            "no_production_causality_claim",
        ),
        "compatible_completion_count": len(verified.compatible_completion_commitments),
        "evidence_digest": verified.evidence_digest,
        "format": "witnessgap.example-receipt.v1",
        "official": False,
        "panel_root": verified.panel_root,
        "proof_root": verified.proof_root,
        "registry_digest": verified.registry_digest,
        "trust_anchor_digest": verified.trust_anchor_digest,
        "unknown_reason": (
            verified.unknown_reason.value if verified.unknown_reason is not None else None
        ),
        "verdict": verified.kind.value,
    }


def _workspace100_payload() -> dict[str, JsonValue]:
    corpus = generate_workspace100(_WORKSPACE100_DEMONSTRATION_SEED)
    views = build_workspace100_evidence_views(corpus)
    baselines = builtin_baseline_set()
    cases_by_view = Counter(case.view for case in views.cases)
    return {
        "baseline_set_root": baselines.baseline_set_root,
        "counts": {
            "assignments": views.assignment_count,
            "builtin_methods": len(baselines.bundles),
            "completions": len(corpus.completions),
            "fresh_process_runs_in_full_matrix": (len(baselines.bundles) * views.case_count),
            "pairs": len(corpus.pairs),
            "participant_cases": views.case_count,
            "templates": len(corpus.templates),
            "variants": len(corpus.variants),
        },
        "format": "witnessgap.workspace100-status.v1",
        "gate16_status": GATE16_STATUS,
        "hostile_code_containment": "not_established",
        "official": False,
        "projection_roots": {
            "assignment": views.assignment_root,
            "evidence": views.evidence_root,
            "projection": views.projection_root,
        },
        "public_release_published": False,
        "release_kind": RELEASE_KIND,
        "scope": (
            "synthetic_finite_corpus",
            "frozen_reviewed_builtins_only",
            "construction_status_not_a_benchmark_result",
        ),
        "view_cases": {view.value: cases_by_view[view] for view in ViewKind},
        "workspace100_corpus_root": corpus.root,
    }


def _write_payload(payload: dict[str, JsonValue], *, compact: bool) -> None:
    if compact:
        print(canonical_json(payload).decode("utf-8"), end="")
        return
    print(
        json.dumps(
            cast(object, payload),
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="witnessgap",
        description=(
            "Inspect finite-family attribution certificates and the Workspace-100 construction."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    example = commands.add_parser(
        "example",
        help="verify the smallest causal-twin ambiguity certificate",
    )
    example.add_argument(
        "--compact",
        action="store_true",
        help="emit canonical one-line JSON",
    )

    workspace100 = commands.add_parser(
        "workspace100",
        help="inspect the deterministic Workspace-100 construction",
    )
    workspace100.add_argument(
        "--compact",
        action="store_true",
        help="emit canonical one-line JSON",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run one deterministic, read-only public inspection command."""

    arguments = _parser().parse_args(argv)
    if arguments.command == "example":
        _write_payload(_example_payload(), compact=arguments.compact)
    elif arguments.command == "workspace100":
        _write_payload(_workspace100_payload(), compact=arguments.compact)
    else:  # pragma: no cover - argparse enforces the closed command set.
        raise RuntimeError("unsupported WitnessGap command")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
