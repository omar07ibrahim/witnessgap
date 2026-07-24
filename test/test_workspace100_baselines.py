from __future__ import annotations

import ast
import json
import re
import sys
import tempfile
from collections import Counter
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from witnessgap import workspace100
from witnessgap.canonical import JsonValue, canonical_json
from witnessgap.identifiability import (
    Evidence,
    InterventionObservation,
    ProbeObservation,
    UnknownReason,
    VerdictKind,
)
from witnessgap.model import Outcome
from witnessgap.workspace100 import TEMPLATES
from witnessgap.workspace100.baselines import (
    PUBLIC_BASELINE_VOCABULARY,
    BuiltinBaseline,
    BuiltinBaselineBundle,
    PublicBaselineVocabulary,
    builtin_baseline_bundles,
    public_baseline_vocabulary_digest,
)
from witnessgap.workspace100.evidence import ParticipantClaim, PublicEvidenceEnvelope
from witnessgap.workspace100.generation import generate_workspace100
from witnessgap.workspace100.views import (
    ViewKind,
    Workspace100EvidenceViews,
    build_workspace100_evidence_views,
)
from witnessgap.workspace100.worker import (
    LocalPythonProcessBackend,
    WorkerFailureKind,
    WorkerLimits,
    WorkerRunStatus,
    run_worker_once,
)

_SEED = bytes.fromhex("713d96c0fcadb930599f4f4370df3484766872ac406f1c26c5a360a996f29ec5")
_RUNTIME_DIGEST = "d" * 64
_SHA256_HEX_LENGTH = 64
_WORKER_INPUT_FAILURE_CODE = 2
_CASE_COUNT = 300
_EXPECTED_PUBLIC_VOCABULARY_DIGEST = (
    "62be02f2222129a1d72aaa5329d0f1e687f1014326e91cbbf7b5141973c651dd"
)
_EXPECTED_BUNDLE_ROOTS = {
    BuiltinBaseline.ALWAYS_UNKNOWN: (
        "464fc2b8de3034120857a551401a89d12b1fc8cd4e2eeafeedc4ca2416aa90f6",
        "d8445be3b868c2fcf35d50112fb5bd1bcb46ed4a9c66481ff7602f39b32a6cee",
    ),
    BuiltinBaseline.FORCED_ENVIRONMENT: (
        "3bca346813676cec998857d8f406cab80533b939ce6e6f4a1a559e1740a2b90d",
        "fcebb34a9e5e6b3af3eec09f18e698f28cae8b25921151197f42e29d758a2810",
    ),
    BuiltinBaseline.REFRESH_SUCCESS_ONLY: (
        "6c813f81504177adf6dc86ea8583f104f4a395eb819df7dbd6d3c6528dd95185",
        "0e87cd46169f9a8f8c32fac779378d4adc8ba8ae8c6110ccb8b1d5001614d469",
    ),
    BuiltinBaseline.REFRESH_OUTCOME: (
        "e2ea0d5fef5e7817087c3d22508911d12bf3b9b5b9ad0cdf1890dd07c19deb02",
        "b0024a7ee5a42f9d3ef0429afbad8088c6d106cc2c7f138434648b41c69036b2",
    ),
}
_SHA256_LITERAL = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")
_UNKNOWN_CLAIM = ParticipantClaim(
    kind=VerdictKind.NOT_IDENTIFIABLE,
    unknown_reason=UnknownReason.AMBIGUOUS_WORLDS,
)
_ROUTING_TERMS = (
    "case_id",
    "completion_commitment",
    "episode_id",
    "pair_id",
    "schedule_position",
    "source_snapshot",
    "template_id",
    "truth_root",
    "variant_id",
    "view",
)


@pytest.fixture(scope="module")
def baseline_scratch_root() -> Iterator[str]:
    root = Path(
        tempfile.mkdtemp(
            prefix=".witnessgap-baseline-test-",
            dir=Path.cwd().parent,
        )
    )
    root.chmod(0o700)
    yield str(root)
    root.rmdir()


@pytest.fixture(scope="module")
def evidence_views() -> Workspace100EvidenceViews:
    return build_workspace100_evidence_views(generate_workspace100(_SEED))


def _trace(
    vocabulary: PublicBaselineVocabulary,
    *,
    interventions: tuple[str, ...] = (),
    suffix: str = "one",
    success: bool = False,
) -> bytes:
    concrete_id = f"concrete_{suffix}"
    return canonical_json(
        {
            "events": (
                {
                    "arguments": {
                        "subject_id": f"subject_{suffix}",
                        "workspace": f"workspace_{suffix}",
                    },
                    "result": {
                        "concrete_id": concrete_id,
                        "display": f"Display {suffix}",
                    },
                    "tool": vocabulary.lookup_tool,
                },
                {
                    "arguments": {
                        "concrete_id": concrete_id,
                        "subject_id": f"subject_{suffix}",
                        "workspace": f"workspace_{suffix}",
                    },
                    "result": {"status": "completed"},
                    "tool": vocabulary.action_tool,
                },
            ),
            "interventions": interventions,
            "task": f"Synthetic public task {suffix}",
            "terminal": "synthetic_success" if success else "synthetic_failure",
        }
    )


def _envelope(
    vocabulary: PublicBaselineVocabulary,
    *,
    view: str,
    refresh_outcome: Outcome = Outcome.FAILURE,
    suffix: str = "one",
    digest_characters: tuple[str, str] = ("1", "2"),
) -> PublicEvidenceEnvelope:
    probes: tuple[ProbeObservation, ...] = ()
    observations: tuple[InterventionObservation, ...] = ()
    if view == "owner":
        probes = (
            ProbeObservation(
                name="workspace_owner",
                value=canonical_json({"value": f"owner_{suffix}"}),
            ),
        )
    elif view == "epoch":
        probes = (
            ProbeObservation(
                name=vocabulary.epoch_probe,
                value=canonical_json({"value": f"epoch_{suffix}"}),
            ),
        )
    elif view == "refresh":
        observations = (
            InterventionObservation(
                interventions=(vocabulary.refresh_atom,),
                public_trace=_trace(
                    vocabulary,
                    interventions=(vocabulary.refresh_atom,),
                    suffix=suffix,
                    success=refresh_outcome is Outcome.SUCCESS,
                ),
                outcome=refresh_outcome,
            ),
        )
    elif view != "trace":
        raise ValueError(f"unsupported synthetic view: {view}")
    return PublicEvidenceEnvelope(
        Evidence(
            registry_digest=digest_characters[0] * _SHA256_HEX_LENGTH,
            coverage_manifest_digest=digest_characters[1] * _SHA256_HEX_LENGTH,
            public_trace=_trace(vocabulary, suffix=suffix),
            outcome=Outcome.FAILURE,
            probes=probes,
            intervention_observations=observations,
        )
    )


def _backend(
    bundle: BuiltinBaselineBundle,
    *,
    scratch_root: str,
) -> LocalPythonProcessBackend:
    return LocalPythonProcessBackend(
        bundle.program_source,
        runtime_digest=_RUNTIME_DIGEST,
        interpreter=sys.executable,
        scratch_root=scratch_root,
    )


def _identified_claim(
    target: str,
    witness: str,
) -> ParticipantClaim:
    return ParticipantClaim(
        kind=VerdictKind.IDENTIFIED_SINGLETON,
        target_family=((target,),),
        minimal_witnesses=((witness,),),
    )


def _expected_claim(
    baseline: BuiltinBaseline,
    vocabulary: PublicBaselineVocabulary,
    *,
    refresh_outcome: Outcome | None,
) -> ParticipantClaim:
    if baseline is BuiltinBaseline.ALWAYS_UNKNOWN:
        return _UNKNOWN_CLAIM
    if baseline is BuiltinBaseline.FORCED_ENVIRONMENT:
        return _identified_claim("environment", vocabulary.refresh_atom)
    if refresh_outcome is None:
        return _UNKNOWN_CLAIM
    if refresh_outcome is Outcome.SUCCESS:
        return _identified_claim("environment", vocabulary.refresh_atom)
    if baseline is BuiltinBaseline.REFRESH_OUTCOME:
        return _identified_claim("policy", vocabulary.repair_atom)
    return _UNKNOWN_CLAIM


def _claim_category(claim: ParticipantClaim) -> str:
    if claim.kind is VerdictKind.NOT_IDENTIFIABLE:
        return "unknown"
    return cast(tuple[tuple[str, ...], ...], claim.target_family)[0][0]


def test_public_baseline_vocabulary_is_exactly_the_documented_template_slice() -> None:
    expected = {
        template.action_tool: (
            template.lookup_tool,
            template.epoch_probe,
            template.refresh_atom,
            template.repair_atom,
        )
        for template in TEMPLATES
    }
    actual = {
        entry.action_tool: (
            entry.lookup_tool,
            entry.epoch_probe,
            entry.refresh_atom,
            entry.repair_atom,
        )
        for entry in PUBLIC_BASELINE_VOCABULARY
    }

    assert actual == expected
    assert tuple(actual) == tuple(sorted(actual))
    assert public_baseline_vocabulary_digest() == _EXPECTED_PUBLIC_VOCABULARY_DIGEST


def test_bundle_registry_is_closed_ordered_and_not_package_exported() -> None:
    bundles = builtin_baseline_bundles()

    assert tuple(bundle.baseline for bundle in bundles) == tuple(BuiltinBaseline)
    assert len({bundle.method_id for bundle in bundles}) == len(BuiltinBaseline)
    assert len(
        {bundle.program_implementation_digest for bundle in bundles}
    ) == len(BuiltinBaseline)
    assert len({bundle.bundle_digest for bundle in bundles}) == len(BuiltinBaseline)
    assert {
        bundle.baseline: (
            bundle.program_implementation_digest,
            bundle.bundle_digest,
        )
        for bundle in bundles
    } == _EXPECTED_BUNDLE_ROOTS

    assert "BuiltinBaseline" not in workspace100.__all__
    assert not hasattr(workspace100, "builtin_baseline_bundles")


def test_standalone_sources_have_only_the_minimal_stdlib_capability() -> None:
    for bundle in builtin_baseline_bundles():
        source = bundle.program_source.decode("utf-8")
        tree = ast.parse(source)
        imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        import_from = tuple(
            node for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
        )
        called_names = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        string_constants = {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and type(node.value) is str
        }

        assert imports == {"json", "sys"}
        assert import_from == ()
        assert not called_names & {"__import__", "eval", "exec", "open"}
        assert "witnessgap.workspace100.truth" not in source
        assert "northstar_studio" not in source
        assert _SHA256_LITERAL.search(source) is None
        for term in _ROUTING_TERMS:
            assert term not in string_constants
        compile(source, bundle.method_id, "exec")


def test_every_strategy_emits_the_exact_five_template_matrix(
    baseline_scratch_root: str,
) -> None:
    views = (
        ("trace", None),
        ("owner", None),
        ("epoch", None),
        ("refresh", Outcome.SUCCESS),
        ("refresh", Outcome.FAILURE),
    )
    expected_counts = {
        BuiltinBaseline.ALWAYS_UNKNOWN: Counter({"unknown": 25}),
        BuiltinBaseline.FORCED_ENVIRONMENT: Counter({"environment": 25}),
        BuiltinBaseline.REFRESH_SUCCESS_ONLY: Counter(
            {"unknown": 20, "environment": 5}
        ),
        BuiltinBaseline.REFRESH_OUTCOME: Counter(
            {"unknown": 15, "environment": 5, "policy": 5}
        ),
    }

    for bundle in builtin_baseline_bundles():
        backend = _backend(bundle, scratch_root=baseline_scratch_root)
        counts: Counter[str] = Counter()
        for vocabulary in PUBLIC_BASELINE_VOCABULARY:
            for view, refresh_outcome in views:
                envelope = _envelope(
                    vocabulary,
                    view=view,
                    refresh_outcome=refresh_outcome or Outcome.FAILURE,
                )
                record = run_worker_once(
                    bundle.worker_program,
                    envelope,
                    backend=backend,
                )

                assert record.status is WorkerRunStatus.CLAIMED
                assert record.failure is None
                assert record.claim == _expected_claim(
                    bundle.baseline,
                    vocabulary,
                    refresh_outcome=refresh_outcome,
                )
                counts[_claim_category(record.claim)] += 1
        assert counts == expected_counts[bundle.baseline]


def test_bundle_outputs_are_independent_of_fingerprint_and_incidental_trace_values(
    baseline_scratch_root: str,
) -> None:
    vocabulary = PUBLIC_BASELINE_VOCABULARY[0]
    first = _envelope(
        vocabulary,
        view="refresh",
        refresh_outcome=Outcome.FAILURE,
        suffix="alpha",
        digest_characters=("1", "2"),
    )
    second = _envelope(
        vocabulary,
        view="refresh",
        refresh_outcome=Outcome.FAILURE,
        suffix="omega",
        digest_characters=("3", "4"),
    )

    for bundle in builtin_baseline_bundles():
        backend = _backend(bundle, scratch_root=baseline_scratch_root)
        first_record = run_worker_once(
            bundle.worker_program,
            first,
            backend=backend,
        )
        second_record = run_worker_once(
            bundle.worker_program,
            second,
            backend=backend,
        )

        assert first.evidence_digest != second.evidence_digest
        assert first_record.claim == second_record.claim


def test_standalone_worker_writes_no_stderr_and_one_canonical_claim(
    baseline_scratch_root: str,
) -> None:
    envelope = _envelope(PUBLIC_BASELINE_VOCABULARY[0], view="trace")
    for bundle in builtin_baseline_bundles():
        raw = _backend(bundle, scratch_root=baseline_scratch_root).invoke(
            envelope.to_canonical_bytes(),
            limits=WorkerLimits(),
        )

        assert raw.returncode == 0
        assert raw.stderr == b""
        claim = ParticipantClaim.from_canonical_bytes(raw.stdout)
        assert claim.to_canonical_bytes() == raw.stdout


def test_standalone_worker_fails_closed_on_unsupported_public_shapes(
    baseline_scratch_root: str,
) -> None:
    vocabulary = PUBLIC_BASELINE_VOCABULARY[0]
    valid = _envelope(vocabulary, view="trace")
    trace_payload = cast(
        dict[str, JsonValue],
        json.loads(valid.evidence.public_trace),
    )
    unknown_trace = canonical_json(
        {
            **trace_payload,
            "events": (
                {
                    "arguments": {
                        "subject_id": "subject_one",
                        "workspace": "workspace_one",
                    },
                    "result": {
                        "concrete_id": "concrete_one",
                        "display": "Display one",
                    },
                    "tool": vocabulary.lookup_tool,
                },
                {
                    "arguments": {
                        "concrete_id": "concrete_one",
                        "subject_id": "subject_one",
                        "workspace": "workspace_one",
                    },
                    "result": {"status": "completed"},
                    "tool": "unsupported_action",
                },
            ),
        }
    )
    unknown_tool = PublicEvidenceEnvelope(
        replace(valid.evidence, public_trace=unknown_trace)
    )
    mismatched_receipt = PublicEvidenceEnvelope(
        replace(
            valid.evidence,
            intervention_observations=(
                InterventionObservation(
                    interventions=("unsupported_refresh",),
                    public_trace=_trace(
                        vocabulary,
                        interventions=("unsupported_refresh",),
                    ),
                    outcome=Outcome.FAILURE,
                ),
            ),
        )
    )

    bundle = BuiltinBaselineBundle(BuiltinBaseline.ALWAYS_UNKNOWN)
    backend = _backend(bundle, scratch_root=baseline_scratch_root)
    for envelope in (unknown_tool, mismatched_receipt):
        record = run_worker_once(
            bundle.worker_program,
            envelope,
            backend=backend,
        )
        assert record.status is WorkerRunStatus.FAILED
        assert record.failure is WorkerFailureKind.NONZERO_EXIT

    noncanonical = valid.to_canonical_bytes().rstrip(b"\n")
    raw = backend.invoke(noncanonical, limits=WorkerLimits())
    assert raw.returncode == _WORKER_INPUT_FAILURE_CODE
    assert raw.stdout == raw.stderr == b""


def test_bundle_revalidates_post_init_mutation() -> None:
    bundle = BuiltinBaselineBundle(BuiltinBaseline.ALWAYS_UNKNOWN)
    object.__setattr__(bundle, "baseline", "forced_environment")

    with pytest.raises(TypeError, match="exact BuiltinBaseline"):
        bundle.to_payload()


def test_policy_repair_vocabulary_is_declared_out_of_band_not_read_from_cases(
    evidence_views: Workspace100EvidenceViews,
) -> None:
    worker_payloads = tuple(case.worker_bytes for case in evidence_views.cases)

    for vocabulary in PUBLIC_BASELINE_VOCABULARY:
        repair_bytes = vocabulary.repair_atom.encode()
        encoded_repair = repair_bytes.hex().encode()
        assert all(repair_bytes not in payload for payload in worker_payloads)
        assert all(encoded_repair not in payload for payload in worker_payloads)


def test_actual_workspace100_matrix_matches_the_frozen_construction_expectations(
    evidence_views: Workspace100EvidenceViews,
    baseline_scratch_root: str,
) -> None:
    vocabulary_by_action = {
        entry.action_tool: entry for entry in PUBLIC_BASELINE_VOCABULARY
    }
    template_by_id = {template.template_id: template for template in TEMPLATES}
    expected_counts = {
        BuiltinBaseline.ALWAYS_UNKNOWN: Counter({"unknown": 300}),
        BuiltinBaseline.FORCED_ENVIRONMENT: Counter({"environment": 300}),
        BuiltinBaseline.REFRESH_SUCCESS_ONLY: Counter(
            {"unknown": 250, "environment": 50}
        ),
        BuiltinBaseline.REFRESH_OUTCOME: Counter(
            {"unknown": 200, "environment": 50, "policy": 50}
        ),
    }

    for bundle_index, bundle in enumerate(builtin_baseline_bundles()):
        backend = _backend(bundle, scratch_root=baseline_scratch_root)
        cases = (
            evidence_views.cases
            if bundle_index % 2 == 0
            else tuple(reversed(evidence_views.cases))
        )
        counts: Counter[str] = Counter()
        run_digests: dict[str, str] = {}
        for case in cases:
            template = template_by_id[case.template_id]
            vocabulary = vocabulary_by_action[template.action_tool]
            refresh_outcome = (
                case.envelope.evidence.intervention_observations[0].outcome
                if case.view is ViewKind.REFRESH_RECEIPT
                else None
            )
            record = run_worker_once(
                bundle.worker_program,
                case.envelope,
                backend=backend,
            )

            assert record.status is WorkerRunStatus.CLAIMED
            assert record.claim == _expected_claim(
                bundle.baseline,
                vocabulary,
                refresh_outcome=refresh_outcome,
            )
            counts[_claim_category(record.claim)] += 1
            run_digests[case.evidence_digest] = record.run_digest

        assert len(run_digests) == _CASE_COUNT
        assert counts == expected_counts[bundle.baseline]
        for case in tuple(reversed(cases))[:5]:
            repeated = run_worker_once(
                bundle.worker_program,
                case.envelope,
                backend=backend,
            )
            assert repeated.run_digest == run_digests[case.evidence_digest]
