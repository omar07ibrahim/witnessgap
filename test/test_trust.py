from __future__ import annotations

import subprocess
import sys
import textwrap
from dataclasses import replace

import pytest

from witnessgap import verifier as verifier_module
from witnessgap.canonical import canonical_json
from witnessgap.identifiability import CandidateRegistry
from witnessgap.trust import VerificationTrustAnchor
from witnessgap.verifier import (
    VerificationError,
    trust_anchor_for_manifest,
    verify_registry_attribution,
)
from witnessgap.workspace100 import runtime as workspace100_runtime_module
from witnessgap.worlds import workspace as workspace_module
from witnessgap.worlds.workspace import workspace_sources, workspace_twins


def test_trust_anchor_has_one_closed_canonical_round_trip() -> None:
    manifest = CandidateRegistry.build(workspace_twins()).manifest
    anchor = trust_anchor_for_manifest(manifest)
    encoded = anchor.to_canonical_bytes()

    parsed = VerificationTrustAnchor.from_canonical_bytes(encoded)

    assert parsed == anchor
    assert parsed.to_canonical_bytes() == encoded
    assert parsed.digest == anchor.digest


def test_trust_anchor_parser_rejects_an_open_schema() -> None:
    manifest = CandidateRegistry.build(workspace_twins()).manifest
    anchor = trust_anchor_for_manifest(manifest)
    payload = anchor.to_payload()
    payload["untrusted_note"] = "accept another verifier"

    with pytest.raises(ValueError, match="closed canonical"):
        VerificationTrustAnchor.from_canonical_bytes(canonical_json(payload))


def test_wrong_pinned_verifier_release_is_rejected_before_decode() -> None:
    worlds = workspace_twins()
    registry = CandidateRegistry.build(worlds)
    evidence = registry.observe(worlds[0].world_id)
    anchor = replace(
        trust_anchor_for_manifest(registry.manifest),
        verifier_implementation_digest="0" * 64,
    )

    with pytest.raises(VerificationError, match="installed verifier implementation"):
        verify_registry_attribution(
            workspace_sources(),
            manifest=registry.manifest,
            trust_anchor=anchor,
            evidence=evidence,
        )


def test_every_builtin_implementation_bundle_pins_the_package_initializer() -> None:
    assert workspace_module._ADAPTER_IMPLEMENTATION_PATHS[0] == "__init__.py"
    assert "worlds/__init__.py" in workspace_module._ADAPTER_IMPLEMENTATION_PATHS
    assert workspace100_runtime_module._ADAPTER_IMPLEMENTATION_PATHS[0] == "__init__.py"
    assert "workspace100/__init__.py" in workspace100_runtime_module._ADAPTER_IMPLEMENTATION_PATHS
    assert verifier_module._VERIFIER_IMPLEMENTATION_PATHS[0] == "__init__.py"


@pytest.mark.parametrize(
    ("module_name", "adapter_class_name"),
    [
        ("witnessgap.worlds.workspace", "WorkspaceSourceAdapter"),
        ("witnessgap.workspace100.runtime", "Workspace100SourceAdapter"),
    ],
)
def test_selected_adapter_import_closure_is_fully_digest_bound(
    module_name: str,
    adapter_class_name: str,
) -> None:
    script = textwrap.dedent(
        f"""
        import importlib
        import sys
        from pathlib import Path

        import witnessgap
        from witnessgap import verifier
        from witnessgap.adapters import resolve_trusted_adapter

        adapter_module = importlib.import_module({module_name!r})
        adapter_type = getattr(adapter_module, {adapter_class_name!r})
        adapter = adapter_type()
        resolved = resolve_trusted_adapter(
            adapter.adapter_id,
            expected_implementation_digest=adapter.implementation_digest,
        )
        assert type(resolved) is adapter_type

        package_root = Path(witnessgap.__file__).resolve().parent
        allowed = set(verifier._VERIFIER_IMPLEMENTATION_PATHS)
        allowed.update(adapter_module._ADAPTER_IMPLEMENTATION_PATHS)
        executed = set()
        for module in tuple(sys.modules.values()):
            module_file = getattr(module, "__file__", None)
            if not module_file or not module_file.endswith(".py"):
                continue
            try:
                relative = Path(module_file).resolve().relative_to(package_root)
            except ValueError:
                continue
            executed.add(relative.as_posix())
        uncovered = sorted(executed - allowed)
        assert not uncovered, uncovered
        """
    )

    subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
    )
