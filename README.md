# WitnessGap

Know when an agent trace cannot justify a cause.

Tool-agent debuggers increasingly patch a suspicious step and replay the rest of
the run. A successful repair shows that the patch was sufficient to change the
outcome. It does not, by itself, show that the patched step was the unique or
minimal source of failure.

WitnessGap is an identifiability benchmark and certificate verifier for that
gap. It admits a precise attribution only when the available trace, captured
state, and bounded intervention panel support it. Otherwise it returns
`unknown` with a reproducible ambiguity witness.

## The contract

Every diagnosis has one of five forms:

- `identified_singleton`: one target is shared by every compatible minimal
  repair;
- `identified_compound`: one irreducible repair requires multiple targets;
- `alternative_minimal_repairs`: multiple incomparable minimal repairs remain
  under the available evidence;
- `effect_only`: an intervention changes the outcome without localizing the
  original fault;
- `not_identifiable`: compatible hidden worlds still imply incompatible causal
  verdicts.

An accepted positive certificate includes the failed trace, the replay snapshot,
the intervention atoms, an outcome flip, and evidence that every strict subset
fails. An accepted negative certificate exhibits two compatible world
completions with the same public evidence and different causal verdicts.

The claim is deliberately bounded: a certificate is valid relative to an
explicit state schema, intervention algebra, success oracle, and committed
finite completion family. A registry digest binds every verdict to that
declared family; it does not prove that an omitted real-world mechanism cannot
exist. WitnessGap does not infer arbitrary production causality from
incomplete logs.

## Smallest complete example

```python
from witnessgap.identifiability import CandidateRegistry
from witnessgap.verifier import (
    trust_anchor_for_manifest,
    verify_attribution_certificate,
    verify_registry_attribution,
)
from witnessgap.worlds.workspace import workspace_sources, workspace_twins

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

verified_record = verify_attribution_certificate(
    certificate.to_canonical_bytes(),
    trust_anchor=anchor,
    expected_proof_root=certificate.proof_root,
)
assert verified_record.kind == "not_identifiable"
```

`trust_anchor_for_manifest` is an authoring helper. A consumer must receive the
resulting anchor and expected proof root through an independent release channel;
generating them from the certificate under review would provide no trust.

## Why another benchmark?

Recent systems already cover stochastic do-replay, confidence intervals,
counterfactual repair, and intervention-supported localization. WitnessGap asks
an earlier question: *does this evidence license a point attribution at all?*

The benchmark is built around causal twins—episodes with byte-identical public
traces and failure outcomes but different hidden completions and minimal
repairs. A method is rewarded for useful decisive coverage and penalized for
unsupported certainty.

Primary metrics will include false-certainty rate, safe coverage at a fixed
false-certainty bound, exact minimal-witness validity, ambiguity safety, and
intervention efficiency.

## Status

WitnessGap is building its first vertical slice. There is no benchmark result
yet.

The current core contains one deterministic in-memory tool world, an
exhaustive search oracle, a manifest-bound causal-twin registry, and a separate
verifier that accepts exact sealed source bytes rather than executable world
objects. It resolves a versioned adapter from an internal trust store,
reconstructs a new world for every replay and probe, validates the complete
trace/terminal/read-log artifact, and binds the result to externally pinned
registry, adapter, and verifier digests. Search-time `minimal_witnesses` and
`target_family` caches are outside that verifier's trust path.

The Workspace-100 layer now defines five closed templates, 50 explicit
variants, and a deterministic generator for 100 salted source openings. Its
closed runtime adapter accepts only exact authored source records, routes every
task read through a recording-state capability, and validates the complete
artifact against a fresh decode. Corpus-wide tests independently verify all
100 panels: 400 unique receipts, 800 runner executions, and 1,000 source
decodes. An adversarial suite also rejects field-level trace, terminal,
state-log, intervention, and cross-twin artifact splices.

Verified panels now project into four closed evidence views without consulting
the search oracle: 400 private episode-to-view assignments deduplicate to 300
participant cases with frozen `50/50/100/100` denominators. Private completion
routes bind every case to its registry and source snapshot, while the worker
wire omits routing IDs, labels, other views, and unqueried receipts. Recursive
leak checks inspect decoded byte fields as well as the JSON wrapper.

This is verified in-memory evidence construction, not a benchmark result. The
next release gate is a fresh-process capability harness, deterministic
evaluator and truth records, and seed-provenance release record. Participant
code must not receive the full WitnessGap package because it contains the
authored catalog and sealed-source generator.

See [the attribution contract](docs/attribution-contract.md) for the current
formal boundary, [the threat model](docs/threat-model.md) for the trusted
computing base, and
[Workspace-100 protocol](docs/workspace-100-protocol.md) for the frozen Stage B
slice.

## Related work

WitnessGap is complementary to, rather than an implementation of:

- [Causal Agent Replay](https://arxiv.org/abs/2606.08275)
- [CausalFlow](https://arxiv.org/abs/2605.25338)
- [REFLECT](https://arxiv.org/abs/2606.09071)
- [Who&When Pro](https://arxiv.org/abs/2607.09996)

## License

Apache-2.0
