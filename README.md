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

Workspace-100 reports decisive coverage, false-certainty risk and incidence,
ambiguity false certainty, correct abstention, exact target family, and exact
minimal witness as raw counts plus exact rational values. A future
participant-controlled query protocol can add fixed-risk coverage and
intervention efficiency; the current one-record worker does not observe either.

## Status

WitnessGap is building its first vertical slice. There is a measured,
regression-pinned built-in report, but no materialized public benchmark release
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

Evaluator truth is now authored through a second independent replay path. It
requires 50 caller-supplied trust anchors, verifies every sealed completion
again, and issues 300 case-bound attribution certificates: 100 ambiguous and
200 identified, balanced 100/100 across environment and policy. A closed
canonical release record binds the corpus, public projection, private routes,
public case bytes, witnesses, and certificates under pinned roots. Parsing
checks those bindings without executing a sealed source; hashes provide
integrity, not signatures, so a release consumer must pin the expected root.

Workspace-100 also has a one-record fresh-process POSIX transport for trusted
built-in methods. The parent sends exactly one canonical evidence envelope,
incrementally bounds stdin/stdout/stderr under a monotonic deadline, accepts
only one canonical claim, and deterministically encodes the observed outcome
under method, caller-pinned runtime, backend, limit, request, and evidence
digests. Each Python invocation gets a fresh cwd, home, tmp, environment, and
process session without receiving an explicit case ID. The staged script
argument contains no source-checkout path, but the absolute interpreter and
scratch paths remain visible; a release operator must choose both outside the
checkout and release tree.

This lifecycle boundary is intentionally not described as a sandbox. Local
workers retain the host filesystem, UID, network, and external shared-state
capabilities, so arbitrary participant code still requires a separately
pinned OS-level isolation backend before release gate 16 can pass.

Four deterministic controls now run as pinned standalone bundles:
`always_unknown`, `forced_environment`, `refresh_success_only`, and
`refresh_outcome`. Their child sources import only `json` and `sys`, ignore
digest fingerprints and incidental trace values, and use a documented
five-entry public tool-to-witness vocabulary. One self-contained canonical
baseline set publishes exact bytes for all four standalone programs and binds
their ordered bundle roots under aggregate root
`f8e5c3aadd426220d52d797cef178efc5aec51cd788092749cf46cf7edf53d4d`.
The complete 4×300 construction matrix is exercised through 1,200 fresh
worker processes and assembled into one closed canonical ClaimSet. The
execution evaluator validates the complete transient schedule before the first
invocation, pins method, backend, request, and limit identities, preserves
participant failures, and canonicalizes all 1,200 results independently of
their storage input order. The ClaimSet contains no execution-order metadata.
Under identical committed inputs, equal complete worker records for every key
produce equal bytes and roots; an arbitrary trusted stateful backend is not
assumed to be schedule-independent.

The evaluator now canonical-copies that ClaimSet and independently replayed
truth, rejoins all 1,200 records by evidence digest, recomputes request
identities, assigns one of nine exhaustive outcomes, and builds additive
overall, view, template, and view-by-template tables. Rates and template macros
are exact rationals with explicit zero-denominator `NA`; all five worker
failure kinds remain auditable. A closed report binds the ClaimSet, truth,
public projection, baseline registry, scorer source closure, every
adjudication, four method summaries, and a separate truth-derived oracle
ceiling. The real fresh-process regression report root is pinned in tests.

This remains an in-memory measured regression, not a materialized public
benchmark release. The next engineering slices are seed-provenance release
artifacts and an external isolation conformance backend. Participant code must
not receive the full WitnessGap package because it contains the authored
catalog, sealed-source generator, evaluator truth, and scorer implementation.

See [the attribution contract](docs/attribution-contract.md) for the current
formal boundary, [the threat model](docs/threat-model.md) for the trusted
computing base, [the worker boundary](docs/worker-boundary.md) for the
one-record transport and remaining isolation contract,
[the baseline bundle contract](docs/baseline-bundles.md) for the public
method vocabulary, [the ClaimSet contract](docs/claim-set.md) for execution
records and external verification,
[the scoring contract](docs/scoring-report.md) for exact metrics and report
roots, and
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
