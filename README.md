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
- `identified_equivalence_class`: multiple alternative minimal repairs remain
  causally equivalent under the available evidence;
- `effect_only`: an intervention changes the outcome without localizing the
  original fault;
- `not_identifiable`: compatible hidden worlds still imply incompatible causal
  verdicts.

An accepted positive certificate includes the failed trace, the replay snapshot,
the intervention atoms, an outcome flip, and evidence that every strict subset
fails. An accepted negative certificate exhibits two compatible world
completions with the same public evidence and different causal verdicts.

The claim is deliberately bounded: a certificate is valid relative to an
explicit state schema, intervention algebra, and success oracle. WitnessGap
does not infer arbitrary production causality from incomplete logs.

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

WitnessGap is at the contract stage. There is no benchmark result yet.

The first vertical slice will contain one deterministic in-memory tool world,
an exhaustive repair oracle, an independent certificate verifier, and paired
cases that must remain `unknown` until an informative probe is exposed.

See [the attribution contract](docs/attribution-contract.md) for the current
formal boundary and release gates.

## Related work

WitnessGap is complementary to, rather than an implementation of:

- [Causal Agent Replay](https://arxiv.org/abs/2606.08275)
- [CausalFlow](https://arxiv.org/abs/2605.25338)
- [REFLECT](https://arxiv.org/abs/2606.09071)
- [Who&When Pro](https://arxiv.org/abs/2607.09996)

## License

Apache-2.0
