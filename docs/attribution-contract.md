# Attribution contract

This document fixes the semantic boundary for the first WitnessGap vertical
slice. It is intentionally smaller than the planned benchmark protocol.

## 1. Deterministic world

A benchmark world is a finite deterministic transition system with:

- an initial hidden state;
- a public task;
- a fixed agent policy;
- typed tool actions and observations;
- a terminal success oracle;
- a finite, task-owned intervention algebra.

The runner fixes every declared exogenous input. No network, wall clock,
ambient filesystem, process environment, or unrecorded random source may affect
a replay.

The public trace contains only the task, tool calls, tool results, and terminal
summary. Oracle state and state-channel provenance are sealed during
attribution.

## 2. Minimal repair witnesses

For a world \(M\), let \(Y_M(S)\) be the terminal outcome after applying a
finite set of intervention atoms \(S\).

A set \(S\) is an inclusion-minimal repair witness when:

1. \(Y_M(S)\) is successful; and
2. \(Y_M(T)\) fails for every strict subset \(T \subset S\).

The vertical slice enumerates every subset of the declared algebra. It may not
use monotonic pruning. The benchmark label is derived from the complete family
of minimal witnesses, not from the list of faults injected by the generator.

A successful replay alone establishes an effect. It does not establish
minimality, uniqueness, or the origin of the fault.

## 3. Evidence and compatibility

Let \(e\) be the evidence available to an attribution method: the public trace,
the declared state coverage manifest, and the outcomes of any intervention
queries already made.

\(K(e)\) is the set of all benchmark worlds that produce exactly that evidence.
Two worlds are causal twins for \(e\) when both belong to \(K(e)\) but their
families of minimal repair witnesses imply different target sets.

The benchmark may reveal an additional state channel or permit an additional
probe. This creates new evidence \(e'\) and a refined compatibility set
\(K(e') \subseteq K(e)\).

## 4. Verdicts

The verifier recognizes four verdict classes:

### `identified_singleton`

Every world in \(K(e)\) has the same normalized singleton target, supported by
at least one valid minimal witness.

### `identified_equivalence_class`

The evidence determines the complete family of alternative minimal target
sets, but no unique member of that family.

### `identified_compound`

Every world in \(K(e)\) has the same single minimal target set and that set
contains more than one target. Removing any member makes the repair fail.

### `effect_only`

The submitted intervention changes the outcome, but the compatible minimal
witness families do not license the claimed localization.

### `not_identifiable`

At least two compatible worlds imply incompatible target sets, the replay
coverage manifest omits a relevant state channel, or the bounded intervention
panel is exhausted before identification.

`not_identifiable` is reason-coded. The initial reasons are:

- `ambiguous_worlds`;
- `missing_state`;
- `budget_exhausted`;
- `replay_diverged`;
- `intervention_unfulfilled`.

## 5. Certificates

A positive certificate contains:

- canonical digests of the task, public trace, world schema, and replay state;
- the applied intervention atoms;
- the replay receipt and terminal outcome;
- receipts for every strict subset;
- the declared enumeration bound;
- state-channel coverage for every downstream read.

An ambiguity certificate contains two sealed world completions that:

- reproduce the same available evidence;
- satisfy the same declared world schema;
- produce different normalized minimal-witness target sets.

Certificate verification is separate from witness search. The verifier replays
receipts from source artifacts and does not trust cached solver labels.

## 6. Vertical-slice release gates

The first public result is blocked until all of the following hold:

1. an independent brute-force oracle and the witness solver agree on every
   intervention subset;
2. at least twenty causal-twin pairs reproduce byte-identical public traces;
3. the certificate verifier accepts every valid fixture and rejects a mutation
   suite covering trace, state, intervention, outcome, and subset receipts;
4. two clean generations produce byte-identical artifacts;
5. a trace-only baseline cannot turn a causal-twin pair into two justified
   singleton claims;
6. results report both decisive coverage and false certainty;
7. documentation states that guarantees apply only to the declared finite
   world family.

No benchmark accuracy, novelty, or production-causality claim exists before
these gates pass.
