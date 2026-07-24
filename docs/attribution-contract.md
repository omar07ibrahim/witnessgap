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
attribution. Public evidence binds a declared coverage-manifest digest; the
ordered actual read log remains sealed and cannot distinguish otherwise
compatible worlds.

Every certified replay starts from exact canonical source bytes plus a
32-byte commitment salt. The verifier recomputes both the salted completion
commitment and the unsalted source-snapshot digest. It never accepts an
executable world object from a claim.

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

The benchmark may reveal a task-authored probe or permit an intervention query.
This creates new evidence \(e'\) and a refined compatibility set
\(K(e') \subseteq K(e)\).

The complete declared family is frozen in a registry manifest containing the
task and source-schema identities, the internally resolved adapter ID, a digest
of its installed implementation modules, intervention/probe/runner/artifact
validator contracts, the recording-state contract, declared state channels,
and every sealed completion commitment. The manifest has one closed canonical
parser. Every evidence view and verdict carries the registry digest.
Identifiability is always relative to this declared finite family: the digest
prevents silent removal of a committed completion, but it cannot establish
that the family exhausts all mechanisms in an arbitrary production system.

## 4. Verdicts

The verifier recognizes five verdict classes:

### `identified_singleton`

Every world in \(K(e)\) has the same normalized singleton target, supported by
at least one valid minimal witness.

### `alternative_minimal_repairs`

The evidence determines a complete antichain of alternative minimal target
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
- `intervention_unfulfilled`;
- `no_repair_in_declared_algebra`.

## 5. Certificates

A positive certificate contains:

- canonical digests of the task, public trace, world schema, exact source
  snapshot, adapter implementation, and verifier implementation;
- the applied intervention atoms;
- the replay receipt and terminal outcome;
- receipts for every strict subset;
- the declared enumeration bound;
- a validator-checked recording-state log for every downstream execution read.

An ambiguity certificate contains two sealed world completions that:

- reproduce the same available evidence;
- satisfy the same declared world schema;
- produce different normalized minimal-witness target sets.

Certificate verification is separate from witness search. The verifier replays
every subset twice, decoding the immutable source again before each attempt. It
also decodes probes twice. A trusted adapter validates the complete artifact:
source snapshot, requested and recorded interventions, public trace, terminal
state, state-read log, and outcome. The verifier does not trust cached solver
labels. Positive identification is a universal claim over every compatible
committed completion; checking one successful witness and its subsets is not
sufficient.

An external trust anchor pins the registry, adapter implementation, and expected
verifier implementation digests. The final proof root commits that anchor, the
evidence digest, all verified panel roots, the compatibility vector, and every
field of the verdict. The serialized record has a closed parser and is checked
against an independently supplied proof root. This is an integrity commitment,
not a digital signature or proof that the finite family is complete.

The built-in Workspace adapters route all post-intervention tool-execution
reads through their recording-state capabilities, and each artifact validator
independently recomputes the expected log. Intervention application itself
remains part of the audited adapter semantics; the contract does not claim that
Python can instrument arbitrary third-party state access.

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
8. an externally stored trust anchor rejects a different verifier or adapter
   implementation before source decoding;
9. participant code runs outside the filesystem/import boundary containing
   sealed sources and private labels.

No benchmark accuracy, novelty, or production-causality claim exists before
these gates pass.
