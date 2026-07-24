# Workspace-100 scoring and report contract

`Workspace100ScoreReport` is the evaluator-side, truth-joined result artifact
for the four frozen Workspace-100 baselines. It is not participant input, a
signature, a release manifest, or proof that arbitrary code ran in isolation.

The implementation consumes exactly:

- one closed 4×300 `Workspace100ClaimSet`;
- one closed 300-case `Workspace100TruthSet`; and
- caller-authenticated expected roots for the ClaimSet, truth, baseline set,
  assignment, evidence, projection, method registry, and scorer source
  closure.

Expected values are inputs to scoring. They are never copied from either
artifact under review.

## Join and failure boundary

The scorer canonical-copies both source artifacts before use. It joins every
method to truth by `(method_digest, evidence_digest)`, never by tuple position.
For every joined record it recomputes the worker request digest from the exact
truth-bound public evidence envelope.

The operation aborts without a report if it encounters:

- a missing, duplicate, or foreign method/evidence key;
- a mismatch in any caller-pinned root;
- different assignment, evidence, or projection roots across ClaimSet and
  truth;
- a request digest that does not match truth-bound public bytes;
- malformed truth, certificate, registry, or ClaimSet structure; or
- a scorer implementation digest that differs from the installed source
  closure.

These are evaluator or artifact faults. They never become a participant
false-certainty category.

The five normalized worker failures remain method outcomes:

- `timed_out`;
- `output_limit_exceeded`;
- `nonzero_exit`;
- `empty_output`; and
- `invalid_claim`.

They remain in the all-case and truth-class denominators, but are neither
decisive claims, abstentions, nor verifier rejections.

## Exhaustive categories

Every one of the 1,200 method/case joins receives exactly one category, in this
closed order:

1. `failed_ambiguous`;
2. `failed_identifiable`;
3. `correct_abstention`;
4. `wrong_reason_abstention`;
5. `missed_identifiable`;
6. `exact_decisive`;
7. `wrong_witness`;
8. `wrong_target`;
9. `decisive_on_ambiguous`.

Classification precedence is deliberate:

1. a worker failure is partitioned by ambiguous or identifiable truth;
2. `not_identifiable(ambiguous_worlds)` is the only exact abstention on
   ambiguous truth;
3. another unknown reason on ambiguous truth is a wrong-reason abstention;
4. any abstention on identifiable truth is a missed identification;
5. any decisive claim on ambiguous truth is false certainty;
6. on identifiable truth, a wrong target takes precedence over witness
   comparison;
7. with the exact target, the complete canonical witness tuple must equal the
   truth tuple; and
8. only an exact target and exact witness are `exact_decisive`.

A coincidentally matching witness receives no credit when the target is wrong.
Subset or set membership is not enough: witness equality is full nested-tuple
equality.

## Exact metrics

Let the nine category counts be:

```text
FA, FI, CA, WA, MI, ED, WW, WT, DA
```

and define:

```text
N = FA + FI + CA + WA + MI + ED + WW + WT + DA
A = FA + CA + WA + DA
I = FI + MI + ED + WW + WT
D = ED + WW + WT + DA
F = WW + WT + DA
```

The seven numeric metrics are:

```text
decisive_coverage          = D / N
false_certainty_risk       = F / D
false_certainty_incidence  = F / N
ambiguity_false_certainty  = DA / A
correct_abstention         = CA / A
exact_target_family        = (ED + WW) / I
exact_minimal_witness      = ED / I
```

`false_certainty_risk` is `NA` when `D = 0`. Any other zero denominator is
represented the same way. A report never substitutes zero for an undefined
ratio.

Each micro metric stores both the raw event numerator and denominator and a
canonical reduced rational. JSON floats, NaN, and infinity are impossible.

### Pre-release clarification for two non-observable fields

The original v1 prose listed `intervention_count` and
`verifier_rejection_count` before a participant query or report schema
existed. The v1 worker cannot select or issue interventions: it receives one
fixed evidence record. Counting visible receipts would measure corpus input,
not method efficiency. Source, replay, certificate, and binding verification
faults abort report construction; `invalid_claim` is a worker failure, not a
verifier rejection.

The closed report therefore preserves both names as explicit non-numeric
values:

```text
intervention_count:
  not_applicable / not_observed_by_protocol

verifier_rejection_count:
  not_applicable / verification_faults_abort_report
```

Publishing either as numeric zero would make a claim the artifacts cannot
support. A future participant-controlled query/intervention protocol requires
a new protocol ID and can define numeric efficiency metrics.

## Tables and macros

Each baseline report contains 30 additive micro tables:

- one overall table;
- four view tables;
- five template tables; and
- twenty view-by-template tables.

Every table carries all nine category counts, all five worker-failure counts,
the seven exact rates, and the two explicit unavailable fields. The parser
checks that views and templates add to the overall table and that every
view-by-template cell adds to both of its parent tables.

Five template macros are stored per method: one overall and one for each view.
Each is the unweighted mean of the five defined template ratios. Undefined
template ratios are excluded rather than converted to zero. Every macro metric
stores its exact reduced value and `defined_template_count`; if all five
components are undefined, the macro is `NA`.

The report also carries a separate `verified_truth_ceiling`. It is derived
from truth, has no participant method identity or ClaimSet run, and is not a
fifth baseline.

## Audit records and roots

All 1,200 adjudications remain in the report. Canonical order is frozen method
order followed by truth order `(view, template, evidence_digest)`. Each row
links:

- the method digest;
- the ClaimSet claim-run digest;
- the truth-case digest;
- the public evidence digest;
- view, template, and split;
- the score category; and
- the exact worker-failure kind when present.

The root graph is layered:

```text
scored run digests
        │
        ▼
adjudication_root ── binds ClaimSet root and truth root
        │
        ▼
aggregate_root ───── binds four method reports and oracle ceiling
        │
        ▼
report_root ──────── binds both layers plus every direct release root
```

`report_root` directly commits to the ClaimSet, truth, baseline-set,
method-registry, assignment, evidence, projection, and scorer implementation
digests. Redundant direct bindings are intentional: a reviewer need not rely
only on transitive interpretation.

`Workspace100ScoreReport.from_canonical_bytes` checks a 4 MiB bound, closed
nested schemas, exact cardinalities and ordering, cross-method truth-link
agreement, unique claim/truth links, category/failure consistency, additive
tables, exact arithmetic, macros, all stored roots, and a byte-for-byte
canonical round trip.

That structural parser cannot authenticate a self-consistently rewritten
artifact. `load_verified_workspace100_score_report` additionally requires an
independently expected report root, rebuilds every adjudication and table from
the authenticated ClaimSet and truth, and requires exact report bytes.

## Frozen measured regression

The repository runs the four exact standalone baseline programs through 1,200
fresh local processes, builds the ClaimSet, joins independently replayed
truth, and pins these identities:

```text
scorer implementation
  5a7288a48308afc78b47650bc08b523734d813731fafecbd1bf5c10746dcc04e

ClaimSet
  748a4089717276a22adfc76ca983d3510b80bfae2950ecf394e54578cd744030

truth
  c66543a10c7cdd7f09d0b3b27807ac3290060c5929b5ab411fd795fc874681f9

adjudication
  13e20da914f6bea2fbee2b95e94ec6ade5f5bbba0c0d2400f1aa83d278076522

aggregate
  b5ac9473fd2229dbd0d98a34f1b8e45753f6923774bb2a095a9c22a22ca90280

report
  17690c2f54303382b33cabd09413cb87c7a0431435a398db212aaa56db1cea1f
```

Overall measured category counts are:

| Method | CA | MI | ED | WT | DA |
|---|---:|---:|---:|---:|---:|
| `always_unknown` | 100 | 200 | 0 | 0 | 0 |
| `forced_environment` | 0 | 0 | 100 | 100 | 100 |
| `refresh_success_only` | 100 | 150 | 50 | 0 | 0 |
| `refresh_outcome` | 100 | 100 | 100 | 0 | 0 |

All omitted categories are zero. The corresponding overall exact rates are:

| Method | Coverage | FC risk | FC incidence | Ambiguity FC | Correct abstention | Exact target | Exact witness |
|---|---:|---:|---:|---:|---:|---:|---:|
| `always_unknown` | 0 | NA | 0 | 0 | 1 | 0 | 0 |
| `forced_environment` | 1 | 2/3 | 2/3 | 1 | 0 | 1/2 | 1/2 |
| `refresh_success_only` | 1/6 | 0 | 0 | 0 | 1 | 1/4 | 1/4 |
| `refresh_outcome` | 1/3 | 0 | 0 | 0 | 1 | 1/2 | 1/2 |

These are measured deterministic regression results for the reviewed built-in
programs. They are not yet a materialized public benchmark release. Release
gates for clean-run reproducibility, a manifest, provenance, and hostile-code
isolation remain separate.

Finally, every digest above is a content identity, not a signature, runtime
attestation, or proof that the code currently loaded in a Python process is
the code found on disk. A release operator must use an immutable runtime and
obtain expected roots through an authenticated channel.
