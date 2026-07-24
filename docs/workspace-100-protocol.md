# Workspace-100 protocol

Protocol ID: `workspace-100-v1`

Status: frozen protocol with an implemented authored catalog, in-memory
sealed-source generator, and trusted runtime adapter. No release artifact
corpus, capability-separated evaluation, evaluated claim, or benchmark result
exists yet. A change to size, evidence views, scoring grain, metric formulas,
or semantic contracts requires a new protocol ID.

Workspace-100 is the Stage B engineering slice for WitnessGap. It tests two
claims inside one synthetic, finite family:

1. a public failure trace can be compatible with different minimal causes; and
2. one relevant probe or replay result can refine that ambiguity into a
   justified singleton attribution.

It is not a leaderboard, a production-agent benchmark, or evidence that the
declared completion family exhausts real failures.

## 1. Frozen size

The slice contains:

- 5 scenario templates;
- 10 authored variants per template;
- 2 sealed completions per variant;
- 50 exact causal-twin pairs;
- 100 episodes;
- 2 intervention atoms and 4 exhaustive subsets per episode;
- 400 unique replay receipts per generation;
- 400 episode-to-view assignments;
- 300 unique participant evidence cases.

The independent verifier executes each subset from two fresh snapshots, so one
complete 100-panel corpus pass performs 800 runner executions and 1,000 source
decodes. These counts do not include independently re-verifying the panels for
each of the 300 participant evidence cases.

The implemented generator requires an explicit exact 32-byte seed. HMAC-SHA256
derives one salt from each canonical source under a versioned domain; no
randomness, clock, path, environment variable, or hidden side coordinate enters
generation. The seed changes salts, commitments, pair IDs, episode IDs, and the
corpus root, but not the 100 source byte strings. Sources inside a pair are
ordered by commitment. The generator writes no release artifacts and creates no
attribution labels or results.

The trusted adapter performs a closed canonical parse and then requires exact
membership in the two authored source records for that template and variant.
It cannot prove salt provenance from one source opening alone. A release
builder must therefore regenerate all sources from its explicit seed and compare
the complete corpus root; accepting an arbitrarily assembled in-memory corpus
is not a provenance check.

Trace-only and owner-probe evidence is byte-identical between the two
completions of a pair. Each is therefore scored once at pair grain: 50
trace-only cases and 50 owner-probe cases. Epoch-probe and refresh-receipt views
remain completion-specific: 100 cases each. The primary evaluation never
counts duplicated evidence as independent observations.

## 2. Templates

| Template | Failed public outcome | Environment mechanism | Policy mechanism |
| --- | --- | --- | --- |
| `publish_draft` | Previous draft is published | Correct semantic selector with a stale draft resolver | Legacy selector with a current resolver |
| `invite_member` | Viewer is granted instead of editor | Approved role with a stale role catalog | Viewer selector with a current catalog |
| `move_work_item` | Item enters triage instead of review | Correct lane key with a stale lane resolver | Triage key with a current resolver |
| `schedule_review` | Previous slot is booked | Approved window with a stale calendar snapshot | Fallback window with a current snapshot |
| `grant_access` | Commenter is granted instead of contributor | Approved scope with a stale permission catalog | Lower scope with a current catalog |

Each template owns exactly:

- one `refresh_*` atom normalized to target `environment`;
- one `repair_*_selection` atom normalized to target `policy`;
- one informative `*_epoch` probe;
- one irrelevant `workspace_owner` control probe.

Atoms, probes, success semantics, and declared state channels are identical
between both completions of a pair.

Informative probe values use neutral version/catalog identifiers. Participant
evidence may not contain `stale`, `current`, a target name, or a completion-side
label.

## 3. Twin construction

For each authored variant, let:

- \(s_c\) be the correct semantic selector;
- \(s_w\) be the wrong selector;
- \(e_c\) be the current resolver state;
- \(e_s\) be the stale resolver state;
- \(i_g\) be the intended concrete ID;
- \(i_b\) be the same incorrect concrete ID in both completions.

The template must satisfy:

\[
\operatorname{resolve}(s_c, e_c) = i_g
\]

\[
\operatorname{resolve}(s_c, e_s)
= \operatorname{resolve}(s_w, e_c)
= i_b
\]

The environment completion starts at \((s_c, e_s)\). The policy completion
starts at \((s_w, e_c)\). Their baseline evidence must be byte-identical:

- public task;
- tool calls and arguments;
- tool results;
- terminal public summary;
- failure outcome;
- declared coverage-manifest digest.

Completion commitments, initial state, ordered state-read logs, probe values,
pair membership, and minimal witnesses remain sealed from the attribution
method.

## 4. Variant records

Every template contains ten explicit source records named `v00` through `v09`.
There is no randomized generation. A record fixes:

- a workspace slug;
- an actor or subject ID;
- a good concrete ID;
- a bad concrete ID;
- an owner;
- task-specific display values.

Within a template:

- all source IDs are unique;
- good and bad IDs differ;
- neither ID contains `environment`, `policy`, `stale`, `current`, `good`,
  `bad`, `fault`, or `cause`;
- public strings do not reveal the completion side;
- opaque episode IDs are derived from salted source commitments, not labels.

## 5. Evidence views

Exactly four views are evaluated for every pair.

### `trace_only`

Only baseline public evidence is exposed. Both completions remain compatible.
The expected verdict is `not_identifiable(ambiguous_worlds)`.

One case is scored per pair because both episode assignments have the same
evidence digest.

### `owner_probe`

The `workspace_owner` result is exposed. It is identical across the pair and
must preserve the trace-only verdict.

One case is scored per pair.

### `epoch_probe`

The template-specific epoch probe is exposed. It differs across completions
and must produce the correct `identified_singleton`.

One case is scored per completion.

### `refresh_receipt`

The public replay receipt for the environment atom is exposed.

- success identifies `environment`;
- failure identifies `policy`, because the full committed family and
  intervention semantics have already been verified.

No view exposes a world ID, completion commitment, target label, source seed,
or unqueried receipt.

Public evidence is assembled from independently verified receipts, never from
search-time `RepairPanel` caches.

## 6. Grouped split

Pairs are indivisible. Templates, not records, define the split:

- development: `publish_draft`, `invite_member` — 40 episodes;
- validation: `move_work_item` — 20 episodes;
- test: `schedule_review`, `grant_access` — 40 episodes.

At unique-case grain this is 120 development, 60 validation, and 120 test
cases. The split exercises one fixed engineering contract on templates not used
while authoring a method. It is not an ML holdout, does not establish
statistical or production-domain generalization, and is not suitable for a
protected leaderboard.

## 7. Deterministic baselines

The Stage B report includes:

### `always_unknown`

Returns `not_identifiable` for every view. This is the zero-coverage safety
floor.

### `forced_environment`

Always returns `identified_singleton(environment)`. The balanced twin
construction gives 50% latent target accuracy but 100% false certainty on
ambiguous views.

### `refresh_success_only`

Returns `environment` only when the refresh receipt succeeds; otherwise
returns `not_identifiable`. Expected decisive coverage is 50% with zero
incorrect decisive verdicts on `refresh_receipt`.

### `refresh_outcome`

Returns `environment` on refresh success and `policy` on refresh failure.
Expected decisive coverage is 100% on `refresh_receipt`.

The verifier-derived method is reported separately from these baselines. No
LLM judge or learned model is part of Workspace-100.

## 8. Metrics

Metrics are computed per view and macro-averaged by template:

- decisive coverage;
- false-certainty rate;
- ambiguity false-certainty rate;
- correct-abstention rate;
- exact target-family match;
- exact minimal-witness match;
- intervention count;
- verifier rejection count.

A decisive answer is false-certain when:

- the declared family is still ambiguous;
- the target family is wrong;
- the submitted witness is not minimal;
- the claim is not bound to the trusted registry and evidence digests; or
- independent verification rejects any source artifact or replay.

Accuracy without decisive coverage and false-certainty rate is not reported as
a primary metric.

The exact formulas are:

- `decisive_coverage = decisive_claims / all_cases`;
- `false_certainty_risk = rejected_or_wrong_decisive / decisive_claims`
  (`NA` when there are no decisive claims);
- `false_certainty_incidence = rejected_or_wrong_decisive / all_cases`;
- `ambiguity_false_certainty = decisive_on_ambiguous / ambiguous_cases`;
- `correct_abstention = exact_ambiguous_worlds_abstentions / ambiguous_cases`;
- `exact_target_family = valid_exact_family / identifiable_cases`;
- `exact_minimal_witness = valid_exact_witness / identifiable_cases`.

Every table publishes raw numerators and denominators, micro rates, and the
template macro. Source-generation failures fail the release gate; they are not
reported as method-level verifier rejections.

## 9. Evaluation isolation and artifacts

The generator and evaluator are capability-separated. A participant worker is
started without the repository checkout, sealed artifact directory, or the
full installed WitnessGap package and receives one canonical `Evidence`
record. Merely hiding the checkout is insufficient because the main package
contains the authored catalog and generator. The worker cannot receive an
episode ID, pair ID, source opening, commitment salt, other view, unqueried
receipt, or label.

The deterministic release layout is:

```text
workspace100/v1/
  protocol.json
  authored/templates.json
  authored/variants.json
  sealed/sources.jsonl
  registries.jsonl
  verified/panels.jsonl
  public/views.jsonl
  truth/labels.jsonl
  results/claims.jsonl
  results/report.json
  release-manifest.json
```

`sealed`, `verified`, and `truth` are never mounted into the participant
worker. They may be published after evaluation for reproducibility; this
remains an open engineering slice, not a hidden leaderboard.

All files use closed canonical schemas, deterministic ordering, no timestamps,
and no absolute paths. `report.json` is computed from immutable claim and truth
records. Human-readable tables are rendered from it rather than written by
hand.

## 10. Release gates

Generation is rejected unless all gates pass:

1. exactly 100 episodes and 50 pair groups exist;
2. every pair has byte-identical baseline public evidence;
3. all 100 baselines fail;
4. the environment atom repairs only the environment completion;
5. the policy atom repairs only the policy completion;
6. both atoms together succeed in both completions;
7. every episode has exactly one raw inclusion-minimal atom witness;
8. informative probes differ and owner probes match within every pair;
9. every post-intervention execution read passes through the recording-state
   capability and is covered by the declared manifest;
10. search and independent verifier profiles agree on all episodes;
11. no participant-visible ID contains a target or completion-side label;
12. two clean generations have identical registry, evidence, panel, and report
    roots.
13. exactly 300 unique evidence digests are scored with the 50/50/100/100
    per-view denominators;
14. recursive case-folded leak scanning finds no target/side label in any
    participant-visible value, key, path, or ordering;
15. search profiles and independently verified panels agree, but public
    evidence references only verified receipts;
16. a worker isolation test proves participant code cannot import or read
    sealed sources and labels;
17. the release manifest pins protocol, source, registry, panel, evidence,
    claim, report, adapter, verifier, and trust-anchor roots.

Expected view-level assertions:

- `trace_only`: 50/50 correct abstentions;
- `owner_probe`: 50/50 correct abstentions;
- `epoch_probe`: 100/100 exact singleton verdicts;
- `refresh_receipt`: 100/100 exact singleton verdicts.

These are construction invariants, not empirical hypotheses.

## 11. Frozen exclusions

Workspace-100 deliberately excludes:

- compound and alternative-minimal benchmark cases;
- missing-state and replay-divergence cases;
- stochastic policies;
- arbitrary shell, browser, or network tools;
- LLM inference;
- learned baselines;
- interactive query planning beyond one fixed intervention;
- claims outside the five declared Workspace templates.

Those belong to a later benchmark protocol and cannot be added to this slice
after results are observed.
