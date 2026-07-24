# Workspace-100 protocol

Protocol ID: `workspace-100-v1`

Status: frozen protocol with an implemented authored catalog, in-memory
sealed-source generator, trusted runtime adapter, closed participant wire, and
verified evidence-view projection, evaluator truth certificates, and a
fresh-process transport for trusted built-in methods. No materialized release
directory, third-party-code isolation backend, evaluated 300-case claim set, or
benchmark result exists yet. A change to size, evidence views, scoring grain,
metric formulas, or semantic contracts requires a new protocol ID.

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
decodes. Truth authoring does not re-run that work once per case. For every
pair, one verifier-owned batch reconstructs both panels and all requested
probes, while a separate 100-panel pass independently derives the minimal
witnesses stored in truth. Across the corpus this adds 1,600 runner executions,
2,400 source decodes, and 400 fresh probe calls. The duplication is a
deliberate trust boundary: no panel supplied by the evidence-view author is
accepted as truth.

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

The implemented in-memory projection independently derives 100 panels and 200
probe receipts, emits 400 private episode-to-view assignments, and
deduplicates them by the full evidence digest into the frozen 300 cases.
Private completion routes bind each assignment to its exact registry,
completion commitment, source snapshot, and four expected evidence digests.
The public case bytes contain none of that routing metadata. Assignment,
evidence, and combined projection roots commit the two sides separately and
together.

### Evaluator truth

Truth authoring accepts the exact corpus, the verified public projection, and
exactly 50 external trust anchors indexed by registry digest. It never creates
an anchor for itself. Each pair's six evidence records enter one
invocation-local verifier batch; the verifier accepts source openings,
manifest, anchor, and evidence only. It does not accept caller-created panels
or a persistent cache. Minimal witnesses come from a separate fresh
verification of all 100 sources.

The resulting 300 private records contain:

- 100 `not_identifiable(ambiguous_worlds)` certificates for `trace_only` and
  `owner_probe`;
- 200 `identified_singleton` certificates for `epoch_probe` and
  `refresh_receipt`;
- 100 environment and 100 policy singleton targets;
- 300 unique proof roots and 150 compatibility-bound panel roots.

Every truth case embeds its exact public evidence case and the private episode
assignments that produced it. Structural validation reconstructs the original
50 routes, 400 assignments, and 300 public cases through the same closed view
schema, then requires the frozen assignment, evidence, and projection roots.
This prevents a label-preserving `trace_only`/`owner_probe` or
`epoch_probe`/`refresh_receipt` relabel, including a coordinated route rewrite.

The canonical truth release stores route, certificate, and aggregate truth
roots. Here `certificate_root` commits complete case-bound certificate records,
including routing, public evidence, and witnesses; it is not a hash of bare
certificate bytes alone. Its parser checks closed nested manifests, trust
anchors, public cases, certificates, counts, ordering, and all stored roots
without replaying source code. Parsing proves record integrity and release
binding, not replay semantics anew. Re-establishing semantics requires the
sealed sources and builder, and authenticity requires an expected truth root
pinned outside the release. The truth module and record bytes never enter a
participant worker.

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

The release generator and evaluator must be capability-separated. A
participant worker must start without the repository checkout, sealed artifact
directory, or the full installed WitnessGap package and receive exactly one
canonical `PublicEvidenceEnvelope` record. Merely hiding the checkout is
insufficient because the main package contains the authored catalog and
generator. The worker cannot receive an explicit episode ID, pair ID, source
opening, commitment salt, other view, unqueried receipt, or label.

The registry digest is necessarily stable across the six cases derived from
one pair, and the coverage digest is stable within a template. The ID-free wire
is therefore linkable if multiple records reach one stateful process. A
conforming launcher must create a fresh isolated worker for each single record
and expose neither canonical case position nor parent metadata. Canonical
`view → template → digest` ordering exists only for deterministic roots; it is
not an execution schedule.

The current local POSIX Python backend implements the one-record transport and
fresh process lifecycle for reviewed built-in methods. It stages source in a
new private cwd, constructs a closed environment, sends only the canonical
evidence bytes, incrementally bounds both output streams, applies a monotonic
wall timeout, and normalizes one canonical claim in the trusted parent. A
release must configure one case-independent scratch root outside the checkout
and release tree. Its canonical run record adds no execution-order or
operating-system metadata. Participant-authored target and witness identifiers
remain part of a syntactically valid claim so wrong predictions can be scored.

That backend deliberately does not claim hostile-code containment. The worker
retains the host UID, filesystem, network, and external shared-state
capabilities. Release gate 16 remains open until a concrete external backend
provides UID, mount, network, PID, resource, metadata-service, and cgroup-wide
cleanup controls and passes the adversarial conformance suite described in
[the worker boundary](worker-boundary.md).

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
12. two clean generations have identical registry, evidence, panel, truth, and
    report roots;
13. exactly 300 unique evidence digests are scored with the 50/50/100/100
    per-view denominators;
14. recursive case-folded leak scanning finds no target/side label in any
    participant-visible value, key, path, or ordering;
15. search profiles and independently verified panels agree, but public
    evidence references only verified receipts;
16. a worker isolation test proves participant code cannot import or read
    sealed sources and labels;
17. the release manifest pins protocol, source, registry, panel, evidence,
    truth, claim, report, adapter, verifier, and trust-anchor roots.

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
