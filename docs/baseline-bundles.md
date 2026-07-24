# Workspace-100 baseline bundles

Workspace-100 ships four deliberately simple reference methods. They are
controls for the evaluator, not competitive systems and not benchmark
results.

Each method is rendered as one pinned, stdlib-only Python source file and run
through the same one-request worker transport as any later participant:

- stdin is exactly one canonical `PublicEvidenceEnvelope`;
- stdout is exactly one canonical `ParticipantClaim`;
- imports are limited to `json` and `sys`;
- no WitnessGap package, repository path, catalog, views, truth, case metadata,
  sibling evidence, or digest lookup table is available;
- malformed or unsupported public shapes exit nonzero instead of being turned
  into a rewarded abstention.

The source validates the closed outer envelope, decodes the canonical public
trace, and selects a template only from its visible lookup/action tool pair.
Registry and coverage digests are shape-checked but never used for a
prediction. Task text, subject, workspace, concrete IDs, probe values, PID,
cwd, and execution order are also prediction-invariant.

## Public protocol vocabulary

A claim for `identified_singleton` must contain a concrete minimal witness.
The refresh atom is absent from trace, owner, and epoch views, while the policy
repair atom is absent from every public evidence record. A method therefore
cannot recover all legal witness names from one request.

Workspace-100 declares this five-entry vocabulary as public, out-of-band
protocol knowledge:

| Action tool | Lookup tool | Epoch probe | Environment witness | Policy witness |
|---|---|---|---|---|
| `publish_draft` | `read_draft` | `draft_store_epoch` | `refresh_draft_store` | `repair_draft_selection` |
| `invite_workspace_member` | `resolve_member_role` | `role_catalog_epoch` | `refresh_role_catalog` | `repair_role_selection` |
| `move_board_item` | `resolve_board_lane` | `lane_resolver_epoch` | `refresh_lane_resolver` | `repair_lane_selection` |
| `book_review_slot` | `resolve_review_window` | `calendar_epoch` | `refresh_calendar_snapshot` | `repair_review_selection` |
| `grant_workspace_access` | `resolve_access_scope` | `permission_catalog_epoch` | `refresh_permission_catalog` | `repair_scope_selection` |

This table is embedded in each source bundle and content-bound by both a
vocabulary digest and the exact program digest. It contains no variant, split,
pair, episode, case, registry, evidence, source, or truth identifier. It is
protocol-specific method configuration, not a value inferred from an
individual request and not evidence of unseen-template generalization.

## Reference strategies

`always_unknown`

: Return `not_identifiable(ambiguous_worlds)` for every admitted request.

`forced_environment`

: Return `identified_singleton(environment)` with the mapped environment
  witness for every admitted request.

`refresh_success_only`

: Return environment with the observed refresh witness only after a successful
  refresh receipt; otherwise abstain.

`refresh_outcome`

: Abstain without a refresh receipt. Return environment with the refresh
  witness on success, and policy with the mapped repair witness on failure.
  Using the observed refresh atom as the policy witness would be invalid.

## Construction expectations

The frozen 300-case projection has 100 refresh-receipt cases, balanced 50
success and 50 failure. Therefore the source-level outcome matrix must be:

| Method | Unknown | Environment | Policy |
|---|---:|---:|---:|
| `always_unknown` | 300 | 0 | 0 |
| `forced_environment` | 0 | 300 | 0 |
| `refresh_success_only` | 250 | 50 | 0 |
| `refresh_outcome` | 200 | 50 | 50 |

These are construction assertions over emitted claim kinds, not measured
quality metrics. False-certainty, exact-target, exact-witness, abstention, and
coverage rates are published only after the separate evaluator joins a closed
300-run claim set to pinned truth and recomputes an exact report.

The local POSIX backend remains suitable only for these reviewed built-ins. It
does not make arbitrary participant code safe; the external isolation gate in
[the worker boundary](worker-boundary.md) remains open.
