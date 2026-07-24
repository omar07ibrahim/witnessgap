# Workspace-100 baseline bundles

Workspace-100 ships four deliberately simple reference methods. They are
controls for the evaluator, not competitive systems and not benchmark
results.

Each method is rendered as one pinned, stdlib-only Python source file and run
through the same one-request worker transport as any later participant:

- stdin is exactly one canonical `PublicEvidenceEnvelope`;
- stdout is exactly one canonical `ParticipantClaim`;
- imports are limited to `json` and `sys`;
- stdin contains no package bytes, repository path, private catalog, explicit
  view/case/routing label, sibling evidence, or digest lookup table;
- the only task-specific catalog knowledge embedded in the exact source is the
  public five-entry vocabulary; the source may infer evidence shape from
  visible probes or receipts;
- malformed or unsupported public shapes exit nonzero instead of being turned
  into a rewarded abstention.

The source validates the closed outer envelope, decodes the canonical public
trace, and selects a template only from its visible lookup/action tool pair.
Registry and coverage digests are shape-checked but never used for a
prediction. Task text, subject, workspace, concrete IDs, probe values, PID,
cwd, and execution order are also prediction-invariant.

These are transport and reviewed-source properties, not operating-system
controls. The local backend leaves host filesystem and package paths
potentially readable even though it does not add them to the import path; the
four pinned sources never access them. Arbitrary participant code still
requires the external isolation contract described below.

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

The canonical vocabulary digest is
`62be02f2222129a1d72aaa5329d0f1e687f1014326e91cbbf7b5141973c651dd`.
No Workspace-100 result or release preceded this declaration, so this digest
completes the `workspace-100-v1` participant contract. Any later change to the
vocabulary, source bytes, program or method identity, or ordered membership
requires a new protocol ID.

## Canonical baseline set

The four methods and the public vocabulary are serialized together as one
closed `witnessgap.workspace100-baseline-set.v1` record. Its four artifacts
appear exactly once in the order listed below. Each artifact carries the
closed bundle record, its bundle digest, and the exact standalone source bytes
as lowercase hex. The program digest binds those bytes; the bundle digest
binds the program and vocabulary digests; the aggregate root binds the four
ordered bundle digests and vocabulary digest.

The frozen aggregate root is
`f8e5c3aadd426220d52d797cef178efc5aec51cd788092749cf46cf7edf53d4d`.
Parsing is a canonical round trip: open fields, alternate ordering, malformed
hex, inconsistent roots, and even a fully rehashed source other than the
reviewed built-in source are rejected. A release publishes the record at
`baselines/baseline-set.json` and pins its aggregate root externally in the
release manifest. The digest is an integrity identity, not an authenticity
mechanism by itself.

The storage schema is closed and bounded to 1 MiB:

```text
{
  baseline_set_root,
  bundles: [{
    bundle: {
      baseline, format, method_id, program_implementation_digest,
      protocol_id, public_vocabulary_digest
    },
    bundle_digest, format, program_source_hex
  }],
  format, protocol_id,
  public_vocabulary: {
    entries: [{
      action_tool, epoch_probe, lookup_tool, refresh_atom, repair_atom
    }],
    format, protocol_id
  },
  public_vocabulary_digest
}
```

`bundles` has normative order `always_unknown`, `forced_environment`,
`refresh_success_only`, `refresh_outcome`. Vocabulary entries have ascending
`action_tool` order. The set-root payload is exactly:

```text
{
  bundle_digests: [the four bundle digests in normative order],
  format: "witnessgap.workspace100-baseline-set.v1",
  protocol_id: "workspace-100-v1",
  public_vocabulary_digest
}
```

The vocabulary, bundle, and set roots hash canonical JSON under domains equal
to their respective `format` strings. Canonical JSON is UTF-8, key-sorted,
compact, float-free, and terminated by one newline. The standalone program
digest hashes the decoded source bytes under
`witnessgap.workspace100-python-program.v1`. Every digest uses
`SHA-256("WGCP" || uint16be(1) || uint16be(domain_length) || domain_ascii ||
uint64be(payload_length) || payload)`.

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
