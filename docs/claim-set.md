# Workspace-100 claim-set contract

`Workspace100ClaimSet` is the closed execution artifact for the four frozen
Workspace-100 baseline bundles. It is not a generic participant-result
container, a truth record, or a benchmark report.

The implemented matrix contains:

- four methods in frozen baseline order;
- 300 unique public evidence records per method;
- the same evidence-digest set for every method; and
- 1,200 complete `WorkerRunRecord` values, including normalized participant
  failures.

The evaluator and binder import no Workspace-100 truth module. They do not
classify predictions or calculate metrics.

## Execution inputs

`evaluate_workspace100_baselines` accepts:

- exact `Workspace100EvidenceViews`;
- the frozen `BuiltinBaselineSet`;
- a `Workspace100ExecutionPlan` containing four ordered `WorkerBackend`
  objects, an independently expected backend implementation digest, and exact
  `WorkerLimits`; and
- a transient permutation of all 1,200 `Workspace100RunKey` method/evidence
  pairs.

The evaluator canonical-copies the pinned limits before execution.
`run_worker_once` keeps pre-invocation limit thresholds and their digest in
private scalar fields, then gives the backend a separate canonical copy. A
backend mutation therefore cannot rewrite the rooted limits or output
normalization policy.

The complete permutation is checked for missing, duplicate, or foreign keys
before the first backend invocation. Each backend program digest must match
the corresponding frozen bundle. All four backend implementation digests must
be identical and must match the caller-pinned expected digest. Program and
backend identities are checked before every invocation and again after each
invocation that returns. Each returned worker record is checked immediately
against its method, evidence, request, limits, and backend identity. A raised
infrastructure error aborts before any post-invocation check is needed.

The execution order is copied into evaluator-owned keys, then discarded. It
is never serialized or hashed. Claim records are stored in frozen method order
and then by lexical evidence digest.

This does not assert that every trusted backend is schedule-independent. A
stateful backend can produce different per-key outcomes under different
schedules. The canonical artifact contains no schedule metadata. Under
identical committed inputs, equal complete `WorkerRunRecord` values for every
method/evidence key produce identical bytes and roots.

`LocalPythonProcessBackend` starts a fresh child for every invocation. The
general `WorkerBackend` contract does not itself prove fresh-process execution,
containment, or provenance.

## Failures and aborts

Participant outcomes such as timeout, output-limit exhaustion, nonzero exit,
empty output, and invalid claims become rooted failed `WorkerRunRecord`
values. They remain in the closed 1,200-run matrix; the future scorer contract
must include them in its all-run denominators.

Evaluator infrastructure failures, a changing backend identity, malformed
execution inputs, or an inconsistent returned record abort the operation.
No partial `Workspace100ClaimSet` is returned.

## Canonical commitments

All records are closed, canonical, float-free JSON with one trailing newline.
The complete claim set is bounded to 8 MiB.

One claim-method digest commits:

```text
{
  baseline,
  baseline_bundle_digest,
  format,
  method_id,
  program_implementation_digest,
  protocol_id
}
```

The method-registry root commits the baseline-set root and the four ordered
method digests. A claim-run digest commits one method digest and the complete
canonical `WorkerRunRecord`, including either its claim or normalized failure.

The run root commits:

```text
{
  backend_implementation_digest,
  claim_run_digests,
  evidence_root,
  format,
  limits_digest,
  method_registry_root,
  protocol_id
}
```

The claim-set root commits:

```text
{
  assignment_root,
  baseline_set_root,
  evidence_root,
  format,
  method_registry_root,
  projection_root,
  protocol_id,
  run_root
}
```

The run root transitively binds the backend, limits, method registry, evidence
root, and all 1,200 run records. The claim-set root then binds it to the public
assignment/evidence projection and frozen baseline set.

The installed evaluator/binder source closure is separately identified by
`workspace100_claims_implementation_digest()`. Its current regression-pinned
digest is
`0665782f8dfdb3490ae1ed0abf846c9b6aa2f72304ccc3336fa4ed56fd95d6f4`.
That digest is an integrity identity, not a signature or runtime attestation.

## Parsing and external verification

`Workspace100ClaimSet.from_canonical_bytes` checks structural integrity only:

- the byte bound and exact canonical round trip;
- closed nested schemas;
- the frozen four-method registry;
- consistency of `projection_root` with `assignment_root` and `evidence_root`;
- every nested stored `worker_run_digest`;
- 1,200 unique method/evidence keys and 300 runs per method;
- one common 300-record evidence set and request identity per evidence digest;
- canonical result ordering; and
- every stored limits, method-registry, run, and claim-set root.

Structural parsing cannot authenticate the public evidence, backend, limits,
or release that supplied the bytes. Untrusted bytes must instead enter through
`load_verified_workspace100_claim_set`, with independently trusted evidence
views, baseline set, expected backend implementation digest, and exact expected
limits. Expected values must never be copied from the payload being checked.

Even the verified loader establishes commitments, not execution attestation.
A release consumer must also compare `claim_set_root` with an independently
authenticated release manifest. A fresh replay can test reproducibility and
semantic agreement, but it cannot prove that the published records were
historically produced by the claimed backend. Historical execution provenance
would require attestation, signatures, or a transparency mechanism that
WitnessGap does not yet implement.

The current repository exercises the full 4×300 matrix and pins regression
roots in tests. It does not yet materialize a public release directory or
publish a benchmark score. A later scorer/report builder must join a verified
ClaimSet to independently pinned truth without exposing truth to participant
workers.
