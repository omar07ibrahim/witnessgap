# Threat model

WitnessGap verifies bounded attribution claims. It does not turn arbitrary
Python code or an incomplete hypothesis family into a trustworthy model of
production causality.

## Trusted computing base

For the current vertical slice, a verifier operator trusts:

- the Python interpreter and standard library used to run the release;
- the installed WitnessGap verifier modules identified by the pinned verifier
  implementation digest;
- the built-in Workspace and Workspace-100 adapter modules identified by their pinned adapter
  implementation digest;
- the installed Workspace-100 claim evaluator/binder closure identified by its
  pinned implementation digest;
- the installed Workspace-100 truth-joined scorer/report closure identified by
  its pinned implementation digest;
- the parent-selected worker backend, runtime identity, and exact limits;
- an independently distributed trust-anchor record;
- the procedure that keeps sealed sources and labels outside the participant
  process.

The adapter registry is closed. It matches a literal built-in ID before lazily
importing only that adapter's digest-bound module closure; an unselected
adapter does not execute. A claim may name an adapter ID, but cannot supply an
adapter object or executable world object. Importing the verifier alone also
does not load the search oracle.

## Untrusted inputs

The verifier treats all of the following as untrusted:

- registry manifests;
- evidence and nested observations;
- source openings and commitment salts;
- runner artifacts;
- serialized certificate records;
- serialized Workspace-100 ClaimSet records; and
- serialized Workspace-100 truth and score-report records.

Boundary values must use exact built-in `bytes`, `str`, `tuple`, `list`, and
`dict` types. Subclasses are rejected before hashing, equality checks, or
iteration. Manifests and trust anchors are parsed into new plain values, and
evidence and source openings are copied into new exact values before use. This
prevents a Python subclass from changing behavior between validation,
compatibility testing, and proof hashing.

## Commitments and anchors

A completion commitment binds a 32-byte salt and the exact canonical source
bytes. A separate snapshot digest binds the decoder input carried by every
execution artifact. The registry binds the complete candidate commitment list
to adapter and semantic-contract digests.

The external trust anchor pins:

- the registry digest;
- the adapter implementation digest;
- the verifier implementation digest.

`trust_anchor_for_manifest` only authors such a record. It is not a substitute
for distributing that record independently. Likewise, a proof root is a
content commitment, not a signature: a consumer must obtain the expected root
from a trusted release record or rerun source verification.

## Replay boundary

For every intervention subset, the verifier:

1. decodes the same immutable source into a new world;
2. runs one single-use runner;
3. validates the full artifact against that decoded source;
4. repeats the process from another new decode;
5. rejects any byte or outcome divergence.

Probes follow the same two-decode rule. Probe names and intervention atoms are
checked against the manifest before the adapter is invoked.

## Benchmark isolation

The small repository fixture and the Workspace-100 authored catalog/generator
expose sealed inputs for tests and reproducibility. Workspace-100 evaluation
must not import them in the participant process. Removing the repository
checkout is not enough: the full WitnessGap installation also exposes those
modules. A capability-separated worker receives only its minimal participant
API and exactly one public evidence record, then returns one claim. Sealed
sources, package resources, pair membership, other views, unqueried receipts,
and labels stay in a separate evaluator process.

Registry and coverage digests remain stable commitments, so records are
linkable across cases even though the wire contains no routing ID. The worker
boundary therefore requires one fresh isolated process per record: no batch,
persistent worker, shared state, canonical-order signal, or parent case
metadata may cross that boundary.

The repository now includes a fresh-process POSIX Python transport for trusted
built-in methods. It stages a standalone source bundle, uses safe-path and
site-disabled Python startup flags, constructs a closed environment, bounds
all three pipes, and reaps the direct child after a monotonic timeout. Its
backend root binds the harness implementation, launcher contract, and an
explicitly caller-pinned runtime digest. The trusted parent records only stable
outcome kinds and content digests.

This lifecycle harness is not the required hostile-code isolation launcher.
The child retains the host UID, filesystem, network, process namespace, and
external shared-state channels. Process-group cleanup also cannot contain a
hostile child that deliberately escapes the group. Arbitrary participant code
therefore requires an independently pinned OS-level backend with mount, UID,
network, PID, metadata-service, resource, and cgroup-wide cleanup controls.
See [the worker boundary](worker-boundary.md) for the exact contract.

Evaluator truth is a separate direct submodule and is not exported through the
Workspace-100 runtime package surface. Its builder requires externally supplied
trust anchors and replays sealed sources independently of evidence projection.
The serialized truth record embeds public cases only so it can reconstruct the
frozen public roots; the complete record, private assignments, certificates,
and witnesses remain evaluator-only capabilities.

The ClaimSet binds complete worker records to the public projection, frozen
baseline registry, backend identity, and exact limits. It contains no truth.
Its structural parser checks only its closed schemas and internal roots. The
externally bound loader additionally requires independently trusted public
views, baseline set, backend digest, and limits; those expected values cannot
come from the payload under review. Neither layer proves that the named backend
actually executed the records.

The scorer is evaluator-only and imports private truth. It canonical-copies
ClaimSet and truth inputs, requires independently supplied ClaimSet, truth,
baseline, method-registry, public-projection, and scorer roots, rejoins every
record by evidence digest, and recomputes each worker request digest. Its
structural report parser accepts only closed, additive, exactly rooted
artifacts. Because an attacker can rewrite both content and hashes, the
verified report loader also requires an independently expected report root,
rebuilds every adjudication and table, and compares exact canonical bytes.
Participant processes never import this module.

Canonical parsing verifies hashes and bindings but is not a signature,
transparency proof, or substitute for semantic replay. A party able to rewrite
every record can also compute new self-consistent roots. Release consumers must
obtain the expected corpus, baseline-set, assignment, evidence, projection,
adapter, verifier, trust-anchor, truth, claim, evaluator/binder, scorer,
report, backend, runtime, and limits roots through an independent authenticated
channel. Fresh truth construction and worker replay can re-establish semantics
and reproducibility, but cannot prove the historical origin of published
runs. That requires an attestation, signature, or transparency mechanism
outside the current implementation.

## Explicit non-goals

WitnessGap does not currently provide:

- a signature or transparency log;
- a proof that the declared finite family exhausts real mechanisms;
- sandboxing for arbitrary third-party participants or adapters;
- instrumentation of arbitrary Python state reads;
- a stochastic or production-agent causality guarantee.
