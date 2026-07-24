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
- serialized certificate records.

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

## Explicit non-goals

WitnessGap does not currently provide:

- a signature or transparency log;
- a proof that the declared finite family exhausts real mechanisms;
- sandboxing for arbitrary third-party adapters;
- instrumentation of arbitrary Python state reads;
- a stochastic or production-agent causality guarantee.
