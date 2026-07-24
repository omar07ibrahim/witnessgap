# Workspace-100 worker boundary

The Workspace-100 worker protocol has one request and one response:

```text
trusted evaluator                         participant process
       │
       ├── PublicEvidenceEnvelope JSON ───────────────►
       │                                               │
       ◄────────────── ParticipantClaim JSON ──────────┤
       │
       └── bind outcome to evidence and method digests
```

Both records are closed canonical JSON. There is no request wrapper, case ID,
pair ID, episode ID, template ID, view, split, schedule position, nonce, truth
record, or batch API. The registry and coverage digests inside public evidence
are stable protocol commitments and therefore remain linkable. A fresh process
removes cross-case process memory and an explicit order channel; it cannot
prevent offline evidence fingerprinting.

## Trusted-parent record

`run_worker_once` validates and reserializes one exact
`PublicEvidenceEnvelope`, calls one backend once, and stores a closed
`WorkerRunRecord`. It snapshots the caller-pinned limits before invocation,
retains only their pre-call digest and output thresholds for normalization, and
passes a separate canonical limits copy to the backend. The record binds:

- the parent-configured method ID and participant implementation digest;
- the worker-backend implementation digest, which for the local backend binds
  its harness source, fixed launcher contract, and caller-pinned runtime digest;
- the exact integer limit digest;
- the public evidence digest;
- a domain-separated digest of the exact request bytes;
- either one parsed `ParticipantClaim` or one stable failure kind.

The parent adds no PID, timestamp, duration, cwd, argv, exit code, stderr,
partial stdout, absolute path, or exception text to the canonical record.
Participant-controlled target and witness identifiers remain verbatim inside
an otherwise valid claim, including when they are wrong; the evaluator-side
scorer classifies them against authenticated truth rather than silently
turning them into transport errors.
Infrastructure failures abort evaluation as `WorkerHarnessError`; they are not
converted into participant abstentions.

Participant outcomes use this precedence:

1. an output stream exceeds its parent-checked bound;
2. the backend reports a timeout;
3. the backend reports an output bound;
4. the process exits nonzero;
5. stdout is empty;
6. stdout is not exactly one canonical claim;
7. the claim is accepted.

The parent checks stream sizes again even when a backend reports a successful
exit. Raw child stderr never enters a rooted result.

The complete evaluator-side assembly, failure-preservation, and external
verification rules are specified in
[the Workspace-100 ClaimSet contract](claim-set.md).

## Local trusted-method backend

`LocalPythonProcessBackend` is the reference transport for trusted,
stdlib-only built-in methods. Construction requires a runtime digest supplied
from trusted parent configuration; the backend never invents an attestation
for its own interpreter. It requires a POSIX host because its lifecycle
contract uses process sessions, pipe selectors, and process-group signals. For
every call it:

- stages immutable source bytes as `participant.py` in a new mode-`0700`
  directory;
- uses a new process and a fixed, absolute Python executable;
- starts Python with `-s -S -B -P`, disabling user/site imports, bytecode
  writes, and unsafe path prepending while allowing the fixed hash seed to take
  effect;
- sets cwd, `HOME`, and `TMPDIR` to the fresh directory;
- constructs a closed nine-variable environment instead of inheriting
  credentials, `PYTHONPATH`, proxies, or shell state;
- uses `shell=False`, closes unrelated file descriptors, and starts a new
  process session;
- multiplexes stdin, stdout, and stderr so a worker cannot deadlock the parent
  by writing before reading;
- bounds both output channels, uses a monotonic wall deadline, terminates the
  process group after every outcome, and reaps the direct child.

The participant script argument is relative to the fresh directory, so it does
not disclose the source bundle's original path. The absolute interpreter,
`sys.executable`, process metadata, cwd, `HOME`, and `TMPDIR` remain visible to
the child and can reveal host paths. An operator must use one case-independent
interpreter and `scratch_root` outside the repository and any published release
tree. These paths are part of the operational disclosure boundary even though
they are deliberately absent from deterministic result records.

The fresh directory name, PID, and other operating-system observations are not
deterministic. Reviewed methods must not branch on them; deterministic results
are checked at the evaluator layer.

This backend is not a security sandbox. The child still has the evaluator's
host UID and can deliberately traverse the host filesystem, use `/tmp` or
`/dev/shm`, open sockets, contact cloud metadata, inspect processes, create a
new session, or leave external state. Safe-path and site-disabled startup
reduce accidental imports; they are not filesystem controls. Process-group
termination is lifecycle cleanup, not containment.

Accordingly, the local backend is suitable only for versioned built-ins whose
source is reviewed and pinned. It does not satisfy Workspace-100 release gate
16 for arbitrary participant code.

## External isolation contract

A release that executes third-party code needs a separately implemented and
audited backend. Its conformance evidence must bind the participant artifact,
runtime or image, launcher, and policy digests and demonstrate all of the
following:

- a fresh root filesystem, work directory, home, and tmp for every case;
- a non-root, invocation-unique identity with no privilege escalation,
  capabilities, host namespaces, or writable host mounts;
- only the participant bundle and one request on stdin, with no repository,
  full WitnessGap installation, sealed sources, verified panels, truth,
  results, Docker socket, SSH agent, or credential files;
- no inherited environment secrets or file descriptors;
- no network, DNS, loopback, Unix-socket, host-IPC, AWS IMDS, or ECS credential
  access;
- enforced wall, CPU, memory, PID, file, file-descriptor, and I/O limits;
- cgroup-wide termination and cleanup, including double-fork and new-session
  descendants;
- deterministic, case-independent argv and environment;
- adversarial tests for filesystem reads, imports, shared-state channels,
  sockets, process inspection, privilege changes, and resource exhaustion.

A backend boolean such as `is_sandboxed = True` is not evidence. The concrete
runtime and policy must be pinned outside the result being verified.

## Trust boundary

The backend object itself runs in the evaluator and is trusted. The
`WorkerBackend` protocol minimizes what that object receives, but Python
structural typing is not a security boundary. Release generation must select a
known backend implementation from trusted parent configuration rather than
accepting a backend object from a participant.

Worker implementation digests bind installed source files. The required local
runtime digest makes runtime identity explicit in the backend root, but the
caller remains responsible for obtaining it from a trustworthy build or image
record. These values are integrity commitments, not signatures, interpreter
attestations, or runtime-isolation proofs. A final release manifest must also
publish the interpreter or container runtime identity and external isolation
policy separately. Likewise, a backend digest inside a ClaimSet is a
commitment, not proof that the named backend executed or contained the
participant.
