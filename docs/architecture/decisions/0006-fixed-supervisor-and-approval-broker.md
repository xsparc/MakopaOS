# ADR-0006: Launch a staged workload through a fixed approval broker

- **Status:** Accepted
- **Date:** 2026-08-28
- **Work item:** OS017
- **Baseline:** `1ad7f728965ea828fdf66a25843ee5821769e14b`

## Context

OS030 replaces bootstrap endpoint roles with task-local capability handles, but
both fixed tasks are still published runnable with kernel-selected initial
authority. The next boundary must prove that a privileged user-space service
can launch an untrusted workload from an explicit authority declaration and
that a declared high-impact operation cannot be committed merely because the
workload requested it.

Current authorization guidance emphasizes least privilege, authority for a
specific action, and attribution to the initiating principal. Current approval
systems also demonstrate a crucial limitation: a review prompt or user-interface
state is not a security boundary unless the effect executor validates the
approval. Capability-oriented component systems reinforce parent-controlled,
explicit routing and denial when a route is absent. Short-lived transaction
tokens offer useful single-transaction semantics, but their protocol and
cryptographic machinery are unnecessary for the first local proof.

MakopaOS does not yet have a clock, preemption, cryptographic identity, dynamic
objects, general policy evaluation, or an event log. Its runtime has exactly two
task slots, one fixed endpoint, task-local 16-slot capability tables, and a trap
ABI with three argument registers. The first policy slice must fit those bounds,
preserve the existing recovery-root and handle-first teardown order, and avoid
claiming a human-approval or external-effect boundary that it cannot prove.

OS017 records the contract only. OS031 is the separately approved future
implementation boundary.

## Decision

OS031 will use task `1` as a fixed trusted supervisor and task `2` as a fixed
untrusted workload. The kernel will start only the supervisor. The workload
will remain staged until the supervisor selects one immutable, statically
registered launch manifest through a task-control capability.

The workload will never receive a capability for the first high-impact effect.
It will receive only a request capability for one kernel-owned approval-broker
slot. The trusted supervisor will hold the decision capability and the fixed
synthetic-effect capability. A successful decision alone will not perform the
effect: the kernel will commit the effect only when the supervisor presents its
effect capability and parameters matching the live approval. Commit and
approval consumption will be one state transition.

This is a local authority and mechanism proof. The supervisor is the trusted
policy decision point, and its fixed QEMU decision vector is not a human,
credential, authentication, or user-interface claim. A compromised supervisor
is outside OS031's containment claim.

### Fixed task and trust boundary

The OS031 launch profile retains exactly two task slots:

- task `1` is the prestarted trusted supervisor;
- task `2` is the staged hostile-workload probe;
- no task can be created, destroyed, replaced, or addressed dynamically; and
- task IDs and nonzero generations remain kernel-owned identities.

ADR-0004's task state machine gains two states for this profile:

| State | Address-space owner | Capability table | Queue membership |
| --- | --- | --- | --- |
| `Staged` | inactive | `Building` with no resolvable entry | absent |
| `BlockedApproval` | inactive | `Live` | absent |

The supervisor starts `Ready` and is the only initial run-queue member. The
workload's address space and complete integer context may be constructed before
publication, but `Staged` is not runnable and its table cannot resolve a
handle. A successful launch publishes the complete manifest-derived table,
changes the workload to `Ready`, and appends it to the FIFO tail as one atomic
transition. Launch failure leaves the workload `Staged`, its table non-live,
and the run queue unchanged.

Once launched, ADR-0004's complete context, cooperative scheduling, recovery-
root, and FIFO rules continue to apply. A successful approval request changes
the running workload to `BlockedApproval`; a terminal broker result changes it
to `Ready` and appends it once to the queue tail. There remains no timer,
preemption, fairness, or availability guarantee.

### Immutable `LaunchManifestV1`

The kernel image contains exactly one version-one workload manifest in a fixed
registry. The supervisor identifies it by nonzero manifest ID; it cannot pass a
pointer, length, byte buffer, or replacement manifest. The fixed-layout record
contains:

- `u32` schema version `1` and `u32` byte size `184`;
- nonzero manifest ID and nonzero local principal ID;
- target task ID and generation;
- fixed workload image or probe identity;
- a route count no greater than four; and
- four fixed route records, with every unused record required to be zero.

All IDs and generations are `u64`. The route count and its reserved companion
are `u32`. Each 32-byte route contains `u32` object type, `u32` reserved zero,
`u64` object ID, `u64` object generation, and `u64` exact rights. The
implementation must use a C-compatible layout with compile-time size and offset
assertions. The manifest carries no code address, credential, external
identity, policy expression, or secret. The principal ID provides boot-local
attribution only; it is not proof that a person or remote service was
authenticated.

Before publication, the kernel validates the complete manifest and every route:
version, size, reserved fields, IDs, generations, target binding, route count,
object liveness, type-specific rights, duplicate object routes, and table
capacity. Unknown fields, types, rights, objects, duplicate routes,
excess routes, missing required bindings, or any authority not declared by the
manifest fail closed. Validation and handle installation complete before the
workload becomes runnable. A failure removes installed entries in reverse order
and publishes none of them.

The OS031 reference manifest contains exactly one route: an
`ApprovalBroker/SUBMIT_APPROVAL` capability for the workload. Absence from the
manifest means denial. The fixed endpoint remains available to the existing
OS030 evidence profile but is not ambient authority and is not routed to the
OS031 workload profile.

### Fixed capability types and routes

OS031 extends ADR-0005's version-one type and rights allow-list with these
non-transferable entries:

| Object type | Right | Bit | Initial holder | Meaning |
| --- | --- | --- | --- | --- |
| `TaskControl` | `START` | `1 << 3` | supervisor | Launch task `2` from the registered manifest. |
| `ApprovalBroker` | `SUBMIT_APPROVAL` | `1 << 4` | workload after launch | Submit one canonical request into the empty broker slot. |
| `ApprovalBroker` | `DECIDE_APPROVAL` | `1 << 5` | supervisor | Inspect and approve, deny, or expire the pending request. |
| `TestEffect` | `COMMIT_EFFECT` | `1 << 6` | supervisor | Commit the fixed synthetic effect when a live approval matches. |

The existing `Endpoint` type and `SEND`, `RECEIVE`, and `DUPLICATE` rights keep
their ADR-0005 meanings. `DUPLICATE` is invalid for the three new object types;
their handles cannot be duplicated, attenuated into another form, or moved to
the workload. Tables remain task-local, and there is no cross-task transfer.

The supervisor's three initial handles are installed as part of the fixed
launch-profile publication. The workload's broker-submit handle is installed
only by the validated manifest. A raw object ID, task ID, request kind, or
approval sequence is never authority by itself.

### Version-one trap additions

OS031 appends these operations to ADR-0005's trap ABI:

| Operation | `RAX` | Inputs | Successful output |
| --- | --- | --- | --- |
| start workload | `6` | `RDI = task-control handle`, `RSI = manifest ID`, `RDX = 0` | `RAX = ok`, `RDX = 0` |
| submit approval | `7` | `RDI = submit handle`, `RSI = request kind`, `RDX = inline argument` | blocks; terminal result in `RAX`, committed value in `RDX` only on success |
| inspect approval | `8` | `RDI = decision handle`, `RSI = 0`, `RDX = 0` | `RDI = sequence`, `RSI = request kind`, `RDX = inline argument` |
| decide approval | `9` | `RDI = decision handle`, `RSI = sequence`, `RDX = decision code` | `RAX = ok`, `RDX = 0` |
| commit effect | `10` | `RDI = effect handle`, `RSI = sequence`, `RDX = exact argument` | `RAX = ok`, `RDX = 0` |

Decision codes are `0 = deny`, `1 = approve`, and `2 = expire`. Inspection is
read-only and does not advance the decision epoch. It exposes only the bounded
request values already known to the fixed local boundary; action, resource,
rights, principal, and task bindings are recovered from the static registries
and kernel-owned metadata. Registers remain preserved except for the outputs
declared by the selected operation.

The existing status values retain their numbers. OS031 appends:

| Status | Value | Meaning |
| --- | --- | --- |
| `InvalidManifest` | `12` | The selected manifest or route set is invalid. |
| `InvalidRequest` | `13` | The request kind, reserved input, or state is invalid. |
| `BrokerFull` | `14` | The one request slot is occupied. |
| `ApprovalMismatch` | `15` | Sequence or commit parameters do not match the live approval. |
| `ApprovalDenied` | `16` | The blocked workload's request was denied. |
| `ApprovalExpired` | `17` | The blocked workload's request expired. |
| `EffectUnavailable` | `18` | The fixed synthetic effect cannot accept the commit. |
| `BrokerUnavailable` | `19` | The broker is closing, dead, or epoch-exhausted. |
| `AlreadyLaunched` | `20` | The staged workload has already published. |

Invalid handles, object types, rights, and generations continue to use
ADR-0005's earlier status precedence. Every synchronous rejection returns zero
for undeclared output registers and preserves all runtime state.

### Canonical approval request

The broker contains one request slot and fixed metadata; it is not a queue or a
log. OS031 supports one statically registered request kind,
`COMMIT_SYNTHETIC_VALUE`. The request-kind registry binds that value to action
ID `1`, synthetic-effect object ID `1` and its live generation, requested right
`COMMIT_EFFECT`, and resulting rights `0`. The exact inline effect argument is
one `u64` supplied by the workload.

A canonical `ApprovalRequestV1` is assembled by the kernel from:

- manifest principal ID;
- workload task ID and generation;
- a nonzero, monotonically increasing request sequence;
- registered action ID;
- effect object ID and generation;
- exact inline `u64` argument;
- requested rights; and
- resulting rights.

Each field is `u64`, producing an exact 80-byte C-compatible record whose size
and offsets are compile-time asserted. The registered request kind is `1`; the
reference manifest ID, principal ID, image ID, action ID, and synthetic-effect
object ID are each `1`. The target remains task `2` at its validated staged
generation.

The sequence never wraps. Exhaustion rejects future submission without
reusing an earlier sequence. Because the action, resource, and rights come from
a fixed request-kind registry, the three-register trap boundary needs only the
broker handle, request kind, and inline argument. No user pointer or partially
built request can cross into the kernel.

Submission requires the caller's live `SUBMIT_APPROVAL` handle, an empty broker,
the registered request kind, and valid task and object generations. Success
stores the complete canonical request, moves the workload from `Running` to
`BlockedApproval`, and schedules the supervisor. A full broker or any invalid,
stale, wrong-type, wrong-right, unknown-kind, or exhausted request fails without
changing the task, broker, capability, queue, effect, sequence, or epoch state.

### Decision epoch, approval, and expiry

The broker owns a nonzero boot-local `u64` decision epoch. It advances once for
each accepted submit, approve, deny, explicit expiry, or commit transition and
never wraps. It is an ordering value, not wall-clock time.

The broker lifecycle is `Building`, `Empty`, `Pending`, `Approved`, `Closing`,
and `Dead`. `Denied`, `Expired`, and `Consumed` are transition results delivered
to the blocked workload, not retained history: each clears the request slot
before publication. Only `Pending` and `Approved` contain an 80-byte request;
only `Approved` contains approval and expiry epochs. `Building`, `Closing`, and
`Dead` reject task operations.

The supervisor decides by presenting its live `DECIDE_APPROVAL` handle, the
pending request sequence, and one exact decision code. The kernel binds an
approval to the complete stored request rather than to a free-form label or
user-supplied token. Approval records the resulting decision epoch and an
expiry epoch exactly one accepted broker transition later. The workload remains
blocked while approval is live.

Denial consumes the pending request and wakes the workload with a denied result.
An explicit supervisor expiry transition consumes a pending or approved request
and wakes the workload with an expired result. This is the deterministic
decision-epoch timeout used by OS031 evidence. It makes no elapsed-time or
liveness claim: without a clock or preemption, a supervisor that never decides
can leave the workload blocked indefinitely.

At epoch exhaustion, the broker fails closed, rejects new approvals and commits,
returns any blocked workload with a broker-unavailable result, and permits only
teardown. No epoch or request sequence may wrap or make stale state live again.

### Single-use synthetic effect enforcement

The version-one effect is one fixed kernel-owned in-memory cell. Its only
operation stores the approved inline value once. It performs no serial, device,
network, storage, credential, or other external operation. The cell is evidence
of enforcement, not an append-only or durable effect record, and teardown clears
it.

The supervisor requests commit by presenting its live `COMMIT_EFFECT` handle,
the approved request sequence, and the exact inline argument. Before mutation,
the kernel validates all of the following:

1. the caller is the live supervisor task and generation;
2. its handle resolves to the fixed live `TestEffect` object with
   `COMMIT_EFFECT`;
3. the broker holds one unconsumed approval for the same principal, workload
   task and generation, request sequence, action, effect object and generation,
   argument, requested rights, and resulting rights;
4. the commit is within the approval's decision-epoch window; and
5. the synthetic cell is empty.

Only after every check passes does one atomic transition store the effect,
consume and clear the approval, advance the epoch, return success to the blocked
workload, change it to `Ready`, and append it once to the FIFO tail. A changed
argument, action, resource, right, task or object generation, stale epoch,
replayed sequence, second commit, wrong handle, or occupied effect cell is
rejected without partial mutation. A consumed, denied, expired, or torn-down
approval can never authorize a later effect.

The kernel enforces capability and broker mechanics; it does not decide whether
the action is desirable. In version one the trusted supervisor makes that
decision from a fixed test vector.

### Rollback and teardown

Launch construction records supervisor entries, the staged address space and
context, manifest-derived workload entries, broker bindings, effect binding,
and queue publication in installation order. A failure reverses only completed
steps, clears the broker and effect bindings, removes capability entries, and
then follows ADR-0005, ADR-0004, and ADR-0003 rollback. No failure may expose a
live workload handle or runnable staged task.

Normal workload or supervisor teardown keeps the recovery root active and
removes reachability in this order:

1. mark the exiting task's capability table closing and mark the broker closing
   if the supervisor exits or the live request names the exiting workload;
2. deny or expire that request, remove live approval and blocked-workload
   references, and clear the synthetic cell when its supervisor owner exits or
   the complete launch profile shuts down;
3. close every live entry in the exiting task's table; during complete profile
   shutdown, close the workload and supervisor tables in reverse publication
   order and prove that neither references the fixed objects;
4. remove affected broker, effect, endpoint, blocked-state, run-queue, task, and
   active-owner references;
5. unmap and invalidate the inactive task address space; and
6. return frames, clear task and object generations, and publish `Dead`.

Supervisor exit first denies any pending workload request and makes future
launch, decision, and commit unavailable. Workload exit removes its pending or
approved request before its handle table closes. A frame cannot be returned
while a manifest route, capability entry, broker request, approval, effect
binding, endpoint side, queue entry, mapping, temporary alias, or active root
can still reach task-owned state.

### Deterministic OS031 reference scenario

The pinned QEMU `qemu64` one-vCPU scenario will preserve all earlier terminal
records, then:

1. publish the supervisor and a non-runnable staged workload;
2. reject an unknown manifest ID and prove the workload remains staged;
3. launch the workload from the exact registered manifest;
4. submit and deny one fixed request, then wake the workload with denial;
5. submit a second request, approve it, explicitly expire it by decision epoch,
   and reject its attempted commit;
6. submit and approve a third request, reject one altered-argument commit,
   commit the exact synthetic value once, and reject its replay;
7. tear down the workload and supervisor in handle-first reverse order; and
8. prove the manifest publication state, broker, approval, synthetic cell,
   capability tables, endpoint, task references, address spaces, and owned
   frames are empty before emitting:

```text
MakopaOS approval v1 ok staged-single-use
```

The record cannot be emitted after a different decision, value, ordering,
residual reference, replay result, or frame count.

## Verification contract for OS031

Host tests must demonstrate:

- exact manifest version, size, fixed limits, reserved-zero fields, static ID
  selection, target and image binding, and no pointer-backed input;
- default-deny rejection of missing, unknown, duplicate, excess-rights,
  excessive-count, stale-object, stale-task, and table-capacity routes;
- state-preserving failure at every construction and publication step, followed
  by reverse-order rollback with no live handle or runnable workload;
- only the fixed supervisor's live `TaskControl/START` handle can launch task
  `2`, launch is single-publication, and the workload cannot mint authority;
- the exact `Staged` and `BlockedApproval` scheduler transitions, queue
  uniqueness, and allowed address-space and capability-table state pairs;
- canonical binding of principal, task and generation, sequence, action,
  resource and generation, inline argument, requested rights, and resulting
  rights;
- allow, deny, explicit decision-epoch expiry, deterministic timeout,
  parameter alteration, stale generation, full broker, sequence and epoch
  exhaustion, replay, and second-use behavior;
- effect commit validates the supervisor capability and complete live approval
  before mutation, and effect storage, approval consumption, workload wakeup,
  and result publication are atomic; and
- rollback and teardown remove approval and effect references before handles,
  handles before task and address-space references, and mappings before frame
  return.

Machine-code inspection must preserve ADR-0004 and ADR-0005's complete trap
capture, recovery-root-first Rust dispatch, and non-returning complete-context
resume. It must also prove the exact new probe operation order selected by the
implementation. The existing host, format, lint, dependency-feature,
lockfile-audit, disassembly, legacy-image, and pinned QEMU checks remain in the
single read-only CI job; OS031 may add evidence to that job but cannot change
its topology or permissions without separate approval.

OS031 must not claim human approval, authenticated principal identity, policy
language, real external effects, durable effect logging, dynamic objects,
cross-task transfer, recursive revocation, timer expiry, availability, or
arbitrary workload support.

## Alternatives considered

### Give the workload the effect capability and ask it to wait for approval

Rejected. A cooperative convention is bypassable by a hostile workload. The
effect executor must validate approval, and the untrusted workload must never
hold direct version-one effect authority.

### Treat a supervisor decision as the effect

Rejected. Separating decision from commit proves that approval is bound to the
exact operation at the enforcement boundary and exposes alteration, replay,
expiry, and second-use failures.

### Pass an approval token to the workload

Rejected. MakopaOS has no entropy or cryptographic identity, and cross-task
capability transfer is outside ADR-0005. A kernel-owned single slot can bind and
consume the request without claiming bearer-token secrecy or adding a transfer
path.

### Accept a manifest or request through a user pointer

Rejected. Pointer validation, copy limits, partial construction, and
time-of-check/time-of-use behavior are unnecessary for one fixed proof. Static
registries plus inline IDs and one `u64` argument fit the existing ABI.

### Add a policy language or general authorization engine

Deferred. Default deny and principal-action-resource-context semantics inform
the fixed records, but a parser, rule store, conflict resolution, dynamic
context, and policy update lifecycle would exceed OS031's bounded evidence.

### Adopt OAuth transaction tokens or another external protocol

Deferred. The emerging short-lived, single-transaction model is useful, but
the current specification is a draft and MakopaOS lacks the cryptographic,
identity, transport, and clock boundaries needed to implement it honestly.

### Add effect logging with approval

Deferred to OS032. The broker and synthetic cell retain only live enforcement
state. Ordered, schema-versioned, bounded, exportable records require a separate
ownership, redaction, capacity, and teardown decision.

## Consequences

- Only one trusted task can launch the workload, decide requests, and present
  the synthetic-effect capability.
- The immutable manifest makes initial workload authority finite, inspectable,
  and default-deny without adding dynamic objects or a parser.
- Exact request binding and atomic consumption make approval alteration and
  replay executable failure cases.
- Decision epochs provide deterministic expiry evidence without pretending
  that cooperative execution supplies wall-clock deadlines.
- A trusted supervisor can approve its own fixed test vector and therefore
  remains inside the trusted computing base; OS031 does not contain its
  compromise.
- The fixed broker has capacity one, can block progress indefinitely, and is
  intentionally unsuitable for concurrent or general workloads.
- No effect history survives teardown. OS032 remains required before MakopaOS
  can claim structured effect attribution.

## Rollback and reconsideration

Replace this decision before OS031 if the fixed task runtime cannot stage one
task without publishing its table, if the three-register ABI cannot express
the registered request and exact argument without a pointer, or if broker and
effect references cannot be removed before handle and frame teardown. A
replacement must retain default-deny launch authority, a trusted user-space
decision point, effect-bound parameter validation, single-use consumption,
fail-closed expiry, state-preserving failure, and reverse-order cleanup.

Reconsider the manifest representation before dynamic images, tasks, objects,
or route counts are admitted. Reconsider the approval lifetime only after a
monotonic clock and preemption contract exists. Reconsider principal identity
only with an authentication and credential-isolation boundary. Reconsider
policy syntax, cross-task delegation, recursive revocation, real effects, and
effect logging through separate approved decisions that preserve the kernel's
mechanism-below-policy boundary.

## References

- [ADR-0003: Address-space and fault containment](0003-address-space-and-fault-containment.md)
- [ADR-0004: Cooperative scheduler and inline IPC](0004-cooperative-scheduler-and-inline-ipc.md)
- [ADR-0005: Task-local capability handles](0005-task-local-capability-handles.md)
- [NIST: Software and AI agent identity and authorization concept](https://www.nccoe.nist.gov/sites/default/files/2026-02/accelerating-the-adoption-of-software-and-ai-agent-identity-and-authorization-concept-paper.pdf)
- [GitHub: Agent automation controls in Issues](https://github.blog/changelog/2026-07-23-agent-automation-controls-in-github-issues-in-public-preview/)
- [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)
- [Fuchsia component capability routing](https://fuchsia.dev/fuchsia-src/get-started/learn/components/organizing-components)
- [Cedar authorization model](https://docs.cedarpolicy.com/auth/authorization.html)
- [IETF OAuth transaction-token draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/)
