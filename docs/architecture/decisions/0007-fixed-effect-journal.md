# ADR-0007: Record effect lifecycles in a fixed runtime journal

- **Status:** Accepted
- **Date:** 2026-08-29
- **Work item:** OS018
- **Baseline:** `0ff26b64f1933e6f67726cf7a44a41b08c7a3964`

## Context

OS031 proves a narrow authority boundary: a staged workload can request one
synthetic effect, the trusted supervisor can approve or reject it, and the
kernel commits only an exact, live, single-use approval. The broker and effect
cell intentionally retain only current enforcement state. After teardown,
there is no ordered account of which accepted requests were approved, denied,
expired, completed, or failed.

Current audit guidance converges on recording who acted, what happened, and the
terminal outcome while minimizing sensitive data. It also treats capacity and
logging failure as explicit security conditions rather than permission to drop
records silently. Read access should be restricted, and records should remain
useful without coupling the producer to an external telemetry schema.

MakopaOS still has exactly two tasks, fixed capability tables, one approval
slot, one synthetic effect, no allocator in the task runtime, no wall clock,
and a three-register trap ABI. The current `Runtime` is exactly 3,112 bytes and
under its 64 KiB bound. A journal embedded in `Runtime` would charge every
existing profile for OS032 and weaken the evidence that OS020 through OS031
already established. A general logging service, durable store, cryptographic
chain, or pointer-based export would introduce boundaries that do not yet
exist.

OS018 records the contract only. OS032 is the separately approved future
implementation boundary.

## Decision

OS032 will add a separate `JournaledRuntime` profile:

```text
JournaledRuntime
|- runtime: Runtime
`- journal: EffectJournalV1
```

`Runtime`, `Runtime::new`, and `Runtime::new_supervised` remain byte-for-byte
and behaviorally unchanged. `JournaledRuntime::new_supervised` will construct
the existing supervised runtime plus one fixed effect journal and one
supervisor-only read capability. All OS020 through OS031 host, disassembly, and
QEMU evidence must continue to pass against the unchanged base profiles.

The journal is a boot-local, append-only evidence object for accepted OS031
approval and synthetic-effect lifecycles. It is not a general kernel logger,
an external audit protocol, durable storage, or proof of non-repudiation.

### Fixed journal ownership and footprint

`EffectJournalV1` has a projected exact size of 2,072 bytes:

| Field | Type | Bytes |
| --- | --- | ---: |
| lifecycle state | `u8` | 1 |
| committed record count | `u8` | 1 |
| reserved record count | `u8` | 1 |
| reserved zero | `[u8; 5]` | 5 |
| object generation | `u64` | 8 |
| next record sequence | `u64` | 8 |
| records | `[EffectRecordV1; 16]` | 2,048 |

The state area is 24 bytes and the record array is 2,048 bytes. Combined with
the existing 3,112-byte `Runtime`, `JournaledRuntime` therefore has a projected
exact size of 5,184 bytes. OS032 must enforce both exact sizes with compile-time
assertions and retain the existing 64 KiB runtime bound. These are contract
sizes for the future implementation, not claims about code delivered by
OS018.

The journal has exactly 16 record slots. It never allocates, overwrites,
rotates, clears, or acknowledges individual records. Sequence or capacity
exhaustion fails closed. The fixed object ID and initial nonzero generation are
both `1`; generation must never wrap.

The journal lifecycle is `Building`, `Live`, `Sealed`, then `Dead`:

- `Building` is not resolvable and may be cleared by construction rollback;
- `Live` admits lifecycle reservations, appends, inspection, and reads;
- `Sealed` admits inspection and reads but no new lifecycle or append; and
- `Dead` is cleared and cannot be resolved, inspected, or read.

Construction creates the journal in `Building`, prepares the existing
supervised runtime state, and installs the journal handle as the final entry in
the still-building supervisor table. It makes the journal `Live` before that
table becomes resolvable. Any failure reverses only completed steps: remove the
journal handle, clear the journal object, then delegate to the existing OS031
rollback order. The public `Runtime::new_supervised` construction path and its
three supervisor handles remain unchanged.

### `EffectRecordV1`

Every record is an immutable, C-compatible, 128-byte value with this exact
layout:

| Offset | Field | Type |
| ---: | --- | --- |
| 0 | `schema_version` | `u32` |
| 4 | `byte_size` | `u32` |
| 8 | `event_kind` | `u32` |
| 12 | `status` | `u32` |
| 16 | `record_sequence` | `u64` |
| 24 | `decision_epoch` | `u64` |
| 32 | `principal_id` | `u64` |
| 40 | `actor_task_id` | `u64` |
| 48 | `actor_task_generation` | `u64` |
| 56 | `subject_task_id` | `u64` |
| 64 | `subject_task_generation` | `u64` |
| 72 | `request_sequence` | `u64` |
| 80 | `action_id` | `u64` |
| 88 | `capability_object_type` | `u32` |
| 92 | `reserved_zero` | `u32` |
| 96 | `capability_object_id` | `u64` |
| 104 | `capability_object_generation` | `u64` |
| 112 | `capability_rights` | `u64` |
| 120 | `reserved_zero` | `u64` |

`schema_version` is `1`, `byte_size` is `128`, and both reserved fields are
zero. `record_sequence` begins at `1`, increases by one for every committed
record, and never wraps. It is the total-order clock; the journal makes no
wall-clock or elapsed-time claim. `decision_epoch` copies the epoch of the
accepted broker transition, or the current request epoch for `Requested`.

The event kinds are fixed:

| Value | Kind | Status |
| ---: | --- | --- |
| 1 | `Requested` | `Ok` |
| 2 | `Approved` | `Ok` |
| 3 | `Denied` | `ApprovalDenied` |
| 4 | `Expired` | `ApprovalExpired` |
| 5 | `Completed` | `Ok` |
| 6 | `Failed` | exact terminal failure, initially `EffectUnavailable` |

The record contains no inline argument, result value, prompt or content,
credential, secret, raw capability handle, user pointer, byte buffer, or
arbitrary payload. It stores the capability entry's resolved object type, ID,
generation, and exact exercised right. This permits attribution without
mistaking a task-local selector for durable identity or retaining the request
parameter.

Actor and subject fields use these exact bindings:

| Event | Actor | Subject | Capability attribution |
| --- | --- | --- | --- |
| `Requested` | workload | workload | `ApprovalBroker/SUBMIT_APPROVAL` |
| explicit `Approved`, `Denied`, `Expired` | supervisor | workload | `ApprovalBroker/DECIDE_APPROVAL` |
| teardown `Denied`, `Expired` | kernel (`0`, `0`) | workload | `ApprovalBroker`, rights `0` |
| `Completed`, `Failed` | supervisor | workload | `TestEffect/COMMIT_EFFECT` |

`principal_id` remains the manifest's boot-local principal. It is attribution,
not evidence of an authenticated person or remote service.

Task ID and generation zero are reserved as the version-one kernel actor. A
teardown-generated terminal record uses that pair because no task presented a
handle: pending teardown records `Denied/ApprovalDenied`, approved teardown
records `Expired/ApprovalExpired`, the capability object fields identify the
broker whose lifecycle is being closed, and `capability_rights` is zero. It
must not claim that the supervisor exercised `DECIDE_APPROVAL`. All non-teardown
records require a nonzero actor and the exact resolved object and right shown
above.

### Complete-lifecycle reservation

An accepted lifecycle must never be left without capacity for its terminal
record. Submit therefore requires three free records and enough non-wrapping
sequence space before it can mutate broker, task, queue, effect, or journal
state.

1. Accepted submit appends `Requested` and reserves two remaining records.
2. Accepted approval consumes one reservation for `Approved` and retains one
   reservation for `Completed`, `Failed`, or post-approval `Expired`.
3. A pending explicit `Denied` or `Expired` result, or a teardown-generated
   pending `Denied`, consumes one reservation and releases the unused second
   reservation.
4. An approved `Completed`, `Failed`, or `Expired` result consumes the final
   reservation and closes the lifecycle.

The record append and corresponding OS031 state transition are one atomic
operation. If capacity, sequence, or journal state cannot support the required
record, the operation returns a categorical failure and leaves task, broker,
approval, effect, queue, capability, and journal contents unchanged. A full or
sequence-exhausted journal rejects submit with `JournalFull`; a journal outside
its permitted lifecycle returns `JournalUnavailable`.

Malformed, unauthorized, wrong-handle, wrong-right, wrong-type,
wrong-generation, replayed, second-use, and altered-parameter attempts are not
accepted lifecycles. They consume no journal capacity and preserve the existing
OS031 state and error precedence.

Within `JournaledRuntime` only, an exact approval-matched commit against an
already occupied synthetic effect is an accepted terminal `Failed` event with
`EffectUnavailable`. It consumes the approval, wakes the workload, and leaves
the effect value unchanged. This refined terminal behavior does not alter
`Runtime::new_supervised` or its OS031 tests and QEMU transcript.

### Read-only journal capability

OS032 will extend the fixed capability tags with `EffectJournal = 5` and add
`READ_EFFECT_JOURNAL = 1 << 7`. Only the trusted supervisor receives that exact
right. In the journaled reference profile it is the supervisor's fourth handle,
expected to encode as `0x13`; the workload receives no journal handle or route.
The handle is non-duplicable and non-transferable under the existing fixed
capability rules.

Capability resolution validates task, table, selector generation, object type,
object generation, lifecycle, and exact read right before returning journal
metadata. Raw handle values are never written into a record.

### Three-register read ABI

The DPL3 trap ABI gains two operations only for the journaled profile:

- operation `11`, `InspectEffectJournal`: input `RDI = journal_handle`, with
  `RSI = 0` and `RDX = 0`; output `RAX = status`, `RDI = first_sequence`
  (always `1` for a nonempty version-one journal, otherwise `0`),
  `RSI = next_record_sequence`, and `RDX = committed_record_count`;
- operation `12`, `ReadEffectRecord`: input `RDI = journal_handle`,
  `RSI = record_sequence`, and `RDX = triplet_index` from `0` through `5`;
  output `RAX = status` and three consecutive little-endian `u64` record words
  in `RDI`, `RSI`, and `RDX`. Triplet `5` returns word `15` in `RDI` and zero
  padding in `RSI` and `RDX`.

The first two words combine the adjacent 32-bit header and event fields in
their C-layout byte order. Because committed records never change, multiple
trap reads of one record are consistent without a snapshot token or user
pointer. An absent sequence or triplet outside `0..=5` returns `InvalidRecord`
and no record data.

OS032 may append only these categorical statuses after OS031's
`AlreadyLaunched = 20`: `JournalFull = 21`, `JournalUnavailable = 22`, and
`InvalidRecord = 23`. Existing operation and status numbers cannot change.

### Teardown and final inspection

Journal obligations precede reachability removal. Normal task or complete
profile teardown must:

1. append the required terminal event for a live request or approval before
   sealing the journal or closing its supervisor handle, using the kernel actor
   and zero-right attribution when teardown rather than a supervisor trap
   causes the transition;
2. resolve approval and broker references before capability tables, task
   contexts, address spaces, mappings, or frames;
3. when no later effect can be accepted, make the journal `Sealed` while any
   still-live supervisor read handle remains valid for bounded export;
4. close task capabilities and complete the existing approval-first,
   handle-first reverse teardown;
5. retain the sealed journal object after task teardown so the kernel can
   perform final read-only verification; and
6. verify all records, clear the wrapper journal, and publish it `Dead` before
   reclaiming the complete journaled profile.

The journal does not survive runtime reclamation or reboot. `Sealed` permits a
bounded supervisor inspection while its handle remains live and direct kernel
inspection after task teardown; it is not persistence, a crash log, or an
external export guarantee.

### Deterministic OS032 reference scenario

The future pinned QEMU `qemu64` one-vCPU scenario must preserve every earlier
terminal record and then generate exactly 11 journal records in this order:

1. request, then deny: two records;
2. request, approve, then expire: three records;
3. request, approve, then complete: three records; and
4. request, approve, then fail because the synthetic effect is occupied: three
   records.

The supervisor reads the complete fixed records through operations `11` and
`12` and compares all schema, event, status, ordering, epoch, principal, task,
capability, and reserved-zero fields. The expected table is 1,408 bytes
(`11 * 128`) and may remain inline in the supervisor's read-only text page.
No pointer crosses into the kernel.

The current linked supervisor and workload probes measure 556 and 116 bytes,
respectively, within the existing 4,096-byte user text-page limit. OS032 must
re-measure the resulting probes and assert that the expected table, compact
read loop, and code remain within their linked bounds. Only after all task,
approval, effect, capability, address-space, frame, reservation, and journal
checks pass may the reference image emit:

```text
MakopaOS effects v1 ok ordered-redacted
```

These sizes establish feasibility for the accepted contract; OS018 does not
add the table, loop, probe code, or terminal record.

## Verification contract for OS032

Host tests must demonstrate:

- exact `EffectRecordV1` layout, size, offsets, version, and reserved-zero
  fields, plus exact 2,072-byte journal and 5,184-byte wrapper sizes;
- the unchanged 3,112-byte `Runtime`, both existing constructors, every OS030
  and OS031 state-machine test, and all prior teardown outcomes;
- all accepted request-deny, request-approve-expire,
  request-approve-complete, and request-approve-fail record sequences;
- nonzero monotonic record and request sequences, exact decision epochs,
  actor, subject, principal, task generation, resolved capability object and
  right attribution, explicit kernel-actor and zero-right teardown attribution,
  and no request argument or result payload;
- three-slot admission, reservation consumption and release, the 16-slot
  boundary, non-wrapping exhaustion, atomic failure, and no missing terminal
  event;
- rejection of wrong task, handle, right, object type, object generation,
  journal state, record sequence, and triplet index without mutation;
- record immutability across repeated multi-trap reads and zero padding for the
  final triplet;
- no capacity consumption for malformed, unauthorized, replayed, second-use,
  or altered-parameter attempts; and
- rollback, terminal-before-seal, approval-first and handle-first teardown,
  sealed final inspection, and complete wrapper reclamation.

Machine-code and repository inspection must preserve complete trap-frame
capture, CPL-aware exception frames, recovery-root-first Rust dispatch,
non-returning complete-context resume, the existing dependency-free runtime,
and the exact dependency-feature and locked-audit evidence. It must prove both
new operation numbers, all expected probe sequences, the absence of a
pointer-based journal interface, and linked supervisor, workload, table, and
text-page sizes.

The pinned QEMU `qemu64` one-vCPU gate must preserve all prior boot records,
compare all 11 records, prove redaction and empty terminal state, and emit the
exact new terminal record. Host, format, lint, dependency-feature, audit,
disassembly, legacy-image, and QEMU evidence remain in the existing single
read-only CI job. OS032 may add evidence to that job but cannot change its
topology, permissions, or dependency policy without separate approval.

OS032 must not claim durable audit, crash recovery, tamper resistance,
cryptographic non-repudiation, authenticated principal identity, human
approval, wall-clock ordering, external export, external schema conformance,
real effects, general workload support, or availability under exhaustion.

## Alternatives considered

### Embed the journal in `Runtime`

Rejected. It would enlarge the base and supervised profiles and blur the exact
3,112-byte OS031 footprint. A wrapper makes the new evidence boundary explicit
and keeps every earlier constructor and proof intact.

### Reuse the endpoint or inline IPC slot

Rejected. The endpoint is consuming and mutable, holds one untyped value, and
cannot provide immutable ordered lifecycle evidence or retain it through task
teardown.

### Read one word per trap

Rejected. It would multiply the fixed probe and transition surface without
adding safety. Three-word reads use the admitted registers and still avoid
user pointers.

### Copy records through a user pointer or buffer

Rejected. User-memory validation, copy limits, partial-copy semantics, and
time-of-check/time-of-use behavior are unnecessary for 16 immutable records.

### Overwrite old entries in a ring

Rejected. Silent loss would make an accepted lifecycle incomplete. Fixed
reservation and explicit `JournalFull` preserve evidence or reject before the
effect lifecycle begins.

### Use dynamic storage or an external telemetry schema in the kernel

Rejected. Allocation, reclamation, protocol versioning, and exporter policy do
not belong in the first kernel mechanism proof. A later user-space monitor may
map these fixed records to OpenTelemetry or another maintained schema.

### Retain raw parameters or hashes

Rejected. Parameters may contain credentials or sensitive content, and hashes
of low-entropy values can still disclose them by enumeration. Resolved object
identity and categorical outcome provide the required evidence without the
payload.

### Add a cryptographic hash chain

Rejected. A volatile kernel structure without protected durable storage cannot
honestly provide tamper resistance or non-repudiation. Cryptography would add
dependencies and a key boundary without strengthening this boot-local proof.

### Use wall-clock timestamps

Rejected. MakopaOS has no clock contract. Monotonic record sequence and the
existing decision epoch state exactly what the runtime can prove.

## Consequences

- Earlier runtime profiles retain their exact behavior and footprint.
- Every accepted journaled lifecycle has capacity reserved for a terminal
  record or is rejected without state change.
- Records are deterministic, bounded, immutable, attributable, and redacted,
  but intentionally volatile and accessible only to the trusted supervisor.
- The supervisor can read evidence but cannot alter, clear, rotate, or consume
  it.
- A 16-record journal admits only a small number of complete lifecycles and can
  deny later requests; this is an explicit bounded-capacity result, not an
  availability guarantee.
- The fixed schema can be mapped by a future user-space exporter without
  binding the kernel ABI to OpenTelemetry, CloudEvents, or another protocol.
- OS032 remains required before MakopaOS can claim executable structured-effect
  evidence.

## Rollback and reconsideration

Replace this decision before OS032 if the wrapper cannot preserve exact base
`Runtime` layout and behavior, if complete-lifecycle reservation cannot be
atomic with broker transitions, if the three-register reads cannot be proven
pointer-free, or if the journal cannot remain readable through final task
teardown without retaining task-owned frames. A replacement must retain
bounded non-overwriting storage, redaction, resolved capability attribution,
explicit capacity failure, immutable read-only access, terminal completeness,
and reverse-order cleanup.

Reconsider capacity and export only after dynamic kernel objects or an isolated
audit service have their own ownership and failure contracts. Reconsider
durability and tamper evidence only with protected storage, boot identity, key
management, and recovery semantics. Reconsider timestamps only after a
monotonic clock exists. External telemetry schemas remain user-space adapter
decisions.

## References

- [ADR-0004: Cooperative scheduler and inline IPC](0004-cooperative-scheduler-and-inline-ipc.md)
- [ADR-0005: Task-local capability handles](0005-task-local-capability-handles.md)
- [ADR-0006: Fixed supervisor and approval broker](0006-fixed-supervisor-and-approval-broker.md)
- [GitHub: Agent Control Plane audit-log attribution](https://github.blog/changelog/2026-02-26-enterprise-ai-controls-agent-control-plane-now-generally-available/)
- [NIST SP 800-53 Rev. 5.1, AU-4 and AU-5](https://csrc.nist.gov/CSRC/media/Projects/risk-management/800-53%20Downloads/800-53r5/SP_800-53_v5_1-derived-OSCAL.pdf)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OpenTelemetry Logs Data Model](https://opentelemetry.io/docs/specs/otel/logs/data-model/)
