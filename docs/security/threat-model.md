# Threat model

Status: Initial

MakopaOS is educational software, not a production security boundary. Its
architecture nevertheless treats isolation claims as testable contracts.

## Protected properties

- kernel memory is inaccessible to unprivileged tasks;
- one task cannot use another task's authority without an explicit transfer;
- external content cannot grant authority;
- accepted effects are attributable to a task and capability without exposing
  secret values;
- build inputs and generated images are reviewable and reproducible;
- a physical frame is not allocated twice unless its prior owner successfully
  returns it to the allocator;
- a frame returned by an address-space owner is no longer reachable through an
  active mapping, temporary alias, or stale mapping token; and
- an expected unprivileged fault cannot resume the faulting task or corrupt the
  kernel recovery context;
- one cooperative task cannot inherit another task's integer register or
  address-space context; and
- bounded IPC cannot expose a user pointer, retain an exited receiver's value,
  or leave a live endpoint generation after teardown;
- a zero, empty, closed, stale, cross-table, wrong-object, or wrong-right handle
  cannot authorize endpoint access or partially mutate runtime state; and
- address-space frames cannot be returned while the task's capability table or
  endpoint side still references live state.

The supervised runtime profile additionally protects these properties within
the fixed OS031 reference boundary:

- a staged workload cannot run or resolve a capability before its complete
  immutable launch manifest publishes;
- a route absent from the manifest cannot become workload authority;
- a workload cannot commit the synthetic high-impact effect because only the
  trusted supervisor holds the effect capability; and
- an approval authorizes only one commit whose principal, task, action,
  resource, inline argument, rights, generations, sequence, and decision epoch
  match the approved request.

The planned OS032 journaled profile must additionally protect these properties
before its evidence claim can close:

- an accepted approval or effect lifecycle either reserves room for its
  terminal record or is rejected without runtime mutation;
- a journal record is immutable, totally ordered, attributable through resolved
  capability identity, and free of request arguments, results, selectors,
  credentials, pointers, and arbitrary payloads;
- only the trusted supervisor's live read capability can inspect the journal;
  the workload cannot receive or mint that authority; and
- task teardown cannot erase a required terminal event or retain task-owned
  frames merely to keep the boot-local journal readable.

## Initial adversaries and failures

- malformed or hostile binaries;
- overlapping, truncated, misaligned, or incorrectly addressed kernel ELF
  segments;
- malformed, overlapping, overflowing, or incorrectly classified boot memory
  regions and framebuffer ranges;
- duplicate, unaligned, unmanaged, or overflowing frame returns and allocator
  fragmentation that exhausts bounded metadata;
- malformed page-table entries, unintended user access to supervisor mappings,
  writable executable pages, stale address-space identifiers, and teardown
  that returns a still-mapped frame;
- a user fault misclassified because of the wrong task, privilege level,
  address, access kind, page-fault cause, or exception-frame layout;
- kernel, user, or double-fault stack exhaustion crossing an unguarded mapping;
- firmware protocol handles, allocations, or references used after boot
  services exit;
- invalid pointers, lengths, handles, and IPC messages;
- confused-deputy requests through a privileged service;
- missing, duplicated, over-righted, stale, or partially published manifest
  routes;
- approval-slot exhaustion, parameter alteration, stale generations, replayed,
  expired, duplicated, or second-use approvals;
- journal capacity or sequence exhaustion, incomplete lifecycle reservation,
  unauthorized reads, malformed record selectors, and teardown before a
  required terminal record;
- a hostile workload attempting to mint task-control, decision, or direct
  effect authority;
- a compromised trusted supervisor approving or committing an unsafe request;
- malicious instructions embedded in repository, web, or message content;
- compromised dependencies or mutable CI actions;
- accidental contributor overreach and undocumented architecture drift.

## Required controls

- memory-safe implementation outside narrow reviewed architecture shims;
- bounded ELF parsing before allocation, with an executable entry constrained
  to a loaded segment at or above 1 MiB;
- no live firmware protocols or heap-backed values across `ExitBootServices`;
- a versioned, fixed-layout handoff held in loader-owned storage until kernel
  entry;
- bounded final-map normalization that keeps live kernel and framebuffer pages
  outside usable memory and defers loader-page reclamation;
- kernel-owned managed and free extent tables seeded only from exact
  `MEMORY_USABLE` records, with no retained handoff reference;
- checked lowest-address allocation and state-preserving rejection of invalid
  or capacity-exceeding frame returns;
- reviewed `UnsafeCell` singleton boundaries for the frame allocator, fixed
  paging state, and cooperative scheduler while interrupts remain disabled and
  no timer, SMP, or reentrant caller exists;
- a kernel-owned four-level recovery root that never adopts inherited UEFI page
  tables, enforces supervisor W^X and NX mappings with `CR0.WP`, and uses
  guarded recovery and double-fault stacks;
- closure-scoped access to arbitrary frames through one supervisor-only
  temporary window whose mapping changes carry explicit TLB invalidation;
- stable assembly exception trampolines with asserted frame layouts and exact
  task, CPL, `CR2`, and error-code checks before a user fault is contained;
- checked address-space lifecycle transitions, stale-generation rejection, and
  teardown that switches to the recovery root, unmaps and invalidates aliases,
  proves frames unreachable, and only then returns them to the allocator;
- a DPL3 interrupt-gate ABI whose stable naked entry captures every admitted
  GPR and switches to the recovery root before Rust can inspect task state;
- validated, integer-only contexts with `CR4.FSGSBASE` clear, zero user FS/GS
  bases, fixed selectors, canonical instruction and stack pointers, and masked
  `IF`, `DF`, and `IOPL` flags;
- exactly two generation-bound task slots, unique deterministic FIFO membership,
  one running task, and reverse-order teardown before another root is resumed;
- one fixed endpoint with explicit occupancy and one inline `u64`, exact
  state-preserving rejections, block/wake and peer-close behavior, and no user
  pointers, byte lengths, or shared mappings;
- one kernel-owned 16-slot capability table per fixed task, with typed endpoint
  entries, non-empty `SEND`, `RECEIVE`, and `DUPLICATE` rights, subset-only
  same-task duplication, non-wrapping slot generations, and table-local lookup;
- handle-first teardown that closes every table entry before detaching endpoint
  and task references and before address-space invalidation and frame return;
- an immutable, statically registered, fixed-layout launch manifest whose
  complete capability route set validates before the staged workload becomes
  runnable and whose absent routes deny authority by default;
- fixed task-control, approval-broker, and synthetic-effect capability types
  with object-specific rights and no duplication or cross-task transfer;
- one bounded kernel approval slot that canonically binds principal, task,
  action, resource, argument, rights, generations, sequence, and decision epoch;
- single-use effect commit that validates the trusted supervisor's live effect
  capability and the complete unexpired approval before atomically mutating the
  synthetic effect and consuming the approval;
- non-wrapping request sequences and boot-local decision epochs, with explicit
  deterministic expiry and no wall-clock or availability claim;
- rollback and teardown that remove broker, approval, and effect references
  before capability entries, task and address-space references, mappings, and
  owned frames;
- for OS032, a separate fixed journal wrapper that leaves existing runtime
  profiles unchanged, reserves complete lifecycle capacity before submit,
  appends immutable redacted records atomically with accepted transitions,
  exposes only typed supervisor read access, seals after terminal recording,
  and is cleared after final kernel verification;
- typed validation at every privilege and protocol boundary;
- bounded queues and slots, explicit failure, cancellation, expiry, and replay
  protection at each implemented boundary;
- separate approval enforced by the effect executor before irreversible or
  externally visible effects are introduced;
- read-only automation permissions unless a work item requires more;
- pinned workflow actions and explicit build-tool versions;
- deterministic tests for every security invariant before phase promotion.

## Deferred threats

Physical access, hostile firmware, speculative-execution side channels,
availability under resource exhaustion, compiler compromise, cryptographic
identity, secure boot, hardware attestation, SMP TLB shootdowns, PCID, global
mappings, SMEP, and SMAP remain deferred until the relevant subsystem exists.
A roadmap item that introduces one of those boundaries must update this
document before claiming coverage.

## OS030 residual boundary

The current containment and scheduling proof is deliberately narrow: two fixed
integer-only probes run cooperatively on one emulated `qemu64` CPU with maskable
interrupts disabled. The recovery root, guard pages, CPL-aware exception
parsing, dedicated double-fault IST path, complete GPR switch, fixed FIFO, one
inline endpoint, task-local 16-slot capability tables, rights attenuation,
stale-handle rejection, and handle-first reverse-order teardown are exercised
by host, disassembly, and QEMU gates. Selectors are not secret bearer tokens,
and the evidence does not establish timer-preemptive scheduling, interrupt
concurrency, SMP TLB coherence, SIMD or TLS switching, cross-task transfer,
recursive revocation, dynamic tasks or objects, policy approval, effect
logging, arbitrary user-binary loading, or real-hardware compatibility. Any
such expansion must first define its synchronization, authority, ownership,
invalidation, and rollback contract.

## OS031 residual boundary

ADR-0006 deliberately trusts task `1` as the fixed supervisor and treats task
`2` as hostile. The implemented kernel mechanism proves staged launch,
default-deny routes, task-local authority, exact request binding, deterministic
decision-epoch expiry, and one atomic synthetic-effect commit. The effect is an
in-memory test cell and the fixed supervisor decision vector is not a human,
credential, authentication, or user-interface boundary.

A compromised supervisor can use its task-control, decision, and effect
capabilities to approve the fixed action and is therefore outside OS031's
containment claim. OS031 also does not cover dynamic objects, cross-task
transfer, recursive revocation, general policy evaluation, real device,
network, storage, or credential effects, durable effect logging, wall-clock
deadlines, preemptive availability, external authorization protocols, or
arbitrary workloads. OS032 remains the separate decision and implementation
boundary for ordered, bounded, redacted effect records.

## OS032 planned evidence boundary

ADR-0007 selects a separate `JournaledRuntime` wrapper for the future OS032
proof. It does not change the implemented OS031 `Runtime` or claim that effect
records exist today. The planned journal has 16 immutable boot-local records,
reserves three slots before accepting a request, exposes only resolved
principal, task, action, capability, epoch, and categorical outcome fields, and
admits read access only through the trusted supervisor's typed capability.

That boundary can prove deterministic ordering, payload minimization, explicit
capacity failure, complete terminal outcomes, read-only access, and teardown
ordering for the fixed synthetic effect. It cannot prove durable audit, crash
recovery, tamper resistance, cryptographic non-repudiation, authenticated
principal identity, human approval, wall-clock order, availability under
exhaustion, external telemetry conformance, real device or network effects, or
containment of a compromised supervisor. Those claims require separate storage,
identity, time, exporter, executor, and recovery decisions.
