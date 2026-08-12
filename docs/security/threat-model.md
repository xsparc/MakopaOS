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
  kernel recovery context.

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
- replayed, expired, or duplicated approvals;
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
- reviewed `UnsafeCell` singleton boundaries for the frame allocator and
  fixed kernel paging state while interrupts remain disabled and no scheduler,
  SMP, or reentrant caller exists;
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
- deny-by-default capability manifests;
- typed validation at every privilege and protocol boundary;
- bounded queues, timeouts, cancellation, and replay protection;
- separate approval for irreversible or externally visible effects;
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

## OS021 residual boundary

The current containment proof is deliberately narrow: one fixed probe runs on
one emulated `qemu64` CPU with maskable interrupts disabled. The recovery root,
guard pages, CPL-aware exception parsing, dedicated double-fault IST path, and
reverse-order teardown are exercised by host and QEMU gates, but they do not
establish scheduler safety, interrupt concurrency, SMP TLB coherence, arbitrary
user-binary loading, or real-hardware compatibility. Any expansion beyond the
single synchronous probe must first add the missing synchronization and
cross-context invalidation contract.
