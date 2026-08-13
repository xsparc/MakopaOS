# MakopaOS implementation roadmap

- Status: Active; item states are recorded below
- Baseline: `5d5a49de783dae05abbd4abc6f21b458aee640f9`
- Updated: 2026-08-13

This roadmap turns the architecture into reviewable vertical slices. Proposed
items describe sequence, not implementation authority. Each item should ship in
its own pull request unless a maintainer explicitly changes the boundary.

## Phase 0: Reproducible baseline

### OS001 — Boot-sector verification

Status: Closed

Scope:

- assemble `boot.asm` in CI;
- verify the exact image size, boot signature, and message payload;
- document the repository contract and target architecture.

Acceptance:

- a clean Ubuntu runner builds the boot sector with NASM warnings treated as
  errors;
- the verifier rejects a non-512-byte image, a missing `0x55AA` signature, or a
  missing `MAKOPA` payload;
- pull requests and pushes to `main` run the same gate with read-only token
  permissions.

Non-scope: boot behavior changes, UEFI code, kernel scaffolding, releases.

### OS002 — Project evidence gate

Status: Closed

Depends on: OS001

Define a MakopaOS-native, non-authoritative traceability index linking objectives,
requirements, roadmap work, design, implementation, verification, validation,
and risk. Add an offline checker without importing another project's identity or
approval rules.

Acceptance: the checker rejects missing and unsafe references, unknown IDs,
unindexed accepted decisions, stale reviews, and implemented requirements
without verification evidence; a strict mode is part of CI.

Non-scope: architecture promotion, research disposition, kernel code, release
automation, and external publication behavior.

### OS003 — 2026-Q3 standards baseline refresh

Status: Closed

Depends on: OS002

Refresh the architecture's external baselines and promote the accepted research
dispositions that affect future boot, authority, component, protocol, and
provenance decisions.

Acceptance:

- architecture references identify MCP `2026-07-28`, A2A `1.0.1`, and stable
  WASI 0.3 as the current protocol and component-study baselines;
- OS010 records monitored Rust and UEFI candidates without pinning a toolchain
  before its decision;
- OS031, OS032, OS040, and OS051 include the applicable security and
  version-specific acceptance criteria derived from the accepted research;
- accepted and monitored findings are review-dated in the project evidence
  registry, and the dated strict evidence gate passes.

Non-scope: code, dependencies, toolchain installation, boot behavior, CI
topology, release automation, protocol implementation, and phase promotion.

## Phase 1: Modern boot handoff

### OS010 — Toolchain and boot-contract decision

Status: Closed

Depends on: OS003

Record the pinned Rust, NASM, QEMU, firmware, target, and linker contract. Define
the versioned x86-64 boot handoff and decide whether the initial UEFI loader is
owned or delegated to a maintained loader.

Decision: [ADR-0001](../architecture/decisions/0001-uefi-loader-and-boot-handoff.md)
selects a thin MakopaOS-owned UEFI loader and a versioned, firmware-neutral
handoff. It pins Rust `1.97.1`, `uefi` `0.39.0`, UEFI `2.11`, the
`x86_64-unknown-uefi` and `x86_64-unknown-none` targets, the toolchain-bundled
`rust-lld`, Ubuntu snapshot `20260810T000000Z`, NASM `2.16.01-1build1`,
`qemu-system-x86` `1:8.2.2+ds-0ubuntu1.18`, and OVMF `2024.02-2ubuntu0.9`.

Acceptance: the accepted decision compares the owned and maintained-loader
paths, defines entry state and handoff compatibility, records validation and
rollback conditions, and identifies exact inputs that future CI can provision.
The direct RustSec package review is recorded as a point-in-time check; OS011
must audit its committed dependency lockfile.

Non-scope: code, dependencies, CI changes, boot behavior, phase promotion,
release automation, Secure Boot, and hardware support. OS011 implements this
accepted baseline without changing the decision.

### OS011 — x86-64 kernel entry

Status: Closed

Depends on: OS010

Boot a `no_std` Rust kernel through UEFI, write a version string to the serial
console, and halt cleanly.

Acceptance: QEMU exits through a deterministic test device after matching the
expected serial transcript; the legacy BIOS sector remains buildable.

Delivery: the pinned Rust workspace builds a MakopaOS-owned UEFI loader and
freestanding kernel. The loader validates bounded ELF64 load segments, releases
all firmware protocols and heap-backed values before `ExitBootServices`, and
enters the kernel with the ADR-0001 System V ABI. CI boots a read-only VVFAT ESP
under the pinned QEMU and OVMF packages, verifies `isa-debug-exit` support,
requires the exact `MakopaOS 0.1.0` serial transcript, audits `Cargo.lock` with
`cargo-audit` `0.22.2`, and preserves the legacy BIOS gate.

Non-scope: populated memory-map or framebuffer handoff fields, allocators,
interrupt handling, hardware drivers, Secure Boot, releases, and phase
promotion. These boundaries remain assigned to later work, beginning with
OS012.

### OS012 — Boot handoff validation

Status: Closed

Depends on: OS011

Pass and validate a versioned handoff containing the memory map and framebuffer
metadata.

Acceptance: unit tests reject incompatible versions, sizes, flags, pointers,
counts, kinds, attributes, malformed ranges, overlaps, arithmetic overflow,
invalid framebuffer metadata, unsafe loader-storage classifications, and
normalization overflow. The pinned QEMU smoke test covers one valid non-empty
memory map with RGB or BGR framebuffer metadata.

Delivery: the loader allocates bounded handoff storage before
`ExitBootServices`, captures only numeric GOP metadata while its protocol is
live, sorts and normalizes the returned final memory map into at most 1,024
fixed-size records (24 KiB), and applies protected overrides for loaded kernel
pages. The framebuffer is overlaid wherever its page-rounded range intersects
the firmware map and remains valid when its MMIO range is not map-described.
Conventional memory becomes usable; loader and former boot-service memory
remains loader-reclaimable until a later kernel slice performs the required
copy and reclamation transition. The kernel validates the complete version-one
structure before using any region and emits the deterministic terminal record
`MakopaOS handoff v1 ok framebuffer` on the pinned reference machine.

Non-scope: allocating or reclaiming frames, copying the normalized map into a
new kernel allocator, changing page tables or stacks, interrupts, drivers,
toolchain or dependency changes, CI topology, releases, and phase promotion.

## Phase 2: Kernel mechanics

### OS013 — Frame ownership and early-allocation decision

Status: Closed

Depends on: OS012

Record how the kernel takes ownership of eligible physical-memory ranges and
select the first deterministic frame-allocation representation before OS020
adds allocator code.

Decision: [ADR-0002](../architecture/decisions/0002-frame-ownership-and-early-allocation.md)
selects kernel-owned, fixed-capacity sorted extent tables. Initialization copies
only `MEMORY_USABLE` ranges from the validated handoff; no handoff reference is
retained. Loader-reclaimable, ACPI, MMIO, framebuffer, kernel, and reserved
storage remain excluded pending an explicit later reclamation transition.

Acceptance: the accepted decision compares bitmap, buddy, intrusive-list, and
monotonic alternatives; defines lowest-address allocation, checked free and
coalescing behavior, fixed-capacity failure semantics, host evidence, and a
deterministic QEMU reuse sequence; and corrects the Rust `1.97.1` release-note
date without changing the pin.

Non-scope: code, dependencies, CI changes, boot behavior, frame allocation or
reclamation, stack switching, page tables, synchronization, releases, and phase
promotion. OS020 implements this accepted boundary without changing the
decision.

### OS020 — Physical frame allocator

Status: Closed

Depends on: OS013

Implement the kernel-owned, fixed-capacity sorted-extent allocator selected by
ADR-0002. After handoff validation, copy only `MEMORY_USABLE` ranges into
immutable managed extents and mutable free extents; retain no handoff reference.
Allocate the lowest available physical frame and recycle checked frees with
sorted coalescing.

Acceptance: deterministic host tests cover copied ownership, usable-only
seeding, exhaustion, multi-extent ordering, alignment, reserved ranges,
left/right/two-sided coalescing, and state-preserving rejection of duplicate,
unaligned, unmanaged, overflowing, and capacity-exceeding frees. QEMU allocates
frames A and B, frees A, reallocates A, and emits the exact terminal record
`MakopaOS frames v1 ok reuse`.

Delivery: a `no_std` library with only the local boot-contract dependency owns
two fixed 1,024-entry extent tables and validates the complete source map in a
first pass before filling state in place. The non-cloneable allocator reports
distinct initialization, allocation, and free errors and preserves state on
rejected operations. The kernel places one immutable wrapper around the
allocator in `.bss`, confines interior mutability to a documented `UnsafeCell`
boundary, and initializes it only after handoff validation. Host tests include
a reference model, fragmentation and coalescing cases, failed-reinitialization
checks, source-map lifetime independence, and a 40 KiB metadata ceiling. The
existing CI job runs the library tests and extends the pinned QEMU transcript
without adding a job, permission, tool, or third-party dependency.

Non-scope: loader-reclaimable memory, multi-frame allocation, dynamic allocator
metadata, page-table or stack changes, synchronization, interrupts, releases,
and phase promotion.

### OS014 — Address-space and fault-containment decision

Status: Closed

Depends on: OS020

Record the owned x86-64 paging, privilege-transition, exception-entry,
address-space ownership, and teardown contract required before OS021 changes
page tables or enters user mode.

Decision:
[ADR-0003](../architecture/decisions/0003-address-space-and-fault-containment.md)
selects four-level 4 KiB paging, a statically bounded kernel recovery root,
guarded recovery and double-fault stacks, a single temporary mapping window,
stable assembly exception trampolines, a fixed ring-3 probe, and explicit
address-space lifecycle and frame-return ordering.

Acceptance: the accepted decision defines supervisor W^X and NX mappings,
fixed virtual addresses and table bounds, stable exception-frame ownership,
exact user-fault classification and recovery, state-preserving construction
rollback, stale-owner rejection, and unmap and invalidation before frame reuse.
It specifies the deterministic host and QEMU evidence OS021 must provide.

Non-scope: code, dependencies, CI changes, boot behavior, page-table or stack
changes, interrupt activation, user-mode execution, releases, and phase
promotion. OS021 implements the accepted contract without changing the
decision.

### OS021 — Address-space isolation

Status: Closed

Depends on: OS014

Install the ADR-0003 kernel recovery context, create one separately owned
address space with guarded supervisor mappings, enter the fixed ring-3 probe,
and contain its expected invalid write.

Acceptance: host tests cover mapping permissions, fixed bounds, lifecycle
transitions, partial-construction rollback, stale-owner rejection, temporary-
window invalidation, and unmap-before-free ordering. The pinned QEMU gate
switches from inherited state to the owned recovery root and guarded stack,
enters ring 3, validates the exact task, CPL, `CR2`, and page-fault error code,
returns to the recovery context without resuming the faulting instruction,
tears down every task-owned frame, and emits the exact terminal record
`MakopaOS isolation v1 ok user-fault-contained` before the existing success
exit.

Delivery: the stable-only kernel pins `x86_64` `0.15.5` with only its
`instructions` feature, builds a bounded four-level recovery root, switches to
guarded recovery and dedicated double-fault IST stacks, and installs
CPL-aware stable naked exception trampolines. One seven-frame task address
space runs the fixed ring-3 write probe. The page-fault path accepts only the
active task root, CPL 3, target address, and `0x06` error code, switches back to
the recovery root without resuming the probe, and performs reverse-order
unmapping, TLB invalidation, reachability checks, and frame return. All
construction failures use the same rollback order. The existing CI job adds
host lifecycle and rollback tests, exact dependency-feature and disassembly
checks, the locked dependency audit, and a QEMU `qemu64` one-vCPU boot that
restores the OS020 frame transcript before the isolation terminal record.

Non-scope: multiple tasks, scheduling, IPC, capabilities, asynchronous
interrupts, SMP, PCID, global mappings, huge pages, LA57, a physical-memory
direct map, loader-memory reclamation, releases, and phase promotion.

### OS015 — Cooperative scheduler and inline-IPC decision

Status: Closed

Depends on: OS021

Record the complete task-context, cooperative scheduling, DPL3 trap, fixed
task-state, and bounded IPC contract required before OS022 runs two live user
address spaces.

Decision:
[ADR-0004](../architecture/decisions/0004-cooperative-scheduler-and-inline-ipc.md)
selects two fixed task slots, a deterministic FIFO run queue, one DPL3
`int 0x80` ABI, complete integer-task context switching through the owned
recovery root, and one kernel-owned endpoint carrying a single inline `u64`
from its fixed sender to its fixed receiver.

Acceptance: the accepted decision defines `Ready`, `Running`,
`BlockedReceive`, `Exited`, and `Dead` transitions; complete register and
privilege-frame preservation; recovery-root-first trap dispatch; state-
preserving ABI rejections; mailbox full, block, wake, peer-exit, and teardown
semantics; and the host, disassembly, and pinned one-vCPU QEMU evidence OS022
must provide.

Non-scope: code, dependencies, CI changes, boot behavior, task or IPC
implementation, timer preemption, asynchronous interrupts, SMP, dynamic task
or endpoint allocation, handles, capabilities, shared memory, byte buffers,
releases, and phase promotion. OS022 implements the accepted contract without
changing the decision.

### OS022 — Minimal scheduler and IPC

Status: Closed

Depends on: OS015

Implement ADR-0004's cooperative scheduler for exactly two owned user address
spaces and exchange one inline `u64` through its fixed single-slot endpoint.

Acceptance: host state-machine tests cover complete integer contexts,
deterministic FIFO transitions, block and wakeup, exact ABI rejections,
peer-exit behavior, and recovery-root-first reverse-order teardown. Disassembly
proves complete trap capture and non-returning `iretq` resume. The existing
pinned QEMU `qemu64` one-vCPU gate preserves the prior transcripts, executes the
declared receiver-block, sender-wake, transfer, exit, and teardown order, and
emits `MakopaOS ipc v1 ok cooperative-two-task` only after all task frames and
endpoint state are gone.

Delivery: a dependency-free `no_std` task-runtime crate owns the two fixed task
slots, complete integer contexts, unique FIFO queue membership, exact trap
results, and the single occupied-bit-plus-`u64` endpoint. The kernel constructs
both seven-frame address spaces before publication, installs DPL3 vector
`0x80`, rejects `CR4.FSGSBASE`, captures every GPR on the guarded recovery
stack, installs the recovery root before Rust dispatch, and resumes only
validated contexts through a non-returning `iretq` path. Global-assembly sender
and receiver probes prove receiver block, sender wake, exact value transfer,
register preservation, exit, reverse-order teardown, and empty residual state.
The existing CI job adds the task-runtime host tests, two-owner construction-
failure rollback, dependency-free manifest evidence, complete-switch
disassembly checks, and the terminal IPC record to its pinned `qemu64` one-vCPU
transcript without changing topology or permissions.

Non-scope: timer preemption, asynchronous interrupts, SMP, priorities,
fairness beyond the fixed FIFO trace, arbitrary user binaries, SIMD or user
TLS, dynamic task or endpoint allocation, multiple queued messages, byte or
pointer payloads, shared memory, handles, capabilities, releases, and phase
promotion.

## Phase 3: Explicit authority

### OS016 — Task-local capability-handle decision

Status: Closed

Depends on: OS022

Record the fixed task-local handle-table, typed endpoint reference, rights,
attenuation, duplication, close, stale-selector, rollback, and teardown
contract required before OS030 replaces the bootstrap endpoint roles.

Decision:
[ADR-0005](../architecture/decisions/0005-task-local-capability-handles.md)
selects one 16-slot table per fixed task, zero-invalid generation-tagged `u64`
selectors, typed endpoint entries, and `SEND`, `RECEIVE`, and `DUPLICATE`
rights. Duplication is same-task and subset-only; closes are independent;
generation exhaustion retires a slot rather than wrapping; and task teardown
removes handles before endpoint, task, address-space, and frame references.

Acceptance: the accepted decision defines selector encoding and resolution,
explicit lookup and error precedence, fail-closed slot reuse, lowest-slot
allocation, subset-only attenuation, independent duplicate lifetime, exact
publication and teardown ordering, and the host and pinned one-vCPU QEMU
evidence OS030 must provide. It states that handle integers are task-local
selectors rather than secret bearer tokens and that table membership is the
authority boundary.

Non-scope: code, dependencies, CI changes, boot behavior, handle or capability
implementation, cross-task transfer, recursive revocation, randomness as
authority, dynamic tasks or objects, policy and approval, effect logging,
releases, and phase promotion. OS030 implements this accepted contract without
changing the decision.

### OS030 — Capability handle table

Status: Closed

Depends on: OS016

Implement ADR-0005's fixed task-local capability tables and mediate the OS022
endpoint through typed handles with monotonic rights attenuation.

Acceptance: host tests cover exact selector encoding, invalid, cross-task,
stale, wrong-object, and wrong-right handles; deterministic lowest-slot
allocation; subset-only attenuation; same-task duplication and independent
close; all 16 slots; table and generation exhaustion; publication rollback;
and handle-first task teardown. The pinned QEMU scenario closes a source
handle, proves its stale rejection, sends through an attenuated duplicate,
receives through the peer's task-local handle, rejects cross-task numeric
authority, and emits its terminal record only after both tables and all task,
endpoint, address-space, and frame references are gone. No test task receives
ambient device access. The exact record is
`MakopaOS capabilities v1 ok task-local-attenuation`.

Delivery: the dependency-free task runtime owns one fixed 16-slot table per
task with `Building`, `Live`, `Closing`, and `Dead` lifecycle checks. Handles
encode a four-bit slot and monotonic 60-bit generation; close removes the entry
before increment or permanent retirement. Send and receive now authorize typed
endpoint references through `SEND` or `RECEIVE`, while same-task duplicate
requires `DUPLICATE` and accepts only a non-empty subset. The kernel preserves
the recovery-root boundary, removes all handles and endpoint references before
unmapping an address space, and publishes `Dead` only after frame return. Host,
dependency-feature, disassembly, audit, and pinned QEMU evidence remain in the
single existing CI job; no workflow topology or dependency changed.

Non-scope: cross-task handle transfer, recursive revocation, random or secret
bearer tokens, dynamic tasks, endpoints, or object storage, policy and
approval, effect logging, releases, and phase promotion.

### OS031 — Policy and approval boundary

Status: Proposed

Depends on: OS030

Introduce a user-space supervisor that launches tasks from a declared capability
manifest and pauses high-impact requests for approval.

Acceptance: allow, deny, expiry, replay, and approval-timeout paths have
deterministic tests; each decision binds the initiating principal, task,
requested capability, and resulting authority without recording credentials.

### OS032 — Structured effect log

Status: Proposed

Depends on: OS031

Record requested, approved, denied, completed, and failed effects without secret
payloads.

Acceptance: records are ordered, schema-versioned, bounded, and exportable over
a read-only channel; effect and approval records preserve principal, task, and
capability attribution without secret payloads.

## Phase 4: Portable isolated workloads

### OS040 — Component ABI experiment

Status: Proposed

Depends on: OS032

Evaluate a minimal component ABI against WASI 0.2 and 0.3 without committing the
kernel ABI to either version.

Acceptance: a decision compares stable WASI 0.3 with the maintained WASI 0.2
baseline across footprint, native async behavior, capability mapping, runtime
and toolchain maturity, migration cost, and rollback. Neither version becomes a
kernel ABI.

### OS041 — Sandboxed component host

Status: Proposed

Depends on: accepted OS040 decision

Run one signed test component with console-only authority.

Acceptance: undeclared filesystem, network, clock, and device imports fail
closed; the permitted console call is recorded.

## Phase 5: Interoperability gateways

### OS050 — Local tool gateway

Status: Proposed

Depends on: OS041

Map a small, versioned local tool schema onto supervisor requests.

Acceptance: schemas are machine-validated; untrusted descriptions cannot alter
authority; high-impact operations still require policy approval.

### OS051 — Protocol adapter study

Status: Proposed

Depends on: OS050

Compare MCP and A2A adapters as user-space services, using MCP `2026-07-28` and
A2A `1.0.1` as the initial study baselines. Adopt only stable protocol subsets
with clear identity, authorization, task-lifecycle, and cancellation behavior.

Acceptance: an accepted decision identifies exact supported versions; maps MCP
stateless routing, authorization, discovery, and task extensions plus A2A task
states and bindings onto local authority; defines delegation and prompt-
injection boundaries; and specifies conformance tests, migration, and removal.

## Delivery gate

A work item closes only when:

- its explicit approval, scope, and non-scope are visible;
- acceptance criteria have executable evidence;
- targeted and broader relevant checks have actually run;
- architecture, roadmap, tests, and operator documentation agree;
- security limitations and skipped checks are stated;
- the pull request remains reviewable and independently reversible.

A future release-producing work item must decide provenance and verification
against SLSA 1.2 and then-current artifact-attestation support. OS003 does not
enable publishing or broaden workflow permissions.
