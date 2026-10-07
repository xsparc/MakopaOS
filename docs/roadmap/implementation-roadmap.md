# MakopaOS implementation roadmap

- Status: Active; item states are recorded below
- Baseline: `a5f45c76f159558b3beb9ec4468295b0895815e9`
- Updated: 2026-09-02

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
  WASI 0.3.1 as the current protocol and component-study baselines;
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

### OS017 — Supervisor launch and approval decision

Status: Closed

Depends on: OS030

Record the fixed trusted-supervisor, staged-workload, immutable launch-manifest,
default-deny capability-route, approval-broker, synthetic-effect, rollback, and
teardown contract required before OS031 adds policy and approval behavior.

Decision:
[ADR-0006](../architecture/decisions/0006-fixed-supervisor-and-approval-broker.md)
selects task `1` as the prestarted trusted supervisor and task `2` as a staged
hostile workload. A bounded static `LaunchManifestV1` publishes only declared
workload routes. One kernel-owned broker binds a request to the principal, task,
action, effect object, inline argument, exact rights, generations, request
sequence, and decision epoch. Only the supervisor holds task-control,
approval-decision, and synthetic-effect authority; commit validates and consumes
one matching live approval atomically.

Acceptance: the accepted decision defines `Staged` and `BlockedApproval` task
states, exact fixed capability types and rights, manifest limits and validation,
default-deny failure, parameter-bound single-use approval, non-wrapping request
and decision epochs, deterministic expiry without a wall-clock claim, fixed
synthetic effect enforcement, construction rollback, handle-first teardown, and
the host, disassembly, and pinned one-vCPU QEMU evidence OS031 must provide.

Non-scope: code, dependencies, CI changes, boot behavior, dynamic tasks or
objects, cross-task transfer, recursive revocation, general policy language,
credentials or authenticated identity, real external effects, effect logging,
external authorization protocols, wall-clock expiry, preemption, releases, and
phase promotion. OS031 implements this accepted contract without changing the
decision.

### OS031 — Policy and approval boundary

Status: Closed

Depends on: OS017

Implement ADR-0006's fixed user-space supervisor, staged workload, immutable
launch manifest, default-deny capability routes, kernel approval-broker slot,
and parameter-bound single-use approval for one synthetic effect.

Acceptance: host tests cover exact manifest layout and limits, missing,
unknown, duplicate, over-righted, stale, and capacity-failing routes,
state-preserving launch rollback, supervisor-only start, hostile-workload
authority isolation, exact request binding, allow, deny, decision-epoch expiry,
deterministic timeout, alteration, replay, second use, sequence and epoch
exhaustion, atomic effect commit, and approval-first teardown. Existing
complete-context disassembly evidence remains intact. The pinned QEMU `qemu64`
one-vCPU gate preserves all earlier transcripts, launches the staged workload,
proves denial, expiry, altered-argument rejection, one exact commit, replay
rejection, and empty broker, effect, capability, task, address-space, and frame
state before emitting `MakopaOS approval v1 ok staged-single-use`.

Delivery: the dependency-free task runtime retains `Runtime::new` and every
OS030 state-machine test while adding a separate `Runtime::new_supervised`
profile. Fixed entries now tag `Endpoint`, `TaskControl`, `ApprovalBroker`, and
`TestEffect` objects with object-specific rights and generations. The staged
workload receives only the one broker-submit route in the statically registered
184-byte manifest. One 80-byte canonical request binds the principal, task,
sequence, action, effect, argument, rights, and generations. Host tests cover
every manifest rejection, publication rollback step, typed-handle rejection,
approval transition, exhaustion path, exact atomic commit, and approval-first
teardown. The fixed runtime metadata measures 3,112 bytes and is asserted below
the existing 64 KiB bound. Existing exception and complete-context checks now
also inspect the supervisor and workload probe instruction sequences. The same
single read-only CI job preserves all earlier transcripts and adds the exact
approval terminal record under pinned `qemu64` with one vCPU.

Non-scope: dynamic tasks or objects, cross-task transfer, recursive revocation,
general policy language, credentials or human authentication, real external
effects, effect logging, external protocols, wall-clock deadlines, preemption,
releases, and phase promotion. The dependency-free runtime and single read-only
CI job remain unchanged in topology unless separately approved.

### OS018 — Fixed effect-journal decision

Status: Closed

Depends on: OS031

Record the bounded, redacted, read-only journal contract required before OS032
adds structured evidence to accepted approval and synthetic-effect lifecycles.

Decision:
[ADR-0007](../architecture/decisions/0007-fixed-effect-journal.md) selects a
separate `JournaledRuntime` wrapper so the 3,112-byte `Runtime`, both existing
constructors, and all OS020 through OS031 evidence remain unchanged. The wrapper
owns one append-only 16-record `EffectJournalV1`; complete-lifecycle reservation
guarantees a terminal record or rejects submit without mutation. Exact
128-byte records attribute principal, actor, subject, request, action, resolved
capability, decision epoch, and categorical outcome while excluding arguments,
results, handles, pointers, credentials, and arbitrary payloads.

Acceptance: the accepted decision fixes the projected 2,072-byte journal and
5,184-byte wrapper layouts; `Requested`, `Approved`, `Denied`, `Expired`,
`Completed`, and `Failed` records; a supervisor-only read capability; two
pointer-free three-register read operations; explicit capacity, sequence,
rollback, sealing, supervisor-capability, and kernel-generated teardown
attribution behavior; and the exhaustive host, disassembly, and pinned
`qemu64` one-vCPU evidence OS032 must provide.

Non-scope: code, dependencies, CI changes, boot behavior, external schemas or
protocols, dynamic objects, cross-task transfer, recursive revocation, durable
storage, cryptographic chains, real effects, releases, and phase promotion.
OS032 implements the accepted contract without changing this decision.

### OS032 — Structured effect log

Status: Closed

Depends on: OS018

Implement ADR-0007's separate `JournaledRuntime`, fixed append-only effect
journal, complete-lifecycle reservation, and supervisor-only read channel while
preserving the existing `Runtime` profiles and evidence.

Acceptance: compile-time layout assertions and host tests prove the exact base,
journal, wrapper, and record footprints; exhaustive state-machine tests cover
all accepted lifecycles, redaction, resolved capability attribution, capacity,
sequence exhaustion, immutability, typed read failures, rollback, sealing, and
terminal-before-teardown ordering, including zero-right kernel attribution for
automatic closure. Disassembly proves the two exact pointer-free read operations
and preserves complete context switching. The existing pinned `qemu64` one-vCPU
gate preserves all prior transcripts, compares the exact 11-record deny,
expire, complete, and failed-effect sequence, proves empty final state, and
emits `MakopaOS effects v1 ok ordered-redacted` through the same single
read-only CI job.

Delivery: the dependency-free task runtime retains the exact 3,112-byte
`Runtime` and both existing constructors while adding an exact 5,184-byte
`JournaledRuntime` wrapper. Its 2,072-byte journal owns 16 immutable 128-byte
records, admits a request only with three available lifecycle slots, and
reserves every accepted terminal record. A fourth supervisor handle with
`READ_EFFECT_JOURNAL` resolves the fixed journal object; operations `11` and
`12` expose metadata and three record words per trap without a user pointer.
Host tests cover layouts, every publication rollback step, ordered lifecycle
transitions, typed failures, capacity and sequence exhaustion, immutable reads,
kernel teardown attribution, sealing, and reclamation. Separate linked probes
measure 1,848 and 150 bytes, compare all 11 records, and preserve the complete
OS020 through OS031 machine-code and serial evidence before the new terminal
record. The existing single read-only CI job retains the pinned `qemu64`
one-vCPU machine and dependency audit.

Non-scope: external telemetry schemas or protocols, persistence, crash
recovery, cryptographic non-repudiation, dynamic objects, cross-task transfer,
recursive revocation, real effects, authenticated identities, wall-clock
ordering, releases, and phase promotion. The dependency-free runtime and CI
topology remain unchanged unless separately approved.

## Phase 4: Portable isolated workloads

### OS040 — Component ABI experiment

Status: Closed

Depends on: OS032

Select a versioned MakopaOS-owned component-host contract for the first
console-only workload and compare WASI 0.2.12 with stable WASI 0.3.1 without
committing the kernel ABI to either version.

Decision:
[ADR-0008](../architecture/decisions/0008-versioned-console-component-host-contract.md)
selects `ComponentHostContractV1` at the user-space workload boundary. The
first profile uses complete import enumeration and exact allowlisting of only
the owned bounded console interface, plus the exact task export. A fixed signed
admission record binds the portable artifact, optional target executable, WIT,
execution profile, build evidence, and finite resource bounds. Wasmtime
`48.0.1` is a compile-only host-side measurement baseline on the 48 LTS line,
not an approved dependency or runtime. Its embedded 0.254.0 parser family is a
separately reported differential input only.

Profile zero selects WebAssembly 1.0 plus the base Component Model. Its fixture
production pins Rust `1.97.1`, `wasm32v1-none`, and `wit-bindgen` 0.61.1 with
default features disabled and only `macros` enabled. Direct-final generation
names the checked-in WIT path and exact world, disables custom-section link
helpers, semver import merging, LTO, and linker-plugin LTO. Legacy core-name
compatibility is confined to componentization of the exact verified producer
output; supplied WIT and final-component identities remain strict. Binding
overrides, adapters, libraries, import remapping, and every allocator except a
fixture-local trap-only allocation sentinel are prohibited. The accepted
contract pins the published package digest and binary-format inventory and
requires isolated offline build, exact realloc-scaffold extraction, negative
task-path reachability, zero-`memory.grow`, disassembly, section, symbol, and
target-feature evidence.

Build evidence keeps its fixed 256-byte record and the admission signature
keeps its exact 318-byte message. Source-revision kind 1 binds a bounded
canonical MakopaOS source manifest: the repository and subtree, Git SHA-1 tree
locator, and complete sorted regular-file inventory of modes, lengths, and
per-file SHA-256 values. The SHA-1 value is only an object locator; independently
reconstructed and read-back-verified file SHA-256 values bind the actual source
bytes. Fixture staging uses committed Git objects from an explicit revision,
never the checkout working tree or persisted checkout credentials.

Independent admission pins `wasmparser` 0.258.0 with default Cargo features
disabled and only `std`, `validate`, `features`, and `component-model` enabled.
Profile zero and the WASI 0.2.12 study use exactly WebAssembly 1.0 plus the base
Component Model runtime mask; the separate WASI 0.3.1 study adds only native
async. All other extensions, including map, implements, version suffixes, and
external IDs, fail closed. Raw final bytes, decoded metadata, and separately
supplied WIT must independently encode the same exact interface graph.

Acceptance: the accepted decision compares WASI 0.2.12 and 0.3.1 across
stability, native async behavior, Component Model features, capability mapping,
toolchain maturity, migration, and rollback; defines fixed-width
little-endian records, exact Ed25519 verification, exact interface allowlisting,
capability mapping, resource, fuel, trap, cancellation, rollback, teardown,
repeated-run, and provenance evidence; and records allocator, linear-memory,
artifact-loading, AOT, platform-hook, and execution-context prerequisites.
Neither WASI release nor Wasmtime becomes a kernel ABI or approved dependency.
Admission independently validates the exact final bytes and contains decoding
and compilation in separate bounded workers that cannot publish partial
evidence. Profile-zero WIT remains capped at 65536 bytes; the larger P2 and P3
closures use separate 131072-byte non-admission study envelopes.

Non-scope: code, dependencies, CI changes, boot behavior, component execution,
phase promotion, releases, dynamic artifact loading, external protocols, and
runtime adoption.

### OS041A — Component admission verifier

Status: Proposed

Depends on: OS040

Implement the host-side admission boundary for the fixed
`ComponentAdmissionV1` bundle. Pin Ed25519 scheme 1 through
`ed25519-dalek = "=3.0.0"` strict verification and `sha2 = "=0.11.0"`, with
default features disabled for both crates and no optional verifier features.
Pin one public test trust root and derived key ID, the `wasmparser`,
`wit-component`, and `wit-parser` 0.258.0 inspection family, and a separately
reported Wasmtime `48.0.1`/parser 0.254.0 compile-measurement configuration.
Produce the frozen verifier-only positive fixture with Rust `1.97.1`,
`wasm32v1-none`, and `wit-bindgen` 0.61.1 with default features disabled and
only `macros` enabled. Name the checked-in WIT path and exact world, retain
component-type metadata while disabling custom-section link helpers, disable
semver import merging, and confine legacy core-name compatibility to
componentization of the exact verified producer output. Reject legacy supplied
WIT and final-component identities. Prohibit binding overrides, adapters,
libraries, import remapping, and every allocator except a fixture-local
trap-only allocation sentinel. Implement the fixed 288-byte
`ComponentAdmissionV1`, 224-byte `ExecutionProfileV1`, and 256-byte
`BuildEvidenceV1` serialized layouts and their separately supplied,
length-and-digest-bound documents. Parse records through checked explicit
little-endian slices. No private signing seed, signer, or key-generation path
is committed.

Implement source-revision kind 1 as the exact bounded
`makopa-source-manifest-v1` grammar selected by ADR-0008. A trusted parent must
resolve its declared subtree from the explicit expected revision, enumerate and
stream committed Git blobs under the fixed path, mode, count, and byte limits,
stage them into a fresh root with create-once and no-follow semantics, and have
an independent checker read back and compare the complete signed inventory.
The worker receives no working-tree, `.git`, hook, configuration, untracked,
ignored, modified, or persisted-credential content.

Acceptance: deterministic host evidence rejects altered records, artifacts,
executables, WIT, execution profiles, build evidence, signatures, keys,
targets, runtimes, bounds, imports, exports, and reserved fields, including
wrong-size, non-canonical, weak-key, unknown-scheme, unknown-key, and key-ID
cases. Fixed-record enums, lengths, digests, reserved bytes, supporting
documents, transitive bindings, and the exact 318-byte signature message are
verified. Parser and validator use the same explicit runtime mask; byte size,
nesting, parent ranges, sections, types, imports, exports, custom sections, and
names are bounded before independent complete validation of the exact final
bytes and before compilation.

Source evidence rejects every changed file byte, path, mode, length, digest,
tree locator, repository, subtree, count, order, line ending, trailing byte,
non-ASCII byte, non-canonical path, duplicate or prefix-colliding path, symlink,
gitlink, special mode, non-blob leaf, missing or extra entry, Git object type or
size mismatch, exceeded per-file or aggregate bound, and producer/checker
disagreement. A matching SHA-1 locator never overrides a SHA-256 inventory
mismatch. Tests also prove modified and untracked checkout content and `.git`
state cannot enter the build.

The verifier enumerates the raw Component Model surface, parses supplied WIT
through the exact in-memory `SourceMap` path, and confines decoding and
compile-only measurement to separate pinned workers. Workers clear the
environment, fix their working directory, apply resource limits before a READY
frame, use bounded versioned pipes, and are killed and reaped after timeout,
overflow, or protocol failure. They never receive paths, URLs, adapters,
libraries, or maps and never instantiate or execute a component. Complete
results are checked before publication; unsupported containment fails closed.

Raw, decoded, and supplied-WIT surfaces produce byte-equal fixed semantic
graphs containing exact versioned identities, directions, functions, ordered
parameters and results, recursive types, and declared enum-case order. Only
unordered maps are sorted by raw UTF-8 bytes. Duplicate, parallel, raw-only,
decoded-only, WIT-only, semver-normalized, legacy, remapped, `implements`,
`version_suffix`, `external_id`, and parser-family disagreement cases fail
closed. Complete enumeration permits exactly the console import and task export
and rejects generic WASI and every undeclared import.

The isolated offline fixture build pins the exact SHA-256-bound source manifest,
registry package digest, binary-format inventory, Cargo, rustc, and LLD; clears
ambient Cargo and Rust configuration; disables persisted checkout credentials;
sets one codegen unit; disables LTO and linker-plugin LTO; and records effective
arguments, map, extraction, traced-input, garbage-collection, section, symbol,
target-feature, direct-call-graph, and disassembly evidence. That evidence
permits only the exact pinned realloc scaffold and versioned wrapper, proves the
task path cannot reach realloc, allocation, or panic code, proves the core
contains no `memory.grow`, and proves the final semantic surface contains only
the strict console import and task export. The P0/P2
Wasmtime worker enables only `component-model` and `cranelift`; P3 uses a
separate build that also records `component-model-async`. Equivalent WASI
0.2.12 and 0.3.1 fixtures produce compile-only comparison evidence under their
separate non-admission envelopes.

Non-scope: target runtime dependencies, target or general-purpose allocator or
page-table changes, executable mappings, boot behavior, component execution,
releases, and phase promotion.

### OS041B — Component memory and execution-substrate decision

Status: Proposed

Depends on: OS041A

Use the admission and measurement evidence to select the target allocator,
immutable artifact loading, AOT representation, W^X code publication,
linear-memory ownership, stack, deterministic fuel, trap, cancellation,
runtime-metadata, rollback, and teardown contract.

Acceptance: an accepted decision pins exact finite ceilings and defines
state-preserving failure and reverse-order reclamation for code, data, runtime
metadata, canonical ABI temporaries, host-call buffers, import bindings,
capabilities, tasks, mappings, and frames. It identifies the exact runtime and
platform hooks, if any, that a later experiment may use.

Non-scope: runtime integration, component imports, boot transcript changes,
releases, and phase promotion.

### OS041C — Component runtime platform experiment

Status: Proposed

Depends on: accepted OS041B decision

Integrate only the selected runtime substrate and platform hooks without
exposing a component import.

Acceptance: host and QEMU evidence covers exact footprint, allocation failure,
code and data permissions, linear-memory bounds, stack and deterministic fuel,
trap classification, cancellation boundaries, construction rollback, complete
teardown, and two fresh constructions without residual state. Existing boot,
isolation, authority, approval, and effect-journal evidence remains unchanged.

Non-scope: console mapping, generic WASI worlds, dynamic artifacts, filesystem,
network, clock, random, environment, credentials, devices, releases, and phase
promotion.

### OS041D — Console-only component execution

Status: Proposed

Depends on: OS041C

Run the immutable admitted profile-0 test component twice with only the bounded
console import.

Acceptance: the host resolves one manifest-routed console capability, denies
every undeclared import before instantiation, enforces the admitted resource
and fuel bounds, records one console call and one terminal outcome per run,
proves trap and cancellation cleanup, and reaches complete reclamation between
runs. The pinned `qemu64` one-vCPU gate preserves all earlier transcripts and
adds a component terminal record only after no code, memory, runtime resource,
host call, import, capability, task, mapping, or frame reference remains.

Non-scope: full WASI 0.2 or 0.3 worlds, async composition, dynamic loading,
filesystem, network, clock, random, environment, process, credentials, devices,
real effects, releases, and phase promotion.

## Phase 5: Interoperability gateways

### OS050 — Local tool gateway

Status: Proposed

Depends on: OS041D

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
