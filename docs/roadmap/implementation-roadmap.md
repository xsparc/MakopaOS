# MakopaOS implementation roadmap

- Status: Active; item states are recorded below
- Baseline: `7c8c62bbe2cf548b7a92ef52b9cc9a98242c7a62`
- Updated: 2026-08-11

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

### OS021 — Address-space isolation

Status: Proposed

Depends on: OS020

Create a second address space with guarded kernel mappings and demonstrate a
contained user-mode fault.

Acceptance: an invalid user write terminates only the test task and emits the
expected event.

### OS022 — Minimal scheduler and IPC

Status: Proposed

Depends on: OS021

Run two user tasks and exchange a bounded message through one kernel endpoint.

Acceptance: message ordering and bounds are covered by host tests and a QEMU
scenario with a deterministic transcript.

## Phase 3: Explicit authority

### OS030 — Capability handle table

Status: Proposed

Depends on: OS022

Add unforgeable task-local handles for IPC endpoints with rights attenuation.

Acceptance: tests cover invalid handles, rights reduction, duplication rules,
and task teardown; no test task receives ambient device access.

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
