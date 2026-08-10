# MakopaOS implementation roadmap

- Status: Proposed, except OS001
- Baseline: `507428c3d98a8b6cea06d6cd9800cb6f0aa002e1`
- Updated: 2026-08-10

This roadmap turns the architecture into reviewable vertical slices. Proposed
items describe sequence, not implementation authority. Each item should ship in
its own pull request unless a maintainer explicitly changes the boundary.

## Phase 0: Reproducible baseline

### OS001 — Boot-sector verification

Status: Approved

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

Status: Proposed

Depends on: OS001

Define a MakopaOS-native, non-authoritative traceability index linking objectives,
requirements, roadmap work, design, implementation, verification, validation,
and risk. Add an offline checker without importing another project's identity or
approval rules.

Acceptance: the checker rejects missing and unsafe references, unknown IDs,
unindexed accepted decisions, stale reviews, and implemented requirements
without verification evidence; a strict mode is part of CI.

## Phase 1: Modern boot handoff

### OS010 — Toolchain and boot-contract decision

Status: Proposed

Depends on: OS002

Record the pinned Rust, NASM, QEMU, firmware, target, and linker contract. Define
the versioned x86-64 boot handoff and decide whether the initial UEFI loader is
owned or delegated to a maintained loader.

Acceptance: an accepted decision describes alternatives, compatibility, update
policy, and rollback; CI can provision the pinned toolchain.

### OS011 — x86-64 kernel entry

Status: Proposed

Depends on: OS010

Boot a `no_std` Rust kernel through UEFI, write a version string to the serial
console, and halt cleanly.

Acceptance: QEMU exits through a deterministic test device after matching the
expected serial transcript; the legacy BIOS sector remains buildable.

### OS012 — Boot handoff validation

Status: Proposed

Depends on: OS011

Pass and validate a versioned handoff containing the memory map and framebuffer
metadata.

Acceptance: unit tests reject incompatible versions and malformed ranges; QEMU
smoke tests cover one valid handoff.

## Phase 2: Kernel mechanics

### OS020 — Physical frame allocator

Status: Proposed

Depends on: OS012

Allocate and recycle page frames from validated usable memory ranges.

Acceptance: deterministic host tests cover exhaustion, reuse, alignment, and
reserved ranges; QEMU allocates and returns a known frame sequence.

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
deterministic tests.

### OS032 — Structured effect log

Status: Proposed

Depends on: OS031

Record requested, approved, denied, completed, and failed effects without secret
payloads.

Acceptance: records are ordered, schema-versioned, bounded, and exportable over
a read-only channel.

## Phase 4: Portable isolated workloads

### OS040 — Component ABI experiment

Status: Proposed

Depends on: OS032

Evaluate a minimal component ABI against WASI 0.2 and 0.3 without committing the
kernel ABI to either version.

Acceptance: a decision compares footprint, async behavior, capability mapping,
toolchain maturity, and migration cost.

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

Compare MCP and A2A adapters as user-space services. Adopt only stable protocol
subsets with clear authentication, task-lifecycle, and cancellation behavior.

Acceptance: an accepted decision identifies the supported protocol versions,
threat boundary, conformance tests, and removal path.

## Delivery gate

A work item closes only when:

- its explicit approval, scope, and non-scope are visible;
- acceptance criteria have executable evidence;
- targeted and broader relevant checks have actually run;
- architecture, roadmap, tests, and operator documentation agree;
- security limitations and skipped checks are stated;
- the pull request remains reviewable and independently reversible.
