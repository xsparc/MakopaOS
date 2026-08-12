# ADR-0003: Own the first address space and fault-containment boundary

- **Status:** Accepted
- **Date:** 2026-08-12
- **Work item:** OS014
- **Baseline:** `95e1ad7e8be8435ee2a5777651e154c06e0e66cd`

## Context

OS020 provides checked ownership of individual physical frames, but it does not
make arbitrary physical memory directly addressable. ADR-0001 guarantees
identity mappings only for the handoff, normalized region array, loaded kernel,
and active loader stack at entry. The shape, ownership, and continued lifetime
of the inherited UEFI page tables are otherwise unspecified.

OS021 must establish a kernel-owned recovery context before it creates a second
address space, enters privilege level 3, or attempts to contain a task fault.
That context needs a page-table editing path, guarded privilege stacks, stable
exception entry, explicit frame ownership, and a teardown order that prevents a
returned frame from remaining reachable through a mapping or stale handle.

The first slice remains deliberately single-core and one-shot. It needs to
prove isolation and recovery, not introduce a scheduler, general virtual-memory
manager, or production process model.

## Decision

MakopaOS will own a four-level x86-64 paging boundary using only 4 KiB pages.
OS021 will first replace the inherited page tables and active stack with a
kernel-owned recovery context, then construct one separately owned user address
space and demonstrate a contained invalid write.

The implementation must remain on stable Rust `1.97.1`. Architecture-specific
assembly and `unsafe` Rust are confined to the transition stack, control-
register operations, temporary mapping window, descriptor tables, exception
trampolines, and privilege transition.

### Paging baseline

The first address-space implementation has these fixed constraints:

- four paging levels with canonical 48-bit virtual addresses;
- 4 KiB leaf pages only;
- `CR4.LA57` must be clear before the owned root is activated;
- `EFER.NXE` is enabled before any no-execute entry becomes active;
- `CR0.WP` is enabled so supervisor writes obey read-only mappings;
- PCID, global mappings, recursive mappings, huge pages, and a physical-memory
  direct map are not used; and
- unsupported entry state or CPU features fail closed before user entry.

No inherited page-table frame is modified, adopted, reclaimed, or retained as
part of the owned address-space model.

### Kernel recovery root

The kernel image reserves a page-aligned pool of exactly 32 page-table frames.
The linker exposes its bounds, and construction fails before a `CR3` switch if
the image layout is misaligned, overlapping, or cannot be described within the
pool. These frames remain kernel-image storage and never enter the OS020 frame
allocator.

The owned recovery root maps:

- the kernel's low identity range using linker-section boundaries: `.text` is
  supervisor read/execute, `.rodata` is supervisor read/no-execute, and writable
  sections are supervisor read/write/no-execute;
- one page-aligned 4 KiB transition stack in the kernel image at its identity
  address;
- a 64 KiB kernel recovery stack at `0xffffff0000001000` through
  `0xffffff0000010fff`, with the pages immediately below and above unmapped;
- a separate 16 KiB double-fault IST stack at `0xffffff0000021000` through
  `0xffffff0000024fff`, also bounded by unmapped pages; and
- one supervisor read/write/no-execute temporary mapping window at
  `0xffffff8000000000`.

The kernel switches to the identity-mapped transition stack while the inherited
root is active, loads the owned recovery `CR3`, switches immediately to the
guarded high virtual recovery stack, and does not map the inherited loader
stack in the owned root. The transition stack is not used after this sequence.

PML4 entry 0 contains the shared supervisor-only low kernel hierarchy. Entry
510 contains the shared guarded stacks, and entry 511 contains the shared
temporary window. A task root copies those three supervisor-only entries from
the recovery root. User mappings use PML4 entry 1, so task-specific tables never
modify the shared kernel hierarchy. The user-accessible bit remains clear at
every level of each shared mapping, and no shared frame is task-owned.

### Temporary mapping window

All access to an arbitrary OS020 frame occurs through the single temporary
window. Its implementation exposes a closure-scoped mutable byte view so no
Rust pointer, reference, or slice can survive unmapping.

For each use, the kernel verifies that the window is empty, installs one target
frame, invalidates the window address, performs the bounded operation, ends the
scoped view, clears the entry, and invalidates the address again. A window
remap, nested use, leaked borrow, or return of a still-window-mapped frame is an
explicit error. This boundary is single-owner while OS021 keeps interrupts
disabled outside synchronous exception entry.

### Address-space ownership and lifecycle

One non-cloneable address-space owner holds a fixed ledger of at most 16 OS020
frames. The ledger covers the task PML4, task-specific intermediate tables,
user code, user stack, and any frame obtained during partial construction.
Shared kernel page-table and stack frames never enter this ledger.

The owner moves through exactly these states:

1. `Building`: allocated frames are recorded before they are linked;
2. `Inactive`: all mappings validate and the root may be activated;
3. `Active`: its `CR3` and task identity are current, so destruction is
   rejected; and
4. `Dead`: mappings, temporary aliases, and owned frames are gone, and every
   operation through the former owner or one of its mapping tokens returns a
   distinct stale-owner error.

Activation is allowed only from `Inactive`. A successful recovery-root switch
moves the task from `Active` back to `Inactive`; teardown then consumes the
owner and publishes `Dead`. Failed construction rolls back from `Building`
without publishing an activatable root. A rejected transition leaves the
owner, ledger, and allocator unchanged.

Mapping tokens are bound to the owner's generation. Teardown invalidates that
generation before recycling any frame, so an identifier retained across
destruction cannot operate on a newly reused physical frame.

### Privilege and exception boundary

OS021 installs a MakopaOS-owned GDT, TSS, and IDT before user entry. The TSS
privilege stack points to the top of the guarded recovery stack, and the
double-fault entry uses only the dedicated IST stack. Ring-3 selectors are
present only for user code and data. User entry fixes `RFLAGS.IF=0`,
`RFLAGS.DF=0`, and `RFLAGS.IOPL=0`, and the TSS I/O bitmap admits no ports.

Rust's `extern "x86-interrupt"` ABI remains unstable, so page-fault, general-
protection, and double-fault entries use small assembly trampolines. Each
trampoline normalizes the vector and optional hardware error code, saves all
general-purpose registers, clears the direction flag, preserves System V stack
alignment, and calls a stable `extern "sysv64"` Rust classifier. The page-fault
entry reads `CR2` before invoking code that could itself fault. Assembly layout
constants and the Rust frame representation must have compile-time size and
offset assertions.

The double-fault path never returns. An unexpected page fault, general-
protection fault, malformed frame, or classifier inconsistency enters the
existing deterministic kernel-failure path rather than being reported as a
contained task failure.

### Fixed user probe

The first task uses this version-one layout in PML4 entry 1:

| Purpose | Virtual address or range | Mapping |
| --- | --- | --- |
| User text | `0x0000008000400000` through `0x0000008000400fff` | user read/execute |
| Invalid-write target | `0x0000008000600000` | unmapped |
| Lower stack guard | `0x00000080007ff000` | unmapped |
| User stack | `0x0000008000800000` through `0x0000008000800fff` | user read/write/no-execute |
| Upper stack guard | `0x0000008000801000` | unmapped |

The user text contains one bounded probe that writes to the invalid-write
target. No user page is writable and executable, and all other entries in the
user hierarchy remain zero.

Before `iretq`, the kernel records the active task identity, task root, recovery
root, recovery-stack checkpoint, and one continuation address. The expected
fault is accepted only when all of these conditions hold:

- a task owner is `Active` and matches the recorded identity;
- the saved code selector has requested privilege level 3;
- `CR2` equals `0x0000008000600000`;
- the page-fault error code has `P=0`, `W=1`, `U=1`, `RSVD=0`, and `I/D=0`,
  making its low defined bits exactly `0x06`; and
- protection-key, shadow-stack, SGX, and every other defined cause bit are
  clear.

The accepted path never returns to the faulting instruction. The trampoline
loads the recovery root, restores the recorded recovery-stack checkpoint, and
jumps to the continuation. The continuation marks the task `Inactive`, tears it
down, proves that every owned frame was returned, and emits the exact terminal
record:

```text
MakopaOS isolation v1 ok user-fault-contained
```

The existing serial records remain in order before this record, and the pinned
QEMU scenario exits with the existing success status. Any mismatch uses the
failure status and cannot emit the success record.

### Teardown and invalidation order

OS021 remains single-core, does not enable PCID, and does not mark entries
global. Loading the recovery `CR3` therefore removes the active task's cached
translations before task frames become eligible for return.

Teardown then performs this order without interruption:

1. invalidate the owner generation and reject further activation or mapping;
2. clear user leaf entries while the task root is inactive;
3. clear and inspect task-owned intermediate tables from leaves toward the
   root;
4. remove every temporary-window alias and execute `invlpg` for the window;
5. verify that no task-owned physical frame is reachable from either root or
   the window; and
6. return user frames, intermediate-table frames, and finally the task root to
   OS020, preserving caller ownership if any return is rejected.

The same ordering applies to partial-construction rollback. A frame is never
returned while a present entry, live temporary alias, mapping token, or active
`CR3` can still reach it.

## Verification contract for OS021

Host-side tests must demonstrate:

- every fixed virtual address is canonical, aligned, ordered, and disjoint;
- kernel and user mapping flags enforce supervisor isolation, W^X, NX, and the
  declared guard pages;
- the 32-frame bootstrap pool and 16-frame task ledger fail closed without
  partial publication when exhausted;
- allocation failures at every construction step follow the same rollback
  order and restore the allocator model;
- only the declared lifecycle transitions succeed, active destruction is
  rejected, and rejected transitions preserve state;
- stale owner and mapping tokens, double teardown, duplicate mappings, and
  unmapping an absent page return distinct errors without changing state;
- temporary-window borrows cannot escape and every remap or removal carries an
  invalidation obligation; and
- an operation trace proves unmap and invalidation occur before each frame
  return and that shared kernel frames are never returned.

The pinned QEMU gate must prove the owned recovery-root and stack transition,
ring-3 entry, exact expected page fault, recovery-root restoration, complete
task teardown, ordered terminal transcript, and unchanged success exit. Host
classifier tests must reject the wrong task, address, privilege level, access
kind, present bit, reserved bit, instruction-fetch bit, or missing active owner.

## Alternatives considered

### Extend the inherited UEFI tables

Rejected. Their structure, spare capacity, ownership, and lifetime are outside
ADR-0001. Modifying them would turn firmware state into an undocumented kernel
dependency and make rollback or reclamation unsafe.

### Identity-map or direct-map all physical memory

Rejected for the first isolation slice. It broadens kernel reachability and
trusted mapping state when a single temporary window is sufficient. A future
allocator or driver requirement may justify a separately reviewed direct map.

### Use recursive page-table mapping

Not selected. Recursive mapping makes table traversal convenient but reserves a
large virtual slot and couples every root to self-referential invariants. The
single closure-scoped window is smaller and makes physical-frame reachability
explicit.

### Use nightly Rust's `extern "x86-interrupt"`

Rejected. It would change the accepted stable toolchain and leave recovery
dependent on an unstable ABI. Owned assembly trampolines keep that contract
small and inspectable.

### Add huge pages, LA57, PCID, global mappings, or SMP shootdowns now

Deferred. None is needed to prove one contained ring-3 fault. They complicate
invalidation and ownership rules and require separate compatibility evidence.

## Consequences

- The kernel gains an explicit recovery root independent of UEFI page-table
  lifetime before it relies on dynamically allocated table frames.
- Supervisor mappings, guarded stacks, W^X, and the exact fault classifier make
  the first isolation claim executable rather than implied.
- Address-space construction and teardown have bounded storage, deterministic
  failure semantics, and an auditable frame-return order.
- Static bootstrap storage and a single temporary window trade flexibility for
  a smaller initial trusted boundary.
- The low identity kernel remains a transitional mapping choice. Moving the
  kernel to a higher-half link address requires a later ADR and does not alter
  the user layout selected here.
- Scheduler integration, asynchronous interrupts, concurrent allocation,
  loader-memory reclamation, and general task creation remain outside OS021.

## Rollback and reconsideration

Replace this decision before OS021 if the pinned QEMU CPU lacks NX support, the
kernel image cannot fit the 32-frame bootstrap-table bound, or stable assembly
trampolines cannot preserve the declared frame contract. A replacement must
retain an owned recovery context, supervisor W^X mappings, guarded privilege
stacks, exact fault classification, and unmap-before-free ownership evidence.

Reconsider the fixed virtual layout and table bounds when multiple tasks,
dynamic program images, a general heap, a higher-half kernel, or address-space
layout randomization becomes approved. Reconsider invalidation when SMP, PCID,
or global mappings are introduced. Those changes must define shootdown,
generation, and frame-reuse semantics before enabling the feature.

## References

- [ADR-0001: UEFI loader and boot handoff](0001-uefi-loader-and-boot-handoff.md)
- [ADR-0002: Early physical-frame ownership](0002-frame-ownership-and-early-allocation.md)
- [Intel 64 and IA-32 Software Developer's Manual, version 092](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- [Rust `x86_64-unknown-none` platform support](https://doc.rust-lang.org/rustc/platform-support/x86_64-unknown-none.html)
- [Rust unstable `abi_x86_interrupt`](https://doc.rust-lang.org/beta/unstable-book/language-features/abi-x86-interrupt.html)
- [`x86_64` mapping and flush contract](https://docs.rs/x86_64/latest/x86_64/structures/paging/mapper/index.html)
- [Linux x86 TLB invalidation](https://docs.kernel.org/next/x86/tlb.html)
- [seL4 16.0.0 stale-frame capability fix](https://docs.sel4.systems/releases/sel4/16.0.0.html)
