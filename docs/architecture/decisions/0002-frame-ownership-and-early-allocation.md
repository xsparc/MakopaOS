# ADR-0002: Own early physical frames with bounded sorted extents

- **Status:** Accepted
- **Date:** 2026-08-11
- **Work item:** OS013
- **Baseline:** `cf5601a1b8e60bdf776d20c8edec5ed9443ffb9f`

## Context

OS012 leaves the kernel with a validated, normalized memory map whose storage is
still owned by the loader. OS020 must establish kernel ownership before it can
allocate physical frames or permit any loader-owned storage to be reclaimed.
The first allocator also has to work before a heap, alternate address space,
scheduler, or synchronization primitive exists.

The current handoff contains at most 1,024 sorted, non-overlapping regions.
`MEMORY_USABLE` identifies memory available to the kernel now. Loader-
reclaimable memory can still contain the handoff, region array, page-table, or
stack storage and requires a separate reclamation transition. The loaded kernel
is reserved. ACPI, MMIO, framebuffer, and other reserved ranges have their own
lifetimes or device semantics and are not allocator input.

OS020 initially needs deterministic single-frame allocation and recycling. It
does not yet need arbitrary contiguous runs, NUMA policy, per-CPU caches, or
high-throughput concurrent allocation.

## Decision

The first physical-frame allocator will be a MakopaOS-owned, fixed-capacity set
of sorted extents. It will maintain two statically allocated kernel-owned
tables, each bounded to 1,024 extents to match the handoff's maximum normalized
region count:

1. an immutable managed-extent table used to prove whether a frame belongs to
   the allocator; and
2. a mutable free-extent table used for allocation and recycling.

Initialization will copy eligible ranges into both tables immediately after the
kernel validates the version-one handoff. It will copy only regions whose kind
is exactly `MEMORY_USABLE`. It will retain no pointer, slice, reference, or
lifetime dependency on the handoff or its region array after initialization.

Loader-reclaimable, ACPI reclaimable, ACPI NVS, MMIO, framebuffer, kernel, and
reserved storage remain outside the managed set. A later, separately approved
reclamation slice may copy any still-needed loader data, prove that no live
reference remains, and extend the managed set under its own recorded contract.
OS020 will not perform that transition.

### Extent contract

An extent is a page-aligned physical start and a non-zero page count. Managed
and free extents are ascending, disjoint, and maximally coalesced. All page-count
multiplication, address addition, and end calculations use checked arithmetic.
Initialization fails without publishing allocator state if eligible input is
malformed or exceeds fixed capacity.

`allocate_frame` removes the lowest-address frame from the first free extent.
It advances that extent by one page or removes it when exhausted. Exhaustion is
an explicit result; physical address zero is not an exhaustion sentinel.

`free_frame` accepts one page-aligned frame only when it is inside an immutable
managed extent and is not already free. It inserts the frame in address order
and coalesces it with either or both adjacent free extents. An unaligned,
unmanaged, duplicate, overflowing, or capacity-exceeding free returns a distinct
error and leaves allocator state unchanged. The caller retains ownership when
a free is rejected.

The OS020 implementation will encapsulate the fixed storage behind one
single-owner interface. Interrupts remain disabled and there is no scheduler,
so synchronization is not part of this decision. Any later concurrent access
requires a separate synchronization decision rather than widening the initial
unsafe boundary.

## Alternatives considered

### Bitmap over physical frame numbers

A bitmap represents individual allocation state compactly and makes membership
queries direct. Its storage is proportional to the represented physical span,
including holes, and it introduces a metadata-placement problem before the
allocator can reserve dynamic storage. A fixed bitmap would also impose a less
transparent maximum physical address. It is not selected for the bounded first
allocator.

### Binary buddy allocator

A buddy allocator supports efficient power-of-two runs and coalescing and is a
strong candidate when page tables, larger contiguous allocations, zones, or
concurrency create that requirement. It adds order-specific free structures,
splitting rules, and metadata that OS020's single-frame contract does not yet
exercise. The initial extent representation preserves contiguous runs so a
later decision can migrate to buddy state without changing frame ownership.

### Intrusive free list stored in free frames

Writing links into free frames minimizes separate metadata, but it makes early
allocator correctness depend on writable mappings and on never mistaking live
storage for a free page. It also makes duplicate and unmanaged frees harder to
reject without another ownership index. That trade is not appropriate at the
first post-handoff boundary.

### Monotonic allocation without free

A bump cursor would be smaller, but it cannot satisfy OS020's required recycle
and reuse behavior and would obscure ownership after callers return frames.

## Verification contract for OS020

Host tests must demonstrate:

- initialization copies its state and remains independent of the source map;
- only `MEMORY_USABLE` ranges enter the managed set;
- allocation is page-aligned, lowest-address-first, and deterministic across
  multiple extents;
- exhaustion is explicit;
- freeing and reallocating the first of two allocated frames returns that same
  address;
- left, right, and two-sided coalescing preserve sorted maximal extents;
- duplicate, unaligned, unmanaged, overflowing, and capacity-exceeding frees
  fail without changing state; and
- malformed, overlapping, out-of-order, or over-capacity initialization fails
  without publishing partial state.

The QEMU gate must initialize from the validated handoff, allocate frames A and
B, free A, allocate once more, and prove the result equals A by emitting the
exact terminal serial record `MakopaOS frames v1 ok reuse`. It must not reclaim
loader-owned memory as part of that scenario.

## Consequences

- Kernel frame ownership becomes independent of loader storage before the first
  allocation.
- Allocation order and reuse are reproducible in host tests and QEMU.
- The initial implementation has bounded metadata and no heap dependency, at
  the cost of linear extent operations and a finite fragmentation budget.
- Returning a frame can fail when fragmentation exhausts table capacity; the
  failure is explicit and never silently loses caller ownership.
- Usable memory is intentionally conservative until a later slice proves the
  loader-reclamation transition.
- The handoff ABI and memory-kind values remain unchanged.

## Rollback and reconsideration

Replace this decision before implementation if the fixed tables cannot describe
the pinned QEMU map or the required host fragmentation cases without an
unreasonable bound. Reconsider it when multi-frame allocation, large alignment,
NUMA zones, memory hot-plug, or concurrent allocation becomes an accepted
requirement. A replacement must preserve the same usable-only seed rule,
kernel-owned state, checked failure behavior, and deterministic acceptance
evidence unless another ADR explicitly changes those contracts.

Loader-reclaimable pages remain excluded until a separate decision identifies
the last live loader reference and validates the one-way ownership transfer.

## References

- [ADR-0001: UEFI loader and boot handoff](0001-uefi-loader-and-boot-handoff.md)
- [UEFI 2.11 `GetMemoryMap`](https://uefi.org/specs/UEFI/2.11/07_Services_Boot_Services.html#efi-boot-services-getmemorymap)
- [Linux physical-memory allocator structures](https://cdn.kernel.org/doc/html/latest/mm/physical_memory.html)
