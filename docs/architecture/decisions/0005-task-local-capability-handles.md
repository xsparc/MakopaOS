# ADR-0005: Mediate endpoint authority with task-local capability handles

- **Status:** Accepted
- **Date:** 2026-08-13
- **Work item:** OS016
- **Baseline:** `5d5a49de783dae05abbd4abc6f21b458aee640f9`

## Context

OS022 runs two isolated tasks through one fixed endpoint, but endpoint ID `1`
and hard-coded sender and receiver roles are still bootstrap authorization. A
task that presents the expected integer is accepted because the runtime already
knows its role. OS030 must replace that special case with explicit authority
without adding dynamic allocation, object transfer, policy, or a second IPC
mechanism.

Capability systems commonly separate the user-visible selector from the
kernel-owned authority it names. seL4 stores capabilities in task-visible
slots, while Zircon resolves process-local handle values to typed kernel
objects and associates rights with each handle. Zircon duplication permits
rights to stay equal or become a strict subset. These patterns fit MakopaOS's
fixed-storage and no-ambient-authority principles, but their full object,
transfer, and revocation models are larger than the next vertical slice.

The current kernel has no entropy source. A random or secret bearer value would
therefore create an unsupported security claim. The authority boundary must
instead be the kernel-owned table entry: a workload may guess an integer, but
cannot create an entry, change its type or rights, or make another task's table
resolve it.

## Decision

OS030 will give each of the two fixed tasks one kernel-owned capability table
containing exactly 16 slots. A selector is meaningful only when resolved in
the current task's live table. Tables are never shared, and the same integer in
two tasks names two independent entries, if both entries exist.

Each table is bound to one task ID and non-zero task generation and moves
through `Building`, `Live`, `Closing`, and `Dead`. Only `Live` tables resolve or
mutate handles. `Building` is private construction state, `Closing` is a
one-way teardown state, and `Dead` has no task binding or object reference. A
rejected transition preserves the complete table.

Version one supports one object type, `Endpoint`, and three rights:

| Right | Bit | Authority |
| --- | --- | --- |
| `SEND` | `1 << 0` | Send one inline `u64` through the referenced endpoint. |
| `RECEIVE` | `1 << 1` | Receive or block on the referenced endpoint. |
| `DUPLICATE` | `1 << 2` | Create another handle in the same task with equal or reduced rights. |

All other right bits are invalid. Every live entry has a non-empty rights set,
an object type, a typed endpoint reference, and the generation of the task and
endpoint to which it is bound. The fixed OS022 endpoint remains the only
endpoint object. OS030 changes how tasks authorize access to it; it does not
make the endpoint dynamic or change its single-slot inline-message semantics.

The initial publication gives task `1` one `SEND | DUPLICATE` handle and task
`2` one `RECEIVE` handle. No task receives a handle for a device, address space,
frame, credential, policy service, or any other object.

### Selector encoding and stale rejection

A `CapabilityHandleV1` is an opaque `u64` with this fixed encoding:

- bits `0..=3` contain the zero-based slot index `0..=15`;
- bits `4..=63` contain a non-zero 60-bit slot generation; and
- value zero is always invalid.

Each slot starts empty at generation `1`. A live selector is
`(generation << 4) | slot_index`. Resolution validates the current task ID and
generation and its live table, decodes the complete selector, checks that the
slot is live, and compares the selector generation with the slot generation
before reading the entry. An empty, malformed, closed, or generation-
mismatched selector returns `invalid handle` without changing any state. A
number observed in another task grants no cross-task authority: it is invalid
when absent from the caller's table, and if the same number independently names
a caller entry, only that caller entry's type and rights apply.

Closing a slot removes its entry before advancing its generation. Generations
never wrap. Closing a slot at generation `2^60 - 1` removes the authority and
permanently retires that slot; later allocation cannot reuse it. Allocation
chooses the lowest-index empty, non-retired slot. A retired slot is skipped,
and failure to find an allocatable slot is explicit. Thus stale selectors
cannot become valid again, even after repeated slot reuse.

Close still succeeds at the maximum generation: it removes the authority and
retires the slot instead of returning an error or leaving the entry live.

The selector is not confidential and is not a cryptographic bearer token.
Unforgeability means that only the kernel can install a typed entry in a task's
table. Guessing a number cannot mint an entry, cross into another table, change
rights, or amplify the authority already installed for the caller.

### Lookup and rights checks

Send and receive replace ADR-0004's raw endpoint ID in `RDI` with a capability
selector. The kernel resolves each request in this order:

1. validate that the caller's task identity, generation, and table are live;
2. decode the selector and match the occupied slot and slot generation;
3. require the `Endpoint` object type;
4. require `SEND` or `RECEIVE`, as appropriate; and
5. match the entry's endpoint identity and generation to the live endpoint.

Failure at any step is state-preserving. Invalid or stale selectors report
`invalid handle`; a different object type reports `wrong object`; absent rights
report `rights denied`; and a stale endpoint reference reports `invalid
handle`. No endpoint payload, queue state, task state, or capability entry is
modified before all checks pass.

Rights are an allow-list, not a task role. Once a valid handle resolves, the
operation is authorized by its type and rights. OS030 removes the fixed sender
and receiver role checks from the send and receive authorization path while
retaining the endpoint's peer-lifetime and blocking rules.

### Duplication and close

ADR-0004's trap ABI gains two version-one operations:

| Operation | `RAX` | Inputs | Successful output |
| --- | --- | --- | --- |
| duplicate | `4` | `RDI = source`, `RSI = requested rights`, `RDX = 0` | `RDX = new handle` |
| close | `5` | `RDI = handle`, `RSI = 0`, `RDX = 0` | `RDX = 0` |

The existing operations and status values retain their numbers. OS030 appends
these exact status values:

| Status | Value | Meaning |
| --- | --- | --- |
| `InvalidHandle` | `6` | Selector, slot, task binding, or object generation is invalid or stale. |
| `WrongObject` | `7` | The live entry has a type unsupported by the requested operation. |
| `RightsDenied` | `8` | The entry lacks an operation or duplication right. |
| `InvalidRights` | `9` | A requested duplication mask is zero, unknown, or not a subset. |
| `HandleTableFull` | `10` | All 16 slots are occupied. |
| `GenerationExhausted` | `11` | At least one slot is retired and every non-retired slot is occupied. |

If no allocatable slot exists, `HandleTableFull` applies only when every slot
is occupied. Otherwise the presence of a retired slot makes the result
`GenerationExhausted`. Both failures preserve the complete table and ABI
output state.

Duplication requires `DUPLICATE` on the source. Requested rights must be a
non-empty subset of the source rights and of the version-one rights mask. The
new entry references the same typed endpoint and is installed only in the
caller's table. Allocation and validation complete before either table state or
ABI output changes. Failure from invalid rights, a stale source, or exhausted
table capacity leaves the source and table unchanged.

There is no cross-task transfer. Closing one handle removes only that table
entry. Duplicates are independent: closing the source does not close, revoke,
or alter an already-created duplicate. Handles do not own or reference-count
the fixed endpoint, so closing the last handle does not synthesize peer exit or
destroy endpoint state. The existing task-lifecycle boundary owns endpoint-side
closure.

Recursive revocation and capability-derivation trees are intentionally absent.
They require ancestry metadata, transfer semantics, and atomic descendant
walks that the two-task fixed endpoint does not need.

### Publication, rollback, and teardown

Task tables, their initial entries, endpoint bindings, address spaces, task
contexts, and run-queue entries publish as one validated unit. Construction
records every installed entry before making the task runnable. Any failure
removes capability entries in reverse installation order, clears endpoint and
task references, then follows ADR-0003 and ADR-0004 address-space rollback. No
partially initialized table becomes visible to a task.

Normal task teardown preserves the recovery-root-first boundary and proceeds
without interruption in this order:

1. switch to and validate the kernel recovery root;
2. mark the task's capability table closing so resolution, duplicate, and close
   requests are rejected;
3. remove every live handle, advance or retire each slot generation, and prove
   that the table contains no object reference;
4. remove the task from endpoint, blocked-receive, run-queue, and active-owner
   state while applying ADR-0004 peer-close semantics;
5. unmap and invalidate the task address space; and
6. return address-space frames, clear the task identity and table task binding,
   and publish `Dead`.

A frame cannot be returned while a capability entry, endpoint binding, queue
entry, mapping, temporary alias, or active root can still reach task-owned
state. A rejected close or teardown step preserves ownership of everything not
yet removed and cannot publish `Dead`.

## Verification contract for OS030

Host tests must demonstrate:

- exact selector encoding, zero rejection, task-local lookup, and deterministic
  lowest-slot allocation;
- invalid, malformed, empty, closed, generation-mismatched, and endpoint-
  generation-mismatched handles fail without state change, including a
  selector that is live in the peer table but absent from the caller table;
- object-type checks precede operation dispatch and missing `SEND`, `RECEIVE`,
  or `DUPLICATE` rights are denied;
- attenuation accepts only a non-empty subset, never adds rights, and preserves
  the source on every rejection;
- same-task duplication creates an independent entry, source close leaves the
  duplicate usable, and closing the duplicate leaves the source unchanged;
- all 16 slots, table exhaustion, deterministic reuse, stale-slot rejection,
  maximum-generation retirement, and failure without generation wrap;
- publication failure at every initial-table step leaves no live handle,
  endpoint reference, task, owner, or frame; and
- task teardown removes handles before endpoint and task references and removes
  those references before address-space invalidation and frame return.

The existing host, format, lint, dependency-feature, lockfile-audit,
disassembly, legacy-image, and pinned QEMU gates remain required. OS030 may add
capability evidence to the existing CI job but cannot add permissions, dynamic
dependencies, an unpinned machine profile, or another job without approval.

The QEMU `qemu64` one-vCPU scenario must preserve the existing ordered serial
records, then:

1. publish the sender's `SEND | DUPLICATE` handle and receiver's `RECEIVE`
   handle;
2. duplicate the sender handle with `SEND` only;
3. close the original and prove its stale selector is rejected;
4. send the fixed inline value through the attenuated duplicate;
5. receive the value through the receiver's task-local handle;
6. prove a numeric selector from the other task grants no cross-task authority;
7. close remaining handles and tear down both tasks in the declared order; and
8. prove both tables, endpoint state, task references, and owned frames are
   empty before emitting the exact terminal record:

```text
MakopaOS capabilities v1 ok task-local-attenuation
```

OS030 must not claim arbitrary user workloads, cryptographic handle secrecy,
cross-task delegation, recursive revocation, dynamic endpoint lifetime, device
authority, policy approval, or effect logging from this evidence.

## Alternatives considered

### Keep raw endpoint IDs and fixed roles

Rejected. That mechanism proves IPC but makes authorization implicit in task
identity and endpoint-specific code. It cannot express attenuation or
independent duplicate lifetime.

### Use random global bearer tokens

Rejected. MakopaOS has no entropy source, global token lookup would weaken task
locality, and secrecy would become an unsupported authorization dependency.
Randomized selector allocation may later improve misuse resistance, but table
membership and rights must remain the security boundary.

### Add transferable capabilities and recursive revocation

Deferred. seL4-style derivation and revocation are valuable for a system that
passes capabilities between protection domains, but OS030 explicitly has no
transfer path. Adding ancestry metadata now would create unverified policy and
teardown states.

### Use dynamically sized tables or a general object store

Deferred. Fixed tables match the two-task runtime, make exhaustion executable,
and require no heap. Dynamic objects should be introduced only with explicit
allocation, lifetime, synchronization, and rollback requirements.

## Consequences

- Endpoint access becomes explicit per task and per operation without changing
  the existing endpoint payload or scheduling model.
- Rights can only stay equal or decrease through same-task duplication.
- Slot generations make close and deterministic reuse safe without relying on
  selector secrecy.
- A 16-slot bound makes metadata and failure evidence finite, at the cost of a
  deliberately small authority budget.
- Independent duplicate close is simple and deterministic, but version one
  cannot revoke a whole family of derived handles at once.
- Transfer, policy, approval, effect attribution, and external protocol
  identity remain user-space roadmap concerns after OS030.

## Rollback and reconsideration

Replace this decision before OS030 if the fixed runtime cannot remove handle
references before endpoint and frame teardown, if stable selector decoding
cannot reject stale generations without partial mutation, or if the 16-slot
bound cannot cover the declared host and QEMU scenarios. A replacement must
preserve task-local resolution, typed rights, monotonic attenuation,
state-preserving failure, and fail-closed stale-handle behavior.

Reconsider the table size and object model before dynamic task or endpoint
creation. Reconsider transfer and recursive revocation only when an approved
work item requires cross-task delegation. Reconsider selector randomization
only after a reviewed entropy source exists, and never make secrecy substitute
for a valid table entry. SMP, asynchronous interrupts, or preemption require a
separate synchronization decision before capability tables become concurrent.

## References

- [ADR-0003: Address-space and fault containment](0003-address-space-and-fault-containment.md)
- [ADR-0004: Cooperative scheduler and inline IPC](0004-cooperative-scheduler-and-inline-ipc.md)
- [seL4 capability tutorial](https://docs.sel4.systems/Tutorials/capabilities.html)
- [Zircon handles](https://fuchsia.dev/fuchsia-src/concepts/kernel/handles)
- [Zircon rights](https://fuchsia.dev/fuchsia-src/concepts/kernel/rights)
- [Zircon handle duplication](https://fuchsia.dev/reference/syscalls/handle_duplicate)
- [Fuchsia software isolation model](https://fuchsia.dev/fuchsia-src/get-started/learn/intro/sandboxing)
- [NIST software and AI agent identity and authorization concept](https://www.nccoe.nist.gov/sites/default/files/2026-02/accelerating-the-adoption-of-software-and-ai-agent-identity-and-authorization-concept-paper.pdf)
- [OpenAI and Hugging Face evaluation-security incident](https://openai.com/index/hugging-face-model-evaluation-security-incident/)
