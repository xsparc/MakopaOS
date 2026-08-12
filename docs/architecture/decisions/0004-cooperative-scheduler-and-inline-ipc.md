# ADR-0004: Cooperatively schedule two tasks through bounded IPC

- **Status:** Accepted
- **Date:** 2026-08-13
- **Work item:** OS015
- **Baseline:** `315b97fc697aa4de7e3c8cc138a0f5e367090888`

## Context

OS021 proves that MakopaOS can enter one owned ring-3 address space, recover
from its exact fault, and return every task-owned frame. It deliberately stores
only one active owner and one recovery continuation. OS022 must advance that
boundary to two live owners, preserve a task across kernel entry, select which
task runs next, and transfer one bounded message without weakening ADR-0003's
recovery-root or teardown invariants.

A general scheduler or channel subsystem would introduce timer policy,
concurrent queues, dynamic allocation, handle transfer, and cancellation rules
before MakopaOS can verify the smaller context-switching boundary. The first
multi-task slice instead needs deterministic state and an exact ABI that host
tests, disassembly, and one pinned QEMU transcript can all inspect.

The project remains single-core. Interrupts stay disabled outside synchronous
exception and trap entry, and the reference machine remains QEMU `qemu64` with
one vCPU. OS015 records the contract only; OS022 is the separately approved
implementation boundary.

## Decision

OS022 will implement a cooperative scheduler for exactly two fixed task slots
and one kernel-owned, single-slot endpoint. Tasks enter the kernel through a
version-one DPL3 trap ABI, and a switch preserves the complete architectural
state admitted by the version-one integer-task profile.

All scheduler, task, context, run-queue, and endpoint metadata uses fixed
kernel storage. Publication is all-or-nothing: both address spaces, initial
contexts, endpoint roles, and queue entries validate before the first task can
run. A construction failure follows ADR-0003 rollback and publishes no
schedulable state.

### Cooperative execution boundary

The first scheduler has these fixed constraints:

- exactly two task slots with IDs `1` and `2` and nonzero generations;
- one logical CPU, no timer source, no preemption, and no asynchronous device
  interrupts;
- scheduling only after an explicit trap, a blocking receive, or a task exit;
- a fixed-capacity FIFO run queue containing each ready task exactly once; and
- at most one `Running` task and one active task `CR3` at any instant.

The initial queue is `[2, 1]`: receiver task `2` runs first so the reference
scenario proves the empty-receive block and sender wakeup path. A ready task is
removed from the queue head on dispatch. A cooperative yield appends the
caller to the tail before dispatching the next head. Queue overflow, duplicate
membership, a non-ready member, or a second running task is a deterministic
kernel failure rather than a best-effort repair.

No fairness or latency claim extends beyond this declared two-task FIFO trace.

### Task state machine

Once both slots are published, each task moves through only these scheduling
states:

| Current state | Event | Next state | Queue effect |
| --- | --- | --- | --- |
| `Ready` | dispatch | `Running` | remove head |
| `Running` | yield | `Ready` | append tail |
| `Running` | receive from empty live endpoint | `BlockedReceive` | none |
| `BlockedReceive` | matching send or sender closure | `Ready` | append tail |
| `Running` | exit | `Exited` | none |
| `Exited` | inactive-root teardown completes | `Dead` | none |

`Exited` is a non-runnable teardown state. The kernel must switch to the
recovery root before publishing it, remove every queue or endpoint reference,
and apply ADR-0003's reverse-order unmap, invalidation, and frame-return
contract before publishing `Dead`. A rejected transition leaves the task,
queue, endpoint, allocator, and active-owner record unchanged.

The scheduling state is separate from ADR-0003's address-space lifecycle. The
implementation must prove their allowed pairs: `Running` has an `Active`
owner; `Ready` and `BlockedReceive` have an `Inactive` owner; `Exited` owns an
inactive owner being torn down; and `Dead` has no live owner or generation.

### Complete version-one task context

The version-one task profile consists of fixed, integer-only probe code. A
saved context contains:

- all 15 general-purpose registers other than `RSP`;
- user `RIP`, `RSP`, `RFLAGS`, `CS`, and `SS`;
- the task page-table root, task ID, and generation; and
- the pending trap return status and receive value represented in saved `RAX`
  and `RDX`.

This is a complete switch for every mutable value admitted by the profile; it
is not a callee-saved-register shortcut. Before resume, the kernel validates
canonical user `RIP` and `RSP`, the fixed ring-3 selectors, the task generation
and inactive root, and an `RFLAGS` mask with `IF=0`, `DF=0`, and `IOPL=0`.
Every register not defined as an ABI output is restored exactly.

The fixed probes do not use x87, MMX, SIMD, debug registers, or user TLS.
`CR4.FSGSBASE` remains clear and the user FS and GS bases remain zero, so these
values are not task-switchable state in version one. Arbitrary compiled user
programs are unsupported until a later decision defines extended-state
save/restore, feature negotiation, and TLS.

### DPL3 trap and switch ABI

IDT vector `0x80` is a present 64-bit interrupt gate with descriptor privilege
level 3. Ring-3 probes invoke it with `int 0x80`. The interrupt-gate form keeps
interrupts masked through the entry even if a later slice enables an interrupt
source; that later slice still requires a synchronization decision before it
may preempt scheduler state.

The version-one register ABI is:

| Register | Entry | Return |
| --- | --- | --- |
| `RAX` | operation | status |
| `RDI` | endpoint ID for send or receive; zero otherwise | preserved |
| `RSI` | inline message for send; zero otherwise | preserved |
| `RDX` | zero | received message, otherwise zero |
| all other GPRs | reserved and preserved | original value |

Operations are `0 = yield`, `1 = send`, `2 = receive`, and `3 = exit`. Status
values are `0 = ok`, `1 = invalid operation`, `2 = invalid endpoint`,
`3 = wrong role`, `4 = slot full`, and `5 = peer exited`. Yield and exit reject
nonzero argument registers. Exit does not return after successful validation.
Unknown operations, reserved inputs, invalid endpoints, wrong roles, and a send
to a full slot return their declared status without changing scheduler or IPC
state.

On entry, a stable naked assembly trampoline captures every GPR and the
hardware privilege frame before Rust executes. It clears the direction flag,
loads the ADR-0003 recovery root, establishes the guarded recovery-stack
checkpoint, and only then calls a stable `extern "sysv64"` dispatcher. The
dispatcher copies the complete frame into the current fixed task slot; no
reference into a task mapping survives the root switch.

Resume is the reverse one-way boundary. Assembly validates the selected saved
frame through the dispatcher, installs its task root immediately before the
return sequence, restores every admitted register, and uses `iretq`. Neither
the entry nor resume trampoline may return through a Rust or System V call
frame. Rust and assembly context layouts have compile-time size and offset
assertions.

### Fixed inline IPC contract

The kernel owns endpoint ID `1`. Task `1` is its only sender and task `2` its
only receiver. The endpoint contains exactly:

- the sender and receiver task IDs and generations;
- one `occupied` bit; and
- one inline `u64` payload.

Zero is a valid message, so occupancy never uses a sentinel. IPC copies only
the inline value into kernel metadata. It accepts no user pointer, byte length,
shared-memory reference, handle, capability, or object graph.

A successful send to an empty slot stores the value and wakes a matching
`BlockedReceive` task by appending it to the run-queue tail. A send to an
occupied slot returns `slot full` and preserves the existing value. A receive
from an occupied slot clears it and returns `ok` with the value in `RDX`. A
receive from an empty endpoint blocks; it does not return an empty result or
spin.

Sender exit marks the sender side closed but leaves an occupied value available
to the receiver. If the receiver is blocked with no value, sender closure wakes
it with `peer exited`. Receiver exit discards any unread value during endpoint
teardown and makes subsequent sends return `peer exited`. Once both tasks are
`Dead`, the endpoint is empty, unbound, and contains no live generation.

These role checks are a fixed bootstrap authority boundary, not a substitute
for the task-local capability handles assigned to OS030.

OS022 does not broaden OS021's exact user-fault classifier. Any exception from
either scheduler probe is unexpected and enters the existing deterministic
kernel-failure path; it is not converted into a successful task exit.

### Deterministic reference scenario

The OS022 QEMU scenario will preserve every existing serial record, including
the OS020 frame-reuse and OS021 contained-fault records, then execute this
sequence:

1. publish both task slots, endpoint `1`, and initial queue `[2, 1]`;
2. dispatch receiver task `2`, which blocks on an empty receive;
3. dispatch sender task `1`, which sends `0x00004d414b4f5041` and wakes task
   `2`;
4. let sender task `1` exit and complete its reverse-order teardown;
5. dispatch receiver task `2`, return the exact inline value, and validate it;
6. let receiver task `2` exit and complete its reverse-order teardown; and
7. prove the queue, endpoint, active-owner record, and both task generations are
   empty before emitting:

```text
MakopaOS ipc v1 ok cooperative-two-task
```

Any different task order, value, status, lifecycle transition, residual owner,
or frame count uses the existing failure exit and cannot emit the success
record.

## Verification contract for OS022

Host-side state-machine tests must demonstrate:

- only the declared task and address-space state pairs and transitions succeed;
- FIFO dispatch and yield ordering, unique queue membership, and one-running-
  task invariants hold across bounded operation sequences;
- empty receive blocks, send wakes exactly the receiver, receive consumes once,
  and zero is transferred as ordinary data;
- invalid operations, reserved arguments, wrong endpoints, wrong roles, and a
  full slot return exact, state-preserving errors;
- sender and receiver exit obey the declared close, wake, discard, and peer-
  exited semantics;
- partial publication, blocked-task teardown, peer exit, and each address-space
  construction failure leave no live queue, endpoint, owner, or frame
  reference; and
- teardown traces prove recovery-root activation, removal of runnable and IPC
  references, unmap and invalidation, and frame return in that order.

Context tests must cover every saved register with distinct values, canonical
and selector validation, `RFLAGS` masking, task-generation mismatch, layout
offsets, and exact ABI result placement. Machine-code inspection must prove that
the `0x80` entry captures all GPRs and switches to the recovery root and stack
before calling Rust, and that resume restores the selected root and complete
integer frame through a non-returning `iretq` path.

The existing CI job must retain its host, format, lint, dependency-feature,
lockfile-audit, disassembly, legacy-image, and QEMU gates. OS022 may extend
those gates with scheduler and IPC evidence, but it may not add a job,
permission, third-party dependency, or unpinned machine profile without a new
approval. The QEMU gate remains explicitly `qemu64` with one vCPU and requires
the exact ordered transcript above.

## Alternatives considered

### Add timer-preemptive round robin now

Deferred. Timer entry would make allocator, temporary-window, scheduler, and
serial state concurrently interruptible and would require interrupt-controller,
time-source, locking, and preemption-point contracts. Cooperative traps prove
the complete switch first.

### Use `syscall` and `sysret`

Not selected for version one. They require additional model-specific-register
configuration and synthesize more return state, while `sysret` adds canonical-
address edge cases. The DPL3 IDT gate reuses the already owned descriptor and
privilege-stack boundary and produces a complete hardware return frame.

### Preserve only System V callee-saved registers

Rejected. A trap may occur at an ABI boundary defined by MakopaOS rather than a
compiler call site. Omitting caller-saved values would make yield and blocking
receive depend on undocumented probe behavior and would prevent register-
distinct context evidence.

### Add dynamic channels, multiple slots, or shared buffers

Deferred. These choices require allocation, backpressure, byte-copy limits,
object lifetime, and authority semantics not needed to prove one bounded
exchange. A one-slot inline value makes every ownership transition explicit.

### Add handles or capability transfer to the bootstrap endpoint

Deferred to OS030. Hard-coding the two endpoint roles is intentionally not a
general authorization model, but it prevents ambient access before capability
handles exist.

### Adopt a fair or deadline scheduler

Deferred. Mature schedulers carry per-CPU queues, timing models, priority and
fairness policy, and cross-CPU coordination. None is needed for the two-task
proof, and selecting one now would obscure the context and ownership boundary.

## Consequences

- OS022 has a finite state space suitable for exhaustive bounded host traces
  and a deterministic one-vCPU boot transcript.
- Complete integer contexts make blocking and resumption independent of Rust's
  function-call preservation rules.
- Switching to the recovery root before Rust keeps the dispatcher independent
  of task mappings and preserves ADR-0003 teardown safety.
- The fixed endpoint proves copying, blocking, wakeup, close, and teardown
  semantics without committing the kernel to a dynamic IPC object model.
- Cooperative progress depends on a task trapping or exiting. A task that loops
  forever can starve its peer; MakopaOS makes no availability claim until a
  later preemption decision.
- Fixed roles, integer-only probes, one message slot, and two task IDs are
  intentionally incompatible with general workloads and must not be presented
  as such.

## Rollback and reconsideration

Replace this decision before OS022 if stable assembly cannot preserve the
declared context, if the recovery-root switch cannot precede Rust dispatch, or
if the two address-space ledgers exceed existing fixed bounds. A replacement
must retain complete admitted-state preservation, deterministic transitions,
bounded inline IPC, explicit roles, recovery-root-first dispatch, and
reverse-order frame teardown.

Reconsider the execution profile before admitting arbitrary compiled user
programs, user TLS, or floating-point and vector instructions. Reconsider the
scheduler before enabling timer or device interrupts, more than two tasks,
priorities, time accounting, SMP, PCID, or global mappings. Reconsider IPC
before adding dynamic endpoints, byte payloads, multiple queued messages,
shared memory, handles, cancellation, or capability transfer. Each expansion
must define its synchronization, invalidation, ownership, and rollback
contract before the feature becomes active.

## References

- [ADR-0003: Address-space and fault containment](0003-address-space-and-fault-containment.md)
- [Intel 64 and IA-32 Software Developer's Manual, version 092](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- [AMD64 Architecture Programmer's Manual, Volume 2, revision 3.44](https://docs.amd.com/v/u/en-US/24593_3.44_APM_Vol2)
- [Rust Reference: inline and naked assembly](https://doc.rust-lang.org/reference/inline-assembly.html)
- [seL4 16.0.0 release notes](https://docs.sel4.systems/releases/sel4/16.0.0.html)
- [seL4 IPC tutorial](https://docs.sel4.systems/Tutorials/ipc)
- [Fuchsia Zircon scheduler](https://fuchsia.dev/fuchsia-src/concepts/kernel/kernel_scheduling)
- [Fuchsia channel object](https://fuchsia.dev/fuchsia-src/reference/kernel_objects/channel)
