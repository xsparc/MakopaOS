# Testing MakopaOS

The test strategy follows the architecture outward: validate pure contracts on
the host, validate binary artifacts without booting, then validate behavior in
QEMU. Real-hardware testing is milestone-specific and never implied by a virtual
machine result.

## Repository and contract gates

```sh
python -m unittest discover -s tests -v
python scripts/check_project_evidence.py
python scripts/check_project_evidence.py --as-of YYYY-MM-DD --strict
cargo +1.97.1 fmt --all -- --check
cargo +1.97.1 test --locked \
  -p makopa-address-space \
  -p makopa-boot-contract \
  -p makopa-frame-allocator \
  -p makopa-kernel-image \
  -p makopa-task-runtime
```

The Rust tests enforce the ADR-0001 handoff sizes and field offsets, exercise
the bounded ELF64 parser, normalize protected memory ranges, and reject
malformed handoff headers, pointers, counts, regions, attributes, and
framebuffers on the host. The ADR-0002 allocator tests cover copied ownership,
usable-only seeding, lowest-address allocation, explicit exhaustion, sorted
coalescing, fragmentation capacity, state-preserving errors, source lifetime,
and exhaustive small sequences against a reference model. Its two 1,024-entry
extent tables occupy 32,784 bytes, below the reviewed 40 KiB static limit.
The ADR-0003 address-space tests cover fixed W^X/NX mappings, canonical and
guarded bounds, fragmented frame ownership, lifecycle and generation checks,
every forward construction failure, reverse-order rollback and teardown,
temporary-window clearing, reachability proof before return, and retained
ownership when a frame return is rejected. Its task ledger remains bounded to
16 entries and the implemented probe owns seven frames.
The ADR-0004 task-runtime tests cover complete distinct-register contexts,
canonical and selector checks, `RFLAGS` masks, generation and root matching,
the receiver-first FIFO, yield ordering, empty-receive blocking, exact wake and
result placement, zero-valued messages, full-slot preservation, exact ABI
rejections, both peer-close directions, empty residual state, and bounded
operation traces. Address-space tests additionally inject every failure in a
second construction and prove that the already-built first owner is unwound
before publication.
The ADR-0005 tests cover exact selector encoding, zero and stale rejection,
task-local lookup, object and rights precedence, subset-only attenuation,
independent duplicate close, deterministic lowest-slot allocation and reuse,
all 16 slots, full and retired-slot exhaustion, maximum-generation retirement,
publication rollback at every initial-table step, peer-close behavior, and the
observable `Live`-to-`Closing`-to-`Dead` handle-first teardown sequence. The
task runtime remains `no_std`, fixed-storage, and dependency-free.
Normalization remains capped at 1,024 fixed-size region records backed by a 24
KiB loader-owned buffer. The static evidence check validates schema,
traceability, local references, and accepted-decision coverage. The dated
strict check additionally blocks overdue reviews. Both evidence commands are
offline and use only the Python standard library.

## Legacy boot-sector gate

```sh
nasm -Wall -Werror -f bin -o boot.bin boot.asm
python scripts/verify_boot.py boot.bin
```

The verifier checks:

- exact 512-byte size;
- the little-endian `0xAA55` signature at bytes 510 and 511;
- the null-terminated `MAKOPA` payload.

This compatibility gate intentionally avoids screenshots and timing-sensitive
emulation.

## UEFI kernel-entry gate

CI provisions Rust `1.97.1`, `uefi` `0.39.0`, QEMU
`1:8.2.2+ds-0ubuntu1.18`, and OVMF `2024.02-2ubuntu0.9`. System packages come
from Ubuntu snapshot `20260810T000000Z`; the source definition is tracked at
`ci/ubuntu-snapshot.sources`.

The kernel pins `x86_64` `0.15.5` without default or nightly-only features.
The stable exception boundary is checked separately from host behavior:

```sh
cargo +1.97.1 tree --locked -e features \
  -p makopa-kernel --target x86_64-unknown-none | \
  python scripts/verify_dependency_features.py - \
    --task-manifest crates/task-runtime/Cargo.toml
python scripts/verify_exception_trampolines.py \
  --objdump /path/to/rust-sysroot/lib/rustlib/HOST/bin/llvm-objdump \
  --kernel target/x86_64-unknown-none/release/makopa-kernel
```

The feature check requires only the crate's stable `instructions` feature,
rejects `default`, `nightly`, `abi_x86_interrupt`, or `step_trait`, and verifies
that `makopa-task-runtime` has no dependency table entries. The disassembly
check preserves the owned page-fault, general-protection, and double-fault
checks and additionally proves that vector `0x80` captures all GPRs, installs
the recovery root and stack checkpoint before Rust dispatch, and restores the
task root and complete integer frame through `iretq`. It also inspects both
fixed probes: the sender must issue duplicate, close, stale send, attenuated
send, close, and exit in that order; the receiver must issue receive, close,
and exit. The sender must require exact stale-handle status `6`, both probes
must retain the message constant, and both retain deterministic failure
transfer. CI obtains `llvm-objdump` from the pinned stable toolchain's
`llvm-tools-preview` component; no nightly compiler is installed.

```sh
python scripts/build_uefi.py
python scripts/verify_uefi_boot.py \
  --ovmf-code /usr/share/OVMF/OVMF_CODE_4M.fd \
  --ovmf-vars /usr/share/OVMF/OVMF_VARS_4M.fd \
  --esp build/esp
```

The build command creates a standard fallback layout containing
`EFI/BOOT/BOOTX64.EFI` and `MAKOPA/KERNEL.ELF`. The verifier first confirms the
QEMU executable exposes `isa-debug-exit`, boots the directory through a
read-only VVFAT device with a disposable OVMF variable store, and then requires
both:

- the exact kernel transcript `MakopaOS 0.1.0\r\n`, followed by
  `MakopaOS handoff v1 ok framebuffer\r\n` and
  `MakopaOS frames v1 ok reuse\r\n`, followed by
  `MakopaOS isolation v1 ok user-fault-contained\r\n`, followed by
  `MakopaOS ipc v1 ok cooperative-two-task\r\n`, followed by
  `MakopaOS capabilities v1 ok task-local-attenuation\r\n`, appears once as
  the terminal serial sequence after any firmware console records;
- QEMU process status `33`, produced by writing success value `0x10` to port
  `0xf4`.

The handoff record proves the kernel accepted a non-empty, aligned, ordered,
non-overlapping normalized map and RGB or BGR framebuffer metadata. The frame
record proves the kernel then initialized its owned allocator, allocated frames
A and B, freed A, and received A from the next allocation. The scenario does
not stop there: QEMU is explicitly started with `-cpu qemu64 -smp 1`, and the
isolation record proves that the kernel switched away from inherited firmware
page tables, entered the fixed CPL-3 probe, classified its exact invalid write,
recovered without resuming it, and returned every task-owned frame after
unmapping and invalidation. The IPC record then proves the receiver-first block,
sender wake, exact inline transfer, complete register-preserving resume, both
task exits, and empty queue, endpoint, active-owner, generation, and frame
ownership state. The scenario does not reclaim loader-owned memory, exercise
timer preemption, asynchronous interrupts, SMP or concurrent allocator access,
load arbitrary user binaries, preserve SIMD or TLS state, or claim real-
hardware compatibility.

The capability record extends that same receiver-first run. Task 1 duplicates
its initial `SEND | DUPLICATE` handle into a `SEND`-only handle, closes the
source, proves selector `0x10` stale even though the peer table independently
contains that number, sends the fixed value through selector `0x11`, and closes
it. Task 2 receives through its own selector `0x10` and closes it. Runtime
teardown then proves both tables empty and dead before the address-space owners
can return frames. This evidence does not claim selector secrecy, cross-task
transfer, recursive revocation, dynamic objects, policy, or effect logging.

## Dependency audit

CI installs `cargo-audit` `0.22.2` from its published lockfile and runs:

```sh
cargo +1.97.1 audit --deny warnings
```

This audits the committed `Cargo.lock`, including the exact `x86_64` `0.15.5`
resolution. It does not imply compiler, firmware,
or system-package provenance beyond the inputs pinned by ADR-0001.

## Validation language

Report commands exactly. Distinguish:

- **passed**: the command ran and returned its documented success result;
- **failed**: the command ran and found a defect;
- **not run**: a tool, environment, or approved target was unavailable;
- **not applicable**: the change cannot affect that check's boundary.
