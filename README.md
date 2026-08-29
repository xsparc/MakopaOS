# MakopaOS

MakopaOS is a compact operating-systems laboratory for learning how a machine
boots and how a small kernel can enforce explicit authority between isolated
workloads.

The repository preserves a 512-byte, 16-bit BIOS boot sector that prints
`MAKOPA` and now also boots a freestanding x86-64 Rust kernel through a thin
UEFI loader. The project grows through deterministic, reviewable slices toward
a capability-oriented runtime with a small, auditable trusted core.

## Current capabilities

- boots as a legacy BIOS sector;
- initializes the real-mode segment and stack registers;
- writes through BIOS interrupt `0x10`;
- produces an exact 512-byte image with the `0x55AA` boot signature;
- builds a pinned UEFI application and ELF kernel with Rust `1.97.1`;
- validates the kernel ELF and a populated version-one memory-map handoff;
- carries RGB or BGR framebuffer metadata without exposing firmware protocols;
- copies usable memory into a bounded kernel-owned physical-frame allocator;
- allocates, recycles, and deterministically reuses page-aligned frames;
- installs a kernel-owned recovery address space and guarded exception stacks;
- contains one exact ring-3 page fault and returns all task-owned frames;
- cooperatively switches complete integer contexts between two fixed ring-3
  tasks through a DPL3 trap;
- transfers one inline `u64` through a fixed single-slot endpoint and tears
  both address spaces down in reverse ownership order;
- resolves endpoint access through one fixed 16-slot capability table per task,
  with typed rights, subset-only same-task duplication, independent close,
  generation-tagged stale rejection, and handle-first teardown;
- preserves that cooperative profile while separately launching a fixed staged
  workload from one immutable default-deny manifest, mediating its declared
  request through a bounded approval broker, and consuming one exact approval
  to commit one synthetic in-memory effect; and
- emits deterministic version, handoff, frame-reuse, fault-containment, and
  cooperative-IPC, capability-attenuation, and approval-boundary records over
  the serial console before exiting QEMU.

## Build and verify

Prerequisites:

- Rust `1.97.1` with the `x86_64-unknown-none` and
  `x86_64-unknown-uefi` targets;
- [NASM](https://www.nasm.us/) `2.16.01`;
- Python 3.11 or newer;
- [QEMU](https://www.qemu.org/) `8.2.2` and OVMF `2024.02` for the UEFI
  smoke test.

```sh
nasm -Wall -Werror -f bin -o boot.bin boot.asm
python scripts/verify_boot.py boot.bin
cargo +1.97.1 test --locked \
  -p makopa-address-space \
  -p makopa-boot-contract \
  -p makopa-frame-allocator \
  -p makopa-kernel-image \
  -p makopa-task-runtime
python scripts/build_uefi.py
python scripts/verify_uefi_boot.py \
  --ovmf-code /usr/share/OVMF/OVMF_CODE_4M.fd \
  --ovmf-vars /usr/share/OVMF/OVMF_VARS_4M.fd \
  --esp build/esp
```

`boot.bin`, `build/esp`, and Cargo target artifacts are generated and
intentionally excluded from version control. CI provisions the exact Ubuntu
snapshot package revisions recorded in ADR-0001.

## Direction

The target is an educational runtime with four clear boundaries:

1. firmware-specific boot code;
2. a memory-safe kernel core for memory, tasks, IPC, and capability handles;
3. isolated system services with structured event records;
4. optional user-space gateways for external workload protocols.

The kernel will remain independent of model vendors and network services.
External requests are data, not authority: privileged operations require
explicit capabilities and produce inspectable evidence.

See [the architecture](docs/architecture/overview.md),
[the roadmap](docs/roadmap/implementation-roadmap.md),
[the project evidence guide](docs/governance/project-evidence.md), and
[the contribution guide](CONTRIBUTING.md).

## License

MakopaOS is licensed under the Apache License 2.0.
