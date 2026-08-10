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
- validates the version-one boot ABI and kernel ELF before transfer;
- emits `MakopaOS 0.1.0` over a dedicated serial channel and exits QEMU
  deterministically.

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
cargo +1.97.1 test --locked -p makopa-boot-contract -p makopa-kernel-image
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
