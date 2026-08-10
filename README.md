# MakopaOS

MakopaOS is a compact operating-systems laboratory for learning how a machine
boots and how a small kernel can enforce explicit authority between isolated
workloads.

Today the repository contains a 512-byte, 16-bit BIOS boot sector that prints
`MAKOPA`. The proposed direction preserves that working baseline while growing
toward an x86-64, capability-oriented runtime with deterministic tests and a
small, auditable trusted core.

## Current capabilities

- boots as a legacy BIOS sector;
- initializes the real-mode segment and stack registers;
- writes through BIOS interrupt `0x10`;
- produces an exact 512-byte image with the `0x55AA` boot signature.

## Build and verify

Prerequisites:

- [NASM](https://www.nasm.us/);
- Python 3.11 or newer;
- [QEMU](https://www.qemu.org/) for interactive boot testing.

```sh
nasm -Wall -Werror -f bin -o boot.bin boot.asm
python scripts/verify_boot.py boot.bin
qemu-system-x86_64 -drive format=raw,file=boot.bin
```

`boot.bin` is generated and intentionally excluded from version control.

## Direction

The target is an educational runtime with four clear boundaries:

1. firmware-specific boot code;
2. a memory-safe kernel core for memory, tasks, IPC, and capability handles;
3. isolated system services with structured event records;
4. optional user-space gateways for external workload protocols.

The kernel will remain independent of model vendors and network services.
External requests are data, not authority: privileged operations require
explicit capabilities and produce inspectable evidence.

See [the architecture](docs/architecture/overview.md), [the roadmap](docs/roadmap/implementation-roadmap.md), and [the contribution guide](CONTRIBUTING.md).

## License

MakopaOS is licensed under the Apache License 2.0.
