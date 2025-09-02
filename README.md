# MakopaOS: A Minimal x86 Bootloader Operating System

MakopaOS is a simple, educational operating system bootloader written in x86 assembly. It demonstrates how to create a bootable binary that prints a custom message ("MAKOPA") to the screen using BIOS interrupts. This project is ideal for those learning about low-level programming, operating system fundamentals, and x86 architecture.

## Features
- 16-bit real mode x86 assembly
- BIOS interrupt usage for direct screen output
- Minimal boot sector (512 bytes)
- Educational and easy to understand

## Getting Started

### Prerequisites
- [NASM](https://www.nasm.us/) (Netwide Assembler)
- [QEMU](https://www.qemu.org/) (for emulation/testing)
- [ndisasm](https://www.nasm.us/doc/nasmdoc8.html) (optional, for disassembly)

### Building the Boot Sector

Assemble the bootloader source code into a bootable binary:

```sh
nasm -f bin -o boot.bin boot.asm
```

### Inspecting the Binary (Optional)

Disassemble the binary to view the generated assembly instructions:

```sh
ndisasm ./boot.bin
```

### Running MakopaOS in QEMU

Boot the binary in a virtual machine using QEMU:

```sh
qemu-system-x86_64 -hda ./boot.bin
```

## Project Structure
- `boot.asm` — Main bootloader source code (x86 assembly)
- `boot.bin` — Compiled boot sector binary (generated)

## Contributing
Contributions, suggestions, and improvements are welcome! Please open an issue or submit a pull request.

## License
This project is released under the Apache License.

---

*Keywords: x86 bootloader, operating system, assembly, BIOS interrupt, NASM, QEMU, educational OS, minimal OS, open source*
