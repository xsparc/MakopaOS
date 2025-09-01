# MakopaOS
Built from ground up operating system for the modern world.

# Assemble the boot sector with NASM
nasm -f bin -o boot.bin boot.asm  # Assemble boot.asm into a 512-byte bootable binary

# Disassemble the binary for inspection (optional)
ndisasm ./boot.bin  # View the assembly instructions in boot.bin

# Run the boot sector in QEMU
qemu-system-x86_64 -hda ./boot.bin  # Boot the binary in a virtual machine
