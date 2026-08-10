# Testing MakopaOS

The test strategy follows the architecture outward: validate pure contracts on
the host, validate binary artifacts without booting, then validate behavior in
QEMU. Real-hardware testing is milestone-specific and never implied by a virtual
machine result.

## Boot-sector gate

```sh
python -m unittest discover -s tests -v
nasm -Wall -Werror -f bin -o boot.bin boot.asm
python scripts/verify_boot.py boot.bin
```

The verifier checks:

- exact 512-byte size;
- the little-endian `0xAA55` signature at bytes 510 and 511;
- the null-terminated `MAKOPA` payload.

The gate intentionally avoids screenshots and timing-sensitive emulation. A
later QEMU smoke test will use serial output and an explicit exit device so CI
can compare a deterministic transcript.

## Validation language

Report commands exactly. Distinguish:

- **passed**: the command ran and returned its documented success result;
- **failed**: the command ran and found a defect;
- **not run**: a tool, environment, or approved target was unavailable;
- **not applicable**: the change cannot affect that check's boundary.
