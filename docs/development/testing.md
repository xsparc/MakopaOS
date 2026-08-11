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
cargo +1.97.1 test --locked -p makopa-boot-contract -p makopa-kernel-image
```

The Rust tests enforce the ADR-0001 handoff sizes and field offsets, exercise
the bounded ELF64 parser, normalize protected memory ranges, and reject
malformed handoff headers, pointers, counts, regions, attributes, and
framebuffers on the host. Normalization is capped at 1,024 fixed-size region
records backed by a 24 KiB loader-owned buffer. The static evidence check
validates schema, traceability, local references, and accepted-decision
coverage. The dated strict check additionally blocks overdue reviews. Both
evidence commands are offline and use only the Python standard library.

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

- the exact kernel transcript `MakopaOS 0.1.0\r\n` followed by
  `MakopaOS handoff v1 ok framebuffer\r\n` appears once as the terminal serial
  sequence, after any firmware console records;
- QEMU process status `33`, produced by writing success value `0x10` to port
  `0xf4`.

The validated record proves the kernel accepted a non-empty, aligned, ordered,
non-overlapping normalized map and RGB or BGR framebuffer metadata. It does not
claim real-hardware compatibility or authorize any page reclamation; those
boundaries remain later roadmap work.

## Dependency audit

CI installs `cargo-audit` `0.22.2` from its published lockfile and runs:

```sh
cargo +1.97.1 audit --deny warnings
```

This audits the committed `Cargo.lock`. It does not imply compiler, firmware,
or system-package provenance beyond the inputs pinned by ADR-0001.

## Validation language

Report commands exactly. Distinguish:

- **passed**: the command ran and returned its documented success result;
- **failed**: the command ran and found a defect;
- **not run**: a tool, environment, or approved target was unavailable;
- **not applicable**: the change cannot affect that check's boundary.
