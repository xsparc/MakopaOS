# ADR-0001: Own the UEFI loader and versioned boot handoff

- **Status:** Accepted
- **Date:** 2026-08-10
- **Work item:** OS010
- **Baseline:** `7c8c62bbe2cf548b7a92ef52b9cc9a98242c7a62`

## Context

MakopaOS needs a reproducible x86-64 path from UEFI firmware to a freestanding
kernel. The loader must keep firmware-specific data out of the kernel, preserve
the existing BIOS diagnostic, and leave room to replace the loader without
changing kernel internals.

The initial choice is between a small MakopaOS-owned UEFI application and the
maintained `rust-osdev/bootloader` project. The maintained loader offers an
established kernel-loading path, but its `0.11.17` release remains explicitly
experimental, requires nightly Rust and `llvm-tools-preview`, and exposes its
own `bootloader_api` at kernel entry. Those constraints would broaden the first
modern-boot slice and couple the kernel boundary to another project's API.

## Decision

MakopaOS will own a thin UEFI loader. It will be a Rust UEFI application whose
responsibilities are limited to:

1. loading and validating the MakopaOS x86-64 kernel image;
2. collecting the final firmware memory map and optional framebuffer details;
3. translating firmware data into the MakopaOS handoff described below;
4. calling `ExitBootServices` with a freshly obtained map key; and
5. transferring control once to the kernel entry point.

The kernel artifact consumed by the loader is a little-endian x86-64 ELF
executable produced for `x86_64-unknown-none`. The loader parses only the ELF
header, program-header table, and bounded `PT_LOAD` segments; it rejects wrong
class, byte order, machine, type, entry placement, alignment, overlap, and
integer overflow. Whether OS011 embeds that artifact or places it on the EFI
system partition does not alter the kernel entry or handoff ABI.

The loader will not contain policy, drivers beyond those needed for boot,
network access, a general-purpose runtime, or kernel services. It must not make
Boot Services calls after `ExitBootServices` succeeds. UEFI handles, protocol
pointers, raw memory descriptors, and other firmware-owned pointers do not
cross the handoff.

### Pinned inputs

The first implementation must use these exact inputs. Updating any row requires
a later reviewed change with the same compatibility and verification evidence.

| Input | Pin | Provisioning contract |
| --- | --- | --- |
| Rust toolchain | `1.97.1` | Install the exact stable patch release; do not follow `stable` implicitly. |
| UEFI library | `uefi = "=0.39.0"` | Use the smallest feature set needed by the loader and commit the resulting lockfile in OS011. |
| Firmware specification | UEFI `2.11` | Treat `ExitBootServices` and memory-map lifetime rules as normative. |
| Loader target | `x86_64-unknown-uefi` | Use Rust's prebuilt Tier 2 target. |
| Kernel target | `x86_64-unknown-none` | Build a freestanding x86-64 kernel without a host OS ABI. |
| Rust linker | the `rust-lld` bundled with Rust `1.97.1` | Use the target's LLVM lld link flavor; do not resolve a host linker by ambient `PATH`. |
| Ubuntu archive | `ubuntu/20260810T000000Z`, release `noble` | Future modern-boot CI must resolve packages from this immutable snapshot and must not run a distribution upgrade. |
| NASM | `2.16.01-1build1` | Install the exact `noble/universe` package when the modern-boot job also verifies the legacy image. |
| QEMU | `qemu-system-x86=1:8.2.2+ds-0ubuntu1.18` | Install the exact `noble-updates/main` package for the reference virtual platform. |
| OVMF | `ovmf=2024.02-2ubuntu0.9` | Install the exact `noble-updates/main` firmware package and use separate, disposable variable storage for each test. |

The Ubuntu snapshot is the reproducibility boundary for OS011, even though
newer upstream NASM, QEMU, and EDK II releases exist. Rust `1.97.1` is selected
over `1.97.0` because the patch release includes a compiler miscompilation fix.
The RustSec advisory database had no direct package entry for `uefi`,
`uefi-raw`, `bootloader`, or `bootloader_api` when reviewed on 2026-08-10. This
is not a transitive audit: OS011 must run the repository's dependency audit
against its committed lockfile before accepting the implementation.

### Entry state

The kernel entry uses the explicit Rust ABI
`extern "sysv64" fn(*const BootHandoffV1) -> !`. The loader guarantees:

- x86-64 long mode with paging enabled;
- the System V AMD64 calling convention, including its stack alignment rules;
- interrupts disabled and the direction flag clear;
- the handoff, normalized memory-region array, kernel image, and active stack
  are identity-mapped and readable at entry; and
- Boot Services have exited successfully before control reaches the kernel.

The kernel must not return. Runtime Services are not part of version 1.0 and no
runtime-service pointer is passed.

### Handoff version 1.0

All handoff records use `#[repr(C)]`, fixed-width unsigned integers, and the
field order below. They contain no Rust references, slices, `bool` values,
implicit-layout enums, function pointers, or firmware-owned pointers.

`BootHandoffHeaderV1` is 32 bytes:

| Field | Type | Meaning |
| --- | --- | --- |
| `magic` | `[u8; 8]` | Exact bytes `MAKOPA\0\0`. |
| `abi_major` | `u16` | `1`. |
| `abi_minor` | `u16` | `0`. |
| `header_size` | `u32` | `32`. |
| `handoff_size` | `u32` | `88`, the size in bytes of the complete top-level record. |
| `flags` | `u32` | Bit 0 means framebuffer metadata is present; all other bits are zero in version 1.0. |
| `reserved` | `u64` | Zero. |

`BootHandoffV1` contains the header followed, in order, by:

| Field | Type | Meaning |
| --- | --- | --- |
| `memory_regions_address` | `u64` | Identity-mapped physical address of the normalized region array. |
| `memory_region_count` | `u32` | Number of array entries. |
| `memory_region_entry_size` | `u32` | `24` for `MemoryRegionV1`. |
| `framebuffer` | `FramebufferV1` | Zero-filled when flag bit 0 is clear. |

`MemoryRegionV1` is 24 bytes and contains `physical_start: u64`,
`page_count: u64`, `kind: u32`, and `attributes: u32`. Region kind values are
`0` reserved, `1` usable, `2` loader-reclaimable, `3` ACPI reclaimable, `4`
ACPI NVS, and `5` MMIO. Unknown firmware types map to reserved. The loader must
emit non-empty, page-aligned, ascending, non-overlapping regions. Live loader,
handoff, region-array, kernel, page-table, and stack storage cannot be marked
usable. Version 1.0 defines no attribute bits, so `attributes` is zero.

`FramebufferV1` is 40 bytes and contains, in order,
`physical_start: u64`, `byte_length: u64`, `width: u32`, `height: u32`,
`stride_pixels: u32`, `pixel_format: u32`, and `reserved: u64`.
Pixel formats are `0` unavailable, `1` RGB, and `2` BGR. Bitmask and blit-only
firmware modes are reported as unavailable in version 1.0 rather than exposing
firmware-specific layouts.

The loader owns the handoff storage until entry. The kernel must validate and
copy the handoff and normalized regions before reclaiming any loader-owned
memory. Length multiplication, address addition, alignment, range overlap,
known flags, fixed reserved fields, and enum values are all checked before use.

### Compatibility

Magic or major-version mismatch fails closed. Version 1.0 initially accepts
only minor version `0`. A later minor version may only append fields, define
previously zero optional flags, or add enum values whose unknown form can be
treated as unavailable or reserved. Existing offsets and meanings cannot
change. Each kernel declares an explicit supported minor-version range and
uses the size fields to bound reads; a higher minor version is never accepted
implicitly. An incompatible layout or semantic change requires a new major
version and a replacement decision record.

Host-side layout tests in OS011 must assert every size and offset in this
record. OS012 must add malformed-version, size, flag, range, overlap, and
lifetime tests plus one successful QEMU handoff.

## Alternatives considered

### Use `rust-osdev/bootloader` 0.11.17

Not selected for the initial path. Its existing loader is useful, but nightly
Rust, `llvm-tools-preview`, experimental status, and direct `bootloader_api`
coupling add moving parts at the boundary MakopaOS is trying to define.

### Expose UEFI structures directly to the kernel

Rejected. It would extend firmware lifetimes into the kernel, weaken validation,
and make a future loader replacement an internal kernel migration.

## Consequences

- MakopaOS owns a small amount of firmware-facing code and must test its ELF,
  range, allocation, and map-key handling carefully.
- The kernel receives one stable, inspectable input independent of the loader
  implementation.
- The legacy BIOS diagnostic remains buildable and unchanged.
- OS011 can prove entry and record layout before OS012 expands behavioral
  handoff validation.
- Secure Boot, measured boot, hardware support, Runtime Services, and release
  provenance remain outside this decision.

## Rollback and reconsideration

If OS011 cannot reach a deterministic QEMU kernel entry while keeping the
loader narrow, stable-Rust-only, and auditable, a replacement ADR may select a
maintained loader. The replacement must translate that loader's API into the
MakopaOS handoff before kernel-core code runs. Kernel subsystems must not depend
directly on `bootloader_api` or raw UEFI types. Returning to the BIOS path is
not a modern-boot rollback; the BIOS sector remains only a diagnostic baseline.

Reconsider this decision if the selected Rust target or UEFI crate loses stable
support, a relevant unresolved security advisory appears, the pinned Ubuntu
snapshot becomes unavailable, or a maintained loader satisfies the same ABI
with materially less trusted code and no nightly-toolchain requirement.

## References

- [UEFI specification 2.11](https://uefi.org/specs/UEFI/2.11/)
- [Rust 1.97.1 release notes](https://doc.rust-lang.org/stable/releases.html#version-1971-2026-03-05)
- [Rust `x86_64-unknown-uefi` platform support](https://doc.rust-lang.org/rustc/platform-support/x86_64-unknown-uefi.html)
- [Rust `x86_64-unknown-none` platform support](https://doc.rust-lang.org/rustc/platform-support/x86_64-unknown-none.html)
- [`uefi` crate 0.39.0](https://docs.rs/crate/uefi/0.39.0)
- [`rust-osdev/bootloader` 0.11.17](https://github.com/rust-osdev/bootloader/releases/tag/v0.11.17)
- [Ubuntu snapshot service](https://snapshot.ubuntu.com/)
- [Ubuntu `noble/universe` snapshot index](https://snapshot.ubuntu.com/ubuntu/20260810T000000Z/dists/noble/universe/binary-amd64/Packages.xz)
- [Ubuntu `noble-updates/main` snapshot index](https://snapshot.ubuntu.com/ubuntu/20260810T000000Z/dists/noble-updates/main/binary-amd64/Packages.xz)
- [RustSec advisory database](https://github.com/RustSec/advisory-db)
