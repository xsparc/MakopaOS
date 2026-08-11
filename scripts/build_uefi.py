#!/usr/bin/env python3
"""Build the pinned MakopaOS UEFI loader and kernel ESP directory."""

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KERNEL_TARGET = "x86_64-unknown-none"
LOADER_TARGET = "x86_64-unknown-uefi"


def build(cargo: str = "cargo") -> tuple[Path, Path]:
    """Build locked release artifacts and return kernel and loader paths."""
    commands = (
        [
            cargo,
            "+1.97.1",
            "build",
            "--locked",
            "--release",
            "-p",
            "makopa-kernel",
            "--target",
            KERNEL_TARGET,
        ],
        [
            cargo,
            "+1.97.1",
            "build",
            "--locked",
            "--release",
            "-p",
            "makopa-loader",
            "--target",
            LOADER_TARGET,
        ],
    )
    for command in commands:
        subprocess.run(command, cwd=ROOT, check=True)

    kernel = ROOT / "target" / KERNEL_TARGET / "release" / "makopa-kernel"
    loader = ROOT / "target" / LOADER_TARGET / "release" / "makopa-loader.efi"
    return kernel, loader


def prepare_esp(kernel: Path, loader: Path, output: Path) -> tuple[Path, Path]:
    """Copy validated artifact kinds into the UEFI fallback boot layout."""
    kernel_bytes = kernel.read_bytes()
    loader_bytes = loader.read_bytes()
    if not kernel_bytes.startswith(b"\x7fELF"):
        raise ValueError(f"kernel artifact is not ELF: {kernel}")
    if not loader_bytes.startswith(b"MZ"):
        raise ValueError(f"loader artifact is not PE/COFF: {loader}")

    boot_destination = output / "EFI" / "BOOT" / "BOOTX64.EFI"
    kernel_destination = output / "MAKOPA" / "KERNEL.ELF"
    boot_destination.parent.mkdir(parents=True, exist_ok=True)
    kernel_destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(loader, boot_destination)
    shutil.copyfile(kernel, kernel_destination)
    return boot_destination, kernel_destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "build" / "esp",
        help="ESP directory to populate",
    )
    parser.add_argument("--cargo", default="cargo", help="Cargo executable")
    args = parser.parse_args()

    kernel, loader = build(args.cargo)
    boot_destination, kernel_destination = prepare_esp(kernel, loader, args.output)
    print(f"build-uefi: loader={boot_destination}")
    print(f"build-uefi: kernel={kernel_destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
