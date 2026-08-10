#!/usr/bin/env python3
"""Validate the structural contract of a MakopaOS BIOS boot sector."""

from __future__ import annotations

import argparse
from pathlib import Path


IMAGE_SIZE = 512
BOOT_SIGNATURE = b"\x55\xaa"
MESSAGE = b"MAKOPA\x00"


def verify(path: Path) -> list[str]:
    """Return contract violations for one boot-sector image."""
    try:
        image = path.read_bytes()
    except OSError as exc:
        return [f"cannot read {path}: {exc}"]

    errors: list[str] = []
    if len(image) != IMAGE_SIZE:
        errors.append(f"expected {IMAGE_SIZE} bytes, found {len(image)}")
    if len(image) < 2 or image[-2:] != BOOT_SIGNATURE:
        errors.append("missing boot signature 0x55AA at bytes 510-511")
    if MESSAGE not in image:
        errors.append("missing null-terminated MAKOPA payload")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="boot-sector image to verify")
    args = parser.parse_args()

    errors = verify(args.image)
    if errors:
        for error in errors:
            print(f"verify-boot: {error}")
        return 1

    print(
        f"verify-boot: {args.image} is {IMAGE_SIZE} bytes with "
        "the MAKOPA payload and 0x55AA signature"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
