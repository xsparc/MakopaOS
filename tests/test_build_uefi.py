from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.build_uefi import prepare_esp


class BuildUefiTests(unittest.TestCase):
    def test_populates_fallback_boot_layout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            kernel = root / "kernel"
            loader = root / "loader.efi"
            output = root / "esp"
            kernel.write_bytes(b"\x7fELFkernel")
            loader.write_bytes(b"MZloader")

            boot_destination, kernel_destination = prepare_esp(
                kernel, loader, output
            )

            self.assertEqual(b"MZloader", boot_destination.read_bytes())
            self.assertEqual(b"\x7fELFkernel", kernel_destination.read_bytes())
            self.assertEqual(output / "EFI" / "BOOT" / "BOOTX64.EFI", boot_destination)
            self.assertEqual(output / "MAKOPA" / "KERNEL.ELF", kernel_destination)

    def test_rejects_wrong_artifact_kinds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            kernel = root / "kernel"
            loader = root / "loader.efi"
            kernel.write_bytes(b"not-elf")
            loader.write_bytes(b"MZloader")

            with self.assertRaisesRegex(ValueError, "not ELF"):
                prepare_esp(kernel, loader, root / "esp")


if __name__ == "__main__":
    unittest.main()
