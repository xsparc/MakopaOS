from __future__ import annotations

import unittest
from pathlib import Path

from scripts.verify_uefi_boot import (
    EXPECTED_EXIT_CODE,
    EXPECTED_SERIAL,
    boot_violations,
    qemu_command,
)


class VerifyUefiBootTests(unittest.TestCase):
    def test_accepts_exact_transcript_and_exit(self) -> None:
        self.assertEqual(
            [], boot_violations(EXPECTED_EXIT_CODE, EXPECTED_SERIAL)
        )

    def test_rejects_changed_transcript(self) -> None:
        errors = boot_violations(EXPECTED_EXIT_CODE, b"MakopaOS dev\r\n")
        self.assertTrue(any("transcript mismatch" in error for error in errors))

    def test_rejects_duplicate_transcript(self) -> None:
        errors = boot_violations(EXPECTED_EXIT_CODE, EXPECTED_SERIAL * 2)
        self.assertTrue(any("transcript mismatch" in error for error in errors))

    def test_rejects_changed_exit_status(self) -> None:
        errors = boot_violations(0, EXPECTED_SERIAL)
        self.assertTrue(any("exit code" in error for error in errors))

    def test_attaches_read_only_vvfat_to_virtio(self) -> None:
        command = qemu_command(
            "qemu-system-x86_64",
            Path("OVMF_CODE.fd"),
            Path("OVMF_VARS.fd"),
            Path("esp"),
        )
        blockdev = command[command.index("-blockdev") + 1]
        devices = [
            command[index + 1]
            for index, argument in enumerate(command)
            if argument == "-device"
        ]

        self.assertIn("driver=vvfat", blockdev)
        self.assertIn("read-only=on", blockdev)
        self.assertIn("virtio-blk-pci,drive=makopa-esp", devices)

        serial_channels = [
            command[index + 1]
            for index, argument in enumerate(command)
            if argument == "-serial"
        ]
        self.assertEqual(["null", "stdio"], serial_channels)


if __name__ == "__main__":
    unittest.main()
