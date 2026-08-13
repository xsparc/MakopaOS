from __future__ import annotations

import unittest
from pathlib import Path

from scripts.verify_uefi_boot import (
    CAPABILITY_SERIAL,
    EXPECTED_EXIT_CODE,
    EXPECTED_SERIAL,
    FRAME_SERIAL,
    HANDOFF_SERIAL,
    IPC_SERIAL,
    ISOLATION_SERIAL,
    VERSION_SERIAL,
    boot_violations,
    qemu_command,
)


class VerifyUefiBootTests(unittest.TestCase):
    def test_accepts_exact_transcript_and_exit(self) -> None:
        self.assertEqual(
            [], boot_violations(EXPECTED_EXIT_CODE, EXPECTED_SERIAL)
        )

    def test_accepts_firmware_prefix_before_kernel_transcript(self) -> None:
        stdout = b"OVMF console record\r\n" + EXPECTED_SERIAL
        self.assertEqual([], boot_violations(EXPECTED_EXIT_CODE, stdout))

    def test_rejects_changed_transcript(self) -> None:
        errors = boot_violations(EXPECTED_EXIT_CODE, b"MakopaOS dev\r\n")
        self.assertTrue(any("transcript mismatch" in error for error in errors))

    def test_rejects_version_record_without_validated_handoff(self) -> None:
        errors = boot_violations(EXPECTED_EXIT_CODE, VERSION_SERIAL)
        self.assertTrue(any("transcript mismatch" in error for error in errors))

    def test_rejects_handoff_without_framebuffer_evidence(self) -> None:
        transcript = (
            VERSION_SERIAL
            + b"MakopaOS handoff v1 ok no-framebuffer\r\n"
            + FRAME_SERIAL
        )
        errors = boot_violations(EXPECTED_EXIT_CODE, transcript)
        self.assertTrue(any("transcript mismatch" in error for error in errors))

    def test_expected_transcript_preserves_ipc_before_terminal_capabilities(self) -> None:
        self.assertTrue(EXPECTED_SERIAL.endswith(CAPABILITY_SERIAL))
        self.assertIn(HANDOFF_SERIAL, EXPECTED_SERIAL)
        self.assertIn(FRAME_SERIAL, EXPECTED_SERIAL)
        self.assertEqual(
            FRAME_SERIAL + ISOLATION_SERIAL + IPC_SERIAL + CAPABILITY_SERIAL,
            EXPECTED_SERIAL[
                -len(
                    FRAME_SERIAL
                    + ISOLATION_SERIAL
                    + IPC_SERIAL
                    + CAPABILITY_SERIAL
                ) :
            ],
        )

    def test_rejects_ipc_without_capability_evidence(self) -> None:
        errors = boot_violations(
            EXPECTED_EXIT_CODE,
            VERSION_SERIAL
            + HANDOFF_SERIAL
            + FRAME_SERIAL
            + ISOLATION_SERIAL
            + IPC_SERIAL,
        )
        self.assertTrue(any("transcript mismatch" in error for error in errors))

    def test_rejects_validated_handoff_without_frame_reuse_evidence(self) -> None:
        errors = boot_violations(
            EXPECTED_EXIT_CODE, VERSION_SERIAL + HANDOFF_SERIAL
        )
        self.assertTrue(any("transcript mismatch" in error for error in errors))

    def test_rejects_duplicate_transcript(self) -> None:
        errors = boot_violations(EXPECTED_EXIT_CODE, EXPECTED_SERIAL * 2)
        self.assertTrue(any("transcript mismatch" in error for error in errors))

    def test_rejects_bytes_after_kernel_transcript(self) -> None:
        errors = boot_violations(EXPECTED_EXIT_CODE, EXPECTED_SERIAL + b"trailing")
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
        self.assertEqual(["stdio"], serial_channels)

        self.assertEqual("qemu64", command[command.index("-cpu") + 1])
        self.assertEqual("1", command[command.index("-smp") + 1])


if __name__ == "__main__":
    unittest.main()
