from __future__ import annotations

import unittest

from scripts.verify_uefi_boot import (
    EXPECTED_EXIT_CODE,
    EXPECTED_SERIAL,
    boot_violations,
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


if __name__ == "__main__":
    unittest.main()
