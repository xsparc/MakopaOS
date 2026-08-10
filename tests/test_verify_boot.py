from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.verify_boot import BOOT_SIGNATURE, IMAGE_SIZE, MESSAGE, verify


class VerifyBootTests(unittest.TestCase):
    def verify_bytes(self, image: bytes) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "boot.bin"
            path.write_bytes(image)
            return verify(path)

    @staticmethod
    def valid_image() -> bytes:
        image = bytearray(IMAGE_SIZE)
        image[16 : 16 + len(MESSAGE)] = MESSAGE
        image[-2:] = BOOT_SIGNATURE
        return bytes(image)

    def test_accepts_valid_image(self) -> None:
        self.assertEqual([], self.verify_bytes(self.valid_image()))

    def test_rejects_wrong_size(self) -> None:
        errors = self.verify_bytes(self.valid_image()[:-1])
        self.assertTrue(any("expected 512 bytes" in error for error in errors))

    def test_rejects_missing_signature(self) -> None:
        image = bytearray(self.valid_image())
        image[-2:] = b"\x00\x00"
        errors = self.verify_bytes(bytes(image))
        self.assertTrue(any("missing boot signature" in error for error in errors))

    def test_rejects_missing_message(self) -> None:
        image = bytearray(self.valid_image())
        image[16 : 16 + len(MESSAGE)] = b"\x00" * len(MESSAGE)
        errors = self.verify_bytes(bytes(image))
        self.assertTrue(any("missing null-terminated MAKOPA" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
