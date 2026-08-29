#!/usr/bin/env python3
"""Run the deterministic MakopaOS UEFI serial boot gate in QEMU."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import tempfile
from pathlib import Path


VERSION_SERIAL = b"MakopaOS 0.1.0\r\n"
HANDOFF_SERIAL = b"MakopaOS handoff v1 ok framebuffer\r\n"
FRAME_SERIAL = b"MakopaOS frames v1 ok reuse\r\n"
ISOLATION_SERIAL = b"MakopaOS isolation v1 ok user-fault-contained\r\n"
IPC_SERIAL = b"MakopaOS ipc v1 ok cooperative-two-task\r\n"
CAPABILITY_SERIAL = b"MakopaOS capabilities v1 ok task-local-attenuation\r\n"
APPROVAL_SERIAL = b"MakopaOS approval v1 ok staged-single-use\r\n"
EFFECT_SERIAL = b"MakopaOS effects v1 ok ordered-redacted\r\n"
EXPECTED_SERIAL = (
    VERSION_SERIAL
    + HANDOFF_SERIAL
    + FRAME_SERIAL
    + ISOLATION_SERIAL
    + IPC_SERIAL
    + CAPABILITY_SERIAL
    + APPROVAL_SERIAL
    + EFFECT_SERIAL
)
EXPECTED_EXIT_CODE = 33


def boot_violations(returncode: int, stdout: bytes) -> list[str]:
    """Return violations of the deterministic serial and exit contract."""
    errors: list[str] = []
    if stdout.count(EXPECTED_SERIAL) != 1 or not stdout.endswith(EXPECTED_SERIAL):
        errors.append(
            "kernel transcript mismatch: expected one terminal "
            f"{EXPECTED_SERIAL!r}, found {stdout!r}"
        )
    if returncode != EXPECTED_EXIT_CODE:
        errors.append(
            f"expected QEMU exit code {EXPECTED_EXIT_CODE}, found {returncode}"
        )
    return errors


def verify_exit_device(qemu: str) -> list[str]:
    """Verify the selected QEMU binary exposes the required test device."""
    result = subprocess.run(
        [qemu, "-device", "isa-debug-exit,help"],
        capture_output=True,
        check=False,
    )
    output = result.stdout + result.stderr
    if result.returncode != 0:
        return ["QEMU does not accept the isa-debug-exit device"]
    if b"iobase" not in output or b"iosize" not in output:
        return ["QEMU did not report the isa-debug-exit port properties"]
    return []


def run_qemu(
    qemu: str,
    ovmf_code: Path,
    ovmf_vars: Path,
    esp: Path,
    timeout: int,
) -> tuple[int, bytes, bytes]:
    """Boot one read-only VVFAT ESP with a disposable variable store."""
    with tempfile.TemporaryDirectory(prefix="makopa-qemu-") as directory:
        variables = Path(directory) / "OVMF_VARS.fd"
        shutil.copyfile(ovmf_vars, variables)
        command = qemu_command(qemu, ovmf_code, variables, esp)
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                check=False,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as error:
            return 124, error.stdout or b"", error.stderr or b""
        return result.returncode, result.stdout, result.stderr


def qemu_command(
    qemu: str,
    ovmf_code: Path,
    ovmf_vars: Path,
    esp: Path,
) -> list[str]:
    """Construct the reference command with an explicitly read-only ESP."""
    esp_backend = (
        "driver=vvfat,node-name=makopa-esp,read-only=on,dir="
        f"{esp.resolve()}"
    )
    return [
        qemu,
        "-machine",
        "q35",
        "-cpu",
        "qemu64",
        "-smp",
        "1",
        "-m",
        "128M",
        "-display",
        "none",
        "-monitor",
        "none",
        "-serial",
        "stdio",
        "-no-reboot",
        "-net",
        "none",
        "-drive",
        f"if=pflash,format=raw,unit=0,readonly=on,file={ovmf_code.resolve()}",
        "-drive",
        f"if=pflash,format=raw,unit=1,file={ovmf_vars.resolve()}",
        "-blockdev",
        esp_backend,
        "-device",
        "virtio-blk-pci,drive=makopa-esp",
        "-device",
        "isa-debug-exit,iobase=0xf4,iosize=0x04",
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", default="qemu-system-x86_64")
    parser.add_argument("--ovmf-code", required=True, type=Path)
    parser.add_argument("--ovmf-vars", required=True, type=Path)
    parser.add_argument("--esp", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()

    device_errors = verify_exit_device(args.qemu)
    if device_errors:
        for error in device_errors:
            print(f"verify-uefi-boot: {error}")
        return 1

    returncode, stdout, stderr = run_qemu(
        args.qemu,
        args.ovmf_code,
        args.ovmf_vars,
        args.esp,
        args.timeout,
    )
    errors = boot_violations(returncode, stdout)
    if errors:
        for error in errors:
            print(f"verify-uefi-boot: {error}")
        if stderr:
            print(f"verify-uefi-boot: QEMU diagnostics: {stderr.decode(errors='replace')}")
        return 1

    print("verify-uefi-boot: matched serial transcript and deterministic exit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
