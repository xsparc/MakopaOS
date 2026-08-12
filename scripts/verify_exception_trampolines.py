#!/usr/bin/env python3
"""Disassemble and verify the stable x86-64 exception-entry boundary."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path


TRAMPOLINES = (
    "makopa_page_fault_trampoline",
    "makopa_general_protection_trampoline",
    "makopa_double_fault_trampoline",
)
REQUIRED_SYMBOLS = TRAMPOLINES + (
    "makopa_exception_dispatch",
    "makopa_double_fault_dispatch",
    "makopa_recover_from_user_fault",
    "makopa_enter_user",
    "makopa_switch_to_recovery",
)


def symbol_body(disassembly: str, symbol: str) -> str | None:
    """Extract one symbol body from GNU- or LLVM-style objdump text."""
    pattern = re.compile(
        rf"(?ms)^[0-9a-fA-F]+\s+<{re.escape(symbol)}>:\s*\n"
        rf"(.*?)(?=^[0-9a-fA-F]+\s+<[^>]+>:\s*$|\Z)"
    )
    match = pattern.search(disassembly)
    return match.group(1) if match else None


def disassembly_violations(disassembly: str) -> list[str]:
    """Return machine-code contract violations."""
    errors: list[str] = []
    bodies: dict[str, str] = {}
    for symbol in REQUIRED_SYMBOLS:
        body = symbol_body(disassembly, symbol)
        if body is None:
            errors.append(f"missing symbol {symbol}")
        else:
            bodies[symbol] = body.lower()

    for symbol in TRAMPOLINES:
        body = bodies.get(symbol, "")
        instruction_lines = [line for line in body.splitlines() if "\t" in line]
        if not instruction_lines or "cld" not in instruction_lines[0]:
            errors.append(f"{symbol} does not begin with cld")
        for mnemonic in ("cld", "call", "ud2"):
            if mnemonic not in body:
                errors.append(f"{symbol} lacks {mnemonic}")
        if "iret" in body or re.search(r"\bret[qwl]?\b", body):
            errors.append(f"{symbol} unexpectedly returns")

    page_fault = bodies.get("makopa_page_fault_trampoline", "")
    if "cr2" not in page_fault:
        errors.append("page-fault trampoline does not capture CR2")
    for symbol in (
        "makopa_general_protection_trampoline",
        "makopa_double_fault_trampoline",
    ):
        if "cr2" in bodies.get(symbol, ""):
            errors.append(f"{symbol} unexpectedly reads CR2")

    recovery = bodies.get("makopa_recover_from_user_fault", "")
    for item in ("cr3", "rsp", "jmp"):
        if item not in recovery:
            errors.append(f"recovery transfer lacks {item}")
    if "ret" in recovery or "iret" in recovery:
        errors.append("recovery transfer unexpectedly returns")

    entry = bodies.get("makopa_enter_user", "")
    if "cr3" not in entry or "iretq" not in entry:
        errors.append("user entry lacks CR3 switch or iretq")

    switch = bodies.get("makopa_switch_to_recovery", "")
    for item in ("cr3", "rsp", "jmp"):
        if item not in switch:
            errors.append(f"recovery-root switch lacks {item}")
    return errors


def disassemble(objdump: Path, kernel: Path) -> str:
    result = subprocess.run(
        [str(objdump), "--disassemble", "--no-show-raw-insn", str(kernel)],
        capture_output=True,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "objdump failed")
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--objdump", required=True, type=Path)
    parser.add_argument("--kernel", required=True, type=Path)
    args = parser.parse_args()
    try:
        output = disassemble(args.objdump, args.kernel)
    except (OSError, RuntimeError) as error:
        print(f"verify-exception-trampolines: {error}")
        return 1
    errors = disassembly_violations(output)
    if errors:
        for error in errors:
            print(f"verify-exception-trampolines: {error}")
        return 1
    print("verify-exception-trampolines: stable naked entry and recovery paths matched")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
