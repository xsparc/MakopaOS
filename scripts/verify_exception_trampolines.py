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
TASK_TRAMPOLINE = "makopa_task_trap_trampoline"
TASK_RESUME = "makopa_resume_task"
PROBES = ("makopa_sender_probe", "makopa_receiver_probe")
REQUIRED_SYMBOLS = TRAMPOLINES + (
    "makopa_exception_dispatch",
    "makopa_double_fault_dispatch",
    "makopa_recover_from_user_fault",
    "makopa_enter_user",
    "makopa_switch_to_recovery",
    TASK_TRAMPOLINE,
    "makopa_task_trap_dispatch",
    TASK_RESUME,
) + PROBES

SAVED_GPRS = (
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rbp",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
)
CAPTURE_ORDER = tuple(reversed(SAVED_GPRS))
RESTORE_OFFSETS = {
    "rax": 0x00,
    "rbx": 0x08,
    "rcx": 0x10,
    "rdx": 0x18,
    "rbp": 0x20,
    "rsi": 0x28,
    "rdi": 0x30,
    "r8": 0x38,
    "r9": 0x40,
    "r10": 0x48,
    "r11": 0x50,
    "r12": 0x58,
    "r13": 0x60,
    "r14": 0x68,
    "r15": 0x70,
}


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

    trap = bodies.get(TASK_TRAMPOLINE, "")
    trap_lines = [line for line in trap.splitlines() if "\t" in line]
    if not trap_lines or "cld" not in trap_lines[0]:
        errors.append("task trap does not begin with cld")
    captured = tuple(re.findall(r"\bpushq?\s+%(r(?:ax|bx|cx|dx|bp|si|di|8|9|10|11|12|13|14|15))\b", trap))
    if captured != CAPTURE_ORDER:
        errors.append(
            "task trap GPR capture order mismatch: "
            f"expected {CAPTURE_ORDER!r}, found {captured!r}"
        )
    cr3_position = trap.find("cr3")
    call_position = trap.find("call")
    stack_position = trap.find("%rsp", trap.find("cr3") + 1)
    if cr3_position < 0 or call_position < 0 or cr3_position > call_position:
        errors.append("task trap does not install recovery CR3 before Rust dispatch")
    if stack_position < 0 or stack_position > call_position:
        errors.append("task trap does not checkpoint the recovery stack before dispatch")
    if "ud2" not in trap or "iret" in trap or re.search(r"\bret[qwl]?\b", trap):
        errors.append("task trap is not a non-returning one-way entry")

    resume = bodies.get(TASK_RESUME, "")
    if "cr3" not in resume or "iretq" not in resume:
        errors.append("task resume lacks task CR3 installation or iretq")
    if "call" in resume or re.search(r"\bret[qwl]?\b", resume):
        errors.append("task resume unexpectedly uses a returning call frame")
    restored: dict[str, int] = {}
    for match in re.finditer(
        r"\bmovq\s+(?:(0x[0-9a-f]+))?\(%r11\),\s*%(r(?:ax|bx|cx|dx|bp|si|di|8|9|10|11|12|13|14|15))\b",
        resume,
    ):
        restored[match.group(2)] = int(match.group(1) or "0", 16)
    for register, expected_offset in RESTORE_OFFSETS.items():
        if restored.get(register) != expected_offset:
            errors.append(
                f"task resume restores {register} from {restored.get(register)!r}, "
                f"expected {expected_offset:#x}"
            )
    privilege_pushes = tuple(
        int(value, 16)
        for value in re.findall(r"\bpushq\s+(0x[0-9a-f]+)\(%r11\)", resume)
    )
    if privilege_pushes != (0x98, 0x80, 0x88, 0x90, 0x78):
        errors.append("task resume privilege-frame layout mismatch")

    for probe in PROBES:
        body = bodies.get(probe, "")
        if body.count("int\t$0x80") != 2:
            errors.append(f"{probe} does not contain exactly two vector 0x80 traps")
        if "4d414b4f5041" not in body:
            errors.append(f"{probe} lacks the fixed inline message evidence")
        if "hlt" not in body:
            errors.append(f"{probe} lacks deterministic failure transfer")
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
    print(
        "verify-exception-trampolines: stable exception, complete task-switch, "
        "and fixed-probe paths matched"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
