from __future__ import annotations

import unittest

from scripts.verify_exception_trampolines import disassembly_violations


def valid_disassembly() -> str:
    return '''0000000000100000 <makopa_page_fault_trampoline>:
  100000:\tcld
  100001:\tmovq %cr2, %rdx
  100004:\tcallq 0x100100 <makopa_exception_dispatch>
  100009:\tud2
0000000000100010 <makopa_general_protection_trampoline>:
  100010:\tcld
  100011:\tcallq 0x100100 <makopa_exception_dispatch>
  100016:\tud2
0000000000100020 <makopa_double_fault_trampoline>:
  100020:\tcld
  100021:\tcallq 0x100120 <makopa_double_fault_dispatch>
  100026:\tud2
0000000000100100 <makopa_exception_dispatch>:
  100100:\tud2
0000000000100120 <makopa_double_fault_dispatch>:
  100120:\tud2
0000000000100140 <makopa_recover_from_user_fault>:
  100140:\tmovq %rdi, %cr3
  100143:\tmovq %rsi, %rsp
  100146:\tjmpq *%rdx
0000000000100160 <makopa_enter_user>:
  100160:\tmovq %rdi, %cr3
  100163:\tiretq
0000000000100180 <makopa_switch_to_recovery>:
  100180:\tmovq %rcx, %rsp
  100183:\tmovq %rdi, %cr3
  100186:\tjmpq *%rdx
'''


class VerifyExceptionTrampolinesTests(unittest.TestCase):
    def test_accepts_stable_naked_machine_code_contract(self) -> None:
        self.assertEqual([], disassembly_violations(valid_disassembly()))

    def test_rejects_returning_or_missing_cr2_path(self) -> None:
        disassembly = valid_disassembly().replace("movq %cr2, %rdx\n", "")
        disassembly = disassembly.replace("  100009:\tud2", "  100009:\tretq")
        errors = disassembly_violations(disassembly)
        self.assertTrue(any("CR2" in error for error in errors))
        self.assertTrue(any("unexpectedly returns" in error for error in errors))

    def test_rejects_missing_dedicated_double_fault_symbol(self) -> None:
        disassembly = valid_disassembly().replace(
            "<makopa_double_fault_trampoline>", "<renamed_double_fault>"
        )
        errors = disassembly_violations(disassembly)
        self.assertIn("missing symbol makopa_double_fault_trampoline", errors)


if __name__ == "__main__":
    unittest.main()
