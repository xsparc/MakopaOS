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
0000000000100200 <makopa_task_trap_trampoline>:
  100200:\tcld
  100201:\tpushq %r15
  100202:\tpushq %r14
  100203:\tpushq %r13
  100204:\tpushq %r12
  100205:\tpushq %r11
  100206:\tpushq %r10
  100207:\tpushq %r9
  100208:\tpushq %r8
  100209:\tpushq %rdi
  10020a:\tpushq %rsi
  10020b:\tpushq %rbp
  10020c:\tpushq %rdx
  10020d:\tpushq %rcx
  10020e:\tpushq %rbx
  10020f:\tpushq %rax
  100210:\tmovq %rsp, %rdi
  100213:\tmovq 0x20(%rip), %rax
  100218:\tmovq %rax, %cr3
  10021b:\tandq $-0x10, %rsp
  10021f:\tcallq 0x100280 <makopa_task_trap_dispatch>
  100224:\tud2
0000000000100280 <makopa_task_trap_dispatch>:
  100280:\tud2
0000000000100300 <makopa_resume_task>:
  100300:\tmovq %rdi, %r11
  100303:\tmovq $0x2000, %rsp
  100308:\tpushq 0x98(%r11)
  10030c:\tpushq 0x80(%r11)
  100310:\tpushq 0x88(%r11)
  100314:\tpushq 0x90(%r11)
  100318:\tpushq 0x78(%r11)
  10031c:\tmovq 0xa0(%r11), %rax
  100323:\tmovq %rax, %cr3
  100326:\tmovq 0x0(%r11), %rax
  10032a:\tmovq 0x8(%r11), %rbx
  10032e:\tmovq 0x10(%r11), %rcx
  100332:\tmovq 0x18(%r11), %rdx
  100336:\tmovq 0x20(%r11), %rbp
  10033a:\tmovq 0x28(%r11), %rsi
  10033e:\tmovq 0x30(%r11), %rdi
  100342:\tmovq 0x38(%r11), %r8
  100346:\tmovq 0x40(%r11), %r9
  10034a:\tmovq 0x48(%r11), %r10
  10034e:\tmovq 0x58(%r11), %r12
  100352:\tmovq 0x60(%r11), %r13
  100356:\tmovq 0x68(%r11), %r14
  10035a:\tmovq 0x70(%r11), %r15
  10035e:\tmovq 0x50(%r11), %r11
  100362:\tiretq
0000000000100400 <makopa_sender_probe>:
  100400:\tmovabsq $0x4d414b4f5041, %rsi
  10040a:\tint\t$0x80
  10040c:\tint\t$0x80
  10040e:\thlt
0000000000100500 <makopa_receiver_probe>:
  100500:\tmovabsq $0x4d414b4f5041, %rax
  10050a:\tint\t$0x80
  10050c:\tint\t$0x80
  10050e:\thlt
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

    def test_rejects_incomplete_task_capture_and_restore(self) -> None:
        disassembly = valid_disassembly().replace("  10020f:\tpushq %rax\n", "")
        disassembly = disassembly.replace("  10035e:\tmovq 0x50(%r11), %r11\n", "")
        errors = disassembly_violations(disassembly)
        self.assertTrue(any("capture order mismatch" in error for error in errors))
        self.assertTrue(any("restores r11" in error for error in errors))

    def test_rejects_wrong_context_offset_or_privilege_frame_order(self) -> None:
        disassembly = valid_disassembly().replace(
            "  10032a:\tmovq 0x8(%r11), %rbx\n",
            "  10032a:\tmovq 0x10(%r11), %rbx\n",
        )
        disassembly = disassembly.replace(
            "  100308:\tpushq 0x98(%r11)\n  10030c:\tpushq 0x80(%r11)\n",
            "  100308:\tpushq 0x80(%r11)\n  10030c:\tpushq 0x98(%r11)\n",
        )
        errors = disassembly_violations(disassembly)
        self.assertTrue(any("restores rbx" in error for error in errors))
        self.assertIn("task resume privilege-frame layout mismatch", errors)

    def test_rejects_rust_dispatch_before_recovery_root(self) -> None:
        disassembly = valid_disassembly().replace(
            "  100218:\tmovq %rax, %cr3\n  10021b:\tandq $-0x10, %rsp\n"
            "  10021f:\tcallq 0x100280 <makopa_task_trap_dispatch>\n",
            "  100218:\tcallq 0x100280 <makopa_task_trap_dispatch>\n"
            "  10021d:\tmovq %rax, %cr3\n  100220:\tandq $-0x10, %rsp\n",
        )
        errors = disassembly_violations(disassembly)
        self.assertTrue(any("recovery CR3" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
