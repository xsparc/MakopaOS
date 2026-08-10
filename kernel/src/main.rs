#![no_main]
#![no_std]

use core::arch::asm;
use core::fmt::{self, Write};
use core::panic::PanicInfo;

use makopa_boot_contract::BootHandoffV1;

const KERNEL_SERIAL: u16 = 0x2f8;
const QEMU_EXIT_PORT: u16 = 0xf4;
const QEMU_SUCCESS: u32 = 0x10;
const QEMU_FAILURE: u32 = 0x11;

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.kernel_entry")]
/// Enter the kernel from a loader that satisfies ADR-0001.
///
/// # Safety
///
/// `handoff` must be null or point to a readable, identity-mapped
/// `BootHandoffV1` that remains live for the duration of this entry probe. The
/// machine state and stack must satisfy the ADR-0001 System V entry contract.
pub unsafe extern "sysv64" fn kernel_entry(handoff: *const BootHandoffV1) -> ! {
    // SAFETY: The loader enters with interrupts disabled; repeating these
    // architectural state operations is harmless and establishes the contract.
    unsafe {
        asm!("cli", "cld", options(nomem, nostack));
    }

    let mut serial = SerialPort::new(KERNEL_SERIAL);
    serial.initialize();

    if handoff.is_null() {
        let _ = serial.write_str("MakopaOS boot error: null handoff\r\n");
        exit_qemu(QEMU_FAILURE);
    }

    // SAFETY: ADR-0001 requires the loader to pass an identity-mapped, readable
    // pointer whose storage remains live until the kernel copies the handoff.
    let handoff = unsafe { &*handoff };
    if !handoff.is_empty_v1() {
        let _ = serial.write_str("MakopaOS boot error: invalid handoff\r\n");
        exit_qemu(QEMU_FAILURE);
    }

    let _ = serial.write_str("MakopaOS 0.1.0\r\n");
    exit_qemu(QEMU_SUCCESS)
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    let mut serial = SerialPort::new(KERNEL_SERIAL);
    serial.initialize();
    let _ = serial.write_str("MakopaOS kernel panic\r\n");
    exit_qemu(QEMU_FAILURE)
}

fn exit_qemu(code: u32) -> ! {
    // SAFETY: OS011 runs only on the declared QEMU reference machine where
    // isa-debug-exit owns this I/O port. The instruction has no memory effect.
    unsafe {
        asm!("out dx, eax", in("dx") QEMU_EXIT_PORT, in("eax") code, options(nomem, nostack));
    }
    halt_forever()
}

fn halt_forever() -> ! {
    loop {
        // SAFETY: Interrupts are disabled, and halting is the terminal fallback
        // if the QEMU test device did not terminate the virtual machine.
        unsafe {
            asm!("hlt", options(nomem, nostack));
        }
    }
}

struct SerialPort {
    base: u16,
}

impl SerialPort {
    const fn new(base: u16) -> Self {
        Self { base }
    }

    fn initialize(&mut self) {
        self.write_register(1, 0x00);
        self.write_register(3, 0x80);
        self.write_register(0, 0x03);
        self.write_register(1, 0x00);
        self.write_register(3, 0x03);
        self.write_register(2, 0xc7);
        self.write_register(4, 0x0b);
    }

    fn write_byte(&mut self, byte: u8) {
        while self.read_register(5) & 0x20 == 0 {
            core::hint::spin_loop();
        }
        self.write_register(0, byte);
    }

    fn read_register(&self, offset: u16) -> u8 {
        let value: u8;
        // SAFETY: The kernel UART owns the declared I/O range on the reference
        // machine. The instruction reads only the requested device register.
        unsafe {
            asm!("in al, dx", in("dx") self.base + offset, out("al") value, options(nomem, nostack));
        }
        value
    }

    fn write_register(&self, offset: u16, value: u8) {
        // SAFETY: The kernel UART owns the declared I/O range on the reference
        // machine. The instruction writes only the requested device register.
        unsafe {
            asm!("out dx, al", in("dx") self.base + offset, in("al") value, options(nomem, nostack));
        }
    }
}

impl Write for SerialPort {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        for byte in value.bytes() {
            self.write_byte(byte);
        }
        Ok(())
    }
}
