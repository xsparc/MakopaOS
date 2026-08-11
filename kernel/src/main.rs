#![no_main]
#![no_std]

use core::arch::asm;
use core::cell::UnsafeCell;
use core::fmt::{self, Write};
use core::mem::align_of;
use core::panic::PanicInfo;
use core::slice;

use makopa_boot_contract::{
    BootHandoffV1, FRAMEBUFFER_PRESENT, MemoryRegionV1, validate_handoff, validate_handoff_header,
};
use makopa_frame_allocator::FrameAllocator;

const KERNEL_SERIAL: u16 = 0x3f8;
const QEMU_EXIT_PORT: u16 = 0xf4;
const QEMU_SUCCESS: u32 = 0x10;
const QEMU_FAILURE: u32 = 0x11;

struct KernelFrameAllocator(UnsafeCell<FrameAllocator>);

impl KernelFrameAllocator {
    const fn new() -> Self {
        Self(UnsafeCell::new(FrameAllocator::new()))
    }
}

// SAFETY: OS020 has one kernel entry path, keeps interrupts disabled, and has
// no scheduler or reentrant allocator caller. Later concurrency must replace
// this single-owner boundary with explicit synchronization.
unsafe impl Sync for KernelFrameAllocator {}

#[unsafe(link_section = ".bss.frame_allocator")]
static FRAME_ALLOCATOR: KernelFrameAllocator = KernelFrameAllocator::new();

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

    if handoff.is_null() || !(handoff as usize).is_multiple_of(align_of::<BootHandoffV1>()) {
        let _ = serial.write_str("MakopaOS boot error: null handoff\r\n");
        exit_qemu(QEMU_FAILURE);
    }

    // SAFETY: ADR-0001 requires the loader to pass an identity-mapped, readable
    // pointer whose storage remains live until the kernel copies the handoff.
    let handoff_address = handoff as usize as u64;
    let handoff = unsafe { handoff.read() };
    let Ok(region_count) = validate_handoff_header(&handoff) else {
        let _ = serial.write_str("MakopaOS boot error: invalid handoff\r\n");
        exit_qemu(QEMU_FAILURE);
    };
    let Ok(region_address) = usize::try_from(handoff.memory_regions_address) else {
        let _ = serial.write_str("MakopaOS boot error: invalid handoff\r\n");
        exit_qemu(QEMU_FAILURE);
    };
    // SAFETY: validate_handoff_header bounded the non-null, aligned address and
    // count. ADR-0001 makes the loader responsible for mapping this readable
    // storage; validate_handoff checks every record before the kernel uses it.
    let regions =
        unsafe { slice::from_raw_parts(region_address as *const MemoryRegionV1, region_count) };
    if validate_handoff(&handoff, handoff_address, regions).is_err() {
        let _ = serial.write_str("MakopaOS boot error: invalid handoff\r\n");
        exit_qemu(QEMU_FAILURE);
    }

    // SAFETY: kernel_entry is the only execution path, interrupts remain
    // disabled, and no reference to this singleton exists elsewhere. The
    // allocator copies usable extents and retains no reference to `regions`.
    let frame_allocator = unsafe { &mut *FRAME_ALLOCATOR.0.get() };
    if frame_allocator.initialize(regions).is_err() {
        let _ = serial.write_str("MakopaOS boot error: frame allocator init\r\n");
        exit_qemu(QEMU_FAILURE);
    }
    let Ok(frame_a) = frame_allocator.allocate_frame() else {
        let _ = serial.write_str("MakopaOS boot error: frame allocation\r\n");
        exit_qemu(QEMU_FAILURE);
    };
    let Ok(frame_b) = frame_allocator.allocate_frame() else {
        let _ = serial.write_str("MakopaOS boot error: frame allocation\r\n");
        exit_qemu(QEMU_FAILURE);
    };
    if frame_b == frame_a || frame_allocator.free_frame(frame_a).is_err() {
        let _ = serial.write_str("MakopaOS boot error: frame recycle\r\n");
        exit_qemu(QEMU_FAILURE);
    }
    let Ok(reused) = frame_allocator.allocate_frame() else {
        let _ = serial.write_str("MakopaOS boot error: frame recycle\r\n");
        exit_qemu(QEMU_FAILURE);
    };
    if reused != frame_a {
        let _ = serial.write_str("MakopaOS boot error: frame reuse mismatch\r\n");
        exit_qemu(QEMU_FAILURE);
    }

    let _ = serial.write_str("MakopaOS 0.1.0\r\n");
    if handoff.header.flags & FRAMEBUFFER_PRESENT != 0 {
        let _ = serial.write_str("MakopaOS handoff v1 ok framebuffer\r\n");
    } else {
        let _ = serial.write_str("MakopaOS handoff v1 ok no-framebuffer\r\n");
    }
    let _ = serial.write_str("MakopaOS frames v1 ok reuse\r\n");
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
