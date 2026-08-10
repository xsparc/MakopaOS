#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::arch::asm;
use core::mem;
use core::panic::PanicInfo;
use core::ptr;

use makopa_boot_contract::{BootHandoffV1, MemoryRegionV1};
use makopa_kernel_image::ValidatedImage;
use uefi::boot::{self, AllocateType, MemoryType};
use uefi::fs::FileSystem;
use uefi::prelude::*;
use uefi::{Status, cstr16};

const PAGE_SIZE: usize = 4096;
const MAX_KERNEL_IMAGE_SIZE: u64 = 16 * 1024 * 1024;
const KERNEL_PATH: &uefi::CStr16 = cstr16!(r"\MAKOPA\KERNEL.ELF");

static HANDOFF: BootHandoffV1 = BootHandoffV1::empty();

#[entry]
fn main() -> Status {
    if uefi::helpers::init().is_err() {
        return Status::LOAD_ERROR;
    }

    match load_and_enter_kernel() {
        Ok(()) => Status::SUCCESS,
        Err(status) => status,
    }
}

fn load_and_enter_kernel() -> Result<(), Status> {
    let kernel_bytes = read_kernel()?;
    let image = ValidatedImage::parse(&kernel_bytes).map_err(|_| Status::LOAD_ERROR)?;
    load_segments(image)?;
    let entry_address = image.entry();
    drop(kernel_bytes);

    let handoff_pointer = ptr::from_ref(&HANDOFF);

    // SAFETY: All protocols and heap-backed values have been dropped. The
    // returned map owns its page allocation and is deliberately leaked because
    // Boot Services cannot free it after a successful exit.
    let memory_map = unsafe { boot::exit_boot_services(Some(MemoryType::LOADER_DATA)) };
    mem::forget(memory_map);

    // SAFETY: The validated ELF entry lies within a loaded executable segment.
    // ADR-0001 declares the System V AMD64 entry ABI and requires interrupts
    // disabled with the direction flag clear before the one-way transfer.
    unsafe {
        asm!("cli", "cld", options(nomem, nostack));
        let entry: unsafe extern "sysv64" fn(*const BootHandoffV1) -> ! =
            mem::transmute(entry_address as usize);
        entry(handoff_pointer)
    }
}

fn read_kernel() -> Result<Vec<u8>, Status> {
    let protocol =
        boot::get_image_file_system(boot::image_handle()).map_err(|error| error.status())?;
    let mut file_system = FileSystem::new(protocol);
    let metadata = file_system
        .metadata(KERNEL_PATH)
        .map_err(file_system_status)?;
    if metadata.file_size() == 0 || metadata.file_size() > MAX_KERNEL_IMAGE_SIZE {
        return Err(Status::LOAD_ERROR);
    }
    drop(metadata);
    file_system.read(KERNEL_PATH).map_err(file_system_status)
}

fn file_system_status(error: uefi::fs::Error) -> Status {
    match error {
        uefi::fs::Error::Io(error) => error.uefi_error.status(),
        _ => Status::LOAD_ERROR,
    }
}

fn load_segments(image: ValidatedImage<'_>) -> Result<(), Status> {
    for segment in image.segments() {
        let page_count = segment.page_count();
        if page_count == 0 || segment.memory_size > usize::MAX as u64 {
            return Err(Status::LOAD_ERROR);
        }

        boot::allocate_pages(
            AllocateType::Address(segment.physical_start),
            MemoryType::LOADER_DATA,
            page_count,
        )
        .map_err(|error| error.status())?;

        // SAFETY: allocate_pages reserved the complete page range at the exact
        // validated physical address. The range is identity-mapped by the UEFI
        // execution environment, does not overlap another segment, and remains
        // loader-owned across ExitBootServices.
        unsafe {
            let destination = segment.physical_start as *mut u8;
            ptr::write_bytes(destination, 0, page_count * PAGE_SIZE);
            ptr::copy_nonoverlapping(
                image.file_bytes(segment).as_ptr(),
                destination,
                segment.file_size,
            );
        }
    }
    Ok(())
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

const _: () = assert!(core::mem::size_of::<MemoryRegionV1>() == 24);
