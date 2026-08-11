#![no_main]
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::arch::asm;
use core::mem;
use core::panic::PanicInfo;
use core::ptr;
use core::slice;

use makopa_boot_contract::{
    BootHandoffHeaderV1, BootHandoffV1, FRAMEBUFFER_PRESENT, FramebufferV1, MAX_MEMORY_REGIONS,
    MEMORY_ACPI_NVS, MEMORY_ACPI_RECLAIMABLE, MEMORY_LOADER_RECLAIMABLE, MEMORY_MMIO,
    MEMORY_RESERVED, MEMORY_USABLE, MemoryRegionOverride, MemoryRegionV1, PAGE_SIZE,
    PIXEL_FORMAT_BGR, PIXEL_FORMAT_RGB, SourceMemoryRegion, normalize_memory_regions,
};
use makopa_kernel_image::{MAXIMUM_LOAD_SEGMENTS, ValidatedImage};
use uefi::boot::{self, AllocateType, MemoryType};
use uefi::fs::FileSystem;
use uefi::mem::memory_map::{MemoryMap, MemoryMapMut};
use uefi::prelude::*;
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};
use uefi::{Status, cstr16};

const UEFI_PAGE_SIZE: usize = PAGE_SIZE as usize;
const MAX_KERNEL_IMAGE_SIZE: u64 = 16 * 1024 * 1024;
const MAX_REGION_OVERRIDES: usize = MAXIMUM_LOAD_SEGMENTS + 1;
const REGION_STORAGE_BYTES: usize = MAX_MEMORY_REGIONS * mem::size_of::<MemoryRegionV1>();
const REGION_STORAGE_PAGES: usize = REGION_STORAGE_BYTES.div_ceil(UEFI_PAGE_SIZE);
const KERNEL_PATH: &uefi::CStr16 = cstr16!(r"\MAKOPA\KERNEL.ELF");

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
    let mut overrides = [MemoryRegionOverride::EMPTY; MAX_REGION_OVERRIDES];
    let mut override_count = collect_kernel_overrides(image, &mut overrides)?;
    load_segments(image)?;
    let entry_address = image.entry();
    let framebuffer = capture_framebuffer()?;
    override_count = add_framebuffer_override(framebuffer, &mut overrides, override_count)?;
    overrides[..override_count].sort_unstable_by_key(|region| region.physical_start);

    let handoff_address = allocate_loader_pages(1)?;
    let region_storage_address = allocate_loader_pages(REGION_STORAGE_PAGES)?;
    drop(kernel_bytes);

    // SAFETY: All protocols and heap-backed values have been dropped. The
    // returned map owns its page allocation and is deliberately leaked because
    // Boot Services cannot free it after a successful exit.
    let mut memory_map = unsafe { boot::exit_boot_services(Some(MemoryType::LOADER_DATA)) };
    memory_map.sort();

    let region_pointer = region_storage_address as usize as *mut MemoryRegionV1;
    // SAFETY: allocate_loader_pages reserved this identity-mapped LoaderData
    // range before the final memory map. Zero initializes all records before a
    // mutable slice is formed, and the fixed array remains live across entry.
    let regions = unsafe {
        ptr::write_bytes(
            region_pointer.cast::<u8>(),
            0,
            REGION_STORAGE_PAGES * UEFI_PAGE_SIZE,
        );
        slice::from_raw_parts_mut(region_pointer, MAX_MEMORY_REGIONS)
    };
    let sources = memory_map.entries().map(|descriptor| SourceMemoryRegion {
        physical_start: descriptor.phys_start,
        page_count: descriptor.page_count,
        kind: memory_kind(descriptor.ty),
    });
    let region_count =
        match normalize_memory_regions(sources, &overrides[..override_count], regions) {
            Ok(count) => count,
            Err(_) => post_exit_failure(),
        };

    let mut header = BootHandoffHeaderV1::new();
    if !framebuffer.is_zero() {
        header.flags = FRAMEBUFFER_PRESENT;
    }
    let handoff = BootHandoffV1 {
        header,
        memory_regions_address: region_storage_address,
        memory_region_count: region_count as u32,
        memory_region_entry_size: mem::size_of::<MemoryRegionV1>() as u32,
        framebuffer,
    };
    let handoff_pointer = handoff_address as usize as *mut BootHandoffV1;
    // SAFETY: the page was allocated as LoaderData and is aligned, writable,
    // identity-mapped, and retained through the one-way kernel transfer.
    unsafe {
        handoff_pointer.write(handoff);
    }
    mem::forget(memory_map);

    // SAFETY: The validated ELF entry lies within a loaded executable segment.
    // ADR-0001 declares the System V AMD64 entry ABI and requires interrupts
    // disabled with the direction flag clear before the one-way transfer.
    unsafe {
        asm!("cli", "cld", options(nomem, nostack));
        let entry: unsafe extern "sysv64" fn(*const BootHandoffV1) -> ! =
            mem::transmute(entry_address as usize);
        entry(handoff_pointer.cast_const())
    }
}

fn collect_kernel_overrides(
    image: ValidatedImage<'_>,
    overrides: &mut [MemoryRegionOverride; MAX_REGION_OVERRIDES],
) -> Result<usize, Status> {
    let mut count = 0;
    for segment in image.segments() {
        if count == MAXIMUM_LOAD_SEGMENTS {
            return Err(Status::LOAD_ERROR);
        }
        overrides[count] = MemoryRegionOverride {
            physical_start: segment.physical_start,
            page_count: segment.page_count() as u64,
            kind: MEMORY_RESERVED,
        };
        count += 1;
    }
    Ok(count)
}

fn add_framebuffer_override(
    framebuffer: FramebufferV1,
    overrides: &mut [MemoryRegionOverride; MAX_REGION_OVERRIDES],
    count: usize,
) -> Result<usize, Status> {
    if framebuffer.is_zero() {
        return Ok(count);
    }
    if count == overrides.len() {
        return Err(Status::OUT_OF_RESOURCES);
    }
    let start = framebuffer.physical_start & !(PAGE_SIZE - 1);
    let end = framebuffer
        .physical_start
        .checked_add(framebuffer.byte_length)
        .and_then(|value| value.checked_add(PAGE_SIZE - 1))
        .map(|value| value & !(PAGE_SIZE - 1))
        .ok_or(Status::LOAD_ERROR)?;
    overrides[count] = MemoryRegionOverride {
        physical_start: start,
        page_count: (end - start) / PAGE_SIZE,
        kind: MEMORY_MMIO,
    };
    Ok(count + 1)
}

fn allocate_loader_pages(page_count: usize) -> Result<u64, Status> {
    boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, page_count)
        .map(|address| address.as_ptr() as usize as u64)
        .map_err(|error| error.status())
}

fn capture_framebuffer() -> Result<FramebufferV1, Status> {
    let Ok(handle) = boot::get_handle_for_protocol::<GraphicsOutput>() else {
        return Ok(FramebufferV1::default());
    };
    let Ok(mut graphics) = boot::open_protocol_exclusive::<GraphicsOutput>(handle) else {
        return Ok(FramebufferV1::default());
    };
    let mode = graphics.current_mode_info();
    let pixel_format = match mode.pixel_format() {
        PixelFormat::Rgb => PIXEL_FORMAT_RGB,
        PixelFormat::Bgr => PIXEL_FORMAT_BGR,
        PixelFormat::Bitmask | PixelFormat::BltOnly => {
            return Ok(FramebufferV1::default());
        }
    };
    let (width, height) = mode.resolution();
    let stride = mode.stride();
    if width == 0 || height == 0 || stride < width {
        return Err(Status::LOAD_ERROR);
    }

    let mut buffer = graphics.frame_buffer();
    let physical_start = buffer.as_mut_ptr() as usize as u64;
    let byte_length = u64::try_from(buffer.size()).map_err(|_| Status::LOAD_ERROR)?;
    let minimum_length = u64::try_from(stride)
        .ok()
        .and_then(|value| value.checked_mul(height as u64))
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or(Status::LOAD_ERROR)?;
    if physical_start == 0
        || byte_length < minimum_length
        || physical_start.checked_add(byte_length).is_none()
    {
        return Err(Status::LOAD_ERROR);
    }

    Ok(FramebufferV1 {
        physical_start,
        byte_length,
        width: u32::try_from(width).map_err(|_| Status::LOAD_ERROR)?,
        height: u32::try_from(height).map_err(|_| Status::LOAD_ERROR)?,
        stride_pixels: u32::try_from(stride).map_err(|_| Status::LOAD_ERROR)?,
        pixel_format,
        reserved: 0,
    })
}

fn memory_kind(memory_type: MemoryType) -> u32 {
    if memory_type == MemoryType::CONVENTIONAL {
        MEMORY_USABLE
    } else if memory_type == MemoryType::LOADER_CODE
        || memory_type == MemoryType::LOADER_DATA
        || memory_type == MemoryType::BOOT_SERVICES_CODE
        || memory_type == MemoryType::BOOT_SERVICES_DATA
    {
        MEMORY_LOADER_RECLAIMABLE
    } else if memory_type == MemoryType::ACPI_RECLAIM {
        MEMORY_ACPI_RECLAIMABLE
    } else if memory_type == MemoryType::ACPI_NON_VOLATILE {
        MEMORY_ACPI_NVS
    } else if memory_type == MemoryType::MMIO || memory_type == MemoryType::MMIO_PORT_SPACE {
        MEMORY_MMIO
    } else {
        MEMORY_RESERVED
    }
}

fn post_exit_failure() -> ! {
    // SAFETY: after ExitBootServices there is no firmware return path. Disable
    // interrupts and halt forever rather than using an invalid service.
    unsafe {
        asm!("cli", options(nomem, nostack));
    }
    loop {
        // SAFETY: interrupts remain disabled; this is the terminal fail-closed
        // path for malformed final firmware state.
        unsafe {
            asm!("hlt", options(nomem, nostack));
        }
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
            ptr::write_bytes(destination, 0, page_count * UEFI_PAGE_SIZE);
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
