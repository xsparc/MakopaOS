#![no_std]

use core::mem::size_of;

pub const HANDOFF_MAGIC: [u8; 8] = *b"MAKOPA\0\0";
pub const ABI_MAJOR: u16 = 1;
pub const ABI_MINOR: u16 = 0;
pub const FRAMEBUFFER_PRESENT: u32 = 1;

pub const MEMORY_RESERVED: u32 = 0;
pub const MEMORY_USABLE: u32 = 1;
pub const MEMORY_LOADER_RECLAIMABLE: u32 = 2;
pub const MEMORY_ACPI_RECLAIMABLE: u32 = 3;
pub const MEMORY_ACPI_NVS: u32 = 4;
pub const MEMORY_MMIO: u32 = 5;

pub const PIXEL_FORMAT_UNAVAILABLE: u32 = 0;
pub const PIXEL_FORMAT_RGB: u32 = 1;
pub const PIXEL_FORMAT_BGR: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootHandoffHeaderV1 {
    pub magic: [u8; 8],
    pub abi_major: u16,
    pub abi_minor: u16,
    pub header_size: u32,
    pub handoff_size: u32,
    pub flags: u32,
    pub reserved: u64,
}

impl BootHandoffHeaderV1 {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            magic: HANDOFF_MAGIC,
            abi_major: ABI_MAJOR,
            abi_minor: ABI_MINOR,
            header_size: size_of::<Self>() as u32,
            handoff_size: size_of::<BootHandoffV1>() as u32,
            flags: 0,
            reserved: 0,
        }
    }

    #[must_use]
    pub fn is_v1(&self) -> bool {
        self.magic == HANDOFF_MAGIC
            && self.abi_major == ABI_MAJOR
            && self.abi_minor == ABI_MINOR
            && self.header_size == size_of::<Self>() as u32
            && self.handoff_size == size_of::<BootHandoffV1>() as u32
            && self.flags & !FRAMEBUFFER_PRESENT == 0
            && self.reserved == 0
    }
}

impl Default for BootHandoffHeaderV1 {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemoryRegionV1 {
    pub physical_start: u64,
    pub page_count: u64,
    pub kind: u32,
    pub attributes: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FramebufferV1 {
    pub physical_start: u64,
    pub byte_length: u64,
    pub width: u32,
    pub height: u32,
    pub stride_pixels: u32,
    pub pixel_format: u32,
    pub reserved: u64,
}

impl FramebufferV1 {
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.physical_start == 0
            && self.byte_length == 0
            && self.width == 0
            && self.height == 0
            && self.stride_pixels == 0
            && self.pixel_format == 0
            && self.reserved == 0
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootHandoffV1 {
    pub header: BootHandoffHeaderV1,
    pub memory_regions_address: u64,
    pub memory_region_count: u32,
    pub memory_region_entry_size: u32,
    pub framebuffer: FramebufferV1,
}

impl BootHandoffV1 {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            header: BootHandoffHeaderV1::new(),
            memory_regions_address: 0,
            memory_region_count: 0,
            memory_region_entry_size: size_of::<MemoryRegionV1>() as u32,
            framebuffer: FramebufferV1 {
                physical_start: 0,
                byte_length: 0,
                width: 0,
                height: 0,
                stride_pixels: 0,
                pixel_format: PIXEL_FORMAT_UNAVAILABLE,
                reserved: 0,
            },
        }
    }

    #[must_use]
    pub fn is_empty_v1(&self) -> bool {
        self.header.is_v1()
            && self.header.flags == 0
            && self.memory_regions_address == 0
            && self.memory_region_count == 0
            && self.memory_region_entry_size == size_of::<MemoryRegionV1>() as u32
            && self.framebuffer.is_zero()
    }
}

impl Default for BootHandoffV1 {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, offset_of, size_of};

    use super::*;

    #[test]
    fn header_layout_matches_adr_0001() {
        assert_eq!(size_of::<BootHandoffHeaderV1>(), 32);
        assert_eq!(align_of::<BootHandoffHeaderV1>(), 8);
        assert_eq!(offset_of!(BootHandoffHeaderV1, magic), 0);
        assert_eq!(offset_of!(BootHandoffHeaderV1, abi_major), 8);
        assert_eq!(offset_of!(BootHandoffHeaderV1, abi_minor), 10);
        assert_eq!(offset_of!(BootHandoffHeaderV1, header_size), 12);
        assert_eq!(offset_of!(BootHandoffHeaderV1, handoff_size), 16);
        assert_eq!(offset_of!(BootHandoffHeaderV1, flags), 20);
        assert_eq!(offset_of!(BootHandoffHeaderV1, reserved), 24);
    }

    #[test]
    fn handoff_layout_matches_adr_0001() {
        assert_eq!(size_of::<BootHandoffV1>(), 88);
        assert_eq!(align_of::<BootHandoffV1>(), 8);
        assert_eq!(offset_of!(BootHandoffV1, header), 0);
        assert_eq!(offset_of!(BootHandoffV1, memory_regions_address), 32);
        assert_eq!(offset_of!(BootHandoffV1, memory_region_count), 40);
        assert_eq!(offset_of!(BootHandoffV1, memory_region_entry_size), 44);
        assert_eq!(offset_of!(BootHandoffV1, framebuffer), 48);
    }

    #[test]
    fn supporting_record_layouts_match_adr_0001() {
        assert_eq!(size_of::<MemoryRegionV1>(), 24);
        assert_eq!(offset_of!(MemoryRegionV1, physical_start), 0);
        assert_eq!(offset_of!(MemoryRegionV1, page_count), 8);
        assert_eq!(offset_of!(MemoryRegionV1, kind), 16);
        assert_eq!(offset_of!(MemoryRegionV1, attributes), 20);

        assert_eq!(size_of::<FramebufferV1>(), 40);
        assert_eq!(offset_of!(FramebufferV1, physical_start), 0);
        assert_eq!(offset_of!(FramebufferV1, byte_length), 8);
        assert_eq!(offset_of!(FramebufferV1, width), 16);
        assert_eq!(offset_of!(FramebufferV1, height), 20);
        assert_eq!(offset_of!(FramebufferV1, stride_pixels), 24);
        assert_eq!(offset_of!(FramebufferV1, pixel_format), 28);
        assert_eq!(offset_of!(FramebufferV1, reserved), 32);
    }

    #[test]
    fn empty_handoff_is_valid_version_one() {
        assert!(BootHandoffV1::empty().is_empty_v1());
    }
}
