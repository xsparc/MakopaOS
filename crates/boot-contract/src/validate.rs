use core::mem::{align_of, size_of};

use crate::{
    ABI_MAJOR, ABI_MINOR, BootHandoffHeaderV1, BootHandoffV1, FRAMEBUFFER_PRESENT, HANDOFF_MAGIC,
    MAX_MEMORY_REGIONS, MEMORY_USABLE, MemoryRegionV1, PAGE_SIZE, PIXEL_FORMAT_BGR,
    PIXEL_FORMAT_RGB, is_known_memory_kind,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    Magic,
    AbiMajor,
    AbiMinor,
    HeaderSize,
    HandoffSize,
    Flags,
    Reserved,
    HandoffAddress,
    RegionAddress,
    RegionCount,
    RegionEntrySize,
    RegionSlice,
    RegionZeroPages,
    RegionAlignment,
    RegionOverflow,
    RegionOrder,
    RegionOverlap,
    RegionKind,
    RegionAttributes,
    HandoffInUsableMemory,
    RegionArrayInUsableMemory,
    FramebufferFlag,
    FramebufferFields,
    FramebufferPixelFormat,
    FramebufferStride,
    FramebufferLength,
    FramebufferOverflow,
    FramebufferInUsableMemory,
}

pub fn validate_handoff_header(handoff: &BootHandoffV1) -> Result<usize, ValidationError> {
    let header = &handoff.header;
    validate_header(header)?;

    if handoff.memory_region_count == 0 || handoff.memory_region_count as usize > MAX_MEMORY_REGIONS
    {
        return Err(ValidationError::RegionCount);
    }
    if handoff.memory_regions_address == 0
        || !handoff
            .memory_regions_address
            .is_multiple_of(align_of::<MemoryRegionV1>() as u64)
    {
        return Err(ValidationError::RegionAddress);
    }
    if handoff.memory_region_entry_size != size_of::<MemoryRegionV1>() as u32 {
        return Err(ValidationError::RegionEntrySize);
    }
    let region_count = handoff.memory_region_count as usize;
    let region_bytes = region_count
        .checked_mul(size_of::<MemoryRegionV1>())
        .ok_or(ValidationError::RegionOverflow)?;
    handoff
        .memory_regions_address
        .checked_add(region_bytes as u64)
        .ok_or(ValidationError::RegionOverflow)?;

    validate_framebuffer_shape(handoff)?;
    Ok(region_count)
}

pub fn validate_handoff(
    handoff: &BootHandoffV1,
    handoff_address: u64,
    regions: &[MemoryRegionV1],
) -> Result<(), ValidationError> {
    let region_count = validate_handoff_header(handoff)?;
    if handoff_address == 0 || !handoff_address.is_multiple_of(align_of::<BootHandoffV1>() as u64) {
        return Err(ValidationError::HandoffAddress);
    }
    let handoff_end = handoff_address
        .checked_add(size_of::<BootHandoffV1>() as u64)
        .ok_or(ValidationError::HandoffAddress)?;
    if regions.len() != region_count
        || handoff.memory_regions_address != regions.as_ptr() as usize as u64
    {
        return Err(ValidationError::RegionSlice);
    }

    let mut previous_start = None;
    let mut previous_end = None;
    for region in regions {
        if region.page_count == 0 {
            return Err(ValidationError::RegionZeroPages);
        }
        if !region.physical_start.is_multiple_of(PAGE_SIZE) {
            return Err(ValidationError::RegionAlignment);
        }
        if !is_known_memory_kind(region.kind) {
            return Err(ValidationError::RegionKind);
        }
        if region.attributes != 0 {
            return Err(ValidationError::RegionAttributes);
        }
        let end = region_end(region)?;
        if let Some(start) = previous_start
            && region.physical_start < start
        {
            return Err(ValidationError::RegionOrder);
        }
        if let Some(previous_end) = previous_end
            && region.physical_start < previous_end
        {
            return Err(ValidationError::RegionOverlap);
        }
        previous_start = Some(region.physical_start);
        previous_end = Some(end);
    }

    if overlaps_usable(handoff_address, handoff_end, regions)? {
        return Err(ValidationError::HandoffInUsableMemory);
    }
    let region_array_end = handoff
        .memory_regions_address
        .checked_add((region_count * size_of::<MemoryRegionV1>()) as u64)
        .ok_or(ValidationError::RegionOverflow)?;
    if overlaps_usable(handoff.memory_regions_address, region_array_end, regions)? {
        return Err(ValidationError::RegionArrayInUsableMemory);
    }
    if handoff.header.flags & FRAMEBUFFER_PRESENT != 0 {
        let framebuffer_end = handoff
            .framebuffer
            .physical_start
            .checked_add(handoff.framebuffer.byte_length)
            .ok_or(ValidationError::FramebufferOverflow)?;
        if overlaps_usable(handoff.framebuffer.physical_start, framebuffer_end, regions)? {
            return Err(ValidationError::FramebufferInUsableMemory);
        }
    }
    Ok(())
}

fn validate_header(header: &BootHandoffHeaderV1) -> Result<(), ValidationError> {
    if header.magic != HANDOFF_MAGIC {
        return Err(ValidationError::Magic);
    }
    if header.abi_major != ABI_MAJOR {
        return Err(ValidationError::AbiMajor);
    }
    if header.abi_minor != ABI_MINOR {
        return Err(ValidationError::AbiMinor);
    }
    if header.header_size != size_of::<BootHandoffHeaderV1>() as u32 {
        return Err(ValidationError::HeaderSize);
    }
    if header.handoff_size != size_of::<BootHandoffV1>() as u32 {
        return Err(ValidationError::HandoffSize);
    }
    if header.flags & !FRAMEBUFFER_PRESENT != 0 {
        return Err(ValidationError::Flags);
    }
    if header.reserved != 0 {
        return Err(ValidationError::Reserved);
    }
    Ok(())
}

fn validate_framebuffer_shape(handoff: &BootHandoffV1) -> Result<(), ValidationError> {
    let present = handoff.header.flags & FRAMEBUFFER_PRESENT != 0;
    if !present {
        return if handoff.framebuffer.is_zero() {
            Ok(())
        } else {
            Err(ValidationError::FramebufferFlag)
        };
    }

    let framebuffer = &handoff.framebuffer;
    if framebuffer.physical_start == 0
        || framebuffer.byte_length == 0
        || framebuffer.width == 0
        || framebuffer.height == 0
        || framebuffer.stride_pixels == 0
        || framebuffer.reserved != 0
    {
        return Err(ValidationError::FramebufferFields);
    }
    if framebuffer.pixel_format != PIXEL_FORMAT_RGB && framebuffer.pixel_format != PIXEL_FORMAT_BGR
    {
        return Err(ValidationError::FramebufferPixelFormat);
    }
    if framebuffer.stride_pixels < framebuffer.width {
        return Err(ValidationError::FramebufferStride);
    }
    let minimum_length = u64::from(framebuffer.stride_pixels)
        .checked_mul(u64::from(framebuffer.height))
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or(ValidationError::FramebufferOverflow)?;
    if minimum_length > framebuffer.byte_length {
        return Err(ValidationError::FramebufferLength);
    }
    framebuffer
        .physical_start
        .checked_add(framebuffer.byte_length)
        .ok_or(ValidationError::FramebufferOverflow)?;
    Ok(())
}

fn region_end(region: &MemoryRegionV1) -> Result<u64, ValidationError> {
    let bytes = region
        .page_count
        .checked_mul(PAGE_SIZE)
        .ok_or(ValidationError::RegionOverflow)?;
    region
        .physical_start
        .checked_add(bytes)
        .ok_or(ValidationError::RegionOverflow)
}

fn overlaps_usable(
    start: u64,
    end: u64,
    regions: &[MemoryRegionV1],
) -> Result<bool, ValidationError> {
    for region in regions {
        if region.kind != MEMORY_USABLE {
            continue;
        }
        let region_end = region_end(region)?;
        if start < region_end && region.physical_start < end {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BootHandoffHeaderV1, FramebufferV1, MEMORY_LOADER_RECLAIMABLE, MEMORY_RESERVED,
        PIXEL_FORMAT_RGB,
    };

    fn valid_regions() -> [MemoryRegionV1; 3] {
        [
            MemoryRegionV1 {
                physical_start: 0,
                page_count: 1,
                kind: MEMORY_RESERVED,
                attributes: 0,
            },
            MemoryRegionV1 {
                physical_start: 0x1000,
                page_count: 8,
                kind: MEMORY_USABLE,
                attributes: 0,
            },
            MemoryRegionV1 {
                physical_start: 0x9000,
                page_count: 4,
                kind: MEMORY_LOADER_RECLAIMABLE,
                attributes: 0,
            },
        ]
    }

    fn valid_handoff(regions: &[MemoryRegionV1]) -> BootHandoffV1 {
        BootHandoffV1 {
            header: BootHandoffHeaderV1::new(),
            memory_regions_address: regions.as_ptr() as usize as u64,
            memory_region_count: regions.len() as u32,
            memory_region_entry_size: size_of::<MemoryRegionV1>() as u32,
            framebuffer: FramebufferV1::default(),
        }
    }

    #[test]
    fn accepts_a_valid_handoff_without_a_framebuffer() {
        let regions = valid_regions();
        let handoff = valid_handoff(&regions);
        assert_eq!(validate_handoff(&handoff, 0x9000, &regions), Ok(()));
    }

    #[test]
    fn accepts_a_valid_rgb_framebuffer() {
        let mut regions = valid_regions();
        regions[0] = MemoryRegionV1 {
            physical_start: 0,
            page_count: 1,
            kind: MEMORY_RESERVED,
            attributes: 0,
        };
        let mut handoff = valid_handoff(&regions);
        handoff.header.flags = FRAMEBUFFER_PRESENT;
        handoff.framebuffer = FramebufferV1 {
            physical_start: 0xd000,
            byte_length: 800 * 600 * 4,
            width: 800,
            height: 600,
            stride_pixels: 800,
            pixel_format: PIXEL_FORMAT_RGB,
            reserved: 0,
        };
        assert_eq!(validate_handoff(&handoff, 0x9000, &regions), Ok(()));
    }

    #[test]
    fn rejects_every_incompatible_header_field() {
        let regions = valid_regions();
        let base = valid_handoff(&regions);
        let mut cases = [base; 7];
        cases[0].header.magic = *b"NOTMAKOP";
        cases[1].header.abi_major += 1;
        cases[2].header.abi_minor += 1;
        cases[3].header.header_size += 1;
        cases[4].header.handoff_size += 1;
        cases[5].header.flags = 2;
        cases[6].header.reserved = 1;
        let expected = [
            ValidationError::Magic,
            ValidationError::AbiMajor,
            ValidationError::AbiMinor,
            ValidationError::HeaderSize,
            ValidationError::HandoffSize,
            ValidationError::Flags,
            ValidationError::Reserved,
        ];
        for (handoff, error) in cases.iter().zip(expected) {
            assert_eq!(validate_handoff_header(handoff), Err(error));
        }
    }

    #[test]
    fn rejects_bad_region_metadata_and_slice_identity() {
        let regions = valid_regions();
        let mut handoff = valid_handoff(&regions);
        handoff.memory_region_count = 0;
        assert_eq!(
            validate_handoff_header(&handoff),
            Err(ValidationError::RegionCount)
        );
        handoff = valid_handoff(&regions);
        handoff.memory_region_count = (MAX_MEMORY_REGIONS + 1) as u32;
        assert_eq!(
            validate_handoff_header(&handoff),
            Err(ValidationError::RegionCount)
        );
        handoff = valid_handoff(&regions);
        handoff.memory_regions_address = 1;
        assert_eq!(
            validate_handoff_header(&handoff),
            Err(ValidationError::RegionAddress)
        );
        handoff = valid_handoff(&regions);
        handoff.memory_region_entry_size += 1;
        assert_eq!(
            validate_handoff_header(&handoff),
            Err(ValidationError::RegionEntrySize)
        );
        handoff = valid_handoff(&regions);
        handoff.memory_regions_address = u64::MAX - 7;
        assert_eq!(
            validate_handoff_header(&handoff),
            Err(ValidationError::RegionOverflow)
        );
        handoff = valid_handoff(&regions);
        handoff.memory_regions_address += size_of::<MemoryRegionV1>() as u64;
        assert_eq!(
            validate_handoff(&handoff, 0x9000, &regions),
            Err(ValidationError::RegionSlice)
        );
        handoff = valid_handoff(&regions);
        assert_eq!(
            validate_handoff(&handoff, 0x9001, &regions),
            Err(ValidationError::HandoffAddress)
        );
        assert_eq!(
            validate_handoff(&handoff, u64::MAX - 7, &regions),
            Err(ValidationError::HandoffAddress)
        );
    }

    #[test]
    fn rejects_malformed_region_ranges() {
        let base = valid_regions();
        let cases = [
            (
                MemoryRegionV1 {
                    page_count: 0,
                    ..base[1]
                },
                ValidationError::RegionZeroPages,
            ),
            (
                MemoryRegionV1 {
                    physical_start: 0x1001,
                    ..base[1]
                },
                ValidationError::RegionAlignment,
            ),
            (
                MemoryRegionV1 {
                    physical_start: !(PAGE_SIZE - 1),
                    page_count: 2,
                    ..base[1]
                },
                ValidationError::RegionOverflow,
            ),
            (
                MemoryRegionV1 {
                    kind: 99,
                    ..base[1]
                },
                ValidationError::RegionKind,
            ),
            (
                MemoryRegionV1 {
                    attributes: 1,
                    ..base[1]
                },
                ValidationError::RegionAttributes,
            ),
        ];
        for (bad_region, error) in cases {
            let regions = [base[0], bad_region, base[2]];
            let handoff = valid_handoff(&regions);
            assert_eq!(validate_handoff(&handoff, 0x9000, &regions), Err(error));
        }
    }

    #[test]
    fn rejects_unsorted_and_overlapping_regions() {
        let mut regions = valid_regions();
        regions.swap(0, 1);
        let handoff = valid_handoff(&regions);
        assert_eq!(
            validate_handoff(&handoff, 0x9000, &regions),
            Err(ValidationError::RegionOrder)
        );

        let mut regions = valid_regions();
        regions[1].page_count = 9;
        let handoff = valid_handoff(&regions);
        assert_eq!(
            validate_handoff(&handoff, 0x9000, &regions),
            Err(ValidationError::RegionOverlap)
        );
    }

    #[test]
    fn rejects_loader_storage_marked_usable() {
        let mut regions = valid_regions();
        regions[2].kind = MEMORY_USABLE;
        let handoff = valid_handoff(&regions);
        assert_eq!(
            validate_handoff(&handoff, 0x9000, &regions),
            Err(ValidationError::HandoffInUsableMemory)
        );

        let mut regions = [MemoryRegionV1::default()];
        let pointer_page = (regions.as_ptr() as usize as u64) & !(PAGE_SIZE - 1);
        regions[0] = MemoryRegionV1 {
            physical_start: pointer_page,
            page_count: 1,
            kind: MEMORY_USABLE,
            attributes: 0,
        };
        let handoff = valid_handoff(&regions);
        assert_eq!(
            validate_handoff(&handoff, 0x1000, &regions),
            Err(ValidationError::RegionArrayInUsableMemory)
        );
    }

    #[test]
    fn rejects_framebuffer_flag_shape_stride_length_and_overflow() {
        let regions = valid_regions();
        let mut handoff = valid_handoff(&regions);
        handoff.framebuffer.width = 1;
        assert_eq!(
            validate_handoff_header(&handoff),
            Err(ValidationError::FramebufferFlag)
        );

        handoff = valid_handoff(&regions);
        handoff.header.flags = FRAMEBUFFER_PRESENT;
        assert_eq!(
            validate_handoff_header(&handoff),
            Err(ValidationError::FramebufferFields)
        );

        handoff.framebuffer = FramebufferV1 {
            physical_start: 0xd000,
            byte_length: 4096,
            width: 16,
            height: 16,
            stride_pixels: 16,
            pixel_format: 99,
            reserved: 0,
        };
        assert_eq!(
            validate_handoff_header(&handoff),
            Err(ValidationError::FramebufferPixelFormat)
        );
        handoff.framebuffer.pixel_format = PIXEL_FORMAT_RGB;
        handoff.framebuffer.stride_pixels = 8;
        assert_eq!(
            validate_handoff_header(&handoff),
            Err(ValidationError::FramebufferStride)
        );
        handoff.framebuffer.stride_pixels = 16;
        handoff.framebuffer.byte_length = 100;
        assert_eq!(
            validate_handoff_header(&handoff),
            Err(ValidationError::FramebufferLength)
        );
        handoff.framebuffer.byte_length = 4096;
        handoff.framebuffer.physical_start = u64::MAX - 100;
        assert_eq!(
            validate_handoff_header(&handoff),
            Err(ValidationError::FramebufferOverflow)
        );
        handoff.framebuffer.physical_start = 1;
        handoff.framebuffer.byte_length = u64::MAX - 1;
        handoff.framebuffer.width = u32::MAX;
        handoff.framebuffer.height = u32::MAX;
        handoff.framebuffer.stride_pixels = u32::MAX;
        assert_eq!(
            validate_handoff_header(&handoff),
            Err(ValidationError::FramebufferOverflow)
        );
    }

    #[test]
    fn rejects_framebuffer_storage_marked_usable() {
        let regions = valid_regions();
        let mut handoff = valid_handoff(&regions);
        handoff.header.flags = FRAMEBUFFER_PRESENT;
        handoff.framebuffer = FramebufferV1 {
            physical_start: 0x2000,
            byte_length: 4096,
            width: 16,
            height: 16,
            stride_pixels: 16,
            pixel_format: PIXEL_FORMAT_RGB,
            reserved: 0,
        };
        assert_eq!(
            validate_handoff(&handoff, 0x9000, &regions),
            Err(ValidationError::FramebufferInUsableMemory)
        );
    }
}
