use crate::{MAX_MEMORY_REGIONS, MemoryRegionV1, PAGE_SIZE, is_known_memory_kind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceMemoryRegion {
    pub physical_start: u64,
    pub page_count: u64,
    pub kind: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryRegionOverride {
    pub physical_start: u64,
    pub page_count: u64,
    pub kind: u32,
}

impl MemoryRegionOverride {
    pub const EMPTY: Self = Self {
        physical_start: 0,
        page_count: 0,
        kind: 0,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalizeError {
    EmptySource,
    ZeroPages,
    UnalignedStart,
    RangeOverflow,
    UnknownKind,
    SourceOutOfOrder,
    SourceOverlap,
    OverrideOutOfOrder,
    OverrideOverlap,
    OverrideOutsideSource,
    CapacityExceeded,
}

pub fn normalize_memory_regions<I>(
    sources: I,
    overrides: &[MemoryRegionOverride],
    output: &mut [MemoryRegionV1],
) -> Result<usize, NormalizeError>
where
    I: IntoIterator<Item = SourceMemoryRegion>,
{
    if output.len() > MAX_MEMORY_REGIONS {
        return Err(NormalizeError::CapacityExceeded);
    }
    validate_overrides(overrides)?;

    let mut writer = RegionWriter::new(output);
    let mut previous_source_start = None;
    let mut previous_source_end = None;
    let mut override_index = 0;
    let mut override_consumed = overrides.first().map_or(0, |region| region.physical_start);
    let mut saw_source = false;

    for source in sources {
        saw_source = true;
        let source_end = checked_region_end(source.physical_start, source.page_count, source.kind)?;
        if let Some(previous_start) = previous_source_start
            && source.physical_start < previous_start
        {
            return Err(NormalizeError::SourceOutOfOrder);
        }
        if let Some(previous_end) = previous_source_end
            && source.physical_start < previous_end
        {
            return Err(NormalizeError::SourceOverlap);
        }

        let mut cursor = source.physical_start;
        while override_index < overrides.len() {
            let replacement = overrides[override_index];
            let replacement_end = region_end(replacement.physical_start, replacement.page_count)?;

            if replacement_end <= cursor {
                if override_consumed != replacement_end {
                    return Err(NormalizeError::OverrideOutsideSource);
                }
                override_index += 1;
                override_consumed = overrides
                    .get(override_index)
                    .map_or(0, |region| region.physical_start);
                continue;
            }
            if replacement.physical_start >= source_end {
                break;
            }

            let replacement_start = replacement.physical_start.max(cursor);
            if override_consumed < replacement_start {
                return Err(NormalizeError::OverrideOutsideSource);
            }
            writer.emit(cursor, replacement_start, source.kind)?;

            let overlap_end = replacement_end.min(source_end);
            writer.emit(replacement_start, overlap_end, replacement.kind)?;
            cursor = overlap_end;
            override_consumed = overlap_end;

            if override_consumed == replacement_end {
                override_index += 1;
                override_consumed = overrides
                    .get(override_index)
                    .map_or(0, |region| region.physical_start);
            } else {
                break;
            }
        }
        writer.emit(cursor, source_end, source.kind)?;

        previous_source_start = Some(source.physical_start);
        previous_source_end = Some(source_end);
    }

    if !saw_source {
        return Err(NormalizeError::EmptySource);
    }
    while override_index < overrides.len() {
        let replacement = overrides[override_index];
        let replacement_end = region_end(replacement.physical_start, replacement.page_count)?;
        if override_consumed != replacement_end {
            return Err(NormalizeError::OverrideOutsideSource);
        }
        override_index += 1;
        override_consumed = overrides
            .get(override_index)
            .map_or(0, |region| region.physical_start);
    }
    if writer.len == 0 {
        return Err(NormalizeError::EmptySource);
    }
    Ok(writer.len)
}

fn validate_overrides(overrides: &[MemoryRegionOverride]) -> Result<(), NormalizeError> {
    let mut previous_start = None;
    let mut previous_end = None;
    for replacement in overrides {
        let end = checked_region_end(
            replacement.physical_start,
            replacement.page_count,
            replacement.kind,
        )?;
        if let Some(start) = previous_start
            && replacement.physical_start < start
        {
            return Err(NormalizeError::OverrideOutOfOrder);
        }
        if let Some(previous_end) = previous_end
            && replacement.physical_start < previous_end
        {
            return Err(NormalizeError::OverrideOverlap);
        }
        previous_start = Some(replacement.physical_start);
        previous_end = Some(end);
    }
    Ok(())
}

fn checked_region_end(start: u64, pages: u64, kind: u32) -> Result<u64, NormalizeError> {
    if !is_known_memory_kind(kind) {
        return Err(NormalizeError::UnknownKind);
    }
    region_end(start, pages)
}

fn region_end(start: u64, pages: u64) -> Result<u64, NormalizeError> {
    if pages == 0 {
        return Err(NormalizeError::ZeroPages);
    }
    if !start.is_multiple_of(PAGE_SIZE) {
        return Err(NormalizeError::UnalignedStart);
    }
    let bytes = pages
        .checked_mul(PAGE_SIZE)
        .ok_or(NormalizeError::RangeOverflow)?;
    start
        .checked_add(bytes)
        .ok_or(NormalizeError::RangeOverflow)
}

struct RegionWriter<'a> {
    output: &'a mut [MemoryRegionV1],
    len: usize,
}

impl<'a> RegionWriter<'a> {
    const fn new(output: &'a mut [MemoryRegionV1]) -> Self {
        Self { output, len: 0 }
    }

    fn emit(&mut self, start: u64, end: u64, kind: u32) -> Result<(), NormalizeError> {
        if start == end {
            return Ok(());
        }
        let page_count = (end - start) / PAGE_SIZE;
        if self.len > 0 {
            let previous = &mut self.output[self.len - 1];
            let previous_end = region_end(previous.physical_start, previous.page_count)?;
            if previous.kind == kind && previous_end == start {
                previous.page_count = previous
                    .page_count
                    .checked_add(page_count)
                    .ok_or(NormalizeError::RangeOverflow)?;
                return Ok(());
            }
        }
        if self.len == self.output.len() {
            return Err(NormalizeError::CapacityExceeded);
        }
        self.output[self.len] = MemoryRegionV1 {
            physical_start: start,
            page_count,
            kind,
            attributes: 0,
        };
        self.len += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MEMORY_LOADER_RECLAIMABLE, MEMORY_MMIO, MEMORY_RESERVED, MEMORY_USABLE};

    fn source(start: u64, pages: u64, kind: u32) -> SourceMemoryRegion {
        SourceMemoryRegion {
            physical_start: start,
            page_count: pages,
            kind,
        }
    }

    fn replacement(start: u64, pages: u64, kind: u32) -> MemoryRegionOverride {
        MemoryRegionOverride {
            physical_start: start,
            page_count: pages,
            kind,
        }
    }

    #[test]
    fn merges_adjacent_regions_with_the_same_kind() {
        let mut output = [MemoryRegionV1::default(); 4];
        let count = normalize_memory_regions(
            [
                source(0x1000, 2, MEMORY_USABLE),
                source(0x3000, 3, MEMORY_USABLE),
            ],
            &[],
            &mut output,
        )
        .unwrap();
        assert_eq!(count, 1);
        assert_eq!(
            output[0],
            MemoryRegionV1 {
                physical_start: 0x1000,
                page_count: 5,
                kind: MEMORY_USABLE,
                attributes: 0,
            }
        );
    }

    #[test]
    fn splits_usable_memory_around_kernel_and_framebuffer_overrides() {
        let mut output = [MemoryRegionV1::default(); 8];
        let count = normalize_memory_regions(
            [source(0x1000, 10, MEMORY_USABLE)],
            &[
                replacement(0x3000, 2, MEMORY_RESERVED),
                replacement(0x8000, 2, MEMORY_MMIO),
            ],
            &mut output,
        )
        .unwrap();
        assert_eq!(count, 5);
        assert_eq!(
            output[..count],
            [
                MemoryRegionV1 {
                    physical_start: 0x1000,
                    page_count: 2,
                    kind: MEMORY_USABLE,
                    attributes: 0
                },
                MemoryRegionV1 {
                    physical_start: 0x3000,
                    page_count: 2,
                    kind: MEMORY_RESERVED,
                    attributes: 0
                },
                MemoryRegionV1 {
                    physical_start: 0x5000,
                    page_count: 3,
                    kind: MEMORY_USABLE,
                    attributes: 0
                },
                MemoryRegionV1 {
                    physical_start: 0x8000,
                    page_count: 2,
                    kind: MEMORY_MMIO,
                    attributes: 0
                },
                MemoryRegionV1 {
                    physical_start: 0xa000,
                    page_count: 1,
                    kind: MEMORY_USABLE,
                    attributes: 0
                },
            ]
        );
    }

    #[test]
    fn applies_one_override_across_adjacent_source_descriptors() {
        let mut output = [MemoryRegionV1::default(); 4];
        let count = normalize_memory_regions(
            [
                source(0x1000, 2, MEMORY_USABLE),
                source(0x3000, 2, MEMORY_LOADER_RECLAIMABLE),
            ],
            &[replacement(0x2000, 2, MEMORY_RESERVED)],
            &mut output,
        )
        .unwrap();
        assert_eq!(count, 3);
        assert_eq!(output[1].physical_start, 0x2000);
        assert_eq!(output[1].page_count, 2);
        assert_eq!(output[1].kind, MEMORY_RESERVED);
    }

    #[test]
    fn rejects_override_in_a_source_gap() {
        let mut output = [MemoryRegionV1::default(); 4];
        assert_eq!(
            normalize_memory_regions(
                [
                    source(0x1000, 1, MEMORY_USABLE),
                    source(0x3000, 1, MEMORY_USABLE),
                ],
                &[replacement(0x2000, 1, MEMORY_RESERVED)],
                &mut output,
            ),
            Err(NormalizeError::OverrideOutsideSource)
        );
    }

    #[test]
    fn rejects_unsorted_overlapping_and_malformed_inputs() {
        let mut output = [MemoryRegionV1::default(); 4];
        assert_eq!(
            normalize_memory_regions(
                [
                    source(0x3000, 1, MEMORY_USABLE),
                    source(0x1000, 1, MEMORY_USABLE),
                ],
                &[],
                &mut output,
            ),
            Err(NormalizeError::SourceOutOfOrder)
        );
        assert_eq!(
            normalize_memory_regions(
                [
                    source(0x1000, 3, MEMORY_USABLE),
                    source(0x3000, 1, MEMORY_USABLE),
                ],
                &[],
                &mut output,
            ),
            Err(NormalizeError::SourceOverlap)
        );
        assert_eq!(
            normalize_memory_regions([source(0x1001, 1, MEMORY_USABLE)], &[], &mut output,),
            Err(NormalizeError::UnalignedStart)
        );
        assert_eq!(
            normalize_memory_regions([source(0x1000, 0, MEMORY_USABLE)], &[], &mut output,),
            Err(NormalizeError::ZeroPages)
        );
        assert_eq!(
            normalize_memory_regions(
                [source(!(PAGE_SIZE - 1), 2, MEMORY_USABLE)],
                &[],
                &mut output,
            ),
            Err(NormalizeError::RangeOverflow)
        );
    }

    #[test]
    fn rejects_bad_override_order_overlap_and_unknown_kinds() {
        let mut output = [MemoryRegionV1::default(); 8];
        assert_eq!(
            normalize_memory_regions(
                [source(0x1000, 8, MEMORY_USABLE)],
                &[
                    replacement(0x5000, 1, MEMORY_RESERVED),
                    replacement(0x3000, 1, MEMORY_RESERVED),
                ],
                &mut output,
            ),
            Err(NormalizeError::OverrideOutOfOrder)
        );
        assert_eq!(
            normalize_memory_regions(
                [source(0x1000, 8, MEMORY_USABLE)],
                &[
                    replacement(0x3000, 2, MEMORY_RESERVED),
                    replacement(0x4000, 1, MEMORY_MMIO),
                ],
                &mut output,
            ),
            Err(NormalizeError::OverrideOverlap)
        );
        assert_eq!(
            normalize_memory_regions([source(0x1000, 1, 99)], &[], &mut output,),
            Err(NormalizeError::UnknownKind)
        );
    }

    #[test]
    fn rejects_empty_sources_and_exhausted_output() {
        let mut output = [MemoryRegionV1::default(); 1];
        assert_eq!(
            normalize_memory_regions([], &[], &mut output),
            Err(NormalizeError::EmptySource)
        );
        assert_eq!(
            normalize_memory_regions(
                [
                    source(0x1000, 1, MEMORY_USABLE),
                    source(0x3000, 1, MEMORY_RESERVED),
                ],
                &[],
                &mut output,
            ),
            Err(NormalizeError::CapacityExceeded)
        );
    }
}
