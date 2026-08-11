#![no_std]

use makopa_boot_contract::{
    MAX_MEMORY_REGIONS, MEMORY_USABLE, MemoryRegionV1, PAGE_SIZE, is_known_memory_kind,
};

pub const MAX_FRAME_EXTENTS: usize = MAX_MEMORY_REGIONS;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Extent {
    physical_start: u64,
    page_count: u64,
}

impl Extent {
    const EMPTY: Self = Self {
        physical_start: 0,
        page_count: 0,
    };

    fn end(self) -> Option<u64> {
        self.page_count
            .checked_mul(PAGE_SIZE)
            .and_then(|bytes| self.physical_start.checked_add(bytes))
    }

    fn contains_frame(self, physical_start: u64, frame_end: u64) -> bool {
        self.end().is_some_and(|extent_end| {
            self.physical_start <= physical_start && frame_end <= extent_end
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitError {
    ZeroPages,
    Unaligned,
    RangeOverflow,
    OutOfOrder,
    Overlap,
    UnknownKind,
    Attributes,
    CapacityExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocateError {
    Exhausted,
    InvariantOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreeError {
    Unaligned,
    AddressOverflow,
    Unmanaged,
    Duplicate,
    CapacityExceeded,
}

/// A bounded, single-owner allocator for page-aligned physical frames.
///
/// Initialization copies eligible ranges into this value. The allocator never
/// retains a reference to the source memory map. It is intentionally neither
/// `Clone` nor `Copy`, so allocation state has one owner.
pub struct FrameAllocator {
    managed: [Extent; MAX_FRAME_EXTENTS],
    managed_len: usize,
    free: [Extent; MAX_FRAME_EXTENTS],
    free_len: usize,
}

impl FrameAllocator {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            managed: [Extent::EMPTY; MAX_FRAME_EXTENTS],
            managed_len: 0,
            free: [Extent::EMPTY; MAX_FRAME_EXTENTS],
            free_len: 0,
        }
    }

    /// Replace allocator state with kernel-owned copies of usable input ranges.
    ///
    /// The complete input is checked before existing state is changed. Failure
    /// therefore leaves the previous allocator state intact.
    pub fn initialize(&mut self, regions: &[MemoryRegionV1]) -> Result<(), InitError> {
        let extent_count = validate_and_count_extents(regions)?;

        // The first pass proved that this fill cannot fail. Keeping the fill
        // in place avoids a second allocator-sized temporary on the boot stack.
        self.managed_len = 0;
        self.free_len = 0;
        for region in regions {
            if region.kind != MEMORY_USABLE {
                continue;
            }

            let can_merge = self.managed_len != 0
                && self.managed[self.managed_len - 1].end() == Some(region.physical_start);
            if can_merge {
                let index = self.managed_len - 1;
                self.managed[index].page_count += region.page_count;
                self.free[index].page_count += region.page_count;
            } else {
                let extent = Extent {
                    physical_start: region.physical_start,
                    page_count: region.page_count,
                };
                self.managed[self.managed_len] = extent;
                self.free[self.free_len] = extent;
                self.managed_len += 1;
                self.free_len += 1;
            }
        }

        debug_assert_eq!(self.managed_len, extent_count);
        debug_assert_eq!(self.free_len, extent_count);
        Ok(())
    }

    /// Allocate the lowest-address free frame.
    pub fn allocate_frame(&mut self) -> Result<u64, AllocateError> {
        if self.free_len == 0 {
            return Err(AllocateError::Exhausted);
        }

        let frame = self.free[0].physical_start;
        if self.free[0].page_count == 1 {
            self.remove_free_extent(0);
        } else {
            let next = frame
                .checked_add(PAGE_SIZE)
                .ok_or(AllocateError::InvariantOverflow)?;
            self.free[0].physical_start = next;
            self.free[0].page_count -= 1;
        }
        Ok(frame)
    }

    /// Return one allocated frame, preserving state on every rejected free.
    pub fn free_frame(&mut self, physical_start: u64) -> Result<(), FreeError> {
        if !physical_start.is_multiple_of(PAGE_SIZE) {
            return Err(FreeError::Unaligned);
        }
        let frame_end = physical_start
            .checked_add(PAGE_SIZE)
            .ok_or(FreeError::AddressOverflow)?;

        if !self.managed[..self.managed_len]
            .iter()
            .any(|extent| extent.contains_frame(physical_start, frame_end))
        {
            return Err(FreeError::Unmanaged);
        }

        let mut insertion = 0;
        while insertion < self.free_len && self.free[insertion].physical_start < physical_start {
            if self.free[insertion].contains_frame(physical_start, frame_end) {
                return Err(FreeError::Duplicate);
            }
            insertion += 1;
        }
        if insertion < self.free_len
            && self.free[insertion].contains_frame(physical_start, frame_end)
        {
            return Err(FreeError::Duplicate);
        }

        let joins_left = if insertion == 0 {
            false
        } else {
            self.free[insertion - 1]
                .end()
                .ok_or(FreeError::AddressOverflow)?
                == physical_start
        };
        let joins_right =
            insertion < self.free_len && self.free[insertion].physical_start == frame_end;

        match (joins_left, joins_right) {
            (true, true) => {
                let left = insertion - 1;
                let merged_pages = self.free[left]
                    .page_count
                    .checked_add(1)
                    .and_then(|pages| pages.checked_add(self.free[insertion].page_count))
                    .ok_or(FreeError::AddressOverflow)?;
                self.free[left].page_count = merged_pages;
                self.remove_free_extent(insertion);
            }
            (true, false) => {
                let left = insertion - 1;
                let merged_pages = self.free[left]
                    .page_count
                    .checked_add(1)
                    .ok_or(FreeError::AddressOverflow)?;
                self.free[left].page_count = merged_pages;
            }
            (false, true) => {
                let merged_pages = self.free[insertion]
                    .page_count
                    .checked_add(1)
                    .ok_or(FreeError::AddressOverflow)?;
                self.free[insertion].physical_start = physical_start;
                self.free[insertion].page_count = merged_pages;
            }
            (false, false) => {
                if self.free_len == MAX_FRAME_EXTENTS {
                    return Err(FreeError::CapacityExceeded);
                }
                for index in (insertion..self.free_len).rev() {
                    self.free[index + 1] = self.free[index];
                }
                self.free[insertion] = Extent {
                    physical_start,
                    page_count: 1,
                };
                self.free_len += 1;
            }
        }
        Ok(())
    }

    #[must_use]
    pub const fn managed_extent_count(&self) -> usize {
        self.managed_len
    }

    #[must_use]
    pub const fn free_extent_count(&self) -> usize {
        self.free_len
    }

    fn remove_free_extent(&mut self, index: usize) {
        for next in index + 1..self.free_len {
            self.free[next - 1] = self.free[next];
        }
        self.free_len -= 1;
    }
}

impl Default for FrameAllocator {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_and_count_extents(regions: &[MemoryRegionV1]) -> Result<usize, InitError> {
    let mut previous_start = None;
    let mut previous_end = None;
    let mut previous_usable_end = None;
    let mut extent_count = 0usize;

    for region in regions {
        if region.page_count == 0 {
            return Err(InitError::ZeroPages);
        }
        if !region.physical_start.is_multiple_of(PAGE_SIZE) {
            return Err(InitError::Unaligned);
        }
        if !is_known_memory_kind(region.kind) {
            return Err(InitError::UnknownKind);
        }
        if region.attributes != 0 {
            return Err(InitError::Attributes);
        }
        let end = region
            .page_count
            .checked_mul(PAGE_SIZE)
            .and_then(|bytes| region.physical_start.checked_add(bytes))
            .ok_or(InitError::RangeOverflow)?;

        if previous_start.is_some_and(|start| region.physical_start < start) {
            return Err(InitError::OutOfOrder);
        }
        if previous_end.is_some_and(|prior_end| region.physical_start < prior_end) {
            return Err(InitError::Overlap);
        }

        if region.kind == MEMORY_USABLE {
            if previous_usable_end != Some(region.physical_start) {
                extent_count = extent_count
                    .checked_add(1)
                    .ok_or(InitError::CapacityExceeded)?;
                if extent_count > MAX_FRAME_EXTENTS {
                    return Err(InitError::CapacityExceeded);
                }
            }
            previous_usable_end = Some(end);
        } else {
            previous_usable_end = None;
        }

        previous_start = Some(region.physical_start);
        previous_end = Some(end);
    }

    Ok(extent_count)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::mem::size_of;
    use std::collections::BTreeSet;
    use std::vec;
    use std::vec::Vec;

    use makopa_boot_contract::{MEMORY_LOADER_RECLAIMABLE, MEMORY_RESERVED, MEMORY_USABLE};

    use super::*;

    fn region(physical_start: u64, page_count: u64, kind: u32) -> MemoryRegionV1 {
        MemoryRegionV1 {
            physical_start,
            page_count,
            kind,
            attributes: 0,
        }
    }

    fn allocator(regions: &[MemoryRegionV1]) -> FrameAllocator {
        let mut allocator = FrameAllocator::new();
        allocator.initialize(regions).unwrap();
        allocator
    }

    fn state(allocator: &FrameAllocator) -> (Vec<Extent>, Vec<Extent>) {
        (
            allocator.managed[..allocator.managed_len].to_vec(),
            allocator.free[..allocator.free_len].to_vec(),
        )
    }

    fn frame_is_free(allocator: &FrameAllocator, physical_start: u64) -> bool {
        let frame_end = physical_start + PAGE_SIZE;
        allocator.free[..allocator.free_len]
            .iter()
            .any(|extent| extent.contains_frame(physical_start, frame_end))
    }

    #[test]
    fn initialization_owns_its_copy_after_source_changes_and_drops() {
        let mut allocator = FrameAllocator::new();
        {
            let mut source = vec![region(0x1000, 2, MEMORY_USABLE)];
            allocator.initialize(&source).unwrap();
            source[0].physical_start = 0x9000;
        }

        assert_eq!(allocator.allocate_frame(), Ok(0x1000));
        assert_eq!(allocator.allocate_frame(), Ok(0x2000));
        assert_eq!(allocator.allocate_frame(), Err(AllocateError::Exhausted));
    }

    #[test]
    fn initialization_seeds_only_usable_ranges() {
        let mut allocator = allocator(&[
            region(0, 1, MEMORY_RESERVED),
            region(0x1000, 1, MEMORY_USABLE),
            region(0x2000, 1, MEMORY_LOADER_RECLAIMABLE),
        ]);

        assert_eq!(allocator.managed_extent_count(), 1);
        assert_eq!(allocator.allocate_frame(), Ok(0x1000));
        assert_eq!(allocator.allocate_frame(), Err(AllocateError::Exhausted));
        assert_eq!(allocator.free_frame(0), Err(FreeError::Unmanaged));
        assert_eq!(allocator.free_frame(0x2000), Err(FreeError::Unmanaged));
    }

    #[test]
    fn initialization_accepts_a_map_without_usable_ranges() {
        let mut allocator = allocator(&[
            region(0, 1, MEMORY_RESERVED),
            region(0x1000, 1, MEMORY_LOADER_RECLAIMABLE),
        ]);

        assert_eq!(allocator.managed_extent_count(), 0);
        assert_eq!(allocator.free_extent_count(), 0);
        assert_eq!(allocator.allocate_frame(), Err(AllocateError::Exhausted));
    }

    #[test]
    fn allocation_is_aligned_lowest_first_and_explicitly_exhausted() {
        let mut allocator = allocator(&[
            region(0, 2, MEMORY_USABLE),
            region(0x2000, 1, MEMORY_RESERVED),
            region(0x3000, 2, MEMORY_USABLE),
        ]);

        for expected in [0, 0x1000, 0x3000, 0x4000] {
            let actual = allocator.allocate_frame().unwrap();
            assert_eq!(actual, expected);
            assert!(actual.is_multiple_of(PAGE_SIZE));
        }
        assert_eq!(allocator.allocate_frame(), Err(AllocateError::Exhausted));
    }

    #[test]
    fn adjacent_usable_input_is_maximally_coalesced() {
        let allocator = allocator(&[
            region(0x1000, 2, MEMORY_USABLE),
            region(0x3000, 3, MEMORY_USABLE),
        ]);

        assert_eq!(allocator.managed_extent_count(), 1);
        assert_eq!(allocator.free_extent_count(), 1);
        assert_eq!(allocator.managed[0], region_extent(0x1000, 5));
    }

    #[test]
    fn frees_coalesce_on_the_left() {
        let mut allocator = allocator(&[region(0x1000, 3, MEMORY_USABLE)]);
        let first = allocator.allocate_frame().unwrap();
        let second = allocator.allocate_frame().unwrap();
        let _third = allocator.allocate_frame().unwrap();

        allocator.free_frame(first).unwrap();
        allocator.free_frame(second).unwrap();

        assert_eq!(allocator.free_extent_count(), 1);
        assert_eq!(allocator.free[0], region_extent(0x1000, 2));
    }

    #[test]
    fn frees_coalesce_on_the_right() {
        let mut allocator = allocator(&[region(0x1000, 3, MEMORY_USABLE)]);
        let first = allocator.allocate_frame().unwrap();
        let second = allocator.allocate_frame().unwrap();
        let _third = allocator.allocate_frame().unwrap();

        allocator.free_frame(second).unwrap();
        allocator.free_frame(first).unwrap();

        assert_eq!(allocator.free_extent_count(), 1);
        assert_eq!(allocator.free[0], region_extent(0x1000, 2));
    }

    #[test]
    fn frees_coalesce_on_both_sides_and_reuse_the_lowest_frame() {
        let mut allocator = allocator(&[region(0x1000, 4, MEMORY_USABLE)]);
        let frames: Vec<u64> = (0..4)
            .map(|_| allocator.allocate_frame().unwrap())
            .collect();

        allocator.free_frame(frames[0]).unwrap();
        allocator.free_frame(frames[2]).unwrap();
        allocator.free_frame(frames[1]).unwrap();

        assert_eq!(allocator.free_extent_count(), 1);
        assert_eq!(allocator.free[0], region_extent(0x1000, 3));
        assert_eq!(allocator.allocate_frame(), Ok(frames[0]));
    }

    #[test]
    fn rejected_frees_are_distinct_and_preserve_state() {
        let mut allocator = allocator(&[region(0x1000, 3, MEMORY_USABLE)]);
        let first = allocator.allocate_frame().unwrap();
        let second = allocator.allocate_frame().unwrap();
        allocator.free_frame(first).unwrap();
        let before = state(&allocator);

        for (address, expected) in [
            (first, FreeError::Duplicate),
            (second + 1, FreeError::Unaligned),
            (0x9000, FreeError::Unmanaged),
            (u64::MAX - (PAGE_SIZE - 1), FreeError::AddressOverflow),
        ] {
            assert_eq!(allocator.free_frame(address), Err(expected));
            assert_eq!(state(&allocator), before);
        }
    }

    #[test]
    fn capacity_exhausted_free_preserves_caller_ownership_and_state() {
        let page_count = (MAX_FRAME_EXTENTS as u64) * 2 + 1;
        let mut allocator = allocator(&[region(0, page_count, MEMORY_USABLE)]);
        let frames: Vec<u64> = (0..page_count)
            .map(|_| allocator.allocate_frame().unwrap())
            .collect();
        for index in (0..MAX_FRAME_EXTENTS * 2).step_by(2) {
            allocator.free_frame(frames[index]).unwrap();
        }
        assert_eq!(allocator.free_extent_count(), MAX_FRAME_EXTENTS);
        let before = state(&allocator);

        assert_eq!(
            allocator.free_frame(frames[MAX_FRAME_EXTENTS * 2]),
            Err(FreeError::CapacityExceeded)
        );
        assert_eq!(state(&allocator), before);
        assert!(!frame_is_free(&allocator, frames[MAX_FRAME_EXTENTS * 2]));
    }

    #[test]
    fn malformed_reinitialization_preserves_existing_state() {
        let malformed = vec![
            (vec![region(0x1000, 0, MEMORY_USABLE)], InitError::ZeroPages),
            (vec![region(0x1001, 1, MEMORY_USABLE)], InitError::Unaligned),
            (
                vec![region(u64::MAX - (PAGE_SIZE - 1), 2, MEMORY_USABLE)],
                InitError::RangeOverflow,
            ),
            (
                vec![
                    region(0x3000, 1, MEMORY_RESERVED),
                    region(0x1000, 1, MEMORY_USABLE),
                ],
                InitError::OutOfOrder,
            ),
            (
                vec![
                    region(0x1000, 2, MEMORY_RESERVED),
                    region(0x2000, 1, MEMORY_USABLE),
                ],
                InitError::Overlap,
            ),
            (vec![region(0x1000, 1, 99)], InitError::UnknownKind),
            (
                vec![MemoryRegionV1 {
                    attributes: 1,
                    ..region(0x1000, 1, MEMORY_USABLE)
                }],
                InitError::Attributes,
            ),
        ];

        for (regions, expected) in malformed {
            let mut allocator = allocator(&[region(0x8000, 2, MEMORY_USABLE)]);
            let _allocated = allocator.allocate_frame().unwrap();
            let before = state(&allocator);
            assert_eq!(allocator.initialize(&regions), Err(expected));
            assert_eq!(state(&allocator), before);
        }
    }

    #[test]
    fn over_capacity_initialization_preserves_existing_state() {
        let mut regions = Vec::new();
        for index in 0..MAX_FRAME_EXTENTS * 2 + 1 {
            let kind = if index.is_multiple_of(2) {
                MEMORY_USABLE
            } else {
                MEMORY_RESERVED
            };
            regions.push(region(index as u64 * PAGE_SIZE, 1, kind));
        }
        let mut allocator = allocator(&[region(0x8000, 2, MEMORY_USABLE)]);
        let before = state(&allocator);

        assert_eq!(
            allocator.initialize(&regions),
            Err(InitError::CapacityExceeded)
        );
        assert_eq!(state(&allocator), before);
    }

    #[test]
    fn allocation_overflow_is_checked_before_state_changes() {
        let mut allocator = FrameAllocator::new();
        allocator.free[0] = region_extent(u64::MAX - (PAGE_SIZE - 1), 2);
        allocator.free_len = 1;
        let before = state(&allocator);

        assert_eq!(
            allocator.allocate_frame(),
            Err(AllocateError::InvariantOverflow)
        );
        assert_eq!(state(&allocator), before);
    }

    #[test]
    fn exhaustive_small_sequences_match_a_reference_model() {
        const ACTION_COUNT: usize = 5;
        const DEPTH: usize = 5;
        let sequence_count = ACTION_COUNT.pow(DEPTH as u32);

        for mut encoded in 0..sequence_count {
            let mut allocator = allocator(&[region(0, 4, MEMORY_USABLE)]);
            let mut free = BTreeSet::from([0, PAGE_SIZE, PAGE_SIZE * 2, PAGE_SIZE * 3]);

            for _ in 0..DEPTH {
                let action = encoded % ACTION_COUNT;
                encoded /= ACTION_COUNT;
                if action == 0 {
                    let expected = free.pop_first().ok_or(AllocateError::Exhausted);
                    assert_eq!(allocator.allocate_frame(), expected);
                } else {
                    let address = (action as u64 - 1) * PAGE_SIZE;
                    let expected = if free.contains(&address) {
                        Err(FreeError::Duplicate)
                    } else {
                        free.insert(address);
                        Ok(())
                    };
                    assert_eq!(allocator.free_frame(address), expected);
                }

                for address in [0, PAGE_SIZE, PAGE_SIZE * 2, PAGE_SIZE * 3] {
                    assert_eq!(frame_is_free(&allocator, address), free.contains(&address));
                }
            }
        }
    }

    #[test]
    fn allocator_metadata_stays_within_the_reviewed_static_budget() {
        assert!(size_of::<FrameAllocator>() <= 40 * 1024);
        assert_eq!(size_of::<FrameAllocator>(), 32_784);
    }

    const fn region_extent(physical_start: u64, page_count: u64) -> Extent {
        Extent {
            physical_start,
            page_count,
        }
    }
}
