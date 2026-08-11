#![no_std]

const ELF_HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;
const PROGRAM_HEADER_LOAD: u32 = 1;
const PROGRAM_FLAG_EXECUTE: u32 = 1;
const ELF_MACHINE_X86_64: u16 = 62;
const ELF_TYPE_EXECUTABLE: u16 = 2;
const PAGE_SIZE: u64 = 4096;
const MINIMUM_LOAD_ADDRESS: u64 = 0x10_0000;
pub const MAXIMUM_LOAD_SEGMENTS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    ImageTooSmall,
    InvalidMagic,
    UnsupportedClass,
    UnsupportedEndianness,
    UnsupportedVersion,
    UnsupportedType,
    UnsupportedMachine,
    InvalidHeaderSize,
    InvalidProgramHeaderSize,
    MissingProgramHeaders,
    TooManyLoadSegments,
    ProgramHeaderTableOutOfBounds,
    SegmentOutOfBounds,
    SegmentFilesLargerThanMemory,
    SegmentAddressMismatch,
    SegmentAddressTooLow,
    SegmentAlignment,
    SegmentOverlap,
    EntryNotExecutable,
    ArithmeticOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Segment {
    pub file_offset: usize,
    pub file_size: usize,
    pub physical_start: u64,
    pub memory_size: u64,
    pub flags: u32,
}

impl Segment {
    #[must_use]
    pub const fn is_executable(self) -> bool {
        self.flags & PROGRAM_FLAG_EXECUTE != 0
    }

    pub fn memory_end(self) -> Result<u64, Error> {
        self.physical_start
            .checked_add(self.memory_size)
            .ok_or(Error::ArithmeticOverflow)
    }

    #[must_use]
    pub const fn page_count(self) -> usize {
        self.memory_size.div_ceil(PAGE_SIZE) as usize
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ValidatedImage<'a> {
    bytes: &'a [u8],
    entry: u64,
    program_headers_offset: usize,
    program_header_count: usize,
}

impl<'a> ValidatedImage<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < ELF_HEADER_SIZE {
            return Err(Error::ImageTooSmall);
        }
        if bytes.get(0..4) != Some(b"\x7fELF") {
            return Err(Error::InvalidMagic);
        }
        if bytes[4] != 2 {
            return Err(Error::UnsupportedClass);
        }
        if bytes[5] != 1 {
            return Err(Error::UnsupportedEndianness);
        }
        if bytes[6] != 1 || read_u32(bytes, 20)? != 1 {
            return Err(Error::UnsupportedVersion);
        }
        if read_u16(bytes, 16)? != ELF_TYPE_EXECUTABLE {
            return Err(Error::UnsupportedType);
        }
        if read_u16(bytes, 18)? != ELF_MACHINE_X86_64 {
            return Err(Error::UnsupportedMachine);
        }
        if usize::from(read_u16(bytes, 52)?) != ELF_HEADER_SIZE {
            return Err(Error::InvalidHeaderSize);
        }
        if usize::from(read_u16(bytes, 54)?) != PROGRAM_HEADER_SIZE {
            return Err(Error::InvalidProgramHeaderSize);
        }

        let program_header_count = usize::from(read_u16(bytes, 56)?);
        if program_header_count == 0 {
            return Err(Error::MissingProgramHeaders);
        }
        let program_headers_offset =
            usize::try_from(read_u64(bytes, 32)?).map_err(|_| Error::ArithmeticOverflow)?;
        let table_size = PROGRAM_HEADER_SIZE
            .checked_mul(program_header_count)
            .ok_or(Error::ArithmeticOverflow)?;
        let table_end = program_headers_offset
            .checked_add(table_size)
            .ok_or(Error::ArithmeticOverflow)?;
        if table_end > bytes.len() {
            return Err(Error::ProgramHeaderTableOutOfBounds);
        }

        let image = Self {
            bytes,
            entry: read_u64(bytes, 24)?,
            program_headers_offset,
            program_header_count,
        };
        image.validate_segments()?;
        Ok(image)
    }

    #[must_use]
    pub const fn entry(self) -> u64 {
        self.entry
    }

    #[must_use]
    pub const fn segments(self) -> Segments<'a> {
        Segments {
            image: self,
            next_index: 0,
        }
    }

    #[must_use]
    pub fn file_bytes(self, segment: Segment) -> &'a [u8] {
        &self.bytes[segment.file_offset..segment.file_offset + segment.file_size]
    }

    fn validate_segments(self) -> Result<(), Error> {
        let mut load_segments = 0;
        let mut entry_is_executable = false;

        for index in 0..self.program_header_count {
            let Some(segment) = self.segment_at(index)? else {
                continue;
            };
            load_segments += 1;
            if load_segments > MAXIMUM_LOAD_SEGMENTS {
                return Err(Error::TooManyLoadSegments);
            }

            let segment_end = segment.memory_end()?;
            if segment.is_executable()
                && self.entry >= segment.physical_start
                && self.entry < segment_end
            {
                entry_is_executable = true;
            }

            for prior_index in 0..index {
                let Some(prior) = self.segment_at(prior_index)? else {
                    continue;
                };
                if ranges_overlap(
                    segment.physical_start,
                    segment_end,
                    prior.physical_start,
                    prior.memory_end()?,
                ) {
                    return Err(Error::SegmentOverlap);
                }
            }
        }

        if load_segments == 0 {
            return Err(Error::MissingProgramHeaders);
        }
        if !entry_is_executable {
            return Err(Error::EntryNotExecutable);
        }
        Ok(())
    }

    fn segment_at(self, index: usize) -> Result<Option<Segment>, Error> {
        let offset = self
            .program_headers_offset
            .checked_add(
                PROGRAM_HEADER_SIZE
                    .checked_mul(index)
                    .ok_or(Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::ArithmeticOverflow)?;
        if read_u32(self.bytes, offset)? != PROGRAM_HEADER_LOAD {
            return Ok(None);
        }

        let flags = read_u32(self.bytes, offset + 4)?;
        let file_offset_u64 = read_u64(self.bytes, offset + 8)?;
        let virtual_start = read_u64(self.bytes, offset + 16)?;
        let physical_start = read_u64(self.bytes, offset + 24)?;
        let file_size_u64 = read_u64(self.bytes, offset + 32)?;
        let memory_size = read_u64(self.bytes, offset + 40)?;
        let alignment = read_u64(self.bytes, offset + 48)?;

        if file_size_u64 > memory_size || memory_size == 0 {
            return Err(Error::SegmentFilesLargerThanMemory);
        }
        if virtual_start != physical_start {
            return Err(Error::SegmentAddressMismatch);
        }
        if physical_start < MINIMUM_LOAD_ADDRESS {
            return Err(Error::SegmentAddressTooLow);
        }
        if physical_start % PAGE_SIZE != 0
            || alignment < PAGE_SIZE
            || !alignment.is_power_of_two()
            || file_offset_u64 % alignment != virtual_start % alignment
        {
            return Err(Error::SegmentAlignment);
        }

        let file_offset =
            usize::try_from(file_offset_u64).map_err(|_| Error::ArithmeticOverflow)?;
        let file_size = usize::try_from(file_size_u64).map_err(|_| Error::ArithmeticOverflow)?;
        let file_end = file_offset
            .checked_add(file_size)
            .ok_or(Error::ArithmeticOverflow)?;
        if file_end > self.bytes.len() {
            return Err(Error::SegmentOutOfBounds);
        }
        physical_start
            .checked_add(memory_size)
            .ok_or(Error::ArithmeticOverflow)?;

        Ok(Some(Segment {
            file_offset,
            file_size,
            physical_start,
            memory_size,
            flags,
        }))
    }
}

pub struct Segments<'a> {
    image: ValidatedImage<'a>,
    next_index: usize,
}

impl Iterator for Segments<'_> {
    type Item = Segment;

    fn next(&mut self) -> Option<Self::Item> {
        while self.next_index < self.image.program_header_count {
            let index = self.next_index;
            self.next_index += 1;
            match self.image.segment_at(index) {
                Ok(Some(segment)) => return Some(segment),
                Ok(None) => {}
                Err(_) => unreachable!("validated program header changed"),
            }
        }
        None
    }
}

fn ranges_overlap(left_start: u64, left_end: u64, right_start: u64, right_end: u64) -> bool {
    left_start < right_end && right_start < left_end
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    let value = bytes.get(offset..offset + 2).ok_or(Error::ImageTooSmall)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    let value = bytes.get(offset..offset + 4).ok_or(Error::ImageTooSmall)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    let value = bytes.get(offset..offset + 8).ok_or(Error::ImageTooSmall)?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec;
    use std::vec::Vec;

    use super::*;

    fn executable_image() -> Vec<u8> {
        let mut image = vec![0_u8; 0x1004];
        image[0..4].copy_from_slice(b"\x7fELF");
        image[4] = 2;
        image[5] = 1;
        image[6] = 1;
        image[16..18].copy_from_slice(&ELF_TYPE_EXECUTABLE.to_le_bytes());
        image[18..20].copy_from_slice(&ELF_MACHINE_X86_64.to_le_bytes());
        image[20..24].copy_from_slice(&1_u32.to_le_bytes());
        image[24..32].copy_from_slice(&MINIMUM_LOAD_ADDRESS.to_le_bytes());
        image[32..40].copy_from_slice(&(ELF_HEADER_SIZE as u64).to_le_bytes());
        image[52..54].copy_from_slice(&(ELF_HEADER_SIZE as u16).to_le_bytes());
        image[54..56].copy_from_slice(&(PROGRAM_HEADER_SIZE as u16).to_le_bytes());
        image[56..58].copy_from_slice(&1_u16.to_le_bytes());

        let header = ELF_HEADER_SIZE;
        image[header..header + 4].copy_from_slice(&PROGRAM_HEADER_LOAD.to_le_bytes());
        image[header + 4..header + 8].copy_from_slice(&5_u32.to_le_bytes());
        image[header + 8..header + 16].copy_from_slice(&0x1000_u64.to_le_bytes());
        image[header + 16..header + 24].copy_from_slice(&MINIMUM_LOAD_ADDRESS.to_le_bytes());
        image[header + 24..header + 32].copy_from_slice(&MINIMUM_LOAD_ADDRESS.to_le_bytes());
        image[header + 32..header + 40].copy_from_slice(&4_u64.to_le_bytes());
        image[header + 40..header + 48].copy_from_slice(&8_u64.to_le_bytes());
        image[header + 48..header + 56].copy_from_slice(&PAGE_SIZE.to_le_bytes());
        image[0x1000..0x1004].copy_from_slice(&[1, 2, 3, 4]);
        image
    }

    #[test]
    fn accepts_a_bounded_executable_image() {
        let bytes = executable_image();
        let image = ValidatedImage::parse(&bytes).unwrap();
        let segments: Vec<_> = image.segments().collect();

        assert_eq!(image.entry(), MINIMUM_LOAD_ADDRESS);
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].page_count(), 1);
        assert_eq!(image.file_bytes(segments[0]), [1, 2, 3, 4]);
    }

    #[test]
    fn rejects_invalid_magic() {
        let mut bytes = executable_image();
        bytes[1] = b'X';
        assert_eq!(
            ValidatedImage::parse(&bytes).unwrap_err(),
            Error::InvalidMagic
        );
    }

    #[test]
    fn rejects_a_segment_outside_the_file() {
        let mut bytes = executable_image();
        let header = ELF_HEADER_SIZE;
        bytes[header + 32..header + 40].copy_from_slice(&16_u64.to_le_bytes());
        bytes[header + 40..header + 48].copy_from_slice(&16_u64.to_le_bytes());
        assert_eq!(
            ValidatedImage::parse(&bytes).unwrap_err(),
            Error::SegmentOutOfBounds
        );
    }

    #[test]
    fn rejects_an_entry_outside_executable_memory() {
        let mut bytes = executable_image();
        bytes[24..32].copy_from_slice(&(MINIMUM_LOAD_ADDRESS + PAGE_SIZE).to_le_bytes());
        assert_eq!(
            ValidatedImage::parse(&bytes).unwrap_err(),
            Error::EntryNotExecutable
        );
    }
}
